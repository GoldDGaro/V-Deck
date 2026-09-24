"""VLESS/REALITY via Xray's Linux TUN; V-Deck owns all network changes."""

from __future__ import annotations

import asyncio
import json
import socket
from contextlib import suppress
from pathlib import Path
from typing import Any

from ..errors import VDeckError
from ..logging_utils import safe_exception_details
from ..models import ConnectionMetadata, RuntimeState
from ..network import RouteRecord, interface_name
from ..runner import OwnedProcess
from ..security import secure_write
from ..xray_config import normalize_xray
from .wireguard import WireGuardBackend


async def response_probe(interface: str) -> bool:
    """Require received application bytes, not a proxy-generated SYN-ACK.

    A fixed, non-sensitive HTTP HEAD is bound to the tunnel. No browsing data,
    DNS lookup or credentials are sent. DNS UDP is verified separately.
    """

    def probe() -> bool:
        bind_option = getattr(socket, "SO_BINDTODEVICE", None)
        if bind_option is None:
            return False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.setsockopt(socket.SOL_SOCKET, bind_option, interface.encode() + b"\0")
                client.connect(("1.1.1.1", 80))
                client.sendall(b"HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")
                return client.recv(16).startswith(b"HTTP/")
        except (OSError, AttributeError):
            return False

    return await asyncio.to_thread(probe)


class XrayBackend(WireGuardBackend):
    # Share the existing journaled interface/route/process cleanup, but never
    # invoke WG configuration, UAPI, handshake or status methods.
    protocol_id = "xray"

    def _config_path(self, connection_id: str) -> Path:
        return self.context.store.runtime / f"{interface_name(connection_id)}-xray.json"

    async def start(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        self._stage(runtime, "VALIDATE")
        text = (self.connection_dir(metadata) / "config").read_text(encoding="utf-8")
        outbound, _, _ = normalize_xray(text)
        info = self.context.store.parsed_runtime_info(metadata.id)
        self._stage(runtime, "ENDPOINT")
        await self.resolve_endpoint_cache(metadata, runtime)
        addresses = self.endpoint_addresses(runtime)
        if not addresses:
            raise VDeckError("ENDPOINT_RESOLVE_FAILED", "Xray endpoint resolution failed")
        _, physical = await self.context.inspector.route_to(addresses[0])
        if not physical or physical.startswith(("vdeck-", "vdns-")):
            raise VDeckError("ENDPOINT_ROUTE_INVALID", "Xray endpoint has no physical-network route")
        interface = interface_name(metadata.id)
        if await self.context.inspector.interface_exists(interface):
            raise VDeckError("INTERFACE_ALREADY_EXISTS", "Refusing to take over an existing interface")
        outbound["settings"]["vnext"][0]["address"] = addresses[0]
        outbound["streamSettings"]["sockopt"] = {"interface": physical}
        config = {
            "log": {"access": "none", "loglevel": "warning"},
            "inbounds": [{"protocol": "tun", "settings": {"name": interface, "MTU": 1500}}],
            "outbounds": [outbound],
        }
        path = self._config_path(metadata.id)
        secure_write(path, json.dumps(config).encode())
        # Xray -test still constructs inbound handlers (including TUN!).
        # Validate the outbound-only configuration so preflight cannot create
        # an unjournaled interface. The real process owns TUN initialization.
        await self.context.runner.run(
            self.context.binaries.command("xray", "run", "-test", "-config", "stdin:"),
            input_text=json.dumps({"log": config["log"], "outbounds": [outbound]}),
            bundled=True,
            timeout=15,
        )
        runtime.interface = interface
        self.context.store.save_runtime(runtime)

        def on_started(owned: OwnedProcess) -> None:
            runtime.process = owned.to_dict()
            self.context.store.save_runtime(runtime)

        def journal(record: RouteRecord) -> None:
            runtime.owned_routes.append(record.to_dict())
            self.context.store.save_runtime(runtime)

        try:
            self._stage(runtime, "PROCESS")
            owned = await self.context.runner.start(
                self.context.binaries.command("xray", "run", "-config", str(path)),
                bundled=True,
                stdout_path=self.context.store.logs / "unused-native-sink",
                on_started=on_started,
            )
            self.logger.info(
                "xray started connection=%s pid=%d transport=tcp security=reality flow_present=%s",
                metadata.id,
                owned.pid,
                bool(outbound["settings"]["vnext"][0]["users"][0]["flow"]),
            )
            self._stage(runtime, "INTERFACE")
            deadline = asyncio.get_running_loop().time() + 8
            while not await self.context.inspector.interface_exists(interface):
                if not self.context.runner.is_alive(owned):
                    raise VDeckError(
                        "XRAY_EXITED",
                        "Xray exited before creating the tunnel",
                        f"exit_code={self.context.runner.exit_code(owned)}",
                    )
                if asyncio.get_running_loop().time() >= deadline:
                    raise VDeckError("TUNNEL_NOT_READY", "Xray TUN creation timed out")
                await asyncio.sleep(0.1)
            for address in info["interface_addresses"]:
                await self.context.runner.run(
                    ["ip", "-6" if ":" in address else "-4", "address", "replace", address, "dev", interface]
                )
            await self.context.runner.run(["ip", "link", "set", "dev", interface, "mtu", "1500", "up"])
            if not await self.context.inspector.interface_ready(interface, info["interface_addresses"]):
                raise VDeckError("TUNNEL_NOT_READY", "Xray interface addresses are not ready")
            self._stage(runtime, "ROUTE")
            await self.context.routes.apply(
                interface,
                info["allowed_ips"],
                info["endpoints"],
                addresses,
                on_record=journal,
                dns_servers=info["dns_servers"],
            )
            self._stage(runtime, "DNS")
            await self.context.dns.apply(interface, info["dns_servers"], True)
            return await self.verify_connected(metadata, runtime)
        except (Exception, asyncio.CancelledError) as exc:
            self.logger.error(
                "connect failed stage=%s protocol=xray code=%s exception=%s details=%s",
                runtime.stage,
                getattr(exc, "code", "XRAY_START_FAILED"),
                type(exc).__name__,
                safe_exception_details(exc),
            )
            try:
                await self.stop(metadata, runtime)
            except Exception as cleanup_exc:
                self.logger.error("cleanup pending protocol=xray details=%s", safe_exception_details(cleanup_exc))
            raise

    async def stop(self, metadata: ConnectionMetadata | None, runtime: RuntimeState) -> None:
        connection_id = metadata.id if metadata else runtime.connection_id
        await super().stop(metadata, runtime)
        if connection_id:
            self._config_path(connection_id).unlink(missing_ok=True)

    async def status(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        interface = runtime.interface or interface_name(metadata.id)
        alive = bool(runtime.process and self.context.runner.is_alive(OwnedProcess.from_dict(runtime.process)))
        exists = await self.context.inspector.interface_exists(interface)
        ready = alive and exists
        counters = {"rx_bytes": 0, "tx_bytes": 0}
        for key in counters:
            with suppress(OSError, ValueError):
                counters[key] = int((Path("/sys/class/net") / interface / "statistics" / key).read_text())
        return {
            "connected": ready,
            "tunnel": ready,
            "interface": interface,
            **counters,
            "health_requires_response": True,
        }

    async def health(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        status = await self.status(metadata, runtime)
        if not status["connected"]:
            return {**status, "healthy": False, "probe_succeeded": False}
        info = self.context.store.parsed_runtime_info(metadata.id)
        routes = await self.context.inspector.vpn_routes_present(status["interface"], info["allowed_ips"])
        answered = routes and await response_probe(status["interface"])
        dns_verified = False
        if routes:
            await self._verify_dns(metadata, runtime)
            dns_verified = True
        self.logger.info(
            "xray health connection=%s process_alive=%s routes=%s tcp_response=%s dns_verified=%s",
            metadata.id,
            status["connected"],
            routes,
            answered,
            dns_verified,
        )
        # A validated remote DNS answer is application traffic over the
        # encrypted outbound. An unavailable HTTP test site must not veto it.
        return {**status, "healthy": dns_verified, "routes": routes, "probe_succeeded": dns_verified}

    async def verify_connected(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        self._stage(runtime, "HEALTH")
        health = await self.health(metadata, runtime)
        if not health.get("healthy"):
            raise VDeckError("XRAY_TRAFFIC_UNCONFIRMED", "No application response received through Xray Reality")
        return health
