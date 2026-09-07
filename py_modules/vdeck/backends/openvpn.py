"""OpenVPN client with owned routing, verified health and bounded management I/O."""

from __future__ import annotations

import asyncio
import secrets
import shlex
import socket
import time
from pathlib import Path
from typing import Any

from ..errors import VDeckError
from ..logging_utils import safe_exception_details
from ..models import ConnectionMetadata, RuntimeState
from ..network import Ipv6Guard, RouteRecord, interface_name
from ..parsers import parse_openvpn
from ..runner import OwnedProcess
from ..security import secure_mkdir, secure_write
from .base import VPNBackend
from .wireguard import handshake_probe_target


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


def _management_request(port: int, password: str, command: str, timeout: float = 3) -> str:
    # TCP may split the password prompt, coalesce the auth reply with INFO, and
    # terminate lines with CRLF. A single recv() is never a protocol frame.
    deadline = time.monotonic() + timeout
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as client:
        buffer = b""
        total = 0

        def line() -> str:
            nonlocal buffer, total
            while b"\n" not in buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Management deadline expired")
                client.settimeout(remaining)
                chunk = client.recv(4096)
                total += len(chunk)
                if not chunk or total > 131072:
                    raise VDeckError("OPENVPN_MANAGEMENT_FAILED", "Invalid management response")
                buffer += chunk
            value, buffer = buffer.split(b"\n", 1)
            return value.rstrip(b"\r").decode(errors="replace")

        while "ENTER PASSWORD:" not in line():
            pass
        client.sendall((password + "\n").encode())
        while True:
            reply = line()
            if reply.startswith("ERROR:"):
                raise VDeckError("OPENVPN_MANAGEMENT_AUTH_FAILED", "Management authentication failed")
            if reply.startswith("SUCCESS:"):
                break
        client.sendall((command + "\n").encode())
        lines: list[str] = []
        while True:
            reply = line()
            if reply.startswith(">"):
                continue
            if reply.startswith("ERROR:"):
                raise VDeckError("OPENVPN_MANAGEMENT_FAILED", "Management command failed")
            lines.append(reply)
            if reply == "END" or reply.startswith("SUCCESS:"):
                break
        return "\n".join(lines) + "\n"


def resolved_openvpn_config(text: str, endpoint_cache: dict[str, list[str]]) -> str:
    rendered: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", ";", "<")):
            rendered.append(raw)
            continue
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError:
            rendered.append(raw)
            continue
        if tokens and tokens[0].lower().removeprefix("--") == "remote" and len(tokens) >= 2:
            addresses = endpoint_cache.get(tokens[1], [])
            if addresses:
                # Preserve OpenVPN comments instead of turning them into quoted arguments.
                comment_at = next((index for index, token in enumerate(tokens) if token.startswith(("#", ";"))), None)
                directive = tokens if comment_at is None else tokens[:comment_at]
                comment = "" if comment_at is None else " " + " ".join(tokens[comment_at:])
                directive[1] = addresses[0]
                rendered.append(shlex.join(directive) + comment)
                continue
        rendered.append(raw)
    return "\n".join(rendered).rstrip() + "\n"


class OpenVPNBackend(VPNBackend):
    protocol_id = "openvpn"

    def _stage(self, runtime: RuntimeState, stage: str) -> None:
        runtime.stage = stage
        self.context.store.save_runtime(runtime)
        self.logger.info("connect stage=%s protocol=openvpn interface=%s", stage, runtime.interface)

    async def _request(self, runtime: RuntimeState, command: str) -> str:
        management = runtime.process.get("management", {})
        password_file = Path(str(management["password_file"]))
        password = password_file.read_text(encoding="utf-8").strip()
        return await asyncio.to_thread(_management_request, int(management["port"]), password, command)

    async def start(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        self._stage(runtime, "VALIDATE")
        directory = self.connection_dir(metadata)
        # Revalidate older stored profiles against the current privileged boundary.
        parse_openvpn(directory / "config")
        info = self.context.store.parsed_runtime_info(metadata.id)
        routes, dns = list(info.get("allowed_ips", [])), list(info.get("dns_servers", []))
        if not routes:
            raise VDeckError(
                "OPENVPN_ROUTES_REQUIRED",
                "This release needs explicit route/redirect-gateway directives; re-import the updated profile",
            )
        if not dns:
            raise VDeckError("DNS_CONFIGURATION_REQUIRED", "OpenVPN requires explicit dhcp-option DNS in this release")
        credentials = directory / "credentials"
        if metadata.requires_username_password and not (credentials / "auth").is_file():
            raise VDeckError("CREDENTIALS_REQUIRED", "OpenVPN username and password are required")
        if metadata.requires_key_passphrase and not (credentials / "passphrase").is_file():
            raise VDeckError("PASSPHRASE_REQUIRED", "The OpenVPN private key requires a passphrase")
        self._stage(runtime, "ENDPOINT")
        endpoint_cache = await self.resolve_endpoint_cache(metadata, runtime)
        selected: dict[str, list[str]] = {}
        for endpoint, candidates in endpoint_cache.items():
            for candidate in sorted(candidates, key=lambda address: ":" in address):
                _, device = await self.context.inspector.route_to(candidate)
                if device and not device.startswith(("vdeck-", "vdns-")):
                    selected[endpoint] = [candidate]
                    break
            if endpoint not in selected:
                raise VDeckError("ENDPOINT_ROUTE_INVALID", "OpenVPN endpoint has no physical-network route")
        runtime.endpoint_cache = selected
        interface = interface_name(metadata.id)
        if await self.context.inspector.interface_exists(interface):
            raise VDeckError("INTERFACE_ALREADY_EXISTS", "Refusing to adopt a pre-existing interface")
        management_dir = self.context.store.runtime / metadata.id
        secure_mkdir(management_dir)
        port = _reserve_port()
        password_file = management_dir / "management-password"
        resolved_config = management_dir / "resolved.conf"
        secure_write(password_file, (secrets.token_urlsafe(24) + "\n").encode())
        secure_write(
            resolved_config,
            resolved_openvpn_config((directory / "config").read_text(encoding="utf-8"), selected).encode(),
        )
        runtime.interface = interface
        self.context.store.save_runtime(runtime)
        args = self.context.binaries.command(
            "openvpn",
            "--config",
            str(resolved_config),
            "--cd",
            str(directory),
            "--dev",
            interface,
            "--dev-type",
            "tun",
            "--disable-dco",
            "--management",
            "127.0.0.1",
            str(port),
            str(password_file),
            "--auth-nocache",
            "--script-security",
            "1",
            # OpenVPN must not replace the host default route or own unjournaled
            # endpoint routes: even SIGKILL/crash cleanup must restore the network.
            "--route-noexec",
            "--remap-usr1",
            "SIGTERM",
            "--verb",
            "3",
        )
        if (credentials / "auth").is_file():
            args += ["--auth-user-pass", str(credentials / "auth")]
        if (credentials / "passphrase").is_file():
            args += ["--askpass", str(credentials / "passphrase")]

        def on_started(owned: OwnedProcess) -> None:
            runtime.process = owned.to_dict()
            runtime.process["management"] = {"port": port, "password_file": str(password_file)}
            self.context.store.save_runtime(runtime)

        try:
            self._stage(runtime, "PROCESS")
            owned = await self.context.runner.start(
                args,
                cwd=directory,
                stdout_path=self.context.store.logs / f"{metadata.id}.log",
                bundled=True,
                on_started=on_started,
            )
            self._stage(runtime, "OPENVPN_HANDSHAKE")
            deadline = asyncio.get_running_loop().time() + 30
            while asyncio.get_running_loop().time() < deadline:
                if not self.context.runner.is_alive(owned):
                    raise VDeckError(
                        "OPENVPN_EXITED",
                        "OpenVPN exited before the tunnel was established",
                        f"exit_code={self.context.runner.exit_code(owned)}",
                    )
                try:
                    state = await self._request(runtime, "state")
                except (OSError, KeyError, ValueError):
                    await asyncio.sleep(0.25)
                    continue
                if any(value in state.lower() for value in ("auth_failed", "auth-failure", "verification failed")):
                    raise VDeckError("OPENVPN_AUTH_FAILED", "OpenVPN authentication failed")
                if ",CONNECTED,SUCCESS," in state:
                    break
                await asyncio.sleep(0.5)
            else:
                raise VDeckError("OPENVPN_CONNECT_TIMEOUT", "OpenVPN did not confirm a connected state")
            self._stage(runtime, "INTERFACE")
            if not await self.context.inspector.interface_ready(interface, []):
                raise VDeckError("TUNNEL_NOT_READY", "OpenVPN interface is not up")
            if "0.0.0.0/0" in routes and "::/0" not in routes:
                self._stage(runtime, "IPV6_GUARD")
                runtime.ipv6_guard = True
                self.context.store.save_runtime(runtime)
                await Ipv6Guard(self.context.runner).enable(interface, self.endpoint_addresses(runtime))

            def journal(record: RouteRecord) -> None:
                runtime.owned_routes.append(record.to_dict())
                self.context.store.save_runtime(runtime)

            self._stage(runtime, "ROUTE")
            await self.context.routes.apply(
                interface,
                routes,
                list(info.get("endpoints", [])),
                self.endpoint_addresses(runtime),
                on_record=journal,
                dns_servers=dns,
            )
            self._stage(runtime, "DNS")
            await self.context.dns.apply(interface, dns, any(route in {"0.0.0.0/0", "::/0"} for route in routes))
            return await self.verify_connected(metadata, runtime)
        except (Exception, asyncio.CancelledError) as exc:
            self.logger.error(
                "connect failed stage=%s protocol=openvpn code=%s exception=%s details=%s",
                runtime.stage,
                getattr(exc, "code", "START_FAILED"),
                type(exc).__name__,
                safe_exception_details(exc),
            )
            # VPNManager performs attempt-all cleanup, preserving the original error.
            raise

    async def stop(self, metadata: ConnectionMetadata | None, runtime: RuntimeState) -> None:
        # Same ownership journal and attempt-all cleanup as userspace WG. SIGTERM
        # uses the checked PID, never an unauthenticated/reused management port.
        from .wireguard import WireGuardBackend

        cleanup = WireGuardBackend(self.context)
        cleanup.protocol_id = self.protocol_id
        await cleanup.stop(metadata, runtime)
        if metadata:
            directory = self.context.store.runtime / metadata.id
            for filename in ("management-password", "resolved.conf", "openvpn.pid"):
                (directory / filename).unlink(missing_ok=True)

    async def status(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        if not runtime.process or not self.context.runner.is_alive(OwnedProcess.from_dict(runtime.process)):
            return {"connected": False, "tunnel": False, "interface": runtime.interface}
        state = await self._request(runtime, "state")
        # Client statistics are comma-separated even with status format 3.
        status = await self._request(runtime, "status 3")
        connected = ",CONNECTED,SUCCESS," in state
        counters = {}
        for line in status.splitlines():
            name, separator, value = line.rpartition(",")
            if separator and name in {"TCP/UDP read bytes", "TCP/UDP write bytes"} and value.isdigit():
                counters[name] = int(value)
        return {
            "connected": connected,
            "tunnel": connected,
            "interface": runtime.interface,
            "management_state": "CONNECTED" if connected else "CONNECTING",
            "rx_bytes": counters.get("TCP/UDP read bytes", 0),
            "tx_bytes": counters.get("TCP/UDP write bytes", 0),
        }

    async def health(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        status = await self.status(metadata, runtime)
        interface = runtime.interface or ""
        routes = list(self.context.store.parsed_runtime_info(metadata.id).get("allowed_ips", []))
        if not status.get("connected") or not await self.context.inspector.interface_ready(interface, []):
            return {**status, "healthy": False}
        if not await self.context.inspector.vpn_routes_present(interface, routes):
            return {**status, "healthy": False, "routes": False}
        target = handshake_probe_target(routes)
        if not target:
            return {**status, "healthy": False, "routes": False}
        result = await self.context.runner.run(
            ["ping", "-6" if ":" in target else "-4", "-I", interface, "-c", "1", "-W", "3", target],
            check=False,
            timeout=5,
        )
        probe = result.returncode == 0 or await self.context.inspector.tcp_probe(interface, target)
        await self._verify_dns(metadata, runtime)
        return {**status, "healthy": probe, "routes": True, "probe_succeeded": probe}

    async def verify_connected(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        self._stage(runtime, "HEALTH")
        status = await self.health(metadata, runtime)
        if not all(status.get(key) for key in ("connected", "healthy", "routes", "probe_succeeded")):
            raise VDeckError("VPN_TRAFFIC_UNCONFIRMED", "OpenVPN routes and traffic could not be verified")
        self.logger.info("VPN traffic confirmed protocol=openvpn interface=%s", runtime.interface)
        return status
