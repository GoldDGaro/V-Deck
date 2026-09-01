"""WireGuard backend with kernel-first and bundled userspace fallback."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from ..errors import VDeckError
from ..models import ConnectionMetadata, RuntimeState
from ..network import interface_name
from ..runner import OwnedProcess, process_matches
from .base import VPNBackend


def handshake_probe_target(allowed_ips: list[str]) -> str | None:
    networks = [ipaddress.ip_network(value, strict=False) for value in allowed_ips]
    networks.sort(key=lambda item: (item.version, item.prefixlen))
    for network in networks:
        if network.prefixlen == 0:
            return "1.1.1.1" if network.version == 4 else "2606:4700:4700::1111"
        return str(next(network.hosts(), network.network_address))
    return None


def endpoint_with_address(endpoint: str, address: str) -> str:
    if endpoint.startswith("["):
        closing = endpoint.find("]")
        port = endpoint[closing + 1 :].removeprefix(":") if closing >= 0 else ""
    else:
        _, separator, port = endpoint.rpartition(":")
        if not separator:
            port = ""
    if not port.isdigit():
        raise VDeckError("ENDPOINT_INVALID", "WireGuard endpoint is missing a valid port")
    rendered_address = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    return f"{rendered_address}:{port}"


def resolved_wireguard_config(text: str, endpoint_cache: dict[str, list[str]]) -> str:
    rendered: list[str] = []
    for raw in text.splitlines():
        if "=" not in raw:
            rendered.append(raw)
            continue
        key, value = raw.split("=", 1)
        endpoint = value.strip()
        addresses = endpoint_cache.get(endpoint, [])
        if key.strip().lower() == "endpoint" and addresses:
            rendered.append(f"{key}= {endpoint_with_address(endpoint, addresses[0])}")
        else:
            rendered.append(raw)
    return "\n".join(rendered).rstrip() + "\n"


class WireGuardBackend(VPNBackend):
    protocol_id = "wireguard"
    tool_name = "wg"
    userspace_name = "wireguard-go"
    force_userspace = False

    async def _create_interface(self, interface: str, runtime: RuntimeState, log_path: Path) -> None:
        process: OwnedProcess | None = None
        if not self.force_userspace:
            kernel = await self.context.runner.run(
                ["ip", "link", "add", "dev", interface, "type", "wireguard"], check=False, timeout=5
            )
            if kernel.returncode == 0:
                return
        process = await self.context.runner.start(
            self.context.binaries.command(self.userspace_name, interface),
            env={"WG_TUN_NAME_FILE": ""},
            stdout_path=log_path,
        )
        runtime.process = process.to_dict()
        self.context.store.save_runtime(runtime)
        for _ in range(40):
            if await self.context.inspector.interface_exists(interface):
                return
            if process and not process_matches(process):
                break
            await asyncio.sleep(0.1)
        raise VDeckError("INTERFACE_CREATE_FAILED", f"Unable to create VPN interface {interface}")

    async def start(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        directory = self.connection_dir(metadata)
        info = self.context.store.parsed_runtime_info(metadata.id)
        endpoint_cache = await self.resolve_endpoint_cache(metadata, runtime)
        resolved_config = resolved_wireguard_config((directory / "config").read_text(encoding="utf-8"), endpoint_cache)
        interface = interface_name(metadata.id)
        runtime.interface = interface
        self.context.store.save_runtime(runtime)
        try:
            await self._create_interface(interface, runtime, self.context.store.logs / f"{metadata.id}.log")
            await self.context.runner.run(
                self.context.binaries.command(self.tool_name, "setconf", interface, "/dev/stdin"),
                input_text=resolved_config,
            )
            for address in info.get("interface_addresses", []):
                family = "-6" if ":" in str(address) else "-4"
                await self.context.runner.run(["ip", family, "address", "replace", str(address), "dev", interface])
            mtu = info.get("mtu") or 1420
            await self.context.runner.run(["ip", "link", "set", "dev", interface, "mtu", str(mtu), "up"])
            runtime.owned_routes = [
                record.to_dict()
                for record in await self.context.routes.apply(
                    interface,
                    list(info.get("allowed_ips", [])),
                    list(info.get("endpoints", [])),
                    self.endpoint_addresses(runtime),
                )
            ]
            self.context.store.save_runtime(runtime)
            full = any(str(item) in {"0.0.0.0/0", "::/0"} for item in info.get("allowed_ips", []))
            await self.context.dns.apply(interface, list(info.get("dns_servers", [])), full)
            await self._probe_handshake(interface, list(info.get("allowed_ips", [])))
            return await self.status(metadata, runtime)
        except Exception:
            await self.stop(metadata, runtime)
            raise

    async def _probe_handshake(self, interface: str, allowed_ips: list[str]) -> None:
        target = handshake_probe_target(allowed_ips)
        if target:
            family = "-6" if ":" in target else "-4"
            await self.context.runner.run(
                ["ping", family, "-I", interface, "-c", "1", "-W", "3", target], check=False, timeout=5
            )
        deadline = asyncio.get_running_loop().time() + 18
        while asyncio.get_running_loop().time() < deadline:
            result = await self.context.runner.run(
                self.context.binaries.command(self.tool_name, "show", interface, "latest-handshakes"),
                check=False,
                timeout=3,
            )
            values = [line.rsplit("\t", 1)[-1].strip() for line in result.stdout.splitlines() if line.strip()]
            if any(value.isdigit() and int(value) > 0 for value in values):
                return
            await asyncio.sleep(0.5)
        raise VDeckError("HANDSHAKE_TIMEOUT", "VPN interface started, but no peer handshake was confirmed")

    async def stop(self, metadata: ConnectionMetadata | None, runtime: RuntimeState) -> None:
        await self.context.routes.cleanup(runtime.owned_routes)
        await self.context.dns.cleanup(runtime.interface)
        if runtime.interface:
            await self.context.runner.run(["ip", "link", "delete", "dev", runtime.interface], check=False, timeout=5)
        if runtime.process:
            with suppress(KeyError, TypeError, ValueError):
                await self.context.runner.stop(OwnedProcess.from_dict(runtime.process))
        if runtime.interface and await self.context.inspector.interface_exists(runtime.interface):
            raise VDeckError("INTERFACE_STOP_FAILED", f"Unable to remove VPN interface {runtime.interface}")
        runtime.process = {}
        runtime.owned_routes = []
        runtime.interface = None
        self.context.store.save_runtime(runtime)

    async def status(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        interface = runtime.interface or interface_name(metadata.id)
        if not await self.context.inspector.interface_exists(interface):
            return {"connected": False, "tunnel": False, "interface": interface, "peers": 0}
        result = await self.context.runner.run(
            self.context.binaries.command(self.tool_name, "show", interface, "dump"), check=False, timeout=3
        )
        peers: list[dict[str, Any]] = []
        lines = result.stdout.splitlines()
        for line in lines[1:]:
            columns = line.split("\t")
            if len(columns) >= 8:
                peers.append(
                    {
                        "endpoint": columns[2],
                        "allowed_ips": columns[3],
                        "latest_handshake": int(columns[4] or 0),
                        "rx_bytes": int(columns[5] or 0),
                        "tx_bytes": int(columns[6] or 0),
                    }
                )
        latest = max((peer["latest_handshake"] for peer in peers), default=0)
        fresh = latest > 0 and time.time() - latest < 180
        return {
            "connected": bool(peers and latest > 0),
            "tunnel": True,
            "interface": interface,
            "peers": len(peers),
            "handshake_fresh": fresh,
            "latest_handshake": latest,
            "rx_bytes": sum(peer["rx_bytes"] for peer in peers),
            "tx_bytes": sum(peer["tx_bytes"] for peer in peers),
            "routes": bool(runtime.owned_routes),
        }

    async def health(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        info = self.context.store.parsed_runtime_info(metadata.id)
        allowed_ips = [str(item) for item in info.get("allowed_ips", [])]
        before = await self.status(metadata, runtime)
        interface = str(before.get("interface") or runtime.interface or interface_name(metadata.id))
        if not before.get("connected") or not before.get("tunnel"):
            return {**before, "healthy": False, "probe_succeeded": False}
        routes_present = await self.context.inspector.vpn_routes_present(interface, allowed_ips)
        if not routes_present:
            return {
                **before,
                "healthy": False,
                "probe_succeeded": False,
                "routes": False,
            }
        target = handshake_probe_target(allowed_ips)
        if not target:
            return {**before, "healthy": False, "probe_succeeded": False, "routes": True}
        family = "-6" if ":" in target else "-4"
        probe = await self.context.runner.run(
            ["ping", family, "-I", interface, "-c", "1", "-W", "3", target],
            check=False,
            timeout=5,
        )
        after = await self.status(metadata, runtime)
        handshake_advanced = int(after.get("latest_handshake", 0)) > int(before.get("latest_handshake", 0))
        received_traffic = int(after.get("rx_bytes", 0)) > int(before.get("rx_bytes", 0))
        transmitted_probe = int(after.get("tx_bytes", 0)) > int(before.get("tx_bytes", 0))
        healthy = bool(probe.returncode == 0 or after.get("handshake_fresh") or handshake_advanced or received_traffic)
        return {
            **after,
            "healthy": healthy,
            "probe_succeeded": probe.returncode == 0,
            "handshake_advanced": handshake_advanced,
            "rx_advanced": received_traffic,
            "tx_advanced": transmitted_probe,
            "routes": True,
        }
