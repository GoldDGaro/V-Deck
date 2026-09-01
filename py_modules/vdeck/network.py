"""Owned interface, route, DNS, firewall, and network inspection helpers."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass
from typing import Any

from .errors import VDeckError
from .runner import CommandRunner

LOGGER = logging.getLogger(__name__)


def interface_name(connection_id: str) -> str:
    compact = connection_id.replace("-", "")[:8].lower()
    if not re.fullmatch(r"[0-9a-f]{8}", compact):
        raise VDeckError("CONNECTION_ID_INVALID", "Invalid connection identifier")
    return f"vdeck-{compact}"


def endpoint_host(value: str) -> str:
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if value.startswith("["):
        return value[1 : value.find("]")]
    return value.rsplit(":", 1)[0]


@dataclass
class RouteRecord:
    family: int
    prefix: str
    interface: str
    gateway: str | None = None
    device: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class NetworkInspector:
    def __init__(self, runner: CommandRunner):
        self.runner = runner

    async def interface_exists(self, name: str) -> bool:
        result = await self.runner.run(["ip", "link", "show", "dev", name], check=False, timeout=3)
        return result.returncode == 0

    async def resolve_endpoint(self, endpoint: str) -> list[str]:
        host = endpoint_host(endpoint)
        try:
            return sorted(
                {item[4][0] for item in await __import__("asyncio").to_thread(socket.getaddrinfo, host, None)}
            )
        except socket.gaierror as exc:
            raise VDeckError("ENDPOINT_RESOLVE_FAILED", f"Unable to resolve VPN endpoint: {host}") from exc

    async def system_dns_servers(self) -> list[str]:
        """Read current resolver destinations without performing an external lookup."""
        result = await self.runner.run(["resolvectl", "dns"], check=False, timeout=3)
        if result.returncode != 0:
            return []
        servers: list[str] = []
        for token in re.split(r"\s+", result.stdout):
            candidate = token.strip("[](),")
            try:
                address = str(ipaddress.ip_address(candidate.split("%", 1)[0]))
            except ValueError:
                continue
            if not ipaddress.ip_address(address).is_loopback and address not in servers:
                servers.append(address)
        return servers

    async def route_to(self, address: str) -> tuple[str | None, str | None]:
        family = "-6" if ipaddress.ip_address(address).version == 6 else "-4"
        result = await self.runner.run(["ip", family, "route", "get", address], check=False, timeout=3)
        if result.returncode != 0:
            return None, None
        via = re.search(r"\bvia\s+(\S+)", result.stdout)
        dev = re.search(r"\bdev\s+(\S+)", result.stdout)
        return (via.group(1) if via else None, dev.group(1) if dev else None)

    async def public_ipv6_present(self) -> bool:
        result = await self.runner.run(["ip", "-6", "addr", "show", "scope", "global"], check=False, timeout=3)
        return bool(re.search(r"\binet6\s+(?!f[cd])[0-9a-f:]", result.stdout, re.IGNORECASE))

    async def vpn_routes_present(self, interface: str, configured_routes: list[str]) -> bool:
        outputs: dict[int, str] = {}
        for family in (4, 6):
            result = await self.runner.run(
                ["ip", f"-{family}", "route", "show", "dev", interface], check=False, timeout=3
            )
            outputs[family] = result.stdout
        if not configured_routes:
            return any(value.strip() for value in outputs.values())
        for raw in configured_routes:
            network = ipaddress.ip_network(raw, strict=False)
            output = outputs[network.version]
            if network.prefixlen == 0:
                halves = [str(item) for item in network.subnets(prefixlen_diff=1)]
                if not (re.search(r"(?m)^default\b", output) or all(prefix in output for prefix in halves)):
                    return False
            elif str(network) not in output:
                return False
        return True


class RouteManager:
    def __init__(self, runner: CommandRunner, inspector: NetworkInspector):
        self.runner = runner
        self.inspector = inspector

    async def apply(
        self,
        interface: str,
        allowed_ips: list[str],
        endpoints: list[str],
        endpoint_addresses: list[str] | None = None,
    ) -> list[RouteRecord]:
        records: list[RouteRecord] = []
        resolved_addresses = endpoint_addresses
        if resolved_addresses is None:
            resolved_addresses = []
            for endpoint in endpoints:
                resolved_addresses.extend(await self.inspector.resolve_endpoint(endpoint))
        for address in dict.fromkeys(resolved_addresses):
            gateway, device = await self.inspector.route_to(address)
            family = ipaddress.ip_address(address).version
            prefix = f"{address}/{'128' if family == 6 else '32'}"
            args = ["ip", f"-{family}", "route", "replace", prefix]
            if gateway:
                args += ["via", gateway]
            if device:
                args += ["dev", device]
            args += ["proto", "186"]
            await self.runner.run(args, timeout=5)
            records.append(RouteRecord(family, prefix, interface, gateway, device))
        for raw in allowed_ips:
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                raise VDeckError("CONFIG_INVALID_ROUTE", f"Invalid AllowedIPs entry: {raw}") from exc
            prefixes = [str(network)]
            if network.prefixlen == 0:
                prefixes = [str(item) for item in network.subnets(prefixlen_diff=1)]
            for prefix in prefixes:
                family = ipaddress.ip_network(prefix).version
                await self.runner.run(
                    ["ip", f"-{family}", "route", "replace", prefix, "dev", interface, "proto", "186", "metric", "4"],
                    timeout=5,
                )
                records.append(RouteRecord(family, prefix, interface))
        return records

    async def cleanup(self, records: list[dict[str, Any]]) -> None:
        for record in reversed(records):
            args = ["ip", f"-{int(record['family'])}", "route", "del", str(record["prefix"])]
            if record.get("gateway"):
                args += ["via", str(record["gateway"])]
            if record.get("device"):
                args += ["dev", str(record["device"])]
            elif record.get("interface"):
                args += ["dev", str(record["interface"])]
            args += ["proto", "186"]
            await self.runner.run(args, check=False, timeout=5)


class DnsManager:
    def __init__(self, runner: CommandRunner):
        self.runner = runner

    async def apply(self, interface: str, servers: list[str], full_tunnel: bool) -> None:
        if not servers:
            return
        result = await self.runner.run(["resolvectl", "dns", interface, *servers], check=False, timeout=5)
        if result.returncode != 0:
            raise VDeckError("DNS_UNAVAILABLE", "systemd-resolved could not apply VPN DNS settings", result.stderr)
        if full_tunnel:
            await self.runner.run(["resolvectl", "domain", interface, "~."], timeout=5)

    async def cleanup(self, interface: str | None) -> None:
        if interface:
            await self.runner.run(["resolvectl", "revert", interface], check=False, timeout=5)


class FirewallManager:
    TABLE = "vdeck"
    OWNER_MARKER = "vdeck-owned:org.vdeck:v1"
    LEGACY_MARKER = 'comment "vdeck-owned"'

    def __init__(self, runner: CommandRunner):
        self.runner = runner

    async def _table_state(self) -> str:
        result = await self.runner.run(["nft", "list", "table", "inet", self.TABLE], check=False, timeout=3)
        if result.returncode != 0:
            return "absent"
        current = f'comment "{self.OWNER_MARKER}"'
        if current in result.stdout or self.LEGACY_MARKER in result.stdout:
            return "owned"
        return "foreign"

    async def enable(
        self,
        interface: str,
        endpoint_addresses: list[str],
        recovery_dns_addresses: list[str] | None = None,
    ) -> None:
        table_state = await self._table_state()
        if table_state == "foreign":
            raise VDeckError(
                "FIREWALL_OWNERSHIP_CONFLICT",
                "A firewall table named vdeck exists without the V-Deck ownership marker",
            )
        if interface and not re.fullmatch(r"vdeck-[0-9a-f]{8}", interface):
            raise VDeckError("FIREWALL_INTERFACE_INVALID", "Refusing to create firewall rules for an unknown interface")
        lines = []
        if table_state == "owned":
            lines.append("delete table inet vdeck")
        lines += [
            f'add table inet vdeck {{ comment "{self.OWNER_MARKER}"; }}',
            "add chain inet vdeck output { type filter hook output priority -100; policy accept; }",
            f'add rule inet vdeck output oifname "lo" accept comment "{self.OWNER_MARKER}"',
            f'add rule inet vdeck output ct state established,related accept comment "{self.OWNER_MARKER}"',
        ]
        if interface:
            lines.append(f'add rule inet vdeck output oifname "{interface}" accept comment "{self.OWNER_MARKER}"')
        for address in dict.fromkeys(endpoint_addresses):
            family = ipaddress.ip_address(address).version
            selector = "ip6 daddr" if family == 6 else "ip daddr"
            lines.append(f'add rule inet vdeck output {selector} {address} accept comment "vdeck-endpoint"')
        for address in dict.fromkeys(recovery_dns_addresses or []):
            family = ipaddress.ip_address(address).version
            selector = "ip6 daddr" if family == 6 else "ip daddr"
            for protocol in ("udp", "tcp"):
                lines.append(
                    f"add rule inet vdeck output {selector} {address} {protocol} dport 53 "
                    'accept comment "vdeck-recovery-dns"'
                )
        lines += [
            'add rule inet vdeck output meta nfproto ipv4 reject comment "vdeck-killswitch"',
            'add rule inet vdeck output meta nfproto ipv6 reject comment "vdeck-killswitch"',
        ]
        await self.runner.run(["nft", "-f", "-"], input_text="\n".join(lines) + "\n", timeout=5)

    async def disable(self) -> bool:
        table_state = await self._table_state()
        if table_state == "absent":
            return False
        if table_state == "foreign":
            LOGGER.warning("Refusing to delete unowned nftables table inet vdeck")
            return False
        await self.runner.run(["nft", "delete", "table", "inet", self.TABLE], check=False, timeout=5)
        return True

    async def active(self) -> bool:
        return await self._table_state() == "owned"
