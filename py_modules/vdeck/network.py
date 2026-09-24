"""Owned interface, route, DNS, firewall, and network inspection helpers."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import struct
import time
from collections.abc import Callable, Coroutine, Iterable
from dataclasses import dataclass
from typing import Any

from .dns import DnsManager  # noqa: F401 - compatibility export for backends
from .errors import VDeckError
from .runner import CommandRunner

LOGGER = logging.getLogger(__name__)


async def first_success(probes: Iterable[Coroutine[Any, Any, bool]]) -> bool:
    """Return on a successful bounded probe; close all losers before returning."""
    tasks = [asyncio.create_task(probe) for probe in probes]
    try:
        for result in asyncio.as_completed(tasks):
            if await result:
                return True
        return False
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


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
    metric: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class NetworkInspector:
    def __init__(self, runner: CommandRunner):
        self.runner = runner

    async def interface_exists(self, name: str) -> bool:
        result = await self.runner.run(["ip", "link", "show", "dev", name], check=False, timeout=3)
        return result.returncode == 0

    async def interface_ready(self, name: str, addresses: list[str]) -> bool:
        result = await self.runner.run(["ip", "-o", "address", "show", "dev", name], check=False, timeout=3)
        link = await self.runner.run(["ip", "-o", "link", "show", "dev", name], check=False, timeout=3)
        flags = re.search(r"<([^>]+)>", link.stdout)
        present = set(re.findall(r"\binet6?\s+(\S+)", result.stdout))
        return bool(
            result.returncode == link.returncode == 0
            and flags
            and "UP" in flags[1].split(",")
            and {str(ipaddress.ip_interface(value)) for value in addresses} <= present
        )

    async def tcp_probe(self, interface: str, address: str) -> bool:
        # Numeric-only destination: no system DNS request or proxy bypass. Use
        # a cancellable socket rather than a worker that can outlive Disconnect.
        target = str(ipaddress.ip_address(address))
        logger = getattr(self.runner, "logger", None) or LOGGER
        started = time.monotonic()
        code, stage, exception, errno = "PROBE_CANCELLED", "BIND", None, None
        try:
            family = socket.AF_INET6 if ":" in target else socket.AF_INET
            bind_option = getattr(socket, "SO_BINDTODEVICE", None)
            if bind_option is None:
                code = "PROBE_BIND_UNSUPPORTED"
                return False
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.setblocking(False)
                client.setsockopt(socket.SOL_SOCKET, bind_option, interface.encode() + b"\x00")
                stage = "CONNECT"
                await asyncio.wait_for(asyncio.get_running_loop().sock_connect(client, (target, 443)), 4)
                code = "OK"
                return True
        except (asyncio.TimeoutError, OSError, AttributeError) as exc:
            exception, errno = type(exc).__name__, getattr(exc, "errno", None)
            code = "PROBE_TCP_TIMEOUT" if isinstance(exc, asyncio.TimeoutError | TimeoutError) else "PROBE_TCP_FAILED"
            return False
        finally:
            logger.info(
                "traffic probe stage=%s method=TCP target=%s port=443 interface=%s "
                "code=%s exception=%s errno=%s elapsed_ms=%d",
                stage,
                target,
                interface,
                code,
                exception,
                errno,
                int((time.monotonic() - started) * 1000),
            )

    async def dns_probe(self, interface: str, servers: list[str]) -> bool:
        # Only the already route-verified numeric resolvers; no host DNS fallback.
        targets = list(dict.fromkeys(str(ipaddress.ip_address(server)) for server in servers[:3]))
        for attempt in (1, 2):
            if await first_success(self._dns_attempt(interface, server, attempt) for server in targets):
                return True
            if attempt == 1 and targets:
                await asyncio.sleep(0.25)
        return False

    async def _dns_attempt(self, interface: str, server: str, attempt: int) -> bool:
        logger = getattr(self.runner, "logger", None) or LOGGER
        started = time.monotonic()
        code, stage, exception, errno = "DNS_PROBE_CANCELLED", "BIND", None, None
        rcode, answers = None, None
        try:
            bind_option = getattr(socket, "SO_BINDTODEVICE", None)
            if bind_option is None:
                code = "DNS_BIND_UNSUPPORTED"
                return False
            family = socket.AF_INET6 if ":" in server else socket.AF_INET
            identifier = os.urandom(2)
            query = identifier + struct.pack("!HHHHH", 0x100, 1, 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"
            with socket.socket(family, socket.SOCK_DGRAM) as client:
                client.setblocking(False)
                client.setsockopt(socket.SOL_SOCKET, bind_option, interface.encode() + b"\x00")
                stage = "CONNECT"
                client.connect((server, 53))

                async def exchange() -> bytes:
                    nonlocal stage
                    loop = asyncio.get_running_loop()
                    stage = "SEND"
                    await loop.sock_sendall(client, query)
                    stage = "RECEIVE"
                    return await loop.sock_recv(client, 4096)

                reply = await asyncio.wait_for(exchange(), 3)
                stage = "VALIDATE"
                code = "DNS_RESPONSE_INVALID"
                if len(reply) >= 12 and reply[:2] == identifier:
                    flags, _, answers = struct.unpack("!HHH", reply[2:8])
                    rcode = flags & 0x000F
                    if flags & 0x8000 and not flags & 0x7A00 and not rcode and answers:
                        code = "OK"
                        return True
                    code = "DNS_RESPONSE_ERROR" if rcode else "DNS_RESPONSE_INVALID"
            return False
        except (asyncio.TimeoutError, OSError, AttributeError) as exc:
            exception, errno = type(exc).__name__, getattr(exc, "errno", None)
            code = "DNS_PROBE_TIMEOUT" if isinstance(exc, asyncio.TimeoutError | TimeoutError) else "DNS_PROBE_FAILED"
            return False
        finally:
            logger.info(
                "DNS probe stage=%s method=UDP server=%s interface=%s attempt=%d "
                "code=%s exception=%s errno=%s rcode=%s answers=%s elapsed_ms=%d",
                stage,
                server,
                interface,
                attempt,
                code,
                exception,
                errno,
                rcode,
                answers,
                int((time.monotonic() - started) * 1000),
            )

    async def resolve_endpoint(self, endpoint: str) -> list[str]:
        host = endpoint_host(endpoint)
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            pass
        try:
            answers = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, None), 12)
            return sorted({str(item[4][0]) for item in answers})
        except asyncio.TimeoutError as exc:
            raise VDeckError("ENDPOINT_RESOLVE_TIMEOUT", "VPN endpoint DNS lookup timed out") from exc
        except socket.gaierror as exc:
            raise VDeckError("ENDPOINT_RESOLVE_FAILED", f"Unable to resolve VPN endpoint: {host}") from exc

    async def system_dns_servers(self) -> list[str]:
        """Read current resolver destinations without performing an external lookup."""
        outputs = []
        for args in (["resolvectl", "dns"], ["nmcli", "--escape", "no", "-g", "IP4.DNS,IP6.DNS", "device", "show"]):
            try:
                result = await self.runner.run(args, check=False, timeout=3)
                if result.returncode == 0:
                    outputs.append(result.stdout)
            except (OSError, VDeckError):
                continue
        servers: list[str] = []
        for token in re.split(r"\s+", "\n".join(outputs)):
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

    async def tunnel_mtu(self, endpoints: list[str], explicit: int | None, *, ipv6: bool) -> int:
        """Use the endpoint route/link MTU minus WG encapsulation, as wg-quick does."""
        if explicit is not None:
            return explicit
        limits: list[int] = []
        for address in endpoints:
            family = "-6" if ipaddress.ip_address(address).version == 6 else "-4"
            route = await self.runner.run(["ip", family, "route", "get", address], check=False, timeout=3)
            if route.returncode:
                continue
            mtu = re.search(r"\bmtu\s+(?:lock\s+)?(\d+)", route.stdout)
            if mtu:
                limits.append(int(mtu[1]))
            device = re.search(r"\bdev\s+(\S+)", route.stdout)
            if device:
                link = await self.runner.run(["ip", "link", "show", "dev", device[1]], check=False, timeout=3)
                link_mtu = re.search(r"\bmtu\s+(\d+)", link.stdout)
                if link.returncode == 0 and link_mtu:
                    limits.append(int(link_mtu[1]))
        mtu_value = min(limits) - 80 if limits else 1420
        if mtu_value < (1280 if ipv6 else 576):
            raise VDeckError("TUNNEL_MTU_UNSUPPORTED", "Underlay MTU is too small for the configured tunnel family")
        LOGGER.info(
            "tunnel MTU selected mtu=%d source=%s ipv6=%s",
            mtu_value,
            "endpoint-route/link" if limits else "fallback",
            ipv6,
        )
        return mtu_value

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
            elif str(network) not in output.split() and not (
                network.prefixlen == network.max_prefixlen and str(network.network_address) in output.split()
            ):
                return False
            # Presence alone is not sufficient: policy routing / a lower metric
            # route could send actual traffic elsewhere.
            target = str(next(network.hosts(), network.network_address))
            if network.prefixlen == 0:
                target = "1.1.1.1" if network.version == 4 else "2606:4700:4700::1111"
            _, device = await self.route_to(target)
            if device != interface:
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
        on_record: Callable[[RouteRecord], None] | None = None,
        dns_servers: list[str] | None = None,
    ) -> list[RouteRecord]:
        records: list[RouteRecord] = []
        resolved_addresses = endpoint_addresses
        if resolved_addresses is None:
            resolved_addresses = []
            for endpoint in endpoints:
                resolved_addresses.extend(await self.inspector.resolve_endpoint(endpoint))
        for address in dict.fromkeys(resolved_addresses):
            gateway, device = await self.inspector.route_to(address)
            if not device or device.startswith(("vdeck-", "vdns-")):
                raise VDeckError("ENDPOINT_ROUTE_INVALID", "VPN endpoint has no physical-network route")
            family = ipaddress.ip_address(address).version
            prefix = f"{address}/{'128' if family == 6 else '32'}"
            existing = await self.runner.run(["ip", f"-{family}", "route", "show", "exact", prefix], timeout=5)
            if existing.stdout.strip():
                continue  # an existing host route already pins the endpoint; never replace/delete it
            args = ["ip", f"-{family}", "route", "add", prefix]
            if gateway:
                args += ["via", gateway]
            if device:
                args += ["dev", device]
            args += ["proto", "186"]
            record = RouteRecord(family, prefix, interface, gateway, device)
            if on_record:
                on_record(record)  # write-ahead: a crash during ip must still be recoverable
            records.append(record)
            await self.runner.run(args, timeout=5)
        installed: set[tuple[int, str]] = set()
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
                if (family, prefix) in installed:
                    continue
                installed.add((family, prefix))
                record = RouteRecord(family, prefix, interface, metric=4)
                if on_record:
                    on_record(record)
                records.append(record)
                await self.runner.run(
                    ["ip", f"-{family}", "route", "add", prefix, "dev", interface, "proto", "186", "metric", "4"],
                    timeout=5,
                )
        # A connected LAN route is more specific than full-tunnel /1 routes.
        # Explicit VPN DNS must use the VPN even if its subnet overlaps Wi-Fi.
        for server in dns_servers or []:
            _, device = await self.inspector.route_to(server)
            if device == interface:
                continue
            if server in resolved_addresses:
                raise VDeckError("DNS_ENDPOINT_CONFLICT", "DNS and VPN endpoint require conflicting host routes")
            dns_address = ipaddress.ip_address(server)
            prefix = f"{dns_address}/{dns_address.max_prefixlen}"
            record = RouteRecord(dns_address.version, prefix, interface, metric=4)
            if on_record:
                on_record(record)
            records.append(record)
            await self.runner.run(
                [
                    "ip",
                    f"-{dns_address.version}",
                    "route",
                    "add",
                    prefix,
                    "dev",
                    interface,
                    "proto",
                    "186",
                    "metric",
                    "4",
                ],
                timeout=5,
            )
        return records

    async def cleanup(self, records: list[dict[str, Any]]) -> None:
        failed = False
        for record in reversed(records):
            args = ["ip", f"-{int(record['family'])}", "route", "del", str(record["prefix"])]
            if record.get("gateway"):
                args += ["via", str(record["gateway"])]
            if record.get("device"):
                args += ["dev", str(record["device"])]
            elif record.get("interface"):
                args += ["dev", str(record["interface"])]
            args += ["proto", "186"]
            if record.get("metric") is not None:
                args += ["metric", str(record["metric"])]
            try:
                result = await self.runner.run(args, check=False, timeout=5)
                if result.returncode and not any(word in result.stderr for word in ("No such", "Cannot find")):
                    failed = True
            except (OSError, VDeckError):
                failed = True
        if failed:
            raise VDeckError("ROUTE_RESTORE_FAILED", "Some owned routes could not be removed; cleanup journal retained")


class FirewallManager:
    TABLE = "vdeck"
    OWNER_MARKER = "vdeck-owned:org.vdeck:v1"
    LEGACY_MARKER = 'comment "vdeck-owned"'

    def __init__(self, runner: CommandRunner):
        self.runner = runner

    async def _table_state(self) -> str:
        result = await self.runner.run(["nft", "list", "table", "inet", self.TABLE], check=False, timeout=3)
        if result.returncode != 0:
            if "No such" in result.stderr:
                return "absent"
            raise VDeckError("FIREWALL_INSPECTION_FAILED", "Cannot inspect kill switch ownership")
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
            # Do not exempt all established flows: they can leak on the physical
            # interface after a route/tunnel disappears.
            "add rule inet vdeck output meta l4proto ipv6-icmp icmpv6 type "
            f'{{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }} accept comment "{self.OWNER_MARKER}"',
            f'add rule inet vdeck output udp sport 68 udp dport 67 accept comment "{self.OWNER_MARKER}"',
            "add rule inet vdeck output ip6 daddr ff02::1:2 udp sport 546 udp dport 547 "
            f'accept comment "{self.OWNER_MARKER}"',
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
        await self.runner.run(["nft", "delete", "table", "inet", self.TABLE], timeout=5)
        return True

    async def active(self) -> bool:
        return await self._table_state() == "owned"


class Ipv6Guard:
    """Prevent IPv6 bypass for an IPv4-only full tunnel, independent of KS."""

    def __init__(self, runner: CommandRunner):
        self.runner = runner

    async def cleanup(self) -> None:
        current = await self.runner.run(["nft", "list", "table", "inet", "vdeck_ipv6"], check=False, timeout=3)
        if current.returncode:
            if "No such" in current.stderr:
                return
            raise VDeckError("IPV6_GUARD_FAILED", "Cannot inspect IPv6 protection")
        if FirewallManager.OWNER_MARKER not in current.stdout:
            raise VDeckError("FIREWALL_OWNERSHIP_CONFLICT", "IPv6 guard table is not owned by V-Deck")
        await self.runner.run(["nft", "delete", "table", "inet", "vdeck_ipv6"], timeout=5)

    async def enable(self, interface: str, endpoints: list[str], *, allow_tunnel: bool = True) -> None:
        await self.cleanup()
        rules = [
            f'add table inet vdeck_ipv6 {{ comment "{FirewallManager.OWNER_MARKER}"; }}',
            "add chain inet vdeck_ipv6 output { type filter hook output priority -90; policy accept; }",
            'add rule inet vdeck_ipv6 output oifname "lo" accept',
            "add rule inet vdeck_ipv6 output meta l4proto ipv6-icmp icmpv6 type "
            "{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept",
            "add rule inet vdeck_ipv6 output ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept",
        ]
        if allow_tunnel:
            rules.append(f'add rule inet vdeck_ipv6 output oifname "{interface}" accept')
        for address in endpoints:
            if ipaddress.ip_address(address).version == 6:
                rules.append(f"add rule inet vdeck_ipv6 output ip6 daddr {address} accept")
        rules.append("add rule inet vdeck_ipv6 output meta nfproto ipv6 reject")
        await self.runner.run(["nft", "-f", "-"], input_text="\n".join(rules) + "\n", timeout=5)
