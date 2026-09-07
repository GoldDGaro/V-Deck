"""WireGuard backend with kernel-first and bundled userspace fallback."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import stat
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from ..errors import VDeckError
from ..logging_utils import safe_exception_details
from ..models import ConnectionMetadata, RuntimeState
from ..network import Ipv6Guard, RouteRecord, interface_name
from ..parsers import ParsedConfig, validate_wireguard_network
from ..runner import OwnedProcess
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
    uapi_directory = Path("/var/run/wireguard")
    startup_timeout = 5.0

    @property
    def logger(self) -> logging.Logger:
        return self.context.store.logger or logging.getLogger(__name__)

    def _stage(self, runtime: RuntimeState, stage: str) -> None:
        runtime.stage = stage
        self.context.store.save_runtime(runtime)
        self.logger.info("connect stage=%s protocol=%s interface=%s", stage, self.protocol_id, runtime.interface)

    def _uapi_path(self, interface: str) -> Path:
        return self.uapi_directory / f"{interface}.sock"

    def _socket_identity(self, path: Path) -> list[int] | None:
        try:
            value = path.lstat()
        except FileNotFoundError:
            return None
        return [value.st_dev, value.st_ino] if stat.S_ISSOCK(value.st_mode) else None

    def _remember_socket(self, runtime: RuntimeState, path: Path) -> None:
        identity = self._socket_identity(path)
        if identity and "uapi_identity" not in runtime.process:
            runtime.process["uapi_identity"] = identity
            self.context.store.save_runtime(runtime)

    async def _uapi_ready(self, path: Path) -> bool:
        if sys.platform == "win32":
            # The shipped backend is Linux-only; Windows tests mock this OS boundary.
            return False
        if not self._socket_identity(path):
            return False
        try:
            _, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(path)), 0.25)
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    async def _startup_failure(self, interface: str, runtime: RuntimeState, code: str) -> None:
        path = self._uapi_path(interface)
        self._remember_socket(runtime, path)
        interface_exists: bool | str = "unknown"
        with suppress(OSError, VDeckError):
            interface_exists = await self.context.inspector.interface_exists(interface)
        owned = None
        with suppress(KeyError, TypeError, ValueError):
            owned = OwnedProcess.from_dict(runtime.process)
        self.logger.info(
            "%s binary=%s interface=%s pid=%s exit_code=%s interface_exists=%s uapi_exists=%s code=%s",
            "process exited" if code in {"PROCESS_START_FAILED", "PROCESS_EXITED"} else "userspace startup failed",
            self.userspace_name,
            interface,
            owned.pid if owned else "unknown",
            self.context.runner.exit_code(owned) if owned else "unknown",
            interface_exists,
            self._socket_identity(path) is not None,
            code,
        )

    async def _create_interface(self, interface: str, runtime: RuntimeState, log_path: Path) -> None:
        if not self.force_userspace:
            kernel = await self.context.runner.run(
                ["ip", "link", "add", "dev", interface, "type", "wireguard"], check=False, timeout=5
            )
            if kernel.returncode == 0:
                self.logger.info("backend selected protocol=wireguard backend=kernel interface=%s", interface)
                return
            self.logger.info("kernel unavailable exit_code=%s; selecting wireguard-go", kernel.returncode)
        args = self.context.binaries.command(self.userspace_name, "--foreground", interface)
        # Upstream checks ENV before parsing --foreground when printing its
        # unconditional Linux banner. Blank inherited FD variables prevent an
        # unrelated Decky environment from selecting daemon-child descriptors.
        env = {
            "WG_PROCESS_FOREGROUND": "1",
            "WG_TUN_FD": "",
            "WG_UAPI_FD": "",
            "WG_TUN_NAME_FILE": "",
            "LOG_LEVEL": "error",
        }
        self.logger.info(
            "starting userspace backend binary=%s interface=%s foreground=true command=%s env=%s",
            self.userspace_name,
            interface,
            args,
            env,
        )

        def on_started(process: OwnedProcess) -> None:
            runtime.process = process.to_dict()
            self.context.store.save_runtime(runtime)
            self.logger.info(
                "userspace process owned binary=%s interface=%s pid=%s foreground=true",
                self.userspace_name,
                interface,
                process.pid,
            )

        try:
            process = await self.context.runner.start(
                args, env=env, stdout_path=log_path, on_started=on_started, bundled=True
            )
            self.logger.info(
                "startup process alive binary=%s interface=%s pid=%s", self.userspace_name, interface, process.pid
            )
            path = self._uapi_path(interface)
            deadline = asyncio.get_running_loop().time() + self.startup_timeout
            interface_exists = False
            while asyncio.get_running_loop().time() < deadline:
                self._remember_socket(runtime, path)
                if not self.context.runner.is_alive(process):
                    raise VDeckError("PROCESS_START_FAILED", f"{self.userspace_name} exited during startup")
                interface_exists = await self.context.inspector.interface_exists(interface)
                if interface_exists and await self._uapi_ready(path):
                    if not self.context.runner.is_alive(process):
                        raise VDeckError("PROCESS_START_FAILED", f"{self.userspace_name} exited during startup")
                    self.logger.info(
                        "UAPI ready binary=%s interface=%s pid=%s", self.userspace_name, interface, process.pid
                    )
                    return
                await asyncio.sleep(0.1)
            code = "UAPI_NOT_READY" if interface_exists else "INTERFACE_CREATE_FAILED"
            raise VDeckError(code, "Userspace VPN startup readiness timed out")
        except (Exception, asyncio.CancelledError) as exc:
            await self._startup_failure(
                interface, runtime, exc.code if isinstance(exc, VDeckError) else type(exc).__name__
            )
            raise

    async def start(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        self._stage(runtime, "VALIDATE")
        directory = self.connection_dir(metadata)
        info = self.context.store.parsed_runtime_info(metadata.id)
        normalized = validate_wireguard_network(
            ParsedConfig(
                protocol=self.protocol_id,
                runtime_config="",
                source_format=metadata.source_format,
                interface_addresses=info.get("interface_addresses", []),
                dns_servers=info.get("dns_servers", []),
                allowed_ips=info.get("allowed_ips", []),
                endpoints=info.get("endpoints", []),
                mtu=info.get("mtu"),
            )
        )
        info.update(
            interface_addresses=normalized.interface_addresses,
            allowed_ips=normalized.allowed_ips,
            dns_servers=normalized.dns_servers,
        )
        addresses = list(info.get("interface_addresses", []))
        allowed_ips = list(info.get("allowed_ips", []))
        dns_servers = list(info.get("dns_servers", []))
        if not addresses or not allowed_ips:
            raise VDeckError("TUNNEL_ADDRESS_MISSING", "The VPN needs interface addresses and AllowedIPs")
        networks = [ipaddress.ip_network(value, strict=False) for value in allowed_ips]
        if any(not any(ipaddress.ip_address(server) in network for network in networks) for server in dns_servers):
            raise VDeckError("DNS_ROUTE_MISSING", "Configured VPN DNS must be reachable within AllowedIPs")
        self._stage(runtime, "ENDPOINT")
        endpoint_cache = await self.resolve_endpoint_cache(metadata, runtime)
        selected_endpoints: dict[str, list[str]] = {}
        for endpoint, candidates in endpoint_cache.items():
            # A hostname may have AAAA records on an IPv4-only Wi-Fi. Pin only
            # a usable endpoint, not every DNS answer (which made Connect fail
            # while adding a route to an unreachable alternate address).
            for candidate in sorted(candidates, key=lambda value: ipaddress.ip_address(value).version):
                _, device = await self.context.inspector.route_to(candidate)
                if device and not device.startswith(("vdeck-", "vdns-")):
                    selected_endpoints[endpoint] = [candidate]
                    break
            if endpoint not in selected_endpoints:
                raise VDeckError("ENDPOINT_ROUTE_INVALID", "VPN endpoint has no physical-network route")
        runtime.endpoint_cache = endpoint_cache = selected_endpoints
        self.context.store.save_runtime(runtime)
        resolved_config = resolved_wireguard_config((directory / "config").read_text(encoding="utf-8"), endpoint_cache)
        interface = interface_name(metadata.id)
        # Refuse resources we did not create in this attempt. In particular,
        # upstream UAPIOpen may otherwise unlink an unrelated/stale socket.
        path = self._uapi_path(interface)
        if await self.context.inspector.interface_exists(interface) or path.exists() or path.is_symlink():
            raise VDeckError(
                "INTERFACE_ALREADY_EXISTS", "Refusing to replace a pre-existing VPN interface or UAPI socket"
            )
        runtime.interface = interface
        self.context.store.save_runtime(runtime)
        try:
            self._stage(runtime, "PROCESS")
            await self._create_interface(interface, runtime, self.context.store.logs / f"{metadata.id}.log")
            self._stage(runtime, "SETCONF")
            await self.context.runner.run(
                self.context.binaries.command(self.tool_name, "setconf", interface, "/dev/stdin"),
                input_text=resolved_config,
                bundled=True,
            )
            if runtime.process and not self.context.runner.is_alive(OwnedProcess.from_dict(runtime.process)):
                await self._startup_failure(interface, runtime, "PROCESS_START_FAILED")
                raise VDeckError("PROCESS_START_FAILED", f"{self.userspace_name} exited during configuration")
            self.logger.info("VPN setconf succeeded protocol=%s interface=%s", self.protocol_id, interface)
            self._stage(runtime, "INTERFACE")
            for address in info.get("interface_addresses", []):
                family = "-6" if ":" in str(address) else "-4"
                await self.context.runner.run(["ip", family, "address", "replace", str(address), "dev", interface])
            mtu = info.get("mtu") or 1420
            await self.context.runner.run(["ip", "link", "set", "dev", interface, "mtu", str(mtu), "up"])
            self.logger.info("interface configured interface=%s addresses=%d mtu=%s", interface, len(addresses), mtu)
            if not await self.context.inspector.interface_ready(interface, addresses):
                raise VDeckError("TUNNEL_NOT_READY", "VPN interface is not up with the configured addresses")
            if "0.0.0.0/0" in allowed_ips and "::/0" not in allowed_ips:
                self._stage(runtime, "IPV6_GUARD")
                runtime.ipv6_guard = True
                self.context.store.save_runtime(runtime)
                await Ipv6Guard(self.context.runner).enable(interface, self.endpoint_addresses(runtime))

            def journal_route(record: RouteRecord) -> None:
                runtime.owned_routes.append(record.to_dict())
                self.context.store.save_runtime(runtime)

            self._stage(runtime, "ROUTE")
            await self.context.routes.apply(
                interface,
                list(info.get("allowed_ips", [])),
                list(info.get("endpoints", [])),
                self.endpoint_addresses(runtime),
                on_record=journal_route,
                dns_servers=dns_servers,
            )
            self.context.store.save_runtime(runtime)
            full = any(str(item) in {"0.0.0.0/0", "::/0"} for item in info.get("allowed_ips", []))
            self.logger.info("routes applied interface=%s owned_routes=%d", interface, len(runtime.owned_routes))
            self._stage(runtime, "DNS")
            await self.context.dns.apply(interface, list(info.get("dns_servers", [])), full)
            for server in dns_servers:
                _, device = await self.context.inspector.route_to(server)
                if device != interface:
                    raise VDeckError("DNS_ROUTE_MISSING", "System route to VPN DNS does not use the tunnel")
            self._stage(runtime, "HEALTH")
            await self._probe_handshake(interface, list(info.get("allowed_ips", [])))
            return await self.verify_connected(metadata, runtime)
        except (Exception, asyncio.CancelledError) as exc:
            self.logger.error(
                "connect failed stage=%s protocol=%s code=%s exception=%s details=%s",
                runtime.stage,
                self.protocol_id,
                getattr(exc, "code", type(exc).__name__),
                type(exc).__name__,
                safe_exception_details(exc),
            )
            try:
                await self.stop(metadata, runtime)
            except Exception as cleanup_error:
                self.logger.error(
                    "runtime cleanup pending code=%s", getattr(cleanup_error, "code", type(cleanup_error).__name__)
                )
            raise

    async def verify_connected(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        self._stage(runtime, "HEALTH")
        info = self.context.store.parsed_runtime_info(metadata.id)
        interface = runtime.interface or interface_name(metadata.id)
        if not await self.context.inspector.interface_ready(interface, list(info.get("interface_addresses", []))):
            raise VDeckError("TUNNEL_NOT_READY", "VPN interface is not up with the configured addresses")
        health = await self.health(metadata, runtime)
        if health.get("dns_error_code"):
            raise VDeckError(str(health["dns_error_code"]), str(health["dns_error_message"]))
        if not all(health.get(field) for field in ("connected", "healthy", "routes", "probe_succeeded")):
            self.logger.warning(
                "traffic verification failed stage=HEALTH code=VPN_TRAFFIC_UNCONFIRMED "
                "protocol=%s interface=%s connected=%s healthy=%s routes=%s probe_succeeded=%s "
                "handshake_present=%s firewall_active=%s",
                self.protocol_id,
                interface,
                bool(health.get("connected")),
                bool(health.get("healthy")),
                bool(health.get("routes")),
                bool(health.get("probe_succeeded")),
                bool(health.get("latest_handshake")),
                runtime.firewall_active,
            )
            raise VDeckError("VPN_TRAFFIC_UNCONFIRMED", "VPN traffic through the configured routes was not confirmed")
        self.logger.info(
            "VPN traffic confirmed protocol=%s interface=%s handshake_present=%s probe=%s firewall_active=%s",
            self.protocol_id,
            interface,
            bool(health.get("latest_handshake")),
            health.get("probe_succeeded"),
            runtime.firewall_active,
        )
        return health

    async def _probe_handshake(self, interface: str, allowed_ips: list[str]) -> None:
        target = handshake_probe_target(allowed_ips)
        if target:
            family = "-6" if ":" in target else "-4"
            try:
                await self.context.runner.run(
                    ["ping", family, "-I", interface, "-c", "1", "-W", "3", target], check=False, timeout=5
                )
            except (OSError, VDeckError):
                await self.context.inspector.tcp_probe(interface, target)
        deadline = asyncio.get_running_loop().time() + 18
        while asyncio.get_running_loop().time() < deadline:
            result = await self.context.runner.run(
                self.context.binaries.command(self.tool_name, "show", interface, "latest-handshakes"),
                check=False,
                timeout=3,
                bundled=True,
            )
            values = [line.rsplit("\t", 1)[-1].strip() for line in result.stdout.splitlines() if line.strip()]
            if any(value.isdigit() and int(value) > 0 for value in values):
                return
            await asyncio.sleep(0.5)
        raise VDeckError("HANDSHAKE_TIMEOUT", "VPN interface started, but no peer handshake was confirmed")

    async def stop(self, metadata: ConnectionMetadata | None, runtime: RuntimeState) -> None:
        # Terminate/reap the exact owned foreground PID before removing its
        # resources. Never pkill by name or signal an unchecked process group.
        self.logger.info("cleanup started protocol=%s interface=%s", self.protocol_id, runtime.interface)
        failures = []
        # DNS first, before deleting its interface. Every stage is attempted even
        # when an earlier one fails; retain ownership for a retry on failure.
        actions = [
            ("DNS restored", self.context.dns.cleanup(runtime.interface)),
            ("routes removed", self.context.routes.cleanup(runtime.owned_routes)),
        ]
        for label, action in actions:
            try:
                await action
                self.logger.info("%s interface=%s", label, runtime.interface)
            except Exception as exc:
                failures.append(exc)
        if runtime.process.get("pid"):
            try:
                await self.context.runner.stop(OwnedProcess.from_dict(runtime.process))
            except Exception as exc:
                failures.append(exc)
        if runtime.interface:
            try:
                await self.context.runner.run(
                    ["ip", "link", "delete", "dev", runtime.interface], check=False, timeout=5
                )
                if await self.context.inspector.interface_exists(runtime.interface):
                    failures.append(VDeckError("INTERFACE_STOP_FAILED", "Unable to remove VPN interface"))
                else:
                    self.logger.info("interface removed interface=%s", runtime.interface)
            except Exception as exc:
                failures.append(exc)
        if runtime.ipv6_guard:
            try:
                await Ipv6Guard(self.context.runner).cleanup()
                runtime.ipv6_guard = False
            except Exception as exc:
                failures.append(exc)
        if runtime.interface and runtime.process.get("uapi_identity"):
            path = self._uapi_path(runtime.interface)
            if self._socket_identity(path) == runtime.process["uapi_identity"]:
                path.unlink(missing_ok=True)
        if failures:
            self.context.store.save_runtime(runtime)
            for failure in failures:
                self.logger.error(
                    "cleanup failed stage=CLEANUP protocol=%s code=%s exception=%s details=%s",
                    self.protocol_id,
                    getattr(failure, "code", "CLEANUP_FAILED"),
                    type(failure).__name__,
                    safe_exception_details(failure),
                )
            self.logger.warning("cleanup pending failure_count=%d", len(failures))
            raise failures[0]
        runtime.process = {}
        runtime.owned_routes = []
        runtime.interface = None
        self.context.store.save_runtime(runtime)
        self.logger.info(
            "cleanup completed protocol=%s profile_still_exists=%s",
            self.protocol_id,
            metadata is not None and (self.connection_dir(metadata) / "metadata.json").is_file(),
        )

    async def status(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        interface = runtime.interface or interface_name(metadata.id)
        if runtime.process and not self.context.runner.is_alive(OwnedProcess.from_dict(runtime.process)):
            await self._startup_failure(interface, runtime, "PROCESS_EXITED")
            return {"connected": False, "tunnel": False, "interface": interface, "peers": 0}
        if not await self.context.inspector.interface_exists(interface):
            return {"connected": False, "tunnel": False, "interface": interface, "peers": 0}
        result = await self.context.runner.run(
            self.context.binaries.command(self.tool_name, "show", interface, "dump"),
            check=False,
            timeout=3,
            bundled=True,
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
        try:
            probe = await self.context.runner.run(
                ["ping", family, "-I", interface, "-c", "1", "-W", "3", target],
                check=False,
                timeout=5,
            )
            probe_succeeded = probe.returncode == 0
        except (OSError, VDeckError):
            probe_succeeded = False
        if not probe_succeeded:
            probe_succeeded = await self.context.inspector.tcp_probe(interface, target)
        after = await self.status(metadata, runtime)
        handshake_advanced = int(after.get("latest_handshake", 0)) > int(before.get("latest_handshake", 0))
        received_traffic = int(after.get("rx_bytes", 0)) > int(before.get("rx_bytes", 0))
        transmitted_probe = int(after.get("tx_bytes", 0)) > int(before.get("tx_bytes", 0))
        healthy = bool(after.get("connected") and (probe_succeeded or handshake_advanced or received_traffic))
        dns_error: VDeckError | None = None
        if healthy:
            try:
                await self._verify_dns(metadata, runtime)
            except VDeckError as exc:
                dns_error = exc
                healthy = False
        if healthy and not await self.context.inspector.vpn_routes_present(interface, allowed_ips):
            healthy = False
            probe_succeeded = False
        return {
            **after,
            "healthy": healthy,
            "probe_succeeded": probe_succeeded,
            "handshake_advanced": handshake_advanced,
            "rx_advanced": received_traffic,
            "tx_advanced": transmitted_probe,
            "routes": True,
            "dns_error_code": dns_error.code if dns_error else None,
            "dns_error_message": dns_error.message if dns_error else None,
        }
