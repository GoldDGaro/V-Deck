"""Protocol backend contract."""

from __future__ import annotations

import ipaddress
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..binaries import BinaryManager
from ..errors import VDeckError
from ..models import ConnectionMetadata, RuntimeState
from ..network import DnsManager, NetworkInspector, RouteManager, interface_name
from ..runner import CommandRunner
from ..storage import VDeckStore


@dataclass
class BackendContext:
    store: VDeckStore
    binaries: BinaryManager
    runner: CommandRunner
    inspector: NetworkInspector
    routes: RouteManager
    dns: DnsManager


class VPNBackend(ABC):
    protocol_id: str

    def __init__(self, context: BackendContext):
        self.context = context

    @property
    def logger(self) -> logging.Logger:
        return self.context.store.logger or logging.getLogger(__name__)

    async def _verify_dns(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> None:
        info = self.context.store.parsed_runtime_info(metadata.id)
        servers = list(info.get("dns_servers", []))
        configured = bool(servers)
        interface = runtime.interface or interface_name(metadata.id)
        if configured:
            if not await self.context.dns.healthy(interface):
                raise VDeckError("DNS_VERIFY_FAILED", "The system resolver no longer uses VPN DNS")
        else:
            servers = await self.context.dns.unmodified_servers()
        require_tunnel = (
            configured
            or self.context.store.load_state().kill_switch
            or any(route in {"0.0.0.0/0", "::/0"} for route in info.get("allowed_ips", []))
        )
        destinations: dict[str, list[str]] = {}
        for server in servers:
            _, device = await self.context.inspector.route_to(server)
            if not device or (require_tunnel and device != interface):
                raise VDeckError(
                    "DNS_ROUTE_MISSING" if configured else "DNS_CONFIGURATION_REQUIRED",
                    "DNS route could not be verified; configure DNS reachable through the VPN",
                )
            destinations.setdefault(device, []).append(server)
        answered = False
        for device, addresses in destinations.items():
            answered = await self.context.inspector.dns_probe(device, addresses) or answered
        if not answered:
            raise VDeckError("DNS_PROBE_FAILED", "DNS did not answer through its verified network path")
        self.logger.info(
            "DNS probe succeeded interface=%s dns_count=%d mode=%s firewall_active=%s",
            interface,
            len(servers),
            "configured" if configured else "unchanged",
            runtime.firewall_active,
        )

    @abstractmethod
    async def start(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]: ...

    @abstractmethod
    async def stop(self, metadata: ConnectionMetadata | None, runtime: RuntimeState) -> None: ...

    @abstractmethod
    async def status(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]: ...

    async def health(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        status = await self.status(metadata, runtime)
        status.setdefault("healthy", bool(status.get("connected")))
        return status

    async def verify_connected(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        status = await self.health(metadata, runtime)
        if not status.get("healthy", status.get("connected")):
            raise VDeckError("VPN_TRAFFIC_UNCONFIRMED", "VPN health verification failed")
        return status

    async def resolve_endpoint_cache(
        self, metadata: ConnectionMetadata, runtime: RuntimeState, *, force: bool = False
    ) -> dict[str, list[str]]:
        endpoints = [str(item) for item in self.context.store.parsed_runtime_info(metadata.id).get("endpoints", [])]
        if (
            not force
            and endpoints
            and all(self._valid_cached_addresses(runtime.endpoint_cache.get(item, [])) for item in endpoints)
        ):
            return runtime.endpoint_cache
        resolved: dict[str, list[str]] = {}
        for endpoint in endpoints:
            addresses = self._valid_cached_addresses(await self.context.inspector.resolve_endpoint(endpoint))
            if not addresses:
                raise VDeckError("ENDPOINT_RESOLVE_FAILED", "Endpoint resolution returned no usable IP addresses")
            resolved[endpoint] = addresses
        runtime.endpoint_cache = resolved
        self.context.store.save_runtime(runtime)
        return resolved

    @staticmethod
    def _valid_cached_addresses(values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            try:
                normalized = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if normalized not in result:
                result.append(normalized)
        return result

    def endpoint_addresses(self, runtime: RuntimeState) -> list[str]:
        result: list[str] = []
        for values in runtime.endpoint_cache.values():
            for address in self._valid_cached_addresses(values):
                if address not in result:
                    result.append(address)
        return result

    async def diagnostics(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        return await self.status(metadata, runtime)

    async def recover(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        await self.stop(metadata, runtime)
        return await self.start(metadata, runtime)

    async def cleanup(self, metadata: ConnectionMetadata | None, runtime: RuntimeState) -> None:
        await self.stop(metadata, runtime)

    def connection_dir(self, metadata: ConnectionMetadata) -> Path:
        return self.context.store.connection_dir(metadata.id)
