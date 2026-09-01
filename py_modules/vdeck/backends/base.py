"""Protocol backend contract."""

from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..binaries import BinaryManager
from ..errors import VDeckError
from ..models import ConnectionMetadata, RuntimeState
from ..network import DnsManager, NetworkInspector, RouteManager
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
