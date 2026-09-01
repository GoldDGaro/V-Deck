"""Protocol backend contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..binaries import BinaryManager
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

    async def diagnostics(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        return await self.status(metadata, runtime)

    async def recover(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        await self.stop(metadata, runtime)
        return await self.start(metadata, runtime)

    async def cleanup(self, metadata: ConnectionMetadata | None, runtime: RuntimeState) -> None:
        await self.stop(metadata, runtime)

    def connection_dir(self, metadata: ConnectionMetadata) -> Path:
        return self.context.store.connection_dir(metadata.id)
