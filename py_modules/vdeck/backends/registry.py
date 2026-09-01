"""Extensible backend registry."""

from __future__ import annotations

from ..errors import VDeckError
from .base import VPNBackend


class BackendRegistry:
    def __init__(self, backends: list[VPNBackend] | None = None):
        self._backends: dict[str, VPNBackend] = {}
        for backend in backends or []:
            self.register(backend)

    def register(self, backend: VPNBackend) -> None:
        if not backend.protocol_id or backend.protocol_id in self._backends:
            raise VDeckError("BACKEND_DUPLICATE", f"Duplicate backend: {backend.protocol_id}")
        self._backends[backend.protocol_id] = backend

    def get(self, protocol_id: str) -> VPNBackend:
        try:
            return self._backends[protocol_id]
        except KeyError as exc:
            raise VDeckError("BACKEND_UNAVAILABLE", f"No backend is registered for {protocol_id}") from exc

    def protocols(self) -> list[str]:
        return sorted(self._backends)
