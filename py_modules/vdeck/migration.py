"""Idempotent, copy-only migration from MrWaip/vpn-deck storage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import Protocol
from .security import sanitize
from .storage import VDeckStore


class MigrationManager:
    def __init__(self, store: VDeckStore, source: Path):
        self.store = store
        self.source = source

    def run(self) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {"imported": [], "failed": []}
        if not self.source.is_dir() or self.source.is_symlink():
            return result
        fingerprints = self.store.migration_fingerprints()
        for path in sorted(self.source.glob("*.conf")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                fingerprint = self.store.fingerprint(path)
            except OSError:
                continue
            if fingerprint in fingerprints:
                continue
            try:
                metadata = self.store.import_connection(Protocol.AMNEZIAWG, path, migration_source=str(path))
                result["imported"].append(metadata.to_dict())
            except Exception as exc:
                metadata = self.store.record_failed_migration(path, sanitize(exc))
                result["failed"].append(metadata.to_dict())
            fingerprints.add(fingerprint)
        self.store.save_migration_fingerprints(fingerprints)
        return result
