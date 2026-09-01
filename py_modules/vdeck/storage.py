"""Transactional V-Deck connection and state storage."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .atomic import atomic_write_json, read_json
from .errors import VDeckError
from .models import ConnectionMetadata, PersistentState, Protocol, RuntimeState
from .parsers import parse_config
from .security import secure_mkdir, secure_write


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def display_name_from_path(path: Path) -> str:
    value = re_sub_separators(path.stem).strip()
    return value.title() or "VPN"


def re_sub_separators(value: str) -> str:
    import re

    return re.sub(r"[_\-.]+", " ", value)


class VDeckStore:
    def __init__(
        self,
        root: Path,
        runtime_root: Path | None = None,
        logs_root: Path | None = None,
        logger: logging.Logger | None = None,
    ):
        self.root = root
        self.configs = root / "configs"
        self.state_dir = root / "state"
        self.runtime = runtime_root or root / "runtime"
        self.logs = logs_root or root / "logs"
        self.logger = logger
        self.reports = root / "reports"
        for directory in (root, self.configs, self.state_dir, self.runtime, self.logs, self.reports):
            secure_mkdir(directory)
        self.state_path = self.state_dir / "state.json"
        self.runtime_path = self.runtime / "runtime.json"

    def load_state(self) -> PersistentState:
        raw = read_json(self.state_path, {})
        if not isinstance(raw, dict):
            raw = {}
        state = PersistentState.from_dict(raw)
        if not self.state_path.exists() or not raw:
            self.save_state(state)
        return state

    def save_state(self, state: PersistentState) -> None:
        atomic_write_json(self.state_path, state.to_dict())

    def load_runtime(self) -> RuntimeState:
        raw = read_json(self.runtime_path, {})
        return RuntimeState.from_dict(raw if isinstance(raw, dict) else {})

    def save_runtime(self, state: RuntimeState) -> None:
        atomic_write_json(self.runtime_path, state.to_dict())

    @staticmethod
    def current_boot_id() -> str | None:
        """Return Linux's per-boot identifier used to distinguish restart from reboot."""
        try:
            value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip().lower()
        except OSError:
            return None
        return value if value else None

    def connection_dir(self, connection_id: str) -> Path:
        try:
            normalized = str(uuid.UUID(connection_id))
        except ValueError as exc:
            raise VDeckError("CONNECTION_ID_INVALID", "Invalid connection identifier") from exc
        return self.configs / normalized

    def get(self, connection_id: str) -> ConnectionMetadata:
        path = self.connection_dir(connection_id) / "metadata.json"
        raw = read_json(path, None)
        if not isinstance(raw, dict):
            raise VDeckError("CONNECTION_NOT_FOUND", "Connection was not found")
        return ConnectionMetadata.from_dict(raw)

    def list(self) -> list[ConnectionMetadata]:
        result: list[ConnectionMetadata] = []
        for child in self.configs.iterdir():
            if not child.is_dir() or child.is_symlink() or child.name.startswith("."):
                continue
            raw = read_json(child / "metadata.json", None)
            if isinstance(raw, dict):
                try:
                    result.append(ConnectionMetadata.from_dict(raw))
                except (TypeError, ValueError):
                    continue
        result.sort(key=lambda item: item.last_used_at or item.created_at, reverse=True)
        return result

    def parsed_runtime_info(self, connection_id: str) -> dict[str, Any]:
        value = read_json(self.connection_dir(connection_id) / "runtime-info.json", {})
        return value if isinstance(value, dict) else {}

    def import_connection(
        self,
        protocol: Protocol,
        source_path: Path,
        display_name: str | None = None,
        username: str | None = None,
        password: str | None = None,
        passphrase: str | None = None,
        migration_source: str | None = None,
    ) -> ConnectionMetadata:
        if self.logger:
            self.logger.info("parser started protocol=%s source=%s", protocol.value, source_path)
        try:
            parsed = parse_config(protocol, source_path)
        except Exception as exc:
            if self.logger:
                code = exc.code if isinstance(exc, VDeckError) else type(exc).__name__
                self.logger.warning(
                    "parser failed protocol=%s source=%s code=%s error=%s",
                    protocol.value,
                    source_path,
                    code,
                    exc,
                )
            raise
        if self.logger:
            self.logger.info("parser succeeded protocol=%s source=%s", protocol.value, source_path)
        connection_id = str(uuid.uuid4())
        created = utc_now()
        name = (display_name or display_name_from_path(source_path)).strip()
        if not name or len(name) > 120:
            raise VDeckError("NAME_INVALID", "Connection name must contain 1 to 120 characters")
        metadata = ConnectionMetadata(
            id=connection_id,
            display_name=name,
            protocol=protocol.value,
            created_at=created,
            updated_at=created,
            source_format=parsed.source_format,
            requires_username_password=parsed.requires_username_password,
            requires_key_passphrase=parsed.requires_key_passphrase,
            migration_source=migration_source,
        )
        stage = Path(tempfile.mkdtemp(prefix=f".{connection_id}.", dir=self.configs))
        if self.logger:
            self.logger.info("storage stage created connection=%s stage=%s", connection_id, stage)
        try:
            secure_mkdir(stage / "files")
            secure_mkdir(stage / "credentials")
            secure_write(stage / "config", parsed.runtime_config.encode("utf-8"))
            for file_name, data in parsed.files.items():
                secure_write(stage / "files" / file_name, data)
            self._save_credentials_to(stage / "credentials", username, password, passphrase)
            atomic_write_json(stage / "metadata.json", metadata.to_dict())
            atomic_write_json(
                stage / "runtime-info.json",
                {
                    "interface_addresses": parsed.interface_addresses,
                    "dns_servers": parsed.dns_servers,
                    "mtu": parsed.mtu,
                    "allowed_ips": parsed.allowed_ips,
                    "endpoints": parsed.endpoints,
                },
            )
            os.replace(stage, self.connection_dir(connection_id))
            if self.logger:
                self.logger.info(
                    "connection committed connection=%s directory=%s",
                    connection_id,
                    self.connection_dir(connection_id),
                )
        except Exception as exc:
            if self.logger:
                code = exc.code if isinstance(exc, VDeckError) else type(exc).__name__
                self.logger.warning("connection commit failed connection=%s code=%s error=%s", connection_id, code, exc)
            shutil.rmtree(stage, ignore_errors=True)
            raise
        return metadata

    def _save_credentials_to(
        self, directory: Path, username: str | None, password: str | None, passphrase: str | None
    ) -> None:
        if username is not None or password is not None:
            if not username or password is None:
                raise VDeckError("CREDENTIALS_REQUIRED", "Both username and password are required")
            secure_write(directory / "auth", f"{username}\n{password}\n".encode())
        if passphrase is not None:
            if not passphrase:
                raise VDeckError("PASSPHRASE_REQUIRED", "Private-key passphrase cannot be empty")
            secure_write(directory / "passphrase", (passphrase + "\n").encode("utf-8"))

    def save_credentials(
        self, connection_id: str, username: str | None, password: str | None, passphrase: str | None
    ) -> None:
        directory = self.connection_dir(connection_id) / "credentials"
        secure_mkdir(directory)
        self._save_credentials_to(directory, username, password, passphrase)

    def rename(self, connection_id: str, display_name: str) -> ConnectionMetadata:
        name = display_name.strip()
        if not name or len(name) > 120:
            raise VDeckError("NAME_INVALID", "Connection name must contain 1 to 120 characters")
        metadata = self.get(connection_id)
        metadata.display_name = name
        metadata.updated_at = utc_now()
        atomic_write_json(self.connection_dir(connection_id) / "metadata.json", metadata.to_dict())
        return metadata

    def update_metadata(self, metadata: ConnectionMetadata) -> None:
        atomic_write_json(self.connection_dir(metadata.id) / "metadata.json", metadata.to_dict())

    def delete(self, connection_id: str) -> None:
        directory = self.connection_dir(connection_id)
        if not directory.exists():
            raise VDeckError("CONNECTION_NOT_FOUND", "Connection was not found")
        tombstone = self.configs / f".{connection_id}.deleting"
        os.replace(directory, tombstone)
        shutil.rmtree(tombstone)

    def record_failed_migration(self, source: Path, message: str) -> ConnectionMetadata:
        connection_id = str(uuid.uuid4())
        created = utc_now()
        metadata = ConnectionMetadata(
            id=connection_id,
            display_name=display_name_from_path(source),
            protocol=Protocol.AMNEZIAWG.value,
            created_at=created,
            updated_at=created,
            source_format=source.suffix.lower(),
            migration_source=str(source),
            import_error=message,
        )
        directory = self.connection_dir(connection_id)
        secure_mkdir(directory)
        atomic_write_json(directory / "metadata.json", metadata.to_dict())
        return metadata

    def migration_fingerprints(self) -> set[str]:
        value = read_json(self.state_dir / "migration.json", {"fingerprints": []})
        values = value.get("fingerprints", []) if isinstance(value, dict) else []
        return {str(item) for item in values}

    def save_migration_fingerprints(self, values: set[str]) -> None:
        atomic_write_json(self.state_dir / "migration.json", {"fingerprints": sorted(values)})

    @staticmethod
    def fingerprint(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()
