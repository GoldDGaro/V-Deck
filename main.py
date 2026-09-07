"""Decky Loader entry point for V-Deck."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import decky

PLUGIN_ROOT = Path(decky.DECKY_PLUGIN_DIR)
MODULE_ROOT = PLUGIN_ROOT / "py_modules"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from vdeck.import_logging import log_import_event  # noqa: E402
from vdeck.service import VDeckService  # noqa: E402


class Plugin:
    service: VDeckService

    async def _main(self) -> None:
        fallback_root = Path(decky.DECKY_USER_HOME) / ".local" / "share" / "v-deck"
        settings_value = str(getattr(decky, "DECKY_PLUGIN_SETTINGS_DIR", "") or "").strip()
        storage_root = Path(settings_value) if settings_value else fallback_root
        runtime_value = str(getattr(decky, "DECKY_PLUGIN_RUNTIME_DIR", "") or "").strip()
        runtime_root = Path(runtime_value) if runtime_value else storage_root / "runtime"
        logs_value = str(getattr(decky, "DECKY_PLUGIN_LOG_DIR", "") or "").strip()
        logs_root = Path(logs_value) if logs_value else storage_root / "logs"
        legacy_root = Path(decky.DECKY_USER_HOME) / ".local" / "share" / "vpn-deck" / "configs"
        self.service = VDeckService(storage_root, PLUGIN_ROOT, legacy_root, runtime_root, logs_root)
        await self.service.initialize()
        decky.logger.info("V-Deck 0.1.0 initialized")

    async def _unload(self) -> None:
        await self.service.shutdown(uninstall=False)

    async def _uninstall(self) -> None:
        await self.service.shutdown(uninstall=True)

    async def get_snapshot(self) -> dict[str, Any]:
        return await self.service.get_snapshot()

    async def log_import_event(self, event: str, details: dict[str, Any]) -> dict[str, Any]:
        return log_import_event(self.service.logger, event, details)

    async def import_connection(
        self,
        protocol: str,
        path: str,
        display_name: str = "",
        username: str = "",
        password: str = "",
        passphrase: str = "",
    ) -> dict[str, Any]:
        return await self.service.import_connection(protocol, path, display_name, username, password, passphrase)

    async def validate_import(self, protocol: str, path: str, realpath: str = "") -> dict[str, Any]:
        return await self.service.validate_import(protocol, path, realpath)

    async def connect(self, connection_id: str) -> dict[str, Any]:
        return await self.service.connect(connection_id)

    async def disconnect(self) -> dict[str, Any]:
        return await self.service.disconnect()

    async def rename_connection(self, connection_id: str, display_name: str) -> dict[str, Any]:
        return await self.service.rename_connection(connection_id, display_name)

    async def delete_connection(self, connection_id: str) -> dict[str, Any]:
        return await self.service.delete_connection(connection_id)

    async def save_credentials(
        self, connection_id: str, username: str = "", password: str = "", passphrase: str = ""
    ) -> dict[str, Any]:
        return await self.service.save_credentials(connection_id, username, password, passphrase)

    async def update_settings(
        self, auto_connect: bool, kill_switch: bool, language: str, warning_seen: bool
    ) -> dict[str, Any]:
        return await self.service.update_settings(auto_connect, kill_switch, language, warning_seen)

    async def get_diagnostics(self, connection_id: str) -> dict[str, Any]:
        return await self.service.get_diagnostics(connection_id)

    async def check_external_ip(self) -> dict[str, Any]:
        return await self.service.check_external_ip()

    async def export_diagnostics(self, connection_id: str, decky_version: str = "") -> dict[str, Any]:
        detected_version = decky_version or str(getattr(decky, "DECKY_VERSION", ""))
        return await self.service.export_diagnostics(connection_id, detected_version)
