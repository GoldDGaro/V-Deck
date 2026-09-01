"""Application service exposed through Decky's structured RPC boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from .backends import AmneziaWGBackend, BackendContext, BackendRegistry, OpenVPNBackend, WireGuardBackend
from .binaries import BinaryManager
from .diagnostics import DiagnosticsManager
from .errors import VDeckError, ok
from .i18n import resolve_language
from .logging_utils import ErrorHistory, create_logger
from .manager import VPNManager
from .migration import MigrationManager
from .models import ConnectionState, Protocol
from .network import DnsManager, FirewallManager, NetworkInspector, RouteManager
from .parsers import parse_config
from .runner import CommandRunner
from .security import sanitize
from .storage import VDeckStore, display_name_from_path


class VDeckService:
    def __init__(
        self,
        storage_root: Path,
        plugin_root: Path,
        legacy_root: Path,
        runtime_root: Path | None = None,
        logs_root: Path | None = None,
    ):
        self.store = VDeckStore(storage_root, runtime_root, logs_root)
        self.logger = create_logger(self.store.logs)
        self.errors = ErrorHistory(self.store.state_dir / "errors.json")
        self.runner = CommandRunner()
        self.binaries = BinaryManager(plugin_root / "bin")
        self.inspector = NetworkInspector(self.runner)
        self.routes = RouteManager(self.runner, self.inspector)
        self.dns = DnsManager(self.runner)
        self.firewall = FirewallManager(self.runner)
        context = BackendContext(self.store, self.binaries, self.runner, self.inspector, self.routes, self.dns)
        self.registry = BackendRegistry([AmneziaWGBackend(context), WireGuardBackend(context), OpenVPNBackend(context)])
        self.manager = VPNManager(self.store, self.registry, self.firewall, self.errors)
        self.diagnostics = DiagnosticsManager(
            self.store, self.registry, self.runner, self.inspector, self.firewall, self.binaries, self.errors
        )
        self.migration = MigrationManager(self.store, legacy_root)
        self._tasks: list[asyncio.Task[Any]] = []
        self._network_process: asyncio.subprocess.Process | None = None

    async def initialize(self) -> None:
        self.binaries.prepare()
        self.migration.run()
        await self.manager.initialize()
        self._tasks.append(asyncio.create_task(self._health_loop()))
        self._tasks.append(asyncio.create_task(self._ping_loop()))
        self._tasks.append(asyncio.create_task(self._network_monitor()))

    async def shutdown(self, uninstall: bool = False) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self._network_process and self._network_process.returncode is None:
            self._network_process.terminate()
            await self._network_process.wait()
        if uninstall:
            await self.manager.stop(manual=True)

    async def _health_loop(self) -> None:
        while True:
            await asyncio.sleep(15)
            try:
                await self.manager.health_check()
            except Exception as exc:
                self.logger.warning("Health check failed: %s", sanitize(exc))

    async def _ping_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            runtime = self.store.load_runtime()
            if runtime.state == ConnectionState.CONNECTED.value and runtime.connection_id:
                try:
                    await self.diagnostics.collect(runtime.connection_id, include_external_ip=False)
                except Exception as exc:
                    self.logger.info("Active tunnel ping probe unavailable: %s", sanitize(exc))

    async def _network_monitor(self) -> None:
        try:
            self._network_process = await asyncio.create_subprocess_exec(
                "nmcli", "monitor", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
        except OSError:
            self.logger.info("NetworkManager monitor unavailable; using bounded health checks")
            return
        assert self._network_process.stdout is not None
        while True:
            line = await self._network_process.stdout.readline()
            if not line:
                return
            await asyncio.sleep(1)
            await self.manager.network_event()

    async def _rpc(self, operation: Callable[[], Awaitable[dict[str, Any]]]) -> dict[str, Any]:
        try:
            return await operation()
        except VDeckError as exc:
            self.logger.warning("RPC error %s: %s", exc.code, exc.message)
            return exc.response()
        except Exception as exc:
            self.logger.exception("Unhandled backend error")
            return VDeckError("INTERNAL_ERROR", "Unexpected V-Deck backend error", sanitize(exc)).response()

    async def get_snapshot(self) -> dict[str, Any]:
        result = self.manager.snapshot()
        result["backend_versions"] = self.binaries.versions()
        result["resolved_language"] = resolve_language(result["settings"]["language"])
        return ok(**result)

    async def import_connection(
        self,
        protocol: str,
        path: str,
        display_name: str = "",
        username: str = "",
        password: str = "",
        passphrase: str = "",
    ) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            try:
                selected = Protocol(protocol)
            except ValueError as exc:
                raise VDeckError("PROTOCOL_INVALID", "Unsupported VPN protocol") from exc
            metadata = self.store.import_connection(
                selected,
                Path(path),
                display_name or None,
                username or None,
                password if username else None,
                passphrase or None,
            )
            return ok(connection=metadata.to_dict())

        return await self._rpc(operation)

    async def validate_import(self, protocol: str, path: str) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            try:
                selected = Protocol(protocol)
            except ValueError as exc:
                raise VDeckError("PROTOCOL_INVALID", "Unsupported VPN protocol") from exc
            source = Path(path)
            parsed = parse_config(selected, source)
            return ok(
                display_name=display_name_from_path(source),
                requires_username_password=parsed.requires_username_password,
                requires_key_passphrase=parsed.requires_key_passphrase,
            )

        return await self._rpc(operation)

    async def connect(self, connection_id: str) -> dict[str, Any]:
        return await self._rpc(lambda: self.manager.start(connection_id))

    async def disconnect(self) -> dict[str, Any]:
        return await self._rpc(lambda: self.manager.stop(manual=True))

    async def rename_connection(self, connection_id: str, display_name: str) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            return ok(connection=self.store.rename(connection_id, display_name).to_dict())

        return await self._rpc(operation)

    async def delete_connection(self, connection_id: str) -> dict[str, Any]:
        return await self._rpc(lambda: self.manager.delete(connection_id))

    async def save_credentials(
        self, connection_id: str, username: str = "", password: str = "", passphrase: str = ""
    ) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            self.store.get(connection_id)
            self.store.save_credentials(
                connection_id, username or None, password if username else None, passphrase or None
            )
            return ok()

        return await self._rpc(operation)

    async def update_settings(
        self, auto_connect: bool, kill_switch: bool, language: str, warning_seen: bool
    ) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            if language not in {"automatic", "ru", "en"}:
                raise VDeckError("LANGUAGE_INVALID", "Unsupported language")
            async with self.manager.lock:
                state = self.store.load_state()
                runtime = self.store.load_runtime()
                previous_kill_switch = state.kill_switch
                state.auto_connect = bool(auto_connect)
                state.kill_switch = bool(kill_switch)
                state.kill_switch_warning_seen = bool(warning_seen)
                state.language = language
                self.store.save_state(state)
                if runtime.state == ConnectionState.CONNECTED.value and runtime.connection_id:
                    if previous_kill_switch and not state.kill_switch:
                        await self.firewall.disable()
                        runtime.firewall_active = False
                    elif state.kill_switch and not previous_kill_switch:
                        metadata = self.store.get(runtime.connection_id)
                        backend = self.registry.get(metadata.protocol)
                        info = self.store.parsed_runtime_info(metadata.id)
                        addresses: list[str] = []
                        for endpoint in info.get("endpoints", []):
                            addresses.extend(await backend.context.inspector.resolve_endpoint(str(endpoint)))
                        await self.firewall.enable(runtime.interface or "", addresses)
                        runtime.firewall_active = True
                    self.store.save_runtime(runtime)
            return ok(settings=state.to_dict(), resolved_language=resolve_language(language))

        return await self._rpc(operation)

    async def get_diagnostics(self, connection_id: str) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            return ok(diagnostics=await self.diagnostics.collect(connection_id))

        return await self._rpc(operation)

    async def export_diagnostics(self, connection_id: str, decky_version: str = "") -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            path = await self.diagnostics.export(connection_id, decky_version or None)
            return ok(path=str(path))

        return await self._rpc(operation)
