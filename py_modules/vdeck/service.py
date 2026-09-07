"""Application service exposed through Decky's structured RPC boundary."""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Awaitable, Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

from .backends import AmneziaWGBackend, BackendContext, BackendRegistry, OpenVPNBackend, WireGuardBackend
from .binaries import BinaryManager
from .diagnostics import DiagnosticsManager
from .errors import VDeckError, ok
from .external_ip import lookup_external_ip
from .i18n import resolve_language
from .logging_utils import ErrorHistory, create_logger, safe_exception_details
from .manager import VPNManager
from .migration import MigrationManager
from .models import ConnectionState, Protocol
from .network import DnsManager, FirewallManager, NetworkInspector, RouteManager
from .parsers import parse_config
from .runner import CommandResult, CommandRunner, check_loader_error, child_environment
from .security import ensure_regular_file, sanitize
from .storage import VDeckStore, display_name_from_path, utc_now


class VDeckService:
    def __init__(
        self,
        storage_root: Path,
        plugin_root: Path,
        legacy_root: Path,
        runtime_root: Path | None = None,
        logs_root: Path | None = None,
    ):
        effective_logs_root = logs_root or storage_root / "logs"
        self.logger = create_logger(effective_logs_root)
        self.store = VDeckStore(storage_root, runtime_root, effective_logs_root, self.logger)
        self._last_snapshot_connection_count: int | None = None
        effective_uid = getattr(os, "geteuid", lambda: None)()
        self.logger.info(
            "runtime storage initialized settings_dir=%s runtime_dir=%s logs_dir=%s uid=%s",
            self.store.root,
            self.store.runtime,
            self.store.logs,
            effective_uid,
        )
        self.errors = ErrorHistory(self.store.state_dir / "errors.json")
        self.runner = CommandRunner(self.logger)
        self.binaries = BinaryManager(plugin_root / "bin")
        self.inspector = NetworkInspector(self.runner)
        self.routes = RouteManager(self.runner, self.inspector)
        self.dns = DnsManager(self.runner, self.store.runtime / "dns-ownership.json")
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
        self._external_ip_lock = asyncio.Lock()
        self._external_ip_samples: dict[str, Any] = {"before": None, "after": None}

    async def initialize(self) -> None:
        self.binaries.prepare()
        self.migration.run()
        try:
            await self.manager.initialize()
        except Exception as exc:
            # Keep RPC/UI available for diagnostics and an explicit cleanup
            # retry. Do not discard the failed recovery ownership journal.
            runtime = self.store.load_runtime()
            runtime.state = ConnectionState.ERROR.value
            runtime.error_code = exc.code if isinstance(exc, VDeckError) else "INITIALIZATION_FAILED"
            runtime.error_message = "Previous VPN resources could not be cleaned up; see technical log"
            self.store.save_runtime(runtime)
            self.logger.error("initialization cleanup pending code=%s", runtime.error_code)
        self._tasks.append(asyncio.create_task(self._health_loop()))
        self._tasks.append(asyncio.create_task(self._ping_loop()))
        self._tasks.append(asyncio.create_task(self._network_monitor()))

    async def shutdown(self, uninstall: bool = False) -> None:
        recovery = self.manager._recovery_task
        if recovery and not recovery.done():
            recovery.cancel()
            await asyncio.gather(recovery, return_exceptions=True)
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
                self.logger.warning("Health check failed: %s", safe_exception_details(exc))

    async def _ping_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            runtime = self.store.load_runtime()
            if runtime.state == ConnectionState.CONNECTED.value and runtime.connection_id:
                try:
                    await self.diagnostics.collect(runtime.connection_id, include_external_ip=False)
                except Exception as exc:
                    self.logger.info("Active tunnel ping probe unavailable: %s", safe_exception_details(exc))

    async def _network_monitor(self) -> None:
        while True:
            try:
                await self._watch_network_devices()
            except Exception as exc:
                self.logger.warning("Network monitor failed: %s", safe_exception_details(exc))
            # NM can restart independently of Decky. Resume monitoring instead
            # of permanently losing Wi-Fi-restored events after EOF.
            await asyncio.sleep(5)

    async def _watch_network_devices(self) -> None:
        try:
            self._network_process = await asyncio.create_subprocess_exec(
                "nmcli",
                "--colors",
                "no",
                "device",
                "monitor",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_environment(),
            )
        except OSError as exc:
            self.logger.info("NetworkManager monitor unavailable details=%s", safe_exception_details(exc))
            return
        process = self._network_process
        assert process.stdout is not None and process.stderr is not None

        async def drain_errors() -> bytes:
            tail = b""
            assert process.stderr is not None
            while chunk := await process.stderr.read(1024):
                tail = (tail + chunk)[-4096:]
            return tail

        errors = asyncio.create_task(drain_errors())
        try:
            while line := await process.stdout.readline():
                # Never log device-monitor messages (they can name profiles).
                device = line.decode(errors="replace").partition(":")[0]
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", device) or device.startswith(("vdeck-", "vdns-")):
                    continue
                self.logger.info("network device event device=%s", device)
                try:
                    await self.manager.network_event()
                except Exception as exc:
                    self.logger.warning("Network event failed: %s", safe_exception_details(exc))
            code = await asyncio.wait_for(process.wait(), 5)
            stderr = (await asyncio.wait_for(errors, 2)).decode(errors="replace")
            self.logger.info("stage=NETWORK_MONITOR exit_code=%s stderr=%s", code, sanitize(stderr)[-800:])
            check_loader_error(CommandResult(("nmcli",), code, "", stderr))
        finally:
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 2)
                except asyncio.TimeoutError:
                    with suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()
            errors.cancel()
            await asyncio.gather(errors, return_exceptions=True)

    async def _rpc(self, operation: Callable[[], Awaitable[dict[str, Any]]]) -> dict[str, Any]:
        try:
            return await operation()
        except VDeckError as exc:
            self.logger.warning("RPC error %s: %s", exc.code, exc.message)
            return exc.response()
        except Exception as exc:
            self.logger.error("Unhandled backend error code=INTERNAL_ERROR details=%s", safe_exception_details(exc))
            return VDeckError("INTERNAL_ERROR", "Unexpected V-Deck backend error").response()

    async def get_snapshot(self) -> dict[str, Any]:
        try:
            result = self.manager.snapshot()
        except VDeckError as exc:
            self.logger.error("snapshot failed code=%s", exc.code)
            return exc.response()
        connection_count = len(result["connections"])
        if connection_count != self._last_snapshot_connection_count:
            self.logger.info("snapshot contains %d connections", connection_count)
            self._last_snapshot_connection_count = connection_count
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
            self.logger.info("import_connection started protocol=%s source=%s", protocol, path)
            try:
                selected = self._protocol(protocol)
                source = self._accessible_import_path(path)
                metadata = self.store.import_connection(
                    selected,
                    source,
                    display_name or None,
                    username or None,
                    password if username else None,
                    passphrase or None,
                )
                committed = self.store.get(metadata.id)
                connections = self.store.list()
                connection_count = len(connections)
                if not any(item.id == metadata.id for item in connections):
                    raise VDeckError(
                        "IMPORT_COMMIT_NOT_VISIBLE",
                        "The imported connection was committed but is not visible in storage",
                    )
            except Exception as exc:
                self.logger.warning(
                    "import_connection failed protocol=%s source=%s code=%s error=%s",
                    protocol,
                    path,
                    self._error_code(exc),
                    safe_exception_details(exc),
                )
                raise
            self.logger.info(
                "import_connection succeeded connection=%s protocol=%s connections=%d",
                committed.id,
                committed.protocol,
                connection_count,
            )
            return ok(connection=committed.to_dict(), connections_count=connection_count)

        return await self._rpc(operation)

    async def validate_import(self, protocol: str, path: str, realpath: str = "") -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            self.logger.info("file selected path=%s realpath=%s", path, realpath or "[not provided]")
            self.logger.info("protocol selected protocol=%s", protocol)
            self.logger.info("validate_import started protocol=%s", protocol)
            try:
                selected = self._protocol(protocol)
                source = self._accessible_import_path(realpath, path)
                parsed = parse_config(selected, source)
            except Exception as exc:
                self.logger.warning(
                    "validate_import failed protocol=%s code=%s error=%s",
                    protocol,
                    self._error_code(exc),
                    safe_exception_details(exc),
                )
                raise
            self.logger.info("validate_import succeeded protocol=%s source=%s", selected.value, source)
            return ok(
                path=str(source),
                display_name=display_name_from_path(source),
                requires_username_password=parsed.requires_username_password,
                requires_key_passphrase=parsed.requires_key_passphrase,
            )

        return await self._rpc(operation)

    @staticmethod
    def _protocol(value: str) -> Protocol:
        try:
            return Protocol(value)
        except ValueError as exc:
            raise VDeckError("PROTOCOL_INVALID", "Unsupported VPN protocol") from exc

    @staticmethod
    def _accessible_import_path(*values: str) -> Path:
        seen: set[str] = set()
        semantic_error: VDeckError | None = None
        for raw in values:
            value = str(raw or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            try:
                source = ensure_regular_file(Path(value))
                with source.open("rb") as stream:
                    stream.read(1)
                return source
            except VDeckError as exc:
                if exc.code in {"CONFIG_EMPTY", "CONFIG_TOO_LARGE"}:
                    semantic_error = semantic_error or exc
            except OSError:
                continue
        if semantic_error:
            raise semantic_error
        raise VDeckError(
            "CONFIG_FILE_NOT_ACCESSIBLE",
            "The selected configuration file is not accessible to V-Deck",
        )

    @staticmethod
    def _error_code(exc: Exception) -> str:
        return exc.code if isinstance(exc, VDeckError) else type(exc).__name__

    async def connect(self, connection_id: str) -> dict[str, Any]:
        self.logger.info("connect requested connection=%s", connection_id)
        self.store.audit(connection_id, "before connect")
        try:
            return await self._rpc(lambda: self.manager.start(connection_id))
        finally:
            self.store.audit(connection_id, "after connect")

    async def disconnect(self) -> dict[str, Any]:
        return await self._rpc(lambda: self.manager.stop(manual=True))

    async def rename_connection(self, connection_id: str, display_name: str) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            return ok(connection=self.store.rename(connection_id, display_name).to_dict())

        return await self._rpc(operation)

    async def delete_connection(self, connection_id: str) -> dict[str, Any]:
        self.logger.warning("explicit delete_connection RPC connection=%s", connection_id)
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
            if kill_switch and not warning_seen:
                raise VDeckError("KILL_SWITCH_CONFIRMATION_REQUIRED", "Accept the Kill Switch warning first")
            async with self.manager.lock:
                state = self.store.load_state()
                runtime = self.store.load_runtime()
                previous_kill_switch = state.kill_switch
                # Commit preferences only after the corresponding network change.
                # OFF also works while recovery is exhausted or between attempts.
                if not kill_switch and (previous_kill_switch or runtime.firewall_active):
                    await self.firewall.disable()
                    runtime.firewall_active = False
                    self.store.save_runtime(runtime)
                elif kill_switch and not previous_kill_switch and runtime.established_once and runtime.connection_id:
                    metadata = self.store.get(runtime.connection_id)
                    backend = self.registry.get(metadata.protocol)
                    try:
                        await self.manager._enable_kill_switch(backend, metadata, runtime)
                        if runtime.state == ConnectionState.CONNECTED.value:
                            await backend.verify_connected(metadata, runtime)
                    except (Exception, asyncio.CancelledError):
                        # Preserve the ownership flag if rollback itself fails.
                        await self.firewall.disable()
                        runtime.firewall_active = False
                        self.store.save_runtime(runtime)
                        raise
                state.auto_connect = bool(auto_connect)
                state.kill_switch = bool(kill_switch)
                state.kill_switch_warning_seen = bool(warning_seen)
                state.language = language
                self.store.save_state(state)
                self.store.save_runtime(runtime)
            return ok(settings=state.to_dict(), resolved_language=resolve_language(language))

        return await self._rpc(operation)

    async def get_diagnostics(self, connection_id: str) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            diagnostics = await self.diagnostics.collect(connection_id, include_external_ip=False)
            diagnostics["external_ip_checks"] = dict(self._external_ip_samples)
            return ok(diagnostics=diagnostics)

        return await self._rpc(operation)

    async def check_external_ip(self) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            if self._external_ip_lock.locked():
                raise VDeckError("OPERATION_IN_PROGRESS", "An external IP check is already running")
            async with self._external_ip_lock:
                runtime = self.store.load_runtime()
                revision = self.manager.network_revision
                if runtime.state == ConnectionState.CONNECTED.value:
                    slot = "after"
                elif runtime.state == ConnectionState.DISCONNECTED.value or (
                    runtime.state == ConnectionState.ERROR.value
                    and self.store.load_state().desired_state == "OFF"
                    and not (
                        runtime.interface
                        or runtime.process
                        or runtime.owned_routes
                        or runtime.firewall_active
                        or runtime.ipv6_guard
                    )
                ):
                    slot = "before"
                else:
                    raise VDeckError("EXTERNAL_IP_VPN_BUSY", "Wait for a stable connection or manually turn VPN off")
                self.logger.info("external IP check started mode=%s vpn_state=%s", slot, runtime.state)
                result = await lookup_external_ip(self.logger)
                current = self.store.load_runtime()
                if revision != self.manager.network_revision or (
                    runtime.state,
                    runtime.connection_id,
                    runtime.started_at,
                ) != (current.state, current.connection_id, current.started_at):
                    raise VDeckError("EXTERNAL_IP_NETWORK_CHANGED", "Network changed during the check; try again")
                sample = {
                    **result,
                    "checked_at": utc_now(),
                    "vpn_state": runtime.state,
                    "connection_id": runtime.connection_id if slot == "after" else None,
                    "connection_name": self.store.get(runtime.connection_id or "").display_name
                    if slot == "after"
                    else None,
                }
                self._external_ip_samples[slot] = sample
                return ok(external_ip_checks=dict(self._external_ip_samples))

        return await self._rpc(operation)

    async def export_diagnostics(self, connection_id: str, decky_version: str = "") -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            path = await self.diagnostics.export(connection_id, decky_version or None)
            return ok(path=str(path))

        return await self._rpc(operation)
