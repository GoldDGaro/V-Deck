"""Serialized single-active-VPN orchestration and recovery state machine."""

from __future__ import annotations

import asyncio
import re
from contextlib import suppress
from typing import Any

from .backends.registry import BackendRegistry
from .errors import VDeckError, ok
from .logging_utils import ErrorHistory
from .models import ConnectionState, DesiredState, PersistentState, RuntimeState
from .network import FirewallManager, interface_name
from .runner import OwnedProcess
from .storage import VDeckStore, utc_now


class VPNManager:
    def __init__(
        self,
        store: VDeckStore,
        registry: BackendRegistry,
        firewall: FirewallManager,
        errors: ErrorHistory,
        recovery_delays: tuple[float, ...] = (0, 3, 10, 30, 60),
    ):
        self.store = store
        self.registry = registry
        self.firewall = firewall
        self.errors = errors
        self.recovery_delays = recovery_delays
        self.lock = asyncio.Lock()
        self._recovery_task: asyncio.Task[None] | None = None

    async def initialize(self) -> None:
        restart_connection_id: str | None = None
        restart_endpoint_cache: dict[str, list[str]] = {}
        current_boot_id = self.store.current_boot_id()
        async with self.lock:
            state = self.store.load_state()
            runtime = self.store.load_runtime()
            if (
                state.desired_state == DesiredState.ON.value
                and runtime.established_once
                and runtime.connection_id
                and current_boot_id is not None
                and runtime.boot_id == current_boot_id
            ):
                with suppress(VDeckError):
                    self.store.get(runtime.connection_id)
                    restart_connection_id = runtime.connection_id
                    restart_endpoint_cache = runtime.endpoint_cache
            if runtime.state != ConnectionState.DISCONNECTED.value or runtime.interface or runtime.process:
                metadata = None
                if runtime.connection_id:
                    with suppress(VDeckError):
                        metadata = self.store.get(runtime.connection_id)
                if metadata:
                    try:
                        await self.registry.get(metadata.protocol).cleanup(metadata, runtime)
                    except Exception as exc:
                        self._record_error(metadata.id, metadata.protocol, "crash_cleanup", exc)
                else:
                    await self._cleanup_orphaned_runtime(runtime)
                self.store.save_runtime(RuntimeState())
                state.active_connection_id = None
                self.store.save_state(state)
            await self._cleanup_known_interfaces()
            if runtime.firewall_active or await self.firewall.active():
                await self.firewall.disable()
            if restart_connection_id:
                self.store.save_runtime(
                    RuntimeState(
                        state=ConnectionState.ERROR.value,
                        connection_id=restart_connection_id,
                        established_once=True,
                        boot_id=current_boot_id,
                        endpoint_cache=restart_endpoint_cache,
                    )
                )
        state = self.store.load_state()
        if restart_connection_id:
            runtime = self.store.load_runtime()
            metadata = self.store.get(restart_connection_id)
            backend = self.registry.get(metadata.protocol)
            if state.kill_switch:
                await self._enable_kill_switch(backend, metadata, runtime)
            self._recovery_task = asyncio.create_task(self._recover(restart_connection_id))
        elif state.auto_connect and state.desired_state == DesiredState.ON.value and state.last_active_connection_id:
            with suppress(VDeckError):
                await self.start(state.last_active_connection_id, user_initiated=False)

    async def start(self, connection_id: str, *, user_initiated: bool = True) -> dict[str, Any]:
        if self._recovery_task and not self._recovery_task.done() and user_initiated:
            self._recovery_task.cancel()
        async with self.lock:
            metadata = self.store.get(connection_id)
            if metadata.import_error:
                raise VDeckError("MIGRATION_IMPORT_FAILED", metadata.import_error)
            state = self.store.load_state()
            runtime = self.store.load_runtime()
            if runtime.state in {
                ConnectionState.CONNECTING.value,
                ConnectionState.DISCONNECTING.value,
                ConnectionState.RECOVERING.value,
            }:
                raise VDeckError("OPERATION_IN_PROGRESS", "Another VPN operation is already in progress")
            if runtime.state == ConnectionState.CONNECTED.value and runtime.connection_id == connection_id:
                return ok(connection=metadata.to_dict(), runtime=runtime.to_dict())
            switching = runtime.connection_id is not None and runtime.connection_id != connection_id
            if switching:
                old = None
                with suppress(VDeckError):
                    old = self.store.get(runtime.connection_id or "")
                await self._stop_locked(old, runtime, state, manual=False)
                state = self.store.load_state()
                runtime = self.store.load_runtime()

            state.desired_state = DesiredState.ON.value
            state.active_connection_id = connection_id
            state.last_active_connection_id = connection_id
            self.store.save_state(state)
            runtime = RuntimeState(
                state=ConnectionState.CONNECTING.value,
                connection_id=connection_id,
                boot_id=self.store.current_boot_id(),
            )
            self.store.save_runtime(runtime)
            backend = self.registry.get(metadata.protocol)
            try:
                status = await backend.start(metadata, runtime)
                if not status.get("connected"):
                    raise VDeckError("BACKEND_NOT_CONNECTED", "The VPN backend did not confirm a connected tunnel")
                runtime = self.store.load_runtime()
                runtime.state = ConnectionState.CONNECTED.value
                runtime.connection_id = connection_id
                runtime.started_at = utc_now()
                runtime.established_once = True
                runtime.error_code = None
                runtime.error_message = None
                metadata.last_used_at = runtime.started_at
                metadata.updated_at = runtime.started_at
                self.store.update_metadata(metadata)
                if state.kill_switch:
                    await self._enable_kill_switch(backend, metadata, runtime)
                self.store.save_runtime(runtime)
                return ok(connection=metadata.to_dict(), runtime=runtime.to_dict(), status=status)
            except Exception as exc:
                try:
                    await backend.cleanup(metadata, runtime)
                finally:
                    await self.firewall.disable()
                runtime = RuntimeState(
                    state=ConnectionState.ERROR.value,
                    connection_id=connection_id,
                    error_code=exc.code if isinstance(exc, VDeckError) else "START_FAILED",
                    error_message=str(exc),
                )
                self.store.save_runtime(runtime)
                state.active_connection_id = None
                state.desired_state = DesiredState.OFF.value
                self.store.save_state(state)
                self._record_error(connection_id, metadata.protocol, "switch" if switching else "start", exc)
                if isinstance(exc, VDeckError):
                    raise
                raise VDeckError("START_FAILED", "Unable to start the VPN connection") from exc

    async def stop(self, *, manual: bool = True) -> dict[str, Any]:
        if self._recovery_task and not self._recovery_task.done():
            self._recovery_task.cancel()
        async with self.lock:
            state = self.store.load_state()
            runtime = self.store.load_runtime()
            metadata = None
            if runtime.connection_id:
                with suppress(VDeckError):
                    metadata = self.store.get(runtime.connection_id)
            await self._stop_locked(metadata, runtime, state, manual=manual)
            return ok(runtime=self.store.load_runtime().to_dict())

    async def _stop_locked(self, metadata: Any, runtime: RuntimeState, state: PersistentState, *, manual: bool) -> None:
        if manual:
            state.desired_state = DesiredState.OFF.value
            self.store.save_state(state)
        runtime.state = ConnectionState.DISCONNECTING.value
        self.store.save_runtime(runtime)
        try:
            if metadata:
                await self.registry.get(metadata.protocol).stop(metadata, runtime)
            else:
                await self._cleanup_orphaned_runtime(runtime)
        finally:
            await self.firewall.disable()
            state.active_connection_id = None
            if manual:
                state.desired_state = DesiredState.OFF.value
            self.store.save_state(state)
            self.store.save_runtime(RuntimeState())

    async def _cleanup_orphaned_runtime(self, runtime: RuntimeState) -> None:
        """Remove only resources carrying V-Deck ownership markers."""
        protocols = self.registry.protocols()
        if not protocols:
            return
        context = self.registry.get(protocols[0]).context
        await context.routes.cleanup(runtime.owned_routes)
        if runtime.interface and re.fullmatch(r"vdeck-[0-9a-f]{8}", runtime.interface):
            await context.dns.cleanup(runtime.interface)
            await context.runner.run(["ip", "link", "delete", "dev", runtime.interface], check=False, timeout=5)
        if runtime.process:
            with suppress(KeyError, TypeError, ValueError):
                await context.runner.stop(OwnedProcess.from_dict(runtime.process))

    async def _cleanup_known_interfaces(self) -> None:
        """Clean stale interfaces only when their UUID prefix belongs to a stored V-Deck connection."""
        protocols = self.registry.protocols()
        if not protocols:
            return
        context = self.registry.get(protocols[0]).context
        for metadata in self.store.list():
            owned_interface = interface_name(metadata.id)
            if await context.inspector.interface_exists(owned_interface):
                await context.dns.cleanup(owned_interface)
                await context.runner.run(["ip", "link", "delete", "dev", owned_interface], check=False, timeout=5)

    async def delete(self, connection_id: str) -> dict[str, Any]:
        state = self.store.load_state()
        runtime = self.store.load_runtime()
        if runtime.connection_id == connection_id or state.active_connection_id == connection_id:
            await self.stop(manual=True)
        async with self.lock:
            self.store.delete(connection_id)
            state = self.store.load_state()
            if state.last_active_connection_id == connection_id:
                state.last_active_connection_id = None
                self.store.save_state(state)
        return ok()

    async def health_check(self) -> None:
        runtime = self.store.load_runtime()
        state = self.store.load_state()
        if runtime.state != ConnectionState.CONNECTED.value or state.desired_state != DesiredState.ON.value:
            return
        try:
            metadata = self.store.get(runtime.connection_id or "")
            status = await self.registry.get(metadata.protocol).health(metadata, runtime)
        except Exception:
            status = {"connected": False, "healthy": False}
        healthy = bool(status.get("healthy", status.get("connected")))
        if not healthy and (not self._recovery_task or self._recovery_task.done()):
            self._recovery_task = asyncio.create_task(self._recover(runtime.connection_id or ""))

    async def network_event(self) -> None:
        state = self.store.load_state()
        runtime = self.store.load_runtime()
        if (
            state.desired_state == DesiredState.ON.value
            and runtime.connection_id
            and (not self._recovery_task or self._recovery_task.done())
        ):
            self._recovery_task = asyncio.create_task(self._recover(runtime.connection_id))

    async def _recover(self, connection_id: str) -> None:
        metadata = self.store.get(connection_id)
        for attempt, delay in enumerate(self.recovery_delays, 1):
            if delay:
                await asyncio.sleep(delay)
            async with self.lock:
                state = self.store.load_state()
                runtime = self.store.load_runtime()
                if state.desired_state != DesiredState.ON.value or runtime.connection_id != connection_id:
                    return
                runtime.state = ConnectionState.RECOVERING.value
                runtime.recovery_attempt = attempt
                runtime.boot_id = self.store.current_boot_id()
                self.store.save_runtime(runtime)
                backend = self.registry.get(metadata.protocol)
                try:
                    await backend.stop(metadata, runtime)
                    status = await backend.start(metadata, runtime)
                    if not status.get("connected"):
                        raise VDeckError("RECOVERY_NOT_CONNECTED", "Recovery did not confirm the tunnel")
                    runtime = self.store.load_runtime()
                    runtime.state = ConnectionState.CONNECTED.value
                    runtime.connection_id = connection_id
                    runtime.started_at = utc_now()
                    runtime.established_once = True
                    runtime.recovery_attempt = 0
                    state.active_connection_id = connection_id
                    state.last_active_connection_id = connection_id
                    self.store.save_state(state)
                    if state.kill_switch:
                        await self._enable_kill_switch(backend, metadata, runtime)
                    self.store.save_runtime(runtime)
                    return
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self._record_error(connection_id, metadata.protocol, "recover", exc)
                    if state.kill_switch and attempt < len(self.recovery_delays):
                        try:
                            await self._refresh_endpoint_cache(backend, metadata, runtime)
                        except Exception as refresh_exc:
                            self._record_error(
                                connection_id,
                                metadata.protocol,
                                "endpoint_refresh",
                                refresh_exc,
                            )
        async with self.lock:
            runtime = self.store.load_runtime()
            runtime.state = ConnectionState.ERROR.value
            runtime.error_code = "RECOVERY_EXHAUSTED"
            runtime.error_message = "Automatic recovery attempts were exhausted"
            self.store.save_runtime(runtime)

    async def _enable_kill_switch(self, backend: Any, metadata: Any, runtime: RuntimeState) -> None:
        if not backend.endpoint_addresses(runtime):
            await backend.resolve_endpoint_cache(metadata, runtime)
        await self.firewall.enable(runtime.interface or "", backend.endpoint_addresses(runtime))
        runtime.firewall_active = True
        self.store.save_runtime(runtime)

    async def _refresh_endpoint_cache(self, backend: Any, metadata: Any, runtime: RuntimeState) -> None:
        cached_addresses = backend.endpoint_addresses(runtime)
        dns_addresses = await backend.context.inspector.system_dns_servers()
        await self.firewall.enable(runtime.interface or "", cached_addresses, dns_addresses)
        try:
            await backend.resolve_endpoint_cache(metadata, runtime, force=True)
        finally:
            restored_addresses = backend.endpoint_addresses(runtime) or cached_addresses
            await self.firewall.enable(runtime.interface or "", restored_addresses)
            runtime.firewall_active = True
            self.store.save_runtime(runtime)

    def _record_error(self, connection_id: str, protocol: str, operation: str, exc: Exception) -> None:
        self.errors.append(
            {
                "timestamp": utc_now(),
                "connection": connection_id,
                "protocol": protocol,
                "operation": operation,
                "summary": str(exc),
            }
        )

    def snapshot(self) -> dict[str, Any]:
        runtime = self.store.load_runtime().to_dict()
        runtime.pop("boot_id", None)
        runtime.pop("endpoint_cache", None)
        return {
            "settings": self.store.load_state().to_dict(),
            "runtime": runtime,
            "connections": [item.to_dict() for item in self.store.list()],
        }
