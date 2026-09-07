"""Serialized single-active-VPN orchestration and recovery state machine."""

from __future__ import annotations

import asyncio
import re
from contextlib import suppress
from typing import Any

from .backends.registry import BackendRegistry
from .backends.wireguard import WireGuardBackend
from .errors import VDeckError, ok
from .logging_utils import ErrorHistory, safe_exception_details
from .models import ConnectionState, DesiredState, PersistentState, RuntimeState
from .network import FirewallManager, interface_name
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
        self.network_revision = 0

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
                        runtime.state = ConnectionState.ERROR.value
                        runtime.error_code = "CLEANUP_PENDING"
                        runtime.error_message = "Previous VPN cleanup needs to be retried"
                        self.store.save_runtime(runtime)
                        raise VDeckError("CLEANUP_PENDING", runtime.error_message) from exc
                else:
                    await self._cleanup_orphaned_runtime(runtime)
                self.store.save_runtime(RuntimeState())
                state.active_connection_id = None
                self.store.save_state(state)
            await self._cleanup_known_interfaces()
            protocols = self.registry.protocols()
            if protocols:
                await self.registry.get(protocols[0]).context.dns.cleanup(None)
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
            self._recovery_task = asyncio.create_task(self._recover(restart_connection_id))
        elif state.auto_connect and state.desired_state == DesiredState.ON.value and state.last_active_connection_id:
            # Cold boot can precede DHCP/default routes. Keep desired ON and
            # use bounded recovery, allowing the network monitor to start now.
            self.store.get(state.last_active_connection_id)
            self.store.save_runtime(
                RuntimeState(
                    state=ConnectionState.RECOVERING.value,
                    connection_id=state.last_active_connection_id,
                    boot_id=current_boot_id,
                )
            )
            self._recovery_task = asyncio.create_task(self._recover(state.last_active_connection_id))

    async def start(self, connection_id: str, *, user_initiated: bool = True) -> dict[str, Any]:
        cancelled_recovery = False
        if self._recovery_task and not self._recovery_task.done() and user_initiated:
            self._recovery_task.cancel()
            await asyncio.gather(self._recovery_task, return_exceptions=True)
            cancelled_recovery = True
        async with self.lock:
            self.network_revision += 1
            metadata = self.store.get(connection_id)
            if self.store.logger:
                self.store.logger.info("profile loaded connection=%s protocol=%s", connection_id, metadata.protocol)
            if metadata.import_error:
                raise VDeckError("MIGRATION_IMPORT_FAILED", metadata.import_error)
            state = self.store.load_state()
            runtime = self.store.load_runtime()
            if cancelled_recovery and runtime.state == ConnectionState.RECOVERING.value:
                # Cancellation during backoff happens outside the attempt's
                # cleanup handler. Unblock manual Connect/switch without losing
                # any ownership records still requiring cleanup below.
                runtime.state = ConnectionState.ERROR.value
                self.store.save_runtime(runtime)
            if runtime.state in {
                ConnectionState.CONNECTING.value,
                ConnectionState.DISCONNECTING.value,
                ConnectionState.RECOVERING.value,
            }:
                raise VDeckError("OPERATION_IN_PROGRESS", "Another VPN operation is already in progress")
            if runtime.state == ConnectionState.CONNECTED.value and runtime.connection_id == connection_id:
                return ok(connection=metadata.to_dict(), runtime=runtime.to_dict())
            if runtime.state == ConnectionState.ERROR.value and (
                runtime.interface
                or runtime.process
                or runtime.owned_routes
                or runtime.ipv6_guard
                or runtime.firewall_active
            ):
                previous = None
                with suppress(VDeckError):
                    previous = self.store.get(runtime.connection_id or connection_id)
                await self._stop_locked(previous, runtime, state, manual=False)
                runtime = self.store.load_runtime()
                state = self.store.load_state()
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
                if state.kill_switch:
                    await self._enable_kill_switch(backend, metadata, runtime)
                    status = await backend.verify_connected(metadata, runtime)
                runtime.state = ConnectionState.CONNECTED.value
                runtime.connection_id = connection_id
                runtime.started_at = utc_now()
                runtime.established_once = True
                runtime.error_code = None
                runtime.error_message = None
                metadata.last_used_at = runtime.started_at
                metadata.updated_at = runtime.started_at
                self.store.update_metadata(metadata)
                self.store.save_runtime(runtime)
                if self.store.logger:
                    self.store.logger.info("CONNECTED protocol=%s connection=%s", metadata.protocol, connection_id)
                return ok(connection=metadata.to_dict(), runtime=runtime.to_dict(), status=status)
            except (Exception, asyncio.CancelledError) as exc:
                self._record_error(connection_id, metadata.protocol, "switch" if switching else "start", exc)
                runtime.state = ConnectionState.ERROR.value
                for cleanup in (lambda: backend.cleanup(metadata, runtime), self.firewall.disable):
                    try:
                        await cleanup()
                        if cleanup == self.firewall.disable:
                            runtime.firewall_active = False
                    except Exception as cleanup_error:
                        self._record_error(connection_id, metadata.protocol, "cleanup_pending", cleanup_error)
                # Do not replace runtime with an empty state: failed cleanup
                # still needs its PID/route/DNS ownership records on next retry.
                runtime.state = ConnectionState.ERROR.value
                runtime.connection_id = connection_id
                runtime.error_code = (
                    exc.code
                    if isinstance(exc, VDeckError)
                    else "START_CANCELLED"
                    if isinstance(exc, asyncio.CancelledError)
                    else "START_FAILED"
                )
                runtime.error_message = (
                    exc.message if isinstance(exc, VDeckError) else "Unable to start the VPN connection"
                )
                self.store.save_runtime(runtime)
                state.active_connection_id = None
                state.desired_state = DesiredState.OFF.value
                self.store.save_state(state)
                if isinstance(exc, VDeckError | asyncio.CancelledError):
                    raise
                raise VDeckError("START_FAILED", "Unable to start the VPN connection") from exc

    async def stop(self, *, manual: bool = True) -> dict[str, Any]:
        self.network_revision += 1
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
        failure = None
        try:
            if metadata:
                await self.registry.get(metadata.protocol).stop(metadata, runtime)
            else:
                await self._cleanup_orphaned_runtime(runtime)
        except Exception as exc:
            failure = exc
        try:
            await self.firewall.disable()
            runtime.firewall_active = False
            if self.store.logger:
                self.store.logger.info("firewall restored")
        except Exception as exc:
            failure = failure or exc
        state.active_connection_id = None
        if manual:
            state.desired_state = DesiredState.OFF.value
        self.store.save_state(state)
        if failure:
            self._record_error(
                runtime.connection_id or "unknown", metadata.protocol if metadata else "unknown", "disconnect", failure
            )
            runtime.state = ConnectionState.ERROR.value
            runtime.error_code = "CLEANUP_PENDING"
            runtime.error_message = "Owned VPN resources could not all be removed; retry Disconnect"
            self.store.save_runtime(runtime)
            raise VDeckError("CLEANUP_PENDING", runtime.error_message) from failure
        else:
            self.store.save_runtime(RuntimeState())

    async def _cleanup_orphaned_runtime(self, runtime: RuntimeState) -> None:
        """Remove only resources carrying V-Deck ownership markers."""
        protocols = self.registry.protocols()
        if not protocols:
            return
        context = self.registry.get(protocols[0]).context
        if runtime.interface and not re.fullmatch(r"vdeck-[0-9a-f]{8}", runtime.interface):
            raise VDeckError("CLEANUP_PENDING", "Invalid interface in the cleanup journal")
        # Metadata may have been lost, but the journal still owns its PID and
        # routes. Use the same attempt-all/verify cleanup as normal Disconnect;
        # an early DNS/route error must not skip process termination or erase it.
        await WireGuardBackend(context).stop(None, runtime)

    async def _cleanup_known_interfaces(self) -> None:
        """A profile-derived name alone is not proof of interface ownership."""
        protocols = self.registry.protocols()
        if not protocols:
            return
        context = self.registry.get(protocols[0]).context
        for metadata in self.store.list():
            owned_interface = interface_name(metadata.id)
            if await context.inspector.interface_exists(owned_interface):
                raise VDeckError(
                    "INTERFACE_ALREADY_EXISTS", "An interface exists without a matching runtime ownership journal"
                )

    async def delete(self, connection_id: str) -> dict[str, Any]:
        state = self.store.load_state()
        runtime = self.store.load_runtime()
        if runtime.connection_id == connection_id or state.active_connection_id == connection_id:
            await self.stop(manual=True)
        async with self.lock:
            # Connect may have won the lock after the earlier snapshot. Never
            # delete its metadata while leaving that newly started VPN alive.
            state = self.store.load_state()
            runtime = self.store.load_runtime()
            if runtime.connection_id == connection_id or state.active_connection_id == connection_id:
                await self._stop_locked(self.store.get(connection_id), runtime, state, manual=True)
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
        except Exception as exc:
            self._record_error(runtime.connection_id or "unknown", "unknown", "health", exc)
            status = {"connected": False, "healthy": False}
        healthy = bool(status.get("healthy", status.get("connected")))
        current = self.store.load_runtime()
        if (
            current.state != ConnectionState.CONNECTED.value
            or current.connection_id != runtime.connection_id
            or current.started_at != runtime.started_at
            or self.store.load_state().desired_state != DesiredState.ON.value
        ):
            return  # a slow probe belongs to the session before OFF/switch/reconnect
        if not healthy and (not self._recovery_task or self._recovery_task.done()):
            self._recovery_task = asyncio.create_task(self._recover(runtime.connection_id or ""))

    async def network_event(self) -> None:
        self.network_revision += 1
        state = self.store.load_state()
        runtime = self.store.load_runtime()
        if runtime.state == ConnectionState.CONNECTED.value:
            await self.health_check()
            return
        if (
            state.desired_state == DesiredState.ON.value
            and runtime.connection_id
            and (runtime.established_once or state.auto_connect)
            and runtime.state == ConnectionState.ERROR.value
            and runtime.error_code == "RECOVERY_EXHAUSTED"
            and (not self._recovery_task or self._recovery_task.done())
        ):
            self._recovery_task = asyncio.create_task(self._recover(runtime.connection_id))

    async def _recover(self, connection_id: str) -> None:
        for attempt, delay in enumerate(self.recovery_delays, 1):
            if delay:
                await asyncio.sleep(delay)
            async with self.lock:
                state = self.store.load_state()
                runtime = self.store.load_runtime()
                if state.desired_state != DesiredState.ON.value or runtime.connection_id != connection_id:
                    return
                metadata = self.store.get(connection_id)
                self.network_revision += 1
                runtime.state = ConnectionState.RECOVERING.value
                runtime.recovery_attempt = attempt
                runtime.boot_id = self.store.current_boot_id()
                self.store.save_runtime(runtime)
                backend = self.registry.get(metadata.protocol)
                try:
                    await backend.stop(metadata, runtime)
                    if state.kill_switch:
                        # The interface name is deterministic, but cleanup has
                        # cleared runtime.interface. Permit the upcoming tunnel
                        # BEFORE backend.start performs its traffic/DNS probes.
                        await self._enable_kill_switch(backend, metadata, runtime)
                    status = await backend.start(metadata, runtime)
                    if not status.get("connected"):
                        raise VDeckError("RECOVERY_NOT_CONNECTED", "Recovery did not confirm the tunnel")
                    runtime = self.store.load_runtime()
                    if state.kill_switch:
                        await self._enable_kill_switch(backend, metadata, runtime)
                        status = await backend.verify_connected(metadata, runtime)
                    runtime.state = ConnectionState.CONNECTED.value
                    runtime.connection_id = connection_id
                    runtime.started_at = utc_now()
                    runtime.established_once = True
                    runtime.recovery_attempt = 0
                    runtime.error_code = None
                    runtime.error_message = None
                    state.active_connection_id = connection_id
                    state.last_active_connection_id = connection_id
                    self.store.save_state(state)
                    self.store.save_runtime(runtime)
                    if self.store.logger:
                        self.store.logger.info(
                            "CONNECTED after recovery protocol=%s connection=%s", metadata.protocol, connection_id
                        )
                    return
                except asyncio.CancelledError:
                    try:
                        await backend.cleanup(metadata, runtime)
                    finally:
                        runtime.state = ConnectionState.ERROR.value
                        runtime.error_code = "RECOVERY_CANCELLED"
                        runtime.error_message = "Recovery cancelled"
                        self.store.save_runtime(runtime)
                    raise
                except Exception as exc:
                    runtime.state = ConnectionState.RECOVERING.value
                    try:
                        await backend.cleanup(metadata, runtime)
                    except Exception as cleanup_error:
                        self._record_error(connection_id, metadata.protocol, "recovery_cleanup", cleanup_error)
                    runtime.state = ConnectionState.RECOVERING.value
                    runtime.error_code = exc.code if isinstance(exc, VDeckError) else "RECOVERY_FAILED"
                    runtime.error_message = exc.message if isinstance(exc, VDeckError) else "Recovery failed"
                    self.store.save_runtime(runtime)
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
                    elif attempt < len(self.recovery_delays):
                        try:
                            await backend.resolve_endpoint_cache(metadata, runtime, force=True)
                        except Exception as refresh_exc:
                            self._record_error(connection_id, metadata.protocol, "endpoint_refresh", refresh_exc)
        async with self.lock:
            runtime = self.store.load_runtime()
            if self.store.load_state().desired_state != DesiredState.ON.value or runtime.connection_id != connection_id:
                return
            runtime.state = ConnectionState.ERROR.value
            runtime.error_code = "RECOVERY_EXHAUSTED"
            runtime.error_message = "Automatic recovery attempts were exhausted"
            self.store.save_runtime(runtime)
            if self.store.logger:
                self.store.logger.warning(
                    "recovery exhausted connection=%s attempts=%d code=RECOVERY_EXHAUSTED cleanup_stage=%s",
                    connection_id,
                    len(self.recovery_delays),
                    runtime.stage,
                )

    async def _enable_kill_switch(self, backend: Any, metadata: Any, runtime: RuntimeState) -> None:
        interface = await self._firewall_interface(backend, metadata, runtime)
        if not backend.endpoint_addresses(runtime):
            await self._refresh_endpoint_cache(backend, metadata, runtime)
        runtime.stage = "FIREWALL"
        runtime.firewall_active = True  # journal before nft's apply/cancellation window
        self.store.save_runtime(runtime)
        if self.store.logger:
            self.store.logger.info("connect stage=FIREWALL protocol=%s interface=%s", metadata.protocol, interface)
        await self.firewall.enable(interface, backend.endpoint_addresses(runtime))
        runtime.firewall_active = True
        self.store.save_runtime(runtime)
        if self.store.logger:
            self.store.logger.info("Kill Switch apply succeeded interface=%s", interface)

    async def _firewall_interface(self, backend: Any, metadata: Any, runtime: RuntimeState) -> str:
        if runtime.interface:
            return str(runtime.interface)
        interface = interface_name(metadata.id)
        if await backend.context.inspector.interface_exists(interface):
            raise VDeckError("INTERFACE_ALREADY_EXISTS", "Refusing to permit an interface without an ownership journal")
        return interface

    async def _refresh_endpoint_cache(self, backend: Any, metadata: Any, runtime: RuntimeState) -> None:
        cached_addresses = backend.endpoint_addresses(runtime)
        dns_addresses = await backend.context.inspector.system_dns_servers()
        interface = await self._firewall_interface(backend, metadata, runtime)
        runtime.firewall_active = True
        self.store.save_runtime(runtime)
        await self.firewall.enable(interface, cached_addresses, dns_addresses)
        try:
            await backend.resolve_endpoint_cache(metadata, runtime, force=True)
        finally:
            restored_addresses = backend.endpoint_addresses(runtime) or cached_addresses
            await self.firewall.enable(interface, restored_addresses)
            runtime.firewall_active = True
            self.store.save_runtime(runtime)

    def _record_error(self, connection_id: str, protocol: str, operation: str, exc: BaseException) -> None:
        if self.store.logger:
            self.store.logger.error(
                "VPN operation failed operation=%s connection=%s protocol=%s stage=%s code=%s exception=%s details=%s",
                operation,
                connection_id,
                protocol,
                self.store.load_runtime().stage,
                getattr(exc, "code", type(exc).__name__),
                type(exc).__name__,
                safe_exception_details(exc),
            )
        self.errors.append(
            {
                "timestamp": utc_now(),
                "connection": connection_id,
                "protocol": protocol,
                "operation": operation,
                "summary": exc.message if isinstance(exc, VDeckError) else type(exc).__name__,
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
