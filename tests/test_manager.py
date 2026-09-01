from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vdeck.backends.registry import BackendRegistry
from vdeck.errors import VDeckError
from vdeck.logging_utils import ErrorHistory
from vdeck.manager import VPNManager
from vdeck.models import ConnectionState, DesiredState, Protocol
from vdeck.storage import VDeckStore

FIXTURES = Path(__file__).parent / "fixtures"


class FakeInspector:
    def __init__(self):
        self.resolve_calls = 0
        self.addresses = ["203.0.113.10"]

    async def resolve_endpoint(self, endpoint):
        self.resolve_calls += 1
        return list(self.addresses)

    async def interface_exists(self, interface):
        return False

    async def system_dns_servers(self):
        return ["192.0.2.53"]


class FakeBackend:
    protocol_id = "wireguard"

    def __init__(self, store):
        self.store = store
        self.inspector = FakeInspector()
        self.context = SimpleNamespace(inspector=self.inspector)
        self.fail_start = False
        self.failures_remaining = 0
        self.connected = False
        self.health_result = None
        self.starts = 0
        self.stops = 0

    async def start(self, metadata, runtime):
        self.starts += 1
        await self.resolve_endpoint_cache(metadata, runtime)
        if self.fail_start or self.failures_remaining > 0:
            self.failures_remaining = max(0, self.failures_remaining - 1)
            raise VDeckError("SYNTHETIC_FAILURE", "Synthetic start failure")
        self.connected = True
        runtime.interface = "vdeck-fake"
        self.store.save_runtime(runtime)
        return {"connected": True, "tunnel": True}

    async def stop(self, metadata, runtime):
        self.stops += 1
        self.connected = False
        runtime.interface = None
        runtime.process = {}
        runtime.owned_routes = []
        self.store.save_runtime(runtime)

    async def cleanup(self, metadata, runtime):
        await self.stop(metadata, runtime)

    async def status(self, metadata, runtime):
        return {"connected": self.connected, "tunnel": self.connected}

    async def health(self, metadata, runtime):
        return self.health_result or await self.status(metadata, runtime)

    async def resolve_endpoint_cache(self, metadata, runtime, *, force=False):
        endpoints = self.store.parsed_runtime_info(metadata.id).get("endpoints", [])
        if force or not all(runtime.endpoint_cache.get(str(endpoint)) for endpoint in endpoints):
            resolved = {}
            for endpoint in endpoints:
                resolved[str(endpoint)] = await self.inspector.resolve_endpoint(str(endpoint))
            runtime.endpoint_cache = resolved
            self.store.save_runtime(runtime)
        return runtime.endpoint_cache

    def endpoint_addresses(self, runtime):
        return [address for values in runtime.endpoint_cache.values() for address in values]

    async def diagnostics(self, metadata, runtime):
        return await self.status(metadata, runtime)


class FakeFirewall:
    def __init__(self):
        self.enabled = False
        self.enable_calls = 0
        self.disable_calls = 0
        self.rules = []

    async def enable(self, interface, addresses, recovery_dns_addresses=None):
        self.enabled = True
        self.enable_calls += 1
        self.rules.append((interface, list(addresses), list(recovery_dns_addresses or [])))

    async def disable(self):
        self.enabled = False
        self.disable_calls += 1

    async def active(self):
        return self.enabled


class ManagerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = VDeckStore(Path(self.temp.name) / "store")
        self.first = self.store.import_connection(Protocol.WIREGUARD, FIXTURES / "wireguard.conf", "A")
        self.second = self.store.import_connection(Protocol.WIREGUARD, FIXTURES / "wireguard.conf", "B")
        self.backend = FakeBackend(self.store)
        self.firewall = FakeFirewall()
        self.manager = VPNManager(
            self.store,
            BackendRegistry([self.backend]),
            self.firewall,
            ErrorHistory(self.store.state_dir / "errors.json"),
            recovery_delays=(0, 0),
        )

    async def asyncTearDown(self):
        if self.manager._recovery_task:
            self.manager._recovery_task.cancel()
            await asyncio.gather(self.manager._recovery_task, return_exceptions=True)
        self.temp.cleanup()

    async def test_connect_and_manual_off_desired_state(self):
        await self.manager.start(self.first.id)
        self.assertEqual(self.store.load_runtime().state, ConnectionState.CONNECTED.value)
        self.assertEqual(self.store.load_state().desired_state, DesiredState.ON.value)
        await self.manager.stop(manual=True)
        self.assertEqual(self.store.load_state().desired_state, DesiredState.OFF.value)
        self.assertEqual(self.store.load_runtime().state, ConnectionState.DISCONNECTED.value)

    async def test_internal_restart_and_endpoint_cache_are_not_exposed_in_snapshot(self):
        self.store.current_boot_id = lambda: "boot-a"
        await self.manager.start(self.first.id)
        runtime = self.manager.snapshot()["runtime"]
        self.assertNotIn("boot_id", runtime)
        self.assertNotIn("endpoint_cache", runtime)

    async def test_single_active_switch(self):
        await self.manager.start(self.first.id)
        await self.manager.start(self.second.id)
        self.assertEqual(self.store.load_runtime().connection_id, self.second.id)
        self.assertGreaterEqual(self.backend.stops, 1)

    async def test_failed_switch_does_not_restore_a_and_removes_kill_switch(self):
        state = self.store.load_state()
        state.kill_switch = True
        self.store.save_state(state)
        await self.manager.start(self.first.id)
        self.assertTrue(self.firewall.enabled)
        self.backend.fail_start = True
        with self.assertRaises(VDeckError):
            await self.manager.start(self.second.id)
        self.assertFalse(self.firewall.enabled)
        self.assertIsNone(self.store.load_state().active_connection_id)
        self.assertEqual(self.store.load_state().desired_state, DesiredState.OFF.value)

    async def test_initial_failure_never_leaves_firewall(self):
        state = self.store.load_state()
        state.kill_switch = True
        self.store.save_state(state)
        self.backend.fail_start = True
        with self.assertRaises(VDeckError):
            await self.manager.start(self.first.id)
        self.assertFalse(self.firewall.enabled)
        self.assertEqual(self.store.load_runtime().state, ConnectionState.ERROR.value)

    async def test_unexpected_loss_recovers(self):
        await self.manager.start(self.first.id)
        self.backend.connected = False
        await self.manager.health_check()
        self.assertIsNotNone(self.manager._recovery_task)
        await self.manager._recovery_task
        self.assertEqual(self.store.load_runtime().state, ConnectionState.CONNECTED.value)
        self.assertEqual(self.store.load_state().desired_state, DesiredState.ON.value)

    async def test_dead_wireguard_probe_starts_recovery(self):
        await self.manager.start(self.first.id)
        self.backend.health_result = {
            "connected": True,
            "healthy": False,
            "handshake_fresh": False,
            "probe_succeeded": False,
        }
        await self.manager.health_check()
        self.assertIsNotNone(self.manager._recovery_task)
        await self.manager._recovery_task
        self.assertGreaterEqual(self.backend.starts, 2)

    async def test_idle_wireguard_with_successful_probe_does_not_recover(self):
        await self.manager.start(self.first.id)
        self.backend.health_result = {
            "connected": True,
            "healthy": True,
            "handshake_fresh": False,
            "probe_succeeded": True,
        }
        await self.manager.health_check()
        self.assertIsNone(self.manager._recovery_task)
        self.assertEqual(self.backend.starts, 1)

    async def test_recovery_exhaustion_preserves_desired_on_and_kill_switch(self):
        state = self.store.load_state()
        state.kill_switch = True
        self.store.save_state(state)
        await self.manager.start(self.first.id)
        self.backend.connected = False
        self.backend.fail_start = True
        await self.manager.health_check()
        await self.manager._recovery_task
        self.assertEqual(self.store.load_runtime().state, ConnectionState.ERROR.value)
        self.assertEqual(self.store.load_state().desired_state, DesiredState.ON.value)
        self.assertTrue(self.firewall.enabled)
        await self.manager.stop(manual=True)
        self.assertFalse(self.firewall.enabled)

    async def test_delete_active_stops_first(self):
        await self.manager.start(self.first.id)
        await self.manager.delete(self.first.id)
        self.assertEqual([item.id for item in self.store.list()], [self.second.id])
        self.assertEqual(self.store.load_runtime().state, ConnectionState.DISCONNECTED.value)

    async def test_auto_connect_respects_manual_off(self):
        state = self.store.load_state()
        state.auto_connect = True
        state.last_active_connection_id = self.first.id
        state.desired_state = DesiredState.OFF.value
        self.store.save_state(state)
        await self.manager.initialize()
        self.assertEqual(self.backend.starts, 0)

    async def test_unexpected_same_boot_restart_recovers_with_auto_connect_off(self):
        self.store.current_boot_id = lambda: "boot-a"
        await self.manager.start(self.first.id)
        state = self.store.load_state()
        state.auto_connect = False
        self.store.save_state(state)
        restarted = VPNManager(
            self.store,
            BackendRegistry([self.backend]),
            self.firewall,
            ErrorHistory(self.store.state_dir / "errors.json"),
            recovery_delays=(0,),
        )
        self.manager = restarted
        await restarted.initialize()
        self.assertIsNotNone(restarted._recovery_task)
        await restarted._recovery_task
        self.assertEqual(self.store.load_runtime().state, ConnectionState.CONNECTED.value)
        self.assertEqual(self.store.load_state().active_connection_id, self.first.id)
        self.assertEqual(self.backend.starts, 2)

    async def test_cold_boot_with_auto_connect_off_does_not_recover(self):
        self.store.current_boot_id = lambda: "boot-a"
        await self.manager.start(self.first.id)
        self.store.current_boot_id = lambda: "boot-b"
        restarted = VPNManager(
            self.store,
            BackendRegistry([self.backend]),
            self.firewall,
            ErrorHistory(self.store.state_dir / "errors.json"),
            recovery_delays=(0,),
        )
        self.manager = restarted
        await restarted.initialize()
        self.assertIsNone(restarted._recovery_task)
        self.assertEqual(self.backend.starts, 1)
        self.assertEqual(self.store.load_state().desired_state, DesiredState.ON.value)

    async def test_manual_off_before_reboot_wins_over_auto_connect(self):
        self.store.current_boot_id = lambda: "boot-a"
        state = self.store.load_state()
        state.auto_connect = True
        self.store.save_state(state)
        await self.manager.start(self.first.id)
        await self.manager.stop(manual=True)
        starts = self.backend.starts
        self.store.current_boot_id = lambda: "boot-b"
        await self.manager.initialize()
        self.assertEqual(self.backend.starts, starts)
        self.assertEqual(self.store.load_state().desired_state, DesiredState.OFF.value)

    async def test_kill_switch_recovery_uses_cached_hostname_address(self):
        state = self.store.load_state()
        state.kill_switch = True
        self.store.save_state(state)
        await self.manager.start(self.first.id)
        self.assertEqual(self.backend.inspector.resolve_calls, 1)
        self.backend.health_result = {"connected": True, "healthy": False}
        await self.manager.health_check()
        await self.manager._recovery_task
        self.assertEqual(self.backend.inspector.resolve_calls, 1)
        self.assertEqual(self.firewall.rules[-1][1], ["203.0.113.10"])
        self.assertEqual(self.firewall.rules[-1][2], [])

    async def test_failed_cached_endpoint_refreshes_through_specific_dns(self):
        state = self.store.load_state()
        state.kill_switch = True
        self.store.save_state(state)
        await self.manager.start(self.first.id)
        self.backend.inspector.addresses = ["203.0.113.11"]
        self.backend.failures_remaining = 1
        self.backend.health_result = {"connected": True, "healthy": False}
        await self.manager.health_check()
        await self.manager._recovery_task
        self.assertEqual(self.backend.inspector.resolve_calls, 2)
        self.assertIn(("", ["203.0.113.10"], ["192.0.2.53"]), self.firewall.rules)
        self.assertEqual(self.firewall.rules[-1][1], ["203.0.113.11"])
        self.assertEqual(self.firewall.rules[-1][2], [])

    async def test_startup_removes_stale_owned_firewall_with_clean_runtime(self):
        self.firewall.enabled = True
        await self.manager.initialize()
        self.assertFalse(self.firewall.enabled)


class RegistryTests(unittest.TestCase):
    def test_duplicate_and_unknown_backends(self):
        fake = SimpleNamespace(protocol_id="wireguard")
        registry = BackendRegistry([fake])
        with self.assertRaises(VDeckError):
            registry.register(fake)
        with self.assertRaises(VDeckError):
            registry.get("future-protocol")


if __name__ == "__main__":
    unittest.main()
