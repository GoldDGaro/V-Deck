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
    async def resolve_endpoint(self, endpoint):
        return ["203.0.113.10"]

    async def interface_exists(self, interface):
        return False


class FakeBackend:
    protocol_id = "wireguard"

    def __init__(self, store):
        self.store = store
        self.context = SimpleNamespace(inspector=FakeInspector())
        self.fail_start = False
        self.connected = False
        self.starts = 0
        self.stops = 0

    async def start(self, metadata, runtime):
        self.starts += 1
        if self.fail_start:
            raise VDeckError("SYNTHETIC_FAILURE", "Synthetic start failure")
        self.connected = True
        runtime.interface = "vdeck-fake"
        self.store.save_runtime(runtime)
        return {"connected": True, "tunnel": True}

    async def stop(self, metadata, runtime):
        self.stops += 1
        self.connected = False

    async def cleanup(self, metadata, runtime):
        await self.stop(metadata, runtime)

    async def status(self, metadata, runtime):
        return {"connected": self.connected, "tunnel": self.connected}

    async def diagnostics(self, metadata, runtime):
        return await self.status(metadata, runtime)


class FakeFirewall:
    def __init__(self):
        self.enabled = False
        self.enable_calls = 0
        self.disable_calls = 0

    async def enable(self, interface, addresses):
        self.enabled = True
        self.enable_calls += 1

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
