from __future__ import annotations

import asyncio
import logging
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from vdeck.backends.amneziawg import AmneziaWGBackend
from vdeck.backends.registry import BackendRegistry
from vdeck.backends.wireguard import WireGuardBackend
from vdeck.errors import VDeckError
from vdeck.logging_utils import ErrorHistory
from vdeck.manager import VPNManager
from vdeck.models import Protocol, RuntimeState
from vdeck.network import interface_name
from vdeck.runner import CommandResult, OwnedProcess
from vdeck.storage import VDeckStore

FIXTURES = Path(__file__).parent / "fixtures"


class SimulatedLinux:
    """Mock only the OS boundary; backend, store and manager remain real.

    These tests do not execute Linux VPN binaries or create real TUN devices.
    """

    def __init__(self):
        self.calls = []
        self.spawn_calls = []
        self.live = {99999: True}  # unrelated process must survive cleanup
        self.exit_codes = {}
        self.stopped = []
        self.tun = False
        self.make_tun = True
        self.socket_exists = False
        self.uapi_available = True
        self.kernel_available = False
        self.fail_setconf = False
        self.startup_exit = None
        self.exit_after_start = False
        self.next_pid = 1000
        self.tables = {}

    async def run(self, args, **options):
        self.calls.append(list(args))  # never retain config stdin
        if args[:3] == ["nft", "list", "table"]:
            table = self.tables.get(args[-1])
            return CommandResult(tuple(args), 0 if table else 1, table or "", "No such file" if not table else "")
        if args[:3] == ["nft", "delete", "table"]:
            self.tables.pop(args[-1], None)
        if args[:2] == ["nft", "-f"]:
            text = options.get("input_text", "")
            self.tables["vdeck_ipv6" if "table inet vdeck_ipv6" in text else "vdeck"] = text
        if args[:3] == ["ip", "link", "add"]:
            self.tun = self.kernel_available
            return CommandResult(tuple(args), 0 if self.kernel_available else 1, "", "")
        if args[:3] == ["ip", "link", "delete"]:
            self.tun = False
        if "setconf" in args and self.fail_setconf:
            raise VDeckError("COMMAND_FAILED", "Synthetic setconf failure")
        output = ""
        if "dump" in args:
            output = (
                f"private\tpublic\t0\toff\npeer\tpsk\t198.51.100.1:51820\t0.0.0.0/0\t{int(time.time())}\t100\t100\t25\n"
            )
        return CommandResult(tuple(args), 0, output, "")

    async def start(self, args, *, env, stdout_path, on_started=None, bundled=False):
        self.spawn_calls.append((list(args), dict(env)))
        self.next_pid += 1
        owned = OwnedProcess(self.next_pid, str(self.next_pid), args[0], list(args))
        self.live[owned.pid] = True
        self.tun = self.make_tun
        self.socket_exists = True
        if on_started:
            on_started(owned)
        code = self.startup_exit
        if "--foreground" not in args and env.get("WG_PROCESS_FOREGROUND") != "1":
            code = 0  # successful upstream daemonization still exits the parent
        if code is not None:
            self.live[owned.pid] = False
            self.exit_codes[owned.pid] = code
            raise VDeckError("PROCESS_START_FAILED", "Synthetic child exited during startup")
        if self.exit_after_start:
            self.live[owned.pid] = False
            self.exit_codes[owned.pid] = 9
        return owned

    def is_alive(self, owned):
        return self.live.get(owned.pid, False)

    def exit_code(self, owned):
        return self.exit_codes.get(owned.pid)

    async def stop(self, owned, **options):
        self.stopped.append(owned.pid)
        self.live[owned.pid] = False


class UserspaceStartupMixin:
    backend_type = AmneziaWGBackend

    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.logger = logging.getLogger(f"startup-test-{self.temp.name}")
        self.store = VDeckStore(self.root / "store", logger=self.logger)
        protocol = Protocol.AMNEZIAWG if self.backend_type is AmneziaWGBackend else Protocol.WIREGUARD
        fixture = "awg31.conf" if protocol is Protocol.AMNEZIAWG else "wireguard.conf"
        self.metadata = self.store.import_connection(protocol, FIXTURES / fixture, "Test")
        self.system = SimulatedLinux()
        inspector = SimpleNamespace(
            interface_exists=AsyncMock(side_effect=lambda _: self.system.tun),
            resolve_endpoint=AsyncMock(return_value=["198.51.100.1"]),
            vpn_routes_present=AsyncMock(return_value=True),
            interface_ready=AsyncMock(return_value=True),
            dns_probe=AsyncMock(return_value=True),
            tcp_probe=AsyncMock(return_value=False),
            route_to=AsyncMock(side_effect=lambda _: (None, self.store.load_runtime().interface or "wlan0")),
        )
        self.routes = SimpleNamespace(apply=AsyncMock(return_value=[]), cleanup=AsyncMock())
        self.dns = SimpleNamespace(apply=AsyncMock(), cleanup=AsyncMock(), healthy=AsyncMock(return_value=True))
        context = SimpleNamespace(
            store=self.store,
            runner=self.system,
            inspector=inspector,
            binaries=SimpleNamespace(command=lambda name, *args: [name, *args]),
            routes=self.routes,
            dns=self.dns,
        )
        self.backend = self.backend_type(context)
        self.backend.uapi_directory = self.root
        self.backend.startup_timeout = 0.12
        self.backend._socket_identity = Mock(
            side_effect=lambda _: [1, self.system.next_pid] if self.system.socket_exists else None
        )
        self.backend._uapi_ready = AsyncMock(side_effect=lambda _: self.system.uapi_available)
        self.backend._probe_handshake = AsyncMock()
        self.firewall = SimpleNamespace(disable=AsyncMock(), enable=AsyncMock())
        self.manager = VPNManager(
            self.store,
            BackendRegistry([self.backend]),
            self.firewall,
            ErrorHistory(self.store.state_dir / "errors.json"),
            recovery_delays=(0,),
        )

    async def asyncTearDown(self):
        if self.manager._recovery_task:
            self.manager._recovery_task.cancel()
            await asyncio.gather(self.manager._recovery_task, return_exceptions=True)
        self.temp.cleanup()

    async def test_foreground_remains_alive_and_manager_connects(self):
        with self.assertLogs(self.logger, level="INFO") as captured:
            result = await self.manager.start(self.metadata.id)
        self.assertTrue(result["success"])
        self.assertEqual(self.store.load_runtime().state, "CONNECTED")
        args, env = self.system.spawn_calls[0]
        self.assertEqual(args, [self.backend.userspace_name, "--foreground", interface_name(self.metadata.id)])
        self.assertEqual(
            env,
            {
                "WG_PROCESS_FOREGROUND": "1",
                "WG_TUN_FD": "",
                "WG_UAPI_FD": "",
                "WG_TUN_NAME_FILE": "",
                "LOG_LEVEL": "error",
            },
        )
        owned = OwnedProcess.from_dict(self.store.load_runtime().process)
        self.assertTrue(self.system.is_alive(owned))
        text = "\n".join(captured.output)
        for marker in (
            "starting userspace backend",
            "foreground=true",
            "pid=1001",
            "startup process alive",
            "UAPI ready",
            "VPN setconf succeeded",
        ):
            self.assertIn(marker, text)
        self.assertNotIn("PrivateKey", text)
        if self.backend.force_userspace:
            self.assertFalse(any(call[:3] == ["ip", "link", "add"] for call in self.system.calls))

    async def test_actual_startup_exit_logs_code_and_cleans_owned_resources(self):
        self.system.startup_exit = 7
        with self.assertLogs(self.logger, level="INFO") as captured, self.assertRaises(VDeckError) as raised:
            await self.manager.start(self.metadata.id)
        self.assertEqual(raised.exception.code, "PROCESS_START_FAILED")
        text = "\n".join(captured.output)
        for marker in ("process exited", "exit_code=7", "interface_exists=True", "uapi_exists=True", "pid=1001"):
            self.assertIn(marker, text)
        self.assertFalse(self.system.tun)
        self.assertFalse(self.system.live[1001])
        self.assertTrue(self.system.live[99999])
        self.assertIn(1001, self.system.stopped)
        self.assertEqual(self.store.load_runtime().process, {})
        self.routes.apply.assert_not_awaited()
        self.dns.apply.assert_not_awaited()

    async def test_exit_after_spawn_is_not_hidden_by_existing_tun(self):
        self.system.exit_after_start = True
        with self.assertRaises(VDeckError) as raised:
            await self.manager.start(self.metadata.id)
        self.assertEqual(raised.exception.code, "PROCESS_START_FAILED")
        self.assertFalse(any("setconf" in call for call in self.system.calls))
        self.assertIn(1001, self.system.stopped)

    async def test_waits_for_uapi_before_setconf_and_network(self):
        async def ready(_):
            self.assertFalse(any("setconf" in call for call in self.system.calls))
            self.routes.apply.assert_not_awaited()
            self.dns.apply.assert_not_awaited()
            return self.backend._uapi_ready.await_count > 1

        self.backend._uapi_ready.side_effect = ready
        self.backend.startup_timeout = 1
        await self.manager.start(self.metadata.id)
        self.assertGreater(self.backend._uapi_ready.await_count, 1)
        self.assertTrue(any("setconf" in call for call in self.system.calls))

    async def test_missing_uapi_times_out_and_stops_process(self):
        self.system.uapi_available = False
        with self.assertRaises(VDeckError) as raised:
            await self.manager.start(self.metadata.id)
        self.assertEqual(raised.exception.code, "UAPI_NOT_READY")
        self.assertFalse(self.system.live[1001])
        self.assertFalse(self.system.tun)
        self.assertFalse(any("setconf" in call for call in self.system.calls))

    async def test_missing_tun_never_reaches_setconf(self):
        self.system.make_tun = False
        with self.assertRaises(VDeckError) as raised:
            await self.manager.start(self.metadata.id)
        self.assertEqual(raised.exception.code, "INTERFACE_CREATE_FAILED")
        self.assertFalse(self.system.live[1001])
        self.backend._uapi_ready.assert_not_awaited()

    async def test_failed_setconf_never_applies_routes_or_dns(self):
        self.system.fail_setconf = True
        with self.assertRaises(VDeckError) as raised:
            await self.manager.start(self.metadata.id)
        self.assertEqual(raised.exception.code, "COMMAND_FAILED")
        self.routes.apply.assert_not_awaited()
        self.dns.apply.assert_not_awaited()
        self.assertFalse(self.system.live[1001])
        self.assertFalse(self.system.tun)

    async def test_stop_and_auto_recovery_own_only_foreground_pids(self):
        await self.manager.start(self.metadata.id)
        self.system.live[1001] = False
        self.system.exit_codes[1001] = 9
        await self.manager.health_check()
        self.assertIsNotNone(self.manager._recovery_task)
        await self.manager._recovery_task
        self.assertEqual(self.store.load_runtime().state, "CONNECTED")
        self.assertEqual(self.store.load_runtime().process["pid"], 1002)
        self.assertIn(1001, self.system.stopped)
        await self.manager.stop()
        self.assertIn(1002, self.system.stopped)
        self.assertFalse(self.system.live[1001])
        self.assertFalse(self.system.live[1002])
        self.assertTrue(self.system.live[99999])

    async def test_cancelled_startup_stops_foreground_process(self):
        entered = asyncio.Event()

        async def pending(_):
            entered.set()
            await asyncio.Event().wait()

        self.backend._uapi_ready.side_effect = pending
        task = asyncio.create_task(self.backend.start(self.metadata, RuntimeState()))
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(self.system.live[1001])
        self.assertFalse(self.system.tun)

    async def test_preexisting_interface_is_not_deleted_on_failure(self):
        self.system.tun = True
        with self.assertRaises(VDeckError) as raised:
            await self.manager.start(self.metadata.id)
        self.assertEqual(raised.exception.code, "INTERFACE_ALREADY_EXISTS")
        self.assertTrue(self.system.tun)
        self.assertFalse(self.system.spawn_calls)
        self.assertFalse(any(call[:3] == ["ip", "link", "delete"] for call in self.system.calls))

    async def test_preexisting_socket_is_not_replaced(self):
        path = self.backend._uapi_path(interface_name(self.metadata.id))
        path.write_text("unrelated", encoding="utf-8")
        with self.assertRaises(VDeckError):
            await self.manager.start(self.metadata.id)
        self.assertEqual(path.read_text(encoding="utf-8"), "unrelated")
        self.assertFalse(self.system.spawn_calls)

    async def test_socket_cleanup_refuses_changed_inode(self):
        path = self.backend._uapi_path(interface_name(self.metadata.id))
        path.write_text("replacement", encoding="utf-8")
        self.backend._socket_identity.return_value = [2, 3]
        self.backend._socket_identity.side_effect = None
        await self.backend.stop(
            self.metadata, RuntimeState(interface=interface_name(self.metadata.id), process={"uapi_identity": [1, 2]})
        )
        self.assertTrue(path.exists())

    async def test_uapi_readiness_connects_and_closes_without_reading_keys(self):
        self.system.socket_exists = True
        path = self.backend._uapi_path(interface_name(self.metadata.id))
        writer = SimpleNamespace(close=Mock(), wait_closed=AsyncMock())
        connector = AsyncMock(return_value=(Mock(), writer))
        with (
            patch("vdeck.backends.wireguard.sys.platform", "linux"),
            patch("vdeck.backends.wireguard.asyncio.open_unix_connection", connector, create=True),
        ):
            ready = await WireGuardBackend._uapi_ready(self.backend, path)
        self.assertTrue(ready)
        connector.assert_awaited_once_with(str(path))
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

    async def test_uapi_socket_file_alone_is_not_readiness(self):
        self.system.socket_exists = True
        connector = AsyncMock(side_effect=ConnectionRefusedError())
        with (
            patch("vdeck.backends.wireguard.sys.platform", "linux"),
            patch("vdeck.backends.wireguard.asyncio.open_unix_connection", connector, create=True),
        ):
            ready = await WireGuardBackend._uapi_ready(self.backend, self.backend._uapi_path("vdeck-12345678"))
        self.assertFalse(ready)


class AmneziaWGStartupTests(UserspaceStartupMixin, unittest.IsolatedAsyncioTestCase):
    backend_type = AmneziaWGBackend


class WireGuardFallbackStartupTests(UserspaceStartupMixin, unittest.IsolatedAsyncioTestCase):
    backend_type = WireGuardBackend

    async def test_kernel_first_does_not_spawn_userspace(self):
        self.system.kernel_available = True
        result = await self.manager.start(self.metadata.id)
        self.assertTrue(result["success"])
        self.assertFalse(self.system.spawn_calls)
        self.backend._uapi_ready.assert_not_awaited()
        self.assertTrue(any(call[:3] == ["ip", "link", "add"] for call in self.system.calls))


if __name__ == "__main__":
    unittest.main()
