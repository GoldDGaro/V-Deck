"""Multiple-operator health checks without unbound probes or relaxed startup."""

from __future__ import annotations

import asyncio
import errno
import logging
import socket
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import test_runtime_pipeline as pipeline
from test_wireguard_health import HealthRunner, backend_for, dump
from vdeck.backends.amneziawg import AmneziaWGBackend
from vdeck.backends.wireguard import traffic_probe_targets
from vdeck.errors import VDeckError
from vdeck.models import RuntimeState
from vdeck.network import NetworkInspector


class TrafficSelectionTests(unittest.IsolatedAsyncioTestCase):
    def test_targets_stay_in_allowed_families_and_networks(self):
        self.assertEqual(traffic_probe_targets(["10.8.0.0/24"]), {4: ["10.8.0.1"]})
        self.assertEqual(traffic_probe_targets(["8.8.8.8/32"]), {4: ["8.8.8.8"]})
        self.assertEqual(traffic_probe_targets([]), {})
        full = traffic_probe_targets(["0.0.0.0/1", "128.0.0.0/1", "::/0"])
        self.assertEqual(full[4], ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        self.assertEqual(len(full[6]), 3)

    def backend(self):
        now = int(time.time())
        backend = backend_for(
            AmneziaWGBackend,
            HealthRunner(
                [dump(now, 100, 100), dump(now, 180, 240)],
                probe_returncode=1,
            ),
        )
        backend.context.inspector.tcp_probe = AsyncMock(return_value=False)
        backend.context.inspector.interface_ready = AsyncMock(return_value=True)
        return backend

    async def test_backup_tcp_can_confirm_startup_after_failed_primary(self):
        backend = self.backend()
        backend.context.inspector.tcp_probe.side_effect = lambda interface, target: target == "8.8.8.8"
        result = await backend.verify_connected(
            SimpleNamespace(id="connection-id"), RuntimeState(interface="vdeck-12345678", owned_routes=[{"family": 4}])
        )
        self.assertTrue(result["probe_succeeded"])
        self.assertTrue(result["healthy"])
        backend._verify_dns.assert_awaited_once()

    async def test_all_probes_failed_cannot_be_hidden_by_handshake_rx_and_dns(self):
        backend = self.backend()
        with self.assertRaises(VDeckError) as error:
            await backend.verify_connected(
                SimpleNamespace(id="connection-id"),
                RuntimeState(interface="vdeck-12345678", owned_routes=[{"family": 4}]),
            )
        self.assertEqual(error.exception.code, "VPN_TRAFFIC_UNCONFIRMED")
        self.assertEqual(backend.context.inspector.tcp_probe.await_count, 3)
        backend._verify_dns.assert_awaited_once()

    async def test_outside_tunnel_route_never_sends_probe(self):
        backend = self.backend()
        backend.context.inspector.route_to = AsyncMock(return_value=(None, "wlan0"))
        self.assertFalse(await backend._traffic_target("vdeck-12345678", "8.8.8.8"))
        self.assertFalse(any(call[0] == "ping" for call in backend.context.runner.calls))
        backend.context.inspector.tcp_probe.assert_not_called()

    async def test_healthy_primary_does_not_contact_backups(self):
        backend = self.backend()
        backend._traffic_target = AsyncMock(return_value=True)
        self.assertTrue(await backend._traffic_family("vdeck-12345678", 4, ["1.1.1.1", "8.8.8.8", "9.9.9.9"]))
        backend._traffic_target.assert_awaited_once_with("vdeck-12345678", "1.1.1.1")

    async def test_backup_success_cancels_slow_sibling_before_return(self):
        backend = self.backend()
        entered, closed = asyncio.Event(), asyncio.Event()

        async def probe(interface, target):
            if target == "1.1.1.1":
                return False
            if target == "8.8.8.8":
                try:
                    entered.set()
                    await asyncio.Event().wait()
                    return False
                finally:
                    closed.set()
            await entered.wait()
            return True

        backend._traffic_target = AsyncMock(side_effect=probe)
        result = await asyncio.wait_for(
            backend._traffic_family("vdeck-12345678", 4, ["1.1.1.1", "8.8.8.8", "9.9.9.9"]), 1
        )
        self.assertTrue(result)
        self.assertTrue(closed.is_set())


class TcpProbeTests(unittest.IsolatedAsyncioTestCase):
    def socket_module(self, client):
        # Replace only vdeck.network's module reference, not socket.socket
        # globally: Windows asyncio uses isinstance(..., socket.socket).
        return SimpleNamespace(
            AF_INET=socket.AF_INET,
            AF_INET6=socket.AF_INET6,
            SOCK_STREAM=socket.SOCK_STREAM,
            SOL_SOCKET=socket.SOL_SOCKET,
            SO_BINDTODEVICE=25,
            socket=MagicMock(return_value=client),
        )

    async def test_bound_socket_success_failure_timeout_and_cancellation_are_sanitized(self):
        for failure in (
            None,
            asyncio.TimeoutError("secret"),
            OSError(errno.ECONNREFUSED, "secret"),
            asyncio.CancelledError(),
        ):
            with self.subTest(failure=type(failure).__name__):
                logger = logging.getLogger("tcp-probe-test")
                inspector = NetworkInspector(SimpleNamespace(logger=logger))
                client = MagicMock()
                client.__enter__.return_value = client
                connect = AsyncMock(side_effect=failure)
                with (
                    patch("vdeck.network.socket", self.socket_module(client)),
                    patch.object(asyncio.get_running_loop(), "sock_connect", connect),
                    self.assertLogs(logger, level="INFO") as captured,
                ):
                    if isinstance(failure, asyncio.CancelledError):
                        with self.assertRaises(asyncio.CancelledError):
                            await inspector.tcp_probe("vdeck-12345678", "8.8.8.8")
                    else:
                        self.assertEqual(await inspector.tcp_probe("vdeck-12345678", "8.8.8.8"), failure is None)
                client.setsockopt.assert_called_once_with(socket.SOL_SOCKET, 25, b"vdeck-12345678\x00")
                client.__exit__.assert_called_once()
                connect.assert_awaited_once_with(client, ("8.8.8.8", 443))
                message = " ".join(captured.output)
                self.assertNotIn("secret", message)
                self.assertIn("target=8.8.8.8", message)
                self.assertIn("elapsed_ms=", message)
                expected = (
                    "OK"
                    if failure is None
                    else (
                        "PROBE_CANCELLED"
                        if isinstance(failure, asyncio.CancelledError)
                        else "PROBE_TCP_TIMEOUT"
                        if isinstance(failure, asyncio.TimeoutError)
                        else "PROBE_TCP_FAILED"
                    )
                )
                self.assertIn("code=" + expected, message)

    async def test_bind_failure_never_retries_unbound(self):
        inspector = NetworkInspector(SimpleNamespace(logger=logging.getLogger("tcp-probe-test")))
        client = MagicMock()
        client.__enter__.return_value = client
        client.setsockopt.side_effect = PermissionError("secret")
        with (
            patch("vdeck.network.socket", self.socket_module(client)),
            patch.object(asyncio.get_running_loop(), "sock_connect", AsyncMock()) as connect,
        ):
            self.assertFalse(await inspector.tcp_probe("vdeck-12345678", "8.8.8.8"))
        connect.assert_not_called()
        client.__exit__.assert_called_once()

    async def test_cancelling_pending_probe_closes_socket(self):
        inspector = NetworkInspector(SimpleNamespace(logger=logging.getLogger("tcp-probe-test")))
        client = MagicMock()
        client.__enter__.return_value = client
        entered = asyncio.Event()

        async def pending(*args):
            entered.set()
            await asyncio.Event().wait()

        with (
            patch("vdeck.network.socket", self.socket_module(client)),
            patch.object(asyncio.get_running_loop(), "sock_connect", AsyncMock(side_effect=pending)),
        ):
            task = asyncio.create_task(inspector.tcp_probe("vdeck-12345678", "8.8.8.8"))
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        client.__exit__.assert_called_once()


class TrafficPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_awg_wg_repeated_connect_cleanup_with_primary_blocked(self):
        for kind in ("awg-vpn", "awg", "kernel", "userspace"):
            with self.subTest(kind=kind):
                case = pipeline.RuntimePipelineTests()
                await case.asyncSetUp()
                try:
                    cid = await case.import_profile(kind)
                    case.system.probe_rc = 1

                    async def tcp_probe(interface, target, system=case.system):
                        rules = system.tables.get("vdeck", "")
                        return target == "8.8.8.8" and (not rules or f'oifname "{interface}" accept' in rules)

                    case.inspector.tcp_probe.side_effect = tcp_probe
                    for ks in (False, True):
                        state = case.service.store.load_state()
                        state.kill_switch = ks
                        case.service.store.save_state(state)
                        result = await case.service.connect(cid)
                        self.assertTrue(result["success"], result)
                        self.assertEqual(result["runtime"]["state"], "CONNECTED")
                        await case.service.manager.health_check()
                        self.assertEqual(case.service.store.load_runtime().state, "CONNECTED")
                        self.assertTrue((await case.service.disconnect())["success"])
                        self.assertFalse(case.system.routes)
                        self.assertFalse(case.system.tun)
                        self.assertFalse(case.system.tables)
                        self.assertTrue(case.system.live[99999])  # unrelated process is deliberately preserved
                        self.assertFalse(any(alive for pid, alive in case.system.live.items() if pid != 99999))
                        self.assertTrue((case.service.store.connection_dir(cid) / "config").exists())
                finally:
                    await case.asyncTearDown()
