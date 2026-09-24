"""September 24 physical-log regressions: Premium ping and transient DNS loss."""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import test_runtime_pipeline as pipeline
from vdeck.diagnostics import DiagnosticsManager
from vdeck.models import RuntimeState
from vdeck.network import NetworkInspector, first_success
from vdeck.runner import CommandResult


class DnsProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.logger = logging.getLogger("dns-probe-test")
        self.inspector = NetworkInspector(SimpleNamespace(logger=self.logger))

    def socket_module(self, client):
        return SimpleNamespace(
            AF_INET=socket.AF_INET,
            AF_INET6=socket.AF_INET6,
            SOCK_DGRAM=socket.SOCK_DGRAM,
            SOL_SOCKET=socket.SOL_SOCKET,
            SO_BINDTODEVICE=25,
            socket=MagicMock(return_value=client),
        )

    def reply(self, flags=0x8180, answers=1, identifier=b"ab"):
        question = b"\x07example\x03com\x00\x00\x01\x00\x01"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01"
        return identifier + struct.pack("!HHHHH", flags, 1, answers, 0, 0) + question + answer

    async def test_bound_udp_ipv4_ipv6_response_and_error_diagnostics(self):
        for server in ("9.9.9.9", "2620:fe::fe"):
            for response, code in (
                (self.reply(), "OK"),
                (self.reply(identifier=b"zz"), "DNS_RESPONSE_INVALID"),
                (self.reply(flags=0x8380), "DNS_RESPONSE_INVALID"),  # truncated
                (self.reply(flags=0x8182), "DNS_RESPONSE_ERROR"),  # SERVFAIL
                (self.reply(answers=0), "DNS_RESPONSE_INVALID"),
                (b"secret", "DNS_RESPONSE_INVALID"),
                (asyncio.TimeoutError("secret"), "DNS_PROBE_TIMEOUT"),
                (OSError(101, "secret"), "DNS_PROBE_FAILED"),
            ):
                with self.subTest(server=server, code=code):
                    client = MagicMock()
                    client.__enter__.return_value = client
                    recv = AsyncMock(
                        side_effect=response if isinstance(response, Exception) else None,
                        return_value=response,
                    )
                    module = self.socket_module(client)
                    loop = asyncio.get_running_loop()
                    with (
                        patch("vdeck.network.socket", module),
                        patch("vdeck.network.os.urandom", return_value=b"ab"),
                        patch.object(loop, "sock_sendall", AsyncMock()) as send,
                        patch.object(loop, "sock_recv", recv),
                        self.assertLogs(self.logger, "INFO") as captured,
                    ):
                        self.assertEqual(await self.inspector._dns_attempt("vdeck-12345678", server, 1), code == "OK")
                    client.setsockopt.assert_called_once_with(socket.SOL_SOCKET, 25, b"vdeck-12345678\x00")
                    client.connect.assert_called_once_with((server, 53))
                    client.__exit__.assert_called_once()
                    send.assert_awaited_once()
                    message = " ".join(captured.output)
                    self.assertIn("code=" + code, message)
                    self.assertIn("attempt=1", message)
                    self.assertIn("stage=", message)
                    self.assertNotIn("secret", message)

    async def test_bind_failure_never_sends_unbound_dns(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.setsockopt.side_effect = PermissionError("secret")
        with patch("vdeck.network.socket", self.socket_module(client)):
            self.assertFalse(await self.inspector.dns_probe("vdeck-12345678", ["9.9.9.9"]))
        client.connect.assert_not_called()
        self.assertEqual(client.__exit__.call_count, 2)

    async def test_transient_failure_retries_but_permanent_failure_stays_bounded(self):
        for succeeds in (False, True):

            async def attempt(interface, server, number, succeeds=succeeds):
                return succeeds and number == 2 and server == "9.9.9.9"

            with patch.object(self.inspector, "_dns_attempt", AsyncMock(side_effect=attempt)) as probe:
                result = await self.inspector.dns_probe("vdeck-12345678", ["8.8.4.4", "9.9.9.9", "9.9.9.9"])
            self.assertEqual(result, succeeds)
            self.assertEqual(probe.await_count, 4)
            self.assertEqual({call.args[2] for call in probe.await_args_list}, {1, 2})

    async def test_success_cancels_other_dns_socket_before_return(self):
        clients = [MagicMock(), MagicMock()]
        for client in clients:
            client.__enter__.return_value = client
        module = self.socket_module(clients[0])
        module.socket.side_effect = clients
        pending = asyncio.Event()

        async def receive(client, size):
            if client is clients[0]:
                pending.set()
                await asyncio.Event().wait()
            await pending.wait()
            return self.reply()

        with (
            patch("vdeck.network.socket", module),
            patch("vdeck.network.os.urandom", return_value=b"ab"),
            patch.object(asyncio.get_running_loop(), "sock_sendall", AsyncMock()),
            patch.object(asyncio.get_running_loop(), "sock_recv", AsyncMock(side_effect=receive)),
        ):
            self.assertTrue(
                await asyncio.wait_for(self.inspector.dns_probe("vdeck-12345678", ["8.8.4.4", "9.9.9.9"]), 1)
            )
        for client in clients:
            client.__exit__.assert_called_once()

    async def test_cancellation_closes_socket_and_does_not_retry(self):
        client = MagicMock()
        client.__enter__.return_value = client
        pending = asyncio.Event()

        async def receive(*args):
            pending.set()
            await asyncio.Event().wait()

        module = self.socket_module(client)
        with (
            patch("vdeck.network.socket", module),
            patch.object(asyncio.get_running_loop(), "sock_sendall", AsyncMock()),
            patch.object(asyncio.get_running_loop(), "sock_recv", AsyncMock(side_effect=receive)),
        ):
            task = asyncio.create_task(self.inspector.dns_probe("vdeck-12345678", ["9.9.9.9"]))
            await asyncio.wait_for(pending.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        client.__exit__.assert_called_once()
        module.socket.assert_called_once()

    async def test_hostname_is_rejected_without_dns_or_sockets(self):
        with (
            patch.object(self.inspector, "_dns_attempt", AsyncMock()) as attempt,
            self.assertRaises(ValueError),
        ):
            await self.inspector.dns_probe("vdeck-12345678", ["secret.invalid"])
        attempt.assert_not_called()

    async def test_real_loopback_udp_retries_lost_packet_on_python310(self):
        # Real nonblocking UDP I/O, but no external traffic and no root needed.
        received, bindings = [], []
        first_packet = asyncio.Event()
        reply = self.reply()

        class Resolver(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                received.append(data)
                first_packet.set()
                if len(received) > 1:
                    self.transport.sendto(data[:2] + reply[2:], addr)

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(Resolver, local_addr=("127.0.0.1", 0))
        port = transport.get_extra_info("sockname")[1]

        class LocalProbeSocket(socket.socket):
            def setsockopt(self, level, option, value):
                if option == 25 and value == b"vdeck-12345678\x00":
                    bindings.append(value)
                else:
                    super().setsockopt(level, option, value)

            def connect(self, address):
                super().connect(("127.0.0.1", port))

        module = self.socket_module(None)
        module.socket = LocalProbeSocket
        wait_for = asyncio.wait_for

        attempts = 0

        async def controlled_timeout(awaitable, timeout):
            nonlocal attempts
            if timeout != 3:
                return await wait_for(awaitable, timeout)
            attempts += 1
            if attempts == 1:
                # Expire only after the local resolver actually received and
                # dropped the packet, not after a flaky 50 ms scheduling race.
                task = asyncio.create_task(awaitable)
                try:
                    await wait_for(first_packet.wait(), 15)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                raise asyncio.TimeoutError()
            return await wait_for(awaitable, 15)

        try:
            with patch("vdeck.network.socket", module), patch("vdeck.network.asyncio.wait_for", controlled_timeout):
                self.assertTrue(await self.inspector.dns_probe("vdeck-12345678", ["192.0.2.53"]))
        finally:
            transport.close()
            await asyncio.sleep(0)
        self.assertEqual(len(received), 2)
        self.assertEqual(len(bindings), 2)

    async def test_first_success_drains_losers_and_propagates_cancel(self):
        for cancel in (False, True):
            entered, closed = asyncio.Event(), asyncio.Event()

            async def pending(entered=entered, closed=closed):
                try:
                    entered.set()
                    await asyncio.Event().wait()
                    return False
                finally:
                    closed.set()

            async def answer(entered=entered, cancel=cancel):
                await entered.wait()
                if cancel:
                    await asyncio.Event().wait()
                return True

            task = asyncio.create_task(first_success([pending(), answer()]))
            await asyncio.wait_for(entered.wait(), 1)
            if cancel:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            else:
                self.assertTrue(await asyncio.wait_for(task, 1))
            self.assertTrue(closed.is_set())


class PingDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.case = pipeline.RuntimePipelineTests()
        await self.case.asyncSetUp()
        self.service = self.case.service
        self.connection = await self.case.import_profile("awg")
        self.assertTrue((await self.service.connect(self.connection))["success"])
        self.manager = DiagnosticsManager(
            self.service.store,
            self.service.registry,
            self.case.system,
            self.case.inspector,
            self.case.firewall,
            self.service.binaries,
            self.service.errors,
        )

    async def asyncTearDown(self):
        await self.service.disconnect()
        await self.case.asyncTearDown()

    def ping_runner(self, handler):
        original = self.case.system.run

        async def run(args, **kwargs):
            if args[0] == "ping":
                return await handler(args)
            return await original(args, **kwargs)

        return patch.object(self.case.system, "run", run)

    async def test_backup_ping_is_saved_and_inactive_profile_keeps_last_value(self):
        calls = []

        async def answer(args):
            calls.append(args)
            good = args[-1] == "9.9.9.9"
            return CommandResult(tuple(args), 0 if good else 1, "64 bytes: time=73.6 ms" if good else "", "")

        with self.ping_runner(answer):
            result = await self.manager.collect(self.connection)
            self.assertEqual(result["ping_ms"], 74)
            self.assertEqual(result["checks"]["internet"]["status"], "OK")
            self.assertEqual(self.service.store.get(self.connection).last_ping_ms, 74)
            self.assertEqual([args[-1] for args in calls], ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
            self.assertTrue(all("-I" in args for args in calls))
            await self.service.disconnect()
            calls.clear()
            self.assertEqual((await self.manager.collect(self.connection))["ping_ms"], 74)
            self.assertEqual(calls, [])

    async def test_route_mismatch_never_sends_ping_and_does_not_invent_latency(self):
        packet = AsyncMock(side_effect=AssertionError("unexpected packet"))
        with (
            patch.object(self.case.inspector, "route_to", AsyncMock(return_value=(None, "wlan0"))),
            self.ping_runner(packet),
        ):
            self.assertIsNone((await self.manager.collect(self.connection))["ping_ms"])
        packet.assert_not_awaited()
        self.assertIsNone(self.service.store.get(self.connection).last_ping_ms)

    async def test_disconnect_during_probe_does_not_store_stale_measurement(self):
        async def answer(args):
            await self.service.disconnect()
            return CommandResult(tuple(args), 0, "time=88 ms", "")

        with self.ping_runner(answer):
            self.assertIsNone((await self.manager.collect(self.connection))["ping_ms"])
        self.assertIsNone(self.service.store.get(self.connection).last_ping_ms)

    async def test_rename_during_probe_is_preserved_and_failed_ping_keeps_cache(self):
        async def answer(args):
            current = self.service.store.get(self.connection)
            current.display_name = "renamed"
            self.service.store.update_metadata(current)
            return CommandResult(tuple(args), 0, "time=41 ms", "")

        with self.ping_runner(answer):
            self.assertEqual((await self.manager.collect(self.connection))["ping_ms"], 41)
        self.assertEqual(self.service.store.get(self.connection).display_name, "renamed")
        with (
            self.ping_runner(AsyncMock(side_effect=OSError("PrivateKey=secret"))),
            self.assertLogs(self.service.logger, "INFO") as captured,
        ):
            result = await self.manager.collect(self.connection)
        self.assertEqual(result["ping_ms"], 41)
        self.assertNotEqual(result["checks"]["internet"]["status"], "OK")
        self.assertNotIn("secret", " ".join(captured.output))

    async def test_ipv6_only_and_split_targets_remain_inside_routes(self):
        runtime = RuntimeState(state="CONNECTED", connection_id=self.connection, interface="vdeck-12345678")
        with (
            patch.object(self.manager, "_same_session", return_value=True),
            patch.object(self.case.inspector, "route_to", AsyncMock(return_value=(None, runtime.interface))),
            patch.object(
                self.case.system, "run", AsyncMock(return_value=CommandResult((), 0, "time=10 ms", ""))
            ) as run,
        ):
            self.assertEqual(await self.manager._measure_ping(runtime, ["::/0"]), 10)
            self.assertIn("-6", run.call_args.args[0])
            self.assertEqual(await self.manager._measure_ping(runtime, ["10.8.0.0/24"]), 10)
            self.assertEqual(run.call_args.args[0][-1], "10.8.0.1")
