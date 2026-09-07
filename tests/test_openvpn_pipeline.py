"""OpenVPN management framing and real service-to-OS lifecycle regressions."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import test_runtime_pipeline as pipeline
from vdeck.backends.openvpn import _management_request
from vdeck.errors import VDeckError
from vdeck.runner import OwnedProcess


class ManagementProtocolTests(unittest.TestCase):
    def test_fragmented_prompt_auth_banner_and_crlf_terminator(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.recv.side_effect = [
            b"ENT",
            b"ER PASS",
            b"WORD:\r\n",
            b"SUCCESS: password is correct\r\n>INFO: banner\r\n",
            b"1,CONNECTED,SUCCESS,10.8.0.2,198.51.100.1\r\nEN",
            b"D\r\n",
        ]
        with patch("vdeck.backends.openvpn.socket.create_connection", return_value=client):
            response = _management_request(42, "synthetic-password", "state")
        self.assertEqual(response, "1,CONNECTED,SUCCESS,10.8.0.2,198.51.100.1\nEND\n")
        self.assertEqual(
            [call.args[0] for call in client.sendall.call_args_list], [b"synthetic-password\n", b"state\n"]
        )

    def test_authentication_failure_is_not_a_connected_state(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.recv.side_effect = [b"ENTER PASSWORD:\r\n", b"ERROR: bad password\r\n"]
        with (
            patch("vdeck.backends.openvpn.socket.create_connection", return_value=client),
            self.assertRaises(VDeckError) as raised,
        ):
            _management_request(42, "synthetic-password", "state")
        self.assertEqual(raised.exception.code, "OPENVPN_MANAGEMENT_AUTH_FAILED")
        self.assertNotIn("synthetic-password", str(raised.exception))


class OpenVPNPipelineTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = pipeline.RuntimePipelineTests.asyncSetUp
    asyncTearDown = pipeline.RuntimePipelineTests.asyncTearDown

    async def profile(self, *, dual=False, routes=True):
        source = self.root / "synthetic.ovpn"
        source.write_text(
            "client\ndev tun\nremote vpn.example.invalid 1194\n"
            + ("redirect-gateway def1 ipv6\n" if dual else "redirect-gateway def1\n" if routes else "")
            + "dhcp-option DNS 9.9.9.9\n",
            encoding="utf-8",
        )
        checked = await self.service.validate_import("openvpn", str(source))
        self.assertTrue(checked["success"], checked)
        imported = await self.service.import_connection("openvpn", checked["path"], "OpenVPN test")
        self.assertTrue(imported["success"], imported)
        backend = self.service.registry.get("openvpn")

        async def start(args, **kwargs):
            self.system.spawn_calls.append((args, kwargs.get("env", {})))
            self.system.next_pid += 1
            result = OwnedProcess(self.system.next_pid, str(self.system.next_pid), args[0], args)
            self.system.live[result.pid] = True
            self.system.interface = args[args.index("--dev") + 1]
            self.system.tun = True
            self.system.up = True
            self.system.addresses = ["10.8.0.2/24"] + (["fd42::2/64"] if dual else [])
            kwargs["on_started"](result)
            self.assertEqual(self.service.store.load_runtime().process["pid"], result.pid)
            self.assertIn("--route-noexec", args)
            self.assertIn("--remap-usr1", args)
            self.assertNotIn("--management-query-passwords", args)
            if self.system.fail_stage == "process":
                self.system.live[result.pid] = False
                self.system.exit_codes[result.pid] = 7
                raise VDeckError("PROCESS_START_FAILED", "Synthetic OpenVPN exit")
            return result

        self.system.start = start
        backend._request = AsyncMock(
            side_effect=lambda _, command: (
                "1,CONNECTED,SUCCESS,10.8.0.2,198.51.100.1\nEND\n"
                if command == "state"
                else "TCP/UDP read bytes,200\nTCP/UDP write bytes,100\nEND\n"
            )
        )
        return imported["connection"]["id"]

    async def test_openvpn_connected_disconnect_ipv4_ipv6_with_kill_switch(self):
        for dual in (False, True):
            with self.subTest(dual=dual):
                connection_id = await self.profile(dual=dual)
                state = self.service.store.load_state()
                state.kill_switch = True
                self.service.store.save_state(state)
                connected = await self.service.connect(connection_id)
                self.assertTrue(connected["success"], connected)
                self.assertEqual(connected["runtime"]["state"], "CONNECTED")
                self.assertTrue(self.system.routes)
                self.assertTrue(self.dns._load())
                self.assertTrue((await self.service.disconnect())["success"])
                self.assertFalse(self.system.routes)
                self.assertFalse(self.dns._load())
                self.assertFalse(self.system.tun)
                self.assertFalse(await self.firewall.active())
                self.assertEqual(self.system.resolver.read_text(), "nameserver 192.0.2.53\n")
                self.assertTrue(self.service.store.get(connection_id))
                self.assertFalse((self.service.store.runtime / connection_id / "resolved.conf").exists())

    async def test_failure_matrix_never_reports_connected_and_keeps_profile(self):
        connection_id = await self.profile()
        for stage in ("process", "route", "dns", "dns_readback", "health"):
            with self.subTest(stage=stage):
                self.system.fail_stage = stage
                self.system.probe_rc = 1 if stage == "health" else 0
                response = await self.service.connect(connection_id)
                self.assertFalse(response["success"], response)
                self.assertEqual(self.service.store.load_runtime().state, "ERROR")
                self.assertTrue(self.service.store.get(connection_id))
                self.assertFalse(self.system.routes)
                self.assertFalse(self.system.tun)
                self.assertFalse(self.dns._load())
                self.system.startup_exit = None
        self.system.fail_stage, self.system.probe_rc = None, 0
        self.assertTrue((await self.service.connect(connection_id))["success"])
        self.assertTrue((await self.service.disconnect())["success"])

    async def test_push_only_profile_is_explicitly_unsupported_before_network_mutation(self):
        connection_id = await self.profile(routes=False)
        response = await self.service.connect(connection_id)
        self.assertEqual(response["code"], "OPENVPN_ROUTES_REQUIRED")
        self.assertFalse(self.system.tun)
        self.assertFalse(self.system.routes)

    async def test_management_failure_after_spawn_is_cleaned_up(self):
        connection_id = await self.profile()
        self.service.registry.get("openvpn")._request = AsyncMock(
            side_effect=VDeckError("OPENVPN_MANAGEMENT_FAILED", "Synthetic management failure")
        )
        self.assertEqual((await self.service.connect(connection_id))["code"], "OPENVPN_MANAGEMENT_FAILED")
        self.assertFalse(self.system.tun)
        self.assertFalse(self.service.store.load_runtime().process)

    async def test_cancel_after_pid_journal_reaps_process(self):
        connection_id = await self.profile()
        entered = asyncio.Event()

        async def wait(*_):
            entered.set()
            await asyncio.Event().wait()

        self.service.registry.get("openvpn")._request = wait
        task = asyncio.create_task(self.service.connect(connection_id))
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(self.system.tun)
        self.assertFalse(self.service.store.load_runtime().process)
