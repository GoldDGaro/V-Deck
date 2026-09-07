"""First-release acceptance at the Linux command boundary, not physical acceptance."""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import unittest
from unittest.mock import AsyncMock, Mock, patch

import test_runtime_pipeline as runtime_fixture
from test_parsers import native_vpn
from vdeck.atomic import atomic_write_json
from vdeck.errors import VDeckError
from vdeck.network import NetworkInspector
from vdeck.runner import CommandResult


class FirstReleaseLifecycleTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = runtime_fixture.RuntimePipelineTests.asyncSetUp
    asyncTearDown = runtime_fixture.RuntimePipelineTests.asyncTearDown

    async def profile(self, kind, *, dual=False):
        self.system.kernel_available = kind == "kernel"
        protocol = "amneziawg" if kind.startswith("awg") else "wireguard"
        fixture = "awg31.conf" if protocol == "amneziawg" else "wireguard.conf"
        config = (runtime_fixture.FIXTURES / fixture).read_text(encoding="utf-8")
        config = re.sub(r"(?m)^DNS\s*=.*$", "DNS = 9.9.9.9", config)
        if dual:
            config = re.sub(r"(?m)^Address\s*=.*$", "Address = 10.30.0.2/32, fd42::2/128", config)
            config = re.sub(r"(?m)^AllowedIPs\s*=.*$", "AllowedIPs = 0.0.0.0/0, ::/0", config)
            config = re.sub(r"(?m)^DNS\s*=.*$", "DNS = 9.9.9.9, 2620:fe::fe", config)
        if kind == "awg-vpn":
            template = re.sub(r"(?m)^DNS\s*=.*$", "DNS = $PRIMARY_DNS, $SECONDARY_DNS", config)
            body = native_vpn(template, dns1="9.9.9.9", dns2="2620:fe::fe" if dual else "")
        else:
            body = config
        source = self.root / (kind + (".vpn" if kind == "awg-vpn" else ".conf"))
        source.write_text(body, encoding="utf-8")
        before = source.read_bytes()
        valid = await self.service.validate_import(protocol, str(source))
        self.assertTrue(valid["success"], valid)
        imported = await self.service.import_connection(protocol, valid["path"], kind)
        self.assertTrue(imported["success"], imported)
        self.assertEqual(source.read_bytes(), before)
        connection = imported["connection"]["id"]
        snapshot = await self.service.get_snapshot()
        self.assertIn(connection, [value["id"] for value in snapshot["connections"]])
        return connection

    async def assert_clean(self, connection):
        snapshot = await self.service.get_snapshot()
        self.assertEqual(snapshot["runtime"]["state"], "DISCONNECTED")
        self.assertEqual(snapshot["settings"]["desired_state"], "OFF")
        self.assertIsNone(snapshot["settings"]["active_connection_id"])
        self.assertIn(connection, [value["id"] for value in snapshot["connections"]])
        self.assertFalse(self.system.tun)
        self.assertFalse(self.system.routes)
        self.assertFalse(self.system.nm_profiles)
        self.assertFalse(self.system.tables)
        self.assertFalse(self.dns._load())
        self.assertFalse(self.service.store.load_runtime().process)
        self.assertEqual([pid for pid, live in self.system.live.items() if live], [99999])
        self.assertEqual(self.system.resolver.read_text(encoding="utf-8"), "nameserver 192.0.2.53\n")

    async def cycle(self, kind):
        connection = await self.profile(kind)
        transitions = []
        save = self.service.store.save_runtime

        def record(runtime):
            transitions.append(runtime.state)
            save(runtime)

        with patch.object(self.service.store, "save_runtime", record):
            result = await self.service.connect(connection)
            self.assertTrue(result["success"], result)
            self.assertEqual(result["runtime"]["state"], "CONNECTED")
            count = len(self.system.spawn_calls)
            repeated = await self.service.connect(connection)
            self.assertTrue(repeated["success"])
            self.assertEqual(len(self.system.spawn_calls), count)
            self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)
        for stage in ("CONNECTING", "CONNECTED", "DISCONNECTING", "DISCONNECTED"):
            self.assertIn(stage, transitions)
        text = (self.service.store.logs / "vdeck.log").read_text(encoding="utf-8")
        for stage in ("VALIDATE", "ENDPOINT", "PROCESS", "SETCONF", "INTERFACE", "ROUTE", "DNS", "HEALTH"):
            self.assertIn(f"stage={stage}", text)
        self.assertIn("cleanup completed", text)
        if kind == "kernel":
            self.assertFalse(self.system.spawn_calls)
        else:
            self.assertTrue(self.system.spawn_calls)

    async def test_awg_native_vpn_connected_disconnect(self):
        await self.cycle("awg-vpn")

    async def test_awg_conf_connected_disconnect(self):
        await self.cycle("awg-conf")

    async def test_wireguard_kernel_connected_disconnect(self):
        await self.cycle("kernel")

    async def test_wireguard_userspace_connected_disconnect(self):
        await self.cycle("userspace")

    async def test_dual_stack_repeat_switch_and_kill_switch_matrix(self):
        for kind in ("awg-vpn", "awg-conf", "kernel", "userspace"):
            with self.subTest(kind=kind):
                connection = await self.profile(kind, dual=True)
                state = self.service.store.load_state()
                state.kill_switch = True
                self.service.store.save_state(state)
                for _ in range(2):
                    response = await self.service.connect(connection)
                    self.assertTrue(response["success"], response)
                    self.assertIn("vdeck", self.system.tables)
                    self.assertTrue(any(route[1] == "-6" for route in self.system.routes))
                    self.assertTrue((await self.service.disconnect())["success"])
                    await self.assert_clean(connection)

    async def test_switch_profiles_and_concurrent_connects_keep_one_active(self):
        first = await self.profile("awg-vpn")
        second = await self.profile("userspace")
        responses = await asyncio.gather(self.service.connect(first), self.service.connect(second))
        self.assertTrue(all(response["success"] for response in responses), responses)
        state = await self.service.get_snapshot()
        self.assertEqual(state["runtime"]["connection_id"], second)
        self.assertEqual(state["settings"]["active_connection_id"], second)
        self.assertEqual(len([pid for pid, live in self.system.live.items() if live and pid != 99999]), 1)
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(second)
        self.assertEqual(len((await self.service.get_snapshot())["connections"]), 2)

    async def test_hostname_uses_real_resolution_method_then_numeric_setconf(self):
        connection = await self.profile("awg-vpn")
        self.inspector.resolve_endpoint = NetworkInspector.resolve_endpoint.__get__(self.inspector)
        rows = [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("198.51.100.7", 0))]
        original = self.system.run
        seen = []

        async def capture(args, **options):
            if "setconf" in args:
                seen.append(re.search(r"(?m)^Endpoint\s*=\s*(.*)$", options["input_text"])[1])
                self.assertTrue(options["bundled"])
            return await original(args, **options)

        with (
            patch("vdeck.network.socket.getaddrinfo", return_value=rows) as resolve,
            patch.object(self.system, "run", capture),
        ):
            response = await self.service.connect(connection)
            self.assertTrue(response["success"], response)
        self.assertEqual(resolve.call_args.args[0], "awg.example.invalid")
        self.assertEqual(seen, ["198.51.100.7:51820"])
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)

    async def test_unexpected_pre_endpoint_failure_logs_safe_traceback_and_keeps_profile(self):
        connection = await self.profile("awg-vpn")
        secret = "UNLABELLED-PRIVATE-MATERIAL"
        backend = self.service.registry.get("amneziawg")
        with patch.object(backend, "resolve_endpoint_cache", AsyncMock(side_effect=ValueError(secret))):
            response = await self.service.connect(connection)
        self.assertEqual(response["code"], "START_FAILED")
        logs = (self.service.store.logs / "vdeck.log").read_text(encoding="utf-8")
        self.assertIn("stage=ENDPOINT", logs)
        self.assertIn("Traceback (sanitized", logs)
        self.assertIn("ValueError", logs)
        self.assertIn("wireguard.py:", logs)
        self.assertIn("cleanup completed", logs)
        self.assertNotIn(secret, logs + json.dumps(response) + json.dumps(self.service.errors.list()))
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)

    async def test_old_import_with_unresolved_dns_fails_with_actionable_code(self):
        connection = await self.profile("awg-vpn")
        info = self.service.store.parsed_runtime_info(connection)
        info["dns_servers"] = ["$PRIMARY_DNS"]
        atomic_write_json(self.service.store.connection_dir(connection) / "runtime-info.json", info)
        result = await self.service.connect(connection)
        self.assertEqual(result["code"], "CONFIG_UNRESOLVED_TEMPLATE")
        self.assertFalse(self.system.spawn_calls)
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)

    async def test_partial_cleanup_preserves_ownership_until_retry(self):
        connection = await self.profile("awg-vpn")
        self.assertTrue((await self.service.connect(connection))["success"])
        original = self.system.run

        async def denied(args, **options):
            if len(args) > 3 and args[2:4] == ["route", "del"]:
                return CommandResult(tuple(args), 2, "", "Operation not permitted")
            return await original(args, **options)

        with patch.object(self.system, "run", denied):
            result = await self.service.disconnect()
        self.assertEqual(result["code"], "CLEANUP_PENDING")
        self.assertTrue(self.service.store.load_runtime().owned_routes)
        self.assertEqual(self.service.store.load_state().desired_state, "OFF")
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)

    async def test_recovery_cancellation_manual_off_does_not_restart(self):
        connection = await self.profile("awg-vpn")
        self.assertTrue((await self.service.connect(connection))["success"])
        runtime = self.service.store.load_runtime()
        self.system.live[runtime.process["pid"]] = False
        self.service.manager.recovery_delays = (0.05,)
        await self.service.manager.health_check()
        recovery = self.service.manager._recovery_task
        self.assertIsNotNone(recovery)
        self.assertTrue((await self.service.disconnect())["success"])
        await asyncio.gather(recovery, return_exceptions=True)
        await self.service.manager.network_event()
        await self.assert_clean(connection)

    async def test_loader_failure_in_dns_cleans_all_created_resources(self):
        connection = await self.profile("awg-vpn")
        original = self.system.run

        async def failed(args, **options):
            if args[0] == "systemctl":
                raise VDeckError("COMMAND_LOADER_FAILED", "Synthetic loader error")
            return await original(args, **options)

        with patch.object(self.system, "run", failed):
            result = await self.service.connect(connection)
        self.assertEqual(result["code"], "COMMAND_LOADER_FAILED")
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)

    async def test_unreachable_aaaa_record_does_not_block_usable_ipv4_endpoint(self):
        connection = await self.profile("awg-vpn")
        self.inspector.resolve_endpoint.return_value = ["2001:db8::7", "198.51.100.7"]
        original = self.inspector.route_to

        async def route(address):
            return (None, None) if ":" in address else await original(address)

        with patch.object(self.inspector, "route_to", route):
            result = await self.service.connect(connection)
        self.assertTrue(result["success"], result)
        self.assertEqual(
            self.service.store.load_runtime().endpoint_cache, {"awg.example.invalid:51820": ["198.51.100.7"]}
        )
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)

    async def test_leftover_firewall_after_failed_connect_is_retried_before_connect(self):
        connection = await self.profile("awg-vpn")
        state = self.service.store.load_state()
        state.kill_switch = True
        self.service.store.save_state(state)
        backend = self.service.registry.get("amneziawg")
        verify = backend.verify_connected

        async def fail_after_firewall(metadata, runtime):
            if runtime.firewall_active:
                raise VDeckError("DNS_PROBE_FAILED", "Synthetic failure after firewall")
            return await verify(metadata, runtime)

        with (
            patch.object(backend, "verify_connected", fail_after_firewall),
            patch.object(
                self.firewall, "disable", AsyncMock(side_effect=VDeckError("FIREWALL_INSPECTION_FAILED", "pending"))
            ),
        ):
            self.assertFalse((await self.service.connect(connection))["success"])
        self.assertTrue(self.service.store.load_runtime().firewall_active)
        state = self.service.store.load_state()
        state.kill_switch = False
        self.service.store.save_state(state)
        self.assertTrue((await self.service.connect(connection))["success"])
        self.assertNotIn("vdeck", self.system.tables)
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)

    async def test_monitor_uses_host_environment_and_reports_loader_stderr(self):
        out = asyncio.StreamReader()
        out.feed_eof()
        err = asyncio.StreamReader()
        err.feed_data(b"nmcli: symbol lookup error: missing symbol PrivateKey=never-show\n")
        err.feed_eof()
        process = Mock(stdout=out, stderr=err, returncode=127, wait=AsyncMock(return_value=127))
        with (
            patch.dict(os.environ, {"LD_LIBRARY_PATH": "/tmp/_MEI-decky", "LD_LIBRARY_PATH_ORIG": "/host/lib"}),
            patch("vdeck.service.asyncio.create_subprocess_exec", AsyncMock(return_value=process)) as spawn,
            self.assertRaises(VDeckError) as raised,
        ):
            await self.service._watch_network_devices()
        self.assertEqual(raised.exception.code, "COMMAND_LOADER_FAILED")
        self.assertEqual(spawn.call_args.kwargs["env"]["LD_LIBRARY_PATH"], "/host/lib")
        text = (self.service.store.logs / "vdeck.log").read_text(encoding="utf-8")
        self.assertIn("stage=NETWORK_MONITOR exit_code=127", text)
        self.assertIn("symbol lookup error", text)
        self.assertNotIn("never-show", text)

    async def test_unexpected_import_exception_never_leaks_config_or_message(self):
        connection = await self.profile("awg-vpn")
        secret = "UNLABELLED-PRIVATE-MATERIAL"
        with patch("vdeck.service.parse_config", side_effect=ValueError(secret)):
            result = await self.service.validate_import("amneziawg", str(self.root / "awg-vpn.vpn"))
        self.assertEqual(result["code"], "INTERNAL_ERROR")
        text = (self.service.store.logs / "vdeck.log").read_text(encoding="utf-8")
        self.assertNotIn(secret, text + json.dumps(result))
        self.assertIn("ValueError", text)
        self.assertIn(connection, json.dumps(await self.service.get_snapshot()))

    async def test_orphan_cleanup_attempts_process_stop_even_when_route_removal_fails(self):
        connection = await self.profile("awg-vpn")
        self.assertTrue((await self.service.connect(connection))["success"])
        runtime = self.service.store.load_runtime()
        original = self.system.run

        async def denied(args, **options):
            if len(args) > 3 and args[2:4] == ["route", "del"]:
                return CommandResult(tuple(args), 2, "", "Operation not permitted")
            return await original(args, **options)

        with patch.object(self.system, "run", denied), self.assertRaises(VDeckError):
            await self.service.manager._cleanup_orphaned_runtime(runtime)
        self.assertFalse(self.system.tun)
        self.assertEqual([pid for pid, live in self.system.live.items() if live], [99999])
        self.assertTrue(self.service.store.load_runtime().owned_routes)
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)

    async def test_startup_does_not_delete_an_interface_only_because_its_name_matches(self):
        connection = await self.profile("awg-vpn")
        with (
            patch.object(self.inspector, "interface_exists", AsyncMock(return_value=True)),
            self.assertRaises(VDeckError) as raised,
        ):
            await self.service.manager._cleanup_known_interfaces()
        self.assertEqual(raised.exception.code, "INTERFACE_ALREADY_EXISTS")
        self.assertFalse(any(args[:3] == ["ip", "link", "delete"] for args in self.system.calls))
        self.assertIn(connection, json.dumps(await self.service.get_snapshot()))

    async def test_delete_waiting_for_connect_cannot_leave_a_running_orphan(self):
        connection = await self.profile("awg-vpn")
        async with self.service.manager.lock:
            connect = asyncio.create_task(self.service.connect(connection))
            await asyncio.sleep(0)
            delete = asyncio.create_task(self.service.delete_connection(connection))
            await asyncio.sleep(0)
        connected, deleted = await asyncio.wait_for(asyncio.gather(connect, delete), 10)
        self.assertTrue(connected["success"], connected)
        self.assertTrue(deleted["success"], deleted)
        self.assertEqual((await self.service.get_snapshot())["connections"], [])
        self.assertFalse(self.system.tun)
        self.assertFalse(self.system.routes)
        self.assertFalse(self.system.tables)
        self.assertEqual([pid for pid, live in self.system.live.items() if live], [99999])

    async def test_plugin_shutdown_cancels_recovery_before_another_instance_starts(self):
        connection = await self.profile("awg-vpn")
        self.assertTrue((await self.service.connect(connection))["success"])
        self.system.live[self.service.store.load_runtime().process["pid"]] = False
        self.service.manager.recovery_delays = (60,)
        await self.service.manager.health_check()
        recovery = self.service.manager._recovery_task
        await self.service.shutdown()
        self.assertTrue(recovery.done())
        self.assertTrue(recovery.cancelled())
        self.assertEqual(self.service.store.load_state().desired_state, "ON")
        self.assertTrue((await self.service.disconnect())["success"])
        await self.assert_clean(connection)
