"""Independent audit regressions: real RPC/state managers, mocked OS only."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

import test_runtime_pipeline as pipeline
from vdeck.diagnostics import DiagnosticsManager
from vdeck.errors import VDeckError
from vdeck.models import Protocol
from vdeck.network import RouteManager
from vdeck.parsers import parse_openvpn, parse_wireguard_text
from vdeck.runner import CommandResult


class OpenVPNImportAuditTests(unittest.TestCase):
    def test_nested_configs_and_privileged_escape_directives_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "vpn.ovpn"
            for directive in (
                "config extra.conf",
                "iproute /tmp/custom-ip",
                "syslog custom",
                "engine /tmp/engine.so",
                "providers /tmp/provider.so",
                "pkcs11-providers /tmp/pkcs11.so",
                "setenv PATH /tmp",
                "http-proxy proxy.invalid 8080 /etc/shadow",
                "secret /etc/shadow",
            ):
                with self.subTest(directive=directive):
                    source.write_text("client\nremote vpn.invalid 1194\n" + directive + "\n")
                    with self.assertRaises(VDeckError) as raised:
                        parse_openvpn(source)
                    self.assertEqual(raised.exception.code, "CONFIG_UNSAFE_DIRECTIVE")

    def test_external_tls_auth_direction_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "vpn.ovpn"
            (source.parent / "ta.key").write_text("synthetic-key")
            source.write_text("client\nremote vpn.invalid 1194\ntls-auth ta.key 1\n")
            self.assertIn("tls-auth files/ta.key 1", parse_openvpn(source).runtime_config)

    def test_openvpn_dns_validation_is_at_import_not_after_process_start(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "vpn.ovpn"
            source.write_text("client\nremote vpn.invalid\ndhcp-option DNS not-an-address\n")
            with self.assertRaises(VDeckError) as raised:
                parse_openvpn(source)
            self.assertEqual(raised.exception.code, "CONFIG_INVALID_DNS")


class SettingsAuditTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = pipeline.RuntimePipelineTests.asyncSetUp
    asyncTearDown = pipeline.RuntimePipelineTests.asyncTearDown
    import_profile = pipeline.RuntimePipelineTests.import_profile

    async def setup_connected(self):
        self.service.firewall = self.firewall
        connection_id = await self.import_profile("kernel")
        self.assertTrue((await self.service.connect(connection_id))["success"])
        return connection_id

    async def test_failed_kill_switch_toggle_does_not_commit_setting_and_can_retry(self):
        await self.setup_connected()
        self.system.fail_stage = "firewall"
        result = await self.service.update_settings(False, True, "en", True)
        self.assertFalse(result["success"])
        self.assertFalse(self.service.store.load_state().kill_switch)
        self.system.fail_stage = None
        result = await self.service.update_settings(False, True, "en", True)
        self.assertTrue(result["success"], result)
        self.assertTrue(await self.firewall.active())
        self.assertTrue((await self.service.disconnect())["success"])

    async def test_disabling_kill_switch_in_recovery_error_removes_rules(self):
        await self.setup_connected()
        self.assertTrue((await self.service.update_settings(False, True, "en", True))["success"])
        runtime = self.service.store.load_runtime()
        runtime.state, runtime.error_code = "ERROR", "RECOVERY_EXHAUSTED"
        self.service.store.save_runtime(runtime)
        self.assertTrue((await self.service.update_settings(False, False, "en", True))["success"])
        self.assertFalse(await self.firewall.active())
        self.assertFalse(self.service.store.load_runtime().firewall_active)
        self.assertTrue((await self.service.disconnect())["success"])

    async def test_live_kill_switch_enable_verifies_dns_and_rolls_back_on_failure(self):
        await self.setup_connected()
        self.inspector.dns_probe = AsyncMock(return_value=False)
        result = await self.service.update_settings(False, True, "en", True)
        self.assertFalse(result["success"])
        self.assertEqual(result["code"], "DNS_PROBE_FAILED")
        self.assertFalse(self.service.store.load_state().kill_switch)
        self.assertFalse(await self.firewall.active())
        self.assertTrue((await self.service.disconnect())["success"])

    async def test_enabling_kill_switch_requires_warning_acknowledgement(self):
        result = await self.service.update_settings(False, True, "en", False)
        self.assertFalse(result["success"])
        self.assertEqual(result["code"], "KILL_SWITCH_CONFIRMATION_REQUIRED")

    async def test_dns_cleanup_failure_does_not_skip_crash_process_cleanup(self):
        connection_id = await self.import_profile("awg")
        self.assertTrue((await self.service.connect(connection_id))["success"])
        pid = self.service.store.load_runtime().process["pid"]
        self.dns.cleanup = AsyncMock(side_effect=VDeckError("DNS_RESTORE_FAILED", "Synthetic DNS cleanup failure"))
        self.service.binaries.prepare = lambda: None
        self.service._network_monitor = AsyncMock()
        await self.service.initialize()
        self.assertFalse(self.system.live[pid])
        self.assertFalse(self.system.tun)
        self.assertFalse(self.system.routes)
        self.assertEqual(self.service.store.load_runtime().error_code, "CLEANUP_PENDING")
        self.assertTrue(self.dns._load())

    async def test_deleted_profile_does_not_restart_from_late_health_event(self):
        connection_id = await self.setup_connected()
        self.assertTrue((await self.service.delete_connection(connection_id))["success"])
        await self.service.manager._recover(connection_id)
        self.assertEqual(self.service.store.load_state().desired_state, "OFF")
        self.assertFalse(self.system.tun)

    async def test_late_health_failure_cannot_restart_a_new_session_of_same_profile(self):
        connection_id = await self.setup_connected()
        backend = self.service.registry.get("wireguard")
        entered, release = asyncio.Event(), asyncio.Event()

        async def delayed_health(*_):
            entered.set()
            await release.wait()
            return {"healthy": False}

        previous_health = backend.health
        backend.health = delayed_health
        task = asyncio.create_task(self.service.manager.health_check())
        await asyncio.wait_for(entered.wait(), 2)
        backend.health = previous_health
        self.assertTrue((await self.service.disconnect())["success"])
        self.assertTrue((await self.service.connect(connection_id))["success"])
        release.set()
        await task
        self.assertIsNone(self.service.manager._recovery_task)
        self.assertEqual(self.service.store.load_runtime().state, "CONNECTED")
        self.assertTrue((await self.service.disconnect())["success"])

    async def test_inactive_profile_diagnostics_do_not_borrow_active_tunnel(self):
        await self.setup_connected()
        inactive = await self.import_profile("awg")
        manager = DiagnosticsManager(
            self.service.store,
            self.service.registry,
            self.system,
            self.inspector,
            self.firewall,
            self.service.binaries,
            self.service.errors,
        )
        backend = self.service.registry.get("amneziawg")
        backend.diagnostics = AsyncMock(return_value={"connected": True, "tunnel": True})
        result = await manager.collect(inactive, include_external_ip=False)
        self.assertEqual(result["state"], "DISCONNECTED")
        self.assertIsNone(result["interface"])
        self.assertEqual(result["checks"]["tunnel"]["status"], "ERROR")
        backend.diagnostics.assert_not_awaited()
        self.assertTrue((await self.service.disconnect())["success"])

    async def test_diagnostics_ping_is_bound_to_active_tunnel(self):
        connection_id = await self.setup_connected()
        manager = DiagnosticsManager(
            self.service.store,
            self.service.registry,
            self.system,
            self.inspector,
            self.firewall,
            self.service.binaries,
            self.service.errors,
        )
        self.system.calls.clear()
        await manager.collect(connection_id, include_external_ip=False)
        pings = [args for args in self.system.calls if args[0] == "ping"]
        self.assertTrue(pings)
        for args in pings:
            self.assertEqual(args[args.index("-I") + 1], self.service.store.load_runtime().interface)
        self.assertTrue((await self.service.disconnect())["success"])


class RouteAuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_expanded_default_routes_do_not_install_duplicate_prefixes(self):
        created = set()

        async def run(args, **kwargs):
            key = tuple(args)
            if key in created:
                raise VDeckError("COMMAND_FAILED", "File exists")
            created.add(key)
            return CommandResult(key, 0, "", "")

        from types import SimpleNamespace

        manager = RouteManager(SimpleNamespace(run=run), object())
        records = await manager.apply("vdeck-12345678", ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"], [], [])
        self.assertEqual(len(records), 2)

    async def test_equivalent_halves_are_full_tunnel_and_keep_crypto_config(self):
        original = (pipeline.FIXTURES / "wireguard.conf").read_text()
        text = original.replace("0.0.0.0/0", "0.0.0.0/1, 128.0.0.0/1")
        parsed = parse_wireguard_text(text, Protocol.WIREGUARD)
        self.assertEqual(parsed.allowed_ips, ["0.0.0.0/0", "::/0"])
        self.assertIn("0.0.0.0/1, 128.0.0.0/1", parsed.runtime_config)

    async def test_table_off_is_not_silently_changed_to_full_tunnel(self):
        text = (pipeline.FIXTURES / "wireguard.conf").read_text().replace("[Interface]", "[Interface]\nTable = off")
        with self.assertRaises(VDeckError) as raised:
            parse_wireguard_text(text, Protocol.WIREGUARD)
        self.assertEqual(raised.exception.code, "CONFIG_UNSUPPORTED_TABLE")
