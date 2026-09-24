"""Synthetic subscription/API flow through the existing AWG runtime pipeline."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import unittest
import zlib
from unittest.mock import AsyncMock, Mock, patch

import test_runtime_pipeline as pipeline
from test_first_release import native_vpn
from vdeck.atomic import atomic_write_json
from vdeck.errors import VDeckError
from vdeck.network import NetworkInspector
from vdeck.premium import PremiumManager


class PremiumTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.case = pipeline.RuntimePipelineTests()
        await self.case.asyncSetUp()
        self.service = self.case.service
        self.premium = self.service.premium
        self.source = self.case.root / "subscription.vpn"
        value = {
            "auth_data": {"api_key": "synthetic-subscription-secret"},
            "api_config": {"service_type": "premium", "service_protocol": "awg", "user_country_code": "RU"},
        }
        self.source.write_text("vpn://" + base64.urlsafe_b64encode(json.dumps(value).encode()).decode())
        self.api = AsyncMock(side_effect=self.response)
        self.premium._request = self.api

    async def asyncTearDown(self):
        await self.case.asyncTearDown()

    async def response(self, operation, value, country=""):
        if operation == "account_info":
            return {
                "data": {
                    "available_countries": [
                        {"server_country_code": code, "server_country_name": code, "available_protocols": ["awg"]}
                        for code in ("DE", "NL")
                    ],
                    "private_account_field": "must-not-leave-backend",
                }
            }
        text = (pipeline.FIXTURES / "awg31.conf").read_text()
        return {"data": {"config": native_vpn(text)}, "private_key": "A" * 43 + "="}

    async def imported(self):
        response = await self.service.premium_import(str(self.source))
        self.assertTrue(response["success"], response)
        self.assertNotIn("synthetic-subscription-secret", json.dumps(response))
        self.assertNotIn("private_account_field", json.dumps(response))
        return response["subscription"]["id"]

    async def selected(self):
        subscription = await self.imported()
        selected = await self.service.premium_select(subscription, "DE")
        self.assertTrue(selected["success"], selected)
        return subscription, selected["connection"]["id"]

    async def test_subscription_locations_connect_disconnect(self):
        subscription, connection = await self.selected()
        for _ in range(2):
            started = await self.service.connect(connection)
            self.assertTrue(started["success"], started)
            self.assertEqual(started["runtime"]["state"], "CONNECTED")
            self.assertTrue((await self.service.disconnect())["success"])
            self.assertFalse(self.case.system.routes)
            self.assertFalse(self.case.system.tun)
        snapshot = await self.service.get_snapshot()
        self.assertEqual(len(snapshot["connections"]), 1)
        self.assertEqual(snapshot["connections"][0]["premium_id"], subscription)
        self.assertNotIn("synthetic-subscription-secret", json.dumps(snapshot))
        self.assertEqual(sum(call.args[0] == "config" for call in self.api.call_args_list), 1)

    async def test_switch_country_reuses_profile_and_device(self):
        subscription, connection = await self.selected()
        previous = self.premium._load(subscription)["installation_uuid"]
        result = await self.service.premium_select(subscription, "NL")
        self.assertTrue(result["success"], result)
        self.assertEqual(result["connection"]["id"], connection)
        self.assertEqual(result["connection"]["premium_country"], "NL")
        self.assertEqual(self.premium._load(subscription)["installation_uuid"], previous)
        self.assertEqual(len(self.service.store.list()), 1)

    async def test_premium_connects_with_backup_probe_without_new_config_issuance(self):
        _, connection = await self.selected()
        self.case.system.probe_rc = 1
        self.case.inspector.tcp_probe.side_effect = lambda interface, target: target == "8.8.8.8"
        result = await self.service.connect(connection)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["runtime"]["state"], "CONNECTED")
        self.assertEqual(sum(call.args[0] == "config" for call in self.api.call_args_list), 1)
        self.assertTrue((await self.service.disconnect())["success"])
        self.assertFalse(self.case.system.routes)
        self.assertFalse(self.case.system.tun)

    async def test_premium_dns_retry_and_exhaustion_keep_startup_strict_and_cleanup_complete(self):
        _, connection = await self.selected()
        inspector = self.case.inspector
        inspector.dns_probe = NetworkInspector.dns_probe.__get__(inspector)
        for ks in (False, True):
            state = self.service.store.load_state()
            state.kill_switch = ks
            self.service.store.save_state(state)
            for succeeds in (True, False):
                with self.subTest(ks=ks, succeeds=succeeds):

                    async def attempt(interface, server, number, succeeds=succeeds):
                        self.assertEqual((await inspector.route_to(server))[1], interface)
                        return succeeds and number == 2

                    with patch.object(inspector, "_dns_attempt", AsyncMock(side_effect=attempt)) as probe:
                        result = await self.service.connect(connection)
                    self.assertEqual(result["success"], succeeds, result)
                    if succeeds:
                        self.assertEqual(result["runtime"]["state"], "CONNECTED")
                    else:
                        self.assertEqual(result["code"], "DNS_PROBE_FAILED")
                    self.assertEqual({call.args[2] for call in probe.await_args_list}, {1, 2})
                    self.assertTrue((await self.service.disconnect())["success"])
                    self.assertFalse(self.case.system.routes)
                    self.assertFalse(self.case.system.tun)
                    self.assertFalse(self.case.system.tables)
                    self.assertTrue(self.case.system.live[99999])  # unrelated process
                    self.assertFalse(any(alive for pid, alive in self.case.system.live.items() if pid != 99999))
                    self.assertTrue((self.service.store.connection_dir(connection) / "config").exists())
        self.assertEqual(sum(call.args[0] == "config" for call in self.api.call_args_list), 1)

    async def test_connected_switch_rejected_without_api_mutation(self):
        subscription, connection = await self.selected()
        self.assertTrue((await self.service.connect(connection))["success"])
        self.api.reset_mock()
        result = await self.service.premium_select(subscription, "NL")
        self.assertEqual(result["code"], "PREMIUM_DISCONNECT_REQUIRED")
        self.api.assert_not_called()
        await self.service.disconnect()

    async def test_failed_api_preserves_profile_and_old_generation(self):
        subscription, connection = await self.selected()
        previous = self.premium._path(subscription).read_bytes()
        self.api.side_effect = VDeckError("PREMIUM_NETWORK_FAILED", "API unavailable")
        result = await self.service.premium_select(subscription, "NL")
        self.assertEqual(result["code"], "PREMIUM_NETWORK_FAILED")
        self.assertEqual(self.premium._path(subscription).read_bytes(), previous)
        self.assertEqual(self.service.store.get(connection).premium_country, "DE")

    async def test_reimport_deduplicates_and_retains_device_identity(self):
        subscription = await self.imported()
        first = self.premium._load(subscription)
        self.assertEqual(await self.imported(), subscription)
        self.assertEqual(self.premium._load(subscription)["installation_uuid"], first["installation_uuid"])
        self.assertEqual(len(self.premium.subscriptions()), 1)

    async def test_subscription_qt_size_prefix_is_hint_not_integrity_check(self):
        raw = base64.urlsafe_b64decode(self.source.read_text().removeprefix("vpn://"))
        for declared in (0, len(raw) - 7, len(raw) + 10, 0xFFFFFFFF):
            with self.subTest(declared=declared):
                packed = declared.to_bytes(4, "big") + zlib.compress(raw)
                self.source.write_text("vpn://" + base64.urlsafe_b64encode(packed).decode())
                await self.imported()

    async def test_invalid_country_does_not_request_config(self):
        subscription = await self.imported()
        self.api.reset_mock()
        result = await self.service.premium_select(subscription, "../other")
        self.assertEqual(result["code"], "PREMIUM_LOCATION_INVALID")
        self.api.assert_not_called()

    async def test_expired_generation_refreshes_on_connect(self):
        subscription, connection = await self.selected()
        value = self.premium._load(subscription)
        value["expires_at"] = "2000-01-01T00:00:00+00:00"
        atomic_write_json(self.premium._path(subscription), value)
        self.api.reset_mock()
        self.assertTrue((await self.service.connect(connection))["success"])
        self.api.assert_awaited_once()
        await self.service.disconnect()

    async def test_recovery_uses_cached_generation_with_kill_switch(self):
        subscription, connection = await self.selected()
        settings = self.service.store.load_state()
        settings.kill_switch = True
        self.service.store.save_state(settings)
        self.assertTrue((await self.service.connect(connection))["success"])
        value = self.premium._load(subscription)
        value["expires_at"] = "2000-01-01T00:00:00+00:00"
        atomic_write_json(self.premium._path(subscription), value)
        self.api.reset_mock()
        await self.service.manager._recover(connection)
        self.api.assert_not_called()
        self.assertEqual(self.service.store.load_runtime().state, "CONNECTED")
        await self.service.disconnect()
        self.assertFalse(self.case.system.tables.get("vdeck"))

    async def test_materialize_repairs_interrupted_derived_write(self):
        _, connection = await self.selected()
        directory = self.service.store.connection_dir(connection)
        (directory / "config").write_text("interrupted")
        (directory / "runtime-info.json").write_text("{}")
        self.assertTrue((await self.service.connect(connection))["success"])
        self.assertIn("[Interface]", (directory / "config").read_text())
        await self.service.disconnect()

    async def test_transport_logging_allowlists_fields_without_secrets(self):
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        self.service.logger.addHandler(handler)
        try:
            self.premium._log_attempts(
                "account_info",
                {
                    "attempts": [
                        {
                            "route": "direct",
                            "host": "gw.amnezia.org",
                            "stage": "TLS",
                            "code": "PREMIUM_TLS_TIMEOUT",
                            "elapsed_ms": 7001,
                            "tls_ms": 7000,
                            "written": False,
                            "body": "secret-payload",
                            "api_key": "secret-key",
                            "error": "secret-error",
                        },
                        {"host": "host\nsecret-key", "elapsed_ms": "secret-key", "stage": ["secret-key"]},
                    ]
                },
            )
        finally:
            self.service.logger.removeHandler(handler)
            handler.close()
        text = output.getvalue()
        self.assertIn("PREMIUM_TLS_TIMEOUT", text)
        self.assertIn("7000", text)
        self.assertNotIn("secret", text)

    async def test_helper_timeout_kills_process_and_reports_distinct_code(self):
        self.premium.binaries = Mock(path=lambda _: self.case.root / "premium-api")
        process = Mock(returncode=None, communicate=AsyncMock(side_effect=asyncio.TimeoutError), wait=AsyncMock())
        value = {
            "id": "a" * 32,
            "installation_uuid": "test",
            "service_type": "premium",
            "user_country_code": "RU",
            "api_key": "test-only",
        }
        with (
            patch("vdeck.premium.asyncio.create_subprocess_exec", AsyncMock(return_value=process)),
            self.assertRaises(VDeckError) as raised,
        ):
            await PremiumManager._request(self.premium, "account_info", value)
        self.assertEqual(raised.exception.code, "PREMIUM_HELPER_TIMEOUT")
        process.kill.assert_called_once()
        process.wait.assert_awaited_once()

    async def test_transport_failure_code_and_trace_survive_rpc(self):
        self.premium.binaries = Mock(path=lambda _: self.case.root / "premium-api")
        output = {
            "code": "PREMIUM_TLS_TIMEOUT",
            "attempts": [
                {
                    "route": "direct",
                    "host": "gw.amnezia.org",
                    "stage": "TLS",
                    "code": "PREMIUM_TLS_TIMEOUT",
                    "tls_ms": 7000,
                }
            ],
        }
        process = Mock(returncode=0, communicate=AsyncMock(return_value=(json.dumps(output).encode(), None)))
        del self.premium._request
        with patch("vdeck.premium.asyncio.create_subprocess_exec", AsyncMock(return_value=process)):
            response = await self.service.premium_import(str(self.source))
        self.assertEqual(response["code"], "PREMIUM_TLS_TIMEOUT")
        self.assertNotIn("synthetic-subscription-secret", json.dumps(response))
