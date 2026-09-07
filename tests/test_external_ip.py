from __future__ import annotations

import asyncio
import logging
import os
import ssl
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from vdeck.errors import VDeckError
from vdeck.external_ip import IP_PROVIDERS, SYSTEM_CA_FILES, NoRedirect, _lookup, host_tls_context, lookup_external_ip
from vdeck.models import Protocol, RuntimeState
from vdeck.service import VDeckService

PROJECT = Path(__file__).resolve().parents[1]


class HostTrustTests(unittest.TestCase):
    def test_linux_explicit_ca_ignores_frozen_paths_and_keylog_without_disabling_verification(self):
        with (
            patch("vdeck.external_ip.sys.platform", "linux"),
            patch("vdeck.external_ip.Path.is_file", return_value=True),
            patch.object(ssl.SSLContext, "load_verify_locations") as load_ca,
            patch.object(ssl.SSLContext, "cert_store_stats", return_value={"x509_ca": 150}),
            patch.dict(os.environ, {"SSL_CERT_FILE": "/tmp/_MEItest/missing.pem", "SSLKEYLOGFILE": "/invalid/keylog"}),
        ):
            context = host_tls_context(logging.getLogger("ip-check-test"))
        load_ca.assert_called_once_with(cafile=SYSTEM_CA_FILES[0])
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertIsNone(context.keylog_filename)

    def test_missing_or_broken_ca_is_explicit_and_never_falls_back_to_unverified_tls(self):
        for present in (False, True):
            with (
                self.subTest(present=present),
                patch("vdeck.external_ip.sys.platform", "linux"),
                patch("vdeck.external_ip.Path.is_file", return_value=present),
                patch.object(ssl.SSLContext, "load_verify_locations", side_effect=ssl.SSLError("fixture")),
                self.assertRaises(VDeckError) as raised,
            ):
                host_tls_context(logging.getLogger("ip-check-test"))
            self.assertEqual(raised.exception.code, "EXTERNAL_IP_CA_UNAVAILABLE")

    def test_bad_first_ca_file_tries_the_next_system_file(self):
        with (
            patch("vdeck.external_ip.sys.platform", "linux"),
            patch("vdeck.external_ip.Path.is_file", return_value=True),
            patch.object(
                ssl.SSLContext, "load_verify_locations", side_effect=[ssl.SSLError("fixture"), None]
            ) as load_ca,
            patch.object(ssl.SSLContext, "cert_store_stats", return_value={"x509_ca": 150}),
        ):
            context = host_tls_context(logging.getLogger("ip-check-test"))
        self.assertEqual(load_ca.call_args_list[-1].kwargs, {"cafile": SYSTEM_CA_FILES[1]})
        self.assertTrue(context.check_hostname)


class ExternalIpTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_certificate_rejection_stays_rejected_with_stable_code_and_safe_details(self):
        error = ssl.SSLCertVerificationError(1, "secret-server-content")
        error.verify_code = 20
        logger = logging.getLogger("ip-check-test")
        with (
            patch("vdeck.external_ip.urllib.request.build_opener") as build,
            self.assertLogs(logger, level="INFO") as logs,
            self.assertRaises(VDeckError) as raised,
        ):
            build.return_value.open.side_effect = urllib.error.URLError(error)
            await lookup_external_ip(logger)
        self.assertEqual(raised.exception.code, "EXTERNAL_IP_TLS_FAILED")
        self.assertIn("verify_code=20", "\n".join(logs.output))
        self.assertNotIn("secret-server-content", "\n".join(logs.output))

    async def test_https_fallback_uses_no_proxy_and_never_logs_response_or_exception_secrets(self):
        logger = logging.getLogger("ip-check-test")
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"8.8.8.8\n"
        opener = MagicMock()
        opener.open.side_effect = [OSError("PrivateKey=secret-value"), response]
        with (
            patch("vdeck.external_ip.urllib.request.build_opener", return_value=opener) as build,
            self.assertLogs(logger) as logs,
        ):
            result = await lookup_external_ip(logger)
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["provider"], IP_PROVIDERS[1])
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], NoRedirect)
        self.assertEqual([call.args[0].full_url for call in opener.open.call_args_list], list(IP_PROVIDERS))
        self.assertTrue(all(call.kwargs["timeout"] == 4 for call in opener.open.call_args_list))
        response.__enter__.return_value.read.assert_called_once_with(65)
        for value in ("secret-value", "8.8.8.8"):
            self.assertNotIn(value, "\n".join(logs.output))

    async def test_invalid_private_ipv6_and_oversized_responses_are_rejected(self):
        for raw in (b"127.0.0.1", b"192.168.1.1", b"2606:4700:4700::1111", b"x" * 65, b"<html>error</html>"):
            with self.subTest(raw=raw):
                response = MagicMock()
                response.__enter__.return_value.read.return_value = raw
                opener = MagicMock()
                opener.open.return_value = response
                with (
                    patch("vdeck.external_ip.urllib.request.build_opener", return_value=opener),
                    self.assertRaisesRegex(VDeckError, "External IP services are unavailable"),
                ):
                    await lookup_external_ip(logging.getLogger("ip-check-test"))

    async def test_redirects_are_refused_and_cancelled_worker_does_not_start_requests(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", None, "http://example.invalid"))
        cancelled = threading.Event()
        cancelled.set()
        with patch("vdeck.external_ip.urllib.request.build_opener") as build:
            with self.assertRaises(VDeckError):
                _lookup(logging.getLogger("ip-check-test"), cancelled)
            build.return_value.open.assert_not_called()


class ExternalIpServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = VDeckService(Path(self.temp.name) / "settings", PROJECT, Path(self.temp.name) / "legacy")
        self.connection = self.service.store.import_connection(
            Protocol.WIREGUARD, PROJECT / "tests/fixtures/wireguard.conf", "Test VPN"
        )

    async def asyncTearDown(self):
        await self.service.shutdown()
        for handler in list(self.service.logger.handlers):
            handler.close()
            self.service.logger.removeHandler(handler)
        self.temp.cleanup()

    async def test_before_after_checks_are_explicit_memory_only_and_label_actual_active_profile(self):
        results = [
            {"ip": "1.1.1.1", "provider": IP_PROVIDERS[0], "family": "IPv4"},
            {"ip": "8.8.8.8", "provider": IP_PROVIDERS[1], "family": "IPv4"},
        ]
        with patch("vdeck.service.lookup_external_ip", AsyncMock(side_effect=results)) as lookup:
            before = await self.service.check_external_ip()
            self.assertTrue(before["success"])
            self.assertIsNone(before["external_ip_checks"]["after"])
            self.service.store.save_runtime(
                RuntimeState(state="CONNECTED", connection_id=self.connection.id, started_at="session-a")
            )
            after = await self.service.check_external_ip()
            samples = after["external_ip_checks"]
            self.assertEqual(samples["before"]["ip"], "1.1.1.1")
            self.assertEqual(samples["after"]["ip"], "8.8.8.8")
            self.assertEqual(samples["after"]["connection_name"], "Test VPN")
            self.assertTrue(samples["after"]["checked_at"])
            self.service.diagnostics.collect = AsyncMock(return_value={})
            diagnostics = await self.service.get_diagnostics(self.connection.id)
            self.assertEqual(diagnostics["diagnostics"]["external_ip_checks"], samples)
            self.assertEqual(lookup.await_count, 2)  # opening diagnostics is not a third request
        log = (self.service.store.logs / "vdeck.log").read_text(encoding="utf-8")
        self.assertNotIn("8.8.8.8", log)
        for path in self.service.store.state_dir.glob("*.json"):
            self.assertNotIn("external_ip_checks", path.read_text(encoding="utf-8"))

    async def test_recovery_or_retained_killswitch_blocks_check_without_any_request(self):
        for runtime in (
            RuntimeState(state="RECOVERING"),
            RuntimeState(state="ERROR", firewall_active=True),
            RuntimeState(state="CONNECTING"),
        ):
            with self.subTest(state=runtime.state):
                self.service.store.save_runtime(runtime)
                with patch("vdeck.service.lookup_external_ip", AsyncMock()) as lookup:
                    result = await self.service.check_external_ip()
                    self.assertEqual(result["code"], "EXTERNAL_IP_VPN_BUSY")
                    lookup.assert_not_awaited()

    async def test_network_change_discards_result_and_concurrent_click_is_rejected(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def lookup(logger):
            entered.set()
            await release.wait()
            return {"ip": "1.1.1.1", "provider": IP_PROVIDERS[0], "family": "IPv4"}

        with patch("vdeck.service.lookup_external_ip", lookup):
            task = asyncio.create_task(self.service.check_external_ip())
            await entered.wait()
            duplicate = await self.service.check_external_ip()
            self.assertEqual(duplicate["code"], "OPERATION_IN_PROGRESS")
            await self.service.manager.network_event()
            release.set()
            result = await task
        self.assertEqual(result["code"], "EXTERNAL_IP_NETWORK_CHANGED")
        self.assertEqual(self.service._external_ip_samples, {"before": None, "after": None})
