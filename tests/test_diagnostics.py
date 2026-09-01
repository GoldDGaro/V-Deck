from __future__ import annotations

import unittest
from types import SimpleNamespace

from vdeck.diagnostics import DiagnosticsManager, _mask_ip


class DiagnosticPrivacyTests(unittest.TestCase):
    def test_ipv4_is_masked(self):
        self.assertEqual(_mask_ip("203.0.113.42"), "203.0.x.x")

    def test_ipv6_is_reduced_to_prefix(self):
        self.assertEqual(_mask_ip("2001:db8:abcd:12::1"), "2001:db8:abcd::/48")

    def test_invalid_value_is_not_exported(self):
        self.assertIsNone(_mask_ip("not-an-address"))


class PartialDiagnosticTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_probes_return_unknown_checks(self):
        class Store:
            def get(self, connection_id):
                return SimpleNamespace(id=connection_id, protocol="wireguard", last_ping_ms=None)

            def load_runtime(self):
                return SimpleNamespace(
                    connection_id="connection-id",
                    firewall_active=False,
                    started_at=None,
                    interface="vdeck-12345678",
                    state="connected",
                )

            def parsed_runtime_info(self, connection_id):
                return {"allowed_ips": ["0.0.0.0/0"]}

        class Backend:
            async def diagnostics(self, metadata, runtime):
                raise OSError("probe unavailable")

        class Registry:
            def get(self, protocol):
                return Backend()

        class Inspector:
            async def public_ipv6_present(self):
                raise OSError("ip unavailable")

        manager = DiagnosticsManager(Store(), Registry(), object(), Inspector(), object(), object(), object())
        result = await manager.collect("connection-id", include_external_ip=False)
        self.assertEqual(result["checks"]["tunnel"]["status"], "UNKNOWN")
        self.assertEqual(result["checks"]["ipv6"]["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
