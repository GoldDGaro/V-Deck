from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from vdeck.i18n import resolve_language
from vdeck.models import DesiredState, Protocol
from vdeck.security import sanitize, sanitize_report
from vdeck.storage import VDeckStore

FIXTURES = Path(__file__).parent / "fixtures"


class SanitizerTests(unittest.TestCase):
    def test_multiline_and_json_secrets_are_redacted(self):
        value = "\n".join(
            (
                "PrivateKey = abc",
                "PresharedKey: def",
                "<key>\nSECRET\n</key>",
                '{"client_priv_key":"xyz"}',
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nABC\n-----END ENCRYPTED PRIVATE KEY-----",
            )
        )
        result = sanitize(value)
        for secret in ("abc", "def", "SECRET", "xyz", "ABC"):
            self.assertNotIn(secret, result)
        self.assertGreaterEqual(result.count("[REDACTED]"), 5)

    def test_diagnostic_report_masks_endpoint_and_awg_secret(self):
        result = sanitize_report("remote 203.0.113.77\nremote6 2001:db8:abcd:12::7\nHeaderProtectionKey = hidden-value")
        self.assertIn("203.0.x.x", result)
        self.assertIn("2001:db8:abcd::/48", result)
        self.assertNotIn("203.0.113.77", result)
        self.assertNotIn("2001:db8:abcd:12::7", result)
        self.assertNotIn("hidden-value", result)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = VDeckStore(Path(self.temp.name) / "vdeck")

    def tearDown(self):
        self.temp.cleanup()

    def test_import_rename_sort_delete_and_uuid_identity(self):
        first = self.store.import_connection(Protocol.WIREGUARD, FIXTURES / "wireguard.conf", "First")
        renamed = self.store.rename(first.id, "Renamed")
        self.assertEqual(renamed.id, first.id)
        self.assertEqual(self.store.list()[0].display_name, "Renamed")
        self.store.delete(first.id)
        self.assertEqual(self.store.list(), [])

    def test_sensitive_permissions(self):
        connection = self.store.import_connection(Protocol.WIREGUARD, FIXTURES / "wireguard.conf")
        if os.name != "nt":
            self.assertEqual((self.store.connection_dir(connection.id) / "config").stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.store.connection_dir(connection.id).stat().st_mode & 0o777, 0o700)

    def test_corrupt_state_recovers_to_defaults(self):
        self.store.state_path.write_text("{broken")
        state = self.store.load_state()
        self.assertEqual(state.desired_state, DesiredState.OFF.value)

    def test_credentials_are_separate_from_metadata(self):
        connection = self.store.import_connection(
            Protocol.WIREGUARD, FIXTURES / "wireguard.conf", username="user", password="secret"
        )
        metadata = (self.store.connection_dir(connection.id) / "metadata.json").read_text()
        self.assertNotIn("secret", metadata)
        self.assertIn("secret", (self.store.connection_dir(connection.id) / "credentials" / "auth").read_text())

    def test_sorting_last_used(self):
        a = self.store.import_connection(Protocol.WIREGUARD, FIXTURES / "wireguard.conf", "A")
        self.store.import_connection(Protocol.WIREGUARD, FIXTURES / "wireguard.conf", "B")
        a.last_used_at = "2099-01-01T00:00:00+00:00"
        self.store.update_metadata(a)
        self.assertEqual(self.store.list()[0].id, a.id)


class LocaleTests(unittest.TestCase):
    def test_language_resolution(self):
        self.assertEqual(resolve_language("automatic", "ru_RU"), "ru")
        self.assertEqual(resolve_language("automatic", "de_DE"), "en")
        self.assertEqual(resolve_language("en", "ru_RU"), "en")


if __name__ == "__main__":
    unittest.main()
