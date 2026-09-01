from __future__ import annotations

import base64
import json
import tempfile
import unittest
import zlib
from pathlib import Path

from vdeck.errors import VDeckError
from vdeck.models import Protocol
from vdeck.parsers import parse_amnezia_vpn, parse_config, parse_openvpn, parse_wireguard_text

FIXTURES = Path(__file__).parent / "fixtures"


def qt_compress(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + zlib.compress(data, 8)


def native_vpn(config: str) -> str:
    document = {
        "description": "Synthetic official-shape fixture",
        "defaultContainer": "amnezia-awg2",
        "containers": [
            {
                "container": "amnezia-awg2",
                "awg": {"last_config": json.dumps({"config": config, "clientId": "synthetic"})},
            }
        ],
    }
    payload = base64.urlsafe_b64encode(qt_compress(json.dumps(document).encode())).decode().rstrip("=")
    return "vpn://" + payload


class WireGuardParserTests(unittest.TestCase):
    def test_standard_wireguard(self):
        parsed = parse_config(Protocol.WIREGUARD, FIXTURES / "wireguard.conf")
        self.assertEqual(parsed.interface_addresses, ["10.20.0.2/32"])
        self.assertNotIn("Address =", parsed.runtime_config)
        self.assertIn("PersistentKeepalive", parsed.runtime_config)

    def test_awg31_preserves_current_fields(self):
        parsed = parse_config(Protocol.AMNEZIAWG, FIXTURES / "awg31.conf")
        for field in ("HeaderProtectionKey", "ContentPaddingAddition", "MaxHandshakeAttempts", "RandomTrailers"):
            self.assertIn(field, parsed.runtime_config)

    def test_awg2_and_legacy_are_accepted(self):
        for name in ("awg2.conf", "awg_legacy.conf"):
            self.assertEqual(parse_config(Protocol.AMNEZIAWG, FIXTURES / name).protocol, "amneziawg")

    def test_wrong_protocol_is_not_silently_changed(self):
        with self.assertRaisesRegex(VDeckError, "AmneziaWG"):
            parse_config(Protocol.WIREGUARD, FIXTURES / "awg31.conf")
        with self.assertRaisesRegex(VDeckError, "standard WireGuard"):
            parse_config(Protocol.AMNEZIAWG, FIXTURES / "wireguard.conf")

    def test_command_hooks_are_rejected(self):
        text = (FIXTURES / "wireguard.conf").read_text().replace("DNS = 1.1.1.1", "PostUp = touch /tmp/owned")
        with self.assertRaisesRegex(VDeckError, "hooks"):
            parse_wireguard_text(text, Protocol.WIREGUARD)

    def test_invalid_keys_are_rejected(self):
        text = (
            (FIXTURES / "wireguard.conf")
            .read_text()
            .replace("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "not-a-key")
        )
        with self.assertRaisesRegex(VDeckError, "invalid WireGuard key"):
            parse_wireguard_text(text, Protocol.WIREGUARD)


class AmneziaNativeParserTests(unittest.TestCase):
    def test_official_qcompress_container_shape(self):
        config = (FIXTURES / "awg31.conf").read_text()
        parsed = parse_amnezia_vpn(native_vpn(config))
        self.assertEqual(parsed.source_format, ".vpn")
        self.assertIn("HeaderProtectionKey", parsed.runtime_config)

    def test_unknown_container_is_rejected(self):
        data = {"containers": [{"container": "amnezia-xray", "xray": {}}]}
        payload = base64.urlsafe_b64encode(qt_compress(json.dumps(data).encode())).decode().rstrip("=")
        with self.assertRaisesRegex(VDeckError, "does not contain"):
            parse_amnezia_vpn("vpn://" + payload)

    def test_random_input_is_rejected(self):
        with self.assertRaises(VDeckError):
            parse_amnezia_vpn("this is not an invented format")

    def test_compressed_size_expansion_is_bounded(self):
        payload = base64.urlsafe_b64encode(qt_compress(b"A" * (8 * 1024 * 1024 + 1))).decode().rstrip("=")
        with self.assertRaisesRegex(VDeckError, "too large"):
            parse_amnezia_vpn("vpn://" + payload)


class OpenVPNParserTests(unittest.TestCase):
    def test_inline_auth_and_encrypted_key(self):
        parsed = parse_openvpn(FIXTURES / "openvpn_inline.ovpn")
        self.assertTrue(parsed.requires_username_password)
        self.assertTrue(parsed.requires_key_passphrase)
        self.assertIn("<ca>", parsed.runtime_config)

    def test_external_files_are_copied_and_rewritten(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "ca.crt").write_text("synthetic ca")
            (root / "client.crt").write_text("synthetic cert")
            (root / "client.key").write_text("synthetic key")
            config = root / "client.ovpn"
            config.write_text("client\nremote example.invalid 1194\nca ca.crt\ncert client.crt\nkey client.key\n")
            parsed = parse_openvpn(config)
            self.assertEqual(set(parsed.files), {"ca.crt", "client.crt", "client.key"})
            self.assertIn("ca files/ca.crt", parsed.runtime_config)

    def test_missing_external_file_fails_transaction(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "bad.ovpn"
            path.write_text("client\nremote example.invalid 1194\nca missing.crt\n")
            with self.assertRaisesRegex(VDeckError, "not found"):
                parse_openvpn(path)

    def test_traversal_and_hooks_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "bad.ovpn"
            path.write_text("client\nremote example.invalid 1194\nca ../secret\n")
            with self.assertRaises(VDeckError):
                parse_openvpn(path)
            path.write_text("client\nremote example.invalid 1194\nup /bin/sh\n")
            with self.assertRaisesRegex(VDeckError, "Executable"):
                parse_openvpn(path)

    def test_output_and_management_directives_are_rejected(self):
        for directive in (
            "log /tmp/vdeck.log",
            "status /tmp/vdeck.status",
            "writepid /tmp/vdeck.pid",
            "management 127.0.0.1 1",
        ):
            with self.subTest(directive=directive), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "unsafe.ovpn"
                path.write_text(f"client\nremote example.invalid 1194\n{directive}\n")
                with self.assertRaisesRegex(VDeckError, "Executable"):
                    parse_openvpn(path)

    def test_dns_and_full_tunnel_are_discovered(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "network.ovpn"
            path.write_text(
                "client\nremote example.invalid 1194\ndhcp-option DNS 10.8.0.1\nredirect-gateway def1 ipv6\n"
            )
            parsed = parse_openvpn(path)
            self.assertEqual(parsed.dns_servers, ["10.8.0.1"])
            self.assertEqual(parsed.allowed_ips, ["0.0.0.0/0", "::/0"])

    def test_connection_block_is_inspected_for_unsafe_directives(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "unsafe-connection.ovpn"
            path.write_text("client\n<connection>\nremote example.invalid 1194\nup /bin/sh\n</connection>\n")
            with self.assertRaisesRegex(VDeckError, "Executable"):
                parse_openvpn(path)

    def test_unknown_and_inline_credential_blocks_are_rejected(self):
        for block in ("unknown", "auth-user-pass"):
            with self.subTest(block=block), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "unsafe-inline.ovpn"
                path.write_text(f"client\nremote example.invalid 1194\n<{block}>\nsecret\n</{block}>\n")
                with self.assertRaisesRegex(VDeckError, "inline block|credentials"):
                    parse_openvpn(path)


if __name__ == "__main__":
    unittest.main()
