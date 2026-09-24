from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import test_runtime_pipeline as runtime_fixture
from vdeck.errors import VDeckError
from vdeck.models import Protocol
from vdeck.parsers import parse_config
from vdeck.xray_config import normalize_xray


def sample():
    return {
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "vpn.example.org",
                            "port": 443,
                            "users": [
                                {
                                    "id": "00000000-0000-4000-8000-000000000001",
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "example.org",
                        "publicKey": "A" * 43,
                        "shortId": "abcd",
                        "fingerprint": "chrome",
                    },
                },
            }
        ]
    }


class XrayImportTests(unittest.TestCase):
    def test_json_and_uri_produce_same_outbound(self):
        uri = (
            "vless://00000000-0000-4000-8000-000000000001@vpn.example.org:443?"
            "security=reality&type=tcp&flow=xtls-rprx-vision&sni=example.org&pbk=" + "A" * 43 + "&sid=abcd"
        )
        self.assertEqual(normalize_xray(uri), normalize_xray(json.dumps(sample())))

    def test_no_arbitrary_listeners_paths_routes_or_direct_outbound(self):
        raw = sample()
        raw.update(
            {
                "inbounds": [{"listen": "0.0.0.0"}],  # noqa: S104 - rejected test input
                "log": {"access": "/etc/evil"},
                "routing": {"rules": [{"outboundTag": "direct"}]},
                "api": {"tag": "admin"},
            }
        )
        raw["outbounds"].append({"protocol": "freedom"})
        clean, _, _ = normalize_xray(json.dumps(raw))
        self.assertEqual(clean["protocol"], "vless")
        for token in ("/etc/evil", "0.0.0.0", "direct", "admin"):  # noqa: S104 - rejected test input
            self.assertNotIn(token, json.dumps(clean))

    def test_unsupported_or_malformed_never_echoes_input(self):
        for raw in ("secret", "[]", "null", '{"outbounds": null}', "vless://secret"):
            with self.subTest(raw=raw), self.assertRaises(VDeckError) as caught:
                normalize_xray(raw)
            self.assertEqual(caught.exception.code, "XRAY_CONFIG_UNSUPPORTED")
            self.assertNotIn("secret", str(caught.exception))

    def test_reject_transport_security_flow_and_multiple_proxies(self):
        for path, value in (("network", "ws"), ("security", "tls")):
            raw = sample()
            raw["outbounds"][0]["streamSettings"][path] = value
            with self.assertRaises(VDeckError):
                normalize_xray(json.dumps(raw))
        raw = sample()
        raw["outbounds"].append(copy.deepcopy(raw["outbounds"][0]))
        with self.assertRaises(VDeckError):
            normalize_xray(json.dumps(raw))

    def test_file_import_runtime_network_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "client.json"
            path.write_text(json.dumps(sample()))
            result = parse_config(Protocol.XRAY, path)
            self.assertEqual(result.allowed_ips, ["0.0.0.0/0", "::/0"])
            self.assertEqual(result.endpoints, ["vpn.example.org:443"])
            self.assertEqual(result.dns_servers, ["1.1.1.1", "8.8.8.8"])


class XrayPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Reuse the simulated Linux boundary, not WG's protocol test methods.
        await runtime_fixture.RuntimePipelineTests.asyncSetUp(self)
        self.backend = self.service.registry.get("xray")
        original_start = self.system.start

        async def xray_start(args, **kwargs):
            config = json.loads(Path(args[-1]).read_text())
            name = config["inbounds"][0]["settings"]["name"]
            # The reused AWG fake models foreground via this flag. Xray itself
            # runs in foreground without flags or WG environment variables.
            return await original_start([args[0], "--foreground", name], env={}, **kwargs)

        self.system.start = xray_start
        self.probe_patch = patch("vdeck.backends.xray.response_probe", AsyncMock(return_value=True))
        self.probe = self.probe_patch.start()
        source = self.root / "reality.json"
        source.write_text(json.dumps(sample()))
        result = await self.service.validate_import("xray", str(source))
        self.assertTrue(result["success"], result)
        imported = await self.service.import_connection("xray", str(source), "Reality")
        self.assertTrue(imported["success"], imported)
        self.connection_id = imported["connection"]["id"]

    async def asyncTearDown(self):
        self.probe_patch.stop()
        await runtime_fixture.RuntimePipelineTests.asyncTearDown(self)

    async def test_connect_disconnect_twice_and_cleanup(self):
        for _ in range(2):
            result = await self.service.connect(self.connection_id)
            self.assertTrue(result["success"], result)
            self.assertEqual(self.service.store.load_runtime().state, "CONNECTED")
            result = await self.service.disconnect()
            self.assertTrue(result["success"], result)
            self.assertFalse(self.system.routes)
            self.assertFalse(self.system.tun)
            self.assertFalse(self.backend._config_path(self.connection_id).exists())
            self.assertTrue((self.service.store.connection_dir(self.connection_id) / "config").exists())

    async def test_no_response_is_failure_not_connected_and_profile_survives(self):
        self.probe.return_value = False
        self.inspector.dns_probe.return_value = False
        result = await self.service.connect(self.connection_id)
        self.assertFalse(result["success"])
        self.assertEqual(result["code"], "DNS_PROBE_FAILED")
        self.assertFalse(self.system.routes)
        self.assertFalse(self.system.tun)
        self.assertTrue((self.service.store.connection_dir(self.connection_id) / "config").exists())

    async def test_kill_switch_connect_manual_off_and_no_orphans(self):
        state = self.service.store.load_state()
        state.kill_switch = True
        state.auto_connect = True
        self.service.store.save_state(state)
        result = await self.service.connect(self.connection_id)
        self.assertTrue(result["success"], result)
        self.assertIn("vdeck", self.system.tables)
        self.assertTrue((await self.service.disconnect())["success"])
        self.assertEqual(self.service.store.load_state().desired_state, "OFF")
        self.assertFalse(self.system.routes)
        self.assertFalse(self.system.tables)
        self.assertFalse(self.system.tun)
        self.assertTrue(self.system.live[99999])

    async def test_http_probe_outage_does_not_veto_real_tunnel_dns_response(self):
        self.probe.return_value = False
        self.assertTrue((await self.service.connect(self.connection_id))["success"])
        self.assertTrue((await self.service.disconnect())["success"])

    async def test_route_failure_cleans_up_owned_resources(self):
        self.system.fail_stage = "route"
        result = await self.service.connect(self.connection_id)
        self.assertFalse(result["success"])
        self.assertFalse(self.system.routes)
        self.assertFalse(self.system.tun)
        self.assertFalse(self.backend._config_path(self.connection_id).exists())

    async def test_existing_interface_is_not_taken_over(self):
        from vdeck.network import interface_name

        self.system.interface = interface_name(self.connection_id)
        self.system.tun = True
        result = await self.service.connect(self.connection_id)
        self.assertFalse(result["success"])
        self.assertEqual(result["code"], "INTERFACE_ALREADY_EXISTS")
        self.assertTrue(self.system.tun)
