from __future__ import annotations

import unittest

from vdeck.backends.wireguard import handshake_probe_target
from vdeck.network import FirewallManager, NetworkInspector
from vdeck.runner import CommandResult


class FakeRunner:
    def __init__(self, routes: dict[int, str] | None = None):
        self.routes = routes or {}
        self.calls: list[tuple[list[str], str | None]] = []

    async def run(self, args, *, input_text=None, **kwargs):
        rendered = list(args)
        self.calls.append((rendered, input_text))
        family = 6 if "-6" in rendered else 4
        return CommandResult(tuple(rendered), 0, self.routes.get(family, ""), "")


class RouteInspectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_tunnel_halves_are_recognized(self):
        runner = FakeRunner({4: "0.0.0.0/1 dev vdeck-12345678\n128.0.0.0/1 dev vdeck-12345678\n"})
        inspector = NetworkInspector(runner)
        self.assertTrue(await inspector.vpn_routes_present("vdeck-12345678", ["0.0.0.0/0"]))

    async def test_missing_configured_route_is_reported(self):
        inspector = NetworkInspector(FakeRunner({4: "10.0.0.0/24 dev vdeck-12345678\n"}))
        self.assertFalse(await inspector.vpn_routes_present("vdeck-12345678", ["10.8.0.0/24"]))


class HandshakeProbeTests(unittest.TestCase):
    def test_split_tunnel_gets_an_in_prefix_probe(self):
        self.assertEqual(handshake_probe_target(["10.8.0.0/24"]), "10.8.0.1")

    def test_ipv6_only_full_tunnel_gets_ipv6_probe(self):
        self.assertEqual(handshake_probe_target(["::/0"]), "2606:4700:4700::1111")


class FirewallTests(unittest.IsolatedAsyncioTestCase):
    async def test_rules_are_isolated_and_block_both_ip_families(self):
        runner = FakeRunner()
        firewall = FirewallManager(runner)
        await firewall.enable("vdeck-12345678", ["198.51.100.8", "2001:db8::8"])
        self.assertEqual(runner.calls[0][0], ["nft", "delete", "table", "inet", "vdeck"])
        rules = runner.calls[1][1] or ""
        self.assertIn("add table inet vdeck", rules)
        self.assertIn('oifname "vdeck-12345678" accept', rules)
        self.assertIn("ip daddr 198.51.100.8 accept", rules)
        self.assertIn("ip6 daddr 2001:db8::8 accept", rules)
        self.assertIn("meta nfproto ipv4 reject", rules)
        self.assertIn("meta nfproto ipv6 reject", rules)


if __name__ == "__main__":
    unittest.main()
