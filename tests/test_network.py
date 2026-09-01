from __future__ import annotations

import unittest

from vdeck.backends.openvpn import resolved_openvpn_config
from vdeck.backends.wireguard import handshake_probe_target
from vdeck.errors import VDeckError
from vdeck.network import FirewallManager, NetworkInspector, endpoint_host
from vdeck.runner import CommandResult


class FakeRunner:
    def __init__(
        self,
        routes: dict[int, str] | None = None,
        nft_table: str | None = None,
        dns_output: str = "",
    ):
        self.routes = routes or {}
        self.nft_table = nft_table
        self.dns_output = dns_output
        self.calls: list[tuple[list[str], str | None]] = []

    async def run(self, args, *, input_text=None, **kwargs):
        rendered = list(args)
        self.calls.append((rendered, input_text))
        if rendered[:4] == ["nft", "list", "table", "inet"]:
            if self.nft_table is None:
                return CommandResult(tuple(rendered), 1, "", "No such file or directory")
            return CommandResult(tuple(rendered), 0, self.nft_table, "")
        if rendered == ["resolvectl", "dns"]:
            return CommandResult(tuple(rendered), 0, self.dns_output, "")
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

    async def test_system_dns_servers_are_specific_and_loopback_is_ignored(self):
        runner = FakeRunner(dns_output="Global: 127.0.0.53 192.0.2.53\nLink 2 (wlan0): 2001:db8::53\n")
        inspector = NetworkInspector(runner)
        self.assertEqual(await inspector.system_dns_servers(), ["192.0.2.53", "2001:db8::53"])


class HandshakeProbeTests(unittest.TestCase):
    def test_split_tunnel_gets_an_in_prefix_probe(self):
        self.assertEqual(handshake_probe_target(["10.8.0.0/24"]), "10.8.0.1")

    def test_ipv6_only_full_tunnel_gets_ipv6_probe(self):
        self.assertEqual(handshake_probe_target(["::/0"]), "2606:4700:4700::1111")

    def test_endpoint_host_preserves_unbracketed_ipv6_literal(self):
        self.assertEqual(endpoint_host("2001:db8::8"), "2001:db8::8")

    def test_openvpn_remote_uses_cached_numeric_address(self):
        rendered = resolved_openvpn_config(
            "client\nremote vpn.example.com 1194 udp\n",
            {"vpn.example.com": ["198.51.100.8"]},
        )
        self.assertIn("remote 198.51.100.8 1194 udp", rendered)

    def test_openvpn_remote_preserves_inline_comment(self):
        rendered = resolved_openvpn_config(
            "remote vpn.example.com 1194 udp # primary endpoint\n",
            {"vpn.example.com": ["198.51.100.8"]},
        )
        self.assertEqual(rendered, "remote 198.51.100.8 1194 udp # primary endpoint\n")
        self.assertNotIn("vpn.example.com", rendered)


class FirewallTests(unittest.IsolatedAsyncioTestCase):
    async def test_rules_are_isolated_and_block_both_ip_families(self):
        runner = FakeRunner()
        firewall = FirewallManager(runner)
        await firewall.enable("vdeck-12345678", ["198.51.100.8", "2001:db8::8"])
        self.assertEqual(runner.calls[0][0], ["nft", "list", "table", "inet", "vdeck"])
        rules = runner.calls[1][1] or ""
        self.assertIn('comment "vdeck-owned:org.vdeck:v1"', rules)
        self.assertIn('oifname "vdeck-12345678" accept', rules)
        self.assertIn("ip daddr 198.51.100.8 accept", rules)
        self.assertIn("ip6 daddr 2001:db8::8 accept", rules)
        self.assertIn("meta nfproto ipv4 reject", rules)
        self.assertIn("meta nfproto ipv6 reject", rules)

    async def test_recovery_dns_rules_are_narrow_and_temporary(self):
        runner = FakeRunner()
        firewall = FirewallManager(runner)
        await firewall.enable("", ["198.51.100.8"], ["192.0.2.53", "2001:db8::53"])
        rules = runner.calls[-1][1] or ""
        self.assertIn("ip daddr 192.0.2.53 udp dport 53 accept", rules)
        self.assertIn("ip daddr 192.0.2.53 tcp dport 53 accept", rules)
        self.assertIn("ip6 daddr 2001:db8::53 udp dport 53 accept", rules)
        self.assertNotIn(
            "udp dport 53 accept",
            rules.replace("ip daddr 192.0.2.53 udp dport 53 accept", "").replace(
                "ip6 daddr 2001:db8::53 udp dport 53 accept", ""
            ),
        )
        self.assertLess(rules.index("dport 53 accept"), rules.index("meta nfproto ipv4 reject"))

    async def test_unowned_same_name_table_is_never_deleted(self):
        runner = FakeRunner(nft_table="table inet vdeck { chain output { type filter hook output priority 0; } }")
        firewall = FirewallManager(runner)
        with self.assertLogs("vdeck.network", level="WARNING"):
            removed = await firewall.disable()
        self.assertFalse(removed)
        self.assertFalse(any(call[0][:3] == ["nft", "delete", "table"] for call in runner.calls))

    async def test_unowned_same_name_table_is_not_replaced(self):
        runner = FakeRunner(nft_table="table inet vdeck { chain unrelated { } }")
        firewall = FirewallManager(runner)
        with self.assertRaisesRegex(VDeckError, "ownership marker"):
            await firewall.enable("vdeck-12345678", ["198.51.100.8"])
        self.assertEqual(len(runner.calls), 1)

    async def test_owned_table_is_deleted(self):
        runner = FakeRunner(nft_table='table inet vdeck { comment "vdeck-owned:org.vdeck:v1"; }')
        firewall = FirewallManager(runner)
        self.assertTrue(await firewall.disable())
        self.assertEqual(runner.calls[-1][0], ["nft", "delete", "table", "inet", "vdeck"])


if __name__ == "__main__":
    unittest.main()
