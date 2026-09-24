"""Regressions for IPv4-only exports with ::/0 and underlay MTU selection."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock

import test_runtime_pipeline as pipeline
from vdeck.backends.wireguard import effective_routes
from vdeck.errors import VDeckError
from vdeck.network import NetworkInspector
from vdeck.runner import CommandResult


class IpFamilyPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.case = pipeline.RuntimePipelineTests()
        await self.case.asyncSetUp()

    async def asyncTearDown(self):
        await self.case.asyncTearDown()

    async def import_dual_routes(self, *, ipv6_address=False):
        text = (
            (pipeline.FIXTURES / "awg31.conf")
            .read_text()
            .replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0")
        )
        if ipv6_address:
            text = text.replace("Address = 10.30.0.2/32", "Address = 10.30.0.2/32, fd00::2/128")
        source = self.case.root / "dual.conf"
        source.write_text(text)
        added = await self.case.service.import_connection("amneziawg", str(source), "dual routes")
        self.assertTrue(added["success"], added)
        return added["connection"]["id"]

    async def test_ipv4_only_export_rejects_ipv6_without_installing_blackhole_routes(self):
        cid = await self.import_dual_routes()
        directory = self.case.service.store.connection_dir(cid)
        originals = {name: (directory / name).read_bytes() for name in ("config", "runtime-info.json")}
        for kill_switch in (False, True):
            state = self.case.service.store.load_state()
            state.kill_switch = kill_switch
            self.case.service.store.save_state(state)
            result = await self.case.service.connect(cid)
            self.assertTrue(result["success"], result)
            self.assertEqual(result["runtime"]["state"], "CONNECTED")
            self.assertFalse(any(route[1] == "-6" for route in self.case.system.routes))
            guard = self.case.system.tables["vdeck_ipv6"]
            self.assertIn("meta nfproto ipv6 reject", guard)
            self.assertNotIn(f'oifname "{self.case.system.interface}" accept', guard)
            await self.case.service.manager.health_check()
            self.assertEqual(self.case.service.store.load_runtime().state, "CONNECTED")
            self.case.service.diagnostics.runner = self.case.system
            self.case.service.diagnostics.inspector = self.case.inspector
            self.case.inspector.public_ipv6_present = AsyncMock(return_value=True)
            diagnostics = await self.case.service.get_diagnostics(cid)
            self.assertTrue(diagnostics["success"], diagnostics)
            self.assertEqual(diagnostics["diagnostics"]["checks"]["routing"]["status"], "OK")
            self.assertEqual(diagnostics["diagnostics"]["checks"]["ipv6"]["detail"], "Direct IPv6 is blocked")
            self.assertTrue((await self.case.service.disconnect())["success"])
            self.assertFalse(self.case.system.routes)
            self.assertNotIn("vdeck_ipv6", self.case.system.tables)
            self.assertNotIn("vdeck", self.case.system.tables)
        self.assertEqual(originals, {name: (directory / name).read_bytes() for name in originals})

    async def test_real_dual_stack_probes_both_families(self):
        cid = await self.import_dual_routes(ipv6_address=True)
        result = await self.case.service.connect(cid)
        self.assertTrue(result["success"], result)
        probes = [c for c in self.case.system.calls if c[0] == "ping"]
        self.assertTrue(any("-4" in c for c in probes))
        self.assertTrue(any("-6" in c for c in probes))
        self.assertTrue(any(route[1] == "-6" for route in self.case.system.routes))
        self.assertFalse(self.case.service.store.load_runtime().ipv6_guard)

    async def test_failed_ipv6_probe_cannot_be_hidden_by_ipv4_success(self):
        cid = await self.import_dual_routes(ipv6_address=True)
        original = self.case.system.run

        async def run(args, **kwargs):
            if args[0] == "ping" and "-6" in args:
                return CommandResult(tuple(args), 1, "", "IPv6 unavailable")
            return await original(args, **kwargs)

        self.case.system.run = run
        result = await self.case.service.connect(cid)
        self.assertFalse(result["success"])
        self.assertEqual(result["code"], "VPN_TRAFFIC_UNCONFIRMED")
        self.assertFalse(self.case.system.routes)
        self.assertFalse(self.case.system.tun)
        self.assertTrue((self.case.service.store.connection_dir(cid) / "config").exists())

    async def test_each_family_can_use_its_own_backup(self):
        cid = await self.import_dual_routes(ipv6_address=True)
        self.case.system.probe_rc = 1
        self.case.inspector.tcp_probe.side_effect = lambda interface, address: address in {"8.8.8.8", "2620:fe::fe"}
        result = await self.case.service.connect(cid)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["runtime"]["state"], "CONNECTED")
        targets = {call.args[1] for call in self.case.inspector.tcp_probe.call_args_list}
        self.assertIn("8.8.8.8", targets)
        self.assertIn("2620:fe::fe", targets)
        self.assertTrue((await self.case.service.disconnect())["success"])
        self.assertFalse(self.case.system.routes)

    async def test_underlay_mtu_is_used_by_real_backend(self):
        cid = await self.import_dual_routes()
        original = self.case.system.run

        async def run(args, **kwargs):
            result = await original(args, **kwargs)
            if list(args[:4]) == ["ip", "-4", "route", "get"] and "dev wlan0" in result.stdout:
                return CommandResult(result.args, result.returncode, result.stdout + " mtu 1280", result.stderr)
            return result

        self.case.system.run = run
        result = await self.case.service.connect(cid)
        self.assertTrue(result["success"], result)
        self.assertTrue(any(c[:3] == ["ip", "link", "set"] and "1200" in c for c in self.case.system.calls))

    def test_split_ipv6_and_ipv6_dns_are_not_silently_discarded(self):
        for routes, dns in ((["0.0.0.0/0", "fd00::/64"], []), (["0.0.0.0/0", "::/0"], ["fd00::53"])):
            with self.subTest(routes=routes, dns=dns), self.assertRaises(VDeckError) as error:
                effective_routes({"allowed_ips": routes, "dns_servers": dns, "interface_addresses": ["10.0.0.2/32"]})
            self.assertEqual(error.exception.code, "CONFIG_IPV6_ADDRESS_REQUIRED")


class MtuSelectionTests(unittest.IsolatedAsyncioTestCase):
    def inspector(self, route, link):
        runner = AsyncMock()

        async def run(args, **kwargs):
            text = route if "route" in args else link
            return CommandResult(tuple(args), 0, text, "")

        runner.run.side_effect = run
        return NetworkInspector(runner)

    async def test_route_mtu_limits_tunnel(self):
        inspector = self.inspector("198.51.100.1 dev wlan0 mtu 1280", "2: wlan0: <UP> mtu 1500")
        self.assertEqual(await inspector.tunnel_mtu(["198.51.100.1"], None, ipv6=False), 1200)

    async def test_link_mtu_used_without_route_metric(self):
        inspector = self.inspector("198.51.100.1 dev wlan0", "2: wlan0: <UP> mtu 1492")
        self.assertEqual(await inspector.tunnel_mtu(["198.51.100.1"], None, ipv6=False), 1412)

    async def test_explicit_mtu_preserved(self):
        inspector = self.inspector("198.51.100.1 dev wlan0", "2: wlan0: <UP> mtu 1500")
        self.assertEqual(await inspector.tunnel_mtu(["198.51.100.1"], 1300, ipv6=True), 1300)
        inspector.runner.run.assert_not_called()

    async def test_ipv6_minimum_cannot_exceed_available_mtu(self):
        inspector = self.inspector("198.51.100.1 dev wlan0 mtu 1280", "2: wlan0: <UP> mtu 1500")
        with self.assertRaises(VDeckError) as error:
            await inspector.tunnel_mtu(["198.51.100.1"], None, ipv6=True)
        self.assertEqual(error.exception.code, "TUNNEL_MTU_UNSUPPORTED")

    async def test_unknown_underlay_uses_logged_fallback(self):
        inspector = self.inspector("", "")
        self.assertEqual(await inspector.tunnel_mtu(["198.51.100.1"], None, ipv6=False), 1420)
