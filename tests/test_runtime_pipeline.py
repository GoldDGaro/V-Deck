"""Real service/store/backends/network managers, simulated Linux command boundary."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from test_parsers import native_vpn
from test_userspace_lifecycle import SimulatedLinux
from vdeck.dns import DnsManager
from vdeck.errors import VDeckError
from vdeck.models import RuntimeState
from vdeck.network import FirewallManager, NetworkInspector, RouteManager
from vdeck.runner import CommandResult
from vdeck.service import VDeckService

PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT / "tests" / "fixtures"


class RuntimeLinux(SimulatedLinux):
    def __init__(self, resolver):
        super().__init__()
        self.resolver = resolver
        self.resolver.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
        self.mode = "default"
        self.resolved = False
        self.nm = True
        self.nm_profiles = {}
        self.link_dns = []
        self.domain = ""
        self.routes = []
        self.addresses = []
        self.up = False
        self.interface = ""
        self.fail_stage = None
        self.probe_rc = 0
        self.route_writes = []
        self.store = None
        self.endpoint_failures = 0

    async def start(self, args, **kwargs):
        self.interface = args[-1]
        if self.fail_stage == "process":
            self.startup_exit = 7
        return await super().start(args, **kwargs)

    async def run(self, args, **kwargs):
        args = list(args)
        self.calls.append(args)
        rc, out, err = 0, "", ""
        stage = None
        if args[:3] == ["ip", "link", "add"]:
            self.interface = args[4]
        if args[0] == "systemctl" and "is-active" in args:
            active = self.resolved if "systemd-resolved.service" in args else self.nm
            rc, out = (0, "active") if active else (3, "inactive")
        elif "--version" in args:
            out = "test OS boundary 1.52"
        elif args[0] == "busctl":
            out = f's "{self.mode if args[-1] == "Mode" else "file"}"'
        elif args[0] == "resolvectl":
            if args[1] == "dns":
                if len(args) > 3:
                    stage = "dns"
                    self.link_dns = args[3:]
                out = f"Link 4 ({self.interface}): " + " ".join(self.link_dns)
            elif args[1] == "domain":
                if len(args) > 3:
                    stage, self.domain = "domain", args[3]
                out = f"Link 4 ({self.interface}): {self.domain}"
            elif args[1] == "revert":
                self.link_dns, self.domain = [], ""
        elif args[0] == "nmcli":
            if "add" in args:
                stage = "dns"
                token = args[args.index("connection.uuid") + 1]
                self.nm_profiles[token] = {
                    "name": args[args.index("con-name") + 1],
                    "device": args[args.index("ifname") + 1],
                    "servers": [
                        server
                        for key in ("ipv4.dns", "ipv6.dns")
                        if key in args
                        for server in args[args.index(key) + 1].split(",")
                    ],
                }
            elif "up" in args:
                profile = self.nm_profiles[args[-1]]
                if self.fail_stage != "dns_readback":
                    self.resolver.write_text("".join(f"nameserver {v}\n" for v in profile["servers"]), encoding="utf-8")
            elif "delete" in args:
                self.nm_profiles.pop(args[-1], None)
                self.resolver.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
            elif "connection" in args and "show" in args:
                profile = self.nm_profiles.get(args[-1])
                if profile:
                    out = "no" if args[2] == "ipv4.routed-dns" else f"{profile['name']}\n{profile['device']}\ndummy"
                else:
                    rc = 10
        elif args[:3] == ["ip", "-o", "address"]:
            out = "\n".join(
                f"4: {self.interface} inet{'6' if ':' in value else ''} {value}" for value in self.addresses
            )
        elif args[:3] == ["ip", "-o", "link"]:
            out = f"4: {self.interface}: <POINTOPOINT,UP,LOWER_UP> mtu 1420" if self.up else ""
        elif args[:3] == ["ip", "link", "show"]:
            rc = 0 if self.tun and args[-1] == self.interface else 1
            err = "Cannot find device" if rc else ""
        elif args[:3] == ["ip", "link", "set"]:
            stage = "interface"
            self.up = True
        elif len(args) > 3 and args[0] == "ip" and args[2] == "address":
            if args[3] == "replace":
                self.addresses.append(args[4])
        elif len(args) > 3 and args[0] == "ip" and args[2] == "route":
            family = args[1]
            if args[3] == "add":
                stage = "route"
                self.route_writes.append(list(self.store.load_runtime().owned_routes))
                self.routes.append(args)
            elif args[3] == "del":
                self.routes = [route for route in self.routes if not (route[1] == family and route[4] == args[4])]
            elif args[3] == "get":
                if args[4] == "198.51.100.1" and self.endpoint_failures:
                    self.endpoint_failures -= 1
                    return CommandResult(tuple(args), 2, "", "Network is unreachable")
                dest = ipaddress.ip_address(args[4])
                matches = [route for route in self.routes if dest in ipaddress.ip_network(route[4])]
                match = max(matches, key=lambda route: ipaddress.ip_network(route[4]).prefixlen) if matches else None
                device = match[match.index("dev") + 1] if match else "wlan0"
                out = f"{dest} via 192.0.2.1 dev {device}"
            elif "exact" not in args:
                out = "\n".join(
                    " ".join(route[4:])
                    for route in self.routes
                    if route[1] == family and route[route.index("dev") + 1] == args[-1]
                )
        elif "latest-handshakes" in args:
            out = "peer\t1\n"
        elif args[0] == "ping":
            rc = self.probe_rc
            # Exercise the actual generated nft rules, not an always-successful
            # ping mock. Recovery must permit a recreated tunnel before HEALTH.
            rules = self.tables.get("vdeck", "")
            if rules and f'oifname "{self.interface}" accept' not in rules:
                rc, err = 1, "ping: sendmsg: Operation not permitted"
        else:
            if "setconf" in args:
                stage = "setconf"
            elif args[:2] == ["nft", "-f"] and "table inet vdeck {" in kwargs.get("input_text", ""):
                stage = "firewall"
            if stage != self.fail_stage or stage is None:
                return await super().run(args, **kwargs)
        if stage and self.fail_stage == stage:
            rc, err = 1, "synthetic stage failed PrivateKey=never-log-this-secret"
        if rc and kwargs.get("check", True):
            raise VDeckError("COMMAND_FAILED", "Synthetic command failure")
        return CommandResult(tuple(args), rc, out, err)


class RuntimePipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.service = VDeckService(self.root / "settings", PROJECT, self.root / "legacy")
        self.system = RuntimeLinux(self.root / "resolv.conf")
        self.system.logger = self.service.logger
        self.system.store = self.service.store
        self.inspector = NetworkInspector(self.system)
        self.inspector.resolve_endpoint = AsyncMock(return_value=["198.51.100.1"])
        self.inspector.tcp_probe = AsyncMock(return_value=False)
        self.inspector.dns_probe = AsyncMock(return_value=True)
        self.dns = DnsManager(self.system, self.service.store.runtime / "dns-ownership.json")
        self.dns.resolv_conf = self.system.resolver
        self.service.dns = self.dns
        self.firewall = FirewallManager(self.system)
        self.service.firewall = self.firewall
        self.service.manager.firewall = self.firewall
        self.service.manager.recovery_delays = (0, 0)
        for protocol in ("wireguard", "amneziawg"):
            backend = self.service.registry.get(protocol)
            backend.context.runner = self.system
            backend.context.inspector = self.inspector
            backend.context.routes = RouteManager(self.system, self.inspector)
            backend.context.dns = self.dns
            backend.context.binaries = Mock(command=lambda name, *args: [name, *args])
            backend.uapi_directory = self.root
            backend._socket_identity = Mock(
                side_effect=lambda _: [1, self.system.next_pid] if self.system.socket_exists else None
            )
            backend._uapi_ready = AsyncMock(return_value=True)

    async def asyncTearDown(self):
        await self.service.shutdown()
        for handler in list(self.service.logger.handlers):
            handler.close()
            self.service.logger.removeHandler(handler)
        self.temp.cleanup()

    async def import_profile(self, kind):
        self.system.kernel_available = kind == "kernel"
        protocol = "amneziawg" if kind.startswith("awg") else "wireguard"
        fixture = "awg31.conf" if kind.startswith("awg") else "wireguard.conf"
        source = FIXTURES / fixture
        if kind == "awg-vpn":
            config = re.sub(r"(?m)^DNS\s*=.*$", "DNS = $PRIMARY_DNS, $SECONDARY_DNS", source.read_text())
            source = self.root / "native.vpn"
            source.write_text(native_vpn(config, dns1="9.9.9.9", dns2=""), encoding="utf-8")
        validated = await self.service.validate_import(protocol, str(source))
        self.assertTrue(validated["success"])
        imported = await self.service.import_connection(protocol, validated["path"], kind)
        self.assertTrue(imported["success"])
        return imported["connection"]["id"]

    async def assert_profile(self, connection_id, original=None):
        snapshot = await self.service.get_snapshot()
        self.assertTrue(snapshot["success"])
        self.assertIn(connection_id, [item["id"] for item in snapshot["connections"]])
        if original:
            directory = self.service.store.connection_dir(connection_id)
            self.assertEqual(original, {name: (directory / name).read_bytes() for name in original})

    async def test_four_variants_with_both_dns_stacks_connect_disconnect_and_no_profile_loss(self):
        for kind in ("awg-vpn", "awg", "kernel", "userspace"):
            for resolved in (False, True):
                with self.subTest(kind=kind, resolved=resolved):
                    self.system.resolved = resolved
                    self.system.resolver.write_text(
                        "nameserver 127.0.0.53\n" if resolved else "nameserver 192.0.2.53\n", encoding="utf-8"
                    )
                    connection_id = await self.import_profile(kind)
                    response = await self.service.connect(connection_id)
                    self.assertTrue(response["success"], response)
                    self.assertEqual(response["runtime"]["state"], "CONNECTED")
                    self.assertTrue(self.system.route_writes and all(self.system.route_writes))
                    self.assertEqual(self.dns._load()["backend"], "resolved" if resolved else "networkmanager")
                    self.assertTrue((await self.service.disconnect())["success"])
                    self.assertFalse(self.system.routes)
                    self.assertFalse(self.system.nm_profiles)
                    self.assertFalse(self.dns._load())
                    self.assertFalse(self.system.tun)
                    await self.assert_profile(connection_id)
                    self.assertTrue(self.system.live[99999])

    async def test_failure_matrix_preserves_files_and_allows_retry(self):
        for kind in ("awg-vpn", "awg", "kernel", "userspace"):
            for stage in (
                "process",
                "setconf",
                "interface",
                "route",
                "dns",
                "dns_readback",
                "firewall",
                "health",
                "dns_probe",
            ):
                if stage == "process" and kind == "kernel":
                    continue
                with self.subTest(kind=kind, stage=stage):
                    connection_id = await self.import_profile(kind)
                    state = self.service.store.load_state()
                    state.kill_switch = stage == "firewall"
                    self.service.store.save_state(state)
                    directory = self.service.store.connection_dir(connection_id)
                    original = {
                        name: (directory / name).read_bytes()
                        for name in ("config", "metadata.json", "runtime-info.json")
                    }
                    self.system.fail_stage = stage
                    self.system.probe_rc = 1 if stage == "health" else 0
                    self.inspector.dns_probe.return_value = stage != "dns_probe"
                    response = await self.service.connect(connection_id)
                    self.assertFalse(response["success"], (kind, stage, response))
                    await self.assert_profile(connection_id, original)
                    self.assertEqual(self.service.store.load_runtime().state, "ERROR")
                    self.assertFalse(self.system.tun)
                    self.assertFalse(self.system.routes)
                    self.assertFalse(self.system.nm_profiles)
                    self.system.fail_stage = self.system.startup_exit = None
                    self.system.probe_rc = 0
                    self.inspector.dns_probe.return_value = True
                    self.assertTrue((await self.service.connect(connection_id))["success"])
                    self.assertTrue((await self.service.disconnect())["success"])

    async def test_resolved_domain_failure_rolls_back(self):
        self.system.resolved = True
        self.system.resolver.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
        connection_id = await self.import_profile("awg")
        self.system.fail_stage = "domain"
        response = await self.service.connect(connection_id)
        self.assertEqual(response["code"], "DNS_APPLY_FAILED")
        self.assertFalse(self.system.link_dns)
        self.assertFalse(self.dns._load())
        await self.assert_profile(connection_id)

    async def test_nm_crash_journal_restores_only_owned_profile_and_is_idempotent(self):
        connection_id = await self.import_profile("awg")
        self.assertTrue((await self.service.connect(connection_id))["success"])
        restarted = DnsManager(self.system, self.dns.journal)
        await restarted.cleanup(None)
        calls = len(self.system.calls)
        await restarted.cleanup(None)
        self.assertEqual(len(self.system.calls), calls)
        self.assertEqual(self.system.resolver.read_text(), "nameserver 192.0.2.53\n")
        self.assertFalse(self.system.nm_profiles)

    async def test_nm_foreign_identity_keeps_journal(self):
        connection_id = await self.import_profile("awg")
        self.assertTrue((await self.service.connect(connection_id))["success"])
        token = self.dns._load()["uuid"]
        self.system.nm_profiles[token]["name"] = "foreign"
        with self.assertRaises(VDeckError) as raised:
            await self.dns.cleanup(None)
        self.assertEqual(raised.exception.code, "DNS_OWNERSHIP_CONFLICT")
        self.assertTrue(self.dns._load())

    async def test_no_supported_dns_manager_is_explicit_and_does_not_modify_system(self):
        connection_id = await self.import_profile("awg")
        self.system.mode = "none"
        result = await self.service.connect(connection_id)
        self.assertEqual(result["code"], "DNS_BACKEND_UNSUPPORTED")
        self.assertFalse(self.system.nm_profiles)
        self.assertFalse(any(args[:2] == ["resolvectl", "dns"] for args in self.system.calls))

    async def test_nm_ipv6_dns_is_temporary_and_restored(self):
        await self.dns.apply("vdeck-12345678", ["2001:db8::53"], True)
        self.assertTrue(await self.dns.healthy("vdeck-12345678"))
        add = next(args for args in self.system.calls if "add" in args and args[0] == "nmcli")
        self.assertEqual(add[add.index("ipv4.method") + 1], "disabled")
        self.assertEqual(add[add.index("save") + 1], "no")
        self.assertEqual(add[add.index("connection.autoconnect") + 1], "no")
        await self.dns.cleanup(None)
        self.assertFalse(self.system.nm_profiles)

    async def test_nm_default_does_not_override_an_ambiguous_active_nss_resolver(self):
        for nss in (True, None):
            self.dns.environment = AsyncMock(
                return_value={
                    "resolved_active": True,
                    "uses_resolved": False,
                    "nss_uses_resolved": nss,
                    "nm_active": True,
                    "dns_mode": "default",
                    "rc_manager": "file",
                }
            )
            with self.assertRaises(VDeckError) as raised:
                await self.dns.apply("vdeck-12345678", ["1.1.1.1"], True)
            self.assertEqual(raised.exception.code, "DNS_BACKEND_UNSUPPORTED")
            self.assertFalse(self.system.nm_profiles)

    async def test_dns_failure_logs_safe_details_and_snapshot_stays_one(self):
        connection_id = await self.import_profile("awg")
        self.assertEqual(len((await self.service.get_snapshot())["connections"]), 1)
        self.system.fail_stage = "dns"
        self.assertFalse((await self.service.connect(connection_id))["success"])
        self.assertEqual(len((await self.service.get_snapshot())["connections"]), 1)
        log = (self.service.store.logs / "vdeck.log").read_text(encoding="utf-8")
        for marker in ("profile audit", "network environment", "DNS backend selected", "exit_code=1", "DNS restored"):
            self.assertIn(marker, log)
        self.assertNotIn("never-log-this-secret", log)
        self.assertNotIn("AAECAwQFBgc", log)

    async def test_bad_metadata_is_visible_error_not_success_with_empty_list(self):
        connection_id = await self.import_profile("awg")
        path = self.service.store.connection_dir(connection_id) / "metadata.json"
        path.write_text("{", encoding="utf-8")
        snapshot = await self.service.get_snapshot()
        self.assertFalse(snapshot["success"])
        self.assertEqual(snapshot["code"], "STORAGE_METADATA_UNREADABLE")
        self.assertNotIn("connections", snapshot)

    async def test_permission_failure_is_not_empty_snapshot(self):
        await self.import_profile("awg")
        with patch("vdeck.storage.Path.open", side_effect=PermissionError):
            result = await self.service.get_snapshot()
        self.assertEqual(result["code"], "STORAGE_METADATA_UNREADABLE")

    async def test_cleanup_failure_preserves_primary_error_and_runtime_ownership(self):
        connection_id = await self.import_profile("awg")
        self.system.fail_stage = "dns"
        routes = self.service.registry.get("amneziawg").context.routes
        real_cleanup = routes.cleanup
        routes.cleanup = AsyncMock(side_effect=VDeckError("ROUTE_RESTORE_FAILED", "failed cleanup"))
        response = await self.service.connect(connection_id)
        self.assertEqual(response["code"], "DNS_APPLY_FAILED")
        self.assertTrue(self.service.store.load_runtime().owned_routes)
        self.assertEqual(self.service.store.load_runtime().state, "ERROR")
        await self.assert_profile(connection_id)
        routes.cleanup = real_cleanup
        self.system.fail_stage = None
        self.assertTrue((await self.service.disconnect())["success"])
        self.assertFalse(self.system.routes)

    async def test_cancellation_after_route_write_is_cleaned_and_not_stuck_connecting(self):
        connection_id = await self.import_profile("awg")
        self.dns.apply = AsyncMock(side_effect=asyncio.CancelledError)
        with self.assertRaises(asyncio.CancelledError):
            await self.service.connect(connection_id)
        self.assertFalse(self.system.routes)
        self.assertFalse(self.system.tun)
        self.assertEqual(self.service.store.load_runtime().state, "ERROR")
        await self.assert_profile(connection_id)

    async def test_ipv6_guard_and_killswitch_do_not_allow_established_underlay_flows(self):
        connection_id = await self.import_profile("awg")
        state = self.service.store.load_state()
        state.kill_switch = True
        self.service.store.save_state(state)
        self.assertTrue((await self.service.connect(connection_id))["success"])
        self.assertIn("meta nfproto ipv6 reject", self.system.tables["vdeck_ipv6"])
        self.assertNotIn("ct state established,related accept", self.system.tables["vdeck"])
        self.assertTrue((await self.service.disconnect())["success"])
        self.assertFalse(self.system.tables)

    async def test_initial_runtime_default_has_no_destructive_profile_effect(self):
        connection_id = await self.import_profile("awg")
        self.service.store.save_runtime(RuntimeState())
        await self.assert_profile(connection_id)

    async def test_wifi_recovery_with_killswitch_allows_recreated_tunnel_before_health(self):
        for kind in ("awg-vpn", "awg", "kernel", "userspace"):
            with self.subTest(kind=kind):
                connection_id = await self.import_profile(kind)
                state = self.service.store.load_state()
                state.kill_switch = True
                self.service.store.save_state(state)
                self.assertTrue((await self.service.connect(connection_id))["success"])
                self.system.endpoint_failures = 1
                await self.service.manager._recover(connection_id)
                self.assertEqual(self.service.store.load_runtime().state, "CONNECTED")
                self.assertIn(f'oifname "{self.system.interface}" accept', self.system.tables["vdeck"])
                self.assertTrue((await self.service.disconnect())["success"])
                self.assertFalse(self.system.tables)
                self.assertFalse(self.system.routes)
                self.assertFalse(self.system.tun)
                await self.assert_profile(connection_id)

    async def test_process_crash_recovers_with_one_dns_profile_then_manual_off(self):
        connection_id = await self.import_profile("awg")
        self.assertTrue((await self.service.connect(connection_id))["success"])
        pid = self.service.store.load_runtime().process["pid"]
        self.system.live[pid] = False
        await self.service.manager.health_check()
        await self.service.manager._recovery_task
        self.assertEqual(self.service.store.load_runtime().state, "CONNECTED")
        self.assertEqual(len(self.system.nm_profiles), 1)
        self.assertTrue((await self.service.disconnect())["success"])
        await self.service.manager.network_event()
        self.assertFalse(self.system.nm_profiles)
        self.assertEqual(self.service.store.load_state().desired_state, "OFF")
        await self.assert_profile(connection_id)

    async def test_profile_switch_removes_old_dns_before_adding_new(self):
        first = await self.import_profile("awg")
        second = await self.import_profile("userspace")
        self.assertTrue((await self.service.connect(first))["success"])
        old = self.dns._load()["uuid"]
        self.assertTrue((await self.service.connect(second))["success"])
        self.assertNotEqual(old, self.dns._load()["uuid"])
        self.assertEqual(len(self.system.nm_profiles), 1)
        self.assertNotIn(old, self.system.nm_profiles)
        self.assertEqual(len((await self.service.get_snapshot())["connections"]), 2)

    async def test_corrupt_dns_journal_is_not_treated_as_empty(self):
        self.dns.journal.write_text("{", encoding="utf-8")
        with self.assertRaises(VDeckError) as raised:
            await self.dns.cleanup(None)
        self.assertEqual(raised.exception.code, "DNS_JOURNAL_UNREADABLE")

    async def test_startup_cleanup_failure_keeps_snapshot_rpc_available(self):
        connection_id = await self.import_profile("awg")
        self.service.dns.cleanup = AsyncMock(side_effect=VDeckError("DNS_RESTORE_FAILED", "pending"))
        self.service.binaries.prepare = Mock()
        self.service._network_monitor = AsyncMock()
        await self.service.initialize()
        snapshot = await self.service.get_snapshot()
        self.assertTrue(snapshot["success"])
        self.assertEqual(snapshot["runtime"]["error_code"], "DNS_RESTORE_FAILED")
        await self.assert_profile(connection_id)

    async def test_endpoint_route_loop_rejected_before_vpn_routes(self):
        connection_id = await self.import_profile("awg")
        self.inspector.route_to = AsyncMock(return_value=(None, "vdeck-12345678"))
        response = await self.service.connect(connection_id)
        self.assertEqual(response["code"], "ENDPOINT_ROUTE_INVALID")
        self.assertFalse(self.system.routes)
        await self.assert_profile(connection_id)

    async def monitor_events(self, events):
        stream = asyncio.StreamReader()
        stream.feed_data(events.encode())
        stream.feed_eof()
        errors = asyncio.StreamReader()
        errors.feed_eof()
        process = Mock(stdout=stream, stderr=errors, returncode=0, wait=AsyncMock(return_value=0))
        with patch("vdeck.service.asyncio.create_subprocess_exec", AsyncMock(return_value=process)) as spawn:
            await self.service._watch_network_devices()
        self.assertEqual(spawn.call_args.args, ("nmcli", "--colors", "no", "device", "monitor"))
        self.assertEqual(spawn.call_args.kwargs["env"]["LC_ALL"], "C")

    async def test_wifi_restored_after_exhaustion_restarts_recovery_but_own_events_do_not(self):
        connection_id = await self.import_profile("awg")
        self.assertTrue((await self.service.connect(connection_id))["success"])
        self.system.live[self.service.store.load_runtime().process["pid"]] = False
        self.system.fail_stage = "route"
        await self.service.manager.health_check()
        await self.service.manager._recovery_task
        self.assertEqual(self.service.store.load_runtime().error_code, "RECOVERY_EXHAUSTED")
        old_task = self.service.manager._recovery_task
        await self.monitor_events("vdeck-12345678: disconnected\nvdns-12345678: connected\n")
        self.assertIs(self.service.manager._recovery_task, old_task)
        self.system.fail_stage = None
        await self.monitor_events("wlan0: connected\n")
        await self.service.manager._recovery_task
        self.assertIsNot(self.service.manager._recovery_task, old_task)
        self.assertEqual(self.service.store.load_runtime().state, "CONNECTED")
        self.assertEqual(len(self.system.nm_profiles), 1)
        self.assertTrue((await self.service.disconnect())["success"])
        stopped_task = self.service.manager._recovery_task
        await self.monitor_events("wlan0: connected\n")
        self.assertIs(self.service.manager._recovery_task, stopped_task)
        self.assertEqual(self.service.store.load_state().desired_state, "OFF")

    async def test_network_events_do_not_restart_healthy_tunnel(self):
        connection_id = await self.import_profile("awg")
        self.assertTrue((await self.service.connect(connection_id))["success"])
        pid = self.service.store.load_runtime().process["pid"]
        await self.monitor_events("vdeck-12345678: connected\nvdns-12345678: connected\nwlan0: connected\n")
        self.assertIsNone(self.service.manager._recovery_task)
        self.assertEqual(self.service.store.load_runtime().process["pid"], pid)

    async def test_network_monitor_resumes_after_nm_exit_with_bounded_backoff(self):
        self.service._watch_network_devices = AsyncMock(side_effect=[None, asyncio.CancelledError])
        with patch("vdeck.service.asyncio.sleep", AsyncMock()) as sleep, self.assertRaises(asyncio.CancelledError):
            await self.service._network_monitor()
        self.assertEqual(self.service._watch_network_devices.await_count, 2)
        sleep.assert_awaited_once_with(5)

    async def test_killswitch_dns_failure_after_successful_preflight_never_publishes_connected(self):
        for kind in ("awg", "kernel", "userspace"):
            with self.subTest(kind=kind):
                connection_id = await self.import_profile(kind)
                state = self.service.store.load_state()
                state.kill_switch = True
                self.service.store.save_state(state)
                stages = []

                async def dns_probe(interface, servers, stages=stages):
                    active = "vdeck" in self.system.tables
                    stages.append((active, self.service.store.load_runtime().state))
                    return not active

                self.inspector.dns_probe.side_effect = dns_probe
                response = await self.service.connect(connection_id)
                self.assertEqual(response["code"], "DNS_PROBE_FAILED")
                self.assertEqual(stages, [(False, "CONNECTING"), (True, "CONNECTING")])
                self.assertFalse(self.system.tables)
                self.assertFalse(self.system.routes)
                self.assertEqual(self.service.store.load_state().desired_state, "OFF")
                await self.assert_profile(connection_id)

    async def without_dns(self, *, split=False):
        source = (FIXTURES / "awg31.conf").read_text(encoding="utf-8")
        source = "\n".join(line for line in source.splitlines() if not line.startswith("DNS ="))
        if split:
            source = source.replace("0.0.0.0/0", "10.30.0.0/24")
        path = self.root / "no-dns.conf"
        path.write_text(source, encoding="utf-8")
        response = await self.service.import_connection("amneziawg", str(path), "No DNS")
        self.assertTrue(response["success"])
        self.dns.environment = AsyncMock(return_value={"nss_uses_resolved": False})
        return response["connection"]["id"]

    async def test_no_dns_direct_system_resolver_is_probed_on_verified_vpn_route(self):
        connection_id = await self.without_dns()
        self.assertTrue((await self.service.connect(connection_id))["success"])
        self.assertFalse(self.system.nm_profiles)
        self.assertEqual(self.system.resolver.read_text(), "nameserver 192.0.2.53\n")
        self.inspector.dns_probe.assert_awaited_with(self.service.store.load_runtime().interface, ["192.0.2.53"])
        self.assertTrue((await self.service.disconnect())["success"])

    async def test_no_dns_stub_or_unreachable_system_resolver_is_explicit_error(self):
        for resolver in ("127.0.0.53", "192.0.2.53"):
            with self.subTest(resolver=resolver):
                connection_id = await self.without_dns()
                self.system.resolver.write_text(f"nameserver {resolver}\n", encoding="utf-8")
                self.inspector.dns_probe.return_value = False
                response = await self.service.connect(connection_id)
                self.assertEqual(
                    response["code"], "DNS_CONFIGURATION_REQUIRED" if resolver.startswith("127") else "DNS_PROBE_FAILED"
                )
                self.assertFalse(self.system.tun)
                self.assertFalse(self.system.routes)
                await self.assert_profile(connection_id)

    async def test_no_dns_split_tunnel_allows_unchanged_underlay_only_with_killswitch_off(self):
        connection_id = await self.without_dns(split=True)
        self.assertTrue((await self.service.connect(connection_id))["success"])
        self.inspector.dns_probe.assert_awaited_with("wlan0", ["192.0.2.53"])
        self.assertTrue((await self.service.disconnect())["success"])
        state = self.service.store.load_state()
        state.kill_switch = True
        self.service.store.save_state(state)
        response = await self.service.connect(connection_id)
        self.assertEqual(response["code"], "DNS_CONFIGURATION_REQUIRED")
        self.assertFalse(self.system.tables)
        await self.assert_profile(connection_id)

    async def test_explicit_dns_overlapping_wifi_subnet_gets_owned_host_route(self):
        path = self.root / "lan-dns.conf"
        path.write_text(
            (FIXTURES / "awg31.conf").read_text().replace("DNS = 9.9.9.9", "DNS = 192.0.2.53"), encoding="utf-8"
        )
        imported = await self.service.import_connection("amneziawg", str(path), "LAN DNS")
        connection_id = imported["connection"]["id"]
        foreign = ["ip", "-4", "route", "add", "192.0.2.0/24", "dev", "wlan0", "proto", "kernel", "metric", "600"]
        self.system.routes.append(foreign)
        self.assertTrue((await self.service.connect(connection_id))["success"])
        runtime = self.service.store.load_runtime()
        self.assertEqual((await self.inspector.route_to("192.0.2.53"))[1], runtime.interface)
        self.assertTrue(
            any(route["prefix"] == "192.0.2.53/32" and route["metric"] == 4 for route in runtime.owned_routes)
        )
        self.assertTrue((await self.service.disconnect())["success"])
        self.assertEqual(self.system.routes, [foreign])
        deletions = [args for args in self.system.calls if args[:4] == ["ip", "-4", "route", "del"]]
        self.assertTrue(all("metric" in args for args in deletions if "vdeck-" in " ".join(args)))

    async def test_dns_endpoint_route_conflict_is_explicit_and_cleanup_preserves_profile(self):
        connection_id = await self.import_profile("awg")
        self.inspector.resolve_endpoint.return_value = ["9.9.9.9"]
        result = await self.service.connect(connection_id)
        self.assertEqual(result["code"], "DNS_ENDPOINT_CONFLICT")
        self.assertFalse(self.system.routes)
        await self.assert_profile(connection_id)

    async def test_dns_outage_on_established_tunnel_triggers_recovery_not_false_healthy(self):
        connection_id = await self.import_profile("awg")
        self.assertTrue((await self.service.connect(connection_id))["success"])
        self.inspector.dns_probe.return_value = False
        backend = self.service.registry.get("amneziawg")
        health = await backend.health(self.service.store.get(connection_id), self.service.store.load_runtime())
        self.assertFalse(health["healthy"])
        self.assertEqual(health["dns_error_code"], "DNS_PROBE_FAILED")
        await self.service.manager.health_check()
        await self.service.manager._recovery_task
        self.assertEqual(self.service.store.load_runtime().error_code, "RECOVERY_EXHAUSTED")
        await self.assert_profile(connection_id)
