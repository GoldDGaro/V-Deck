from __future__ import annotations

import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from vdeck.backends.amneziawg import AmneziaWGBackend
from vdeck.backends.wireguard import WireGuardBackend, resolved_wireguard_config
from vdeck.models import RuntimeState
from vdeck.network import NetworkInspector
from vdeck.runner import CommandResult


class FakeStore:
    def parsed_runtime_info(self, connection_id):
        return {"allowed_ips": ["0.0.0.0/0"], "endpoints": ["vpn.example.com:51820"]}

    def save_runtime(self, runtime):
        return None


class FakeBinaries:
    def command(self, name, *args):
        return [name, *args]


class HealthRunner:
    def __init__(self, dumps, *, probe_returncode):
        self.dumps = list(dumps)
        self.probe_returncode = probe_returncode
        self.calls = []

    async def run(self, args, **kwargs):
        rendered = list(args)
        self.calls.append(rendered)
        if rendered[:4] == ["ip", "link", "show", "dev"]:
            return CommandResult(tuple(rendered), 0, "", "")
        if rendered[:4] == ["ip", "-4", "route", "show"]:
            routes = "0.0.0.0/1 dev vdeck-12345678\n128.0.0.0/1 dev vdeck-12345678\n"
            return CommandResult(tuple(rendered), 0, routes, "")
        if rendered[:4] == ["ip", "-6", "route", "show"]:
            return CommandResult(tuple(rendered), 0, "", "")
        if rendered[:4] == ["ip", "-4", "route", "get"]:
            return CommandResult(tuple(rendered), 0, "1.1.1.1 dev vdeck-12345678", "")
        if rendered and rendered[0] == "ping":
            return CommandResult(tuple(rendered), self.probe_returncode, "", "timeout")
        if "show" in rendered and "dump" in rendered:
            value = self.dumps.pop(0) if len(self.dumps) > 1 else self.dumps[0]
            return CommandResult(tuple(rendered), 0, value, "")
        return CommandResult(tuple(rendered), 0, "", "")


def dump(handshake, rx, tx):
    return f"private\tpublic\t51820\toff\npeer\tpsk\t198.51.100.8:51820\t0.0.0.0/0\t{handshake}\t{rx}\t{tx}\t25\n"


def backend_for(backend_type, runner):
    inspector = NetworkInspector(runner)
    context = SimpleNamespace(
        store=FakeStore(),
        binaries=FakeBinaries(),
        runner=runner,
        inspector=inspector,
        routes=object(),
        dns=object(),
    )
    backend = backend_type(context)
    # These tests isolate traffic/handshake semantics; real DNS verification is
    # exercised by RuntimePipelineTests with both resolver implementations.
    backend._verify_dns = AsyncMock()
    return backend


class WireGuardHealthTests(unittest.IsolatedAsyncioTestCase):
    async def test_old_handshake_failed_probe_is_unhealthy_for_wg_and_awg(self):
        old = int(time.time()) - 600
        for backend_type in (WireGuardBackend, AmneziaWGBackend):
            with self.subTest(backend=backend_type.__name__):
                runner = HealthRunner([dump(old, 100, 100), dump(old, 100, 120)], probe_returncode=1)
                backend = backend_for(backend_type, runner)
                runtime = RuntimeState(
                    interface="vdeck-12345678",
                    owned_routes=[{"family": 4, "prefix": "0.0.0.0/1"}],
                )
                result = await backend.health(SimpleNamespace(id="connection-id"), runtime)
                self.assertFalse(result["healthy"])
                self.assertFalse(result["probe_succeeded"])
                self.assertFalse(result["handshake_advanced"])
                self.assertTrue(result["tx_advanced"])
                expected_tool = "awg" if backend_type is AmneziaWGBackend else "wg"
                self.assertTrue(any(call and call[0] == expected_tool for call in runner.calls))

    async def test_old_handshake_successful_probe_keeps_idle_tunnel_healthy(self):
        old = int(time.time()) - 600
        for backend_type in (WireGuardBackend, AmneziaWGBackend):
            with self.subTest(backend=backend_type.__name__):
                runner = HealthRunner([dump(old, 100, 100), dump(old, 100, 120)], probe_returncode=0)
                backend = backend_for(backend_type, runner)
                runtime = RuntimeState(interface="vdeck-12345678", owned_routes=[{"family": 4}])
                result = await backend.health(SimpleNamespace(id="connection-id"), runtime)
                self.assertTrue(result["healthy"])
                self.assertTrue(result["probe_succeeded"])

    async def test_new_handshake_confirms_peer_even_when_inner_ping_is_blocked(self):
        old = int(time.time()) - 600
        recent = int(time.time())
        runner = HealthRunner([dump(old, 100, 100), dump(recent, 100, 120)], probe_returncode=1)
        backend = backend_for(WireGuardBackend, runner)
        result = await backend.health(
            SimpleNamespace(id="connection-id"), RuntimeState(interface="vdeck-12345678", owned_routes=[{"family": 4}])
        )
        self.assertTrue(result["healthy"])
        self.assertTrue(result["handshake_advanced"])


class ResolvedConfigTests(unittest.TestCase):
    def test_hostname_endpoint_is_replaced_with_cached_numeric_address(self):
        source = "[Peer]\nEndpoint = vpn.example.com:51820\n"
        rendered = resolved_wireguard_config(source, {"vpn.example.com:51820": ["2001:db8::8"]})
        self.assertIn("Endpoint = [2001:db8::8]:51820", rendered)
        self.assertNotIn("vpn.example.com", rendered)


if __name__ == "__main__":
    unittest.main()
