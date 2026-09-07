"""On-demand structured tunnel diagnostics and privacy-safe reports."""

from __future__ import annotations

import ipaddress
import json
import platform
import re
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .atomic import atomic_write_bytes
from .backends.registry import BackendRegistry
from .backends.wireguard import handshake_probe_target
from .binaries import BinaryManager
from .dns import DnsManager
from .logging_utils import ErrorHistory
from .models import CheckStatus
from .network import FirewallManager, NetworkInspector
from .runner import CommandRunner
from .security import sanitize, sanitize_report
from .storage import VDeckStore


def _mask_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version == 4:
        octets = value.split(".")
        return f"{octets[0]}.{octets[1]}.x.x"
    network = ipaddress.ip_network(f"{address}/48", strict=False)
    return f"{network.network_address.compressed}/48"


def check(status: CheckStatus, detail: str = "") -> dict[str, str]:
    return {"status": status.value, "detail": detail}


class DiagnosticsManager:
    def __init__(
        self,
        store: VDeckStore,
        registry: BackendRegistry,
        runner: CommandRunner,
        inspector: NetworkInspector,
        firewall: FirewallManager,
        binaries: BinaryManager,
        errors: ErrorHistory,
    ):
        self.store = store
        self.registry = registry
        self.runner = runner
        self.inspector = inspector
        self.firewall = firewall
        self.binaries = binaries
        self.errors = errors

    async def collect(self, connection_id: str, *, include_external_ip: bool = False) -> dict[str, Any]:
        metadata = self.store.get(connection_id)
        runtime = self.store.load_runtime()
        backend_available = True
        backend = self.registry.get(metadata.protocol)
        active = runtime.connection_id == connection_id
        try:
            status = await backend.diagnostics(metadata, runtime) if active else {"connected": False, "tunnel": False}
        except Exception:
            backend_available = False
            status = {"connected": False, "tunnel": False, "rx_bytes": 0, "tx_bytes": 0}
        info = self.store.parsed_runtime_info(connection_id)
        configured_routes = [str(item) for item in info.get("allowed_ips", [])]
        full = any(item in {"0.0.0.0/0", "::/0"} for item in configured_routes)
        initial_rx = int(status.get("rx_bytes", 0))
        initial_tx = int(status.get("tx_bytes", 0))
        ping_ms = None
        ping_available = True
        if active and status.get("connected"):
            try:
                target = handshake_probe_target(configured_routes)
                if not target or not runtime.interface:
                    raise ValueError("No tunnel probe destination")
                ping = await self.runner.run(
                    ["ping", "-6" if ":" in target else "-4", "-I", runtime.interface, "-c", "1", "-W", "3", target],
                    check=False,
                    timeout=5,
                )
                match = re.search(r"time[=<]([0-9.]+)\s*ms", ping.stdout)
                if match:
                    ping_ms = round(float(match.group(1)))
                    # A probe yields: do not resurrect a deleted profile or
                    # overwrite a concurrent rename with its stale metadata.
                    current = self.store.get(connection_id)
                    current.last_ping_ms = ping_ms
                    self.store.update_metadata(current)
            except Exception:
                ping_available = False
            if backend_available:
                try:
                    status = await backend.diagnostics(metadata, runtime)
                except Exception:
                    backend_available = False
        transfer_delta = max(0, int(status.get("rx_bytes", 0)) - initial_rx) + max(
            0, int(status.get("tx_bytes", 0)) - initial_tx
        )
        routes_available = True
        route_present = False
        if active and runtime.interface:
            try:
                route_present = await self.inspector.vpn_routes_present(runtime.interface, configured_routes)
            except Exception:
                routes_available = False
        try:
            ipv6_underlay: bool | None = await self.inspector.public_ipv6_present()
        except Exception:
            ipv6_underlay = None
        vpn_has_ipv6 = any(":" in str(value) for value in info.get("allowed_ips", []))
        ipv6_status = CheckStatus.OK
        ipv6_detail = ""
        if ipv6_underlay is None:
            ipv6_status = CheckStatus.UNKNOWN
            ipv6_detail = "IPv6 inspection unavailable"
        elif ipv6_underlay and not vpn_has_ipv6:
            blocked = active and (runtime.firewall_active or getattr(runtime, "ipv6_guard", False))
            ipv6_status = CheckStatus.OK if blocked else CheckStatus.WARNING
            ipv6_detail = "Direct IPv6 is blocked" if blocked else "Possible IPv6 leak"
        # Public-IP requests are now a separate explicit user action. Ordinary
        # diagnostics, background ping and exported reports never send one.
        duration = None
        if active and runtime.started_at:
            try:
                started = datetime.fromisoformat(runtime.started_at)
                duration = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
            except ValueError:
                pass
        checks = {
            "tunnel": check(
                CheckStatus.UNKNOWN
                if not backend_available
                else CheckStatus.OK
                if status.get("tunnel")
                else CheckStatus.ERROR
            ),
            "handshake_state": check(
                CheckStatus.UNKNOWN
                if not backend_available
                else CheckStatus.WARNING
                if status.get("connected") and status.get("handshake_fresh") is False
                else CheckStatus.OK
                if status.get("connected")
                else CheckStatus.ERROR,
                "No recent handshake" if status.get("connected") and status.get("handshake_fresh") is False else "",
            ),
            "traffic": check(CheckStatus.OK if transfer_delta > 0 else CheckStatus.UNKNOWN),
            "routing": check(
                CheckStatus.UNKNOWN
                if not active or not routes_available
                else CheckStatus.OK
                if route_present
                else CheckStatus.ERROR,
                "Full tunnel" if full else "Limited routing / Split tunnel",
            ),
            "internet": check(
                CheckStatus.UNKNOWN
                if not ping_available
                else CheckStatus.OK
                if ping_ms is not None
                else CheckStatus.WARNING,
                "Ping utility unavailable" if not ping_available else "ICMP may be blocked" if ping_ms is None else "",
            ),
            "ipv4": check(
                CheckStatus.UNKNOWN
                if not backend_available
                else CheckStatus.OK
                if active and status.get("connected")
                else CheckStatus.ERROR
            ),
            "ipv6": check(ipv6_status, ipv6_detail),
        }
        overall = (
            CheckStatus.ERROR
            if any(item["status"] == CheckStatus.ERROR.value for item in checks.values())
            else (
                CheckStatus.WARNING
                if any(item["status"] == CheckStatus.WARNING.value for item in checks.values())
                else CheckStatus.OK
            )
        )
        return {
            "overall": overall.value,
            "protocol": metadata.protocol,
            "checks": checks,
            "external_ip": None,
            "ping_ms": ping_ms if ping_ms is not None else metadata.last_ping_ms,
            "session_seconds": duration,
            "rx_bytes": status.get("rx_bytes", 0),
            "tx_bytes": status.get("tx_bytes", 0),
            "interface": runtime.interface if active else None,
            "state": runtime.state if active else "DISCONNECTED",
        }

    async def export(self, connection_id: str, decky_version: str | None = None) -> Path:
        metadata = self.store.get(connection_id)
        diagnostics = await self.collect(connection_id)
        diagnostics["external_ip"] = _mask_ip(diagnostics.get("external_ip"))
        os_release = ""
        with suppress(OSError):
            os_release = Path("/etc/os-release").read_text(encoding="utf-8")
        logs = ""
        log_path = self.store.logs / "vdeck.log"
        if log_path.exists():
            logs = log_path.read_text(encoding="utf-8", errors="replace")[-100_000:]
        report = {
            "vdeck_version": "0.1.0",
            "steamos": sanitize(os_release),
            "decky_version": decky_version,
            "architecture": platform.machine(),
            "platform": platform.platform(),
            "backend_versions": self.binaries.versions(),
            "network_environment": await DnsManager(self.runner).environment(),
            "connection": {"display_name": metadata.display_name, "id": metadata.id, "protocol": metadata.protocol},
            "diagnostics": diagnostics,
            "firewall_active": await self._firewall_active(),
            "recent_errors": [
                {key: sanitize_report(value) for key, value in entry.items()} for entry in self.errors.list()
            ],
            "logs": sanitize_report(logs),
        }
        name = f"vdeck-diagnostics-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        path = self.store.reports / name
        atomic_write_bytes(path, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode())
        return path

    async def _firewall_active(self) -> bool | None:
        try:
            return await self.firewall.active()
        except Exception:
            return None
