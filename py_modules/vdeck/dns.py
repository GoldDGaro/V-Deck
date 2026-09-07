"""Capability-gated DNS with a write-ahead journal; never edit system config files."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import shutil
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any

from .atomic import atomic_write_json
from .errors import VDeckError
from .runner import CommandResult, CommandRunner, check_loader_error
from .security import sanitize

NM = "org.freedesktop.NetworkManager"


class DnsManager:
    def __init__(self, runner: CommandRunner, journal: Path | None = None):
        self.runner = runner
        self.journal = journal
        self._owned: dict[str, Any] = {}
        self.logger = getattr(runner, "logger", logging.getLogger(__name__))
        self.resolv_conf = Path("/etc/resolv.conf")

    def _load(self) -> dict[str, Any]:
        if not self.journal:
            return self._owned
        try:
            value = json.loads(self.journal.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("Invalid journal")
            return value
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise VDeckError("DNS_JOURNAL_UNREADABLE", "DNS cleanup journal is unreadable") from exc

    def _save(self, value: dict[str, Any]) -> None:
        if self.journal:
            atomic_write_json(self.journal, value)
        self._owned = value.copy()

    async def _command(self, args: list[str], *, required: bool = False) -> CommandResult:
        # Only DNS/control commands are accepted here, never wg show/config input.
        try:
            result = await self.runner.run(args, check=False, timeout=12, env={"LC_ALL": "C"})
        except (OSError, VDeckError) as exc:
            if isinstance(exc, VDeckError) and exc.code == "COMMAND_LOADER_FAILED":
                raise
            self.logger.warning("DNS command unavailable command=%s error=%s", args, type(exc).__name__)
            if required:
                raise VDeckError("DNS_COMMAND_FAILED", "DNS command could not be executed") from exc
            return CommandResult(tuple(args), 127, "", type(exc).__name__)
        check_loader_error(result)
        self.logger.info(
            "DNS command command=%s exit_code=%d stdout=%s stderr=%s",
            args,
            result.returncode,
            sanitize(result.stdout)[-1200:],
            sanitize(result.stderr)[-1200:],
        )
        if required and result.returncode:
            raise VDeckError("DNS_APPLY_FAILED", "Unable to apply VPN DNS; see technical log")
        return result

    async def _nm_property(self, name: str) -> str:
        result = await self._command(
            [
                "busctl",
                "--system",
                "get-property",
                NM,
                "/org/freedesktop/NetworkManager/DnsManager",
                f"{NM}.DnsManager",
                name,
            ]
        )
        values = shlex.split(result.stdout) if result.returncode == 0 else []
        return values[1] if len(values) == 2 and values[0] == "s" else "unknown"

    def _resolvers(self) -> list[str]:
        try:
            text = self.resolv_conf.read_text(encoding="utf-8")
        except OSError:
            return []
        values = re.findall(r"(?m)^\s*nameserver\s+(\S+)", text)
        return [str(ipaddress.ip_address(value)) for value in values]

    async def environment(self) -> dict[str, Any]:
        resolved = await self._command(["systemctl", "is-active", "systemd-resolved.service"])
        nm = await self._command(["systemctl", "is-active", "NetworkManager.service"])
        mode = await self._nm_property("Mode") if nm.returncode == 0 else "inactive"
        rc = await self._nm_property("RcManager") if nm.returncode == 0 else "inactive"
        versions = {}
        for command in ("nmcli", "systemctl", "resolvectl"):
            result = await self._command([command, "--version"])
            versions[command] = result.stdout.splitlines()[0] if result.stdout else "unavailable"
        try:
            target = os.readlink(self.resolv_conf) if self.resolv_conf.is_symlink() else "regular-file"
            resolvers = self._resolvers()
        except (OSError, ValueError):
            target, resolvers = "unreadable", []
        os_info = "unknown"
        try:
            lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
            os_info = " ".join(line for line in lines if line.startswith(("ID=", "VERSION_ID=", "BUILD_ID=")))
        except OSError:
            pass
        ipv6 = "unknown"
        with suppress(OSError):
            ipv6 = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text().strip()
        nss_resolved = None
        with suppress(OSError):
            nss = Path("/etc/nsswitch.conf").read_text(encoding="utf-8")
            hosts = re.search(r"(?m)^hosts:\s*([^\n#]*)", nss)
            if hosts:
                nss_resolved = "resolve" in hosts[1].split()
        result_info = {
            "os": os_info,
            "kernel": platform.release(),
            "arch": platform.machine(),
            "tools": {name: shutil.which(name) for name in ("resolvectl", "nmcli", "busctl", "ip", "nft", "ping")},
            "resolved_active": resolved.returncode == 0,
            "nm_active": nm.returncode == 0,
            "dns_mode": mode,
            "rc_manager": rc,
            "versions": versions,
            "resolv_conf": target,
            "resolver_count": len(resolvers),
            "uses_resolved": bool(resolvers) and set(resolvers) <= {"127.0.0.53", "127.0.0.54"},
            "nss_uses_resolved": nss_resolved,
            "tun_present": Path("/dev/net/tun").exists(),
            "ipv6_disabled": ipv6,
        }
        self.logger.info("network environment %s", result_info)
        return result_info

    async def apply(self, interface: str, servers: list[str], full_tunnel: bool) -> None:
        if not servers:
            self.logger.info("DNS backend selected backend=unchanged dns_count=0 interface=%s", interface)
            return
        if not re.fullmatch(r"vdeck-[0-9a-f]{8}", interface):
            raise VDeckError("DNS_INTERFACE_INVALID", "DNS target is not an owned VPN interface")
        servers = list(dict.fromkeys(str(ipaddress.ip_address(value)) for value in servers))
        if self._load():
            await self.cleanup(None)
        env = await self.environment()
        self.logger.info(
            "DNS apply started interface=%s dns_count=%d full_tunnel=%s", interface, len(servers), full_tunnel
        )
        # A running resolved instance is insufficient: libc must actually use it.
        if env["resolved_active"] and env["uses_resolved"]:
            backend = "resolved"
        elif (
            env["nm_active"]
            and env["dns_mode"] == "default"
            and env["rc_manager"] not in {"unmanaged", "unknown"}
            and (not env["resolved_active"] or env["nss_uses_resolved"] is False)
        ):
            backend = "networkmanager"
        else:
            raise VDeckError("DNS_BACKEND_UNSUPPORTED", "No supported active DNS manager; see technical log")
        self.logger.info("DNS backend selected backend=%s interface=%s", backend, interface)
        owned: dict[str, Any] = {"backend": backend, "interface": interface, "servers": servers, "ready": False}
        try:
            if backend == "resolved":
                self._save(owned)
                await self._command(["resolvectl", "dns", interface, *servers], required=True)
                # WG DNS has no search-domain scope: send all lookups to its DNS,
                # including split tunnels (DNS destinations must be in AllowedIPs).
                await self._command(["resolvectl", "domain", interface, "~."], required=True)
                await self._command(["resolvectl", "default-route", interface, "yes"], required=True)
            else:
                await self._apply_nm(owned)
            if not await self._verify(owned):
                raise VDeckError("DNS_VERIFY_FAILED", "VPN DNS settings were not adopted by the system resolver")
            owned["ready"] = True
            self._save(owned)
            self.logger.info("DNS apply succeeded backend=%s interface=%s", backend, interface)
        except (Exception, asyncio.CancelledError):
            try:
                await self.cleanup(interface)
            except Exception as exc:
                self.logger.warning("DNS rollback pending code=%s", getattr(exc, "code", type(exc).__name__))
            raise

    async def unmodified_servers(self) -> list[str]:
        """Allow unchanged DNS only when libc's direct resolver path is known.

        A local stub or NSS resolve module can bind requests to another link;
        a successful tunnel-bound probe would not prove that path is safe.
        Do not invent public DNS or change the imported profile to work around it.
        """
        env = await self.environment()
        try:
            servers = self._resolvers()
        except ValueError:
            servers = []
        if (
            not servers
            or env["nss_uses_resolved"] is not False
            or any(
                ipaddress.ip_address(value).is_loopback or ipaddress.ip_address(value).is_link_local
                for value in servers
            )
        ):
            raise VDeckError(
                "DNS_CONFIGURATION_REQUIRED",
                "Set DNS in the VPN profile: the unchanged resolver path could not be verified",
            )
        return list(dict.fromkeys(servers))

    async def _apply_nm(self, owned: dict[str, Any]) -> None:
        # For NM dns=default only: a temporary DNS-contributor profile. It owns
        # a separate dummy link, never adopts/reapplies a physical or VPN link.
        # Not used with caching plugins, which bind DNS sockets to that link.
        token = str(uuid.uuid4())
        device = f"vdns-{token[:8]}"
        name = f"vdeck-dns-{token}"
        exists = await self._command(["ip", "link", "show", "dev", device])
        if exists.returncode == 0:
            raise VDeckError("DNS_OWNERSHIP_CONFLICT", "DNS helper interface already exists")
        owned.update(uuid=token, name=name, device=device)
        self._save(owned)  # before add/up, including cancellation/crash window
        args = [
            "nmcli",
            "--wait",
            "10",
            "connection",
            "add",
            "save",
            "no",
            "type",
            "dummy",
            "ifname",
            device,
            "con-name",
            name,
            "connection.uuid",
            token,
            "connection.autoconnect",
            "no",
        ]
        v4 = [value for value in owned["servers"] if ":" not in value]
        v6 = [value for value in owned["servers"] if ":" in value]
        for family, servers in ((4, v4), (6, v6)):
            setting = f"ipv{family}"
            if not servers:
                args += [f"{setting}.method", "disabled"]
                continue
            # An NM manual dummy needs an address to contribute DNS. These
            # host-only addresses are local placeholders, never VPN addresses.
            placeholder = "169.254.254.254/32" if family == 4 else f"fd42:{token[:4]}:{token[4:8]}::1/128"
            addresses = await self._command(["ip", f"-{family}", "address", "show"], required=True)
            if placeholder.split("/")[0] + "/" in addresses.stdout:
                raise VDeckError("DNS_OWNERSHIP_CONFLICT", "DNS helper address is already in use")
            args += [
                f"{setting}.method",
                "manual",
                f"{setting}.addresses",
                placeholder,
                f"{setting}.never-default",
                "yes",
                f"{setting}.ignore-auto-dns",
                "yes",
                f"{setting}.dns-priority",
                "-2147483648",
                f"{setting}.route-table",
                "254",
                f"{setting}.dns",
                ",".join(servers),
            ]
        await self._command(args, required=True)
        # Property is absent in older NM. On newer NM override a global default
        # that could otherwise route DNS into the dummy instead of the VPN.
        for family in (4, 6):
            property_name = f"ipv{family}.routed-dns"
            routed = await self._command(["nmcli", "-g", property_name, "connection", "show", "uuid", token])
            if routed.returncode == 0:
                await self._command(
                    [
                        "nmcli",
                        "connection",
                        "modify",
                        "--temporary",
                        "uuid",
                        token,
                        property_name,
                        "no",
                    ],
                    required=True,
                )
        await self._command(["nmcli", "--wait", "10", "connection", "up", "uuid", token], required=True)

    async def _verify(self, owned: dict[str, Any]) -> bool:
        if owned["backend"] == "networkmanager":
            try:
                return set(self._resolvers()) == set(owned["servers"])
            except ValueError:
                return False
        dns = await self._command(["resolvectl", "dns", owned["interface"]])
        domain = await self._command(["resolvectl", "domain", owned["interface"]])
        domains = await self._command(["resolvectl", "domain"])
        if domains.returncode or domains.stdout.split().count("~.") != 1:
            return False  # do not compete with another VPN root DNS domain
        tokens = dns.stdout.split()
        return (
            dns.returncode == domain.returncode == 0
            and all(value in tokens for value in owned["servers"])
            and "~." in domain.stdout.split()
        )

    async def healthy(self, interface: str) -> bool:
        owned = self._load()
        return bool(owned) and (
            owned.get("interface") == interface and bool(owned.get("ready")) and await self._verify(owned)
        )

    async def cleanup(self, interface: str | None) -> None:
        owned = self._load()
        if not owned or (interface and owned.get("interface") != interface):
            return
        if owned.get("backend") == "networkmanager":
            token = str(uuid.UUID(owned["uuid"]))
            result = await self._command(
                [
                    "nmcli",
                    "-g",
                    "connection.id,connection.interface-name,connection.type",
                    "connection",
                    "show",
                    "uuid",
                    token,
                ]
            )
            if result.returncode == 0:
                if result.stdout.splitlines() != [owned["name"], owned["device"], "dummy"]:
                    raise VDeckError("DNS_OWNERSHIP_CONFLICT", "Refusing to remove an unowned DNS profile")
                await self._command(["nmcli", "--wait", "10", "connection", "delete", "uuid", token], required=True)
            elif result.returncode != 10:  # nmcli: object not found; other failures must keep journal
                raise VDeckError("DNS_RESTORE_FAILED", "Cannot verify DNS profile removal")
            # Deleting the active NM software connection removes its dummy link;
            # do not delete a same-name link ourselves without an identity cookie.
        elif owned.get("backend") == "resolved":
            name = owned.get("interface", "")
            if not re.fullmatch(r"vdeck-[0-9a-f]{8}", name):
                raise VDeckError("DNS_OWNERSHIP_CONFLICT", "Invalid DNS ownership journal")
            exists = await self._command(["ip", "link", "show", "dev", name])
            if exists.returncode == 0:
                await self._command(["resolvectl", "revert", name], required=True)
            elif exists.returncode != 1:
                raise VDeckError("DNS_RESTORE_FAILED", "Cannot verify DNS interface removal")
        else:
            raise VDeckError("DNS_OWNERSHIP_CONFLICT", "Unknown DNS ownership journal")
        self._save({})
        self.logger.info("DNS restored backend=%s interface=%s", owned["backend"], owned["interface"])
