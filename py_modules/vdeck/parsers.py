"""Parsers for supported VPN configuration formats.

Imported files are untrusted. Parsing never executes hooks and never rewrites the
user's source file.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import shlex
import zlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .errors import VDeckError
from .models import Protocol
from .security import MAX_CONFIG_BYTES, ensure_regular_file, resolve_import_dependency

AWG_FIELDS = {
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "headerprotectionkey",
    "contentpaddingaddition",
    "rekeyaftertime",
    "rekeytimeout",
    "rejectaftertime",
    "keepalivetimeout",
    "maxhandshakeattempts",
    "randomtrailers",
    "disablecookies",
}
INTERFACE_ONLY_FIELDS = {"address", "dns", "mtu", "table"}
WG_DANGEROUS_FIELDS = {"preup", "postup", "predown", "postdown", "saveconfig"}
OPENVPN_DANGEROUS = {
    "up",
    "down",
    "route-up",
    "route-pre-down",
    "ipchange",
    "tls-verify",
    "auth-user-pass-verify",
    "client-connect",
    "client-disconnect",
    "learn-address",
    "plugin",
    "script-security",
    "management",
    "management-client-user",
    "management-client-group",
    "daemon",
    "chroot",
    "management-client-auth",
    "management-external-key",
    "management-external-cert",
    "management-hold",
    "management-query-passwords",
    "management-query-remote",
    "management-query-proxy",
    "management-signal",
    "management-up-down",
    "management-forget-disconnect",
    "tls-crypt-v2-verify",
    "askpass",
    "log",
    "log-append",
    "status",
    "writepid",
    "cd",
    "tmp-dir",
    "tls-export-cert",
    "auth-gen-token-secret",
    "client-config-dir",
    "replay-persist",
    "capath",
}
OPENVPN_EXTERNAL = {
    "ca",
    "cert",
    "key",
    "pkcs12",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "crl-verify",
    "dh",
    "extra-certs",
}
OPENVPN_INLINE_MATERIAL = OPENVPN_EXTERNAL | {"pkcs12"}
# A blacklist misses nested config loading, alternate executables and new
# plugin/file options. Only reviewed client directives may reach the root daemon.
OPENVPN_CLIENT_OPTIONS = OPENVPN_EXTERNAL | {
    "client",
    "tls-client",
    "dev",
    "dev-type",
    "proto",
    "remote",
    "port",
    "rport",
    "lport",
    "remote-random",
    "resolv-retry",
    "nobind",
    "bind",
    "local",
    "persist-key",
    "persist-tun",
    "auth-user-pass",
    "auth-nocache",
    "auth-retry",
    "auth",
    "cipher",
    "data-ciphers",
    "data-ciphers-fallback",
    "tls-cipher",
    "tls-ciphersuites",
    "tls-version-min",
    "tls-version-max",
    "remote-cert-tls",
    "remote-cert-ku",
    "remote-cert-eku",
    "verify-x509-name",
    "peer-fingerprint",
    "key-direction",
    "pull",
    "route",
    "route-ipv6",
    "redirect-gateway",
    "dhcp-option",
    "ifconfig",
    "ifconfig-ipv6",
    "topology",
    "tun-mtu",
    "mssfix",
    "fragment",
    "mtu-disc",
    "ping",
    "ping-restart",
    "ping-exit",
    "keepalive",
    "connect-retry",
    "connect-retry-max",
    "connect-timeout",
    "server-poll-timeout",
    "explicit-exit-notify",
    "reneg-sec",
    "reneg-bytes",
    "reneg-pkts",
    "hand-window",
    "tran-window",
    "tls-timeout",
    "sndbuf",
    "rcvbuf",
    "fast-io",
    "verb",
    "mute",
    "mute-replay-warnings",
    "allow-compression",
    "compress",
    "comp-lzo",
    "float",
    "disable-dco",
    "auth-token-user",
}


@dataclass
class ParsedConfig:
    protocol: str
    runtime_config: str
    source_format: str
    interface_addresses: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    mtu: int | None = None
    allowed_ips: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    files: dict[str, bytes] = field(default_factory=dict)
    requires_username_password: bool = False
    requires_key_passphrase: bool = False


def _decode_text(path: Path) -> str:
    resolved = ensure_regular_file(path)
    try:
        return resolved.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise VDeckError("CONFIG_ENCODING", "Configuration must be UTF-8 text") from exc


def _parse_sectioned(text: str) -> list[tuple[str, str, str, str]]:
    section = ""
    parsed: list[tuple[str, str, str, str]] = []
    for line_number, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        # wg/awg and wg-quick ignore # comments, including inline comments.
        raw = raw.split("#", 1)[0]
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", ";")):
            parsed.append((section, "", "", raw))
            continue
        match = re.fullmatch(r"\[([^]]+)\]", stripped)
        if match:
            section = match.group(1).strip().lower()
            parsed.append((section, "", "", raw))
            continue
        if "=" not in raw or not section:
            raise VDeckError("CONFIG_MALFORMED", f"Malformed configuration at line {line_number}")
        key, value = raw.split("=", 1)
        parsed.append((section, key.strip(), value.strip(), raw))
    return parsed


def _looks_like_key(value: str) -> bool:
    try:
        return len(base64.b64decode(value.strip(), validate=True)) == 32
    except (ValueError, binascii.Error):
        return False


def validate_wireguard_network(parsed: ParsedConfig) -> ParsedConfig:
    """Normalize untrusted network fields without echoing their values in errors."""
    for attribute, parser, code in (
        ("interface_addresses", ipaddress.ip_interface, "CONFIG_INVALID_ADDRESS"),
        ("dns_servers", ipaddress.ip_address, "CONFIG_INVALID_DNS"),
        ("allowed_ips", lambda value: ipaddress.ip_network(value, strict=False), "CONFIG_INVALID_ROUTE"),
    ):
        normalized: list[str] = []
        for index, value in enumerate(getattr(parsed, attribute)):
            if not isinstance(value, str) or "$" in value:
                raise VDeckError(
                    "CONFIG_UNRESOLVED_TEMPLATE", "Re-import the original VPN file to resolve network fields"
                )
            try:
                address = parser(value)
                if "%" in value:
                    raise ValueError("Scoped addresses are unsupported")
            except ValueError as exc:
                raise VDeckError(code, f"Invalid {attribute} entry at position {index + 1}") from exc
            rendered = str(address)
            if rendered not in normalized:
                normalized.append(rendered)
        setattr(parsed, attribute, normalized)
    v4 = ipaddress.collapse_addresses(ipaddress.IPv4Network(value) for value in parsed.allowed_ips if ":" not in value)
    v6 = ipaddress.collapse_addresses(ipaddress.IPv6Network(value) for value in parsed.allowed_ips if ":" in value)
    parsed.allowed_ips = [str(network) for network in [*v4, *v6]]
    if not parsed.interface_addresses or not parsed.allowed_ips or not parsed.endpoints:
        raise VDeckError("CONFIG_MISSING_NETWORK", "Configuration requires Address, AllowedIPs, and Endpoint")
    if parsed.mtu is not None and (type(parsed.mtu) is not int or not 576 <= parsed.mtu <= 65535):
        raise VDeckError("CONFIG_INVALID_MTU", "MTU must be between 576 and 65535")
    if any(":" in address for address in parsed.interface_addresses) and parsed.mtu is not None and parsed.mtu < 1280:
        raise VDeckError("CONFIG_INVALID_MTU", "IPv6 requires an MTU of at least 1280")
    for endpoint in parsed.endpoints:
        if not isinstance(endpoint, str) or "$" in endpoint:
            raise VDeckError("CONFIG_UNRESOLVED_TEMPLATE", "Re-import the original VPN file to resolve the endpoint")
        match = re.fullmatch(r"(?:\[([0-9A-Fa-f:]+)\]|([A-Za-z0-9_.-]+)):(\d{1,5})", endpoint)
        if not match or not 1 <= int(match[3]) <= 65535:
            raise VDeckError("ENDPOINT_INVALID", "Endpoint must contain a hostname or IP and a valid port")
        if match[1]:
            try:
                ipaddress.IPv6Address(match[1])
            except ValueError as exc:
                raise VDeckError("ENDPOINT_INVALID", "Invalid IPv6 endpoint") from exc
    return parsed


def parse_wireguard_text(text: str, selected_protocol: Protocol, source_format: str = ".conf") -> ParsedConfig:
    entries = _parse_sectioned(text)
    sections = {section for section, _, _, _ in entries if section}
    if "interface" not in sections or "peer" not in sections:
        raise VDeckError("CONFIG_MISSING_SECTION", "WireGuard configuration requires [Interface] and [Peer]")

    field_names = {key.lower() for _, key, _, _ in entries if key}
    has_awg = bool(field_names & AWG_FIELDS)
    if selected_protocol == Protocol.WIREGUARD and has_awg:
        raise VDeckError("CONFIG_WRONG_PROTOCOL_AWG", "This file looks like an AmneziaWG configuration")
    if selected_protocol == Protocol.AMNEZIAWG and not has_awg:
        raise VDeckError("CONFIG_WRONG_PROTOCOL_WG", "This file looks like a standard WireGuard configuration")
    dangerous = field_names & WG_DANGEROUS_FIELDS
    if dangerous:
        raise VDeckError("CONFIG_UNSAFE_DIRECTIVE", f"Command hooks are not supported: {', '.join(sorted(dangerous))}")

    private_keys = [
        value for section, key, value, _ in entries if section == "interface" and key.lower() == "privatekey"
    ]
    public_keys = [value for section, key, value, _ in entries if section == "peer" and key.lower() == "publickey"]
    if not private_keys or not public_keys:
        raise VDeckError("CONFIG_MISSING_KEY", "Configuration is missing a required private or public key")
    if not all(_looks_like_key(value) for value in private_keys + public_keys):
        raise VDeckError("CONFIG_INVALID_KEY", "Configuration contains an invalid WireGuard key")

    addresses: list[str] = []
    dns: list[str] = []
    allowed: list[str] = []
    endpoints: list[str] = []
    mtu: int | None = None
    output: list[str] = []
    for section, key, value, raw in entries:
        lowered = key.lower()
        if section == "interface" and lowered in INTERFACE_ONLY_FIELDS:
            values = [item.strip() for item in value.split(",") if item.strip()]
            if lowered == "address":
                addresses.extend(values)
            elif lowered == "dns":
                dns.extend(values)
            elif lowered == "mtu":
                try:
                    mtu = int(value)
                except ValueError as exc:
                    raise VDeckError("CONFIG_INVALID_MTU", "MTU must be an integer") from exc
            elif lowered == "table" and value.lower() != "auto":
                raise VDeckError("CONFIG_UNSUPPORTED_TABLE", "V-Deck owns routing; custom Table/off is unsupported")
            continue
        if section == "peer" and lowered == "allowedips":
            allowed.extend(item.strip() for item in value.split(",") if item.strip())
        if section == "peer" and lowered == "endpoint":
            endpoints.append(value)
        output.append(raw)

    if not addresses or not allowed or not endpoints:
        raise VDeckError("CONFIG_MISSING_NETWORK", "Configuration requires Address, AllowedIPs, and Endpoint")
    return validate_wireguard_network(
        ParsedConfig(
            protocol=selected_protocol.value,
            runtime_config="\n".join(output).strip() + "\n",
            source_format=source_format,
            interface_addresses=addresses,
            dns_servers=dns,
            mtu=mtu,
            allowed_ips=allowed,
            endpoints=endpoints,
        )
    )


def _qt_uncompress(value: bytes) -> bytes:
    def decompress_limited(compressed: bytes) -> bytes:
        decompressor = zlib.decompressobj()
        result = decompressor.decompress(compressed, MAX_CONFIG_BYTES * 2 + 1)
        if len(result) > MAX_CONFIG_BYTES * 2 or not decompressor.eof:
            raise VDeckError("CONFIG_TOO_LARGE", "Decoded Amnezia configuration is too large")
        return result + decompressor.flush()

    if len(value) >= 6:
        expected = int.from_bytes(value[:4], "big")
        try:
            result = decompress_limited(value[4:])
            if expected == len(result):
                return result
        except zlib.error:
            pass
    try:
        return decompress_limited(value)
    except zlib.error:
        return value


def _decode_amnezia_container(text: str) -> dict[str, object]:
    payload = text.strip()
    if payload.startswith("vpn://"):
        payload = payload[6:]
    if not payload or re.search(r"\s", payload):
        raise VDeckError("AMNEZIA_UNSUPPORTED", "Unsupported Amnezia configuration format")
    try:
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        raw = _qt_uncompress(decoded)
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, zlib.error) as exc:
        raise VDeckError("AMNEZIA_DECODE_FAILED", "Unable to decode the Amnezia configuration") from exc
    if not isinstance(document, dict):
        raise VDeckError("AMNEZIA_UNSUPPORTED", "Unsupported Amnezia configuration format")
    return document


def parse_amnezia_vpn(text: str) -> ParsedConfig:
    document = _decode_amnezia_container(text)
    containers = document.get("containers")
    if not isinstance(containers, list):
        raise VDeckError("AMNEZIA_UNSUPPORTED", "Unsupported Amnezia configuration format")
    matches = [
        item
        for item in containers
        if isinstance(item, dict) and item.get("container") in {"amnezia-awg", "amnezia-awg2"}
    ]
    if not matches:
        raise VDeckError("AMNEZIA_AWG_NOT_FOUND", "The Amnezia file does not contain an AmneziaWG connection")
    if len(matches) > 1:
        preferred = document.get("defaultContainer")
        matches = [item for item in matches if item.get("container") == preferred] or matches
    awg = matches[0].get("awg")
    if not isinstance(awg, dict):
        raise VDeckError("AMNEZIA_UNSUPPORTED", "Unsupported AmneziaWG container structure")
    last = awg.get("last_config")
    if isinstance(last, str):
        try:
            last = json.loads(last)
        except json.JSONDecodeError as exc:
            raise VDeckError("AMNEZIA_UNSUPPORTED", "Invalid AmneziaWG client data") from exc
    if not isinstance(last, dict) or not isinstance(last.get("config"), str):
        raise VDeckError("AMNEZIA_UNSUPPORTED", "The AmneziaWG container has no client configuration")
    config = last["config"]
    # Native sharing stores the DNS template; Amnezia applies the exported
    # server's dns1/dns2 before passing last_config.config to the VPN backend.
    replacements = {"$PRIMARY_DNS": document.get("dns1"), "$SECONDARY_DNS": document.get("dns2")}
    lines: list[str] = []
    for section, key, value, raw in _parse_sectioned(config):
        if section == "interface" and key.lower() == "dns":
            servers: list[str] = []
            for item in value.split(","):
                item = item.strip()
                if item in replacements:
                    replacement = replacements[item]
                    if item == "$SECONDARY_DNS" and replacement in (None, ""):
                        continue  # secondary DNS is optional; never invent a fallback
                    if not isinstance(replacement, str) or not replacement.strip():
                        raise VDeckError("AMNEZIA_DNS_MISSING", "The native VPN file is missing its DNS setting")
                    item = replacement.strip()
                if item:
                    servers.append(item)
            raw = "DNS = " + ", ".join(servers)
        lines.append(raw)
    return parse_wireguard_text("\n".join(lines), Protocol.AMNEZIAWG, source_format=".vpn")


def _openvpn_lines(text: str) -> Iterable[tuple[int, str, list[str]]]:
    in_block: str | None = None
    for number, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        stripped = raw.strip()
        if in_block and in_block != "connection":
            if stripped.lower() == f"</{in_block}>":
                in_block = None
            continue
        if in_block == "connection" and stripped.lower() == "</connection>":
            in_block = None
            continue
        if re.fullmatch(r"</[A-Za-z0-9_-]+>", stripped):
            raise VDeckError("CONFIG_MALFORMED", f"Unexpected OpenVPN inline closing tag at line {number}")
        block = re.fullmatch(r"<([A-Za-z0-9_-]+)>", stripped)
        if block:
            name = block.group(1).lower()
            if in_block:
                raise VDeckError("CONFIG_MALFORMED", f"Nested OpenVPN inline block at line {number}")
            if name == "auth-user-pass":
                raise VDeckError(
                    "CONFIG_UNSAFE_DIRECTIVE", "Inline OpenVPN credentials are not imported; enter them in V-Deck"
                )
            if name != "connection" and name not in OPENVPN_INLINE_MATERIAL:
                raise VDeckError("CONFIG_UNSAFE_DIRECTIVE", f"Unsupported OpenVPN inline block: {name}")
            in_block = name
            continue
        if not stripped or stripped.startswith(("#", ";")):
            continue
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError as exc:
            raise VDeckError("CONFIG_MALFORMED", f"Malformed OpenVPN directive at line {number}") from exc
        if tokens:
            yield number, tokens[0].lower().removeprefix("--"), tokens
    if in_block:
        raise VDeckError("CONFIG_MALFORMED", f"Unclosed OpenVPN inline block: {in_block}")


def parse_openvpn(path: Path) -> ParsedConfig:
    resolved = ensure_regular_file(path)
    text = _decode_text(resolved)
    directives = list(_openvpn_lines(text))
    names = {name for _, name, _ in directives}
    unsafe = names & OPENVPN_DANGEROUS
    if unsafe or names - OPENVPN_CLIENT_OPTIONS:
        raise VDeckError(
            "CONFIG_UNSAFE_DIRECTIVE", "Executable or unsupported OpenVPN directive; use a client-only profile"
        )
    if "remote" not in names:
        raise VDeckError("CONFIG_MISSING_REMOTE", "OpenVPN configuration requires at least one remote directive")

    source_dir = resolved.parent
    replacements: dict[int, str] = {}
    files: dict[str, bytes] = {}
    requires_auth = False
    requires_passphrase = "ENCRYPTED PRIVATE KEY" in text or "Proc-Type: 4,ENCRYPTED" in text
    remote_values: list[str] = []
    dns_servers: list[str] = []
    allowed_ips: list[str] = []
    used_names: set[str] = set()
    for number, name, tokens in directives:
        if name == "remote" and len(tokens) >= 2:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", tokens[1]):
                raise VDeckError("ENDPOINT_INVALID", "Invalid OpenVPN endpoint")
            remote_values.append(tokens[1])
        if name == "dhcp-option" and len(tokens) >= 3 and tokens[1].upper() == "DNS":
            try:
                dns_servers.append(str(ipaddress.ip_address(tokens[2])))
            except ValueError as exc:
                raise VDeckError("CONFIG_INVALID_DNS", "Invalid OpenVPN DNS address") from exc
        if name in {"route", "route-ipv6"}:
            try:
                network: ipaddress.IPv4Network | ipaddress.IPv6Network
                if name == "route":
                    mask = tokens[2] if len(tokens) >= 3 else "255.255.255.255"
                    network = ipaddress.IPv4Network(f"{tokens[1]}/{mask}", strict=False)
                    if len(tokens) > 3 and tokens[3] != "vpn_gateway":
                        raise ValueError("Physical gateway routes are unsupported")
                else:
                    network = ipaddress.ip_network(tokens[1], strict=False)
                    if network.version != 6 or len(tokens) > 2:
                        raise ValueError("Only tunnel IPv6 routes are supported")
                allowed_ips.append(str(network))
            except (ValueError, IndexError) as exc:
                raise VDeckError("CONFIG_INVALID_ROUTE", "Unsupported OpenVPN route; use a tunnel destination") from exc
        if name == "redirect-gateway":
            if "!ipv4" not in tokens[1:]:
                allowed_ips.append("0.0.0.0/0")
            if any(token.lower() == "ipv6" for token in tokens[1:]):
                allowed_ips.append("::/0")
        if name == "auth-user-pass":
            requires_auth = True
            replacements[number] = "auth-user-pass"
            continue
        if name not in OPENVPN_EXTERNAL or len(tokens) < 2 or tokens[1].startswith("[[INLINE]]"):
            continue
        dependency = ensure_regular_file(resolve_import_dependency(source_dir, tokens[1]))
        base = re.sub(r"[^A-Za-z0-9._-]+", "_", dependency.name).lstrip(".") or "file"
        candidate = base
        suffix = 1
        while candidate.lower() in used_names:
            suffix += 1
            candidate = f"{Path(base).stem}-{suffix}{Path(base).suffix}"
        used_names.add(candidate.lower())
        data = dependency.read_bytes()
        files[candidate] = data
        replacements[number] = shlex.join([name, f"files/{candidate}", *tokens[2:]])
        if name == "key" and (b"ENCRYPTED PRIVATE KEY" in data or b"Proc-Type: 4,ENCRYPTED" in data):
            requires_passphrase = True

    rendered: list[str] = []
    for number, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        rendered.append(replacements.get(number, raw))
    return ParsedConfig(
        protocol=Protocol.OPENVPN.value,
        runtime_config="\n".join(rendered).strip() + "\n",
        source_format=".ovpn",
        endpoints=list(dict.fromkeys(remote_values)),
        dns_servers=list(dict.fromkeys(dns_servers)),
        allowed_ips=list(dict.fromkeys(allowed_ips)),
        files=files,
        requires_username_password=requires_auth,
        requires_key_passphrase=requires_passphrase,
    )


def parse_config(protocol: Protocol, path: Path) -> ParsedConfig:
    suffix = path.suffix.lower()
    if protocol == Protocol.OPENVPN:
        if suffix != ".ovpn":
            raise VDeckError("CONFIG_EXTENSION", "OpenVPN requires an .ovpn file")
        return parse_openvpn(path)
    if protocol == Protocol.AMNEZIAWG and suffix == ".vpn":
        return parse_amnezia_vpn(_decode_text(path))
    if suffix != ".conf":
        raise VDeckError("CONFIG_EXTENSION", "This protocol requires a .conf file")
    return parse_wireguard_text(_decode_text(path), protocol)
