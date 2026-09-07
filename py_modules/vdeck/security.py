"""Security primitives for untrusted imported configurations and logs."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

from .errors import VDeckError

MAX_CONFIG_BYTES = 4 * 1024 * 1024

_KEY_VALUE_SECRET = re.compile(
    r"(?im)^(\s*(?:PrivateKey|PresharedKey|HeaderProtectionKey|Password|Passphrase|auth-token|token)\s*[=:]\s*).*$"
)
_JSON_SECRET = re.compile(
    r'(?i)("(?:client_priv_key|private_key|psk_key|password|passphrase|api_key|token)"\s*:\s*)"(?:\\.|[^"\\])*"'
)
_PEM_PRIVATE = re.compile(r"(?is)-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:ENCRYPTED )?PRIVATE KEY-----")
_INLINE_KEY = re.compile(r"(?is)<key>.*?</key>")
_AUTH_BLOCK = re.compile(r"(?im)^(auth-user-pass\s+)(\S+).*$")
_INLINE_SECRET = re.compile(
    r"(?i)(\b(?:PrivateKey|PresharedKey|HeaderProtectionKey|Password|Passphrase|auth-token|token)\s*[=:]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")


def sanitize(text: object) -> str:
    value = str(text)
    value = _PEM_PRIVATE.sub("-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----", value)
    value = _INLINE_KEY.sub("<key>\n[REDACTED]\n</key>", value)
    value = _KEY_VALUE_SECRET.sub(r"\1[REDACTED]", value)
    value = _JSON_SECRET.sub(r'\1"[REDACTED]"', value)
    value = _AUTH_BLOCK.sub(r"\1[REDACTED]", value)
    value = _INLINE_SECRET.sub(r"\1[REDACTED]", value)
    return value


def sanitize_report(text: object) -> str:
    value = sanitize(text)

    def mask_ipv4(match: re.Match[str]) -> str:
        parts = match.group(0).split(".")
        if any(int(part) > 255 for part in parts):
            return match.group(0)
        return f"{parts[0]}.{parts[1]}.x.x"

    def mask_ipv6(match: re.Match[str]) -> str:
        try:
            address = ipaddress.IPv6Address(match.group(0))
        except ipaddress.AddressValueError:
            return match.group(0)
        network = ipaddress.IPv6Network(f"{address}/48", strict=False)
        return f"{network.network_address.compressed}/48"

    return _IPV6.sub(mask_ipv6, _IPV4.sub(mask_ipv4, value))


def ensure_regular_file(path: Path, *, max_bytes: int = MAX_CONFIG_BYTES) -> Path:
    try:
        if path.is_symlink() or not path.is_file():
            raise VDeckError("CONFIG_UNSAFE_PATH", "The selected path is not a regular file")
        size = path.stat().st_size
    except OSError as exc:
        raise VDeckError("CONFIG_READ_FAILED", "Unable to read the selected file", sanitize(exc)) from exc
    if size == 0:
        raise VDeckError("CONFIG_EMPTY", "The selected configuration is empty")
    if size > max_bytes:
        raise VDeckError("CONFIG_TOO_LARGE", "The selected configuration is too large")
    return path.resolve(strict=True)


def resolve_import_dependency(source_dir: Path, raw_name: str) -> Path:
    name = raw_name.strip().strip("\"'")
    candidate = Path(name)
    if not name or candidate.is_absolute() or ".." in candidate.parts:
        raise VDeckError("CONFIG_UNSAFE_PATH", f"Unsafe referenced path: {name or '[empty]'}")
    root = source_dir.resolve(strict=True)
    unresolved = root
    for part in candidate.parts:
        unresolved /= part
        if unresolved.is_symlink():
            raise VDeckError("CONFIG_UNSAFE_PATH", f"Symbolic links are not accepted during import: {name}")
    try:
        target = unresolved.resolve(strict=True)
    except FileNotFoundError as exc:
        raise VDeckError("CONFIG_MISSING_FILE", f"Required file was not found: {name}") from exc
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise VDeckError("CONFIG_UNSAFE_PATH", f"Referenced file escapes the import directory: {name}") from exc
    if not target.is_file():
        raise VDeckError("CONFIG_MISSING_FILE", f"Required file was not found: {name}")
    return target


def secure_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)


def secure_write(path: Path, data: bytes) -> None:
    if path.exists() and path.is_symlink():
        raise VDeckError("UNSAFE_STORAGE", f"Refusing to write through symlink: {path.name}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("Unable to complete secure file write")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if os.name != "nt":
        path.chmod(0o600)
