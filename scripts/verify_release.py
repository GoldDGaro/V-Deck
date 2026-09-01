#!/usr/bin/env python3
"""Verify V-Deck release structure, native hashes, ELF linkage, and secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from elf_audit import ElfError, audit

REQUIRED = {
    "V-Deck/main.py",
    "V-Deck/plugin.json",
    "V-Deck/package.json",
    "V-Deck/dist/index.js",
    "V-Deck/LICENSE",
    "V-Deck/README.md",
    "V-Deck/SECURITY.md",
    "V-Deck/SOURCE_OFFER.md",
    "V-Deck/THIRD_PARTY_NOTICES.md",
    "V-Deck/backend/versions.json",
    "V-Deck/bin/amneziawg-go",
    "V-Deck/bin/awg",
    "V-Deck/bin/wireguard-go",
    "V-Deck/bin/wg",
    "V-Deck/bin/openvpn",
}
NATIVE = ("amneziawg-go", "awg", "wireguard-go", "wg", "openvpn")
FORBIDDEN_PARTS = {".git", "node_modules", "tests", "__pycache__", ".mypy_cache", ".ruff_cache"}
SECRET_PATTERNS = {
    "WireGuard private key": re.compile(rb"(?im)^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=\s*$"),
    "password assignment": re.compile(rb'(?i)["\'](?:password|passphrase)["\']\s*:\s*["\'][^"\']{4,}["\']'),
    "private PEM material": re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{40,}", re.I
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    versions = json.loads((project / "backend" / "versions.json").read_text(encoding="utf-8"))
    errors: list[str] = []
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            errors.append("duplicate ZIP entries")
        for name in names:
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != "V-Deck":
                errors.append(f"unsafe or unexpected root: {name}")
            if any(part in FORBIDDEN_PARTS for part in pure.parts):
                errors.append(f"forbidden release content: {name}")
        errors.extend(f"missing {name}" for name in sorted(REQUIRED - set(names)))

        plugin = json.loads(archive.read("V-Deck/plugin.json"))
        package = json.loads(archive.read("V-Deck/package.json"))
        if plugin.get("name") != "V-Deck" or package.get("version") != "0.1.0":
            errors.append("plugin/package identity mismatch")
        license_text = archive.read("V-Deck/LICENSE").decode("utf-8")
        if not license_text.startswith("# Polyform Noncommercial License 1.0.0"):
            errors.append("unrecognized root license text")

        with tempfile.TemporaryDirectory(prefix="vdeck-release-") as temporary:
            root = Path(temporary)
            for native in NATIVE:
                name = f"V-Deck/bin/{native}"
                info = archive.getinfo(name)
                mode = (info.external_attr >> 16) & 0o777
                if mode != 0o755:
                    errors.append(f"{name} mode is {oct(mode)}, expected 0o755")
                data = archive.read(name)
                expected = versions["components"][native]["binary_sha256"]
                if sha256(data) != expected:
                    errors.append(f"{native} SHA256 mismatch")
                extracted = root / native
                extracted.write_bytes(data)
                try:
                    audit(extracted)
                except (OSError, ElfError) as exc:
                    errors.append(f"{native} ELF audit: {exc}")

        for info in infos:
            if info.is_dir() or info.file_size > 8 * 1024 * 1024:
                continue
            data = archive.read(info)
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(data):
                    errors.append(f"possible {label} in {info.filename}")

    if errors:
        raise SystemExit("Release verification failed:\n- " + "\n- ".join(sorted(set(errors))))
    print(f"OK {path}: structure, license, secrets, ELF, modes, and native hashes verified")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("zip", type=Path)
    arguments = parser.parse_args()
    verify(arguments.zip)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
