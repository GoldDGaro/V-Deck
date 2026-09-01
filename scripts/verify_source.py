#!/usr/bin/env python3
"""Verify the GPL corresponding-source archive is complete and well formed."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path, PurePosixPath

REPOSITORIES = {
    "amneziawg-go": "LICENSE",
    "amneziawg-tools": "COPYING",
    "wireguard-go": "LICENSE",
    "wireguard-tools": "COPYING",
    "openvpn": "COPYING",
    "wolfssl": "COPYING",
}
PROJECT_REQUIRED = {
    "V-Deck-source/V-Deck/backend/Dockerfile",
    "V-Deck-source/V-Deck/backend/README.md",
    "V-Deck-source/V-Deck/backend/versions.json",
    "V-Deck-source/V-Deck/backend/amneziawg-go-version.patch",
    "V-Deck-source/V-Deck/backend/amneziawg-tools-bundled-uapi.patch",
    "V-Deck-source/V-Deck/backend/wireguard-tools-bundled-uapi.patch",
    "V-Deck-source/V-Deck/backend/openvpn-static-cmake.patch",
    "V-Deck-source/V-Deck/backend/openvpn-static-autotools.patch",
    "V-Deck-source/V-Deck/backend/wolfssl-openvpn-cmake.patch",
    "V-Deck-source/V-Deck/pnpm-lock.yaml",
    "V-Deck-source/V-Deck/requirements-dev.txt",
    "V-Deck-source/V-Deck/SOURCE_OFFER.md",
}
FORBIDDEN_PARTS = {".git", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache"}


def verify(path: Path) -> None:
    errors: list[str] = []
    with zipfile.ZipFile(path) as archive:
        corrupt = archive.testzip()
        if corrupt:
            errors.append(f"CRC failure: {corrupt}")
        names = {info.filename for info in archive.infolist()}
        for name in names:
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != "V-Deck-source":
                errors.append(f"unsafe or unexpected root: {name}")
            if any(part in FORBIDDEN_PARTS for part in pure.parts):
                errors.append(f"forbidden source content: {name}")
        errors.extend(f"missing {name}" for name in sorted(PROJECT_REQUIRED - names))
        for repository, marker in REPOSITORIES.items():
            prefix = f"V-Deck-source/third_party_src/{repository}/"
            if not any(name.startswith(prefix) for name in names):
                errors.append(f"missing source tree {repository}")
            marker_name = prefix + marker
            if marker_name not in names:
                errors.append(f"missing source license {marker_name}")

    if errors:
        raise SystemExit("Source verification failed:\n- " + "\n- ".join(sorted(set(errors))))
    print(f"OK {path}: corresponding source, build inputs, roots, and CRCs verified")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("zip", type=Path)
    arguments = parser.parse_args()
    verify(arguments.zip)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
