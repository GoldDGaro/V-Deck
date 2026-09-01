#!/usr/bin/env python3
"""Fetch exact upstream trees needed for corresponding-source packaging."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
SOURCES = {
    "amneziawg-go": "https://github.com/amnezia-vpn/amneziawg-go.git",
    "amneziawg-tools": "https://github.com/amnezia-vpn/amneziawg-tools.git",
    "wireguard-go": "https://git.zx2c4.com/wireguard-go",
    "wireguard-tools": "https://git.zx2c4.com/wireguard-tools",
    "openvpn": "https://github.com/OpenVPN/openvpn.git",
    "wolfssl": "https://github.com/wolfSSL/wolfssl.git",
}


def run(arguments: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(arguments, cwd=cwd, check=True, text=True, capture_output=True)
    return completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, default=PROJECT.parent / "research")
    arguments = parser.parse_args()
    versions = json.loads((PROJECT / "backend" / "versions.json").read_text(encoding="utf-8"))
    arguments.destination.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        component = versions["sources"][name]
        target = arguments.destination / name
        if not target.exists():
            run(["git", "clone", "--depth", "1", "--branch", component["tag"], url, str(target)])
        actual = run(["git", "rev-parse", "HEAD"], cwd=target)
        if actual != component["commit"]:
            raise SystemExit(f"{name}: expected {component['commit']}, found {actual}")
        print(f"OK {name} {component['tag']} {actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
