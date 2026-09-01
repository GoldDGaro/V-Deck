"""Pinned bundled executable discovery."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .errors import VDeckError

VERSIONS = {
    "amneziawg-go": "3.1.20260828",
    "awg": "3.1.20260812",
    "wireguard-go": "0.0.20250522",
    "wg": "1.0.20260223",
    "openvpn": "2.7.6",
}
HASHES = {
    "amneziawg-go": "1bcfbc0e24e431d20e284699d8a9b4acd22df8072c6731707699f7b009d65eaa",
    "awg": "3ff472d58270c938a95693e56a93961ae145ae4d2242d5adca900956707ca92d",
    "wireguard-go": "0fbe1b8f2a145b928a070b067e3c34ade18bcf85ce1b745a1536fe5ad4404cb3",
    "wg": "b6ee639f351efab943b77fd29b511c0823bd37d4a5aa9bdc27a239d884c2d348",
    "openvpn": "b8deac04bd47817a2227674f1768b0cff4d4a658eef9195b43c756639cccbd26",
}


class BinaryManager:
    def __init__(self, bin_dir: Path):
        self.bin_dir = bin_dir

    def path(self, name: str) -> Path:
        if name not in VERSIONS:
            raise VDeckError("BINARY_UNKNOWN", f"Unknown bundled executable: {name}")
        path = self.bin_dir / name
        if path.is_symlink() or not path.is_file():
            raise VDeckError("BINARY_MISSING", f"Bundled executable is missing: {name}")
        if os.name != "nt" and not os.access(path, os.X_OK):
            raise VDeckError("BINARY_NOT_EXECUTABLE", f"Bundled executable is not executable: {name}")
        return path

    def prepare(self) -> None:
        for name, expected in HASHES.items():
            path = self.bin_dir / name
            if path.is_symlink() or not path.is_file():
                raise VDeckError("BINARY_MISSING", f"Bundled executable is missing: {name}")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                raise VDeckError("BINARY_INTEGRITY_FAILED", f"Bundled executable failed integrity verification: {name}")
            if os.name != "nt":
                path.chmod(0o755)

    def command(self, name: str, *args: str) -> list[str]:
        return [str(self.path(name)), *args]

    def versions(self) -> dict[str, str]:
        return dict(VERSIONS)
