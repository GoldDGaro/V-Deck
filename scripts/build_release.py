#!/usr/bin/env python3
"""Build deterministic install and complete corresponding-source ZIPs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import zipfile
from collections.abc import Iterable, Set
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
WORK = PROJECT.parent
DEFAULT_OUTPUT = WORK / "outputs"
EPOCH = (2026, 8, 31, 0, 0, 0)
NATIVE_NAMES = {"amneziawg-go", "awg", "wireguard-go", "wg", "openvpn"}
INSTALL_FILES = {
    "main.py",
    "plugin.json",
    "package.json",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "SOURCE_OFFER.md",
    "THIRD_PARTY_NOTICES.md",
    "CHANGELOG.md",
    "MANUAL_TESTS_STEAM_DECK.md",
    "USER_GUIDE_RU.md",
    "USER_GUIDE_EN.md",
    "VALIDATION.md",
    "backend/versions.json",
}
SOURCE_REPOSITORIES = (
    "amneziawg-go",
    "amneziawg-tools",
    "wireguard-go",
    "wireguard-tools",
    "openvpn",
    "wolfssl",
)
COMMON_EXCLUDED_PARTS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "outputs",
    }
)
PROJECT_SOURCE_EXCLUDED_PARTS = COMMON_EXCLUDED_PARTS | {"dist", "bin", "release", "third_party_src"}


def _iter_files(root: Path, *, excluded_parts: Set[str] = COMMON_EXCLUDED_PARTS) -> Iterable[Path]:
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().lower()):
        relative = path.relative_to(root)
        if any(part in excluded_parts for part in relative.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix in {".pyc", ".zip"}:
            continue
        if path.name == "index.js.map":
            continue
        yield path


def _write_file(archive: zipfile.ZipFile, source: Path, name: str, mode: int) -> None:
    info = zipfile.ZipInfo(name.replace("\\", "/"), EPOCH)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | mode) << 16
    archive.writestr(info, source.read_bytes(), compresslevel=9)


def _install_entries() -> Iterable[tuple[Path, str, int]]:
    for name in sorted(INSTALL_FILES):
        path = PROJECT / name
        if not path.is_file():
            raise FileNotFoundError(path)
        yield path, f"V-Deck/{name}", 0o644
    for directory in ("dist", "py_modules", "bin", "licenses"):
        root = PROJECT / directory
        if not root.is_dir():
            raise FileNotFoundError(root)
        for path in _iter_files(root):
            relative = path.relative_to(PROJECT).as_posix()
            mode = 0o755 if directory == "bin" and path.name in NATIVE_NAMES else 0o644
            yield path, f"V-Deck/{relative}", mode


def build_install(path: Path) -> None:
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        for source, name, mode in _install_entries():
            _write_file(archive, source, name, mode)


def build_source(path: Path, research: Path) -> None:
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        for source in _iter_files(PROJECT, excluded_parts=PROJECT_SOURCE_EXCLUDED_PARTS):
            relative = source.relative_to(PROJECT).as_posix()
            _write_file(archive, source, f"V-Deck-source/V-Deck/{relative}", 0o644)
        for repository in SOURCE_REPOSITORIES:
            root = research / repository
            if not root.is_dir():
                raise FileNotFoundError(
                    f"Corresponding source is missing: {root}. Fetch the pinned repositories first."
                )
            for source in _iter_files(root):
                relative = source.relative_to(root).as_posix()
                _write_file(
                    archive,
                    source,
                    f"V-Deck-source/third_party_src/{repository}/{relative}",
                    0o644,
                )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--research-dir", type=Path, default=WORK / "research")
    arguments = parser.parse_args()
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    install = arguments.output_dir / "V-Deck-v0.1.0.zip"
    source = arguments.output_dir / "V-Deck-v0.1.0-source.zip"
    build_install(install)
    build_source(source, arguments.research_dir)
    sums = arguments.output_dir / "SHA256SUMS.txt"
    sums.write_text(
        f"{_sha256(install)}  {install.name}\n{_sha256(source)}  {source.name}\n",
        encoding="utf-8",
        newline="\n",
    )
    manifest = {
        "version": "0.1.0",
        "install": install.name,
        "source": source.name,
        "install_sha256": _sha256(install),
        "source_sha256": _sha256(source),
        "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH", "2026-08-31T00:00:00Z"),
    }
    (arguments.output_dir / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
