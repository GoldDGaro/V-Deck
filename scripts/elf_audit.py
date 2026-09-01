#!/usr/bin/env python3
"""Small dependency-free ELF64/x86-64 static-link auditor."""

from __future__ import annotations

import argparse
import glob
import struct
import sys
from pathlib import Path


class ElfError(ValueError):
    pass


def _unpack(fmt: str, data: bytes, offset: int) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ElfError("truncated ELF structure")
    return struct.unpack_from(fmt, data, offset)


def audit(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise ElfError("expected ELF64 little-endian")
    header = _unpack("<HHIQQQIHHHHHH", data, 16)
    elf_type, machine = header[0], header[1]
    if machine != 62:
        raise ElfError(f"expected x86-64 machine 62, got {machine}")
    if elf_type not in {2, 3}:
        raise ElfError(f"unexpected ELF type {elf_type}")

    program_offset, program_entry_size, program_count = header[4], header[8], header[9]
    program_types: list[int] = []
    for index in range(program_count):
        entry = _unpack("<IIQQQQQQ", data, program_offset + index * program_entry_size)
        program_types.append(entry[0])
    if 3 in program_types:
        raise ElfError("PT_INTERP is present; binary is dynamically loaded")

    section_offset, section_entry_size, section_count = header[5], header[10], header[11]
    sections: list[tuple[int, ...]] = []
    for index in range(section_count):
        sections.append(_unpack("<IIQQQQIIQQ", data, section_offset + index * section_entry_size))
    needed: list[str] = []
    for section in sections:
        if section[1] != 6:  # SHT_DYNAMIC
            continue
        linked_index = section[6]
        if linked_index >= len(sections):
            raise ElfError("dynamic string-table link is invalid")
        string_section = sections[linked_index]
        strings = data[string_section[4] : string_section[4] + string_section[5]]
        entry_size = section[9] or 16
        for offset in range(section[4], section[4] + section[5], entry_size):
            tag, value = _unpack("<QQ", data, offset)
            if tag == 0:
                break
            if tag == 1:
                end = strings.find(b"\0", value)
                if end < 0:
                    raise ElfError("unterminated DT_NEEDED name")
                needed.append(strings[value:end].decode("ascii", errors="replace"))
    if needed:
        raise ElfError(f"DT_NEEDED entries present: {', '.join(needed)}")
    return {"path": str(path), "size": len(data), "machine": "x86_64", "static": True}


def _expand(values: list[str]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        matches = glob.glob(value)
        paths.extend(Path(item) for item in (matches or [value]))
    return paths


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+")
    arguments = parser.parse_args()
    failed = False
    for path in _expand(arguments.paths):
        try:
            result = audit(path)
            print(f"OK {result['path']} x86_64 static {result['size']} bytes")
        except (OSError, ElfError) as exc:
            failed = True
            print(f"FAIL {path}: {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
