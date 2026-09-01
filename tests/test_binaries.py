from __future__ import annotations

import json
import unittest
from pathlib import Path

from vdeck.binaries import HASHES, BinaryManager

PROJECT = Path(__file__).resolve().parents[1]


class BundledBinaryTests(unittest.TestCase):
    def test_runtime_integrity_manifest_matches_release_manifest(self):
        versions = json.loads((PROJECT / "backend" / "versions.json").read_text(encoding="utf-8"))
        expected = {name: details["binary_sha256"] for name, details in versions["components"].items()}
        self.assertEqual(HASHES, expected)
        BinaryManager(PROJECT / "bin").prepare()


if __name__ == "__main__":
    unittest.main()
