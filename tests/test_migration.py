from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vdeck.migration import MigrationManager
from vdeck.storage import VDeckStore

FIXTURES = Path(__file__).parent / "fixtures"


class MigrationTests(unittest.TestCase):
    def test_copy_only_idempotent_migration_and_failure_record(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            legacy = root / "legacy"
            legacy.mkdir()
            source = legacy / "legacy.conf"
            source.write_bytes((FIXTURES / "awg_legacy.conf").read_bytes())
            invalid = legacy / "invalid.conf"
            invalid.write_text("not a config")
            before = source.read_bytes()
            store = VDeckStore(root / "new")
            migration = MigrationManager(store, legacy)
            first = migration.run()
            second = migration.run()
            self.assertEqual(len(first["imported"]), 1)
            self.assertEqual(len(first["failed"]), 1)
            self.assertEqual(second, {"imported": [], "failed": []})
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(len(store.list()), 2)


if __name__ == "__main__":
    unittest.main()
