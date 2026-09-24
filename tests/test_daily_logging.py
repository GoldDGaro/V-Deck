from __future__ import annotations

import io
import os
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from vdeck.logging_utils import create_logger


class DailyLoggingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = patch("vdeck.logging_utils.date")
        self.day = self.clock.start()
        self.day.today.return_value = date(2026, 9, 21)
        self.day.fromisoformat.side_effect = date.fromisoformat
        self.logger = None

    def tearDown(self):
        if self.logger:
            for handler in list(self.logger.handlers):
                handler.close()
                self.logger.removeHandler(handler)
        self.clock.stop()
        self.temp.cleanup()

    def test_append_and_restart_same_file(self):
        self.logger = create_logger(self.root)
        self.logger.info("first")
        for handler in list(self.logger.handlers):
            handler.close()
            self.logger.removeHandler(handler)
        self.logger = create_logger(self.root)
        self.logger.info("second")
        self.assertEqual(len(list(self.root.iterdir())), 1)
        text = (self.root / "vdeck-2026-09-21.log").read_text()
        self.assertIn("first", text)
        self.assertIn("second", text)

    def test_midnight_rollover_prunes_before_opening_new_day(self):
        for day in (18, 19, 20):
            (self.root / f"vdeck-2026-09-{day}.log").write_text("previous")
        self.logger = create_logger(self.root)
        self.logger.info("day21")
        self.assertFalse((self.root / "vdeck-2026-09-18.log").exists())
        self.day.today.return_value = date(2026, 9, 22)
        self.logger.info("day22")
        self.assertEqual(
            {p.name for p in self.root.iterdir()},
            {"vdeck-2026-09-20.log", "vdeck-2026-09-21.log", "vdeck-2026-09-22.log"},
        )
        self.assertNotIn("day22", (self.root / "vdeck-2026-09-21.log").read_text())

    def test_only_old_recognized_logs_removed(self):
        for name in ("vdeck.log.1", "2026-09-01 10.20.30.log", "keep.json", "other.log"):
            path = self.root / name
            path.write_text("old")
            os.utime(path, (1, 1))
        self.logger = create_logger(self.root)
        self.logger.info("current")
        self.assertFalse((self.root / "vdeck.log.1").exists())
        self.assertFalse((self.root / "2026-09-01 10.20.30.log").exists())
        self.assertTrue((self.root / "keep.json").exists())
        self.assertTrue((self.root / "other.log").exists())

    def test_secrets_and_exception_source_not_logged(self):
        self.logger = create_logger(self.root)
        try:
            raise ValueError("naked-secret")
        except ValueError:
            self.logger.exception("PrivateKey=secret")
        text = (self.root / "vdeck-2026-09-21.log").read_text()
        self.assertNotIn("naked-secret", text)
        self.assertNotIn("=secret", text)
        self.assertIn("ValueError", text)

    def test_handler_is_not_duplicated(self):
        self.logger = create_logger(self.root)
        self.assertIs(self.logger, create_logger(self.root))
        self.assertEqual(len(self.logger.handlers), 1)

    def test_disk_failure_does_not_raise_or_print_secret_record(self):
        self.logger = create_logger(self.root)
        stderr = io.StringIO()
        with patch.object(self.logger.handlers[0], "_open", side_effect=PermissionError), patch("sys.stderr", stderr):
            self.logger.error("PrivateKey=never-print-this")
        self.assertIn("LOG_WRITE_FAILED", stderr.getvalue())
        self.assertNotIn("never-print-this", stderr.getvalue())

    @unittest.skipIf(os.name == "nt", "Linux filesystem security")
    def test_symlinks_untouched_and_new_file_private(self):
        target = self.root / "keep"
        target.write_text("keep")
        (self.root / "vdeck-2026-09-01.log").symlink_to(target)
        self.logger = create_logger(self.root)
        self.logger.info("private")
        self.assertTrue((self.root / "vdeck-2026-09-01.log").is_symlink())
        self.assertEqual((self.root / "vdeck-2026-09-21.log").stat().st_mode & 0o777, 0o600)
