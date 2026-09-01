from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from vdeck.service import VDeckService

PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT / "tests" / "fixtures"


class ImportFlowTests(unittest.IsolatedAsyncioTestCase):
    async def _exercise(self, protocol: str, fixture_name: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / fixture_name
            selected.write_bytes((FIXTURES / fixture_name).read_bytes())
            service = VDeckService(
                root / "settings",
                PROJECT,
                root / "legacy",
                root / "runtime",
                root / "logs",
            )
            try:
                validated = await service.validate_import(protocol, str(selected), str(selected.resolve()))
                self.assertTrue(validated["success"])
                self.assertEqual(Path(validated["path"]), selected.resolve())

                imported = await service.import_connection(
                    protocol,
                    validated["path"],
                    f"E2E {protocol}",
                )
                self.assertTrue(imported["success"])
                self.assertEqual(imported["connections_count"], 1)

                snapshot = await service.get_snapshot()
                self.assertTrue(snapshot["success"])
                self.assertEqual(len(snapshot["connections"]), 1)
                connection = snapshot["connections"][0]
                self.assertEqual(connection["protocol"], protocol)
                self.assertEqual(connection["display_name"], f"E2E {protocol}")

                connection_dir = service.store.connection_dir(connection["id"])
                for name in ("metadata.json", "runtime-info.json", "config"):
                    self.assertTrue((connection_dir / name).is_file(), name)
                metadata = json.loads((connection_dir / "metadata.json").read_text(encoding="utf-8"))
                self.assertEqual(metadata["protocol"], protocol)
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(connection_dir.stat().st_mode), 0o700)
                    self.assertEqual(stat.S_IMODE((connection_dir / "config").stat().st_mode), 0o600)

                for handler in service.logger.handlers:
                    handler.flush()
                technical_log = (root / "logs" / "vdeck.log").read_text(encoding="utf-8")
                for event in (
                    "file selected",
                    "protocol selected",
                    "validate_import started",
                    "validate_import succeeded",
                    "import_connection started",
                    "parser succeeded",
                    "storage stage created",
                    "connection committed",
                    "snapshot contains 1 connections",
                ):
                    self.assertIn(event, technical_log)
                self.assertNotIn("PrivateKey =", technical_log)
                self.assertNotIn("PresharedKey =", technical_log)
            finally:
                for handler in list(service.logger.handlers):
                    service.logger.removeHandler(handler)
                    handler.close()

    async def test_wireguard_full_import_flow(self):
        await self._exercise("wireguard", "wireguard.conf")

    async def test_amneziawg_full_import_flow(self):
        await self._exercise("amneziawg", "awg31.conf")

    async def test_realpath_directory_falls_back_to_selected_file_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / "wireguard.conf"
            selected.write_bytes((FIXTURES / "wireguard.conf").read_bytes())
            service = VDeckService(root / "settings", PROJECT, root / "legacy", logs_root=root / "logs")
            try:
                response = await service.validate_import("wireguard", str(selected), str(root))
                self.assertTrue(response["success"])
                self.assertEqual(Path(response["path"]), selected.resolve())
            finally:
                for handler in list(service.logger.handlers):
                    service.logger.removeHandler(handler)
                    handler.close()

    async def test_directory_selection_has_explicit_accessibility_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = VDeckService(root / "settings", PROJECT, root / "legacy", logs_root=root / "logs")
            try:
                response = await service.validate_import("wireguard", str(root), str(root))
                self.assertFalse(response["success"])
                self.assertEqual(response["code"], "CONFIG_FILE_NOT_ACCESSIBLE")
            finally:
                for handler in list(service.logger.handlers):
                    service.logger.removeHandler(handler)
                    handler.close()


class DeckyManifestTests(unittest.TestCase):
    def test_vdeck_requests_the_actual_decky_root_flag(self):
        plugin = json.loads((PROJECT / "plugin.json").read_text(encoding="utf-8"))
        self.assertIn("root", plugin["flags"])
        self.assertNotIn("_root", plugin["flags"])


if __name__ == "__main__":
    unittest.main()
