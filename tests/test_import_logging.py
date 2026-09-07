from __future__ import annotations

import ast
import logging
import unittest
from pathlib import Path

from vdeck.import_logging import log_import_event


class ImportLoggingTests(unittest.TestCase):
    def test_safe_frontend_events_reach_log_without_form_or_error_text(self):
        logger = logging.getLogger("vdeck-test-import-logging")
        with self.assertLogs(logger, level="INFO") as captured:
            response = log_import_event(
                logger,
                "importSelected entered",
                {
                    "protocol": "amneziawg",
                    "filePathPresent": True,
                    "namePresent": True,
                    "busy": False,
                    "rpcStarted": False,
                    "sequence": 3,
                    "stage": "preflight",
                    "errorKind": "TypeError",
                    "code": "IMPORT_FRONTEND_FAILED",
                    "password": "secret-password",
                    "config": "PrivateKey=secret-key",
                    "message": "PresharedKey=secret-key",
                    "stack": "secret-stack",
                    "name": "secret-name",
                },
            )
        self.assertTrue(response["success"])
        output = "\n".join(captured.output)
        for expected in ("importSelected entered", "amneziawg", '"rpcStarted": false', "IMPORT_FRONTEND_FAILED"):
            self.assertIn(expected, output)
        for forbidden in ("secret-", "password", "PrivateKey", "PresharedKey", "stack"):
            self.assertNotIn(forbidden, output)

    def test_invalid_event_rejected_and_invalid_field_values_ignored(self):
        logger = logging.getLogger("vdeck-test-import-logging")
        with self.assertNoLogs(logger, level="INFO"):
            self.assertFalse(log_import_event(logger, "PrivateKey=secret", {})["success"])
        with self.assertLogs(logger, level="INFO") as captured:
            log_import_event(
                logger,
                "fresh snapshot",
                {
                    "connections": 1,
                    "protocol": "secret",
                    "busy": "secret",
                    "code": "secret\ntext",
                    "errorKind": ["secret"],
                    "stage": "secret",
                    "sequence": -1,
                },
            )
        self.assertIn("fresh snapshot contains 1 connections", captured.output[0])
        self.assertNotIn("secret", captured.output[0])

    def test_decky_rpc_positional_contract(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8"))
        plugin = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Plugin")
        methods = {node.name: node for node in plugin.body if isinstance(node, ast.AsyncFunctionDef)}
        self.assertEqual(
            [arg.arg for arg in methods["import_connection"].args.args][1:],
            ["protocol", "path", "display_name", "username", "password", "passphrase"],
        )
        self.assertEqual([arg.arg for arg in methods["log_import_event"].args.args][1:], ["event", "details"])


if __name__ == "__main__":
    unittest.main()
