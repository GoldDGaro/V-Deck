"""Allowlisted frontend import telemetry; no form, config or exception text."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

EVENTS = frozenset(
    {
        "import UI mounted",
        "import UI unmounted",
        "protocol selected",
        "file selected",
        "validate_import started",
        "validate_import succeeded",
        "validate_import failed",
        "file picker cancelled",
        "import form rendered",
        "import button pressed",
        "importSelected entered",
        "import blocked",
        "RPC import_connection starting",
        "RPC import_connection returned success",
        "RPC import_connection returned failure",
        "refresh after import started",
        "fresh snapshot",
        "import failed",
        "import completed",
        "toast failed",
    }
)
ENUM_FIELDS = {
    "protocol": {"amneziawg", "wireguard", "openvpn"},
    "stage": {"validation", "preflight", "rpc", "refresh", "complete"},
    "errorKind": {
        "TypeError",
        "RangeError",
        "Error",
        "string",
        "object",
        "undefined",
        "number",
        "boolean",
        "symbol",
        "function",
        "bigint",
    },
}
BOOL_FIELDS = {"filePathPresent", "namePresent", "validationPresent", "busy", "rpcStarted"}


def log_import_event(logger: logging.Logger, event: str, details: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, str) or event not in EVENTS or not isinstance(details, dict):
        return {"success": False, "code": "IMPORT_LOG_EVENT_INVALID"}
    safe: dict[str, str | int | bool] = {}
    for key, allowed in ENUM_FIELDS.items():
        value = details.get(key)
        if isinstance(value, str) and value in allowed:
            safe[key] = value
    for key in BOOL_FIELDS:
        if isinstance(details.get(key), bool):
            safe[key] = details[key]
    for key in ("sequence", "connections"):
        value = details.get(key)
        if type(value) is int and 0 <= value <= 2**53 - 1:
            safe[key] = value
    code = details.get("code")
    if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
        safe["code"] = code
    summary = (
        f"fresh snapshot contains {safe.get('connections', 0)} connections" if event == "fresh snapshot" else event
    )
    logger.info("frontend import: %s %s", summary, json.dumps(safe, sort_keys=True))
    return {"success": True, "code": "OK"}
