"""Stable error codes shared by the backend and UI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class VDeckError(Exception):
    code: str
    message: str
    details: str = ""

    def __str__(self) -> str:
        return self.message

    def response(self, **extra: Any) -> dict[str, Any]:
        return {
            "success": False,
            "code": self.code,
            "message": self.message,
            **extra,
        }


def ok(**data: Any) -> dict[str, Any]:
    return {"success": True, "code": "OK", **data}
