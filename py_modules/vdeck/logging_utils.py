"""Bounded, sanitized technical logging and error history."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .atomic import atomic_write_json, read_json
from .security import sanitize, secure_mkdir


class SanitizingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return sanitize(super().format(record))


def create_logger(log_dir: Path) -> logging.Logger:
    secure_mkdir(log_dir)
    logger = logging.getLogger(f"vdeck.{log_dir}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = RotatingFileHandler(log_dir / "vdeck.log", maxBytes=512 * 1024, backupCount=3, encoding="utf-8")
        handler.setFormatter(SanitizingFormatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    return logger


class ErrorHistory:
    def __init__(self, path: Path, limit: int = 50):
        self.path = path
        self.limit = limit

    def append(self, entry: dict[str, object]) -> None:
        history = self.list()
        history.append({key: sanitize(value) for key, value in entry.items()})
        atomic_write_json(self.path, history[-self.limit :])

    def list(self) -> list[dict[str, str]]:
        value = read_json(self.path, [])
        return value if isinstance(value, list) else []
