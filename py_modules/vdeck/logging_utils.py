"""Bounded, sanitized technical logging and error history."""

from __future__ import annotations

import logging
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .atomic import atomic_write_json, read_json
from .errors import VDeckError
from .security import sanitize, secure_mkdir


def safe_exception_details(exc: BaseException) -> str:
    """Trace locations/types, never locals, source lines or arbitrary messages.

    ValueError may contain an entire config, a naked key, or a password. A
    regex scrub of traceback.format_exc() cannot reliably make that safe.
    """
    parts = ["Traceback (sanitized; values and source lines withheld):"]
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(seen) < 5:
        seen.add(id(current))
        for frame, line in traceback.walk_tb(current.__traceback__):
            parts.append(f"  {Path(frame.f_code.co_filename).name}:{line} in {frame.f_code.co_name}")
        parts.append(type(current).__name__)
        if isinstance(current, VDeckError):
            parts.append(f"code={current.code} details={sanitize(current.details)}")
        elif isinstance(current, OSError):
            parts.append(f"errno={current.errno}")
        current = current.__cause__ or (None if current.__suppress_context__ else current.__context__)
    return "\n".join(parts)[-6000:]


class SanitizingFormatter(logging.Formatter):
    def formatException(self, ei: tuple[type[BaseException], BaseException, object] | tuple[None, None, None]) -> str:
        return safe_exception_details(ei[1]) if ei[1] is not None else ""

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
