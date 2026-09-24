"""Bounded, sanitized technical logging and error history."""

from __future__ import annotations

import logging
import os
import re
import sys
import traceback
from contextlib import suppress
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

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


def daily_log_path(log_dir: Path) -> Path:
    return log_dir / f"vdeck-{date.today().isoformat()}.log"


class DailyLogHandler(logging.FileHandler):
    """One append-only file per local calendar day, including across restarts.

    Retain today and the previous two dates. Only recognized plugin log files
    are eligible for deletion; never follow symlinks or recurse into folders.
    """

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir.resolve()
        self.day = date.today()
        self.prune()
        super().__init__(daily_log_path(self.log_dir), mode="a", encoding="utf-8", delay=True)

    def prune(self) -> None:
        cutoff = date.today() - timedelta(days=2)
        for path in self.log_dir.iterdir():
            if path.is_symlink() or not path.is_file():
                continue
            match = re.fullmatch(r"vdeck-(\d{4}-\d{2}-\d{2})\.log", path.name)
            try:
                if match:
                    logged_day = date.fromisoformat(match[1])
                elif re.fullmatch(
                    r"(?:vdeck|[0-9a-f-]{36}|\d{4}-\d{2}-\d{2} \d{2}\.\d{2}\.\d{2})\.log(?:\.\d+)?",
                    path.name,
                ):
                    logged_day = datetime.fromtimestamp(path.stat().st_mtime).date()
                else:
                    continue
                if logged_day < cutoff:
                    path.unlink()
            except (OSError, ValueError):
                # Failure to remove an old log must not stop VPN cleanup.
                continue

    def _open(self) -> Any:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        if Path(self.baseFilename).is_symlink():
            raise OSError("Refusing symlink log file")
        fd = os.open(self.baseFilename, flags, 0o600)
        fchmod = getattr(os, "fchmod", None)
        if fchmod is not None:
            fchmod(fd, 0o600)
        return os.fdopen(fd, "a", encoding="utf-8")

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if date.today() != self.day:
                if self.stream:
                    self.stream.close()
                    self.stream = None  # type: ignore[assignment]
                self.day = date.today()
                self.prune()
                self.baseFilename = str(daily_log_path(self.log_dir))
            super().emit(record)
        except (OSError, ValueError):
            self.handleError(record)

    def handleError(self, record: logging.LogRecord) -> None:
        # logging's default handler prints raw msg/args on failure, potentially
        # bypassing the sanitizer. Never let disk failure prevent VPN cleanup.
        with suppress(OSError, ValueError):
            sys.stderr.write("V-Deck LOG_WRITE_FAILED: daily technical log unavailable\n")


def create_logger(log_dir: Path) -> logging.Logger:
    secure_mkdir(log_dir)
    logger = logging.getLogger(f"vdeck.{log_dir}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = DailyLogHandler(log_dir)
        handler.setFormatter(SanitizingFormatter("%(asctime)s %(levelname)s pid=%(process)d %(message)s"))
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
