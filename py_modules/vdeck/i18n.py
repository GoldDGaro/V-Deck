"""Backend locale selection; user-facing strings remain keyed in the frontend."""

from __future__ import annotations

import locale

SUPPORTED = {"ru", "en"}


def resolve_language(setting: str, system_locale: str | None = None) -> str:
    if setting in SUPPORTED:
        return setting
    value = system_locale
    if value is None:
        value = locale.getlocale()[0] or ""
    language = value.lower().split("_", 1)[0].split("-", 1)[0]
    return language if language in SUPPORTED else "en"
