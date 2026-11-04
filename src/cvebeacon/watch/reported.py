"""Client-report marks: validation, identity defaults and display text."""

from __future__ import annotations

import getpass
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone

from ..errors import ConfigurationError
from .records import ReportedMark

BY_LIMIT = 100
NOTE_LIMIT = 500
# Not a valid rule name: rule names must start with a letter or digit, and the
# parser reserves every ``@``-prefixed name for internal notice events.
NOTICE_RULE = "@reported"
NOTICE_KINDS = ("reported", "unreported")
NOTICE_LABELS = {"reported": "[REPORTED]", "unreported": "[UNREPORTED]"}
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


@dataclass(frozen=True, slots=True)
class ReportedEntry:
    """One row of the append-only report audit trail."""

    id: int
    cve_id: str
    action: str
    by: str
    note: str | None
    at: str


@dataclass(frozen=True, slots=True)
class NoticeDelivery:
    """The delivery state of one report or unreport notice."""

    channel: str
    status: str
    attempts: int
    last_error: str | None = None


def normalize_cve_id(value: object) -> str:
    from ..sources.common import cve_id as source_cve_id

    identifier = source_cve_id(value)
    if identifier is None:
        raise ConfigurationError("CVE id must look like CVE-2026-1234")
    return identifier


def _checked_text(value: object, label: str) -> str:
    """Reject controls, line boundaries and invalid Unicode before trimming.

    The error never includes the supplied value, so a terminal control or a
    surrogate cannot reach logs or the audit trail.
    """
    text = str(value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ConfigurationError(
            f"{label} must not contain control characters, line breaks, "
            "or invalid UTF-8"
        ) from None
    if any(
        unicodedata.category(character) in _FORBIDDEN_CATEGORIES
        for character in text
    ):
        raise ConfigurationError(
            f"{label} must not contain control characters, line breaks, "
            "or invalid UTF-8"
        )
    return text


def default_identity() -> str:
    """Return the OS login name, or ``unknown`` when it cannot be used safely."""
    try:
        name = getpass.getuser()
    except (OSError, KeyError, ImportError):
        return "unknown"
    try:
        text = _checked_text(name, "OS login name").strip(" ")
    except ConfigurationError:
        return "unknown"
    if not text or len(text) > BY_LIMIT:
        return "unknown"
    return text


def validate_identity(value: object) -> str:
    if value is None:
        raise ConfigurationError("reported by is required")
    text = _checked_text(value, "reported by").strip(" ")
    if not text:
        raise ConfigurationError("reported by must not be empty")
    if len(text) > BY_LIMIT:
        raise ConfigurationError(
            f"reported by must be at most {BY_LIMIT} characters"
        )
    return text


def validate_note(value: object | None) -> str | None:
    if value is None:
        return None
    text = _checked_text(value, "note").strip(" ")
    if not text:
        return None
    if len(text) > NOTE_LIMIT:
        raise ConfigurationError(f"note must be at most {NOTE_LIMIT} characters")
    return text


def format_timestamp(value: str | None) -> str:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return str(value or "")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def format_reported(mark: ReportedMark) -> str:
    """The single display form used by events, messages and status output."""
    return f"Reported to clients by {mark.by} at {format_timestamp(mark.at)}"
