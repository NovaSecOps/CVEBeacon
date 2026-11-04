"""Client-report marks: validation, identity defaults and display text."""

from __future__ import annotations

import getpass
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from ..errors import ConfigurationError
from .records import ReportedMark

CVE_PATTERN = re.compile(r"^CVE-(1999|2\d{3})-\d{4,}$")
BY_LIMIT = 100
NOTE_LIMIT = 500
# Not a valid rule name, so a configured rule can never collide with it.
NOTICE_RULE = "@reported"
NOTICE_KINDS = ("reported", "unreported")
NOTICE_LABELS = {"reported": "[REPORTED]", "unreported": "[UNREPORTED]"}


@dataclass(frozen=True, slots=True)
class ReportedEntry:
    """One row of the append-only report audit trail."""

    id: int
    cve_id: str
    action: str
    by: str
    note: str | None
    at: str

    def mark(self) -> ReportedMark | None:
        if self.action != "report":
            return None
        return ReportedMark(self.cve_id, self.by, self.note, self.at)


def normalize_cve_id(value: object) -> str:
    text = str(value or "").strip().upper()
    if CVE_PATTERN.fullmatch(text) is None:
        raise ConfigurationError("CVE id must look like CVE-2026-1234")
    return text


def _has_control_characters(text: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in text)


def default_identity() -> str:
    try:
        name = getpass.getuser()
    except (OSError, KeyError, ImportError):
        return "unknown"
    text = str(name).strip()
    return text or "unknown"


def validate_identity(value: object | None) -> str:
    text = default_identity() if value is None else str(value).strip()
    if not text:
        raise ConfigurationError("reported by must not be empty")
    if len(text) > BY_LIMIT:
        raise ConfigurationError(
            f"reported by must be at most {BY_LIMIT} characters"
        )
    if _has_control_characters(text):
        raise ConfigurationError("reported by must not contain control characters")
    return text


def validate_note(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > NOTE_LIMIT:
        raise ConfigurationError(f"note must be at most {NOTE_LIMIT} characters")
    if _has_control_characters(text):
        raise ConfigurationError(
            "note must be a single line without control characters"
        )
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
