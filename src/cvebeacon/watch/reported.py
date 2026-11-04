"""Client-report marks: validation, identity defaults and display text."""

from __future__ import annotations

import getpass
import os
import socket
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone

from ..errors import ConfigurationError
from .catalog import DEFAULT_LANGUAGE, catalog_for, translate
from .records import ReportedMark

BY_LIMIT = 100
NOTE_LIMIT = 500
OS_ACCOUNT_LIMIT = 100
HOST_LIMIT = 255
IDENTITY_MODES = ("open", "registered", "authenticated")
# Not a valid rule name: rule names must start with a letter or digit, and the
# parser reserves every ``@``-prefixed name for internal notice events.
NOTICE_RULE = "@reported"
NOTICE_KINDS = ("reported", "unreported")
NOTICE_LABEL_KEYS = {
    "reported": "label_reported",
    "unreported": "label_unreported",
}
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
REPORT_CHAIN_FIELDS = (
    "id",
    "cve_id",
    "action",
    "by",
    "user_id",
    "username",
    "identity_mode",
    "os_account",
    "host",
    "note",
    "at",
)


@dataclass(frozen=True, slots=True)
class ReportedEntry:
    """One row of the append-only report audit trail."""

    id: int
    cve_id: str
    action: str
    by: str
    note: str | None
    at: str
    user_id: int | None = None
    username: str | None = None
    identity_mode: str | None = None
    os_account: str | None = None
    host: str | None = None
    chain: str | None = None
    chain_version: int = 1

    @property
    def legacy(self) -> bool:
        return self.chain_version == 0


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


def checked_text(value: object, label: str) -> str:
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


def safe_environment_text(value: object, limit: int) -> str:
    """Return a bounded single-line environment value or ``unknown``."""
    try:
        text = checked_text(value, "environment value").strip(" ")
    except ConfigurationError:
        return "unknown"
    if not text:
        return "unknown"
    return text[:limit]


def os_account() -> str:
    """The operating-system account, informational only and never trusted."""
    if os.name == "nt":
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(257)
            size = ctypes.c_ulong(257)
            if ctypes.windll.secur32.GetUserNameExW(2, buffer, ctypes.byref(size)):
                return safe_environment_text(buffer.value, OS_ACCOUNT_LIMIT)
        except (AttributeError, OSError, ValueError):
            pass
    else:
        try:
            import pwd

            return safe_environment_text(
                pwd.getpwuid(os.getuid()).pw_name, OS_ACCOUNT_LIMIT
            )
        except (ImportError, KeyError, OSError):
            pass
    try:
        return safe_environment_text(getpass.getuser(), OS_ACCOUNT_LIMIT)
    except (OSError, KeyError, ImportError):
        return "unknown"


def host_name() -> str:
    try:
        return safe_environment_text(socket.gethostname(), HOST_LIMIT)
    except OSError:
        return "unknown"


def validate_identity_mode(value: object) -> str:
    text = str(value).strip().casefold()
    if text not in IDENTITY_MODES:
        raise ConfigurationError(
            "watch.reporting.identity must be open, registered, or authenticated"
        )
    return text


def identity_label(by: str, username: str | None = None) -> str:
    if username and username.casefold() != by.casefold():
        return f"{by} ({username})"
    return by


def default_identity() -> str:
    """Return the OS login name, or ``unknown`` when it cannot be used safely."""
    try:
        name = getpass.getuser()
    except (OSError, KeyError, ImportError):
        return "unknown"
    try:
        text = checked_text(name, "OS login name").strip(" ")
    except ConfigurationError:
        return "unknown"
    if not text or len(text) > BY_LIMIT:
        return "unknown"
    return text


def validate_identity(value: object) -> str:
    if value is None:
        raise ConfigurationError("reported by is required")
    text = checked_text(value, "reported by").strip(" ")
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
    text = checked_text(value, "note").strip(" ")
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


def format_reported(
    mark: ReportedMark, language: str = DEFAULT_LANGUAGE
) -> str:
    """The single display form used by events, messages and status output."""
    return translate(
        catalog_for(language),
        "reported_line",
        by=identity_label(mark.by, mark.username),
        at=format_timestamp(mark.at),
    )
