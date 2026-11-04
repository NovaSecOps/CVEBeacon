"""Tamper-evident hash chains for append-only audit tables."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable, Mapping, Sequence

from .records import canonical_json


def chain_hash(previous: str | None, values: Mapping[str, object]) -> str:
    """Hash one row together with the preceding row's chain value."""
    payload = (previous or "").encode("utf-8") + canonical_json(
        dict(values)
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def chain_matches(expected: str, stored: object) -> bool:
    try:
        return isinstance(stored, str) and hmac.compare_digest(
            expected.encode("utf-8"), stored.encode("utf-8")
        )
    except UnicodeEncodeError:
        return False


INVALID_TEXT = object()


def decode_text(value: bytes):
    """SQLite ``text_factory``: keep invalid UTF-8 as a sentinel, not an error."""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return INVALID_TEXT


def decoded_row(row: Mapping[str, object]) -> dict[str, object] | None:
    """Decode one row, rejecting BLOB text and invalid UTF-8."""
    values: dict[str, object] = {}
    try:
        keys = row.keys()
    except AttributeError:
        return None
    for key in keys:
        try:
            value = row[key]
        except (KeyError, IndexError):
            return None
        if isinstance(value, bytes) or value is INVALID_TEXT:
            return None
        values[key] = value
    return values


def row_id(row: Mapping[str, object]) -> int:
    """Return a safe row identifier without hydrating untrusted fields.

    ``-1`` means the row id itself is unreadable.
    """
    try:
        value = row["id"]
    except (KeyError, IndexError, TypeError):
        return -1
    return value if isinstance(value, int) and not isinstance(value, bool) else -1


def verify_chain(
    rows: Iterable[Mapping[str, object]],
    fields: Sequence[str],
    *,
    optional_fields: Sequence[str] = (),
) -> int | None:
    """Return the first broken row id, or ``None`` when the chain is valid.

    Invalid stored types, invalid UTF-8 and canonicalisation failures count as
    damage; they must never escape as a traceback from an integrity check.
    """
    previous = ""
    for original in rows:
        decoded = decoded_row(original)
        if decoded is None:
            return row_id(original)
        try:
            values = {field: decoded[field] for field in fields}
            for field in optional_fields:
                try:
                    value = decoded[field]
                except (KeyError, IndexError):
                    continue
                if value is not None:
                    values[field] = value
            expected = chain_hash(previous, values)
            stored = decoded["chain"]
        except (KeyError, IndexError, TypeError, ValueError, UnicodeError, OverflowError):
            return row_id(original)
        if not chain_matches(expected, stored):
            return row_id(original)
        previous = expected
    return None
