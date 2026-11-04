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


def row_id(row: Mapping[str, object]) -> int:
    """Return a safe row identifier without hydrating untrusted fields.

    ``-1`` means the row id itself is unreadable.
    """
    try:
        value = row["id"]
    except (KeyError, TypeError):
        return -1
    return value if isinstance(value, int) and not isinstance(value, bool) else -1


def verify_chain(
    rows: Iterable[Mapping[str, object]], fields: Sequence[str]
) -> int | None:
    """Return the first broken row id, or ``None`` when the chain is valid.

    Invalid stored types and canonicalisation failures count as damage; they
    must never escape as a traceback from an integrity check.
    """
    previous = ""
    for row in rows:
        try:
            values = {field: row[field] for field in fields}
            expected = chain_hash(previous, values)
            stored = row["chain"]
        except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
            return row_id(row)
        if not chain_matches(expected, stored):
            return row_id(row)
        previous = expected
    return None
