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


def verify_chain(
    rows: Iterable[Mapping[str, object]], fields: Sequence[str]
) -> Mapping[str, object] | None:
    """Return the first row whose stored chain does not recompute."""
    previous = ""
    for row in rows:
        values = {field: row[field] for field in fields}
        expected = chain_hash(previous, values)
        stored = row["chain"]
        try:
            valid = isinstance(stored, str) and hmac.compare_digest(
                expected.encode("utf-8"), stored.encode("utf-8")
            )
        except UnicodeEncodeError:
            valid = False
        if not valid:
            return row
        previous = expected
    return None
