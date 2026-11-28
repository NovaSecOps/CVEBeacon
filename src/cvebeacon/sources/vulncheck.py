"""VulnCheck KEV index adapter.

The v3 index endpoint is a cursor-paginated JSON query. A page is requested
with ``limit`` and either the initial ``start_cursor`` flag or the ``cursor``
value returned in ``_meta.next_cursor``. Only a terminal page without a cursor
proves that the catalog was read completely, so a caller may infer negative
membership only from a successful full load. Pages are bounded by count, bytes
and a request budget; any truncation or inconsistency is a source error.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from ..errors import SourceError
from ..http import HttpClient
from ..models import Evidence
from .common import cve_id, source_payload

KEV_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
PAGE_SIZE = 100
MAX_PAGES = 300
MAX_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 250_000
MAX_IDS_PER_ENTRY = 100
MAX_REFERENCES = 100
MAX_REFERENCE_BYTES = 2048
MAX_TIMESTAMP_BYTES = 80

MALFORMED = "KEV index returned malformed data"
INCOMPLETE = "KEV index did not return a complete catalog"
REFLECTED = "KEV index reflected a credential in retained data"


def _malformed() -> SourceError:
    return SourceError("vulncheck", MALFORMED)


def _incomplete() -> SourceError:
    return SourceError("vulncheck", INCOMPLETE)


def _text(value: Any, *, limit: int) -> str:
    if not isinstance(value, str):
        raise _malformed()
    text = value.strip()
    if not text or len(text) > limit:
        raise _malformed()
    return text


def _timestamp(value: Any, token: str) -> str:
    text = _text(value, limit=MAX_TIMESTAMP_BYTES)
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        raise _malformed() from None
    if token and token in text:
        raise SourceError("vulncheck", REFLECTED)
    return text


def _url(value: Any, token: str) -> str:
    text = _text(value, limit=MAX_REFERENCE_BYTES)
    parsed = urlsplit(text)
    try:
        port = parsed.port
    except ValueError:
        port = -1
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or port == -1):
        raise _malformed()
    if token and token in text:
        raise SourceError("vulncheck", REFLECTED)
    return text


def _identifiers(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_IDS_PER_ENTRY:
        raise _malformed()
    output: list[str] = []
    for item in value:
        identifier = cve_id(item)
        if not identifier:
            raise _malformed()
        if identifier not in output:
            output.append(identifier)
    return output


def _ransomware(value: Any) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _malformed()
    text = value.strip().casefold()
    if text == "known":
        return True
    if text == "unknown":
        return False
    raise _malformed()


def _reference_entries(value: Any, field: str, token: str) -> list[dict[str, str | None]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _malformed()
    output: list[dict[str, str | None]] = []
    for item in value:
        if not isinstance(item, dict):
            raise _malformed()
        raw = item.get(field)
        if raw is None:
            continue
        url = _url(raw, token)
        if any(entry["url"] == url for entry in output):
            continue
        date_added = item.get("date_added")
        output.append({
            "url": url,
            "date_added": None if date_added is None else _timestamp(date_added, token),
        })
        if len(output) >= MAX_REFERENCES:
            break
    return output


def _meta(
    payload: Any,
    *,
    expected_limit: int,
    token: str,
) -> tuple[list[Any], int | None, str | None]:
    if not isinstance(payload, dict):
        raise _malformed()
    data, meta = payload.get("data"), payload.get("_meta")
    if not isinstance(data, list) or not isinstance(meta, dict):
        raise _malformed()
    limit = meta.get("limit")
    if type(limit) is not int or limit != expected_limit or limit <= 0:
        raise _malformed()
    if len(data) > limit:
        raise _malformed()
    total = meta.get("total_documents")
    if total is not None:
        if type(total) is not int or total < 0 or len(data) > total:
            raise _malformed()
    truncated = meta.get("truncated")
    if truncated is not None and type(truncated) is not bool:
        raise _malformed()
    if truncated:
        raise _incomplete()
    next_cursor = meta.get("next_cursor")
    if next_cursor is not None:
        if not isinstance(next_cursor, str) or not next_cursor.strip():
            raise _malformed()
        next_cursor = next_cursor.strip()
        if token and token in next_cursor:
            raise SourceError("vulncheck", REFLECTED)
    return data, total, next_cursor


def _record(item: Any, token: str) -> tuple[list[str], Evidence]:
    if not isinstance(item, dict):
        raise _malformed()
    identifiers = _identifiers(item.get("cve"))
    date_added = _timestamp(item["date_added"], token) if "date_added" in item else None
    ransomware = _ransomware(item.get("knownRansomwareCampaignUse"))
    references = _reference_entries(item.get("vulncheck_xdb"), "xdb_url", token)
    reported = _reference_entries(
        item.get("vulncheck_reported_exploitation"), "url", token
    )
    details = {
        "date_added": date_added,
        "ransomware": ransomware,
        "reported_exploited": len(reported),
        "reported_exploitation": reported,
        "exploit_references": [entry["url"] for entry in references],
    }
    return identifiers, Evidence(
        "vulncheck",
        "known_exploitation",
        "VulnCheck KEV lists this CVE as known exploited",
        KEV_URL,
        date_added,
        details=details,
    )


def _add_records(
    items: list[Any],
    output: dict[str, Evidence],
    token: str,
    *,
    remaining: int,
) -> None:
    if len(items) > remaining:
        raise _incomplete()
    for item in items:
        identifiers, evidence = _record(item, token)
        for identifier in identifiers:
            output[identifier] = evidence
        if len(output) > MAX_ENTRIES:
            raise _incomplete()


class VulnCheckSource:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    @source_payload("vulncheck")
    def kev(self, token: str) -> dict[str, Evidence]:
        token = token.strip()
        if not token:
            raise SourceError("vulncheck", "no API token")
        headers = {"Authorization": f"Bearer {token}"}
        used = 0
        entries = 0
        output: dict[str, Evidence] = {}
        cursor: str | None = None
        seen_cursors: set[str] = set()
        reported_total: int | None = None
        for _page in range(MAX_PAGES):
            params: dict[str, Any] = {"limit": PAGE_SIZE}
            if cursor is None:
                params["start_cursor"] = "true"
            else:
                params["cursor"] = cursor
            remaining_bytes = MAX_BYTES - used
            if remaining_bytes <= 0:
                raise _incomplete()
            raw = b"".join(self.http.stream_bytes(
                KEV_URL,
                source="vulncheck",
                byte_cap=remaining_bytes,
                params=params,
                headers=headers,
                identity_only=True,
            ))
            used += len(raw)
            try:
                payload = json.loads(raw)
            except (ValueError, UnicodeError, RecursionError):
                raise _malformed() from None
            data, total, next_cursor = _meta(
                payload, expected_limit=PAGE_SIZE, token=token
            )
            if total is not None:
                if reported_total is None:
                    reported_total = total
                elif reported_total != total:
                    raise _incomplete()
            _add_records(data, output, token, remaining=MAX_ENTRIES - entries)
            entries += len(data)
            if next_cursor:
                if total == 0:
                    raise _incomplete()
                if next_cursor in seen_cursors:
                    raise _incomplete()
                seen_cursors.add(next_cursor)
                cursor = next_cursor
                continue
            if not data and reported_total != 0:
                raise _incomplete() if reported_total is not None else _malformed()
            if reported_total is not None and entries != reported_total:
                raise _incomplete()
            return output
        raise _incomplete()

    @staticmethod
    def parse(payload: Any, token: str = "") -> dict[str, Evidence]:
        """Parse one complete terminal response for callers and tests."""
        data, total, next_cursor = _meta(
            payload, expected_limit=PAGE_SIZE, token=token
        )
        if len(data) > MAX_ENTRIES:
            raise _incomplete()
        if next_cursor:
            raise _incomplete()
        if total is not None and total != len(data):
            raise _incomplete()
        if not data and total != 0:
            raise _malformed()
        output: dict[str, Evidence] = {}
        _add_records(data, output, token, remaining=MAX_ENTRIES)
        return output


def fetch_kev(http: HttpClient, token: str | None) -> dict[str, Evidence]:
    if not token:
        raise SourceError("vulncheck", "no API token")
    return VulnCheckSource(http).kev(token)
