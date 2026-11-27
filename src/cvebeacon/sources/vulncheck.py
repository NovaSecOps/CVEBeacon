"""VulnCheck KEV bulk index adapter.

The v3 API is documented as a JSON index endpoint authenticated with a bearer
token. The exact response envelope is treated defensively because the public
documentation is not available offline and no token is available to verify it
against the live service. A successful download is cached by the caller once
per run.
"""

from __future__ import annotations

import json
from typing import Any

from ..errors import SourceError
from ..http import HttpClient
from ..models import Evidence
from .common import cve_id, source_payload

KEV_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
MAX_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 250_000
MAX_REFERENCES = 100


def _items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("data", "items", "vulnerabilities", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict) and key in {"data", "vulnerabilities"}:
                nested = value.get("vulnerabilities") or value.get("items")
                if isinstance(nested, list):
                    return nested
    raise SourceError("vulncheck", "KEV index returned an invalid response envelope")


def _identifiers(value: Any) -> list[str]:
    raw = value if isinstance(value, list) else [value]
    return [identifier for item in raw if (identifier := cve_id(item))]


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    return text[:4096] or None


def _flag(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().casefold()
    if text in {"true", "yes", "known", "1"}:
        return True
    if text in {"false", "no", "unknown", "none", "", "0"}:
        return False
    return None


def _reference_urls(value: Any) -> list[str]:
    raw = value if isinstance(value, list) else [value] if value else []
    output: list[str] = []
    for item in raw:
        if isinstance(item, str):
            text = item.strip()
        elif isinstance(item, dict):
            text = str(item.get("url") or item.get("link") or "").strip()
        else:
            text = ""
        if text and len(text) <= 2048 and text not in output:
            output.append(text)
        if len(output) >= MAX_REFERENCES:
            break
    return output


def _exploitation_counts(item: dict[str, Any]) -> tuple[int, tuple[str, ...]]:
    reported = item.get("reported_exploited")
    references = _reference_urls(item.get("exploit_references"))
    if isinstance(reported, list):
        reported_urls = _reference_urls(reported)
        references = list(dict.fromkeys((*references, *reported_urls)))[:MAX_REFERENCES]
        return len(reported_urls), tuple(references)
    if isinstance(reported, bool):
        return (1 if reported else 0), tuple(references)
    if isinstance(reported, int) and not isinstance(reported, bool):
        return max(reported, 0), tuple(references)
    return (len(references) if references else 0), tuple(references)


class VulnCheckSource:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    @source_payload("vulncheck")
    def kev(self, token: str) -> dict[str, Evidence]:
        if not token or not token.strip():
            raise SourceError("vulncheck", "no API token")
        raw = b"".join(
            self.http.stream_bytes(
                KEV_URL,
                source="vulncheck",
                byte_cap=MAX_BYTES,
                headers={"Authorization": f"Bearer {token.strip()}"},
            )
        )
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise SourceError("vulncheck", "KEV index returned invalid JSON") from exc
        return self.parse(payload)

    @staticmethod
    def parse(payload: Any) -> dict[str, Evidence]:
        items = _items(payload)
        if len(items) > MAX_ENTRIES:
            raise SourceError("vulncheck", "KEV index exceeded the entry limit")
        output: dict[str, Evidence] = {}
        for item in items:
            if not isinstance(item, dict):
                raise SourceError("vulncheck", "KEV index contains a non-object entry")
            identifiers = _identifiers(item.get("cve") if "cve" in item else item.get("cve_id"))
            if not identifiers:
                raise SourceError("vulncheck", "KEV index entry omitted its CVE identifier")
            if len(identifiers) > 100:
                raise SourceError("vulncheck", "KEV index entry exceeded the identifier limit")
            date_added = _text(item.get("date_added") or item.get("dateAdded"))
            ransomware = _flag(item.get("ransomware"))
            reported, references = _exploitation_counts(item)
            details = {
                "date_added": date_added,
                "ransomware": ransomware,
                "reported_exploited": reported,
                "exploit_references": list(references),
            }
            for identifier in identifiers:
                output[identifier] = Evidence(
                    "vulncheck",
                    "known_exploitation",
                    "VulnCheck KEV lists this CVE as known exploited",
                    KEV_URL,
                    date_added,
                    details=details,
                )
        return output


def kev_fields(items: dict[str, Evidence]) -> dict[str, tuple[str | None, str | None]]:
    """Reduce parsed evidence to the watch catalog's added date and ransomware text."""
    output: dict[str, tuple[str | None, str | None]] = {}
    for identifier, evidence in items.items():
        details = evidence.details
        ransomware = details.get("ransomware")
        added = details.get("date_added")
        output[identifier] = (
            None if added is None else str(added)[:80],
            None if ransomware is None else ("Known" if ransomware else "Unknown"),
        )
    return output


def fetch_kev(http: HttpClient, token: str | None) -> dict[str, Evidence]:
    if not token:
        raise SourceError("vulncheck", "no API token")
    return VulnCheckSource(http).kev(token)
