"""Shodan CVEDB adapter for CVE enrichment and corroborating discovery.

CVEDB is a keyless CVE database. Queries carry only a CVE identifier or a CPE
2.3 name. Every response is read through a bounded identity-encoded stream so a
page cannot allocate more than its declared byte budget. Discovery requests a
count first, then reads at most five 100-row pages and marks any inconsistent
or truncated result as degraded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from ..errors import SourceError
from ..http import HttpClient
from .common import as_float, cve_id, source_payload

BASE_URL = "https://cvedb.shodan.io"
CVE_URL = BASE_URL + "/cve/{identifier}"
CPE_URL = BASE_URL + "/cves"
PAGE_SIZE = 100
MAX_PAGES = 5
MAX_RESULTS = 500
LOOKUP_CAP = 500
DISCOVERY_REQUEST_CAP = 250
MAX_REFERENCES = 100
MAX_REFERENCE_BYTES = 2048
MAX_DETAIL_BYTES = 1 * 1024 * 1024
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_COUNT_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class CVEDBRecord:
    cve_id: str
    summary: str | None = None
    published: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    kev: bool | None = None
    ransomware: bool | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CVEDBDiscovery:
    records: dict[str, CVEDBRecord]
    degraded: bool = False
    message: str | None = None


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


def _score(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    number = as_float(value)
    return number if number is not None and 0 <= number <= 10 else None


def _probability(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    number = as_float(value)
    return number if number is not None and 0 <= number <= 1 else None


def _version(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text or len(text) > 16:
        return None
    try:
        float(text)
    except (TypeError, ValueError, OverflowError):
        return None
    return text


def _published(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return None
    return text


def _reference_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if len(text) > MAX_REFERENCE_BYTES:
        raise SourceError("shodan_cvedb", "source returned a malformed reference")
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except (ValueError, TypeError):
        raise SourceError("shodan_cvedb", "source returned a malformed reference") from None
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or port == -1):
        raise SourceError("shodan_cvedb", "source returned a malformed reference")
    return text


def _references(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    output: list[str] = []
    for item in value:
        if isinstance(item, str):
            text = _reference_url(item)
        elif isinstance(item, dict):
            text = _reference_url(item.get("url") or item.get("link"))
        else:
            text = None
        if text is not None and text not in output:
            output.append(text)
        if len(output) >= MAX_REFERENCES:
            break
    return tuple(output)


def _identifier(item: dict[str, Any]) -> str | None:
    return cve_id(item.get("cve_id"))


def parse_record(item: Any, *, expected: str | None = None) -> CVEDBRecord:
    if not isinstance(item, dict):
        raise SourceError("shodan_cvedb", "source returned a non-object CVE entry")
    identifier = _identifier(item)
    if not identifier:
        raise SourceError("shodan_cvedb", "source returned an entry without a valid CVE identifier")
    if expected is not None and identifier != expected:
        raise SourceError("shodan_cvedb", "CVE lookup identity mismatch")
    score = _score(item.get("cvss"))
    if score is None:
        score = next((candidate for key in ("cvss_v4", "cvss_v3", "cvss_v2")
                      if (candidate := _score(item.get(key))) is not None), None)
    return CVEDBRecord(
        identifier,
        _text(item.get("summary")),
        _published(item.get("published_time")),
        score,
        None,
        _version(item.get("cvss_version")),
        _flag(item.get("kev")),
        _campaign(item.get("ransomware_campaign")),
        _probability(item.get("epss")),
        _percentile(item),
        _references(item.get("references")),
    )


def _campaign(value: Any) -> bool | None:
    """Preserve the documented campaign string without inventing a negative."""
    if not isinstance(value, str):
        return None
    return True if value.strip().casefold() == "known" else None


def _percentile(item: dict[str, Any]) -> float | None:
    """Use the documented 0-1 ranking, preserving zero and unknown values."""
    if "ranking_epss" in item:
        return _probability(item["ranking_epss"])
    return _probability(item.get("epss_percentile"))


def _json(
    http: HttpClient,
    url: str,
    *,
    byte_cap: int,
    params: Any = None,
    before_attempt=None,
) -> Any:
    raw = b"".join(http.stream_bytes(
        url, source="shodan_cvedb", byte_cap=byte_cap, params=params,
        identity_only=True, before_attempt=before_attempt,
    ))
    if not raw:
        raise SourceError("shodan_cvedb", "source returned an empty response")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise SourceError("shodan_cvedb", "source returned invalid JSON") from None


class _BudgetExhausted(Exception):
    """The per-run discovery request budget cannot send another attempt."""


class ShodanCVEDBSource:
    def __init__(self, http: HttpClient, *, lookup_cap: int = LOOKUP_CAP,
                 discovery_request_cap: int = DISCOVERY_REQUEST_CAP) -> None:
        self.http = http
        self.lookup_cap = lookup_cap
        self.discovery_request_cap = discovery_request_cap
        self.lookups = 0
        self.cap_reached = False
        self.discovery_requests = 0
        self.discovery_cap_reached = False
        self._cves: dict[str, CVEDBRecord | None] = {}
        self._cpes: dict[str, CVEDBDiscovery] = {}

    def remember(self, record: CVEDBRecord) -> None:
        """Seed the run cache from a discovery response."""
        self._cves.setdefault(record.cve_id, record)

    def lookup(self, identifier: str) -> CVEDBRecord | None:
        """Fetch one CVE, or None when it is absent or the run cap is reached."""
        identifier = cve_id(identifier) or ""
        if not identifier:
            return None
        if identifier in self._cves:
            return self._cves[identifier]
        if self.lookups >= self.lookup_cap:
            self.cap_reached = True
            return None
        self.lookups += 1
        try:
            payload = _json(
                self.http, CVE_URL.format(identifier=identifier), byte_cap=MAX_DETAIL_BYTES
            )
        except SourceError as exc:
            if exc.status_code == 404:
                self._cves[identifier] = None
                return None
            raise
        record = parse_record(payload, expected=identifier)
        self._cves[identifier] = record
        return record

    def _charge_discovery(self) -> None:
        """Charge one HTTP attempt, including a retry, before it is sent."""
        if self.discovery_requests >= self.discovery_request_cap:
            self.discovery_cap_reached = True
            raise _BudgetExhausted()
        self.discovery_requests += 1

    @source_payload("shodan_cvedb")
    def discover(self, cpe23: str) -> CVEDBDiscovery:
        """Return CVEs reported for one exact CPE and the coverage state."""
        if cpe23 in self._cpes:
            return self._cpes[cpe23]
        found: dict[str, CVEDBRecord] = {}
        degraded = False
        messages: list[str] = []
        total: int | None = None
        try:
            payload = _json(
                self.http, CPE_URL, byte_cap=MAX_COUNT_BYTES,
                params={"cpe23": cpe23, "count": "true"},
                before_attempt=self._charge_discovery,
            )
        except _BudgetExhausted:
            result = CVEDBDiscovery({}, True, "discovery request cap reached")
            self._cpes[cpe23] = result
            return result
        if not isinstance(payload, dict) or type(payload.get("total")) is not int or payload["total"] < 0:
            degraded = True
            messages.append("invalid discovery total")
        else:
            total = payload["total"]
            wanted = min(total, MAX_RESULTS)
            if total > MAX_RESULTS:
                degraded = True
                messages.append(f"total {total} exceeds the {MAX_RESULTS} result limit")
            skip = 0
            pages = 0
            while skip < wanted and pages < MAX_PAGES:
                expected = min(PAGE_SIZE, wanted - skip)
                try:
                    page = _json(
                        self.http, CPE_URL, byte_cap=MAX_PAGE_BYTES,
                        params={"cpe23": cpe23, "skip": skip, "limit": PAGE_SIZE},
                        before_attempt=self._charge_discovery,
                    )
                except _BudgetExhausted:
                    degraded = True
                    messages.append("discovery request cap reached")
                    break
                if not isinstance(page, dict) or not isinstance(page.get("cves"), list):
                    raise SourceError(
                        "shodan_cvedb", "CPE search returned an invalid response envelope"
                    )
                items = page["cves"]
                if len(items) > PAGE_SIZE:
                    raise SourceError("shodan_cvedb", "CPE search returned an oversized page")
                if len(items) != expected:
                    degraded = True
                    messages.append("discovery page count is inconsistent")
                for item in items[:expected]:
                    record = parse_record(item)
                    if record.cve_id in found:
                        degraded = True
                    else:
                        found[record.cve_id] = record
                pages += 1
                skip += min(len(items), expected)
                if len(items) < expected:
                    break
            if total is not None and len(found) != min(total, MAX_RESULTS):
                degraded = True
                messages.append("discovery CVE identifiers are incomplete or duplicated")
        result = CVEDBDiscovery(
            found, degraded, "; ".join(dict.fromkeys(messages)) or None
        )
        self._cpes[cpe23] = result
        return result


def fetch_cve(http: HttpClient, identifier: str) -> CVEDBRecord:
    payload = _json(
        http, CVE_URL.format(identifier=identifier), byte_cap=MAX_DETAIL_BYTES
    )
    return parse_record(payload, expected=identifier)
