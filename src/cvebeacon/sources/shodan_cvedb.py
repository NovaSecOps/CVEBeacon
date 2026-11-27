"""Shodan CVEDB adapter for CVE enrichment and corroborating discovery.

CVEDB is a keyless CVE database. Queries carry only a CVE identifier or a CPE
2.3 name. The public API documentation could not be verified offline; the
adapter accepts the documented field names and common aliases defensively.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
MAX_REFERENCES = 100


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


def _probability(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    number = as_float(value)
    return number if number is not None and 0 <= number <= 1 else None


def _references(value: Any) -> tuple[str, ...]:
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
    return tuple(output)


def _identifier(item: dict[str, Any]) -> str | None:
    return cve_id(item.get("cve_id") or item.get("cve") or item.get("id"))


def parse_record(item: Any, *, expected: str | None = None) -> CVEDBRecord:
    if not isinstance(item, dict):
        raise SourceError("shodan_cvedb", "source returned a non-object CVE entry")
    identifier = _identifier(item)
    if not identifier:
        raise SourceError("shodan_cvedb", "source returned an entry without a valid CVE identifier")
    if expected is not None and identifier != expected:
        raise SourceError("shodan_cvedb", "CVE lookup identity mismatch")
    return CVEDBRecord(
        identifier,
        _text(item.get("summary") or item.get("description")),
        _text(item.get("published_time") or item.get("published")),
        as_float(item.get("cvss")),
        _text(item.get("cvss_vector") or item.get("vector")),
        _text(item.get("cvss_version")),
        _flag(item.get("kev")),
        _flag(item.get("ransomware")),
        _probability(item.get("epss")),
        _probability(item.get("epss_percentile") or item.get("ranking_epss")),
        _references(item.get("references")),
    )


class ShodanCVEDBSource:
    def __init__(self, http: HttpClient, *, lookup_cap: int = LOOKUP_CAP) -> None:
        self.http = http
        self.lookup_cap = lookup_cap
        self.lookups = 0
        self.cap_reached = False
        self._cves: dict[str, CVEDBRecord | None] = {}
        self._cpes: dict[str, tuple[dict[str, CVEDBRecord], bool]] = {}

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
            payload = self.http.get_json(
                CVE_URL.format(identifier=identifier), source="shodan_cvedb"
            )
        except SourceError as exc:
            if exc.status_code == 404:
                self._cves[identifier] = None
                return None
            raise
        record = parse_record(payload, expected=identifier)
        self._cves[identifier] = record
        return record

    @source_payload("shodan_cvedb")
    def discover(self, cpe23: str) -> tuple[dict[str, CVEDBRecord], bool]:
        """Return CVEs reported for one exact CPE and whether results were truncated."""
        if cpe23 in self._cpes:
            return self._cpes[cpe23]
        found: dict[str, CVEDBRecord] = {}
        truncated = False
        total: int | None = None
        for page in range(MAX_PAGES):
            skip = page * PAGE_SIZE
            try:
                payload = self.http.get_json(
                    CPE_URL,
                    source="shodan_cvedb",
                    params={"cpe23": cpe23, "skip": skip, "limit": PAGE_SIZE},
                )
            except SourceError as exc:
                if exc.status_code == 404:
                    payload = {"cves": [], "total": 0}
                else:
                    raise
            if not isinstance(payload, dict) or not isinstance(payload.get("cves"), list):
                raise SourceError("shodan_cvedb", "CPE search returned an invalid response envelope")
            items = payload["cves"]
            for item in items:
                record = parse_record(item)
                if record.cve_id not in found and len(found) < MAX_RESULTS:
                    found[record.cve_id] = record
            total = payload.get("total")
            if total is not None and (type(total) is not int or total < 0):
                raise SourceError("shodan_cvedb", "CPE search returned an invalid total count")
            expected = None if total is None else min(PAGE_SIZE, max(total - skip, 0))
            if expected is not None and len(items) != expected:
                raise SourceError("shodan_cvedb", "CPE search returned an incomplete page")
            if len(found) >= MAX_RESULTS or (total is not None and skip + len(items) >= total):
                break
            if total is None and len(items) < PAGE_SIZE:
                break
        else:
            truncated = True
        if total is not None and total > MAX_RESULTS:
            truncated = True
        if len(found) >= MAX_RESULTS and (total is None or total > MAX_RESULTS):
            truncated = True
        self._cpes[cpe23] = (found, truncated)
        return found, truncated


def fetch_cve(http: HttpClient, identifier: str) -> CVEDBRecord:
    payload = http.get_json(CVE_URL.format(identifier=identifier), source="shodan_cvedb")
    return parse_record(payload, expected=identifier)
