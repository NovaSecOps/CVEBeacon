"""NVD CVE and CPE 2.0 adapter with explicit pagination."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

from ..http import HttpClient
from ..errors import SourceError
from ..models import Asset, Evidence, Vulnerability
from .common import as_float, cve_id, source_payload

CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


@dataclass(frozen=True, slots=True)
class CPECandidate:
    name: str
    title: str
    part: str
    vendor: str
    product: str


def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def split_cpe23(value: str, *, keep_escapes: bool = False) -> tuple[str, ...]:
    if not value.startswith("cpe:2.3:"):
        return ()
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value[8:]:
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current) if keep_escapes else _unescape("".join(current)))
            current = []
        else:
            current.append(char)
    if escaped:
        return ()
    fields.append("".join(current) if keep_escapes else _unescape("".join(current)))
    return tuple(fields)


class NVDSource:
    def __init__(self, http: HttpClient, *, api_key: str | None = None, interval: float = 6) -> None:
        self.http = http
        self.headers = {"apiKey": api_key} if api_key else None
        self.interval = interval

    def _pages(self, url: str, params: dict[str, Any], page_size: int) -> Iterator[dict[str, Any]]:
        start = 0
        while True:
            payload = self.http.get_json(
                url,
                source="nvd",
                params={**params, "startIndex": start, "resultsPerPage": page_size},
                headers=self.headers,
                minimum_interval=self.interval,
            )
            if not isinstance(payload, dict):
                raise SourceError("nvd", "source returned an invalid response envelope")
            collection = "products" if url == CPE_URL else "vulnerabilities"
            if not isinstance(payload.get(collection), list) or "totalResults" not in payload or "resultsPerPage" not in payload:
                raise SourceError("nvd", f"source response omitted required {collection} pagination fields")
            count, total, offset = (payload.get(key) for key in ("resultsPerPage", "totalResults", "startIndex"))
            if any(type(value) is not int or value < 0 for value in (count, total, offset)) or offset != start:
                raise SourceError("nvd", "source returned invalid pagination metadata")
            if len(payload[collection]) != count or start + count > total or (count == 0 and start < total):
                raise SourceError("nvd", "source returned an incomplete page")
            yield payload
            if start + count >= total:
                return
            start += count

    @source_payload("nvd")
    def resolve_cpes(self, asset: Asset) -> list[CPECandidate]:
        result: list[CPECandidate] = []
        keyword = f"{asset.vendor} {asset.product}"
        for page in self._pages(CPE_URL, {"keywordSearch": keyword}, 10000):
            for wrapped in page.get("products", []):
                cpe = wrapped.get("cpe", {}) if isinstance(wrapped, dict) else {}
                name = str(cpe.get("cpeName") or "")
                parts = split_cpe23(name)
                if len(parts) != 11:
                    raise SourceError("nvd", "source returned an invalid CPE name")
                if cpe.get("deprecated"):
                    continue
                titles = cpe.get("titles") or []
                title = next(
                    (str(item.get("title")) for item in titles if item.get("lang") == "en"),
                    str(titles[0].get("title")) if titles else "",
                )
                result.append(CPECandidate(name, title, parts[0], parts[1], parts[2]))
        return result

    @source_payload("nvd")
    def vulnerabilities(self, *, cpe_name: str) -> list[tuple[Vulnerability, Evidence]]:
        found: list[tuple[Vulnerability, Evidence]] = []
        for page in self._pages(CVE_URL, {"cpeName": cpe_name, "isVulnerable": ""}, 2000):
            for wrapped in page.get("vulnerabilities", []):
                raw = wrapped.get("cve", {}) if isinstance(wrapped, dict) else {}
                parsed = self.parse_cve(raw)
                if parsed:
                    found.append(parsed)
                else:
                    raise SourceError("nvd", "source returned a vulnerability without a valid identifier")
        return found

    @staticmethod
    def parse_cve(raw: dict[str, Any]) -> tuple[Vulnerability, Evidence] | None:
        identifier = cve_id(raw.get("id"))
        if not identifier:
            return None
        descriptions = raw.get("descriptions") or []
        summary = next((x.get("value") for x in descriptions if x.get("lang") == "en"), None)
        score = vector = version = None
        metrics = raw.get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {})
                score, vector, version = as_float(data.get("baseScore")), data.get("vectorString"), data.get("version")
                break
        statuses = {str(item.get("status", "")).lower() for item in raw.get("vulnStatus", [])} if isinstance(raw.get("vulnStatus"), list) else {str(raw.get("vulnStatus", "")).lower()}
        rejected = "rejected" in statuses
        refs = tuple(str(x.get("url")) for x in raw.get("references", []) if x.get("url"))
        vuln = Vulnerability(
            identifier, summary, raw.get("published"), raw.get("lastModified"), rejected,
            score, vector, str(version) if version else None, references=refs,
        )
        evidence = Evidence(
            "nvd", "applicability_and_enrichment", "NVD returned this CVE for the exact CPE name",
            f"{CVE_URL}?cveId={identifier}", raw.get("lastModified"),
            details={"configurations": raw.get("configurations", []), "affected": raw.get("affected", []), "metrics": metrics},
        )
        return vuln, evidence
