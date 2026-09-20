"""ENISA EUVD search adapter."""

from __future__ import annotations

from typing import Any

from ..http import HttpClient
from ..errors import SourceError
from ..models import Evidence, Vulnerability
from .common import as_float, cve_id

SEARCH_URL = "https://euvdservices.enisa.europa.eu/api/search"


class EUVDSource:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    def search(self, vendor: str, product: str) -> list[tuple[Vulnerability, Evidence]]:
        page = 0
        found: dict[str, tuple[Vulnerability, Evidence]] = {}
        while True:
            payload = self.http.get_json(
                SEARCH_URL, source="euvd", params={"vendor": vendor, "product": product, "page": page, "size": 100}
            )
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise SourceError("euvd", "source returned an invalid search envelope")
            items = payload["items"]
            for item in items:
                if not isinstance(item, dict):
                    raise SourceError("euvd", "source returned a non-object search item")
                parsed = self.parse_item(item)
                if parsed:
                    found[parsed[0].cve_id] = parsed
            try:
                total = int(payload.get("total") or 0)
            except (TypeError, ValueError) as exc:
                raise SourceError("euvd", "source returned an invalid total count") from exc
            if not items or (page + 1) * 100 >= total:
                break
            page += 1
        return list(found.values())

    @staticmethod
    def parse_item(item: dict[str, Any]) -> tuple[Vulnerability, Evidence] | None:
        aliases = item.get("aliases") or []
        if isinstance(aliases, str):
            aliases = aliases.replace(",", " ").split()
        identifier = next((value for value in (cve_id(x) for x in aliases) if value), None)
        if not identifier:
            identifier = cve_id(item.get("id"))
        if not identifier:
            return None
        refs = item.get("references") or []
        if isinstance(refs, str):
            refs = [line.strip() for line in refs.splitlines() if line.strip()]
        vuln = Vulnerability(
            identifier, item.get("description"), item.get("datePublished"), item.get("dateUpdated"),
            cvss_score=as_float(item.get("baseScore")), cvss_vector=item.get("baseScoreVector"),
            cvss_version=str(item.get("baseScoreVersion")) if item.get("baseScoreVersion") else None,
            references=tuple(str(x) for x in refs),
        )
        products = item.get("enisaIdProduct") or []
        evidence = Evidence(
            "euvd", "independent_enrichment", "EUVD returned product/version evidence",
            source_timestamp=item.get("dateUpdated"),
            details={"euvd_id": item.get("id"), "products": products, "vendors": item.get("enisaIdVendor") or []},
        )
        return vuln, evidence
