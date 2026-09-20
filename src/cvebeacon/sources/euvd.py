"""ENISA EUVD search adapter."""

from __future__ import annotations

from typing import Any
from dataclasses import replace

from ..http import HttpClient
from ..errors import SourceError
from ..models import Evidence, Vulnerability
from .common import as_float, cve_id, source_payload

SEARCH_URL = "https://euvdservices.enisa.europa.eu/api/search"


class EUVDSource:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    @source_payload("euvd")
    def search(self, vendor: str, product: str, *, identifier: str | None = None) -> list[tuple[Vulnerability, Evidence]]:
        page = 0
        found: list[tuple[Vulnerability, Evidence]] = []
        while True:
            payload = self.http.get_json(
                SEARCH_URL, source="euvd", params={**({"text": identifier} if identifier else {"vendor": vendor, "product": product}), "page": page, "size": 100}
            )
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise SourceError("euvd", "source returned an invalid search envelope")
            items = payload["items"]
            for item in items:
                if not isinstance(item, dict):
                    raise SourceError("euvd", "source returned a non-object search item")
                parsed = self.parse_item(item)
                if parsed:
                    aliases = item.get("aliases") or []
                    if isinstance(aliases, str):
                        aliases = aliases.replace(",", " ").split()
                    identifiers = {value for alias in aliases if (value := cve_id(alias))} or {parsed[0].cve_id}
                    found.extend((replace(parsed[0], cve_id=value), parsed[1]) for value in sorted(identifiers) if identifier is None or identifier == value)
            try:
                total = payload["total"]
                if type(total) is not int or total < 0:
                    raise ValueError("invalid count")
            except (TypeError, ValueError) as exc:
                raise SourceError("euvd", "source returned an invalid total count") from exc
            if len(items) != min(100, max(total - page * 100, 0)):
                raise SourceError("euvd", "source returned an incomplete page")
            if (page + 1) * 100 >= total:
                break
            page += 1
        return found

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
            source_url=f"https://euvd.enisa.europa.eu/vulnerability/{item.get('id', '')}",
            source_timestamp=item.get("dateUpdated"),
            details={"euvd_id": item.get("id"), "products": products, "vendors": item.get("enisaIdVendor") or [], "cvss": {key: item.get(key) for key in ("baseScore", "baseScoreVector", "baseScoreVersion")}},
        )
        return vuln, evidence
