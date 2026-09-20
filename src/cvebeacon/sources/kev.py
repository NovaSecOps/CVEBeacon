"""CISA KEV and ENISA consolidated KEV adapters."""

from __future__ import annotations

from typing import Any

from ..http import HttpClient
from ..errors import SourceError
from ..models import Evidence
from .common import cve_id, source_payload

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EU_URL = "https://euvdservices.enisa.europa.eu/api/kev/dump"


class KEVSource:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    @source_payload("cisa_kev")
    def cisa(self) -> dict[str, Evidence]:
        payload = self.http.get_json(CISA_URL, source="cisa_kev")
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise SourceError("cisa_kev", "catalog returned an invalid response envelope")
        output: dict[str, Evidence] = {}
        if "count" in payload and payload["count"] != len(payload["vulnerabilities"]):
            raise SourceError("cisa_kev", "catalog count does not match returned entries")
        for item in payload["vulnerabilities"]:
            if not isinstance(item, dict):
                raise SourceError("cisa_kev", "catalog contains a non-object vulnerability entry")
            identifier = cve_id(item.get("cveID"))
            if not identifier:
                raise SourceError("cisa_kev", "catalog entry omitted its CVE identifier")
            if identifier:
                output[identifier] = Evidence(
                    "cisa_kev", "known_exploitation", "CISA lists this CVE as known exploited",
                    CISA_URL, payload.get("dateReleased"), details=dict(item),
                )
        return output

    @source_payload("eu_kev")
    def eu(self) -> dict[str, Evidence]:
        payload = self.http.get_json(EU_URL, source="eu_kev")
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict) and ("items" in payload or "data" in payload):
            items = payload.get("items", payload.get("data"))
        else:
            raise SourceError("eu_kev", "catalog returned an invalid response envelope")
        if not isinstance(items, list):
            raise SourceError("eu_kev", "catalog returned an invalid response envelope")
        output: dict[str, Evidence] = {}
        for item in items:
            if not isinstance(item, dict):
                raise SourceError("eu_kev", "catalog contains a non-object entry")
            identifier = cve_id(item.get("cveId"))
            sources = item.get("sources")
            if not identifier or not isinstance(sources, list) or not all(isinstance(value, str) for value in sources):
                raise SourceError("eu_kev", "catalog entry omitted its CVE identifier or source provenance")
            if identifier and "eukev_kev" in sources:
                output[identifier] = Evidence(
                    "eu_kev", "known_exploitation", "ENISA EU KEV lists this CVE as known exploited",
                    EU_URL, item.get("dateAdded"), details={"sources": sources, **dict(item)},
                )
        return output
