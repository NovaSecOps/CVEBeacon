"""Targeted official CVE List V5 record retrieval and parsing."""

from __future__ import annotations

from typing import Any

from ..http import HttpClient
from ..errors import SourceError
from ..models import Evidence
from .common import cve_id

RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


def record_url(identifier: str) -> str:
    normalized = cve_id(identifier)
    if not normalized:
        raise ValueError(f"invalid CVE identifier: {identifier}")
    _, year, serial = normalized.split("-")
    bucket = f"{int(serial) // 1000}xxx"
    return f"{RAW_BASE}/{year}/{bucket}/{normalized}.json"


class CVEListSource:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    def record(self, identifier: str) -> dict[str, Any]:
        normalized = cve_id(identifier)
        payload = self.http.get_json(record_url(identifier), source="cve_list")
        if not isinstance(payload, dict):
            raise SourceError("cve_list", "official record is not a JSON object")
        metadata = payload.get("cveMetadata")
        version = str(payload.get("dataVersion") or "")
        if not isinstance(metadata, dict) or cve_id(metadata.get("cveId")) != normalized or not version.startswith("5."):
            raise SourceError("cve_list", "official record omitted required CVE JSON 5 metadata")
        return payload

    @staticmethod
    def evidence(record: dict[str, Any]) -> tuple[Evidence, ...]:
        metadata = record.get("cveMetadata", {})
        identifier = cve_id(metadata.get("cveId"))
        if not identifier:
            return ()
        state = str(metadata.get("state") or "").upper()
        containers = record.get("containers", {})
        output: list[Evidence] = []
        for role, container in [("cna", containers.get("cna"))]:
            if isinstance(container, dict):
                output.append(CVEListSource._container_evidence(identifier, role, container, state))
        for index, container in enumerate(containers.get("adp") or []):
            if not isinstance(container, dict):
                continue
            provider = container.get("providerMetadata", {})
            org = str(provider.get("shortName") or provider.get("orgId") or f"adp-{index + 1}")
            output.append(CVEListSource._container_evidence(identifier, f"adp:{org}", container, state))
        return tuple(output)

    @staticmethod
    def _container_evidence(identifier: str, role: str, container: dict[str, Any], state: str) -> Evidence:
        affected = container.get("affected") or []
        statement = "official CVE record rejected" if state == "REJECTED" else "official CVE affected-product evidence"
        return Evidence(
            "cve_list", role, statement, record_url(identifier),
            details={"state": state, "affected": affected, "rejected_reasons": container.get("rejectedReasons", [])},
        )
