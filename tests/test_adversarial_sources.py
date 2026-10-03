"""Record real wire serialization and isolate required-source degradation."""

from dataclasses import replace
import httpx
import pytest

from cvebeacon.config import AppConfig, HttpConfig, InventoryConfig, SourceConfig
from cvebeacon.engine import QueryEngine
from cvebeacon.errors import SourceError
from cvebeacon.http import HttpClient
from cvebeacon.models import Asset, Applicability as A, HealthStatus as H
from cvebeacon.sources.cve_list import record_url
from cvebeacon.sources.epss import EPSS_URL
from cvebeacon.sources.euvd import SEARCH_URL
from cvebeacon.sources.kev import CISA_URL, EU_URL
from cvebeacon.sources.nvd import CPE_URL, CVE_URL
from test_osv import record
from test_package_engine import engine, package


def test_all_public_source_requests_keep_operational_canaries_local(tmp_path, caplog, monkeypatch):
    identifier = "CVE-2026-1234"
    canaries = ["CANARY-ASSET", "CANARY-HOST.internal", "CANARY-CATEGORY", "CANARY-OWNER", "CANARY-PATH"]
    for name in ("NVD_API_KEY", "CVEBEACON_TEAMS_WEBHOOK_URL", "CVEBEACON_M365_TENANT_ID", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    observed = []
    cpe = "cpe:2.3:a:publicvendor:publicproduct:1.0.0:*:*:*:*:*:*:*"
    def handle(request):
        observed.append(request)
        url = str(request.url).split("?")[0]
        if url.endswith("/querybatch"):
            payload = {"results": [{"vulns": [{"id": "TEST-2026-123", "modified": "2026-10-03T00:00:00Z"}]}]}
        elif url.endswith("/vulns/TEST-2026-123"):
            payload = record(aliases=[identifier])
        elif url == CPE_URL:
            payload = {"products": [{"cpe": {"cpeName": cpe}}], "totalResults": 1, "startIndex": 0, "resultsPerPage": 1}
        elif url == CVE_URL:
            payload = {"vulnerabilities": [{"cve": {"id": identifier}}], "totalResults": 1, "startIndex": 0, "resultsPerPage": 1}
        elif url == record_url(identifier):
            payload = {"dataVersion": "5.1", "cveMetadata": {"cveId": identifier, "state": "PUBLISHED"},
                       "containers": {"cna": {"affected": []}}}
        elif url == SEARCH_URL:
            payload = {"items": [], "total": 0}
        elif url == CISA_URL:
            payload = {"count": 0, "vulnerabilities": []}
        elif url == EU_URL:
            payload = []
        elif url == EPSS_URL:
            payload = {"status": "OK", "total": 0, "data": []}
        else:
            pytest.fail("unexpected outbound public URL")
        return httpx.Response(200, json=payload)
    config = AppConfig(tmp_path / "c.toml", InventoryConfig(tmp_path / "i.csv"), tmp_path / "s.db", tmp_path,
        sources=SourceConfig(minimum_request_interval=0), http=HttpConfig(retries=0))
    assets = [replace(package(), asset_id=canaries[0], system_id=canaries[1], category=canaries[2],
                      vendor=canaries[3], repository="https://example.invalid/" + canaries[4]),
              Asset(canaries[0], "PublicVendor", "PublicProduct", "1.0.0", category=canaries[2], system_id=canaries[1])]
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        with HttpClient(config.http, client=client) as http:
            with QueryEngine(config, http=http) as value:
                assert value.scan(assets)[0].findings[0].applicability == A.AFFECTED
    wire = " ".join(str(r.url) + r.content.decode() + str(r.headers) for r in observed)
    assert all(canary not in wire and canary not in caplog.text for canary in canaries)
    assert all("authorization" not in r.headers and "apikey" not in r.headers for r in observed)
    assert {CPE_URL, CVE_URL, SEARCH_URL, CISA_URL, EU_URL, EPSS_URL, record_url(identifier)} <= {
        str(r.url).split("?")[0] for r in observed}


@pytest.mark.parametrize("source", ["nvd", "euvd", "cve_list", "cisa_kev", "eu_kev", "epss"])
def test_each_optional_package_source_outage_preserves_applicability(tmp_path, source):
    with engine(tmp_path, [record()]) as value:
        names = {"cve_list": "cve"}
        value.config = replace(value.config, sources=replace(value.config.sources, **{names.get(source, source) + "_enabled": True}))
        def fail(*args, **kwargs):
            raise SourceError(source, "synthetic unavailable")
        if source == "nvd": value.nvd.by_id = fail
        elif source == "euvd": value.euvd.search = fail
        elif source == "cve_list": value._official_evidence = fail
        elif source in {"cisa_kev", "eu_kev"}: value._catalog = fail
        else: value.epss.scores = fail
        result = value.scan([package()])[0]
    assert result.findings[0].applicability == A.AFFECTED
    assert result.coverage is None
    assert any(h.source == source and h.status in {H.DEGRADED, H.FAILED} for h in result.source_health)


def test_partial_required_source_cannot_make_fixed_evidence_clean(tmp_path):
    value = record(events=[{"introduced": "0"}, {"fixed": "1.0.0"}])
    with engine(tmp_path, [value], error="synthetic detail failure") as service:
        result = service.scan([package()])[0]
    assert result.findings[0].applicability == A.NEEDS_REVIEW
    assert result.coverage == A.COVERAGE_UNKNOWN
