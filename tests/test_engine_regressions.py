from dataclasses import replace
from types import SimpleNamespace

import pytest

from cvebeacon.config import AppConfig, InventoryConfig, SourceConfig
from cvebeacon.engine import QueryEngine
from cvebeacon.errors import SourceError
from cvebeacon.models import Applicability as A, Asset, Evidence, HealthStatus, Vulnerability


ASSET = Asset("a", "Acme", "Widget", "1.0.0")
CPE = "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*"
ID = "CVE-2026-1234"


def engine(tmp_path):
    value = object.__new__(QueryEngine)
    value.config = AppConfig(tmp_path / "c.toml", InventoryConfig(tmp_path / "i.csv"), tmp_path / "s.db", tmp_path)
    value._resolve_cpe = lambda asset: (CPE, "test identity")
    nvd = Evidence("nvd", "applicability", "test", details={"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": CPE}]}]}]})
    official = Evidence("cve_list", "cna", "test", details={"affected": [{"vendor": "Acme", "product": "Widget", "versions": [{"version": "1.0.0", "status": "affected"}]}]})
    value.nvd = SimpleNamespace(vulnerabilities=lambda **kw: [(Vulnerability(ID), nvd)])
    value.euvd = SimpleNamespace(search=lambda *a: [(Vulnerability(ID), Evidence("euvd", "enrichment", "test"))])
    value._official_evidence = lambda identifier: (official,)
    value._catalog = lambda name: {}
    value.epss = SimpleNamespace(scores=lambda ids: {})
    return value


@pytest.mark.parametrize("source", ["nvd", "cve_list", "euvd", "cisa_kev", "eu_kev", "epss"])
def test_each_source_failure_is_visible_and_preserves_useful_findings(tmp_path, source):
    value = engine(tmp_path)
    def fail(*a, **kw): raise SourceError(source, "unavailable")
    if source == "nvd": value.nvd.vulnerabilities = fail
    elif source == "euvd": value.euvd.search = fail
    elif source == "cve_list": value._official_evidence = fail
    elif source == "epss": value.epss.scores = fail
    else: value._catalog = lambda name: fail() if name == source else {}
    result = value.query_asset(ASSET)
    assert result.coverage == A.COVERAGE_UNKNOWN
    assert result.findings
    assert result.findings[0].applicability != A.NOT_AFFECTED
    assert any(h.source == source and h.status in {HealthStatus.FAILED, HealthStatus.DEGRADED} for h in result.source_health)
    if source in {"cisa_kev", "eu_kev"}:
        assert getattr(result.findings[0].vulnerability, source) is None


def test_monitoring_refreshes_rejected_cve_no_longer_in_discovery(tmp_path):
    value = engine(tmp_path)
    value.nvd.vulnerabilities = lambda **kw: []
    value.euvd.search = lambda *a: []
    value._official_evidence = lambda identifier: (Evidence("cve_list", "cna", "rejected", details={"state": "REJECTED"}),)
    known = {"asset": {"asset_id": "a", "vendor": "Acme", "product": "Widget", "version": "1.0.0"}, "vulnerability": {"cve_id": ID}}
    result = value.scan([ASSET], known_findings=[known])[0]
    assert result.findings[0].vulnerability.rejected
    assert result.findings[0].applicability == A.NEEDS_REVIEW


def test_version_case_is_not_deduplicated():
    assert replace(ASSET, version="1.0.0-ALPHA").target_key != replace(ASSET, version="1.0.0-alpha").target_key


def test_unknown_kev_is_distinct_from_verified_nonmembership(tmp_path):
    result = engine(tmp_path).query_asset(ASSET)
    assert result.findings[0].vulnerability.cisa_kev is False
