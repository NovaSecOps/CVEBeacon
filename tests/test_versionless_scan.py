"""Version-less inventory rows are scanned conservatively across all versions."""

from cvebeacon.applicability import VERSION_UNKNOWN_REASON, known_version, wildcard_cpe_version
from cvebeacon.config import AppConfig, InventoryConfig, SourceConfig
from cvebeacon.engine import QueryEngine
from cvebeacon.models import Applicability as A, Asset, Evidence, HealthStatus as H, Vulnerability
from cvebeacon.sources.nvd import CPECandidate
from cvebeacon.sources.osv import OSVResult

from test_osv import record


def config(tmp_path, *, nvd=False, catalog=False):
    return AppConfig(
        tmp_path / "c.toml", InventoryConfig(tmp_path / "i.csv"), tmp_path / "s.db", tmp_path,
        sources=SourceConfig(nvd_enabled=nvd, cve_enabled=catalog, euvd_enabled=catalog,
                             cisa_kev_enabled=False, eu_kev_enabled=False, epss_enabled=False),
    )


def nvd_evidence(cpe):
    return Evidence("nvd", "applicability", "test", details={"configurations": [{
        "nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": cpe}]}],
    }]})


def test_versionless_product_scan_uses_a_wildcard_cpe_and_needs_review(tmp_path):
    php = Asset("php", vendor="php", product="php")
    cpe = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
    with QueryEngine(config(tmp_path, nvd=True, catalog=True)) as engine:
        engine.nvd.resolve_cpes = lambda asset: [CPECandidate(cpe, "", "a", "php", "php")]
        engine.euvd.search = lambda *args, **kwargs: [
            (Vulnerability("CVE-2025-0002"), Evidence("euvd", "enrichment", "test"))]
        engine._official_evidence = lambda identifier: (
            Evidence("cve_list", "cna", "test", details={"affected": []}),)
        calls = []

        def vulnerabilities(*, cpe_name, limit=None):
            calls.append((cpe_name, limit))
            return [(Vulnerability("CVE-2025-0001"), nvd_evidence(cpe))]

        engine.nvd.vulnerabilities = vulnerabilities
        result = engine.query_asset(php)

    assert calls == [(cpe, 2000)]
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2025-0001")
    assert len(result.findings) == 2
    assert finding.applicability is A.NEEDS_REVIEW
    assert finding.reason == VERSION_UNKNOWN_REASON
    assert finding.confidence == "limited"
    assert all(item.applicability is A.NEEDS_REVIEW and item.reason == VERSION_UNKNOWN_REASON
               for item in result.findings)
    assert result.coverage is A.NEEDS_REVIEW and result.coverage_reason == VERSION_UNKNOWN_REASON
    assert any(health.source == "nvd" and health.status is H.OK
               and "CVEs for all versions" in health.message for health in result.source_health)


def test_versionless_product_scan_reports_a_truncated_nvd_result(tmp_path):
    php = Asset("php", vendor="php", product="php")
    cpe = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
    with QueryEngine(config(tmp_path, nvd=True, catalog=True)) as engine:
        engine.nvd.resolve_cpes = lambda asset: [CPECandidate(cpe, "", "a", "php", "php")]
        engine.euvd.search = lambda *args, **kwargs: [
            (Vulnerability("CVE-2025-0002"), Evidence("euvd", "enrichment", "test"))]
        engine._official_evidence = lambda identifier: (
            Evidence("cve_list", "cna", "test", details={"affected": []}),)
        engine.nvd.truncated = True
        engine.nvd.vulnerabilities = lambda **kwargs: [
            (Vulnerability("CVE-2025-0001"), nvd_evidence(cpe))]
        result = engine.query_asset(php)

    assert result.coverage is A.COVERAGE_UNKNOWN
    assert any(health.source == "nvd" and health.status is H.DEGRADED
               and "result limit reached" in health.message for health in result.source_health)


def test_versionless_package_scan_queries_osv_without_a_version(tmp_path):
    lodash = Asset("lodash", purl="pkg:npm/lodash")
    advisory = record("npm", name="lodash", kind="SEMVER")
    with QueryEngine(config(tmp_path)) as engine:
        queries = []

        def query_many(assets):
            queries.extend(assets)
            return {asset.target_key: OSVResult((advisory,), None, frozenset({advisory["id"]}))
                    for asset in assets}

        engine.osv.query_many = query_many
        result = engine.query_asset(lodash)

    assert [asset.purl for asset in queries] == ["pkg:npm/lodash"]
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.applicability is A.NEEDS_REVIEW
    assert finding.reason == VERSION_UNKNOWN_REASON
    assert result.coverage is A.NEEDS_REVIEW and result.coverage_reason == VERSION_UNKNOWN_REASON


def test_wildcard_cpe_keeps_product_qualifiers_and_rejects_incomplete_names():
    cpe = "cpe:2.3:a:acme:widget:*:update:edition:en:sw:windows:x64:other"
    assert wildcard_cpe_version(cpe) == cpe
    try:
        wildcard_cpe_version("cpe:2.3:a:acme:*:*")
    except ValueError as exc:
        assert "complete" in str(exc)
    else:
        raise AssertionError("an incomplete CPE must be refused")


def test_known_version_still_rejects_wildcard_text():
    assert known_version("1.2.3")
    assert not known_version("*") and not known_version("latest") and not known_version("")
