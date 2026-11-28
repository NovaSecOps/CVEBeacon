"""Version-less inventory rows are scanned conservatively across all versions."""

import httpx

from cvebeacon.applicability import (VERSION_UNKNOWN_REASON, known_version, wildcard_cpe_version)
from cvebeacon.config import AppConfig, HttpConfig, InventoryConfig, SourceConfig
from cvebeacon.engine import QueryEngine
from cvebeacon.http import HttpClient
from cvebeacon.models import Applicability as A, Asset, Evidence, HealthStatus as H, Vulnerability
from cvebeacon.sources.nvd import CPECandidate, NVDResult
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


def nvd_record(identifier, cpe, *, vulnerable=True):
    return {"id": identifier, "descriptions": [{"lang": "en", "value": "test"}],
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
                {"vulnerable": vulnerable, "criteria": cpe}]}]}]}


def recording_engine(tmp_path, handler):
    settings = SourceConfig(nvd_enabled=True, cve_enabled=False, euvd_enabled=False,
                            cisa_kev_enabled=False, eu_kev_enabled=False, epss_enabled=False,
                            minimum_request_interval=0)
    settings = AppConfig(tmp_path / "c.toml", InventoryConfig(tmp_path / "i.csv"),
                         tmp_path / "s.db", tmp_path, sources=settings)
    http = HttpClient(HttpConfig(retries=0),
                      client=httpx.Client(transport=httpx.MockTransport(handler)),
                      sleep=lambda _: None)
    return QueryEngine(settings, http=http), http


def test_versionless_product_scan_uses_a_product_wide_lookup_and_needs_review(tmp_path):
    php = Asset("php", vendor="php", product="php")
    cpe = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
    with QueryEngine(config(tmp_path, nvd=True, catalog=True)) as engine:
        engine.nvd.resolve_cpes = lambda asset: [CPECandidate(cpe, "", "a", "php", "php")]
        engine.euvd.search = lambda *args, **kwargs: [
            (Vulnerability("CVE-2025-0002"), Evidence("euvd", "enrichment", "test"))]
        engine._official_evidence = lambda identifier: (
            Evidence("cve_list", "cna", "test", details={"affected": []}),)
        calls = []

        def vulnerabilities(**kwargs):
            calls.append(kwargs)
            return NVDResult(((Vulnerability("CVE-2025-0001"), nvd_evidence(cpe)),))

        engine.nvd.vulnerabilities = vulnerabilities
        result = engine.query_asset(php)

    assert calls == [{"virtual_match": cpe, "limit": 2000}]
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
        engine.nvd.vulnerabilities = lambda **kwargs: NVDResult(
            ((Vulnerability("CVE-2025-0001"), nvd_evidence(cpe)),), True)
        result = engine.query_asset(php)

    assert result.coverage is A.COVERAGE_UNKNOWN
    assert any(health.source == "nvd" and health.status is H.DEGRADED
               and "result limit reached" in health.message for health in result.source_health)


def test_nvd_product_wide_request_parameters_and_prerequisite_record(tmp_path):
    wildcard = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
    exact = "cpe:2.3:a:php:php:8.3.0:*:*:*:*:*:*:*"
    params = []

    def handler(request):
        values = dict(request.url.params)
        params.append(values)
        if "virtualMatchString" in values:
            return httpx.Response(200, json={
                "startIndex": 0, "resultsPerPage": 2, "totalResults": 2,
                "vulnerabilities": [
                    {"cve": nvd_record("CVE-2026-0001", wildcard)},
                    {"cve": nvd_record("CVE-2026-0002", wildcard, vulnerable=False)},
                ]})
        return httpx.Response(200, json={
            "startIndex": 0, "resultsPerPage": 1, "totalResults": 1,
            "vulnerabilities": [{"cve": nvd_record("CVE-2026-0003", exact)}]})

    engine, http = recording_engine(tmp_path, handler)
    try:
        engine.nvd.resolve_cpes = lambda asset: [CPECandidate(wildcard, "", "a", "php", "php")]
        versionless = engine.query_asset(Asset("php", vendor="php", product="php"))
        versioned = engine.query_asset(Asset("php-830", vendor="php", product="php",
                                             version="8.3.0", cpe=wildcard))
    finally:
        http.close()

    assert params == [
        {"virtualMatchString": wildcard, "startIndex": "0", "resultsPerPage": "2000"},
        {"cpeName": exact, "isVulnerable": "", "startIndex": "0", "resultsPerPage": "2000"},
    ]
    assert [item.vulnerability.cve_id for item in versionless.findings] == [
        "CVE-2026-0001", "CVE-2026-0002"]
    prerequisite = versionless.findings[1]
    assert prerequisite.applicability is A.NEEDS_REVIEW
    assert prerequisite.reason == VERSION_UNKNOWN_REASON
    assert all(item.applicability is A.NEEDS_REVIEW and item.reason == VERSION_UNKNOWN_REASON
               for item in versionless.findings)
    only = versionless.findings[0]
    assert all("exact CPE name" not in item.statement for item in only.evidence if item.source == "nvd")
    assert [item.vulnerability.cve_id for item in versioned.findings] == ["CVE-2026-0003"]
    assert versioned.findings[0].applicability is A.AFFECTED


def test_nvd_product_wide_2001_total_stops_after_one_request(tmp_path):
    cpe = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
    calls = []

    def handler(request):
        calls.append(dict(request.url.params))
        return httpx.Response(200, json={
            "startIndex": 0, "resultsPerPage": 2000, "totalResults": 2001,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{number:04d}"}}
                                for number in range(1, 2001)]})

    engine, http = recording_engine(tmp_path, handler)
    try:
        engine.nvd.resolve_cpes = lambda asset: [CPECandidate(cpe, "", "a", "php", "php")]
        result = engine.query_asset(Asset("php", vendor="php", product="php"))
    finally:
        http.close()

    assert len(calls) == 1 and calls[0]["virtualMatchString"] == cpe
    assert "cpeName" not in calls[0] and "isVulnerable" not in calls[0]
    assert len(result.findings) == 2000
    assert result.coverage is A.COVERAGE_UNKNOWN
    assert any(health.source == "nvd" and health.status is H.DEGRADED
               and "result limit reached after 2000 CVEs" in health.message
               for health in result.source_health)


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


def test_state_stores_a_versionless_finding_and_counts_it(tmp_path):
    from cvebeacon.models import Finding, QueryResult
    from cvebeacon.state import StateStore

    asset = Asset("php", vendor="php", product="php", client="Acme")
    finding = Finding(asset, Vulnerability("CVE-2025-0001"), A.NEEDS_REVIEW, "limited",
                      VERSION_UNKNOWN_REASON, (nvd_evidence("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),))
    store = StateStore(tmp_path / "state.db")
    _, events = store.record_scan([QueryResult(asset, (finding,), (), A.NEEDS_REVIEW,
                                             VERSION_UNKNOWN_REASON)])
    assert len(events) == 1
    stored = store.latest_findings()[0]
    assert stored["asset"]["version"] == "" and stored["applicability"] == "needs_review"
    assert store.finding_summary(["php"]) == {"php": (1, None)}
