from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import httpx
import pytest
from openpyxl import load_workbook

from cvebeacon import backup, reporting
from cvebeacon.config import (
    AppConfig,
    HttpConfig,
    InventoryConfig,
    SourceConfig,
    load_config,
)
from cvebeacon.dashboard_config import source_effective_states
from cvebeacon.engine import QueryEngine
from cvebeacon.errors import ConfigurationError, SourceError
from cvebeacon.http import HttpClient
from cvebeacon.models import (
    Applicability,
    Asset,
    Finding,
    HealthStatus,
    QueryResult,
    Vulnerability,
)
from cvebeacon.sources import shodan_cvedb, vulncheck
from cvebeacon.sources.shodan_cvedb import CVEDBRecord
from cvebeacon.sources.vulncheck import VulnCheckSource
from cvebeacon.state import StateStore

from test_dashboard import setup
from test_dashboard_accounts import accounts, login


BASE = """
[inventory]
path = "inventory.csv"
[inventory.columns]
asset_id = "asset_id"
vendor = "vendor"
product = "product"
version = "version"
[state]
database = "state/state.db"
[output]
directory = "reports"
"""

CPE = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"
TOKEN = "SYNTHETIC-VULNCHECK-TOKEN"


def write_config(tmp_path: Path, extra: str = "", name: str = "config.toml") -> Path:
    path = tmp_path / name
    path.write_text(BASE + extra, encoding="utf-8", newline="\n")
    return path


def source_config(**overrides) -> SourceConfig:
    values = dict(
        osv_enabled=False,
        nvd_enabled=False,
        cve_enabled=False,
        euvd_enabled=False,
        cisa_kev_enabled=False,
        eu_kev_enabled=False,
        epss_enabled=False,
        vulncheck_enabled=True,
        shodan_cvedb_enabled=False,
    )
    values.update(overrides)
    return SourceConfig(**values)


def make_engine(tmp_path: Path, handler, *, sources: SourceConfig) -> QueryEngine:
    config = AppConfig(
        config_path=tmp_path / "config.toml",
        inventory=InventoryConfig(tmp_path / "inventory.csv"),
        database_path=tmp_path / "state.db",
        output_dir=tmp_path / "reports",
        http=HttpConfig(retries=0),
        sources=sources,
    )
    http = HttpClient(
        config.http,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=lambda _: None,
    )
    return QueryEngine(config, http=http)


def nvd_payload(*entries):
    return {
        "startIndex": 0,
        "resultsPerPage": len(entries),
        "totalResults": len(entries),
        "vulnerabilities": [{"cve": item} for item in entries],
    }


def nvd_cve(identifier: str, *, vulnerable: bool = True):
    return {
        "id": identifier,
        "descriptions": [{"lang": "en", "value": "Synthetic summary"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "version": "3.1",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [{"vulnerable": vulnerable, "criteria": CPE}],
                    }
                ]
            }
        ],
    }


def test_source_config_defaults_and_vulncheck_token_accessors(tmp_path, monkeypatch):
    config = load_config(write_config(tmp_path))
    assert config.sources.vulncheck_enabled is True
    assert config.sources.vulncheck_api_key_env == "VULNCHECK_API_TOKEN"
    assert config.sources.vulncheck_api_key_file is None
    assert config.sources.shodan_cvedb_enabled is False
    assert config.vulncheck_api_key() is None

    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    assert config.vulncheck_api_key() == TOKEN

    key = tmp_path / "vulncheck.token"
    key.write_text(TOKEN + "\n", encoding="utf-8")
    if os.name == "posix":
        key.chmod(0o600)
    path = write_config(
        tmp_path,
        f'\n[sources]\nvulncheck_api_key_file = "{key.name}"\n',
        name="file-config.toml",
    )
    monkeypatch.delenv("VULNCHECK_API_TOKEN")
    config = load_config(path)
    assert config.sources.vulncheck_api_key_file == key.resolve()
    assert config.vulncheck_api_key() == TOKEN


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_vulncheck_key_file_validation_matches_nvd_rules(tmp_path, monkeypatch):
    key = tmp_path / "vulncheck.token"
    key.write_text(TOKEN, encoding="utf-8")
    key.chmod(0o644)
    path = write_config(
        tmp_path,
        f'\n[sources]\nvulncheck_api_key_file = "{key.name}"\n',
        name="permissions.toml",
    )
    with pytest.raises(ConfigurationError, match="group or other accessible"):
        load_config(path)

    key.chmod(0o600)
    key.write_text("x" * (16 * 1024 + 1), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="at most 16384 bytes"):
        load_config(path)

    with pytest.raises(ConfigurationError, match="must be a nonempty path"):
        load_config(write_config(
            tmp_path,
            '\n[sources]\nvulncheck_api_key_file = "  "\n',
            name="blank-file.toml",
        ))
    with pytest.raises(ConfigurationError, match="vulncheck_api_key_env cannot be blank"):
        load_config(write_config(
            tmp_path,
            '\n[sources]\nvulncheck_api_key_env = ""\n',
            name="blank-env.toml",
        ))


def test_settings_effective_states_never_include_the_token(tmp_path, monkeypatch):
    config = load_config(write_config(tmp_path))
    assert source_effective_states(config)["shodan_cvedb"] == "off: disabled"
    assert source_effective_states(config)["vulncheck"] == "off: no token"

    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    states = source_effective_states(config)
    assert states["vulncheck"] == "on"
    assert TOKEN not in json.dumps(states)

    path = write_config(
        tmp_path,
        "\n[sources]\nvulncheck_enabled = false\nshodan_cvedb_enabled = true\n",
        name="disabled.toml",
    )
    states = source_effective_states(load_config(path))
    assert states["vulncheck"] == "off: disabled"
    assert states["shodan_cvedb"] == "on"


@pytest.fixture
def settings_accounts(accounts):
    accounts[0].config_path.chmod(0o644)
    return accounts


def test_settings_page_shows_source_states_and_never_the_token(settings_accounts, monkeypatch):
    config, users, app, client = settings_accounts
    login(client, "admin")
    page = client.get("/config/sources")
    assert page.status_code == 200
    assert "off: no token" in page.text
    assert "VulnCheck needs an API token" in page.text
    assert "cvedb.shodan.io" in page.text
    assert "terms of use" in page.text
    assert TOKEN not in page.text

    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    page = client.get("/config/sources")
    assert page.status_code == 200
    assert "VulnCheck KEV: <strong>on</strong>" in page.text
    assert TOKEN not in page.text


def test_vulncheck_parser_and_oversize_download(tmp_path, monkeypatch):
    payload = {
        "data": [
            {
                "cve": ["CVE-2026-0001", "CVE-2026-0002"],
                "date_added": "2026-01-02",
                "ransomware": True,
                "reported_exploited": ["https://example.test/one"],
                "exploit_references": [
                    "https://example.test/one",
                    {"url": "https://example.test/two"},
                ],
            }
        ]
    }
    items = VulnCheckSource.parse(payload)
    evidence = items["CVE-2026-0001"]
    assert evidence.details["date_added"] == "2026-01-02"
    assert evidence.details["ransomware"] is True
    assert evidence.details["reported_exploited"] == 1
    assert evidence.details["exploit_references"] == [
        "https://example.test/one",
        "https://example.test/two",
    ]

    monkeypatch.setattr(vulncheck, "MAX_BYTES", 32)
    http = HttpClient(
        HttpConfig(retries=0),
        client=httpx.Client(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"x" * 64)
        )),
        sleep=lambda _: None,
    )
    with pytest.raises(SourceError, match="size limit"):
        VulnCheckSource(http).kev(TOKEN)


def test_vulncheck_enrichment_and_badge_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    calls = []

    def handler(request):
        url = str(request.url)
        calls.append(url)
        if "api.vulncheck.com" in url:
            assert request.headers.get("Authorization") == f"Bearer {TOKEN}"
            return httpx.Response(200, json={
                "data": [{
                    "cve": ["CVE-2026-0001"],
                    "date_added": "2026-01-02",
                    "ransomware": True,
                    "reported_exploited": ["https://example.test/report"],
                    "exploit_references": ["https://example.test/exploit"],
                }]
            })
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(nvd_enabled=True))
    try:
        result = engine.query_asset(Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finally:
        engine.close()
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert finding.vulnerability.vulncheck_kev is True
    assert finding.vulnerability.vulncheck_date_added == "2026-01-02"
    assert finding.vulnerability.vulncheck_ransomware is True
    assert finding.vulnerability.vulncheck_reported_exploits == 1
    assert finding.vulnerability.vulncheck_exploit_references == 2
    evidence = next(item for item in finding.evidence if item.source == "vulncheck")
    assert evidence.details["exploit_references"] == [
        "https://example.test/exploit", "https://example.test/report"
    ]
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.OK and health.message.startswith("on")
    assert calls


def test_vulncheck_without_token_sends_no_request(tmp_path, monkeypatch):
    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if "services.nvd.nist.gov" in str(request.url):
            return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))
        raise AssertionError(f"unexpected request {request.url}")

    engine = make_engine(tmp_path, handler, sources=source_config(nvd_enabled=True))
    try:
        result = engine.query_asset(Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finally:
        engine.close()
    assert not any("vulncheck" in url for url in calls)
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.DISABLED
    assert health.message.startswith("off: no token")
    assert "skipped: no token" in health.message


def test_vulncheck_failure_degrades_only_its_health(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(500)
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(nvd_enabled=True))
    try:
        result = engine.query_asset(Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finally:
        engine.close()
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.FAILED and health.message.startswith("on;")
    assert next(item for item in result.source_health if item.source == "nvd").status == HealthStatus.OK
    assert any(item.applicability == Applicability.AFFECTED for item in result.findings)


def test_cvedb_disabled_sends_no_request(tmp_path):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=False),
    )
    try:
        result = engine.query_asset(Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finally:
        engine.close()
    assert not any("cvedb" in url for url in calls)
    health = next(item for item in result.source_health if item.source == "shodan_cvedb")
    assert health.status == HealthStatus.DISABLED and health.message == "off: disabled"


def test_cvedb_discovery_is_needs_review_and_never_upgrades_nvd(tmp_path):
    def run(cvedb_enabled):
        def handler(request):
            url = str(request.url)
            if "cvedb.shodan.io/cves" in url:
                return httpx.Response(200, json={
                    "cves": [{"cve_id": "CVE-2026-0001", "summary": "CVEDB view", "cvss": 7.5}],
                    "total": 1,
                })
            if "cvedb.shodan.io/cve/" in url:
                return httpx.Response(200, json={"cve_id": "CVE-2026-0001", "kev": True, "ransomware": True})
            return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001", vulnerable=False)))

        engine = make_engine(
            tmp_path, handler,
            sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=cvedb_enabled),
        )
        try:
            result = engine.query_asset(Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
        finally:
            engine.close()
        return next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")

    baseline = run(False)
    with_cvedb = run(True)
    assert baseline.applicability == Applicability.NEEDS_REVIEW
    assert with_cvedb.applicability == baseline.applicability
    assert with_cvedb.reason == baseline.reason

    def discovery_only(request):
        url = str(request.url)
        if "cvedb.shodan.io/cves" in url:
            return httpx.Response(200, json={
                "cves": [{"cve_id": "CVE-2026-0009", "summary": "Only CVEDB", "cvss": 5.0}],
                "total": 1,
            })
        if "cvedb.shodan.io/cve/" in url:
            return httpx.Response(404)
        return httpx.Response(200, json=nvd_payload())

    engine = make_engine(
        tmp_path, discovery_only,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True),
    )
    try:
        result = engine.query_asset(Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finally:
        engine.close()
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0009")
    assert finding.applicability == Applicability.NEEDS_REVIEW
    assert finding.reason == "reported by Shodan CVEDB only; confirm applicability"
    assert finding.vulnerability.shodan_cvedb_kev is None


def test_cvedb_enrichment_and_lookup_cap(tmp_path):
    def handler(request):
        url = str(request.url)
        if "cvedb.shodan.io/cves" in url:
            return httpx.Response(200, json={"cves": [], "total": 0})
        if "/CVE-2026-0001" in url:
            return httpx.Response(200, json={
                "cve_id": "CVE-2026-0001",
                "kev": True,
                "ransomware": True,
                "epss": 0.91,
                "ranking_epss": 0.99,
                "references": ["https://example.test/advisory"],
            })
        if "services.nvd.nist.gov" in url:
            return httpx.Response(200, json=nvd_payload(
                nvd_cve("CVE-2026-0001"), nvd_cve("CVE-2026-0002")
            ))
        return httpx.Response(404)

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True,
                              cisa_kev_enabled=False, eu_kev_enabled=False),
    )
    engine.cvedb.lookup_cap = 1
    try:
        result = engine.query_asset(Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finally:
        engine.close()
    health = next(item for item in result.source_health if item.source == "shodan_cvedb")
    assert health.status == HealthStatus.DEGRADED
    assert "lookup cap reached" in health.message
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    evidence = next(item for item in finding.evidence if item.source == "shodan_cvedb")
    assert evidence.details["kev"] is True
    assert evidence.details["epss"] == 0.91
    assert evidence.details["epss_percentile"] == 0.99


def test_cvedb_discovery_truncation_degrades_health(tmp_path, monkeypatch):
    monkeypatch.setattr(shodan_cvedb, "MAX_PAGES", 1)

    def handler(request):
        url = str(request.url)
        if "/cves" in url:
            return httpx.Response(200, json={
                "cves": [{"cve_id": f"CVE-2026-{index:04d}"} for index in range(100)],
                "total": 600,
            })
        if "/cve/" in url:
            return httpx.Response(404)
        return httpx.Response(200, json=nvd_payload())

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True),
    )
    engine.cvedb.lookup_cap = 0
    try:
        result = engine.query_asset(Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finally:
        engine.close()
    health = next(item for item in result.source_health if item.source == "shodan_cvedb")
    assert health.status == HealthStatus.DEGRADED
    assert "results truncated" in health.message


def test_findings_badge_is_escaped_and_kev_filter_works(setup):
    _, store, client = setup
    asset = Asset("a", "Acme", "Widget", "1")
    vuln = Vulnerability(
        "CVE-2026-1234",
        vulncheck_kev=True,
        vulncheck_date_added="<script>alert(1)</script>",
        vulncheck_ransomware=True,
        vulncheck_reported_exploits=2,
    )
    store.record_scan([QueryResult(
        asset,
        (Finding(asset, vuln, Applicability.NEEDS_REVIEW, "limited", "test"),),
        (),
    )])
    page = client.get("/findings")
    assert page.status_code == 200
    assert "VulnCheck KEV" in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "<script>alert(1)</script>" not in page.text
    filtered = client.get("/findings?vulncheck=yes")
    assert filtered.status_code == 200 and "CVE-2026-1234" in filtered.text
    missing = client.get("/findings?vulncheck=no")
    assert "CVE-2026-1234" not in missing.text


def test_exports_include_vulncheck_fields(tmp_path):
    asset = Asset("a", "Acme", "Widget", "1")
    vuln = Vulnerability(
        "CVE-2026-1234",
        vulncheck_kev=True,
        vulncheck_date_added="2026-01-02",
        vulncheck_ransomware=False,
        vulncheck_reported_exploits=2,
        vulncheck_exploit_references=3,
    )
    result = QueryResult(
        asset,
        (Finding(asset, vuln, Applicability.AFFECTED, "high", "test"),),
        (),
    )
    json_path = reporting.write_json([result], tmp_path / "report.json")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    stored = payload[0]["findings"][0]["vulnerability"]
    assert stored["vulncheck_kev"] is True
    assert stored["vulncheck_date_added"] == "2026-01-02"
    assert stored["vulncheck_reported_exploits"] == 2
    assert stored["vulncheck_exploit_references"] == 3

    xlsx_path = reporting.write_xlsx([result], tmp_path / "report.xlsx")
    workbook = load_workbook(xlsx_path, read_only=True)
    rows = list(workbook["Findings"].iter_rows(values_only=True))
    headers = rows[0]
    assert "VulnCheck KEV" in headers
    row = rows[1]
    assert row[headers.index("VulnCheck KEV")] is True
    assert row[headers.index("VulnCheck Date Added")] == "2026-01-02"


def test_cvedb_record_parser_and_identity_mismatch():
    record = shodan_cvedb.parse_record({
        "cve_id": "CVE-2026-0001",
        "summary": "Test",
        "cvss": 8.1,
        "cvss_version": "3.1",
        "kev": "true",
        "ransomware": "false",
        "epss": "0.5",
        "ranking_epss": "0.9",
        "references": [{"url": "https://example.test/a"}],
    })
    assert record == CVEDBRecord(
        "CVE-2026-0001", "Test", None, 8.1, None, "3.1", True, False, 0.5, 0.9,
        ("https://example.test/a",),
    )
    with pytest.raises(SourceError, match="identity mismatch"):
        shodan_cvedb.parse_record({"cve_id": "CVE-2026-0002"}, expected="CVE-2026-0001")


def test_secret_never_reaches_logs_exports_state_or_backup(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    caplog.set_level(logging.DEBUG)

    def handler(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(200, json={"data": [{"cve": "CVE-2026-0001",
                                                       "date_added": "2026-01-02"}]})
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(nvd_enabled=True))
    try:
        result = engine.query_asset(Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finally:
        engine.close()
    assert TOKEN not in caplog.text
    assert TOKEN not in json.dumps([item.to_dict() for item in [result]])

    store = StateStore(engine.config.database_path)
    store.record_scan([result])
    assert TOKEN.encode() not in Path(engine.config.database_path).read_bytes()

    export = reporting.write_json([result], tmp_path / "report.json")
    assert TOKEN not in export.read_text(encoding="utf-8")
    xlsx = reporting.write_xlsx([result], tmp_path / "report.xlsx")
    assert TOKEN.encode() not in xlsx.read_bytes()

    config_path = tmp_path / "config.toml"
    key = tmp_path / "vulncheck.token"
    key.write_text(TOKEN, encoding="utf-8")
    if os.name == "posix":
        key.chmod(0o600)
    config_path.write_text(
        BASE + f'\n[sources]\nvulncheck_api_key_file = "{key.name}"\n',
        encoding="utf-8",
        newline="\n",
    )
    config = load_config(config_path)
    created = backup.create(config)
    archive = backup.build_archive(config, created.id)
    try:
        assert TOKEN.encode() not in archive.read()
    finally:
        archive.close()
