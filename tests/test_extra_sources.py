from __future__ import annotations

import gzip
import json
import logging
import os
import re
import threading
from dataclasses import replace
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
    Evidence,
    Finding,
    HealthStatus,
    QueryResult,
    SourceHealth,
    Vulnerability,
    utc_now,
)
from cvebeacon.optional_sources import CVEDB_ONLY_REASON
from cvebeacon.sources import shodan_cvedb, vulncheck
from cvebeacon.sources.osv import OSVResult
from cvebeacon.sources.shodan_cvedb import CVEDBRecord, ShodanCVEDBSource
from cvebeacon.sources.vulncheck import VulnCheckSource
from cvebeacon.state import StateStore, material_fingerprint

from test_dashboard import post, setup
from test_dashboard_accounts import accounts, login
from test_osv import record as osv_record


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
        vulncheck_enabled=False,
        shodan_cvedb_enabled=False,
    )
    values.update(overrides)
    return SourceConfig(**values)


def make_engine(tmp_path: Path, handler, *, sources: SourceConfig, retries: int = 0) -> QueryEngine:
    config = AppConfig(
        config_path=tmp_path / "config.toml",
        inventory=InventoryConfig(tmp_path / "inventory.csv"),
        database_path=tmp_path / "state.db",
        output_dir=tmp_path / "reports",
        http=HttpConfig(retries=retries),
        sources=sources,
    )
    http = HttpClient(
        config.http,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=lambda _: None,
    )
    return QueryEngine(config, http=http)


def make_http(handler, *, retries: int = 0) -> HttpClient:
    return HttpClient(
        HttpConfig(retries=retries),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=lambda _: None,
    )


def scan(engine: QueryEngine, asset: Asset, *, known_findings=()):
    try:
        return engine.scan([asset], known_findings=known_findings)[0]
    finally:
        engine.close()


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


def vulncheck_entry(identifier: str, **overrides):
    entry = {
        "cve": [identifier],
        "date_added": "2026-01-02T00:00:00Z",
        "knownRansomwareCampaignUse": "Known",
        "vulncheck_xdb": [],
        "vulncheck_reported_exploitation": [],
    }
    entry.update(overrides)
    return entry


def vulncheck_page(entries, *, total=None, next_cursor=None, truncated=None, limit=100):
    meta = {"limit": limit}
    if total is not None:
        meta["total_documents"] = total
    if next_cursor is not None:
        meta["next_cursor"] = next_cursor
    if truncated is not None:
        meta["truncated"] = truncated
    return {"data": entries, "_meta": meta}


def cve_list_record(identifier: str, *, status: str = "unaffected", version: str = "1.0"):
    return {
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": identifier, "state": "PUBLISHED"},
        "containers": {"cna": {"affected": [{
            "vendor": "Acme", "product": "Widget",
            "versions": [{"version": version, "status": status}],
        }]}},
    }


def cvedb_rows(start: int, count: int):
    return [
        {"cve_id": f"CVE-2026-{index:04d}", "summary": f"CVEDB row {index}"}
        for index in range(start, start + count)
    ]


def authoritative_prior(identifier: str = "CVE-2026-0001") -> dict:
    return {
        "asset": {
            "asset_id": "a", "vendor": "Acme", "product": "Widget", "version": "1.0",
            "category": "", "system_id": "", "ecosystem": "", "purl": "", "cpe": CPE,
            "repository": "", "commit": "", "client": "",
        },
        "vulnerability": {"cve_id": identifier, "advisory_id": identifier},
        "applicability": "needs_review",
        "reason": "prior authoritative finding",
    }


CORE_SOURCES = {"nvd", "cve_list", "euvd", "cisa_kev", "eu_kev", "epss", "osv"}
OPTIONAL_SOURCES = {"vulncheck", "shodan_cvedb"}


def core_view(result: dict) -> dict:
    """Strip optional-source rows, metadata and evidence from a result dict."""
    value = json.loads(json.dumps(result))
    value["source_health"] = [
        row for row in value["source_health"] if row["source"] not in OPTIONAL_SOURCES
    ]
    for row in value["source_health"]:
        row["checked_at"] = None
        row["freshness_at"] = None
    findings = []
    for finding in value["findings"]:
        for item in finding["evidence"]:
            item["retrieved_at"] = None
        vulnerability = finding["vulnerability"]
        for key in list(vulnerability):
            if key.startswith(("vulncheck", "shodan_cvedb")):
                vulnerability.pop(key)
        finding["evidence"] = [
            item for item in finding["evidence"] if item["source"] not in OPTIONAL_SOURCES
        ]
        findings.append(finding)
    value["findings"] = findings
    return value


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


def test_vulncheck_paginates_with_cursors_and_parses_documented_fields():
    calls = []
    first = vulncheck_page(
        [vulncheck_entry(
            "CVE-2026-0001",
            knownRansomwareCampaignUse="Known",
            vulncheck_xdb=[
                {"xdb_url": "https://example.test/xdb/one"},
                {"xdb_url": "https://example.test/xdb/two"},
            ],
            vulncheck_reported_exploitation=[
                {"url": "https://example.test/report/one", "date_added": "2026-01-03"},
            ],
        )],
        total=2, next_cursor="page-2",
    )
    second = vulncheck_page(
        [vulncheck_entry("CVE-2026-0002", knownRansomwareCampaignUse="Unknown")],
        total=2,
    )

    def handler(request):
        assert request.headers.get("Authorization") == f"Bearer {TOKEN}"
        calls.append(dict(request.url.params))
        return httpx.Response(200, json=first if len(calls) == 1 else second)

    items = VulnCheckSource(make_http(handler)).kev(TOKEN)
    assert calls == [
        {"limit": "100", "start_cursor": "true"},
        {"limit": "100", "cursor": "page-2"},
    ]
    first_evidence = items["CVE-2026-0001"]
    assert first_evidence.source_timestamp == "2026-01-02T00:00:00Z"
    assert first_evidence.details["ransomware"] is True
    assert first_evidence.details["exploit_references"] == [
        "https://example.test/xdb/one", "https://example.test/xdb/two",
    ]
    assert first_evidence.details["reported_exploited"] == 1
    assert first_evidence.details["reported_exploitation"] == [
        {"url": "https://example.test/report/one", "date_added": "2026-01-03"},
    ]
    assert items["CVE-2026-0002"].details["ransomware"] is False


@pytest.mark.parametrize("payload", [
    {"data": [], "_meta": {"limit": "100", "total_documents": 0}},
    {"data": [], "_meta": {"limit": 50, "total_documents": 0}},
    {"data": [], "_meta": {"limit": 100}},
    {"data": [], "_meta": {"limit": 100, "total_documents": "0"}},
    {"data": [], "_meta": {"limit": 100, "total_documents": 0, "truncated": "yes"}},
    {"data": [vulncheck_entry("CVE-2026-0001"), vulncheck_entry("CVE-2026-0002")],
     "_meta": {"limit": 100, "total_documents": 1}},
])
def test_vulncheck_malformed_metadata_is_a_source_error(payload):
    handler = lambda request: httpx.Response(200, json=payload)
    with pytest.raises(SourceError, match="malformed data"):
        VulnCheckSource(make_http(handler)).kev(TOKEN)


def test_vulncheck_empty_catalog_requires_valid_terminal_metadata():
    valid = lambda request: httpx.Response(200, json=vulncheck_page([], total=0))
    assert VulnCheckSource(make_http(valid)).kev(TOKEN) == {}
    missing_total = lambda request: httpx.Response(
        200, json={"data": [], "_meta": {"limit": 100}}
    )
    with pytest.raises(SourceError, match="malformed data"):
        VulnCheckSource(make_http(missing_total)).kev(TOKEN)


def test_vulncheck_incomplete_page_is_a_source_error_and_keeps_membership_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(200, json=vulncheck_page(
                [vulncheck_entry("CVE-2026-0002")], total=2, truncated=True,
            ))
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(
        nvd_enabled=True, vulncheck_enabled=True,
    ))
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.FAILED
    assert "complete catalog" in health.message
    assert TOKEN not in health.message
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert finding.vulnerability.vulncheck_kev is None
    assert "vulncheck_kev" not in finding.to_dict()["vulnerability"]


def test_vulncheck_rejects_repeated_cursor_and_budgets(monkeypatch):
    def repeated(request):
        return httpx.Response(200, json=vulncheck_page([], next_cursor="same"))

    with pytest.raises(SourceError, match="complete catalog"):
        VulnCheckSource(make_http(repeated)).kev(TOKEN)

    missing_meta = lambda request: httpx.Response(200, json={"data": []})
    with pytest.raises(SourceError, match="malformed data"):
        VulnCheckSource(make_http(missing_meta)).kev(TOKEN)

    oversized_page = lambda request: httpx.Response(200, json=vulncheck_page(
        [vulncheck_entry(f"CVE-2026-{index:04d}") for index in range(101)], total=101,
    ))
    with pytest.raises(SourceError, match="malformed data"):
        VulnCheckSource(make_http(oversized_page)).kev(TOKEN)

    monkeypatch.setattr(vulncheck, "MAX_PAGES", 1)
    endless = lambda request: httpx.Response(200, json=vulncheck_page(
        [], next_cursor="next", total=2,
    ))
    with pytest.raises(SourceError, match="complete catalog"):
        VulnCheckSource(make_http(endless)).kev(TOKEN)
    monkeypatch.undo()

    monkeypatch.setattr(vulncheck, "MAX_ENTRIES", 1)
    two_entries = lambda request: httpx.Response(200, json=vulncheck_page(
        [vulncheck_entry("CVE-2026-0001"), vulncheck_entry("CVE-2026-0002")], total=2,
    ))
    with pytest.raises(SourceError, match="complete catalog"):
        VulnCheckSource(make_http(two_entries)).kev(TOKEN)
    monkeypatch.undo()

    monkeypatch.setattr(vulncheck, "MAX_BYTES", 32)
    with pytest.raises(SourceError, match="size limit"):
        VulnCheckSource(make_http(
            lambda request: httpx.Response(200, content=b"{" + b"x" * 64)
        )).kev(TOKEN)
    monkeypatch.undo()

    mismatch = lambda request: httpx.Response(200, json=vulncheck_page(
        [vulncheck_entry("CVE-2026-0001")], total=2,
    ))
    with pytest.raises(SourceError, match="complete catalog"):
        VulnCheckSource(make_http(mismatch)).kev(TOKEN)


def test_vulncheck_rejects_token_in_cursor_before_using_it(caplog):
    calls = []

    def handler(request):
        calls.append(dict(request.url.params))
        return httpx.Response(200, json=vulncheck_page(
            [vulncheck_entry("CVE-2026-0001")],
            total=2,
            next_cursor=f"cursor-{TOKEN}",
        ))

    source = VulnCheckSource(make_http(handler))
    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("httpcore").setLevel(logging.INFO)
    caplog.set_level(logging.INFO)
    with pytest.raises(SourceError) as caught:
        source.kev(TOKEN)
    assert str(caught.value) == "vulncheck: KEV index reflected a credential in retained data"
    assert len(calls) == 1
    assert TOKEN not in str(caught.value)
    assert TOKEN not in caplog.text
    assert logging.getLogger("httpx").level == logging.INFO
    assert logging.getLogger("httpcore").level == logging.INFO


def test_vulncheck_rejects_reflected_token_without_echoing_it():
    def handler(request):
        return httpx.Response(200, json=vulncheck_page([
            vulncheck_entry(
                "CVE-2026-0001",
                vulncheck_xdb=[{"xdb_url": f"https://example.test/{TOKEN}/xdb"}],
            ),
        ], total=1))

    with pytest.raises(SourceError) as caught:
        VulnCheckSource(make_http(handler)).kev(TOKEN)
    assert str(caught.value) == "vulncheck: KEV index reflected a credential in retained data"
    assert TOKEN not in str(caught.value)


def test_reflected_success_response_retains_no_token(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(
                200,
                extensions={"reason_phrase": f"OK for {TOKEN}".encode("ascii")},
                json=vulncheck_page([
                    vulncheck_entry(
                        "CVE-2026-0001",
                        vulncheck_reported_exploitation=[
                            {"url": f"https://example.test/{TOKEN}/report"},
                        ],
                    ),
                ], total=1),
            )
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(
        nvd_enabled=True, vulncheck_enabled=True,
    ))
    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("httpcore").setLevel(logging.INFO)
    caplog.set_level(logging.INFO)
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.FAILED
    assert TOKEN not in health.message
    assert TOKEN not in caplog.text
    assert logging.getLogger("httpx").level == logging.INFO
    assert logging.getLogger("httpcore").level == logging.INFO
    assert TOKEN not in json.dumps([result.to_dict()])
    store = StateStore(engine.config.database_path)
    store.record_scan([result])
    assert TOKEN.encode() not in Path(engine.config.database_path).read_bytes()
    export = reporting.write_json(
        [result], tmp_path / "reflected.json", vulncheck=True, cvedb=True,
    )
    assert TOKEN not in export.read_text(encoding="utf-8")


def test_vulncheck_complete_empty_catalog_sets_false_membership(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(200, json=vulncheck_page([], total=0))
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(
        nvd_enabled=True, vulncheck_enabled=True,
    ))
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert finding.vulnerability.vulncheck_kev is False
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.OK


def test_vulncheck_enrichment_and_badge_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    calls = []

    def handler(request):
        url = str(request.url)
        calls.append(url)
        if "api.vulncheck.com" in url:
            assert request.headers.get("Authorization") == f"Bearer {TOKEN}"
            return httpx.Response(200, json=vulncheck_page([
                vulncheck_entry(
                    "CVE-2026-0001",
                    vulncheck_xdb=[{"xdb_url": "https://example.test/exploit"}],
                    vulncheck_reported_exploitation=[
                        {"url": "https://example.test/report", "date_added": "2026-01-03"},
                    ],
                ),
            ], total=1))
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(
        nvd_enabled=True, vulncheck_enabled=True,
    ))
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert finding.vulnerability.vulncheck_kev is True
    assert finding.vulnerability.vulncheck_date_added == "2026-01-02T00:00:00Z"
    assert finding.vulnerability.vulncheck_ransomware is True
    assert finding.vulnerability.vulncheck_reported_exploits == 1
    assert finding.vulnerability.vulncheck_exploit_references == 1
    evidence = next(item for item in finding.evidence if item.source == "vulncheck")
    assert evidence.details["exploit_references"] == ["https://example.test/exploit"]
    assert evidence.details["reported_exploitation"][0]["url"] == "https://example.test/report"
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

    engine = make_engine(tmp_path, handler, sources=source_config(
        nvd_enabled=True, vulncheck_enabled=True,
    ))
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    assert not any("vulncheck" in url for url in calls)
    assert not any(item.source == "vulncheck" for item in result.source_health)
    assert not any(key.startswith("vulncheck") for key in result.findings[0].to_dict()["vulnerability"])
    store = StateStore(engine.config.database_path)
    store.record_scan([result])
    stored = store.latest_findings()[0]["vulnerability"]
    assert not any(key.startswith("vulncheck") for key in stored)


def test_vulncheck_failure_degrades_only_its_health(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(500)
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(
        nvd_enabled=True, vulncheck_enabled=True,
    ))
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.FAILED and health.message.startswith("on;")
    assert next(item for item in result.source_health if item.source == "nvd").status == HealthStatus.OK
    assert any(item.applicability == Applicability.AFFECTED for item in result.findings)


def test_vulncheck_recursion_error_keeps_core_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    decode = vulncheck.json.loads

    def decoder(raw, *args, **kwargs):
        if raw == b"RECURSION":
            raise RecursionError("synthetic nesting")
        return decode(raw, *args, **kwargs)

    monkeypatch.setattr(vulncheck.json, "loads", decoder)

    def handler(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(200, content=b"RECURSION")
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    with pytest.raises(SourceError) as caught:
        VulnCheckSource(make_http(handler)).kev(TOKEN)
    assert str(caught.value) == "vulncheck: KEV index returned malformed data"

    engine = make_engine(tmp_path, handler, sources=source_config(
        nvd_enabled=True, vulncheck_enabled=True,
    ))
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.FAILED
    assert health.message == "on; vulncheck: KEV index returned malformed data"
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert finding.applicability == Applicability.AFFECTED
    assert finding.vulnerability.vulncheck_kev is None


def test_vulncheck_fields_do_not_change_legacy_material_fingerprint():
    asset = Asset("a", "Acme", "Widget", "1.0")
    common = dict(
        summary="Synthetic summary", cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_version="3.1", cisa_kev=True, eu_kev=False,
    )
    evidence = (
        Evidence("cve_list", "cna", "statement", details={
            "state": "PUBLISHED", "affected": [{"vendor": "Acme", "product": "Widget"}],
        }),
        Evidence("vulncheck", "known_exploitation", "statement", details={
            "date_added": "2026-01-02", "ransomware": True,
            "reported_exploited": 2,
            "exploit_references": ["https://example.test/xdb"],
        }),
    )
    before = Finding(
        asset, Vulnerability("CVE-2026-0001", **common), Applicability.AFFECTED,
        "high", "reason", evidence,
    )
    after = Finding(
        asset, Vulnerability(
            "CVE-2026-0001", **common, vulncheck_kev=True,
            vulncheck_date_added="2026-01-02", vulncheck_ransomware=True,
            vulncheck_reported_exploits=2, vulncheck_exploit_references=1,
            shodan_cvedb_kev=True,
        ), Applicability.AFFECTED, "high", "reason", evidence,
    )
    assert material_fingerprint(before) == material_fingerprint(after)
    assert material_fingerprint(after) == "adcc90934ef62903d0d94768fd8a3ed9f7c1e97d6b98325c4b781bcb287f5640"


def test_vulncheck_enriches_package_findings_as_evidence_only(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def run(entries):
        def handler(request):
            if "api.vulncheck.com" in str(request.url):
                return httpx.Response(200, json=vulncheck_page(entries, total=len(entries)))
            raise AssertionError(f"unexpected request {request.url}")

        engine = make_engine(tmp_path, handler, sources=source_config(
            osv_enabled=True, vulncheck_enabled=True,
        ))
        record_data = osv_record()
        engine.osv.query_many = lambda assets: {
            asset.target_key: OSVResult(
                (record_data,), None, frozenset({record_data["id"]})
            )
            for asset in assets
        }
        return scan(engine, Asset("a", purl="pkg:pypi/example@1.0.0"))

    matched = run([vulncheck_entry(
        "CVE-2026-1234",
        vulncheck_xdb=[{"xdb_url": "https://example.test/package-xdb"}],
        vulncheck_reported_exploitation=[
            {"url": "https://example.test/package-report", "date_added": "2026-01-03"},
        ],
    )])
    finding = matched.findings[0]
    assert finding.applicability == Applicability.AFFECTED
    assert finding.vulnerability.vulncheck_kev is True
    assert finding.vulnerability.vulncheck_reported_exploits == 1
    evidence = next(item for item in finding.evidence if item.source == "vulncheck")
    assert evidence.details["exploit_references"] == ["https://example.test/package-xdb"]

    absent = run([])
    finding = absent.findings[0]
    assert finding.applicability == Applicability.AFFECTED
    assert finding.vulnerability.vulncheck_kev is False


def test_cvedb_disabled_sends_no_request(tmp_path):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=False),
    )
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    assert not any("cvedb" in url for url in calls)
    assert not any(item.source == "shodan_cvedb" for item in result.source_health)


def test_cvedb_discovery_requests_count_then_pages(tmp_path):
    calls = []
    rows = cvedb_rows(1, 125)

    def handler(request):
        url = str(request.url)
        if "cvedb.shodan.io/cves" in url:
            calls.append(dict(request.url.params))
            params = request.url.params
            if params.get("count") == "true":
                return httpx.Response(200, json={"total": 125})
            skip = int(params["skip"])
            limit = int(params["limit"])
            return httpx.Response(200, json={"cves": rows[skip:skip + limit]})
        return httpx.Response(200, json=nvd_payload())

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True),
    )
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    assert calls[0].get("count") == "true"
    assert calls[1]["skip"] == "0" and calls[1]["limit"] == "100"
    assert calls[2]["skip"] == "100" and calls[2]["limit"] == "100"
    assert len(result.findings) == 125
    assert all(item.applicability == Applicability.NEEDS_REVIEW for item in result.findings)
    assert all(item.reason == CVEDB_ONLY_REASON for item in result.findings)
    health = next(item for item in result.source_health if item.source == "shodan_cvedb")
    assert health.status == HealthStatus.OK
    assert "125 CVE results for the exact CPE" in health.message


def test_cvedb_discovery_marks_over_limit_duplicates_and_invalid_counts():
    def count_and_pages(total, page_rows):
        def handler(request):
            params = request.url.params
            if params.get("count") == "true":
                return httpx.Response(200, json={"total": total})
            if "cvedb.shodan.io/cves" not in str(request.url):
                return httpx.Response(404)
            skip = int(params["skip"])
            return httpx.Response(200, json={"cves": page_rows(skip)})
        return handler

    over = ShodanCVEDBSource(make_http(
        count_and_pages(600, lambda skip: cvedb_rows(skip + 1, 100))
    ))
    result = over.discover(CPE)
    assert len(result.records) == 500
    assert result.degraded is True
    assert "exceeds the 500 result limit" in (result.message or "")
    assert over.discovery_requests == 6

    duplicate = ShodanCVEDBSource(make_http(
        count_and_pages(3, lambda skip: cvedb_rows(1, 2) if skip == 0 else cvedb_rows(1, 1))
    ))
    result = duplicate.discover(CPE)
    assert result.degraded is True
    assert "incomplete or duplicated" in (result.message or "")

    invalid = ShodanCVEDBSource(make_http(
        lambda request: httpx.Response(200, json={"total": -1})
    ))
    result = invalid.discover(CPE)
    assert result.records == {}
    assert result.degraded is True
    assert "invalid discovery total" in (result.message or "")


def test_cvedb_discovery_request_cap_and_search_404():
    def empty_count(request):
        return httpx.Response(200, json={"total": 0})

    source = ShodanCVEDBSource(make_http(empty_count), discovery_request_cap=1)
    assert source.discover(CPE).degraded is False
    capped = source.discover("cpe:2.3:a:acme:gadget:1.0:*:*:*:*:*:*:*")
    assert capped.degraded is True
    assert capped.message == "discovery request cap reached"

    not_found = ShodanCVEDBSource(make_http(lambda request: httpx.Response(404)))
    with pytest.raises(SourceError) as caught:
        not_found.discover(CPE)
    assert caught.value.status_code == 404


def test_cvedb_discovery_retries_are_charged_to_the_budget():
    attempts = []

    def handler(request):
        params = request.url.params
        if params.get("count") == "true":
            attempts.append("count")
            return httpx.Response(200, json={"total": 1})
        attempts.append("page")
        if len(attempts) == 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"cves": cvedb_rows(1, 1)})

    limited = ShodanCVEDBSource(
        make_http(handler, retries=1), discovery_request_cap=2
    )
    result = limited.discover(CPE)
    assert result.degraded is True
    assert "discovery request cap reached" in (result.message or "")
    assert limited.discovery_requests == 2
    assert attempts == ["count", "page"]

    attempts.clear()

    def retrying(request):
        params = request.url.params
        if params.get("count") == "true":
            attempts.append("count")
            return httpx.Response(200, json={"total": 1})
        attempts.append("page")
        if len(attempts) == 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"cves": cvedb_rows(1, 1)})

    allowed = ShodanCVEDBSource(
        make_http(retrying, retries=1), discovery_request_cap=3
    )
    result = allowed.discover(CPE)
    assert result.degraded is False
    assert len(result.records) == 1
    assert allowed.discovery_requests == 3
    assert attempts == ["count", "page", "page"]


def test_cvedb_discovery_failure_degrades_health(tmp_path):
    def handler(request):
        if "cvedb.shodan.io/cves" in str(request.url):
            return httpx.Response(404)
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True),
    )
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    health = next(item for item in result.source_health if item.source == "shodan_cvedb")
    assert health.status == HealthStatus.FAILED
    assert "HTTP 404" in health.message
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert finding.applicability == Applicability.AFFECTED


def test_cvedb_lookup_cap_is_reported():
    source = ShodanCVEDBSource(
        make_http(lambda request: httpx.Response(200, json={
            "cve_id": str(request.url).rsplit("/", 1)[-1],
        })),
        lookup_cap=1,
    )
    assert source.lookup("CVE-2026-0001") is not None
    assert source.lookup("CVE-2026-0002") is None
    assert source.cap_reached is True


def test_cvedb_per_cve_404_is_no_record(tmp_path):
    def handler(request):
        url = str(request.url)
        if "cvedb.shodan.io/cves" in url:
            return httpx.Response(200, json={"total": 0})
        if "cvedb.shodan.io/cve/" in url:
            return httpx.Response(404)
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True),
    )
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    health = next(item for item in result.source_health if item.source == "shodan_cvedb")
    assert health.status == HealthStatus.OK
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert not any(item.source == "shodan_cvedb" for item in finding.evidence)


def test_cvedb_record_parser_uses_documented_fields():
    record = shodan_cvedb.parse_record({
        "cve_id": "CVE-2026-0001",
        "summary": "Test",
        "published_time": "2026-01-02T00:00:00Z",
        "cvss": 8.1,
        "cvss_version": 3.1,
        "cvss_v3": 9.9,
        "kev": True,
        "ransomware_campaign": "Known",
        "epss": 0.5,
        "ranking_epss": 0.0,
        "references": [{"url": "https://example.test/a"}],
        "cpes": [CPE],
    })
    assert record == CVEDBRecord(
        "CVE-2026-0001", "Test", "2026-01-02T00:00:00Z", 8.1, None, "3.1", True, True,
        0.5, 0.0, ("https://example.test/a",),
    )
    unknown = shodan_cvedb.parse_record({
        "cve_id": "CVE-2026-0002", "ransomware_campaign": "Unknown",
        "ranking_epss": 0,
    })
    assert unknown.ransomware is None
    assert unknown.epss_percentile == 0.0
    with pytest.raises(SourceError, match="identity mismatch"):
        shodan_cvedb.parse_record({"cve_id": "CVE-2026-0002"}, expected="CVE-2026-0001")


def test_cvedb_malformed_references_are_fixed_source_errors(tmp_path):
    payload = {
        "cve_id": "CVE-2026-0001",
        "references": [{"url": "https://[malformed"}],
    }
    with pytest.raises(SourceError) as caught:
        shodan_cvedb.parse_record(payload)
    assert str(caught.value) == "shodan_cvedb: source returned a malformed reference"
    with pytest.raises(SourceError) as caught:
        shodan_cvedb.fetch_cve(
            make_http(lambda request: httpx.Response(200, json=payload)),
            "CVE-2026-0001",
        )
    assert str(caught.value) == "shodan_cvedb: source returned a malformed reference"

    def handler(request):
        url = str(request.url)
        if "cvedb.shodan.io/cves" in url:
            if request.url.params.get("count") == "true":
                return httpx.Response(200, json={"total": 1})
            return httpx.Response(200, json={"cves": [payload]})
        if "cvedb.shodan.io/cve/" in url:
            return httpx.Response(404)
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True),
    )
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    health = next(item for item in result.source_health if item.source == "shodan_cvedb")
    assert health.status == HealthStatus.FAILED
    assert health.message.startswith("on; shodan_cvedb: source returned a malformed reference")
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert finding.applicability == Applicability.AFFECTED


def test_cvedb_bounded_responses_and_recursion_errors(tmp_path, monkeypatch):
    monkeypatch_cap = shodan_cvedb.MAX_DETAIL_BYTES
    shodan_cvedb.MAX_DETAIL_BYTES = 8
    try:
        source = ShodanCVEDBSource(make_http(
            lambda request: httpx.Response(200, content=b'{"cve_id": "CVE-2026-0001"}')
        ))
        with pytest.raises(SourceError, match="size limit"):
            source.lookup("CVE-2026-0001")
    finally:
        shodan_cvedb.MAX_DETAIL_BYTES = monkeypatch_cap

    gzip_source = ShodanCVEDBSource(make_http(
        lambda request: httpx.Response(
            200, content=gzip.compress(b"{}"), headers={"Content-Encoding": "gzip"}
        )
    ))
    with pytest.raises(SourceError, match="unsupported content encoding"):
        gzip_source.lookup("CVE-2026-0001")

    oversized = ShodanCVEDBSource(make_http(
        lambda request: httpx.Response(200, json={"total": 101}) if request.url.params.get("count") == "true"
        else httpx.Response(200, json={"cves": cvedb_rows(1, 101)})
    ))
    with pytest.raises(SourceError, match="oversized page"):
        oversized.discover(CPE)

    malformed = ShodanCVEDBSource(make_http(
        lambda request: httpx.Response(200, content=b'{"body": "SECRET-UPSTREAM-TEXT"')
    ))
    with pytest.raises(SourceError) as caught:
        malformed.lookup("CVE-2026-0001")
    assert str(caught.value) == "shodan_cvedb: source returned invalid JSON"

    decode = shodan_cvedb.json.loads

    def decoder(raw, *args, **kwargs):
        if raw == b"RECURSION":
            raise RecursionError("synthetic nesting")
        return decode(raw, *args, **kwargs)

    monkeypatch.setattr(shodan_cvedb.json, "loads", decoder)
    nested_source = ShodanCVEDBSource(make_http(
        lambda request: httpx.Response(200, content=b"RECURSION")
    ))
    with pytest.raises(SourceError) as caught:
        nested_source.lookup("CVE-2026-0001")
    assert str(caught.value) == "shodan_cvedb: source returned invalid JSON"

    def nested(request):
        if "cvedb.shodan.io/cves" in str(request.url):
            return httpx.Response(200, json={"total": 0})
        if "cvedb.shodan.io/cve/" in str(request.url):
            return httpx.Response(200, content=b"RECURSION")
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(
        tmp_path, nested,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True),
    )
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    health = next(item for item in result.source_health if item.source == "shodan_cvedb")
    assert health.status == HealthStatus.FAILED
    assert "1 CVE lookups failed" in health.message
    assert next(item for item in result.source_health if item.source == "nvd").status == HealthStatus.OK
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert finding.applicability == Applicability.AFFECTED


def test_cvedb_only_rows_use_cvedb_data_and_skip_core_lookups(tmp_path):
    def handler(request):
        url = str(request.url)
        if "cvedb.shodan.io/cves" in url:
            if request.url.params.get("count") == "true":
                return httpx.Response(200, json={"total": 1})
            return httpx.Response(200, json={"cves": [{
                "cve_id": "CVE-2026-0009",
                "summary": "CVEDB-only summary",
                "published_time": "2026-01-02T00:00:00Z",
                "cvss": 7.5,
                "cvss_version": 3.1,
                "kev": True,
                "ransomware_campaign": "Known",
                "epss": 0.4,
                "ranking_epss": 0.3,
                "references": [{"url": "https://example.test/cvedb"}],
            }]})
        if "cvedb.shodan.io/cve/" in url:
            return httpx.Response(404)
        if "CVE-2026-0009" in url or "CVE-2026-0009" in str(request.url.params):
            raise AssertionError(f"CVEDB-only row used a core lookup: {url}")
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True),
    )
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0009")
    assert finding.applicability == Applicability.NEEDS_REVIEW
    assert finding.reason == CVEDB_ONLY_REASON
    assert finding.vulnerability.summary == "CVEDB-only summary"
    assert finding.vulnerability.cvss_score == 7.5
    assert finding.vulnerability.cvss_version == "3.1"
    assert finding.vulnerability.epss_score == 0.4
    assert finding.vulnerability.epss_percentile == 0.3
    assert finding.vulnerability.shodan_cvedb_kev is True
    assert finding.vulnerability.shodan_cvedb_ransomware is True
    assert [item.source for item in finding.evidence] == ["shodan_cvedb"]


def test_cvedb_cannot_change_authoritative_positive_or_negative_decisions(tmp_path):
    def run(cvedb_enabled, official_status):
        def handler(request):
            url = str(request.url)
            if "cvedb.shodan.io/cves" in url:
                if request.url.params.get("count") == "true":
                    return httpx.Response(200, json={"total": 1})
                return httpx.Response(200, json={"cves": [
                    {"cve_id": "CVE-2026-0009", "summary": "CVEDB only"},
                ]})
            if "cvedb.shodan.io/cve/" in url:
                return httpx.Response(404)
            if "raw.githubusercontent.com" in url:
                if "CVE-2026-0009" in url:
                    raise AssertionError("CVEDB-only row used an official lookup")
                return httpx.Response(200, json=cve_list_record(
                    "CVE-2026-0001", status=official_status
                ))
            raise AssertionError(f"unexpected request {url}")

        engine = make_engine(
            tmp_path, handler,
            sources=source_config(
                cve_enabled=True, shodan_cvedb_enabled=cvedb_enabled,
            ),
        )
        return scan(
            engine,
            Asset("a", "Acme", "Widget", "1.0", cpe=CPE),
            known_findings=[authoritative_prior()],
        )

    for official_status in ("affected", "unaffected"):
        off = run(False, official_status)
        on = run(True, official_status)
        off_finding = next(item for item in off.findings if item.vulnerability.cve_id == "CVE-2026-0001")
        on_finding = next(item for item in on.findings if item.vulnerability.cve_id == "CVE-2026-0001")
        expected = Applicability.AFFECTED if official_status == "affected" else Applicability.NOT_AFFECTED
        assert off_finding.applicability == on_finding.applicability == expected
        assert off_finding.reason == on_finding.reason
        assert material_fingerprint(off_finding) == material_fingerprint(on_finding)
        assert next(item for item in off.source_health if item.source == "cve_list").status == HealthStatus.OK
        assert next(item for item in on.source_health if item.source == "cve_list").status == HealthStatus.OK
        cvedb_health = next(item for item in on.source_health if item.source == "shodan_cvedb")
        assert cvedb_health.status == HealthStatus.OK
        cvedb_only = next(item for item in on.findings if item.vulnerability.cve_id == "CVE-2026-0009")
        assert cvedb_only.applicability == Applicability.NEEDS_REVIEW
        assert cvedb_only.reason == CVEDB_ONLY_REASON


def test_prior_cvedb_only_finding_is_not_carried_over_as_authoritative(tmp_path):
    asset = Asset("a", "Acme", "Widget", "1.0", cpe=CPE)
    prior = {
        "asset": {
            "asset_id": "a", "vendor": "Acme", "product": "Widget", "version": "1.0",
            "category": "", "system_id": "", "ecosystem": "", "purl": "", "cpe": CPE,
            "repository": "", "commit": "", "client": "",
        },
        "vulnerability": {"cve_id": "CVE-2026-0009", "advisory_id": "CVE-2026-0009"},
        "applicability": "needs_review",
        "reason": CVEDB_ONLY_REASON,
    }

    def excluded(request):
        return httpx.Response(200, json=nvd_payload())

    engine = make_engine(tmp_path, excluded, sources=source_config(
        nvd_enabled=True, cve_enabled=True,
    ))
    result = scan(engine, asset, known_findings=[prior])
    assert result.findings == ()

    def genuine(request):
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0009")))

    engine = make_engine(tmp_path, genuine, sources=source_config(
        nvd_enabled=True, cve_enabled=True,
    ))
    result = scan(engine, asset, known_findings=[prior])
    finding = next(item for item in result.findings if item.vulnerability.cve_id == "CVE-2026-0009")
    assert finding.applicability == Applicability.AFFECTED


@pytest.mark.parametrize("optional", ["vulncheck", "cvedb"])
def test_optional_activation_does_not_change_a_carried_authoritative_row(tmp_path, monkeypatch, optional):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        url = str(request.url)
        if "api.vulncheck.com" in url:
            return httpx.Response(200, json=vulncheck_page(
                [vulncheck_entry("CVE-2026-0001")], total=1,
            ))
        if "cvedb.shodan.io/cves" in url:
            return httpx.Response(200, json={"total": 0})
        if "cvedb.shodan.io/cve/CVE-2026-0001" in url:
            return httpx.Response(200, json={
                "cve_id": "CVE-2026-0001", "kev": True, "epss": 0.9,
            })
        if "cvedb.shodan.io/cve/" in url:
            return httpx.Response(404)
        # NVD and EUVD return a different CVE; CVE List is disabled.
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0002")))

    sources = source_config(
        nvd_enabled=True,
        vulncheck_enabled=optional == "vulncheck",
        shodan_cvedb_enabled=optional == "cvedb",
    )
    asset = Asset("a", "Acme", "Widget", "1.0", cpe=CPE)
    off_sources = source_config(nvd_enabled=True)

    off_engine = make_engine(tmp_path, handler, sources=off_sources)
    off_result = scan(off_engine, asset, known_findings=[authoritative_prior()])
    off_finding = next(item for item in off_result.findings if item.vulnerability.cve_id == "CVE-2026-0001")

    on_engine = make_engine(tmp_path, handler, sources=sources)
    on_result = scan(on_engine, asset, known_findings=[authoritative_prior()])
    on_finding = next(item for item in on_result.findings if item.vulnerability.cve_id == "CVE-2026-0001")

    assert off_finding.applicability == on_finding.applicability == Applicability.COVERAGE_UNKNOWN
    assert off_finding.reason == on_finding.reason
    assert material_fingerprint(off_finding) == material_fingerprint(on_finding)
    assert off_result.coverage == on_result.coverage

    store = StateStore(tmp_path / "activation.db")
    store.record_scan([off_result])
    before = store.history(asset_id="a", cve_id="CVE-2026-0001")
    store.record_scan([on_result])
    after = store.history(asset_id="a", cve_id="CVE-2026-0001")
    assert [row["event_type"] for row in after] == [row["event_type"] for row in before]


def test_cvedb_supplemental_epss_failure_does_not_change_core_health_or_coverage(tmp_path):
    epss_requests = []

    def handler(request):
        url = str(request.url)
        if "cvedb.shodan.io/cves" in url:
            if request.url.params.get("count") == "true":
                return httpx.Response(200, json={"total": 1})
            return httpx.Response(200, json={"cves": [
                {"cve_id": "CVE-2026-0009", "summary": "CVEDB only"},
            ]})
        if "cvedb.shodan.io/cve/" in url:
            return httpx.Response(404)
        if "api.first.org" in url:
            value = str(request.url.params.get("cve", ""))
            epss_requests.append(value)
            if "CVE-2026-0009" in value:
                return httpx.Response(500)
            return httpx.Response(200, json={
                "status": "OK", "total": 1,
                "data": [{
                    "cve": "CVE-2026-0001", "epss": "0.25",
                    "percentile": "0.5", "date": "2026-01-02",
                }],
            })
        if "euvdservices" in url:
            return httpx.Response(200, json={
                "items": [{
                    "id": "EUVD-2026-0001",
                    "aliases": ["CVE-2026-0001"],
                    "description": "Synthetic EUVD record",
                }],
                "total": 1,
            })
        if "raw.githubusercontent.com" in url:
            return httpx.Response(200, json=cve_list_record(
                "CVE-2026-0001", status="affected"
            ))
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    def run(cvedb_enabled):
        engine = make_engine(
            tmp_path, handler,
            sources=source_config(
                nvd_enabled=True, euvd_enabled=True, cve_enabled=True,
                epss_enabled=True, shodan_cvedb_enabled=cvedb_enabled,
            ),
        )
        return scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))

    off = run(False)
    on = run(True)
    off_finding = next(item for item in off.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    on_finding = next(item for item in on.findings if item.vulnerability.cve_id == "CVE-2026-0001")
    assert off_finding.vulnerability.epss_score == on_finding.vulnerability.epss_score == 0.25
    assert next(item for item in off.source_health if item.source == "epss").status == HealthStatus.OK
    assert next(item for item in on.source_health if item.source == "epss").status == HealthStatus.OK
    assert off.coverage == on.coverage is None
    assert all("CVE-2026-0009" not in value for value in epss_requests)
    assert material_fingerprint(off_finding) == material_fingerprint(on_finding)


def test_inactive_optional_sources_return_the_completed_result_unchanged(tmp_path):
    from cvebeacon import optional_sources

    engine = make_engine(
        tmp_path, lambda request: httpx.Response(500),
        sources=source_config(),
    )
    asset = Asset("a", "Acme", "Widget", "1.0")
    result = QueryResult(asset, (), ())
    try:
        assert optional_sources.apply(engine, asset, result) is result
    finally:
        engine.close()


def test_default_results_match_the_core_shape(tmp_path):
    def handler(request):
        if "api.first.org" in str(request.url):
            return httpx.Response(200, json={
                "status": "OK", "total": 1,
                "data": [{
                    "cve": "CVE-2026-0001", "epss": "0.5",
                    "percentile": "0.7", "date": "2026-01-02",
                }],
            })
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, epss_enabled=True),
    )
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    value = result.to_dict()
    assert {row["source"] for row in value["source_health"]} == {
        "nvd", "euvd", "cve_list", "cisa_kev", "eu_kev", "epss",
    }
    vulnerability = value["findings"][0]["vulnerability"]
    assert set(vulnerability) == {
        "cve_id", "summary", "published", "modified", "rejected", "cvss_score",
        "cvss_vector", "cvss_version", "epss_score", "epss_percentile",
        "epss_date", "cisa_kev", "eu_kev", "references", "advisory_id",
        "aliases", "source_ids", "fixed_versions",
    }
    assert {item["source"] for item in value["findings"][0]["evidence"]} == {"nvd", "epss"}


def test_off_and_on_results_add_only_optional_fields_and_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        url = str(request.url)
        if "api.vulncheck.com" in url:
            return httpx.Response(200, json=vulncheck_page(
                [vulncheck_entry("CVE-2026-0001")], total=1,
            ))
        if "cvedb.shodan.io/cves" in url:
            return httpx.Response(200, json={"total": 0})
        if "cvedb.shodan.io/cve/" in url:
            return httpx.Response(200, json={"cve_id": "CVE-2026-0001", "kev": False})
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    asset = Asset("a", "Acme", "Widget", "1.0", cpe=CPE)

    def run(**overrides):
        engine = make_engine(
            tmp_path, handler,
            sources=source_config(nvd_enabled=True, **overrides),
        )
        return scan(engine, asset).to_dict()

    off = run()
    vulncheck_on = run(vulncheck_enabled=True)
    cvedb_on = run(shodan_cvedb_enabled=True)
    assert core_view(off) == core_view(vulncheck_on) == core_view(cvedb_on)
    assert {row["source"] for row in vulncheck_on["source_health"]} - CORE_SOURCES == {"vulncheck"}
    assert {row["source"] for row in cvedb_on["source_health"]} - CORE_SOURCES == {"shodan_cvedb"}
    assert "vulncheck_kev" in vulncheck_on["findings"][0]["vulnerability"]
    assert "shodan_cvedb_kev" in cvedb_on["findings"][0]["vulnerability"]
    assert "vulncheck" not in {item["source"] for item in off["findings"][0]["evidence"]}


def test_package_optional_sources_add_only_optional_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        url = str(request.url)
        if "api.vulncheck.com" in url:
            return httpx.Response(200, json=vulncheck_page(
                [vulncheck_entry("CVE-2026-1234")], total=1,
            ))
        if "cvedb.shodan.io/cve/" in url:
            return httpx.Response(200, json={
                "cve_id": "CVE-2026-1234", "kev": True, "ransomware_campaign": "Known",
            })
        raise AssertionError(f"unexpected request {url}")

    record_data = osv_record()

    def run(**overrides):
        engine = make_engine(
            tmp_path, handler,
            sources=source_config(osv_enabled=True, **overrides),
        )
        engine.osv.query_many = lambda assets: {
            asset.target_key: OSVResult(
                (record_data,), None, frozenset({record_data["id"]})
            )
            for asset in assets
        }
        return scan(engine, Asset("a", purl="pkg:pypi/example@1.0.0")).to_dict()

    off = run()
    on = run(vulncheck_enabled=True, shodan_cvedb_enabled=True)
    assert core_view(off) == core_view(on)
    vulnerability = on["findings"][0]["vulnerability"]
    assert vulnerability["vulncheck_kev"] is True
    assert vulnerability["shodan_cvedb_kev"] is True
    assert {row["source"] for row in on["source_health"]} - CORE_SOURCES == {
        "vulncheck", "shodan_cvedb",
    }


def test_off_exports_match_the_core_headers_and_keys(tmp_path):
    asset = Asset("a", "Acme", "Widget", "1")
    vuln = Vulnerability("CVE-2026-0001", cisa_kev=False, eu_kev=None)
    result = QueryResult(
        asset,
        (Finding(asset, vuln, Applicability.NEEDS_REVIEW, "limited", "test", (
            Evidence("cve_list", "cna", "statement"),
        )),),
        (SourceHealth("cve_list", HealthStatus.OK, utc_now(), "ok"),),
    )
    payload = json.loads(reporting.write_json(
        [result], tmp_path / "off.json", vulncheck=False, cvedb=False,
    ).read_text(encoding="utf-8"))
    assert set(payload[0]["findings"][0]["vulnerability"]) == {
        "cve_id", "summary", "published", "modified", "rejected", "cvss_score",
        "cvss_vector", "cvss_version", "epss_score", "epss_percentile",
        "epss_date", "cisa_kev", "eu_kev", "references", "advisory_id",
        "aliases", "source_ids", "fixed_versions",
    }
    workbook = load_workbook(
        reporting.write_xlsx([result], tmp_path / "off.xlsx", vulncheck=False, cvedb=False),
        read_only=True,
    )
    headers = list(list(workbook["Findings"].iter_rows(values_only=True))[0])
    assert headers == [
        "Asset ID", "Vendor", "Product", "Version", "Advisory", "Applicability",
        "Confidence", "Reason", "CVSS", "CVSS Vector", "EPSS", "EPSS Percentile",
        "EPSS Date", "CISA KEV", "EU KEV", "Rejected", "Published", "Modified",
        "Summary", "Sources", "Conflicts",
    ]
    assert list(workbook["Source Health"].iter_rows(values_only=True))[1][1] == "cve_list"
    assert list(workbook["Evidence"].iter_rows(values_only=True))[1][2] == "cve_list"


def test_reporting_visibility_off_and_on(tmp_path):
    asset = Asset("a", "Acme", "Widget", "1")
    vuln = Vulnerability(
        "CVE-2026-1234",
        vulncheck_kev=True,
        vulncheck_date_added="2026-01-02",
        vulncheck_ransomware=False,
        vulncheck_reported_exploits=2,
        vulncheck_exploit_references=3,
        shodan_cvedb_kev=True,
    )
    result = QueryResult(
        asset,
        (Finding(asset, vuln, Applicability.AFFECTED, "high", "test", (
            Evidence("vulncheck", "known_exploitation", "statement"),
            Evidence("shodan_cvedb", "independent_enrichment", "statement"),
        )),),
        (
            SourceHealth("vulncheck", HealthStatus.OK, utc_now(), "on"),
            SourceHealth("shodan_cvedb", HealthStatus.OK, utc_now(), "on"),
        ),
    )
    off_json = json.loads(reporting.write_json(
        [result], tmp_path / "off.json", vulncheck=False, cvedb=False,
    ).read_text(encoding="utf-8"))
    off_finding = off_json[0]["findings"][0]
    off_vuln = off_finding["vulnerability"]
    assert not any(key.startswith(("vulncheck", "shodan_cvedb")) for key in off_vuln)
    assert off_finding["evidence"] == []
    assert off_json[0]["source_health"] == []

    on_json = json.loads(reporting.write_json(
        [result], tmp_path / "on.json", vulncheck=True, cvedb=True,
    ).read_text(encoding="utf-8"))
    on_vuln = on_json[0]["findings"][0]["vulnerability"]
    assert on_vuln["vulncheck_kev"] is True
    assert on_vuln["vulncheck_date_added"] == "2026-01-02"
    assert on_vuln["vulncheck_reported_exploits"] == 2
    assert on_vuln["vulncheck_exploit_references"] == 3
    assert on_vuln["shodan_cvedb_kev"] is True
    assert {item["source"] for item in on_json[0]["findings"][0]["evidence"]} == {
        "vulncheck", "shodan_cvedb",
    }

    off_book = load_workbook(
        reporting.write_xlsx([result], tmp_path / "off.xlsx", vulncheck=False, cvedb=False),
        read_only=True,
    )
    off_headers = list(off_book["Findings"].iter_rows(values_only=True))[0]
    assert "VulnCheck KEV" not in off_headers
    assert "Shodan CVEDB KEV" not in off_headers
    assert len(list(off_book["Evidence"].iter_rows(values_only=True))) == 1
    assert len(list(off_book["Source Health"].iter_rows(values_only=True))) == 1

    on_book = load_workbook(
        reporting.write_xlsx([result], tmp_path / "on.xlsx", vulncheck=True, cvedb=True),
        read_only=True,
    )
    on_headers = list(on_book["Findings"].iter_rows(values_only=True))[0]
    assert "VulnCheck KEV" in on_headers
    assert "Shodan CVEDB KEV" in on_headers
    assert len(list(on_book["Evidence"].iter_rows(values_only=True))) == 3
    assert len(list(on_book["Source Health"].iter_rows(values_only=True))) == 3


def test_findings_and_event_pages_hide_disabled_vulncheck_evidence(setup, monkeypatch):
    _, store, client = setup
    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    asset = Asset("a", "Acme", "Widget", "1")
    vuln = Vulnerability(
        "CVE-2026-1234",
        vulncheck_kev=True,
        vulncheck_ransomware=True,
    )
    finding = Finding(
        asset, vuln, Applicability.NEEDS_REVIEW, "limited", "test",
        (Evidence("vulncheck", "known_exploitation", "VulnCheck statement"),),
    )
    run_id, events = store.record_scan([QueryResult(asset, (finding,), ())])
    page = client.get("/findings")
    assert page.status_code == 200
    assert "VulnCheck" not in page.text
    assert "VulnCheck statement" not in page.text
    assert 'name="vulncheck"' not in page.text
    ignored = client.get("/findings?vulncheck=yes")
    assert ignored.status_code == 200 and "CVE-2026-1234" in ignored.text
    event = client.get(f"/event/{events[0]}")
    assert event.status_code == 200
    assert "VulnCheck" not in event.text
    assert "VulnCheck statement" not in event.text

    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    page = client.get("/findings")
    assert "VulnCheck KEV" in page.text
    assert "VulnCheck statement" in page.text
    assert 'name="vulncheck"' in page.text
    filtered = client.get("/findings?vulncheck=yes")
    assert filtered.status_code == 200 and "CVE-2026-1234" in filtered.text
    missing = client.get("/findings?vulncheck=no")
    assert "CVE-2026-1234" not in missing.text
    event = client.get(f"/event/{events[0]}")
    assert "VulnCheck statement" in event.text


def test_home_and_sources_hide_inactive_optional_health(setup, monkeypatch):
    _, store, client = setup
    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    asset = Asset("a", "Acme", "Widget", "1")
    store.record_scan([QueryResult(
        asset, (),
        (
            SourceHealth("cve_list", HealthStatus.OK, utc_now(), "ok"),
            SourceHealth("vulncheck", HealthStatus.OK, utc_now(), "on"),
            SourceHealth("shodan_cvedb", HealthStatus.OK, utc_now(), "on"),
        ),
    )])
    home = client.get("/")
    assert home.status_code == 200
    assert "vulncheck" not in home.text
    assert "shodan_cvedb" not in home.text
    sources = client.get("/sources")
    assert sources.status_code == 200
    assert "off: no token" in sources.text
    assert "off: disabled" in sources.text


def test_cvedb_only_rows_disappear_from_current_views_when_disabled(setup, monkeypatch):
    from cvebeacon import dashboard, tech_report

    config, store, client = setup
    asset = Asset("a", "Acme", "Widget", "1", client="Acme")
    core = Finding(
        asset, Vulnerability("CVE-2026-1234"), Applicability.AFFECTED,
        "high", "core finding",
    )
    cvedb_only = Finding(
        asset,
        Vulnerability("CVE-2026-0009", summary="CVEDB-only summary"),
        Applicability.NEEDS_REVIEW,
        "limited",
        CVEDB_ONLY_REASON,
        (Evidence("shodan_cvedb", "independent_enrichment", "CVEDB statement"),),
    )
    store.record_scan([QueryResult(
        asset, (core, cvedb_only),
        (SourceHealth("nvd", HealthStatus.OK, utc_now(), "ok"),),
    )])
    # A fresh core-only scan does not include the CVEDB-only row.
    store.record_scan([QueryResult(
        asset, (core,),
        (SourceHealth("nvd", HealthStatus.OK, utc_now(), "ok"),),
    )])

    assert not config.cvedb_active()
    home = client.get("/")
    assert home.status_code == 200
    match = re.search(
        r'<span class="stat-value">([^<]*)</span>'
        r'<span class="stat-label">Needs review</span>',
        home.text,
    )
    assert match is not None and match.group(1) == "0"
    assert "CVE-2026-0009" not in home.text
    findings = client.get("/findings")
    assert findings.status_code == 200
    assert "CVE-2026-1234" in findings.text
    assert "CVE-2026-0009" not in findings.text
    assert CVEDB_ONLY_REASON not in findings.text
    asset_page = client.get("/asset?asset_id=a")
    assert asset_page.status_code == 200
    assert "CVE-2026-0009" not in asset_page.text
    assert CVEDB_ONLY_REASON not in asset_page.text

    # The report query applies the same provenance rule before its result cap.
    monkeypatch.setattr(tech_report, "FINDINGS_CAP", 1)
    off, _ = tech_report._read_findings(
        config.database_path, "Acme", ["a"], vulncheck=False, cvedb=False,
    )
    assert [item["cve_id"] for item in off["a"]] == ["CVE-2026-1234"]
    on, _ = tech_report._read_findings(
        config.database_path, "Acme", ["a"], vulncheck=False, cvedb=True,
    )
    assert [item["cve_id"] for item in on["a"]] == ["CVE-2026-0009"]

    on_config = replace(
        config, sources=replace(config.sources, shodan_cvedb_enabled=True)
    )
    on_app = dashboard.create_app(on_config)
    try:
        on_client = on_app.test_client()
        page = on_client.get("/findings")
        assert page.status_code == 200
        assert "CVE-2026-0009" in page.text
        assert CVEDB_ONLY_REASON in page.text
    finally:
        on_app.extensions["dashboard_jobs"].shutdown()


def test_manual_query_off_matches_the_core_page(setup, monkeypatch):
    _, store, client = setup
    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    page = client.get("/query")
    assert page.status_code == 200
    assert "VulnCheck" not in page.text
    response = post(
        client, "/query", mode="product", vendor="Acme", product="Widget", version="1.0"
    )
    assert response.status_code == 200
    assert "VulnCheck" not in response.text
    assert "shodan_cvedb" not in response.text


def test_scan_notification_text_hides_vulncheck_when_off():
    from cvebeacon.notifications import alert_items, render_text

    rows = [{
        "event_id": 1, "asset_id": "a", "cve_id": "CVE-2026-1234",
        "event_type": "new",
        "payload_json": json.dumps({
            "applicability": "affected",
            "vulnerability": {"cvss_score": 9.8, "cisa_kev": True, "eu_kev": False,
                              "vulncheck_kev": True},
        }),
    }]
    assert "VulnCheck" not in render_text(alert_items(rows))
    assert "VulnCheck KEV" in render_text(alert_items(rows, vulncheck=True))


def test_tech_report_off_restores_the_core_kev_behavior(tmp_path, monkeypatch):
    from werkzeug.datastructures import MultiDict
    from cvebeacon import tech_report

    assert tech_report.read_filters(
        MultiDict({"kev": "vulncheck"}), [], [], vulncheck=False
    )["kev"] == "any"
    assert tech_report.read_filters(
        MultiDict({"kev": "vulncheck"}), [], [], vulncheck=True
    )["kev"] == "vulncheck"

    class Window:
        field = "last_seen"

        @staticmethod
        def includes(_value):
            return True

    cve = {
        "cve_id": "CVE-2026-1234", "last_seen": "2026-01-02",
        "severity": "high", "cisa_kev": False, "eu_kev": False,
        "vulncheck_kev": True,
    }
    off_filters = tech_report.read_filters(
        MultiDict({"kev": "either"}), [], [], vulncheck=False
    )
    on_filters = tech_report.read_filters(
        MultiDict({"kev": "either"}), [], [], vulncheck=True
    )
    off_cve = {key: value for key, value in cve.items() if key != "vulncheck_kev"}
    assert not tech_report._cve_matches(off_cve, Window(), off_filters)
    assert tech_report._cve_matches(cve, Window(), on_filters)

    record = {
        "cve_id": "CVE-2026-1234", "applicability": "needs_review",
        "first_seen": "2026-01-01", "last_seen": "2026-01-02",
        "vulnerability": json.dumps({
            "cve_id": "CVE-2026-1234", "vulncheck_kev": True,
            "vulncheck_date_added": "2026-01-02",
        }),
    }
    assert "vulncheck_kev" not in tech_report._finding(record, vulncheck=False)
    assert tech_report._finding(record, vulncheck=True)["vulncheck_kev"] is True

    config = load_config(write_config(tmp_path))
    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    off = tech_report.build_report(config, "acme", MultiDict())
    assert "vulncheck_kev" not in off["summary"]
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    on = tech_report.build_report(config, "acme", MultiDict())
    assert on["summary"]["vulncheck_kev"] == 0

    from cvebeacon import dashboard_tech_report
    assert b"VulnCheck" not in dashboard_tech_report._csv(off, False).read()
    assert b"VulnCheck" in dashboard_tech_report._csv(on, True).read()
    off_book = load_workbook(dashboard_tech_report._xlsx(off, False), read_only=True)
    off_rows = list(off_book["Technologies"].iter_rows(values_only=True))
    assert not any("VulnCheck KEV" in row for row in off_rows)
    on_book = load_workbook(dashboard_tech_report._xlsx(on, True), read_only=True)
    on_rows = list(on_book["Technologies"].iter_rows(values_only=True))
    assert any("VulnCheck KEV" in row for row in on_rows)


def test_tech_report_template_off_uses_either_catalog(setup, monkeypatch):
    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    _, store, client = setup
    page = client.get("/web-assets/report?client=acme")
    assert page.status_code == 200
    assert "Either catalog" in page.text
    assert "Any catalog" not in page.text
    assert "VulnCheck" not in page.text


def test_successful_refresh_with_vulncheck_off_stores_no_evidence(setup, monkeypatch):
    _, store, client = setup
    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    asset = Asset("a", "Acme", "Widget", "1")
    on_vuln = Vulnerability("CVE-2026-1234", vulncheck_kev=True)
    on_finding = Finding(
        asset, on_vuln, Applicability.NEEDS_REVIEW, "limited", "test",
        (Evidence("vulncheck", "known_exploitation", "statement"),),
    )
    store.record_scan([QueryResult(
        asset, (on_finding,),
        (SourceHealth("vulncheck", HealthStatus.OK, utc_now(), "on"),),
    )])
    off_finding = Finding(asset, Vulnerability("CVE-2026-1234"), Applicability.NEEDS_REVIEW, "limited", "test")
    store.record_scan([QueryResult(
        asset, (off_finding,),
        (SourceHealth("nvd", HealthStatus.OK, utc_now(), "ok"),),
    )])
    stored = store.latest_findings()[0]
    assert not any(item["source"] == "vulncheck" for item in stored["evidence"])
    assert "vulncheck_kev" not in stored["vulnerability"]


def test_failed_off_scan_then_failed_reenable_does_not_resurrect_optional_evidence(
    tmp_path, monkeypatch
):
    asset = Asset("a", "Acme", "Widget", "1.0", cpe=CPE)
    store = StateStore(tmp_path / "state.db")
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def initial(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(200, json=vulncheck_page(
                [vulncheck_entry("CVE-2026-0001")], total=1,
            ))
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(
        tmp_path, initial, sources=source_config(nvd_enabled=True, vulncheck_enabled=True),
    )
    store.record_scan([scan(engine, asset)])
    assert store.latest_findings()[0]["vulnerability"]["vulncheck_kev"] is True

    def failed_nvd(request):
        assert "services.nvd.nist.gov" in str(request.url)
        return httpx.Response(503)

    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    engine = make_engine(
        tmp_path, failed_nvd,
        sources=source_config(nvd_enabled=True, vulncheck_enabled=True),
    )
    store.record_scan([
        scan(engine, asset, known_findings=store.latest_findings())
    ])

    def failed_vulncheck(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(
                401, extensions={"reason_phrase": b"Unauthorized"}
            )
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    engine = make_engine(
        tmp_path, failed_vulncheck,
        sources=source_config(nvd_enabled=True, vulncheck_enabled=True),
    )
    result = scan(engine, asset, known_findings=store.latest_findings())
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.FAILED
    store.record_scan([result])

    stored = store.latest_findings()[0]
    assert not any(
        key.startswith("vulncheck") for key in stored["vulnerability"]
    )
    assert not any(item["source"] == "vulncheck" for item in stored["evidence"])


@pytest.mark.parametrize("status", [HealthStatus.FAILED, HealthStatus.DEGRADED])
def test_optional_health_does_not_mark_a_run_failed(tmp_path, status):
    asset = Asset("a", "Acme", "Widget", "1")
    store = StateStore(tmp_path / "state.db")
    finding = Finding(
        asset, Vulnerability("CVE-2026-1234"), Applicability.NEEDS_REVIEW,
        "limited", "test",
    )
    store.record_scan([QueryResult(
        asset, (finding,),
        (
            SourceHealth("nvd", HealthStatus.OK, utc_now(), "ok"),
            SourceHealth("vulncheck", status, utc_now(), "on; temporary failure"),
        ),
    )])
    assert store.dashboard_snapshot()["latest"]["status"] == "completed"


def test_cvedb_partial_lookup_failure_saves_the_successful_record(tmp_path):
    first, second = "CVE-2026-0001", "CVE-2026-0002"

    def handler(request):
        url = str(request.url)
        if "cvedb.shodan.io/cves" in url:
            if request.url.params.get("count") == "true":
                return httpx.Response(200, json={"total": 0})
            return httpx.Response(200, json={"cves": []})
        if "cvedb.shodan.io/cve/" in url:
            if first in url:
                return httpx.Response(200, json={
                    "cve_id": first,
                    "kev": True,
                    "ransomware_campaign": "Known",
                })
            return httpx.Response(503)
        return httpx.Response(
            200, json=nvd_payload(nvd_cve(first), nvd_cve(second))
        )

    asset = Asset("a", "Acme", "Widget", "1.0", cpe=CPE)
    store = StateStore(tmp_path / "state.db")
    engine = make_engine(
        tmp_path, handler, sources=source_config(nvd_enabled=True),
    )
    store.record_scan([scan(engine, asset)])

    engine = make_engine(
        tmp_path, handler,
        sources=source_config(nvd_enabled=True, shodan_cvedb_enabled=True),
    )
    result = scan(engine, asset, known_findings=store.latest_findings())
    health = next(item for item in result.source_health if item.source == "shodan_cvedb")
    assert health.status == HealthStatus.DEGRADED
    store.record_scan([result])

    stored = {item["vulnerability"]["cve_id"]: item for item in store.latest_findings()}
    assert stored[first]["vulnerability"]["shodan_cvedb_kev"] is True
    assert any(item["source"] == "shodan_cvedb" for item in stored[first]["evidence"])
    assert "shodan_cvedb_kev" not in stored[second]["vulnerability"]
    assert not any(item["source"] == "shodan_cvedb" for item in stored[second]["evidence"])


def test_secret_never_reaches_logs_exports_state_or_backup(tmp_path, monkeypatch, caplog):
    import tarfile

    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(200, json=vulncheck_page([
                vulncheck_entry("CVE-2026-0001"),
            ], total=1))
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(
        nvd_enabled=True, vulncheck_enabled=True,
    ))
    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("httpcore").setLevel(logging.INFO)
    caplog.set_level(logging.INFO)
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    assert TOKEN not in caplog.text
    assert TOKEN not in json.dumps([result.to_dict()])

    store = StateStore(engine.config.database_path)
    store.record_scan([result])
    assert TOKEN.encode() not in Path(engine.config.database_path).read_bytes()

    export = reporting.write_json(
        [result], tmp_path / "report.json", vulncheck=True, cvedb=True,
    )
    assert TOKEN not in export.read_text(encoding="utf-8")
    xlsx = reporting.write_xlsx(
        [result], tmp_path / "report.xlsx", vulncheck=True, cvedb=True,
    )
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

    included = backup.create(config, include_secrets=True)
    archive = backup.build_archive(config, included.id)
    try:
        with tarfile.open(fileobj=archive, mode="r:gz") as tar:
            secret_name = f"{included.id}/secrets/0"
            assert secret_name in tar.getnames()
            assert tar.extractfile(secret_name).read() == TOKEN.encode()
    finally:
        archive.close()


def test_vulncheck_token_file_matches_nvd_backup_flow(tmp_path):
    import tarfile

    nvd_key = tmp_path / "nvd.key"
    vulncheck_key = tmp_path / "vulncheck.token"
    nvd_key.write_text("SYNTHETIC-NVD-KEY", encoding="utf-8")
    vulncheck_key.write_text(TOKEN, encoding="utf-8")
    for path in (nvd_key, vulncheck_key):
        if os.name == "posix":
            path.chmod(0o600)
    path = write_config(
        tmp_path,
        f'\n[sources]\nnvd_api_key_file = "{nvd_key.name}"\n'
        f'vulncheck_api_key_file = "{vulncheck_key.name}"\n',
        name="both-keys.toml",
    )
    config = load_config(path)
    plain = backup.create(config)
    assert [row["reference"] for row in json.loads(
        (plain.path / "manifest.json").read_text(encoding="utf-8")
    )["secrets"]] == []

    included = backup.create(config, include_secrets=True)
    manifest = json.loads(
        (included.path / "manifest.json").read_text(encoding="utf-8")
    )
    references = {row["reference"]: row["file"] for row in manifest["secrets"]}
    assert set(references) == {"sources.nvd_api_key_file", "sources.vulncheck_api_key_file"}
    archive = backup.build_archive(config, included.id)
    try:
        with tarfile.open(fileobj=archive, mode="r:gz") as tar:
            assert tar.extractfile(f"{included.id}/{references['sources.nvd_api_key_file']}").read() == b"SYNTHETIC-NVD-KEY"
            assert tar.extractfile(f"{included.id}/{references['sources.vulncheck_api_key_file']}").read() == TOKEN.encode()
    finally:
        archive.close()


def test_reflected_failure_response_keeps_token_out_of_health_and_logs(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)

    def handler(request):
        if "api.vulncheck.com" in str(request.url):
            return httpx.Response(
                401,
                extensions={
                    "reason_phrase": f"Unauthorized for {TOKEN}".encode("ascii")
                },
                headers={"X-Echo": TOKEN, "Retry-After": "1"},
                content=f"denied for bearer {TOKEN}".encode(),
            )
        return httpx.Response(200, json=nvd_payload(nvd_cve("CVE-2026-0001")))

    engine = make_engine(tmp_path, handler, sources=source_config(
        nvd_enabled=True, vulncheck_enabled=True,
    ))
    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("httpcore").setLevel(logging.INFO)
    caplog.set_level(logging.INFO)
    result = scan(engine, Asset("a", "Acme", "Widget", "1.0", cpe=CPE))
    health = next(item for item in result.source_health if item.source == "vulncheck")
    assert health.status == HealthStatus.FAILED
    assert health.message == "on; vulncheck: HTTP 401"
    assert TOKEN not in caplog.text
    assert TOKEN not in json.dumps([result.to_dict()])
    assert logging.getLogger("httpx").level == logging.INFO
    assert logging.getLogger("httpcore").level == logging.INFO


def test_overlapping_quiet_requests_keep_logger_levels_and_other_logs(
    monkeypatch, caplog
):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", TOKEN)
    first_started = threading.Event()
    second_started = threading.Event()
    release_first = threading.Event()
    release_second = threading.Event()

    def first_handler(request):
        first_started.set()
        release_first.wait(10)
        return httpx.Response(
            401, extensions={"reason_phrase": b"Unauthorized"}
        )

    def second_handler(request):
        second_started.set()
        release_second.wait(10)
        return httpx.Response(
            401,
            extensions={
                "reason_phrase": f"Unauthorized for {TOKEN}".encode("ascii")
            },
        )

    first = VulnCheckSource(make_http(first_handler))
    second = VulnCheckSource(make_http(second_handler))
    ordinary = make_http(lambda request: httpx.Response(200, json={"ok": True}))

    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("httpcore").setLevel(logging.INFO)
    caplog.set_level(logging.INFO)

    failures: dict[str, str] = {}

    def run(name, source):
        try:
            source.kev(TOKEN)
        except BaseException as exc:
            failures[name] = str(exc)

    first_thread = threading.Thread(target=run, args=("first", first), daemon=True)
    second_thread = None
    first_thread.start()
    try:
        assert first_started.wait(10)
        # A quiet request must not change the level other threads rely on.
        assert logging.getLogger("httpx").level == logging.INFO
        assert logging.getLogger("httpcore").level == logging.INFO

        ordinary.get_json("https://example.test/ordinary", source="test")
        assert any(
            "https://example.test/ordinary" in record.getMessage()
            for record in caplog.records
        )

        second_thread = threading.Thread(
            target=run, args=("second", second), daemon=True
        )
        second_thread.start()
        assert second_started.wait(10)
    finally:
        release_first.set()
        release_second.set()
        first_thread.join(10)
        if second_thread is not None:
            second_thread.join(10)

    assert not first_thread.is_alive()
    assert second_thread is not None and not second_thread.is_alive()
    assert failures == {
        "first": "vulncheck: HTTP 401",
        "second": "vulncheck: HTTP 401",
    }
    assert TOKEN not in caplog.text
    assert logging.getLogger("httpx").level == logging.INFO
    assert logging.getLogger("httpcore").level == logging.INFO
