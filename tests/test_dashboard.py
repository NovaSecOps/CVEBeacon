from contextlib import closing
from dataclasses import replace
from datetime import timedelta
from io import BytesIO
import json
import re

import pytest
from openpyxl import load_workbook

from cvebeacon import cli, dashboard
from cvebeacon.config import load_config
from cvebeacon.errors import CVEBeaconError, SourceError
from cvebeacon.models import Applicability as A, Asset, Evidence, Finding, HealthStatus as H, QueryResult, SourceHealth, Vulnerability, utc_now
from cvebeacon.state import StateStore


@pytest.fixture
def setup(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("[inventory]\npath='inventory.csv'\n[state]\ndatabase='state.db'\n[output]\ndirectory='reports'\n[sources]\n" +
                    "\n".join(f"{name}_enabled=false" for name in ("nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")), encoding="utf-8")
    (tmp_path / "inventory.csv").write_text("asset_id,vendor,product,version\na,Acme,Widget,1\n", encoding="utf-8")
    config = load_config(path)
    store = StateStore(config.database_path)
    app = dashboard.create_app(config)
    return config, store, app.test_client()


def result(*, status=A.AFFECTED, health=H.OK, text="Exact source evidence"):
    asset = Asset("a", "Acme", "Widget", "1")
    item = Finding(asset, Vulnerability("CVE-2026-1234", summary=text, cvss_score=9.1, epss_score=.8, cisa_kev=True, eu_kev=None),
                   status, "high", text, (Evidence("cve_list", "cna", text, source_url="javascript:alert(1)", details={"text": text}),))
    return QueryResult(asset, (item,), (SourceHealth("cve_list", health, utc_now(), text),),
                       A.COVERAGE_UNKNOWN if health != H.OK else None, "Unresolved source coverage" if health != H.OK else None)


def post(client, url, **values):
    response = client.get(url)
    assert response.status_code == 200
    token = re.search(r'name="csrf" value="([^"]+)"', response.text)[1]
    return client.post(url, data={"csrf": token, **values})


def dump(store):
    store.initialize()
    with closing(store._connect()) as db:
        return list(db.iterdump())


def test_empty_database_is_unknown_and_server_is_safe(setup):
    config, store, client = setup
    response = client.get("/")
    assert response.status_code == 200
    assert "No scan results recorded" in response.text
    assert "Coverage unknown assets" in response.text
    assert not client.application.debug
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "HttpOnly" in response.headers["Set-Cookie"] and "SameSite=Strict" in response.headers["Set-Cookie"]


def test_populated_overview_reports_findings_and_delivery(setup):
    _, store, client = setup
    _, ids = store.record_scan([result()], channels=("teams",))
    store.mark_delivery("teams", ids, accepted=False, error="private delivery error")
    response = client.get("/")
    assert response.status_code == 200
    assert "CVE-2026-1234" in response.text and "failed" in response.text
    assert "private delivery error" not in response.text
    assert "Last successful full scan" in response.text and "None recorded" not in response.text


@pytest.mark.parametrize("health", [H.FAILED, H.DEGRADED])
def test_failed_or_degraded_refresh_retains_old_finding_visibly(setup, health):
    _, store, client = setup
    store.record_scan([result()])
    store.record_scan([result(status=A.NOT_AFFECTED, health=health)])
    response = client.get("/findings")
    assert response.status_code == 200
    assert "coverage was incomplete" in response.text
    assert "Retained observation" in response.text
    assert 'class="badge affected"' in response.text
    assert 'class="badge not_affected"' not in response.text


def test_stale_scan_and_source_cannot_appear_current(setup):
    _, store, client = setup
    store.record_scan([result()])
    old = (utc_now() - timedelta(days=2)).isoformat()
    with store.transaction() as db:
        db.execute("UPDATE runs SET completed_at=?", (old,))
        db.execute("UPDATE source_health SET checked_at=?", (old,))
    assert "Stale scan data" in client.get("/").text
    assert "stale" in client.get("/sources").text
    assert "not live availability checks" in client.get("/sources").text


def test_unfinished_or_failed_attempt_overrides_old_success(setup):
    _, store, client = setup
    store.record_scan([result()])
    identifier = store.start_scan()
    assert "may be running or interrupted" in client.get("/").text
    store.finish_scan(identifier, successful=False)
    assert "latest scan or delivery failed" in client.get("/").text


@pytest.mark.parametrize("query,expected", [("q=widget", True), ("asset=a&vendor=Acme&product=Widget&version=1&cve=1234", True),
    ("applicability=affected&cvss=9&severity=critical&cisa=yes&eu=unknown", True), ("q=absent", False),
    ("applicability=not_affected", False), ("cvss=10", False), ("cisa=no", False), ("eu=yes", False), ("severity=low", False)])
def test_findings_filters(setup, query, expected):
    _, store, client = setup
    store.record_scan([result()])
    response = client.get("/findings?" + query)
    assert response.status_code == 200
    assert ("CVE-2026-1234" in response.text) is expected


def test_history_event_and_sql_input(setup):
    _, store, client = setup
    _, ids = store.record_scan([result()])
    assert "CVE-2026-1234" in client.get("/history?asset=a").text
    assert "CVE-2026-1234" not in client.get("/history", query_string={"asset": "' OR 1=1 --"}).text
    event = client.get(f"/event/{ids[0]}")
    assert event.status_code == 200 and "Exact source evidence" in event.text
    assert "Historical observation" in event.text
    assert client.get("/event/999999").status_code == 404


def test_asset_lookup_uses_inventory_and_marks_changed_version(setup):
    config, store, client = setup
    store.record_scan([result()])
    assert "Widget" in client.get("/assets?q=Acme").text
    assert "CVE-2026-1234" in client.get("/asset?asset_id=a").text
    config.inventory.path.write_text("asset_id,vendor,product,version\na,Acme,Widget,2\n", encoding="utf-8")
    response = client.get("/asset?asset_id=a")
    assert "coverage_unknown" in response.text
    assert "Inventory changed or asset removed" in response.text
    assert "Version 2" in response.text
    assert client.get("/asset?asset_id=absent").status_code == 404


def test_inventory_failure_cannot_show_clean_coverage(setup):
    config, store, client = setup
    store.record_scan([result()])
    config.inventory.path.write_text("invalid", encoding="utf-8")
    assert "Inventory unavailable" in client.get("/").text


def test_manual_query_calls_same_cli_core_and_preserves_alerts(setup, monkeypatch):
    _, store, client = setup
    store.record_scan([result()], channels=("teams", "email"))
    before = dump(store)
    called = []
    def query(config, assets):
        called.append(assets)
        return [replace(result(health=H.DEGRADED), asset=assets[0])]
    monkeypatch.setattr(cli, "_run_query", query)
    response = post(client, "/query", vendor="Acme", product="Widget", version="1")
    assert response.status_code == 200 and "coverage_unknown" in response.text
    assert "CVE-2026-1234" in response.text and "0.8" in response.text
    assert called == [[Asset("manual-query", "Acme", "Widget", "1")]]
    assert dump(store) == before


def test_real_offline_manual_engine_creates_no_monitoring_database(setup):
    config, _, client = setup
    response = post(client, "/query", vendor="Acme", product="Widget", version="unknown")
    assert response.status_code == 200 and "coverage_unknown" in response.text
    assert not config.database_path.exists()


@pytest.mark.parametrize("kind", ["json", "xlsx"])
def test_report_download_reuses_reporting_without_state_writes(setup, monkeypatch, kind):
    _, store, client = setup
    store.record_scan([result()], channels=("teams",))
    before = dump(store)
    monkeypatch.setattr(cli, "_run_query", lambda config, assets: [result()])
    response = post(client, "/reports", format=kind, output="../../arbitrary")
    assert response.status_code == 200
    assert f"cvebeacon-report.{kind}" in response.headers["Content-Disposition"]
    if kind == "json":
        assert json.loads(response.data)[0]["findings"][0]["vulnerability"]["cve_id"] == "CVE-2026-1234"
    else:
        book = load_workbook(BytesIO(response.data))
        assert book["Findings"]["E2"].value == "CVE-2026-1234"
        book.close()
    assert dump(store) == before


def test_html_and_evidence_are_escaped_and_urls_are_inert(setup):
    _, store, client = setup
    store.record_scan([result(text='<script>alert("x")</script>')])
    response = client.get("/findings")
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text
    assert 'href="javascript:' not in response.text
    assert "\\u003cscript\\u003e" in response.text


@pytest.mark.parametrize("url", ["/findings?cvss=nan", "/findings?cvss=11", "/findings?severity=bogus", "/findings?cisa=maybe",
    "/findings?applicability=clean", "/findings?q=one&q=two", "/assets?q=" + "x" * 257])
def test_invalid_filters_rejected(setup, url):
    assert setup[2].get(url).status_code == 400


@pytest.mark.parametrize("values", [{"vendor": "", "product": "Widget", "version": "1"},
    {"vendor": "Acme", "product": "Widget", "version": "x" * 257}, {"vendor": "Acme\n", "product": "\x00", "version": "1"}])
def test_invalid_manual_input_rejected(setup, values):
    assert post(setup[2], "/query", **values).status_code == 400


@pytest.mark.parametrize("url", ["/static/../../config.toml", "/static/%2e%2e/config.toml", "/reports/../../config.toml"])
def test_path_traversal_cannot_read_files(setup, url):
    response = setup[2].get(url)
    assert response.status_code == 404
    assert "database=" not in response.text


def test_report_format_traversal_rejected(setup):
    assert post(setup[2], "/reports", format="../../config.toml").status_code == 400


def test_csrf_required_and_untrusted_host_rejected(setup):
    _, _, client = setup
    assert client.post("/query", data={"vendor": "Acme", "product": "Widget", "version": "1"}).status_code == 400
    assert client.get("/", headers={"Host": "attacker.example"}).status_code == 400
    assert client.post("/query", data={"x": "x" * 9000}).status_code == 413


def test_wildcard_binding_accepts_lan_ip_but_not_rebinding_hostname(setup):
    app = dashboard.create_app(setup[0], host="0.0.0.0")
    client = app.test_client()
    assert client.get("/", headers={"Host": "192.0.2.10:8787"}).status_code == 200
    assert client.get("/", headers={"Host": "attacker.example:8787"}).status_code == 400


def test_config_and_upstream_secrets_never_rendered(setup, monkeypatch):
    config, store, client = setup
    secret = "sensitive-test-value-123"
    for name in (config.teams.webhook_env, config.email.client_secret_env, config.sources.nvd_api_key_env):
        monkeypatch.setenv(name, secret)
    for route in ("/", "/sources", "/findings", "/history", "/assets", "/query", "/reports"):
        assert secret not in client.get(route).text
    def fail(*args):
        raise SourceError("nvd", secret)
    monkeypatch.setattr(cli, "_run_query", fail)
    response = post(client, "/query", vendor="Acme", product="Widget", version="1")
    assert response.status_code == 503 and secret not in response.text
    assert str(config.config_path) not in response.text


@pytest.mark.parametrize("host,port", [("127.0.0.1", 8787), ("0.0.0.0", 8989), ("::1", 8787)])
def test_server_binding_and_debug_disabled(setup, monkeypatch, capsys, host, port):
    import waitress
    calls = []
    class Server:
        def run(self): calls.append("run")
        def close(self): calls.append("close")
    def create(app, **kwargs):
        assert not app.debug
        calls.append(kwargs)
        return Server()
    monkeypatch.setattr(waitress, "create_server", create)
    dashboard.serve(setup[0], host=host, port=port)
    assert calls[0]["host"] == host and calls[0]["port"] == port
    assert calls[0]["expose_tracebacks"] is False and calls[-1] == "close"
    assert str(port) in capsys.readouterr().out


@pytest.mark.parametrize("host,port", [("", 8787), ("host/path", 8787), ("127.0.0.1", 0), ("127.0.0.1", 65536)])
def test_invalid_bind_options(setup, host, port):
    with pytest.raises(CVEBeaconError):
        dashboard.serve(setup[0], host=host, port=port)


def test_cli_serve_defaults_and_options(setup, monkeypatch):
    calls = []
    monkeypatch.setattr(dashboard, "serve", lambda config, **kwargs: calls.append(kwargs))
    assert cli.main(["--config", str(setup[0].config_path), "serve"]) == 0
    assert calls[-1] == {"host": "127.0.0.1", "port": 8787}
    assert cli.main(["--config", str(setup[0].config_path), "serve", "--host", "0.0.0.0", "--port", "8989"]) == 0
    assert calls[-1] == {"host": "0.0.0.0", "port": 8989}


def test_coverage_filter_applies_to_unscanned_assets(setup):
    client = setup[2]
    assert "No scan observation for this inventory" in client.get("/findings?applicability=coverage_unknown&asset=a").text
    assert "No scan observation for this inventory" not in client.get("/findings?applicability=coverage_unknown&asset=absent").text


def test_history_cursor_keeps_older_events_accessible(setup):
    _, store, client = setup
    _, first = store.record_scan([result()])
    _, second = store.record_scan([result(status=A.NEEDS_REVIEW)])
    rows = store.history(before_event_id=second[0])
    assert [row["event_id"] for row in rows] == first
    page = client.get(f"/history?before={second[0]}")
    assert f"/event/{first[0]}" in page.text and f"/event/{second[0]}" not in page.text
    assert client.get("/history?before=-1").status_code == 400


def test_non_ascii_csrf_is_invalid_without_querying(setup, monkeypatch):
    def forbidden(*args): raise AssertionError("invalid form reached engine")
    monkeypatch.setattr(cli, "_run_query", forbidden)
    response = setup[2].post("/query", data={"csrf": "é", "vendor": "Acme", "product": "Widget", "version": "1"})
    assert response.status_code == 400


def test_non_loopback_binding_warns_about_access_control(setup, monkeypatch, caplog):
    import waitress
    class Server:
        def run(self): pass
        def close(self): pass
    monkeypatch.setattr(waitress, "create_server", lambda *args, **kwargs: Server())
    dashboard.serve(setup[0], host="0.0.0.0")
    assert "no built-in authentication" in caplog.text
