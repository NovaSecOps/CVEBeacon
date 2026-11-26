"""Home KPI cards use honest, current inventory and delivery state."""

from datetime import timedelta

import pytest

from cvebeacon import dashboard, dashboard_setup
from cvebeacon.config import load_config
from cvebeacon.dashboard_home import HomeContextCache
from cvebeacon.errors import StateError
from cvebeacon.models import Applicability as A, Asset, Finding, QueryResult, Vulnerability, utc_now
from cvebeacon.state import StateStore


@pytest.fixture(autouse=True)
def _no_host_scheduler(monkeypatch):
    monkeypatch.setattr(dashboard_setup, "schedule_scan_state", lambda config: "none")


def make_home(tmp_path, *, inventory=True, watch_enabled=False):
    path = tmp_path / "config.toml"
    text = "[state]\ndatabase = 'state.db'\n[output]\ndirectory = 'reports'\n"
    if inventory:
        text += "[inventory]\npath = 'inventory.csv'\n"
    if watch_enabled:
        text += "[watch]\nenabled = true\n"
    text += "[sources]\n" + "\n".join(
        f"{name}_enabled = false"
        for name in ("nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")
    ) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    if inventory:
        (tmp_path / "inventory.csv").write_text(
            "asset_id,vendor,product,version\na,Acme,Widget,1\n",
            encoding="utf-8",
            newline="\n",
        )
    config = load_config(path)
    app = dashboard.create_app(config)
    return config, app, app.test_client()


def finding(asset, identifier, applicability):
    vuln = Vulnerability(identifier, summary="Synthetic finding", cvss_score=8.0)
    return Finding(asset, vuln, applicability, "high", "Synthetic evidence")


def home_kpis(page):
    start = page.find('id="home-kpis"')
    if start < 0:
        start = page.find('<div class="stat-grid">')
    if start < 0:
        return page
    if 'id="home-kpis"' not in page:
        end = page.find('<section class="card', start)
        return page[start:end] if end >= 0 else page[start:]
    wrapper_start = page.rfind("<div", 0, start)
    grid_start = page.index('<div class="stat-grid">', wrapper_start)
    grid_end = page.index("</div>", grid_start) + len("</div>")
    wrapper_end = page.index("</div>", grid_end) + len("</div>")
    return page[wrapper_start:wrapper_end]


def test_home_replaces_seven_stat_tiles_with_five_linked_kpis(tmp_path):
    _, _, client = make_home(tmp_path)
    page = client.get("/")
    assert page.status_code == 200
    kpis = home_kpis(page.text)
    assert kpis.count('<a class="stat') == 5
    for title in (
        "Affected findings",
        "Needs review",
        "Assets with unknown coverage",
        "Alerts waiting or uncertain",
        "Latest scan",
    ):
        assert title in kpis
    assert 'href="/findings?applicability=affected"' in kpis
    assert 'href="/findings?applicability=needs_review"' in kpis
    assert 'href="/findings?applicability=coverage_unknown"' in kpis
    assert 'href="/watch/events"' in kpis
    assert 'href="/#scan-activity"' in kpis
    for removed in ("CISA KEV CVEs", "EU KEV CVEs", "Assets to check"):
        assert removed not in kpis


@pytest.mark.parametrize(
    ("inventory_row", "expected_affected", "expected_review", "expected_unknown"),
    [
        ("a,Acme,Widget,1", "1", "1", "0"),
        ("a,Acme,Widget,2", "0", "0", "1"),
        ("other,Acme,Widget,1", "0", "0", "1"),
    ],
)
def test_home_counts_only_matching_inventory_identity_and_version(
    tmp_path, inventory_row, expected_affected, expected_review, expected_unknown
):
    config, _, client = make_home(tmp_path)
    config.inventory.path.write_text(
        "asset_id,vendor,product,version\n" + inventory_row + "\n",
        encoding="utf-8",
        newline="\n",
    )
    asset = Asset("a", "Acme", "Widget", "1")
    store = StateStore(config.database_path)
    store.record_scan(
        [QueryResult(asset, (
            finding(asset, "CVE-2026-1111", A.AFFECTED),
            finding(asset, "CVE-2026-1112", A.NEEDS_REVIEW),
        ), ())]
    )
    kpis = home_kpis(client.get("/").text)
    assert f'<span class="stat-value">{expected_affected}</span><span class="stat-label">Affected findings</span>' in kpis
    assert f'<span class="stat-value">{expected_review}</span><span class="stat-label">Needs review</span>' in kpis
    assert f'<span class="stat-value">{expected_unknown}</span><span class="stat-label">Assets with unknown coverage</span>' in kpis
    if expected_affected == "0":
        assert "No affected findings recorded for this inventory." in kpis


def test_home_does_not_show_zero_for_no_inventory_or_no_scan(tmp_path):
    _, _, client = make_home(tmp_path, inventory=False, watch_enabled=True)
    kpis = home_kpis(client.get("/").text)
    assert kpis.count("Add inventory to see these numbers.") == 3
    assert "No scan recorded" in kpis
    assert '<span class="stat-value">0</span>' not in kpis


def test_home_shows_no_scan_recorded_for_configured_inventory(tmp_path):
    _, _, client = make_home(tmp_path)
    kpis = home_kpis(client.get("/").text)
    assert kpis.count("No scan recorded") >= 3
    assert '<span class="stat-value">0</span>' not in kpis


def test_home_inventory_read_error_shows_unknown_not_zero(tmp_path):
    config, _, client = make_home(tmp_path)
    config.inventory.path.write_text("not a valid inventory file\n", encoding="utf-8", newline="\n")
    kpis = home_kpis(client.get("/").text)
    assert kpis.count('<span class="stat-value">Unknown</span>') >= 3
    assert "Could not check." in kpis
    assert '<span class="stat-value">0</span>' not in kpis


def test_home_marks_stale_inventory_counts_with_age_and_warning(tmp_path):
    config, _, client = make_home(tmp_path)
    asset = Asset("a", "Acme", "Widget", "1")
    store = StateStore(config.database_path)
    store.record_scan([QueryResult(asset, (finding(asset, "CVE-2026-2222", A.AFFECTED),), ())])
    old = (utc_now() - timedelta(days=2)).isoformat()
    with store.transaction() as db:
        db.execute("UPDATE runs SET completed_at=?", (old,))
    kpis = home_kpis(client.get("/").text)
    assert '<span class="stat-value">1</span><span class="stat-label">Affected findings</span>' in kpis
    assert "Stale scan data" in kpis
    assert old in kpis


def test_home_scan_read_error_is_unknown_and_does_not_render_zero(tmp_path, monkeypatch):
    _, _, client = make_home(tmp_path)

    def unreadable(_store):
        raise StateError("private scan database detail")

    monkeypatch.setattr(StateStore, "dashboard_snapshot", unreadable)
    page = client.get("/")
    assert page.status_code == 200
    kpis = home_kpis(page.text)
    assert kpis.count("Could not check.") >= 4
    assert '<span class="stat-value">0</span>' not in kpis
    assert "No recent deliveries." not in page.text
    assert "private scan database detail" not in page.text


def test_home_delivery_counts_ignore_sent_and_count_gave_up_inside_failed(tmp_path):
    _, app, client = make_home(tmp_path, watch_enabled=True)
    store = app.extensions["dashboard_watch"]["store"]
    store.initialize()
    with store.transaction() as db:
        db.executemany(
            "INSERT INTO watch_delivery(event_id,channel,status,attempts,updated_at) VALUES(?,?,?,?,?)",
            [
                (1, "email", "pending", 0, "2026-11-01T00:00:00+00:00"),
                (2, "email", "sending", 1, "2026-11-01T00:00:00+00:00"),
                (3, "email", "sent", 1, "2026-11-01T00:00:00+00:00"),
                (4, "email", "failed", 99, "2026-11-01T00:00:00+00:00"),
                (5, "email", "ambiguous", 1, "2026-11-01T00:00:00+00:00"),
            ],
        )
    kpis = home_kpis(client.get("/").text)
    assert "Queued 1 · Sending 1 · Failed 1 · Unsure 1" in kpis
    assert "Gave up 1" not in kpis
    assert "Gave up is included in failed." in kpis
    assert "Accepted by the service" not in kpis


def test_home_with_no_delivery_rows_does_not_claim_zero_alerts(tmp_path):
    _, app, client = make_home(tmp_path, watch_enabled=True)
    app.extensions["dashboard_watch"]["store"].initialize()
    kpis = home_kpis(client.get("/").text)
    assert "No alert delivery state recorded" in kpis
    assert "Queued 0 · Sending 0" not in kpis


def test_home_delivery_read_error_shows_unknown(tmp_path, monkeypatch):
    _, app, client = make_home(tmp_path, watch_enabled=True)
    store = app.extensions["dashboard_watch"]["store"]

    def unreadable():
        raise StateError("private Watch database detail")

    monkeypatch.setattr(store, "_connect_readonly", unreadable)
    kpis = home_kpis(client.get("/").text)
    assert "Unknown" in kpis
    assert "Could not check." in kpis
    assert "private Watch database detail" not in client.get("/").text


def test_home_shows_latest_scan_and_a_distinct_later_attempt(tmp_path):
    config, _, client = make_home(tmp_path)
    asset = Asset("a", "Acme", "Widget", "1")
    store = StateStore(config.database_path)
    store.record_scan([QueryResult(asset, (finding(asset, "CVE-2026-3333", A.AFFECTED),), ())])
    attempt = store.start_scan()
    store.finish_scan(attempt, successful=False)
    kpis = home_kpis(client.get("/").text)
    assert "Latest stored scan result: Finished" in kpis
    assert "Latest attempt: Failed" in kpis


def test_home_shows_a_failed_attempt_when_no_scan_run_was_recorded(tmp_path):
    config, _, client = make_home(tmp_path)
    store = StateStore(config.database_path)
    attempt = store.start_scan()
    store.finish_scan(attempt, successful=False)
    kpis = home_kpis(client.get("/").text)
    assert "No scan recorded" in kpis
    assert "Latest attempt: Failed" in kpis


def test_home_latest_scan_card_reports_a_running_attempt(tmp_path):
    config, _, client = make_home(tmp_path)
    StateStore(config.database_path).start_scan()
    kpis = home_kpis(client.get("/").text)
    assert '<span class="stat-value">Scan in progress</span><span class="stat-label">Latest scan</span>' in kpis
    assert "Latest attempt: Running" in kpis


def test_home_does_not_repeat_an_attempt_that_matches_the_latest_scan(tmp_path):
    config, _, client = make_home(tmp_path)
    store = StateStore(config.database_path)
    attempt = store.start_scan()
    asset = Asset("a", "Acme", "Widget", "1")
    store.record_scan(
        [QueryResult(asset, (finding(asset, "CVE-2026-4444", A.AFFECTED),), ())],
        attempt_id=attempt,
    )
    store.finish_scan(attempt, successful=True)
    kpis = home_kpis(client.get("/").text)
    assert "Latest stored scan result: Finished" in kpis
    assert "Latest attempt:" not in kpis


def test_home_context_cache_reuses_one_snapshot_for_thirty_seconds(tmp_path, monkeypatch):
    _, _, client = make_home(tmp_path)
    original = StateStore.dashboard_snapshot
    calls = 0

    def counted(store):
        nonlocal calls
        calls += 1
        return original(store)

    monkeypatch.setattr(StateStore, "dashboard_snapshot", counted)
    assert client.get("/").status_code == 200
    assert client.get("/").status_code == 200
    assert calls == 1


def test_home_cache_expires_and_failed_refresh_does_not_reuse_old_value():
    now = [0.0]
    cache = HomeContextCache(ttl_seconds=30, clock=lambda: now[0])
    assert cache.get("config", lambda: "first") == "first"
    assert cache.get("config", lambda: "unused") == "first"
    now[0] = 31.0

    def failed_refresh():
        raise StateError("refresh failed")

    with pytest.raises(StateError):
        cache.get("config", failed_refresh)
    assert cache.get("config", lambda: "fresh") == "fresh"
