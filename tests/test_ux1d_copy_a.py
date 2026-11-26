"""Plain-language copy for the monitoring and operations pages."""

from __future__ import annotations

import re
import shlex
import sqlite3

import pytest

from cvebeacon import dashboard, scheduling
from cvebeacon.locking import RunLock, run_lock_path
from cvebeacon.models import (
    Applicability,
    Asset,
    Finding,
    QueryResult,
    Vulnerability,
)
from cvebeacon.state import StateStore
from cvebeacon.watch.store import DELIVERY_MAX_ATTEMPTS
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from watch_support import write_config

PASSWORD = "Synthetic copy pass password"

# Section 5.3: these technical words must stay inside a disclosure or code.
BANNED_OUTSIDE_DETAILS = (
    "SIGINT",
    "TOML",
    "cron",
    "watch notify",
    "cvebeacon users add",
    "[inventory]",
)
# Section 6: wording that must never imply a safer state than the data supports.
BANNED_WORDS = ("safe", "protected", "working", "healthy", "all set", "not affected")


class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def fake_scheduler(text=""):
    def run(args, **kwargs):
        if args == ["crontab", "-l"]:
            return _Result(stdout=text)
        return _Result()

    return run


def visible(html: str) -> str:
    """Remove only the contents of the approved explain disclosures."""
    return re.sub(
        r'(<div\b(?=[^>]*\bclass=["\'][^"\']*\bexplain-body\b)[^>]*>).*?(</div>)',
        r"\1\2",
        html,
        flags=re.S | re.I,
    )


def assert_no_banned_technical_words(html: str) -> None:
    text = visible(html).casefold()
    for word in BANNED_OUTSIDE_DETAILS:
        assert word.casefold() not in text, word


def h1(html: str) -> str:
    match = re.search(r"<h1[^>]*>(.*?)</h1>", html, flags=re.S | re.I)
    assert match is not None
    return match.group(1).strip()


def login(client) -> None:
    page = client.get("/login")
    assert page.status_code == 200
    token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    response = client.post(
        "/login",
        data={"csrf": token, "username": "admin", "password": PASSWORD},
    )
    assert response.status_code == 303


def make_config(tmp_path, *, inventory: bool):
    config = write_config(
        tmp_path,
        sources=("nvd",),
        inventory=inventory,
    )
    if inventory:
        (tmp_path / "missing-inventory.csv").write_text(
            "asset_id,vendor,product,version\na,Acme,Widget,1\n",
            encoding="utf-8",
        )
    return config


@pytest.fixture
def signed_in(tmp_path):
    config = make_config(tmp_path, inventory=True)
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler()
    client = app.test_client()
    login(client)
    try:
        yield config, app, client
    finally:
        app.extensions["dashboard_jobs"].shutdown()


@pytest.fixture
def watch_only(tmp_path):
    config = make_config(tmp_path, inventory=False)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler()
    try:
        yield config, app, app.test_client()
    finally:
        app.extensions["dashboard_jobs"].shutdown()


def test_page_titles_match_navigation_labels(signed_in):
    _, _, client = signed_in
    for path, title in (
        ("/", "Home"),
        ("/watch", "Watch overview"),
        ("/watch/events", "Alerts"),
        ("/sources", "Sources"),
        ("/operations/", "Operations"),
        ("/operations/jobs", "Job history"),
    ):
        response = client.get(path)
        assert response.status_code == 200, path
        assert h1(response.text) == title, path


def test_banned_technical_words_stay_inside_disclosures(signed_in, tmp_path):
    config, app, client = signed_in
    job = app.extensions["dashboard_jobs"].store.create(
        "watch-refresh", "admin", ["cvebeacon", "watch", "refresh", "CVE-2026-0001"]
    )
    pages = (
        "/",
        "/watch",
        "/watch/events",
        "/sources",
        "/operations/",
        "/operations/jobs",
        f"/operations/jobs/{job.id}",
    )
    for path in pages:
        response = client.get(path)
        assert response.status_code == 200, path
        assert_no_banned_technical_words(response.text)


@pytest.mark.parametrize(
    "html",
    ("<code>cron</code>", "<pre>cron</pre>", "<details><code>cron</code></details>"),
)
def test_banned_technical_word_outside_explain_is_flagged(html):
    with pytest.raises(AssertionError, match="cron"):
        assert_no_banned_technical_words(html)


def test_home_uses_plain_names_for_changes_and_delivery(signed_in):
    config, _, client = signed_in
    store = StateStore(config.database_path)
    asset = Asset("a", "Acme", "Widget", "1")
    finding = Finding(
        asset,
        Vulnerability("CVE-2026-1234", summary="Example flaw"),
        Applicability.AFFECTED,
        "high",
        "Example evidence",
    )
    _, event_ids = store.record_scan(
        [QueryResult(asset, (finding,), ())], channels=("sink",)
    )
    store.mark_delivery("sink", event_ids, accepted=True)

    text = client.get("/").text
    assert "Assets with unknown coverage" in text
    assert "Assets with no recent scan result" not in text
    assert "Coverage unknown assets" not in text
    assert "Assets needing coverage review" not in text
    assert "Assets to check" not in text
    assert "Recent changes" in text
    assert "Recent material changes" not in text
    assert "New finding" in text
    assert " · new · " not in text
    assert "Accepted by the service" in text
    assert " · accepted:" not in text
    assert "<td>accepted</td>" not in text
    assert "Accepted means accepted" not in text
    assert "Accepted by the service does not confirm that a person received it." in text
    assert "Finished" in text
    assert " · completed" not in text


def test_home_inventory_notice_is_plain_language(watch_only):
    _, _, client = watch_only
    text = client.get("/").text
    copy = re.sub(r"<[^>]+>", "", text)
    assert "No inventory is set up yet." in text
    assert "Add a list on the Inventory page. Client is optional." in copy
    assert "Alerts about public flaws still work without an inventory." in text
    assert 'href="/inventory">Inventory page</a>' in text
    # The technical alternative is still available, but closed by default.
    assert "[inventory]" in text
    assert "[inventory]" not in visible(text)


def test_operations_account_less_copy(watch_only, monkeypatch):
    # The fake scheduler output is cron output; read it as Linux on every runner.
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    _, _, client = watch_only
    response = client.get("/operations/")
    assert response.status_code == 200
    text = response.text
    assert "Operations need a user account" in text
    assert "Open the" in text and "setup page" in text
    assert "to create the first administrator." in text
    assert 'href="/bootstrap"' in text
    assert "cvebeacon users add" in text
    assert "cvebeacon users add" not in visible(text)
    assert "Not scheduled" in text


def test_watch_overview_alert_timing_and_operations_link(signed_in):
    _, _, client = signed_in
    text = client.get("/watch").text
    assert (
        "Alerts are queued when a rule matches. They go out the next time "
        "watch monitoring runs, or when you choose <strong>Deliver pending alerts</strong> "
        "on <a href=\"/operations/\">Operations</a>."
    ) in text
    assert 'href="/operations/">Operations</a>' in text


def test_watch_overview_backfill_copy(signed_in):
    config, _, client = signed_in
    from cvebeacon.watch.store import WatchStore

    watch_store = WatchStore(config.watch.database)
    watch_store.set_metadata(
        {
            "initial_mode": "backfill",
            "initial_window_start": "2026-10-27",
            "initialized_at": "2026-11-03T12:00:00+00:00",
            "initial_sync_completed_at": "2026-11-03T12:10:00+00:00",
            "initial_evaluated_at": "2026-11-03T12:11:00+00:00",
        }
    )
    text = client.get("/watch").text
    assert "First load" in text
    assert "Alerts for flaws in the window shown above" in text
    assert "Backfill</strong> sends alerts for flaws published in the window shown above." in text
    assert "last few days" not in text
    assert "backfill" in text
    assert '<summary>Technical details</summary>' in text
    assert '<dt>First load mode (stored value)</dt><dd>backfill</dd>' in text


def test_gave_up_is_counted_inside_failed(signed_in):
    config, _, client = signed_in
    from cvebeacon.watch.store import WatchStore

    watch_store = WatchStore(config.watch.database)
    watch_store.initialize()
    with watch_store.transaction() as db:
        cursor = db.execute(
            "INSERT INTO watch_event(rule,cve_id,kind,reasons_json,details_json,"
            "occurrence,initial,created_at) VALUES (?,?,?,?,?,?,0,?)",
            ("fixture", "CVE-2026-9999", "new", "[]", "{}", "fixture", "2026-11-03T12:00:00Z"),
        )
        db.execute(
            "INSERT INTO watch_delivery(event_id,channel,status,attempts,last_error,updated_at) "
            "VALUES (?, 'fixture', 'failed', ?, 'failure', '2026-11-03T12:00:00Z')",
            (cursor.lastrowid, DELIVERY_MAX_ATTEMPTS),
        )
    status = next(row for row in watch_store.delivery_status() if row.channel == "fixture")
    assert status.failed == 1 and status.given_up == 1
    text = client.get("/watch").text
    assert "Gave up is counted inside Failed." in text
    assert "<td class=\"num\">1</td>" in text


def test_watch_overview_delivery_help(signed_in):
    _, _, client = signed_in
    text = client.get("/watch").text
    assert "Gave up" in text
    assert "Unsure" in text
    assert (
        "Unsure means the service may or may not have received the alert. "
        "Check the destination before sending again."
    ) in text


def test_watch_events_copy(signed_in):
    _, _, client = signed_in
    text = client.get("/watch/events").text
    assert h1(text) == "Alerts"
    assert "Type of alert" in text
    assert "From the first check" in text
    assert (
        "Raised during the first check after installation, not by a later change."
        in text
    )
    assert "<th scope=\"col\">Kind</th>" not in text


def test_sources_copy(signed_in):
    _, _, client = signed_in
    text = client.get("/sources").text
    assert h1(text) == "Sources"
    assert (
        "Public databases CVEBeacon reads, and whether the last read worked."
        in text
    )
    assert "cached observations" not in text.casefold()
    assert "catalogues" not in text.casefold()


def test_queued_job_cancel_copy(signed_in):
    _, app, client = signed_in
    store = app.extensions["dashboard_jobs"].store
    queued = store.create(
        "watch-refresh", "admin", ["cvebeacon", "watch", "refresh", "CVE-2026-0001"]
    )
    text = client.get(f"/operations/jobs/{queued.id}").text
    assert "Cancelling removes this queued job before it starts." in text
    assert 'data-confirm="Cancel this job? It will be removed before it starts."' in text
    assert "The job will be asked to stop." not in text
    assert "How cancellation works" not in text
    assert "SIGINT" not in text
    assert "Result</dt>" in text
    assert "Result code" not in text
    assert "Exit code" not in text


def test_running_job_cancellation_discloses_signal_and_cleanup(signed_in):
    _, app, client = signed_in
    store = app.extensions["dashboard_jobs"].store
    running = store.create(
        "watch-refresh", "admin", ["cvebeacon", "watch", "refresh", "CVE-2026-0001"]
    )
    assert store.mark_running(running.id)
    text = client.get(f"/operations/jobs/{running.id}").text
    assert (
        "Cancelling asks the job to stop and clean up. The result shows whether "
        "it finished cleanly."
    ) in text
    assert "SIGINT" in text
    assert "SIGINT" not in visible(text)
    assert 'data-confirm="Cancel this job? The job will be asked to stop."' in text


def test_job_result_codes_are_in_technical_details(signed_in):
    _, app, client = signed_in
    store = app.extensions["dashboard_jobs"].store
    failed = store.create("scan", "admin", ["cvebeacon", "scan"])
    store.finish(failed.id, "failed", exit_code=2, message="bad")
    detail = client.get(f"/operations/jobs/{failed.id}").text
    history = client.get("/operations/jobs").text
    for page in (detail, history):
        assert "Failed" in page
        assert "Validation or operational failure" in page
        assert "<summary>Technical details</summary>" in page
        assert "Result code: <code class=\"num\">2</code>" in page
        assert "Result code:" not in visible(page)
        assert re.search(r'<span class="num(?: nowrap)?">2</span>', visible(page)) is None


def test_job_page_alert_timing_copy(signed_in):
    _, app, client = signed_in
    job = app.extensions["dashboard_jobs"].store.create(
        "watch-refresh", "admin", ["cvebeacon", "watch", "refresh", "CVE-2026-0001"]
    )
    text = client.get(f"/operations/jobs/{job.id}").text
    assert "the next time watch monitoring runs" in text
    assert "when you choose <strong>Deliver pending alerts</strong> on Operations." in text


def test_operations_hides_raw_external_command_in_technical_details(signed_in):
    config, _, client = signed_in
    with RunLock(run_lock_path(config), command="watch run"):
        text = client.get("/operations/").text
    assert "Another task is running" in text
    assert "watch run" in text
    assert "watch run" not in visible(text)
    assert "<summary>Technical details</summary>" in text
    assert "Command: <code>watch run</code>" in text


def test_jobs_and_operations_tables_say_task(signed_in):
    _, app, client = signed_in
    app.extensions["dashboard_jobs"].store.create(
        "scan", "admin", ["cvebeacon", "scan"]
    )
    for path in ("/operations/", "/operations/jobs"):
        text = client.get(path).text
        assert "<th>Task</th>" in text, path
        assert "<th>Operation</th>" not in text, path


def test_operations_shows_a_plain_schedule_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path, inventory=False)
    app = dashboard.create_app(config)
    installed = (
        scheduling.CRON_BEGIN
        + f"\n0 */4 * * * cvebeacon --config {shlex.quote(str(config.config_path))} watch run\n"
        + scheduling.CRON_END
    )
    app.extensions["dashboard_schedule_runner"] = fake_scheduler(installed)
    client = app.test_client()
    try:
        response = client.get("/operations/")
        assert response.status_code == 200
        assert "Scheduled automatically" in response.text
        assert "cron" not in visible(response.text).casefold()
        assert "Not scheduled" not in response.text
    finally:
        app.extensions["dashboard_jobs"].shutdown()


def test_pages_do_not_use_overstated_wording(signed_in):
    _, app, client = signed_in
    job = app.extensions["dashboard_jobs"].store.create(
        "scan", "admin", ["cvebeacon", "scan"]
    )
    for path in (
        "/",
        "/watch",
        "/watch/events",
        "/sources",
        "/operations/",
        "/operations/jobs",
        f"/operations/jobs/{job.id}",
    ):
        text = visible(client.get(path).text).casefold()
        for word in BANNED_WORDS:
            assert not re.search(
                rf"\b{re.escape(word.casefold())}\b", text
            ), (path, word)


def test_footer_copy_is_plain_language(signed_in):
    _, _, client = signed_in
    text = client.get("/").text
    assert (
        "Data shows when it was last checked, not now. Scheduled and manual "
        "tasks run separately from this page."
    ) in text
