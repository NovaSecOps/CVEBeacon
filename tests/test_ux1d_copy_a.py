"""Plain-language copy for the monitoring and operations pages."""

from __future__ import annotations

import re

import pytest

from cvebeacon import dashboard, scheduling
from cvebeacon.models import (
    Applicability,
    Asset,
    Finding,
    QueryResult,
    Vulnerability,
)
from cvebeacon.state import StateStore
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
    """Remove text that the design allows to be technical."""
    without_details = re.sub(
        r"<details\b[^>]*>.*?</details>", "", html, flags=re.S | re.I
    )
    return re.sub(
        r"<code\b[^>]*>.*?</code>", "", without_details, flags=re.S | re.I
    )


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
        text = visible(response.text).casefold()
        for word in BANNED_OUTSIDE_DETAILS:
            assert word.casefold() not in text, (path, word)


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
    assert "Assets with no recent scan result" in text
    assert "Coverage unknown assets" not in text
    assert "Assets needing coverage review" not in text
    assert "Assets to check" in text
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
    assert "No software list is set up yet." in text
    assert "Add a client and upload their software list on the" in text
    assert "Alerts about public flaws still work without it." in text
    assert 'href="/watch/clients"' in text
    # The technical alternative is still available, but closed by default.
    assert "[inventory]" in text
    assert "[inventory]" not in visible(text)


def test_operations_account_less_copy(watch_only):
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


def test_watch_overview_copy(signed_in):
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
    assert (
        "Alerts are queued when a rule matches. They are sent the next time "
        "CVEBeacon runs, or when you press Deliver pending alerts on the"
    ) in text
    assert "Gave up" in text
    assert "Unsure" in text
    assert (
        "Unsure means the service may or may not have received the alert. "
        "Check the destination before sending again."
    ) in text
    assert "First load" in text
    assert "Recent flaws alerted" in text
    assert "backfill" not in visible(text).casefold()
    assert "backfill" in text


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


def test_job_page_copy(signed_in):
    _, app, client = signed_in
    job = app.extensions["dashboard_jobs"].store.create(
        "watch-refresh", "admin", ["cvebeacon", "watch", "refresh", "CVE-2026-0001"]
    )
    text = client.get(f"/operations/jobs/{job.id}").text
    assert "Result code" in text
    assert "Exit code" not in text
    assert (
        "Cancelling asks the job to stop and clean up. The result shows whether "
        "it finished cleanly."
    ) in text
    assert "SIGINT" in text
    assert "SIGINT" not in visible(text)
    assert "Deliver pending alerts" in text
    assert "watch notify" not in visible(text)


def test_jobs_and_operations_tables_say_task(signed_in):
    _, app, client = signed_in
    app.extensions["dashboard_jobs"].store.create(
        "scan", "admin", ["cvebeacon", "scan"]
    )
    for path in ("/operations/", "/operations/jobs"):
        text = client.get(path).text
        assert "<th>Task</th>" in text, path
        assert "<th>Operation</th>" not in text, path


def test_operations_shows_a_plain_schedule_summary(tmp_path):
    config = make_config(tmp_path, inventory=False)
    app = dashboard.create_app(config)
    installed = (
        scheduling.CRON_BEGIN
        + "\n0 */4 * * * cvebeacon watch run\n"
        + scheduling.CRON_END
    )
    app.extensions["dashboard_schedule_runner"] = fake_scheduler(installed)
    client = app.test_client()
    try:
        response = client.get("/operations/")
        assert response.status_code == 200
        assert "Scheduled automatically" in response.text
        assert "cron" not in visible(response.text).casefold()
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
