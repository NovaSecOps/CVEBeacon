from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path
import re

import pytest

from cvebeacon import dashboard, dashboard_watch
from cvebeacon.errors import ConfigurationError
from cvebeacon.watch import feeds
from cvebeacon.watch.records import (
    CVSSEntry,
    EUVDUpdate,
    Product,
    Reference,
    WatchRecord,
)
from cvebeacon.watch.reporting import ReportService
from cvebeacon.watch.rules import parse_rules
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.sync import sync_watch
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from test_watch_statements import docx_bytes
from watch_support import NOW as SYNC_NOW, mock_client, write_config

PASSWORD = "Synthetic dashboard watch password"
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
CHANNELS = """
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
notify_reported = true
"""


def record(identifier: str = "CVE-2026-0001", **overrides):
    values = {
        "cve_id": identifier,
        "status": "published",
        "published": "2026-11-01T00:00:00.000",
        "last_modified": "2026-11-02T00:00:00.000",
        "description": "Acme Widget before 4.2.1 allows remote code execution.",
        "source_identifier": "security@example.test",
        "cvss": (
            CVSSEntry(
                "nvd",
                "nvd@nist.gov",
                "3.1",
                9.8,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CRITICAL",
            ),
        ),
        "cwes": ("CWE-79",),
        "products": (Product("acme", "widget"),),
        "references": (Reference("https://example.test/a", ("Patch",)),),
        "ssvc_exploitation": "active",
    }
    values.update(overrides)
    return WatchRecord(**values)


def login(client, username: str = "admin") -> None:
    page = client.get("/login")
    assert page.status_code == 200
    token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    response = client.post(
        "/login",
        data={"csrf": token, "username": username, "password": PASSWORD},
    )
    assert response.status_code == 303


def csrf(client, path: str) -> str:
    page = client.get(path)
    assert page.status_code == 200
    return re.search(r'name="csrf" value="([^"]+)"', page.text)[1]


def seeded(tmp_path: Path, *, identity: str = "open"):
    config = write_config(
        tmp_path,
        sources=("nvd", "euvd", "epss"),
        initial="backfill",
        extra=f'[watch.reporting]\nidentity = "{identity}"\n',
        channels=CHANNELS,
    )
    users = UserStore(config.watch.users_database)
    users.add(
        "admin",
        password=PASSWORD,
        display_name="Alice",
        is_admin=True,
        authorization=BOOTSTRAP,
    )
    admin = users.authenticate("admin", PASSWORD)
    assert admin is not None
    users.save_role("none", set(), authorization=admin)
    users.save_role("ops", {"view", "report", "statement"}, authorization=admin)
    users.add("ops", password=PASSWORD, display_name="Olive", role="ops")
    users.add("reader", password=PASSWORD, role="viewer")
    users.add("nobody", password=PASSWORD, role="none")

    store = WatchStore(config.watch.database, clock=lambda: NOW)
    records = [
        record("CVE-2026-0001"),
        record(
            "CVE-2026-0002",
            references=(
                Reference("https://example.test/a", ("Patch",)),
                Reference("javascript:alert(1)"),
            ),
        ),
    ]
    store.replace_euvd_items(
        [
            EUVDUpdate(
                ("CVE-2026-0001",),
                "EUVD-2026-1",
                "2026-10-01",
                CVSSEntry("euvd", "euvd", "3.1", 9.8),
                "2026-11-01",
            )
        ],
        catalogs=config.watch.sources,
    )
    store.upsert_nvd(records, catalogs=config.watch.sources)
    rule = parse_rules(
        [{"name": "all", "condition": {"cvss_min": 0}, "channels": ["hook"]}]
    )[0]
    store.evaluate_touched(
        (rule,), catalogs=config.watch.sources, initial=True
    )
    store.upsert_nvd(
        [
            replace(
                records[1],
                cisa_kev_added="2026-11-03",
                cisa_kev_due="2026-11-20",
                cisa_required_action="Apply updates",
                cisa_ransomware="Known",
            )
        ],
        catalogs=config.watch.sources,
    )
    store.evaluate_touched((rule,), catalogs=config.watch.sources)
    store.set_metadata(
        {
            "nvd_cursor": NOW.isoformat(),
            "euvd_cursor": "2026-11-01",
            "euvd_page_cursor": json.dumps(
                {
                    "start": "2026-10-30",
                    "end": "2026-11-03",
                    "page": 1,
                    "total": 500,
                    "size": feeds.EUVD_PAGE_SIZE,
                    "phase": "scan",
                    "verify": 0,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            "initial_mode": "backfill",
            "initial_window_start": "2026-10-27",
            "initialized_at": NOW.isoformat(),
            "initial_sync_completed_at": NOW.isoformat(),
            "last_sync_at": NOW.isoformat(),
            "last_sync_failures": "",
            "sync_nvd_at": NOW.isoformat(),
            "sync_nvd_requests": "3",
            "sync_nvd_records": "2",
            "sync_nvd_new": "2",
            "sync_nvd_changed": "0",
            "sync_nvd_error": "",
            "sync_euvd_at": NOW.isoformat(),
            "sync_euvd_requests": "7",
            "sync_euvd_records": "1",
            "sync_euvd_new": "1",
            "sync_euvd_changed": "0",
            "sync_euvd_error": "",
        }
    )
    ReportService(store, None, "open").report_cve(
        "CVE-2026-0001",
        by="seed",
        note="=Seed note",
        notify_channels=("hook",),
    )
    app = dashboard.create_app(config)
    return config, users, store, app, app.test_client()


@pytest.fixture
def watch(tmp_path):
    return seeded(tmp_path)


def test_overview_shows_database_cursors_sync_health_and_initial_state(watch):
    _, _, _, _, client = watch
    login(client, "reader")
    response = client.get("/watch")
    assert response.status_code == 200
    text = response.text
    assert "watch.db" in text
    assert "Schema version" in text and "7" in text
    assert NOW.isoformat() in text
    assert "2026-11-01" in text
    assert "scanning 2026-10-30..2026-11-03, page 2 of 5" in text
    assert "Last sync started 2026-11-03 12:00 UTC" in text
    assert "hook" in text and "pending" in text
    assert "backfill" in text
    assert "Watched CVEs" in text
    assert "KEV" in text
    assert "SSVC" in text
    assert "Reported to clients" in text


def test_empty_database_pages_render(tmp_path):
    config = write_config(
        tmp_path,
        sources=("nvd", "euvd", "epss"),
        initial="baseline",
        extra='[watch.reporting]\nidentity = "open"\n',
        channels=CHANNELS,
    )
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client, "admin")
    response = client.get("/watch")
    assert response.status_code == 200
    assert "No sync summary has been recorded yet" in response.text
    assert client.get("/watch/events").status_code == 200
    assert "No matching events" in client.get("/watch/events").text
    assert client.get("/watch/reported").status_code == 200
    assert "No CVE is currently reported" in client.get("/watch/reported").text
    assert client.get("/watch/cve/CVE-2026-0404").status_code == 404
    assert client.get("/watch/cve/CVE-2026-0404/statement").status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/watch",
        "/watch/events",
        "/watch/cve/CVE-2026-0001",
        "/watch/reported",
    ],
)
def test_view_pages_render_for_view_and_deny_without_it(watch, path):
    _, _, _, _, client = watch
    login(client, "reader")
    assert client.get(path).status_code == 200
    client.get("/logout")
    login(client, "nobody")
    assert client.get(path).status_code == 403


def test_cve_detail_shows_stored_view_kev_links_events_and_trail(watch):
    _, _, _, _, client = watch
    login(client, "reader")
    response = client.get("/watch/cve/CVE-2026-0002")
    assert response.status_code == 200
    text = response.text
    assert "CVE-2026-0002" in text
    assert "Apply updates" in text and "2026-11-20" in text
    assert "active" in text
    assert "CWE-79" in text and "widget" in text
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-0002" in text
    assert "https://www.cve.org/CVERecord?id=CVE-2026-0002" in text
    assert 'href="javascript:' not in text
    assert "javascript:alert(1)" in text
    assert "kev_added" in text
    assert "hook: pending" in text
    assert "Not reported to clients" in text


def test_report_records_session_user_in_open_mode_and_queues_notice(watch):
    _, users, store, _, client = watch
    login(client, "ops")
    token = csrf(client, "/watch/cve/CVE-2026-0002")
    response = client.post(
        "/watch/cve/CVE-2026-0002/report",
        data={
            "csrf": token,
            "note": "Ticket OPS-42",
            "by": "attacker",
            "user": "attacker",
            "username": "attacker",
        },
    )
    assert response.status_code == 303
    entries = store.reported_cves()
    entry = next(item for item in entries if item.cve_id == "CVE-2026-0002")
    assert entry.by == "ops"
    assert entry.username is None
    assert entry.identity_mode == "open"
    assert entry.note == "Ticket OPS-42"
    notices = store.notice_deliveries(cve_id="CVE-2026-0002")
    states = notices[("report", entry.id)]
    assert [(state.channel, state.status) for state in states] == [
        ("hook", "pending")
    ]
    page = client.get(response.headers["Location"])
    assert page.status_code == 200
    assert "The report was recorded." in page.text
    assert "hook: pending" in page.text


def test_report_uses_registered_identity(tmp_path):
    _, users, store, _, client = seeded(tmp_path, identity="registered")
    login(client, "ops")
    token = csrf(client, "/watch/cve/CVE-2026-0002")
    response = client.post(
        "/watch/cve/CVE-2026-0002/report",
        data={"csrf": token, "note": "Registered"},
    )
    assert response.status_code == 303
    entry = next(
        item for item in store.reported_cves() if item.cve_id == "CVE-2026-0002"
    )
    assert entry.by == "Olive"
    assert entry.username == "ops"
    assert entry.identity_mode == "registered"


def test_report_uses_authenticated_dashboard_session(tmp_path):
    _, users, store, _, client = seeded(tmp_path, identity="authenticated")
    login(client, "ops")
    token = csrf(client, "/watch/cve/CVE-2026-0002")
    response = client.post(
        "/watch/cve/CVE-2026-0002/report",
        data={"csrf": token, "note": "Authenticated"},
    )
    assert response.status_code == 303
    entry = next(
        item for item in store.reported_cves() if item.cve_id == "CVE-2026-0002"
    )
    assert entry.by == "Olive"
    assert entry.username == "ops"
    assert entry.identity_mode == "authenticated"
    assert entry.user_id is not None


def test_unreport_withdraws_the_session_users_mark(watch):
    _, _, store, _, client = watch
    login(client, "ops")
    token = csrf(client, "/watch/cve/CVE-2026-0001")
    response = client.post(
        "/watch/cve/CVE-2026-0001/unreport",
        data={"csrf": token, "note": "Withdrawn"},
    )
    assert response.status_code == 303
    assert all(
        item.cve_id != "CVE-2026-0001" for item in store.reported_cves()
    )
    trail = store.report_trail("CVE-2026-0001")
    assert trail[0].action == "unreport"
    assert trail[0].note == "Withdrawn"
    page = client.get(response.headers["Location"])
    assert "The report was withdrawn." in page.text


def test_report_and_statement_require_their_permissions(watch):
    _, _, _, _, client = watch
    login(client, "reader")
    assert client.get("/watch/cve/CVE-2026-0001/statement").status_code == 403
    token = csrf(client, "/watch/cve/CVE-2026-0002")
    assert client.post(
        "/watch/cve/CVE-2026-0002/report",
        data={"csrf": token, "note": "No"},
    ).status_code == 403
    client.get("/logout")
    login(client, "nobody")
    assert client.get("/watch/cve/CVE-2026-0001/statement").status_code == 403
    token = csrf(client, "/account")
    assert client.post(
        "/watch/cve/CVE-2026-0002/report",
        data={"csrf": token},
    ).status_code == 403


def test_report_and_statement_require_csrf(watch):
    _, _, _, _, client = watch
    login(client, "ops")
    assert client.post("/watch/cve/CVE-2026-0002/report").status_code == 400
    assert client.post("/watch/cve/CVE-2026-0002/statement").status_code == 400
    stranger = client.application.test_client()
    foreign = csrf(stranger, "/login")
    assert client.post(
        "/watch/cve/CVE-2026-0002/report", data={"csrf": foreign}
    ).status_code == 400
    assert client.post(
        "/watch/cve/CVE-2026-0002/statement", data={"csrf": foreign}
    ).status_code == 400


def test_events_filters_and_pagination(watch):
    _, _, store, _, client = watch
    rule = parse_rules(
        [{"name": "all", "condition": {"cvss_min": 0}, "channels": ["hook"]}]
    )[0]
    store.upsert_nvd(
        [record(f"CVE-2026-{number:04d}") for number in range(1000, 1060)],
        catalogs=("nvd", "euvd", "epss"),
    )
    store.evaluate_touched(
        (rule,), catalogs=("nvd", "euvd", "epss")
    )
    login(client, "reader")
    first = client.get("/watch/events")
    assert first.status_code == 200
    assert first.text.count('href="/watch/cve/') == 50
    assert "Page 1" in first.text and "Older events" in first.text
    second = client.get("/watch/events?page=2")
    assert second.status_code == 200
    assert second.text.count('href="/watch/cve/') == 13
    assert "Page 2" in second.text and "Newer events" in second.text
    empty = client.get("/watch/events?page=3")
    assert empty.status_code == 200
    assert empty.text.count('href="/watch/cve/') == 0
    for path in (
        "/watch/events?page=0",
        "/watch/events?page=abc",
        "/watch/events?page=100001",
    ):
        assert client.get(path).status_code == 400


@pytest.mark.parametrize(
    "query,expected",
    [
        ("rule=ALL", 3),
        ("rule=missing", 0),
        ("kind=kev_added", 1),
        ("initial=yes", 2),
        ("initial=no", 1),
        ("pending=no", 0),
        ("cve=CVE-2026-0002", 2),
        ("since=2026-11-03&until=2026-11-03", 3),
        ("since=2026-11-04", 0),
    ],
)
def test_events_filter_results(watch, query, expected):
    _, _, store, _, client = watch
    login(client, "reader")
    response = client.get("/watch/events?" + query)
    assert response.status_code == 200
    assert response.text.count('href="/watch/cve/') == expected


@pytest.mark.parametrize(
    "query",
    [
        "kind=unknown",
        "initial=maybe",
        "pending=maybe",
        "since=not-a-date",
        "since=2026-11-04&until=2026-11-03",
        "until=9999-12-31",
        "cve=not-a-cve",
    ],
)
def test_invalid_event_filters_are_rejected(watch, query):
    _, _, _, _, client = watch
    login(client, "reader")
    assert client.get("/watch/events?" + query).status_code == 400


def test_reported_list_permission_pagination_and_exports(watch, monkeypatch):
    _, _, store, _, client = watch
    monkeypatch.setattr(dashboard_watch, "REPORT_PAGE_SIZE", 1)
    monkeypatch.setattr(dashboard_watch, "EXPORT_BATCH", 1)
    # Add a second active mark so both pages exist.
    ReportService(store, None, "open").report_cve(
        "CVE-2026-0002", by="seed", note="=SUM(1)"
    )
    login(client, "reader")
    first = client.get("/watch/reported")
    assert first.status_code == 200
    assert "CVE-2026-0001" in first.text and "CVE-2026-0002" not in first.text
    assert "Download CSV" not in first.text
    second = client.get("/watch/reported?page=2")
    assert second.status_code == 200
    assert "CVE-2026-0002" in second.text
    assert client.get("/watch/reported/export?format=csv").status_code == 403

    client.get("/logout")
    login(client, "admin")
    csv_response = client.get("/watch/reported/export?format=csv")
    assert csv_response.status_code == 200
    assert csv_response.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in csv_response.headers["Content-Disposition"]
    body = csv_response.get_data(as_text=True)
    assert "cve_id,action,by" in body.splitlines()[0]
    assert "'=SUM(1)" in body

    json_response = client.get("/watch/reported/export?format=json")
    assert json_response.status_code == 200
    assert json_response.headers["Content-Type"].startswith("application/json")
    records = json.loads(json_response.get_data(as_text=True))
    assert [item["cve_id"] for item in records] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    assert any(item["note"] == "=SUM(1)" for item in records)
    assert client.get("/watch/reported/export?format=xml").status_code == 400


def test_statement_builtin_and_uploaded_templates(watch):
    _, _, _, _, client = watch
    login(client, "ops")
    page = client.get("/watch/cve/CVE-2026-0001/statement")
    assert page.status_code == 200
    assert "Built-in Markdown template" in page.text
    token = csrf(client, "/watch/cve/CVE-2026-0001/statement")
    builtin = client.post(
        "/watch/cve/CVE-2026-0001/statement",
        data={"csrf": token, "template": "builtin"},
    )
    assert builtin.status_code == 200
    assert "attachment" in builtin.headers["Content-Disposition"]
    assert builtin.headers["Content-Disposition"].endswith("-statement.md")
    assert b"# CVE statement: CVE-2026-0001" in builtin.data
    assert b"## Summary" in builtin.data

    token = csrf(client, "/watch/cve/CVE-2026-0001/statement")
    text = b"Uploaded statement for ${cve_id} with ${severity}.\n"
    uploaded = client.post(
        "/watch/cve/CVE-2026-0001/statement",
        data={
            "csrf": token,
            "template": "upload",
            "template_file": (BytesIO(text), "custom.md"),
        },
        content_type="multipart/form-data",
    )
    assert uploaded.status_code == 200
    assert b"Uploaded statement for CVE-2026-0001 with critical." in uploaded.data

    token = csrf(client, "/watch/cve/CVE-2026-0001/statement")
    docx = client.post(
        "/watch/cve/CVE-2026-0001/statement",
        data={
            "csrf": token,
            "template": "upload",
            "template_file": (
                BytesIO(
                    docx_bytes(
                        "<w:p><w:r><w:t>${cve_id}</w:t></w:r></w:p>"
                    )
                ),
                "custom.docx",
            ),
        },
        content_type="multipart/form-data",
    )
    assert docx.status_code == 200
    assert docx.data.startswith(b"PK")
    assert b"CVE-2026-0001" in docx.data
    assert "wordprocessingml.document" in docx.headers["Content-Type"]


def test_statement_rejects_bad_uploads(watch, monkeypatch):
    _, _, _, _, client = watch
    login(client, "ops")
    token = csrf(client, "/watch/cve/CVE-2026-0001/statement")
    unsupported = client.post(
        "/watch/cve/CVE-2026-0001/statement",
        data={
            "csrf": token,
            "template": "upload",
            "template_file": (BytesIO(b"%PDF"), "custom.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert unsupported.status_code == 400
    assert "unsupported statement template type" in unsupported.text

    token = csrf(client, "/watch/cve/CVE-2026-0001/statement")
    missing = client.post(
        "/watch/cve/CVE-2026-0001/statement",
        data={"csrf": token, "template": "upload"},
        content_type="multipart/form-data",
    )
    assert missing.status_code == 400

    monkeypatch.setattr(dashboard_watch, "MAX_STATEMENT_UPLOAD_BYTES", 10)
    token = csrf(client, "/watch/cve/CVE-2026-0001/statement")
    oversized = client.post(
        "/watch/cve/CVE-2026-0001/statement",
        data={
            "csrf": token,
            "template": "upload",
            "template_file": (BytesIO(b"x" * 100), "big.md"),
        },
        content_type="multipart/form-data",
    )
    assert oversized.status_code == 413


def test_statement_rejects_invalid_placeholders(watch):
    _, _, _, _, client = watch
    login(client, "ops")
    token = csrf(client, "/watch/cve/CVE-2026-0001/statement")
    response = client.post(
        "/watch/cve/CVE-2026-0001/statement",
        data={
            "csrf": token,
            "template": "upload",
            "template_file": (BytesIO(b"${unknown_field}\n"), "bad.md"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "unknown_field" in response.text


def test_authenticated_report_rechecks_the_account_before_writing(tmp_path):
    config = write_config(
        tmp_path,
        sources=("nvd",),
        initial="baseline",
        extra='[watch.reporting]\nidentity = "authenticated"\n',
        channels=CHANNELS,
    )
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    users.add("ops", password=PASSWORD, role="viewer")
    admin = users.authenticate("admin", PASSWORD)
    proof = users.authenticate("ops", PASSWORD)
    assert admin is not None and proof is not None
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.upsert_nvd([record()], catalogs=config.watch.sources)
    users.disable("ops", authorization=admin)
    service = ReportService(store, config.watch.users_database, "authenticated")
    with pytest.raises(ConfigurationError):
        service.report_cve("CVE-2026-0001", authenticated=proof)
    assert store.report_trail("CVE-2026-0001") == ()


def test_sync_records_last_source_status(tmp_path):
    config = write_config(
        tmp_path,
        sources=("nvd",),
        initial="baseline",
        channels="",
    )

    def unexpected(request):
        raise AssertionError("baseline sync must not contact a source")

    report = sync_watch(config, mock_client(unexpected), clock=lambda: SYNC_NOW)
    assert report.baseline
    metadata = WatchStore(config.watch.database).metadata()
    assert metadata["last_sync_at"] == SYNC_NOW.isoformat()
    assert metadata["sync_nvd_at"] == SYNC_NOW.isoformat()
    assert metadata["sync_nvd_requests"] == "0"
    assert metadata["last_sync_failures"] == ""
