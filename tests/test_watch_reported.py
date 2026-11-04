from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from typing import Any

import httpx
import pytest
from watch_support import NOW, mock_client, write_config

from cvebeacon import cli
from cvebeacon.errors import ConfigurationError, StateError
from cvebeacon.watch.delivery import deliver_pending
from cvebeacon.watch.messages import build_messages, webhook_payload
from cvebeacon.watch.records import (
    CVSSEntry,
    DeliveryEvent,
    ReportedMark,
    WatchRecord,
    WatchView,
)
from cvebeacon.watch.reported import (
    default_identity,
    normalize_cve_id,
    validate_identity,
)
from cvebeacon.watch.rules import parse_rules
from cvebeacon.watch.store import WatchStore

MARK = ReportedMark(
    "CVE-2026-0001",
    "alice",
    "Ticket OPS-42",
    "2026-11-03T12:00:00+00:00",
)

CHANNELS = """
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
notify_reported = true

[watch.channels.quiet]
type = "webhook"
url = "https://example.test/quiet"
"""

RULE = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["hook"]
"""


def record(identifier: str = "CVE-2026-0001") -> WatchRecord:
    return WatchRecord(
        identifier,
        "published",
        description="Acme Widget allows remote code execution.",
        cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8),),
    )


def seed(config, identifiers: tuple[str, ...] = ("CVE-2026-0001",)) -> WatchStore:
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.upsert_nvd(
        [record(identifier) for identifier in identifiers],
        catalogs=config.watch.sources,
    )
    return store


def view(cve_id: str = "CVE-2026-1234", **overrides: Any) -> WatchView:
    values: dict[str, Any] = {
        "cve_id": cve_id,
        "status": "published",
        "description": "Acme Widget before 4.2.1 allows remote code execution.",
        "cvss": (CVSSEntry("cna", "security@acme.example", "3.1", 9.8),),
        "epss": 0.62,
    }
    values.update(overrides)
    return WatchView(**values)


def event(
    kind: str = "match",
    *,
    cve_id: str = "CVE-2026-1234",
    reported: ReportedMark | None = None,
    details: dict[str, Any] | None = None,
    initial: bool = False,
    rule: str = "critical",
    event_id: int = 1,
) -> DeliveryEvent:
    return DeliveryEvent(
        event_id,
        rule,
        cve_id,
        kind,
        ("cvss 9.8 v3.1 (cna)",),
        initial,
        "2026-11-04T12:00:00+00:00",
        view(cve_id),
        details or {},
        "pending",
        reported,
    )


def rows(store: WatchStore) -> list[tuple]:
    with sqlite3.connect(store.path) as db:
        return db.execute(
            "SELECT channel,status,attempts FROM watch_delivery ORDER BY channel"
        ).fetchall()


def deliver(config, store, handler, *, now=NOW, **kwargs):
    return deliver_pending(
        config,
        store,
        mock_client(handler),
        clock=lambda: now,
        monotonic=lambda: 0.0,
        **kwargs,
    )


def test_report_and_unreport_keep_an_append_only_trail(tmp_path):
    config = write_config(tmp_path, channels="")
    store = seed(config)

    first = store.report_cve("cve-2026-0001", by="alice", note="Ticket OPS-42")
    assert first.changed is True
    assert first.entry is not None
    assert (first.entry.cve_id, first.entry.action, first.entry.by) == (
        "CVE-2026-0001",
        "report",
        "alice",
    )
    current = store.reported_cves()
    assert [entry.cve_id for entry in current] == ["CVE-2026-0001"]
    assert current[0].note == "Ticket OPS-42"
    assert store.reported_marks(["CVE-2026-0001"])["CVE-2026-0001"] == MARK

    repeated = store.report_cve("CVE-2026-0001", by="bob")
    assert repeated.changed is False
    assert repeated.entry is not None and repeated.entry.by == "alice"
    assert len(store.reported_entries()) == 1

    forced = store.report_cve("CVE-2026-0001", by="bob", force=True)
    assert forced.changed is True
    assert forced.entry is not None and forced.entry.by == "bob"
    assert len(store.reported_entries()) == 2

    withdrawn = store.unreport_cve("CVE-2026-0001", by="carol", note="Sent in error")
    assert withdrawn.changed is True
    assert withdrawn.entry is not None and withdrawn.entry.action == "unreport"
    assert store.reported_cves() == ()
    assert store.reported_marks(["CVE-2026-0001"]) == {}
    assert [entry.action for entry in store.reported_entries()] == [
        "report",
        "report",
        "unreport",
    ]
    assert store.unreport_cve("CVE-2026-0001", by="dave").changed is False
    assert len(store.reported_entries()) == 3


def test_report_requires_a_stored_cve(tmp_path):
    config = write_config(tmp_path, channels="")
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    with pytest.raises(StateError, match="CVE-2026-9999 is not in the watch database"):
        store.report_cve("CVE-2026-9999", by="alice")
    assert store.reported_entries() == ()


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"by": "x" * 101}, "at most 100"),
        ({"by": "ali\nce"}, "control characters"),
        ({"by": "   "}, "must not be empty"),
        ({"by": "alice", "note": "x" * 501}, "at most 500"),
        ({"by": "alice", "note": "line\nbreak"}, "control characters"),
    ],
)
def test_report_validates_identity_and_note(tmp_path, kwargs, match):
    config = write_config(tmp_path, channels="")
    store = seed(config)
    with pytest.raises(ConfigurationError, match=match):
        store.report_cve("CVE-2026-0001", **kwargs)
    assert store.reported_entries() == ()


def test_report_validates_the_cve_format(tmp_path):
    config = write_config(tmp_path, channels="")
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    with pytest.raises(ConfigurationError, match="CVE id must look like"):
        store.report_cve("not-a-cve", by="alice")


def test_identity_default_uses_the_os_login_or_unknown(monkeypatch):
    monkeypatch.setattr("cvebeacon.watch.reported.getpass.getuser", lambda: "alice")
    assert default_identity() == "alice"

    for value in ("", "ali\nce", "x" * 101, "ali\u202ece"):
        monkeypatch.setattr(
            "cvebeacon.watch.reported.getpass.getuser", lambda value=value: value
        )
        assert default_identity() == "unknown"

    def unavailable():
        raise OSError("no login name")

    monkeypatch.setattr("cvebeacon.watch.reported.getpass.getuser", unavailable)
    assert default_identity() == "unknown"
    with pytest.raises(ConfigurationError, match="required"):
        validate_identity(None)


def test_store_requires_an_explicit_identity(tmp_path):
    config = write_config(tmp_path, channels="")
    store = seed(config)
    with pytest.raises(TypeError):
        store.report_cve("CVE-2026-0001")
    with pytest.raises(TypeError):
        store.unreport_cve("CVE-2026-0001")
    with pytest.raises(ConfigurationError, match="required"):
        store.report_cve("CVE-2026-0001", by=None)
    assert store.reported_entries() == ()


@pytest.mark.parametrize(
    "text",
    [
        "\nalice\t",
        "ali\u0085ce",
        "ali\u009bce",
        "ali\u202ece",
        "ali\u2028ce",
        "ali\u2029ce",
        "ali\udcffce",
    ],
)
def test_identity_rejects_raw_controls_and_invalid_unicode(tmp_path, text):
    config = write_config(tmp_path, channels="")
    store = seed(config)
    with pytest.raises(ConfigurationError, match="control characters"):
        store.report_cve("CVE-2026-0001", by=text)
    assert store.reported_entries() == ()
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT COUNT(*) FROM watch_delivery").fetchone()[0] == 0


@pytest.mark.parametrize(
    "text",
    [
        "a\u2028b",
        "a\u2029b",
        "a\u0085b",
        "a\u009bb",
        "a\u202eb",
        "a\udcffb",
        "\nnote\t",
    ],
)
def test_note_rejects_raw_controls_and_invalid_unicode(tmp_path, text):
    config = write_config(tmp_path, channels="")
    store = seed(config)
    with pytest.raises(ConfigurationError, match="control characters"):
        store.report_cve("CVE-2026-0001", by="alice", note=text)
    assert store.reported_entries() == ()


def test_cli_rejects_invalid_unicode_without_writing_rows(tmp_path, capsys):
    config = write_config(tmp_path, channels="")
    seed(config)
    base = ["--config", str(config.config_path)]
    assert cli.main(
        [*base, "watch", "report", "CVE-2026-0001", "--by", "a\udcffb"]
    ) == 2
    error = capsys.readouterr().err
    assert "control characters" in error
    assert "\udcff" not in error
    assert cli.main(
        [*base, "watch", "report", "CVE-2026-0001", "--by", "alice", "--note", "a\udcffb"]
    ) == 2
    assert "control characters" in capsys.readouterr().err
    assert WatchStore(config.watch.database).reported_entries() == ()


@pytest.mark.parametrize(
    "value",
    [
        "CVE-2026-0001",
        "cve-2026-0001",
        "CVE-1999-0001",
    ],
)
def test_cve_ids_are_normalized(value):
    expected = value.upper()
    assert normalize_cve_id(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "CVE-2026-000",
        "CVE-2026-٠٠٠١",
        "CVE-2026-１２３４",
        "CVE-2026-" + "1" * 20,
        "not-a-cve",
    ],
)
def test_cve_ids_are_ascii_and_bounded(value):
    with pytest.raises(ConfigurationError, match="CVE id must look like"):
        normalize_cve_id(value)


def test_notice_rule_names_are_reserved():
    with pytest.raises(ConfigurationError, match="reserved"):
        parse_rules(
            [
                {
                    "name": "@reported",
                    "condition": {"cvss_min": 9},
                    "channels": ["hook"],
                }
            ]
        )


def test_schema_four_database_migrates_to_five_and_keeps_rows(tmp_path):
    config = write_config(tmp_path, channels="")
    store = seed(config)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "INSERT INTO watch_event(rule,cve_id,kind,reasons_json,details_json,"
            "occurrence,initial,created_at) VALUES "
            "('critical','CVE-2026-0001','match','[]','{}','match',0,?)",
            (NOW.isoformat(),),
        )
        event_id = db.execute("SELECT MAX(id) FROM watch_event").fetchone()[0]
        db.execute(
            "INSERT INTO watch_delivery(event_id,channel,status,attempts,"
            "last_error,first_attempt_at,updated_at) VALUES (?,?,?,?,?,?,?)",
            (event_id, "hook", "failed", 3, "connection failed", None, NOW.isoformat()),
        )
        db.execute("UPDATE watch_meta SET value='4' WHERE key='schema_version'")
        db.execute("DROP TABLE watch_report")
    upgraded = WatchStore(store.path, clock=lambda: NOW)
    upgraded.initialize()
    assert upgraded.metadata()["schema_version"] == "5"
    assert upgraded.status()["rows"] == 1
    with sqlite3.connect(store.path) as db:
        tables = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert db.execute("SELECT COUNT(*) FROM watch_event").fetchone()[0] == 1
        assert db.execute(
            "SELECT channel,status,attempts FROM watch_delivery"
        ).fetchall() == [("hook", "failed", 3)]
    assert "watch_report" in tables
    assert upgraded.report_cve("CVE-2026-0001", by="alice").changed is True


def test_cli_report_list_and_unreport(tmp_path, capsys):
    config = write_config(tmp_path, channels="")
    seed(config)
    base = ["--config", str(config.config_path)]

    assert cli.main([*base, "watch", "report", "CVE-2026-0001", "--by", "alice", "--note", "Ticket OPS-42"]) == 0
    output = capsys.readouterr().out
    assert "CVE-2026-0001  reported to clients by alice at " in output
    assert " UTC" in output

    assert cli.main([*base, "watch", "reported"]) == 0
    output = capsys.readouterr().out
    assert "CVE-2026-0001  alice  " in output
    assert " UTC  Ticket OPS-42" in output

    assert cli.main([*base, "watch", "report", "CVE-2026-0001", "--by", "bob"]) == 0
    output = capsys.readouterr().out
    assert "already reported to clients by alice" in output

    assert cli.main([*base, "watch", "unreport", "CVE-2026-0001", "--by", "bob", "--note", "Sent in error"]) == 0
    output = capsys.readouterr().out
    assert "report withdrawn by bob" in output

    assert cli.main([*base, "watch", "reported"]) == 0
    assert "no CVEs are marked as reported to clients" in capsys.readouterr().out

    assert cli.main([*base, "watch", "reported", "--all"]) == 0
    output = capsys.readouterr().out
    assert "reported by alice" in output
    assert "unreported by bob" in output
    assert "Sent in error" in output


def test_cli_report_rejects_an_unknown_cve(tmp_path, capsys):
    config = write_config(tmp_path, channels="")
    WatchStore(config.watch.database, clock=lambda: NOW).initialize()
    assert cli.main(
        ["--config", str(config.config_path), "watch", "report", "CVE-2026-9999"]
    ) == 2
    assert "not in the watch database" in capsys.readouterr().err


def test_cli_events_and_status_show_the_mark(tmp_path, capsys):
    config = write_config(tmp_path, channels="""
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
""", extra=RULE)
    store = seed(config)
    store.evaluate_touched(config.watch.rules, catalogs=config.watch.sources)
    store.report_cve("CVE-2026-0001", by="alice", note="Ticket OPS-42")

    assert cli.main(["--config", str(config.config_path), "watch", "events"]) == 0
    output = capsys.readouterr().out
    assert "Reported to clients by alice at " in output

    assert cli.main(["--config", str(config.config_path), "watch", "status"]) == 0
    assert "reported to clients: 1" in capsys.readouterr().out


def test_alert_and_initial_digest_show_the_mark():
    for initial in (False, True):
        message = build_messages(
            (event(reported=MARK, initial=initial),),
            channel_type="slack",
            grouping="run",
            max_items=20,
            names={"critical": "critical"},
            since="2026-10-27",
        )[0]
        assert (
            "Reported to clients by alice at 2026-11-03 12:00 UTC"
            in message.text
        )


def test_webhook_payload_includes_the_reported_state():
    marked = webhook_payload((event(reported=MARK),), {})["events"][0]
    assert marked["view"]["reported"] == {
        "by": "alice",
        "at": "2026-11-03T12:00:00+00:00",
        "note": "Ticket OPS-42",
    }
    plain = webhook_payload((event(reported=None),), {})["events"][0]
    assert plain["view"]["reported"] is None
    assert "notice" not in plain


@pytest.mark.parametrize(
    "kind,text,subject",
    [
        (
            "reported",
            "[REPORTED] CVE-2026-1234 reported to clients by alice at 2026-11-04 12:00 UTC",
            "CVEBeacon: [REPORTED] CVE-2026-1234",
        ),
        (
            "unreported",
            "[UNREPORTED] CVE-2026-1234 report withdrawn by alice at 2026-11-04 12:00 UTC",
            "CVEBeacon: [UNREPORTED] CVE-2026-1234",
        ),
    ],
)
def test_notice_messages_are_short_and_standalone(kind, text, subject):
    notice = event(
        kind,
        rule="@reported",
        details={"by": "alice", "note": "Ticket OPS-42"},
    )
    message = build_messages(
        (notice,),
        channel_type="slack",
        grouping="run",
        max_items=20,
        names={},
    )[0]
    assert message.subject == subject
    assert text in message.text
    assert "Ticket OPS-42" in message.text
    assert "CVSS" not in message.text
    assert message.event_ids == (1,)


def test_report_notification_is_sent_once_through_the_ledger(tmp_path):
    config = write_config(tmp_path, channels=CHANNELS)
    store = seed(config)
    requests: list[httpx.Request] = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    outcome = store.report_cve(
        "CVE-2026-0001", by="alice", note="Ticket OPS-42", notify_channels=("hook",)
    )
    assert outcome.channels == ("hook",)
    assert store.events() == ()

    report = deliver(config, store, handler)
    assert report.failed is False
    assert len(requests) == 1
    payload = json.loads(requests[0].content)
    assert payload["events"][0]["kind"] == "reported"
    assert payload["events"][0]["notice"]["by"] == "alice"
    assert payload["events"][0]["view"]["reported"]["note"] == "Ticket OPS-42"
    assert rows(store) == [("hook", "sent", 0)]

    again = deliver(config, store, handler)
    assert len(requests) == 1
    assert (again.channels[0].messages, again.channels[0].events) == (0, 0)
    assert rows(store) == [("hook", "sent", 0)]

    with sqlite3.connect(store.path) as db:
        channels = {
            row[0]
            for row in db.execute("SELECT DISTINCT channel FROM watch_delivery")
        }
    assert channels == {"hook"}


def test_failed_report_notification_waits_for_backoff_and_retries_once(tmp_path):
    config = write_config(tmp_path, channels=CHANNELS)
    store = seed(config)
    store.report_cve("CVE-2026-0001", by="alice", notify_channels=("hook",))
    attempts: list[str] = []

    def failing(request):
        attempts.append("failed")
        raise httpx.ConnectError("refused")

    first = deliver(config, store, failing)
    assert first.channels[0].failed == 1
    assert rows(store) == [("hook", "failed", 1)]

    too_soon = deliver(config, store, failing)
    assert len(attempts) == 1
    assert (too_soon.channels[0].messages, too_soon.channels[0].events) == (0, 0)

    def succeeding(request):
        attempts.append("sent")
        return httpx.Response(200, json={})

    retried = deliver(
        config, store, succeeding, now=NOW + timedelta(minutes=5)
    )
    assert retried.channels[0].events == 1
    assert attempts == ["failed", "sent"]
    assert rows(store) == [("hook", "sent", 1)]

    deliver(config, store, succeeding, now=NOW + timedelta(minutes=10))
    assert attempts == ["failed", "sent"]


def test_cli_report_attempts_delivery_immediately(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, channels=CHANNELS)
    seed(config)
    requests: list[httpx.Request] = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    base = ["--config", str(config.config_path)]
    assert cli.main(
        [*base, "watch", "report", "CVE-2026-0001", "--by", "alice", "--note", "Ticket OPS-42"]
    ) == 0
    output = capsys.readouterr().out
    assert "hook (webhook): 1 message, 1 event sent" in output
    assert len(requests) == 1

    assert cli.main([*base, "watch", "notify"]) == 0
    assert len(requests) == 1


def posted_events(requests) -> list[dict]:
    output = []
    for request in requests:
        payload = json.loads(request.content)
        output.extend(payload.get("events") or [])
    return output


def test_notices_follow_the_audit_order_in_one_run(tmp_path):
    config = write_config(tmp_path, channels=CHANNELS)
    store = seed(config)
    store.report_cve(
        "CVE-2026-0001", by="first", notify_channels=("hook",)
    )
    store.unreport_cve(
        "CVE-2026-0001", by="second", notify_channels=("hook",)
    )
    store.report_cve(
        "CVE-2026-0001", by="third", notify_channels=("hook",)
    )
    requests: list[httpx.Request] = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    report = deliver(config, store, handler)
    assert report.failed is False
    events = posted_events(requests)
    assert [event["kind"] for event in events] == [
        "reported",
        "unreported",
        "reported",
    ]
    assert [event["notice"]["by"] for event in events] == [
        "first",
        "second",
        "third",
    ]
    assert rows(store) == [("hook", "sent", 0)] * 3


def test_withdrawal_waits_for_a_failed_report_during_backoff(tmp_path):
    config = write_config(tmp_path, channels=CHANNELS)
    store = seed(config)
    store.report_cve(
        "CVE-2026-0001", by="first", notify_channels=("hook",)
    )

    def failing(request):
        raise httpx.ConnectError("refused")

    first = deliver(config, store, failing)
    assert first.channels[0].failed == 1
    store.unreport_cve(
        "CVE-2026-0001", by="second", notify_channels=("hook",)
    )

    requests: list[httpx.Request] = []

    def succeeding(request):
        requests.append(request)
        return httpx.Response(200, json={})

    blocked = deliver(config, store, succeeding)
    assert requests == []
    assert (blocked.channels[0].messages, blocked.channels[0].events) == (0, 0)

    retried = deliver(
        config, store, succeeding, now=NOW + timedelta(minutes=5)
    )
    assert retried.channels[0].events == 2
    assert [event["kind"] for event in posted_events(requests)] == [
        "reported",
        "unreported",
    ]
    assert sorted(rows(store)) == [("hook", "sent", 0), ("hook", "sent", 1)]


def test_given_up_notice_no_longer_blocks_later_notices(tmp_path):
    config = write_config(tmp_path, channels=CHANNELS)
    store = seed(config)
    store.report_cve(
        "CVE-2026-0001", by="first", notify_channels=("hook",)
    )

    def failing(request):
        raise httpx.ConnectError("refused")

    deliver(config, store, failing)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_delivery SET attempts=10")
        db.execute(
            "UPDATE watch_delivery SET status='failed', last_error='connection failed'"
        )
    store.unreport_cve(
        "CVE-2026-0001", by="second", notify_channels=("hook",)
    )
    requests: list[httpx.Request] = []

    def succeeding(request):
        requests.append(request)
        return httpx.Response(200, json={})

    report = deliver(config, store, succeeding)
    assert report.channels[0].events == 1
    assert [event["kind"] for event in posted_events(requests)] == ["unreported"]


def test_retry_failed_sends_the_predecessor_then_the_successor(tmp_path):
    config = write_config(tmp_path, channels=CHANNELS)
    store = seed(config)
    store.report_cve(
        "CVE-2026-0001", by="first", notify_channels=("hook",)
    )

    def failing(request):
        raise httpx.ConnectError("refused")

    deliver(config, store, failing)
    store.unreport_cve(
        "CVE-2026-0001", by="second", notify_channels=("hook",)
    )
    requests: list[httpx.Request] = []

    def succeeding(request):
        requests.append(request)
        return httpx.Response(200, json={})

    report = deliver(config, store, succeeding, retry_failed=True)
    assert report.failed is False
    assert [event["kind"] for event in posted_events(requests)] == [
        "reported",
        "unreported",
    ]


def test_retry_ambiguous_sends_the_predecessor_then_the_successor(tmp_path):
    config = write_config(tmp_path, channels=CHANNELS)
    store = seed(config)
    store.report_cve(
        "CVE-2026-0001", by="first", notify_channels=("hook",)
    )

    def ambiguous(request):
        raise httpx.ReadTimeout("timeout")

    deliver(config, store, ambiguous)
    store.unreport_cve(
        "CVE-2026-0001", by="second", notify_channels=("hook",)
    )
    requests: list[httpx.Request] = []

    def succeeding(request):
        requests.append(request)
        return httpx.Response(200, json={})

    assert deliver(config, store, succeeding).channels[0].events == 0
    report = deliver(config, store, succeeding, retry_ambiguous=True)
    assert report.failed is False
    assert [event["kind"] for event in posted_events(requests)] == [
        "reported",
        "unreported",
    ]


def test_immediate_notice_does_not_flush_unrelated_alerts(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, channels=CHANNELS, extra=RULE)
    store = seed(config)
    store.evaluate_touched(config.watch.rules, catalogs=config.watch.sources)
    requests: list[httpx.Request] = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(
        [
            "--config",
            str(config.config_path),
            "watch",
            "report",
            "CVE-2026-0001",
            "--by",
            "alice",
        ]
    ) == 0
    assert "1 message, 1 event sent" in capsys.readouterr().out
    assert [event["kind"] for event in posted_events(requests)] == ["reported"]
    pending = store.events(pending=True)
    assert [event.kind for event in pending] == ["match"]
    assert store.delivery_status(["hook"])[0].pending == 1


def test_immediate_notice_survives_a_failing_initial_summary(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, channels=CHANNELS, extra=RULE)
    store = seed(config)
    store.evaluate_touched(
        config.watch.rules, catalogs=config.watch.sources, initial=True
    )
    requests: list[httpx.Request] = []

    def handler(request):
        payload = json.loads(request.content)
        if any(event["initial"] for event in payload.get("events") or []):
            raise httpx.ConnectError("initial summary refused")
        requests.append(request)
        return httpx.Response(200, json={})

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(
        [
            "--config",
            str(config.config_path),
            "watch",
            "report",
            "CVE-2026-0001",
            "--by",
            "alice",
        ]
    ) == 0
    assert "1 message, 1 event sent" in capsys.readouterr().out
    assert [event["kind"] for event in posted_events(requests)] == ["reported"]
    with sqlite3.connect(store.path) as db:
        assert db.execute(
            "SELECT d.status FROM watch_delivery d "
            "JOIN watch_event e ON e.id=d.event_id WHERE e.initial=1"
        ).fetchall() == [("pending",)]


def test_immediate_notice_is_sent_with_an_exhausted_initial_backlog(
    tmp_path, monkeypatch, capsys
):
    identifiers = tuple(f"CVE-2026-{index:04d}" for index in range(1, 31))
    config = write_config(tmp_path, channels=CHANNELS, extra=RULE)
    store = seed(config, identifiers)
    store.evaluate_touched(
        config.watch.rules, catalogs=config.watch.sources, initial=True
    )
    requests: list[httpx.Request] = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(
        [
            "--config",
            str(config.config_path),
            "watch",
            "report",
            "CVE-2026-0001",
            "--by",
            "alice",
        ]
    ) == 0
    assert "1 message, 1 event sent" in capsys.readouterr().out
    assert [event["kind"] for event in posted_events(requests)] == ["reported"]
    with sqlite3.connect(store.path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM watch_delivery d "
            "JOIN watch_event e ON e.id=d.event_id "
            "WHERE e.initial=1 AND d.status='pending'"
        ).fetchone()[0] == len(identifiers)


def test_repeated_report_warns_about_a_failed_notice(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, channels=CHANNELS)
    seed(config)
    requests: list[httpx.Request] = []

    def failing(request):
        requests.append(request)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(failing))
    base = ["--config", str(config.config_path)]
    command = [*base, "watch", "report", "CVE-2026-0001", "--by", "alice"]
    assert cli.main(command) == 3
    assert len(requests) == 1
    assert cli.main(command) == 0
    output = capsys.readouterr().out
    assert "already reported to clients by alice" in output
    assert (
        "notice delivery failed earlier; run "
        "`cvebeacon watch notify --retry-failed`"
    ) in output
    assert len(requests) == 1
    final_store = WatchStore(config.watch.database)
    assert rows(final_store) == [("hook", "failed", 1)]


def test_repeated_report_does_not_add_a_second_notice(tmp_path):
    config = write_config(tmp_path, channels=CHANNELS)
    store = seed(config)
    requests: list[httpx.Request] = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    store.report_cve(
        "CVE-2026-0001", by="alice", notify_channels=("hook",)
    )
    deliver(config, store, handler)
    store.report_cve(
        "CVE-2026-0001", by="alice", notify_channels=("hook",)
    )
    deliver(config, store, handler)
    assert len(requests) == 1
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT COUNT(*) FROM watch_delivery").fetchone()[0] == 1


def test_reported_all_shows_notice_delivery_states(tmp_path, capsys):
    config = write_config(tmp_path, channels=CHANNELS)
    store = seed(config)
    store.report_cve(
        "CVE-2026-0001", by="alice", notify_channels=("hook",)
    )
    assert cli.main(
        ["--config", str(config.config_path), "watch", "reported", "--all"]
    ) == 0
    assert "notices: hook pending" in capsys.readouterr().out

    def failing(request):
        raise httpx.ConnectError("refused")

    deliver(config, store, failing)
    assert cli.main(
        ["--config", str(config.config_path), "watch", "reported", "--all"]
    ) == 0
    assert "notices: hook failed" in capsys.readouterr().out


def test_channels_without_notify_reported_get_nothing(tmp_path):
    config = write_config(tmp_path, channels=CHANNELS)
    channels = {channel.name: channel for channel in config.watch.channels}
    assert channels["hook"].notify_reported is True
    assert channels["quiet"].notify_reported is False

    store = seed(config)
    store.report_cve("CVE-2026-0001", by="alice", notify_channels=("hook",))
    with sqlite3.connect(store.path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM watch_delivery WHERE channel='quiet'"
        ).fetchone()[0] == 0


def test_invalid_notify_reported_setting_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="notify_reported must be true or false"):
        write_config(
            tmp_path,
            channels="""
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
notify_reported = "yes"
""",
        )
