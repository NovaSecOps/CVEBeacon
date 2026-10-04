"""Current-source, offline regressions for the independent hostile review."""

from contextlib import closing
from dataclasses import replace
import importlib
from pathlib import Path
import sqlite3
import time
import uuid

import pytest

from cvebeacon_automation.common import AutomationError
from cvebeacon_automation.http import Response
from cvebeacon_automation.notifications import _sqlite, service
from cvebeacon_automation.notifications.adapters import bind, validate_channels
from cvebeacon_automation.notifications.ledger import ledger
from cvebeacon_automation.notifications.reader import core_reader
from test_automation_notifications import Clock, Wire, channel, config, core, dispatch, secrets


EXPENSIVE_SQL = """WITH RECURSIVE synthetic(x) AS
    (VALUES(1) UNION ALL SELECT x+1 FROM synthetic WHERE x<1000000000)
    SELECT count(*) FROM synthetic"""


@pytest.fixture(autouse=True)
def require_current_source():
    root = Path(__file__).resolve().parents[1] / "src"
    for name in ("adapters", "ledger", "reader", "service", "_sqlite"):
        module = importlib.import_module("cvebeacon_automation.notifications." + name)
        assert Path(module.__file__).resolve().is_relative_to(root)


@pytest.mark.parametrize("status", [408, 500, 502, 503, 504, 599])
def test_matrix_encryption_outage_retries_before_any_plaintext_put(tmp_path, secrets, status):
    class EncryptionWire(Wire):
        encryption_status = status

        def request(self, method, url, **kwargs):
            if method == "GET" and self.encryption_status != 404:
                self.calls.append((method, url, kwargs.get("headers", {}), b""))
                return Response(self.encryption_status, {}, b"temporarily unavailable")
            return super().request(method, url, **kwargs)

    cfg, filename, clock, wire = config(tmp_path, ("matrix",)), core(tmp_path), Clock(), EncryptionWire()
    first = dispatch(cfg, filename, wire, clock)
    assert first["channels"]["matrix"]["states"]["retryable"] == 1
    assert first["channels"]["matrix"]["states"]["permanent"] == 0
    assert [call[0] for call in wire.calls] == ["GET"]
    wire.encryption_status = 404
    clock.value += 60
    second = dispatch(cfg, filename, wire, clock)
    assert second["channels"]["matrix"]["states"]["accepted"] == 1
    assert [call[0] for call in wire.calls] == ["GET", "GET", "PUT"]


@pytest.mark.parametrize("status,body", [(200, b"{}"), (401, b"{}"),
    (404, b'{"errcode":"M_NOT_FOUND","errcode":"M_NOT_FOUND"}'), (404, b"{}")])
def test_matrix_uncertain_or_encrypted_state_still_refuses_plaintext(tmp_path, secrets, status, body):
    wire = Wire()

    def check(method, url, **kwargs):
        wire.calls.append((method, url))
        assert method == "GET"
        return Response(status, {}, body)

    wire.request = check
    target = bind(validate_channels((channel("matrix"),), tmp_path)[0])
    assert target.send("synthetic alert", "fixed-txn", transport_factory=wire.factory).state == "permanent"
    assert len(wire.calls) == 1


def test_discovery_digest_uses_actual_result_fields_and_only_safe_aggregates(tmp_path, monkeypatch):
    cfg = replace(config(tmp_path), operations={"enabled": True, "discovery": True, "interval_seconds": 60})
    state = {"status": "operational", "sources": {}, "core_exit": 0, "discovery": {
        "PRIVATE-ADDRESS-CANARY": {"status": "success", "changed": True, "scope_changed": False,
            "added": 2, "not_observed": 1, "service_changes": 3, "banner": "PRIVATE-BANNER-CANARY"},
        "scope-only": {"status": "success", "changed": True, "scope_changed": True,
            "added": 0, "not_observed": 0, "service_changes": 0},
        "failed": {"status": "failed", "changed": True, "added": 1000},
        "unchanged": {"status": "success", "changed": False, "added": 1000},
        "malformed": {"status": "success", "changed": True, "added": True,
            "not_observed": -1, "service_changes": "PRIVATE-COUNT-CANARY"},
    }}
    captured = []
    monkeypatch.setattr(service, "_deliver", lambda _, *, messages, **kwargs: captured.extend(messages))
    service.operational(cfg, state, {"status": "operational"}, clock=lambda: 2000000000.0)
    notices = [text for _, text in captured if "DISCOVERY" in text]
    assert len(notices) == 1 and "observation changes: 6" in notices[0]
    assert "Changed jobs: 3; changed scopes: 1" in notices[0]
    assert "PRIVATE-" not in notices[0]


@pytest.mark.parametrize("enabled,changed,status", [(False, True, "success"),
    (True, False, "success"), (True, True, "disabled"), (True, True, "incomplete")])
def test_idle_or_unsuccessful_discovery_does_not_emit_change_notice(tmp_path, monkeypatch, enabled, changed, status):
    cfg = replace(config(tmp_path), operations={"enabled": True, "discovery": enabled, "interval_seconds": 60})
    captured = []
    monkeypatch.setattr(service, "_deliver", lambda _, *, messages, **kwargs: captured.extend(messages))
    service.operational(cfg, {"status": "operational", "discovery": {
        "synthetic": {"status": status, "changed": changed, "added": 1}}}, {}, clock=lambda: 2000000000.0)
    assert not any("DISCOVERY" in text for _, text in captured)


def test_discovery_change_count_is_capped(tmp_path, monkeypatch):
    cfg = replace(config(tmp_path), operations={"enabled": True, "discovery": True, "interval_seconds": 60})
    captured = []
    monkeypatch.setattr(service, "_deliver", lambda _, *, messages, **kwargs: captured.extend(messages))
    service.operational(cfg, {"status": "operational", "discovery": {"synthetic": {
        "status": "success", "changed": True, "added": 10**12,
        "not_observed": 10**12, "service_changes": 10**12}}}, {}, clock=lambda: 2000000000.0)
    assert "observation changes: 10000" in captured[-1][1]


@pytest.mark.parametrize("declaration,composite", [("INTEGER", False), ("INT PRIMARY KEY", False),
    ("TEXT PRIMARY KEY", False), ("INTEGER UNIQUE", False), ("INTEGER", True)])
def test_noncanonical_core_event_primary_key_is_rejected_without_cursor_or_send(tmp_path, secrets, declaration, composite):
    cfg, filename, wire, clock = config(tmp_path, ("slack",)), core(tmp_path), Wire(), Clock()
    with closing(sqlite3.connect(filename)) as db:
        db.executescript("ALTER TABLE events RENAME TO original_events; CREATE TABLE events(event_id " + declaration + """,
            run_id TEXT,occurred_at TEXT,asset_id TEXT,cve_id TEXT,event_type TEXT,fingerprint TEXT,payload_json TEXT"""
            + (", PRIMARY KEY(event_id,run_id)" if composite else "") + ");")
        db.execute("INSERT INTO events SELECT * FROM original_events")
        if declaration == "INTEGER":
            db.execute("INSERT INTO events SELECT event_id,?,occurred_at,asset_id,cve_id,event_type,fingerprint,payload_json FROM original_events",
                       (str(uuid.uuid4()),))
        db.commit()
    before = filename.read_bytes()
    result = dispatch(cfg, filename, wire, clock)
    assert result["errors"] == {"slack": "event_preparation_failed"} and not wire.calls
    assert result["attempted"] == 0 and filename.read_bytes() == before
    with ledger(cfg, readonly=True) as db:
        assert db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM destinations").fetchone()[0] == 0


@pytest.mark.parametrize("schema_sql", [
    "CREATE TRIGGER synthetic_dwell AFTER INSERT ON deliveries BEGIN " + EXPENSIVE_SQL + "; END;",
    "CREATE VIEW synthetic_view AS " + EXPENSIVE_SQL,
    "CREATE INDEX synthetic_index ON deliveries(text)",
    "CREATE TABLE synthetic_table(value TEXT)",
])
@pytest.mark.parametrize("readonly", [False, True])
def test_foreign_ledger_schema_objects_are_rejected_before_writes(tmp_path, schema_sql, readonly):
    cfg = config(tmp_path)
    with ledger(cfg):
        pass
    path = cfg.state_dir / "notification-ledger.sqlite3"
    with closing(sqlite3.connect(path)) as db:
        db.executescript(schema_sql)
    before = path.read_bytes()
    with pytest.raises(AutomationError, match="unsupported_notification_ledger"):
        with ledger(cfg, readonly=readonly):
            pytest.fail("foreign schema must not reach ledger callers")
    assert path.read_bytes() == before


@pytest.mark.parametrize("kind", ["ledger", "core"])
def test_sql_statement_timeout_interrupts_expensive_work_with_fixed_error(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(_sqlite, "SQL_TIMEOUT_SECONDS", 0.02)
    manager = ledger(config(tmp_path)) if kind == "ledger" else core_reader(core(tmp_path))
    category = "notification_ledger_unavailable" if kind == "ledger" else "core_events_unreadable"
    started = time.monotonic()
    with pytest.raises(AutomationError, match=category):
        with manager as db:
            db.execute(EXPENSIVE_SQL).fetchone()
    assert time.monotonic() - started < 2


@pytest.mark.parametrize("kind", ["ledger", "core"])
def test_sql_deadline_resets_after_idle_time_for_each_statement(tmp_path, monkeypatch, kind):
    value = [0.0]
    monkeypatch.setattr(_sqlite.time, "monotonic", lambda: value[0])
    manager = ledger(config(tmp_path)) if kind == "ledger" else core_reader(core(tmp_path))
    query = "WITH RECURSIVE s(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM s WHERE x<10000) SELECT count(*) FROM s"
    with manager as db:
        for _ in range(3):
            value[0] += _sqlite.SQL_TIMEOUT_SECONDS + 1
            assert db.execute(query).fetchone()[0] == 10000


@pytest.mark.parametrize("chat,thread", [(77, None), (-10077, None), (-10077, 7)])
def test_telegram_numeric_destination_aliases_are_deduplicated(tmp_path, secrets, chat, thread):
    extra = {} if thread is None else {"message_thread_id": thread}
    channels = (channel("telegram", "integer", chat_id=chat, **extra),
                channel("telegram", "string", chat_id=str(chat), **extra))
    parsed = validate_channels(channels, tmp_path)
    assert bind(parsed[0]).destination == bind(parsed[1]).destination
    cfg, clock, wire = replace(config(tmp_path), notifications=channels), Clock(), Wire()
    result = dispatch(cfg, core(tmp_path), wire, clock)
    assert result["attempted"] == 1 and len(wire.calls) == 1
    assert result["errors"] == {"string": "channel_unavailable"}


def test_telegram_distinct_threads_remain_distinct_destinations(tmp_path, secrets):
    parsed = validate_channels((channel("telegram", "a", chat_id=-10077, message_thread_id=7),
                               channel("telegram", "b", chat_id="-10077", message_thread_id=8)), tmp_path)
    assert bind(parsed[0]).destination != bind(parsed[1]).destination
