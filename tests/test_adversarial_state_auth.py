"""Preserve monitoring authority and isolate authentication failure state."""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import date, datetime
import json
from pathlib import Path
import sqlite3

import pytest

from cvebeacon import dashboard_auth
from cvebeacon.errors import StateError
from cvebeacon.state import StateStore
from cvebeacon.models import Asset, Applicability as A, Evidence, Finding, QueryResult, Vulnerability
from test_dashboard_auth import authenticated, encoded
from test_dashboard import setup


def test_ambiguous_schema_metadata_fails_without_mutation(tmp_path):
    path = tmp_path / "ambiguous.db"
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE schema_info(version INTEGER)")
        db.executemany("INSERT INTO schema_info VALUES (?)", [(2,), (999,)])
        db.commit()
        before = list(db.iterdump())
    with pytest.raises(StateError):
        StateStore(path).initialize()
    with closing(sqlite3.connect(path)) as db:
        assert list(db.iterdump()) == before


def restored_legacy(payload):
    vuln = payload["vulnerability"]
    if vuln.get("epss_date"):
        vuln = {**vuln, "epss_date": date.fromisoformat(vuln["epss_date"])}
    return Finding(Asset(**payload["asset"]), Vulnerability(**vuln), A(payload["applicability"]),
        payload["confidence"], payload["reason"], tuple(Evidence(**{
            **item, "retrieved_at": datetime.fromisoformat(item["retrieved_at"])}) for item in payload["evidence"]),
        tuple(payload["conflicts"]))


def populated_store(tmp_path):
    path = tmp_path / "legacy.db"
    sql = (Path(__file__).parent / "fixtures" / "schema2_populated.sql").read_text(encoding="utf-8")
    with closing(sqlite3.connect(path)) as db:
        db.executescript(sql)
    return StateStore(path)


def test_actual_legacy_state_preserves_history_deliveries_and_fingerprints(tmp_path):
    # Fixture was produced by the schema-2 application, with three assets,
    # repeated/changed scans, KEV/EPSS, failures and every delivery state.
    store = populated_store(tmp_path)
    with closing(sqlite3.connect(store.path)) as db:
        before = list(db.iterdump())
        payloads = [json.loads(row[0]) for row in db.execute("SELECT payload_json FROM current_findings")]
    store.initialize()
    store.initialize()
    with closing(sqlite3.connect(store.path)) as db:
        after = list(db.iterdump())
    for statement in before:
        if not statement.startswith('INSERT INTO "schema_info"'):
            assert statement in after
    results = []
    for asset_id in {item["asset"]["asset_id"] for item in payloads}:
        findings = tuple(restored_legacy(item) for item in payloads if item["asset"]["asset_id"] == asset_id)
        results.append(QueryResult(findings[0].asset, findings, ()))
    _, events = store.record_scan(results, channels=("teams", "email"))
    assert events == []
    assert len(store.history()) == 12
    assert len(store.pending_events("teams")) == 10
    assert len(store.pending_events("email")) == 12
    changed = replace(results[0].findings[0], vulnerability=replace(results[0].findings[0].vulnerability, cvss_score=9.9))
    assert len(store.record_scan([QueryResult(changed.asset, (changed,), ())])[1]) == 1
    assert store.record_scan([QueryResult(changed.asset, (changed,), ())])[1] == []
    store.record_scan([QueryResult(changed.asset, (), (), A.COVERAGE_UNKNOWN, "Synthetic outage")])
    snapshot = store.dashboard_snapshot()
    assert len(snapshot["findings"]) == 6
    assert all(row["last_seen"] != snapshot["latest"]["completed_at"] for row in snapshot["findings"])


def test_populated_migration_failure_restores_every_historical_row(tmp_path):
    store = populated_store(tmp_path)
    with closing(sqlite3.connect(store.path)) as db:
        db.execute("CREATE TRIGGER migration_failure BEFORE UPDATE ON schema_info BEGIN SELECT RAISE(ABORT,'forced migration failure'); END")
        db.commit()
        before = list(db.iterdump())
    with pytest.raises(StateError, match="forced migration failure"):
        store.initialize()
    with closing(sqlite3.connect(store.path)) as db:
        assert list(db.iterdump()) == before
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_throttle_exhaustion_does_not_deny_an_unrelated_origin(monkeypatch):
    monkeypatch.setattr(dashboard_auth, "check_password_hash", lambda encoded, password: password == "correct")
    auth = dashboard_auth.DashboardAuth("synthetic", 60, clock=lambda: 100)
    auth.max_origins = 2
    assert auth.login("192.0.2.1", "wrong") is None
    assert auth.login("192.0.2.2", "wrong") is None
    assert auth.login("192.0.2.3", "correct") is not None
    assert len(auth.attempts) <= 2


def test_concurrent_failures_reserve_before_hashing(monkeypatch):
    calls = []
    monkeypatch.setattr(dashboard_auth, "check_password_hash", lambda *args: calls.append(True) or False)
    auth = dashboard_auth.DashboardAuth("synthetic", 60, clock=lambda: 100)
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(lambda _: auth.login("2001:db8::1", "wrong"), range(32))) == [None] * 32
    assert calls == [True]


def test_cookie_forgery_restart_parallel_sessions_and_public_errors(authenticated):
    # Existing fixture creates realistic inventory/history. All requests below
    # challenge the gate before any protected data is loaded.
    from cvebeacon.dashboard import create_app
    from test_dashboard import post
    from test_dashboard_auth import PASSWORD

    config, _, client = authenticated
    app = client.application
    second = app.test_client()
    assert post(client, "/login", password=PASSWORD).status_code == 303
    assert post(second, "/login", password=PASSWORD).status_code == 303
    assert client.get("/").status_code == second.get("/").status_code == 200
    with second.session_transaction() as session:
        token = session["csrf"]
    assert second.post("/logout", data={"csrf": token}).status_code == 303
    assert client.get("/").status_code == 200
    cookie = client.get_cookie("cvebeacon_session").value
    attacker = app.test_client()
    payload, signature = cookie.rsplit(".", 1)
    # Trailing Base64 padding bits can change spelling without changing the
    # decoded MAC. Mutate its first character to alter actual signature bits.
    tampered = payload + "." + ("a" if signature[0] != "a" else "b") + signature[1:]
    attacker.set_cookie("cvebeacon_session", tampered)
    assert attacker.get("/").status_code == 303
    restarted = create_app(config).test_client()
    restarted.set_cookie("cvebeacon_session", cookie)
    assert restarted.get("/").status_code == 303
    for path in ("/reports", "/event/not-an-integer", "/findings?cvss=nan", "/static/../../state.db"):
        response = attacker.get(path)
        assert response.status_code in {303, 404}
        assert "Widget" not in response.text and "Traceback" not in response.text
        assert response.headers["Cache-Control"] == "no-store"
