from __future__ import annotations

import sqlite3
from datetime import date, datetime, timezone

import pytest

from cvebeacon.watch.records import CVSSEntry, EUVDUpdate, KEVFields, Product, WatchRecord
from cvebeacon.watch.rules import parse_rules
from cvebeacon.watch.store import WatchStore

NOW = datetime(2026, 11, 3, 7, 0, tzinfo=timezone.utc)


def record(identifier: str = "CVE-2026-0001", **overrides) -> WatchRecord:
    values = {
        "cve_id": identifier,
        "status": "published",
        "description": "Example vulnerability",
        "source_identifier": "security@example.com",
        "cvss": (CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8),),
        "cwes": ("CWE-79",),
        "products": (Product("acme", "widget"),),
    }
    values.update(overrides)
    return WatchRecord(**values)


def rule(name: str = "critical", condition: dict | None = None, **overrides):
    values = {
        "name": name,
        "condition": condition or {"cvss_min": 9},
        "channels": ["soc-email"],
    }
    values.update(overrides)
    return parse_rules([values])[0]


def test_touched_evaluation_is_idempotent_and_acknowledges(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    configured = rule()
    first = store.evaluate_touched((configured,), catalogs=("nvd",))
    assert (first.evaluated, first.events) == (1, 1)
    assert first.by_kind == (("match", 1),)
    assert store.pending_evaluations(10) == ()
    second = store.evaluate_touched((configured,), catalogs=("nvd",))
    assert (second.evaluated, second.events) == (0, 0)
    assert len(store.events()) == 1


def test_event_uniqueness_constraint_and_pending_deliveries(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    configured = rule(channels=["soc-email", "teams"])
    store.evaluate_touched((configured,), catalogs=("nvd",))
    with sqlite3.connect(store.path) as db:
        event = db.execute("SELECT id,rule,cve_id,kind,reasons_json FROM watch_event").fetchone()
        deliveries = db.execute(
            "SELECT channel,status,attempts FROM watch_delivery WHERE event_id=? ORDER BY channel",
            (event[0],),
        ).fetchall()
        assert deliveries == [("soc-email", "pending", 0), ("teams", "pending", 0)]
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO watch_event(rule,cve_id,kind,reasons_json,initial,created_at) "
                "VALUES (?,?,?,?,0,?)",
                (event[1], event[2], event[3], event[4], NOW.isoformat()),
            )


def test_initial_flag_for_touched_and_all(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record("CVE-2026-0001")])
    configured = rule()
    store.evaluate_touched((configured,), catalogs=("nvd",), initial=True)
    assert store.events()[0].initial is True
    assert "initial_evaluated_at" in store.metadata()

    other = WatchStore(tmp_path / "other.db", clock=lambda: NOW)
    other.upsert_nvd([record("CVE-2026-0002")])
    result = other.evaluate_all((configured,), catalogs=("nvd",), initial=True)
    assert (result.evaluated, result.events) == (1, 1)
    assert other.events()[0].initial is True
    assert other.pending_evaluations(10) == ("CVE-2026-0002",)


def test_escalation_is_stored_with_reasons_and_delivery(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    configured = rule()
    store.evaluate_touched((configured,), catalogs=("nvd",))
    store.acknowledge(store.pending_evaluations(10))
    store.upsert_nvd([record(cisa_kev_added="2026-11-03")], catalogs=("nvd",))
    result = store.evaluate_touched((configured,), catalogs=("nvd",))
    assert result.by_kind == (("kev_added", 1),)
    latest = store.events(limit=1)[0]
    assert latest.kind == "kev_added"
    assert latest.reasons == ("kev cisa false \u2192 true",)
    assert latest.initial is False


def test_euvd_vendor_names_reach_rule_filters(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record(products=())])
    store.acknowledge(store.pending_evaluations(10))
    store.replace_euvd_items(
        [
            EUVDUpdate(
                ("CVE-2026-0001",),
                "EUVD-1",
                None,
                None,
                None,
                (Product("Acme", "Widget"),),
            )
        ],
        catalogs=("nvd", "euvd"),
    )
    configured = rule(
        condition={"all": [{"vendor": ["acme"]}, {"product": ["widget"]}]}
    )
    result = store.evaluate_touched((configured,), catalogs=("nvd", "euvd"))
    assert result.by_kind == (("match", 1),)
    current = store.view("CVE-2026-0001", catalogs=("nvd", "euvd"))
    assert current is not None
    assert current.vendors == ("Acme",)
    assert current.products == ("Widget",)


def test_epss_only_touch_is_evaluated(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.acknowledge(store.pending_evaluations(10))
    store.replace_epss(
        [("CVE-2026-0001", 0.2, 0.5, date(2026, 11, 2))], thresholds=(0.3,)
    )
    store.acknowledge(store.pending_evaluations(10))
    changed = store.replace_epss(
        [("CVE-2026-0001", 0.4, 0.7, date(2026, 11, 3))], thresholds=(0.3,)
    )
    assert changed.changed_ids == ("CVE-2026-0001",)
    configured = rule(condition={"epss_min": 0.3})
    result = store.evaluate_touched((configured,), catalogs=("nvd",))
    assert result.by_kind == (("match", 1),)
    assert store.events()[0].reasons == ("epss 0.4",)


def test_evaluate_all_rechecks_existing_state_without_duplicates(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    configured = rule()
    store.evaluate_touched((configured,), catalogs=("nvd",))
    result = store.evaluate_all((configured,), catalogs=("nvd",), initial=True)
    assert (result.evaluated, result.events) == (1, 0)


def test_event_listing_filters_rule_limit_and_pending(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record("CVE-2026-0001"), record("CVE-2026-0002")])
    rules = (rule("first"), rule("second"))
    store.evaluate_touched(rules, catalogs=("nvd",))
    assert len(store.events()) == 4
    assert {row.rule for row in store.events(rule="first")} == {"first"}
    assert len(store.events(limit=2)) == 2
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_delivery SET status='sent' WHERE event_id IN "
            "(SELECT id FROM watch_event WHERE rule='first')"
        )
    pending = store.events(pending=True)
    assert {row.rule for row in pending} == {"second"}
    assert len(pending) == 2


def test_v1_database_migrates_in_place(tmp_path):
    path = tmp_path / "watch.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE watch_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO watch_meta VALUES ('schema_version','1')")
        db.execute(
            "CREATE TABLE watch_euvd_item ("
            "euvd_id TEXT PRIMARY KEY, cve_ids_json TEXT NOT NULL, date_updated TEXT, "
            "score REAL, version TEXT, vector TEXT, exploited_since TEXT, "
            "seen_at TEXT NOT NULL)"
        )
    store = WatchStore(path, clock=lambda: NOW)
    store.initialize()
    assert store.metadata()["schema_version"] == "2"
    with sqlite3.connect(path) as db:
        tables = {
            row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        columns = {row[1] for row in db.execute("PRAGMA table_info(watch_euvd_item)")}
        event_columns = {
            row[1] for row in db.execute("PRAGMA table_info(watch_event)")
        }
        delivery_columns = {
            row[1] for row in db.execute("PRAGMA table_info(watch_delivery)")
        }
    assert {"watch_alert_state", "watch_event", "watch_delivery"} <= tables
    assert "vendors_json" in columns
    assert event_columns >= {"id", "rule", "cve_id", "kind", "reasons_json", "initial", "created_at"}
    assert delivery_columns >= {"event_id", "channel", "status", "attempts", "last_error", "updated_at"}


def test_unknown_schema_version_still_fails_closed(tmp_path):
    path = tmp_path / "watch.db"
    store = WatchStore(path)
    store.initialize()
    with sqlite3.connect(path) as db:
        db.execute("UPDATE watch_meta SET value='9' WHERE key='schema_version'")
    with pytest.raises(Exception, match="unsupported watch schema version 9"):
        store.initialize()


def test_rejected_escalation_is_recorded(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    configured = rule()
    store.evaluate_touched((configured,), catalogs=("nvd",))
    store.acknowledge(store.pending_evaluations(10))
    store.upsert_nvd([record(status="rejected")], catalogs=("nvd",))
    result = store.evaluate_touched((configured,), catalogs=("nvd",))
    assert result.by_kind == (("rejected", 1),)
    assert store.events(limit=1)[0].reasons == ("status published \u2192 rejected",)


def test_deliveries_are_not_duplicated_when_an_event_already_exists(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    configured = rule()
    store.evaluate_touched((configured,), catalogs=("nvd",))
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM watch_alert_state")
        db.execute("DELETE FROM watch_touched")
        db.execute("INSERT INTO watch_touched(cve_id,touched_at) VALUES (?,?)", ("CVE-2026-0001", NOW.isoformat()))
    result = store.evaluate_touched((configured,), catalogs=("nvd",))
    assert result.events == 0
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT COUNT(*) FROM watch_delivery").fetchone()[0] == 1
