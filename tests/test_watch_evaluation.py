from __future__ import annotations

import sqlite3
from datetime import date, datetime, timezone

import pytest

from cvebeacon.errors import StateError
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
        event = db.execute(
            "SELECT id,rule,cve_id,kind,reasons_json,occurrence FROM watch_event"
        ).fetchone()
        deliveries = db.execute(
            "SELECT channel,status,attempts FROM watch_delivery WHERE event_id=? ORDER BY channel",
            (event[0],),
        ).fetchall()
        assert deliveries == [("soc-email", "pending", 0), ("teams", "pending", 0)]
        assert event[5] == "match"
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO watch_event(rule,cve_id,kind,reasons_json,occurrence,"
                "initial,created_at) VALUES (?,?,?,?,?,0,?)",
                (
                    event[1],
                    event[2],
                    event[3],
                    '["different reason"]',
                    event[5],
                    NOW.isoformat(),
                ),
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
    assert latest.reasons == ("kev cisa false -> true",)
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
    result = store.evaluate_touched((configured,), catalogs=("nvd", "epss"))
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
    assert store.metadata()["schema_version"] == "5"
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
    assert "watch_report" in tables
    assert "vendors_json" in columns
    assert event_columns >= {"id", "rule", "cve_id", "kind", "reasons_json", "initial", "created_at"}
    assert delivery_columns >= {
        "event_id",
        "channel",
        "status",
        "attempts",
        "last_error",
        "first_attempt_at",
        "updated_at",
    }


def test_v1_upgrade_rewinds_the_euvd_cursor_to_the_initial_window(tmp_path):
    path = tmp_path / "watch.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE watch_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO watch_meta VALUES (?,?)",
            [
                ("schema_version", "1"),
                ("initial_mode", "backfill"),
                ("initial_window_start", "2026-11-01"),
                ("initialized_at", NOW.isoformat()),
                ("euvd_cursor", "2026-11-04"),
            ],
        )
        db.execute(
            "CREATE TABLE watch_euvd_item ("
            "euvd_id TEXT PRIMARY KEY, cve_ids_json TEXT NOT NULL, date_updated TEXT, "
            "score REAL, version TEXT, vector TEXT, exploited_since TEXT, "
            "seen_at TEXT NOT NULL)"
        )
    store = WatchStore(path, clock=lambda: NOW)
    store.initialize()
    assert store.metadata()["euvd_cursor"] == "2026-11-01"

    # The rewind happens once. Later syncs own the cursor again.
    with sqlite3.connect(path) as db:
        db.execute("UPDATE watch_meta SET value='2026-11-03' WHERE key='euvd_cursor'")
    store.initialize()
    assert store.metadata()["euvd_cursor"] == "2026-11-03"


def test_unknown_schema_version_still_fails_closed(tmp_path):
    path = tmp_path / "watch.db"
    store = WatchStore(path)
    store.initialize()
    with sqlite3.connect(path) as db:
        db.execute("UPDATE watch_meta SET value='9' WHERE key='schema_version'")
    with pytest.raises(Exception, match="unsupported watch schema version 9"):
        store.initialize()


def test_pre_release_alert_tables_fail_with_a_clear_message(tmp_path):
    path = tmp_path / "watch.db"
    WatchStore(path, clock=lambda: NOW).initialize()
    with sqlite3.connect(path) as db:
        # Schema version 2 as an earlier build wrote it, without the newer columns.
        db.execute("DROP TABLE watch_alert_state")
        db.execute(
            "CREATE TABLE watch_alert_state(rule TEXT NOT NULL, cve_id TEXT NOT NULL, "
            "first_matched_at TEXT NOT NULL, snapshot_json TEXT NOT NULL, "
            "PRIMARY KEY(rule, cve_id))"
        )
        db.execute("DROP TABLE watch_event")
        db.execute(
            "CREATE TABLE watch_event(id INTEGER PRIMARY KEY, rule TEXT NOT NULL, "
            "cve_id TEXT NOT NULL, kind TEXT NOT NULL, reasons_json TEXT NOT NULL, "
            "initial INTEGER NOT NULL, created_at TEXT NOT NULL)"
        )
    with pytest.raises(
        StateError,
        match=r"^watch database was created by a pre-release build; "
        r"delete it and run `watch sync` again$",
    ):
        WatchStore(path, clock=lambda: NOW).initialize()
    # Refused, not migrated: the old table shape is still there.
    with sqlite3.connect(path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(watch_alert_state)")}
    assert "providers_hash" not in columns


def test_v2_database_keeps_deliveries_and_adds_statuses(tmp_path):
    path = tmp_path / "watch.db"
    store = WatchStore(path, clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.evaluate_touched((rule(),), catalogs=("nvd",))
    event_id = store.events()[0].id
    with sqlite3.connect(path) as db:
        db.execute("UPDATE watch_meta SET value='2' WHERE key='schema_version'")
        db.execute("DROP TABLE watch_delivery")
        db.execute(
            "CREATE TABLE watch_delivery ("
            "event_id INTEGER NOT NULL, channel TEXT NOT NULL, "
            "status TEXT NOT NULL CHECK(status IN ('pending','sent','failed')), "
            "attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, "
            "updated_at TEXT NOT NULL, PRIMARY KEY(event_id, channel))"
        )
        db.execute(
            "INSERT INTO watch_delivery VALUES (?,?,?,?,?,?)",
            (event_id, "soc-email", "pending", 0, None, NOW.isoformat()),
        )
    upgraded = WatchStore(path, clock=lambda: NOW)
    upgraded.initialize()
    assert upgraded.metadata()["schema_version"] == "5"
    assert upgraded.delivery_status()[0].pending == 1
    upgraded.mark_delivery([event_id], "soc-email", "ambiguous", error="test")
    assert upgraded.delivery_status()[0].ambiguous == 1
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM watch_delivery").fetchone()[0] == 1
        tables = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "watch_report" in tables


def test_rejected_escalation_is_recorded(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    configured = rule()
    store.evaluate_touched((configured,), catalogs=("nvd",))
    store.acknowledge(store.pending_evaluations(10))
    store.upsert_nvd([record(status="rejected")], catalogs=("nvd",))
    result = store.evaluate_touched((configured,), catalogs=("nvd",))
    assert result.by_kind == (("rejected", 1),)
    assert store.events(limit=1)[0].reasons == ("status published -> rejected",)


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


V3_SCHEMA = (
    "CREATE TABLE watch_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """CREATE TABLE watch_cve (
        cve_id TEXT PRIMARY KEY, published TEXT, last_modified TEXT,
        status TEXT NOT NULL CHECK(status IN ('published','rejected')),
        description TEXT, source_identifier TEXT, cvss_json TEXT NOT NULL,
        cwes_json TEXT NOT NULL, products_json TEXT NOT NULL,
        references_json TEXT NOT NULL,
        ssvc_exploitation TEXT CHECK(ssvc_exploitation IN ('none','poc','active') OR ssvc_exploitation IS NULL),
        cisa_kev_added TEXT, cisa_kev_due TEXT, cisa_required_action TEXT,
        cisa_ransomware TEXT, first_seen TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    """CREATE TABLE watch_alert_state (
        rule TEXT NOT NULL, cve_id TEXT NOT NULL,
        first_matched_at TEXT NOT NULL, snapshot_json TEXT NOT NULL,
        rule_hash TEXT NOT NULL, providers_hash TEXT NOT NULL,
        PRIMARY KEY(rule, cve_id))""",
    """CREATE TABLE watch_event (
        id INTEGER PRIMARY KEY, rule TEXT NOT NULL, cve_id TEXT NOT NULL,
        kind TEXT NOT NULL, reasons_json TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}', occurrence TEXT NOT NULL,
        initial INTEGER NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(rule, cve_id, kind, occurrence))""",
    """CREATE TABLE watch_delivery (
        event_id INTEGER NOT NULL, channel TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','sending','sent','failed','ambiguous')),
        attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
        updated_at TEXT NOT NULL, PRIMARY KEY(event_id, channel))""",
)


def test_v3_database_adds_first_attempt_at_and_keeps_rows(tmp_path):
    path = tmp_path / "watch.db"
    with sqlite3.connect(path) as db:
        for statement in V3_SCHEMA:
            db.execute(statement)
        db.execute("INSERT INTO watch_meta VALUES ('schema_version','3')")
        db.execute(
            "INSERT INTO watch_cve(cve_id,status,cvss_json,cwes_json,"
            "products_json,references_json,first_seen,updated_at) "
            "VALUES ('CVE-2026-0001','published','[]','[]','[]','[]',?,?)",
            (NOW.isoformat(), NOW.isoformat()),
        )
        db.execute(
            "INSERT INTO watch_event(rule,cve_id,kind,reasons_json,details_json,"
            "occurrence,initial,created_at) VALUES "
            "('critical','CVE-2026-0001','match','[]','{}','match',0,?)",
            (NOW.isoformat(),),
        )
        db.execute(
            "INSERT INTO watch_delivery(event_id,channel,status,attempts,"
            "last_error,updated_at) VALUES (1,'hook','failed',2,?,?)",
            ("connection failed", NOW.isoformat()),
        )
    store = WatchStore(path, clock=lambda: NOW)
    store.initialize()
    assert store.metadata()["schema_version"] == "5"
    with sqlite3.connect(path) as db:
        columns = {
            row[1] for row in db.execute("PRAGMA table_info(watch_delivery)")
        }
        assert "first_attempt_at" in columns
        assert db.execute(
            "SELECT channel,status,attempts FROM watch_delivery"
        ).fetchall() == [("hook", "failed", 2)]
        assert db.execute("SELECT COUNT(*) FROM watch_event").fetchone()[0] == 1
        tables = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "watch_report" in tables
    assert store.report_cve("CVE-2026-0001", by="alice").changed is True


P1A_SCHEMA = (
    "CREATE TABLE watch_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """CREATE TABLE watch_cve (
        cve_id TEXT PRIMARY KEY, published TEXT, last_modified TEXT,
        status TEXT NOT NULL CHECK(status IN ('published','rejected')),
        description TEXT, source_identifier TEXT, cvss_json TEXT NOT NULL,
        cwes_json TEXT NOT NULL, products_json TEXT NOT NULL,
        references_json TEXT NOT NULL,
        ssvc_exploitation TEXT CHECK(ssvc_exploitation IN ('none','poc','active') OR ssvc_exploitation IS NULL),
        cisa_kev_added TEXT, cisa_kev_due TEXT, cisa_required_action TEXT,
        cisa_ransomware TEXT, first_seen TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    """CREATE TABLE watch_euvd_item (
        euvd_id TEXT PRIMARY KEY, cve_ids_json TEXT NOT NULL, date_updated TEXT,
        score REAL, version TEXT, vector TEXT, exploited_since TEXT,
        vendors_json TEXT NOT NULL, seen_at TEXT NOT NULL)""",
    """CREATE TABLE watch_euvd_alias (
        cve_id TEXT NOT NULL, euvd_id TEXT NOT NULL,
        PRIMARY KEY(cve_id, euvd_id),
        FOREIGN KEY(euvd_id) REFERENCES watch_euvd_item(euvd_id) ON DELETE CASCADE)""",
    """CREATE TABLE watch_kev (
        catalog TEXT NOT NULL CHECK(catalog IN ('cisa','eu')), cve_id TEXT NOT NULL,
        date_added TEXT, due_date TEXT, required_action TEXT, ransomware TEXT,
        PRIMARY KEY(catalog, cve_id))""",
    """CREATE TABLE watch_epss (
        cve_id TEXT PRIMARY KEY, epss REAL NOT NULL, percentile REAL NOT NULL,
        score_date TEXT NOT NULL)""",
    """CREATE TABLE watch_view (
        cve_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    """CREATE TABLE watch_touched (
        cve_id TEXT PRIMARY KEY, touched_at TEXT NOT NULL)""",
    """CREATE TABLE watch_lookup (
        cve_id TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL, last_error TEXT)""",
)


def build_p1a_database(path, *, initial_mode: str) -> None:
    with sqlite3.connect(path) as db:
        for statement in P1A_SCHEMA:
            db.execute(statement)
        db.execute("INSERT INTO watch_meta VALUES ('schema_version','1')")
        db.execute("INSERT INTO watch_meta VALUES ('nvd_cursor',?)", (NOW.isoformat(),))
        db.execute("INSERT INTO watch_meta VALUES ('initialized_at',?)", (NOW.isoformat(),))
        db.execute("INSERT INTO watch_meta VALUES ('initial_mode',?)", (initial_mode,))
        db.execute("INSERT INTO watch_meta VALUES ('initial_window_start','2026-10-27')")
        db.execute(
            "INSERT INTO watch_cve(cve_id,published,last_modified,status,description,"
            "source_identifier,cvss_json,cwes_json,products_json,references_json,"
            "ssvc_exploitation,first_seen,updated_at) VALUES "
            "('CVE-2026-0001','2026-11-01T00:00:00.000','2026-11-02T00:00:00.000',"
            "'published',NULL,NULL,'[]','[]','[]','[]',NULL,?,?)",
            (NOW.isoformat(), NOW.isoformat()),
        )
        for identifier in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"):
            db.execute(
                "INSERT INTO watch_touched VALUES (?,?)",
                (identifier, NOW.isoformat()),
            )


@pytest.mark.parametrize("initial_mode", ["baseline", "backfill"])
def test_p1a_queue_upgrade_drops_stale_obligations(tmp_path, initial_mode):
    path = tmp_path / "watch.db"
    build_p1a_database(path, initial_mode=initial_mode)
    store = WatchStore(path, clock=lambda: NOW)
    store.initialize()
    metadata = store.metadata()
    assert metadata["schema_version"] == "5"
    assert metadata["initial_evaluated_at"] == NOW.isoformat()
    assert store.pending_evaluations(10) == ()
    assert store.status()["rows"] == 1
    result = store.evaluate_touched((rule(),), catalogs=("nvd",))
    assert (result.evaluated, result.events) == (0, 0)


def touch(store: WatchStore, *identifiers: str) -> None:
    with sqlite3.connect(store.path) as db:
        db.executemany(
            "INSERT OR IGNORE INTO watch_touched(cve_id,touched_at) VALUES (?,?)",
            ((identifier, NOW.isoformat()) for identifier in identifiers),
        )


def test_rule_definition_change_updates_state_without_events(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    original = rule(condition={"cvss_min": 9})
    store.evaluate_touched((original,), catalogs=("nvd",))
    store.acknowledge(store.pending_evaluations(10))
    with sqlite3.connect(store.path) as db:
        first_hash = db.execute(
            "SELECT rule_hash FROM watch_alert_state"
        ).fetchone()[0]

    edited = rule(condition={"cvss_min": 5}, cvss_providers=["nvd"])
    touch(store, "CVE-2026-0001")
    result = store.evaluate_touched((edited,), catalogs=("nvd",))
    assert (result.evaluated, result.events) == (1, 0)
    with sqlite3.connect(store.path) as db:
        snapshot_json, second_hash = db.execute(
            "SELECT snapshot_json,rule_hash FROM watch_alert_state"
        ).fetchone()
    assert second_hash != first_hash
    assert '"severity_band":"critical"' in snapshot_json

    # After the silent state update, later evidence escalates normally.
    store.upsert_nvd([record(cisa_kev_added="2026-11-03")], catalogs=("nvd",))
    result = store.evaluate_touched((edited,), catalogs=("nvd",))
    assert result.by_kind == (("kev_added", 1),)


def test_cvss_provider_edit_does_not_create_a_false_increase(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd(
        [
            record(
                cvss=(
                    CVSSEntry("cna", "security@example.com", "3.1", 5.0),
                    CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8),
                )
            )
        ]
    )
    only_cna = rule(condition={"cvss_min": 1}, cvss_providers=["cna"])
    store.evaluate_touched((only_cna,), catalogs=("nvd",))
    store.acknowledge(store.pending_evaluations(10))
    all_providers = rule(condition={"cvss_min": 1})
    touch(store, "CVE-2026-0001")
    result = store.evaluate_touched((all_providers,), catalogs=("nvd",))
    assert result.events == 0
    with sqlite3.connect(store.path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM watch_event WHERE kind='severity_increase'"
        ).fetchone()[0] == 0


def cna_and_nvd(cna: float, nvd: float = 9.8) -> tuple[CVSSEntry, CVSSEntry]:
    return (
        CVSSEntry("cna", "security@example.com", "3.1", cna),
        CVSSEntry("nvd", "nvd@nist.gov", "3.1", nvd),
    )


def test_rule_edit_keeps_escalations_that_arrive_with_it(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    identifiers = [f"CVE-2026-{number:04d}" for number in range(1, 101)]
    store.upsert_nvd([record(identifier) for identifier in identifiers])
    store.evaluate_touched((rule(condition={"cvss_min": 9}),), catalogs=("nvd", "cisa_kev"))
    assert len(store.events(limit=500)) == 100
    store.acknowledge(store.pending_evaluations(500))

    store.replace_kev(
        "cisa",
        {identifier: KEVFields("2026-11-03") for identifier in identifiers[:10]},
        catalogs=("nvd", "cisa_kev"),
    )
    edited = rule(condition={"cvss_min": 8.5})
    result = store.evaluate_touched((edited,), catalogs=("nvd", "cisa_kev"))
    assert result.by_kind == (("kev_added", 10),)
    kinds = [event.kind for event in store.events(limit=500)]
    assert kinds.count("kev_added") == 10
    assert kinds.count("severity_increase") == 0


def test_provider_edit_with_a_kev_addition_alerts_once(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record(cvss=cna_and_nvd(5.0))])
    store.evaluate_touched(
        (rule(condition={"cvss_min": 1}, cvss_providers=["cna"]),),
        catalogs=("nvd", "cisa_kev"),
    )
    store.acknowledge(store.pending_evaluations(10))

    store.replace_kev(
        "cisa", {"CVE-2026-0001": KEVFields("2026-11-03")}, catalogs=("nvd", "cisa_kev")
    )
    all_providers = rule(condition={"cvss_min": 1})
    result = store.evaluate_touched((all_providers,), catalogs=("nvd", "cisa_kev"))
    assert result.by_kind == (("kev_added", 1),)


def test_provider_edit_rebaselines_the_severity_high_water_mark(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record(cvss=cna_and_nvd(5.0))])
    store.evaluate_touched((rule(condition={"cvss_min": 1}),), catalogs=("nvd",))
    store.acknowledge(store.pending_evaluations(10))

    # Going from critical (all providers) to medium (CNA only) is not an alert.
    only_cna = rule(condition={"cvss_min": 1}, cvss_providers=["cna"])
    touch(store, "CVE-2026-0001")
    result = store.evaluate_touched((only_cna,), catalogs=("nvd",))
    assert result.events == 0
    store.acknowledge(store.pending_evaluations(10))

    # Under the new providers the band is medium, so a rise to high alerts.
    store.upsert_nvd([record(cvss=cna_and_nvd(7.5))])
    result = store.evaluate_touched((only_cna,), catalogs=("nvd",))
    assert result.by_kind == (("severity_increase", 1),)
    increases = [event for event in store.events(limit=10) if event.kind == "severity_increase"]
    assert increases[0].reasons == ("severity medium -> high",)


def test_case_only_rule_rename_reuses_state(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    upper = rule(name="Critical")
    store.evaluate_touched((upper,), catalogs=("nvd",))
    assert len(store.events()) == 1
    store.acknowledge(store.pending_evaluations(10))
    lower = rule(name="critical")
    touch(store, "CVE-2026-0001")
    result = store.evaluate_touched((lower,), catalogs=("nvd",))
    assert result.events == 0
    assert len(store.events()) == 1
    assert store.events()[0].rule == "critical"


def test_rule_rename_starts_a_new_match(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.evaluate_touched((rule(name="first"),), catalogs=("nvd",))
    store.acknowledge(store.pending_evaluations(10))
    touch(store, "CVE-2026-0001")
    result = store.evaluate_touched((rule(name="second"),), catalogs=("nvd",))
    assert result.by_kind == (("match", 1),)
    assert {row.rule for row in store.events()} == {"first", "second"}


def test_watch_events_rule_filter_is_case_insensitive(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.evaluate_touched((rule(name="Critical"),), catalogs=("nvd",))
    assert len(store.events(rule="critical")) == 1
    assert len(store.events(rule="CRITICAL")) == 1


def test_corrupt_alert_state_names_the_rule_and_cve(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.evaluate_touched((rule(name="Critical"),), catalogs=("nvd",))
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_alert_state SET snapshot_json='{'")
    touch(store, "CVE-2026-0001")
    with pytest.raises(
        Exception, match=r"rule 'critical' and CVE CVE-2026-0001"
    ):
        store.evaluate_touched((rule(name="Critical"),), catalogs=("nvd",))


def test_kev_readdition_alerts_only_for_a_new_date(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    configured = rule(condition={"cvss_min": 1})
    store.evaluate_touched((configured,), catalogs=("nvd", "cisa_kev"))
    store.acknowledge(store.pending_evaluations(10))

    def replace(added: str | None) -> None:
        fields = {"CVE-2026-0001": KEVFields(added)} if added else {}
        store.replace_kev("cisa", fields, catalogs=("nvd", "cisa_kev"))

    replace("2026-11-01")
    store.evaluate_touched((configured,), catalogs=("nvd", "cisa_kev"))
    assert {row.kind for row in store.events(rule="critical")} == {
        "match",
        "kev_added",
    }
    replace(None)
    store.evaluate_touched((configured,), catalogs=("nvd", "cisa_kev"))
    replace("2026-11-01")
    store.evaluate_touched((configured,), catalogs=("nvd", "cisa_kev"))
    assert sum(
        row.kind == "kev_added" for row in store.events(rule="critical", limit=20)
    ) == 1
    replace(None)
    store.evaluate_touched((configured,), catalogs=("nvd", "cisa_kev"))
    replace("2026-11-03")
    result = store.evaluate_touched((configured,), catalogs=("nvd", "cisa_kev"))
    assert result.by_kind == (("kev_added", 1),)
    assert sum(
        row.kind == "kev_added" for row in store.events(rule="critical", limit=20)
    ) == 2


def test_severity_oscillation_stores_one_event(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    low = (CVSSEntry("nvd", "nvd@nist.gov", "3.1", 8.0),)
    high = (CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8),)
    store.upsert_nvd([record(cvss=low)])
    configured = rule(condition={"cvss_min": 1})
    store.evaluate_touched((configured,), catalogs=("nvd",))
    store.upsert_nvd([record(cvss=high)], catalogs=("nvd",))
    store.evaluate_touched((configured,), catalogs=("nvd",))
    store.upsert_nvd([record(cvss=low)], catalogs=("nvd",))
    store.evaluate_touched((configured,), catalogs=("nvd",))
    store.upsert_nvd([record(cvss=high)], catalogs=("nvd",))
    result = store.evaluate_touched((configured,), catalogs=("nvd",))
    assert result.events == 0
    with sqlite3.connect(store.path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM watch_event WHERE kind='severity_increase'"
        ).fetchone()[0] == 1


def test_epss_oscillation_stores_one_event_per_new_maximum(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.replace_epss([("CVE-2026-0001", 0.6, 0.5, date(2026, 11, 3))])
    configured = rule(condition={"cvss_min": 1})
    store.evaluate_touched((configured,), catalogs=("nvd", "epss"))
    for score in (0.2, 0.95, 0.2, 0.95):
        store.replace_epss(
            [("CVE-2026-0001", score, 0.5, date(2026, 11, 3))]
        )
        store.evaluate_touched((configured,), catalogs=("nvd", "epss"))
    with sqlite3.connect(store.path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM watch_event WHERE kind='epss_increase'"
        ).fetchone()[0] == 1


def test_evaluate_all_marks_only_matches_initial(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    configured = rule(condition={"cvss_min": 1})
    store.evaluate_touched((configured,), catalogs=("nvd",))
    store.acknowledge(store.pending_evaluations(10))
    store.upsert_nvd([record(cisa_kev_added="2026-11-03")], catalogs=("nvd",))
    result = store.evaluate_all((configured,), catalogs=("nvd",), initial=True)
    assert result.by_kind == (("kev_added", 1),)
    row = store.events(limit=1)[0]
    assert row.kind == "kev_added" and row.initial is False


def test_initial_window_closes_only_after_a_complete_evaluation(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.evaluate_touched((rule(),), catalogs=("nvd",), initial=True, complete=False)
    assert "initial_evaluated_at" not in store.metadata()
    store.upsert_nvd([record("CVE-2026-0002")], catalogs=("nvd",))
    store.evaluate_touched((rule(),), catalogs=("nvd",), initial=True, complete=True)
    assert "initial_evaluated_at" in store.metadata()


def test_multibatch_evaluation_drains_a_larger_queue(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    identifiers = [f"CVE-2026-{index:04d}" for index in range(1, 6)]
    store.upsert_nvd([record(identifier) for identifier in identifiers])
    result = store.evaluate_touched((rule(),), catalogs=("nvd",), limit=2)
    assert (result.evaluated, result.events) == (5, 5)
    assert store.pending_evaluations(10) == ()


def test_crash_mid_batch_keeps_completed_batches_and_no_duplicates(tmp_path, monkeypatch):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    identifiers = [f"CVE-2026-{index:04d}" for index in range(1, 6)]
    store.upsert_nvd([record(identifier) for identifier in identifiers])
    original = WatchStore._evaluate_batch
    calls = {"count": 0}

    def flaky(self, db, batch, rules, catalogs, now, initial):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("simulated crash")
        return original(self, db, batch, rules, catalogs, now, initial)

    monkeypatch.setattr(WatchStore, "_evaluate_batch", flaky)
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.evaluate_touched((rule(),), catalogs=("nvd",), limit=1)
    assert len(store.events(limit=10)) == 1
    assert len(store.pending_evaluations(10)) == 4

    monkeypatch.setattr(WatchStore, "_evaluate_batch", original)
    result = store.evaluate_touched((rule(),), catalogs=("nvd",), limit=1)
    assert (result.evaluated, result.events) == (4, 4)
    assert len(store.events(limit=10)) == 5
    assert store.pending_evaluations(10) == ()
