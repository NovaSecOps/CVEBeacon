"""Teams storage migration from released schema 7 and schema 8."""

from pathlib import Path
import sqlite3

import pytest

from cvebeacon.errors import StateError
from cvebeacon.watch.store import WatchStore

FIXTURES = Path(__file__).parent / "fixtures"
STAMP = "2026-01-01T00:00:00+00:00"


def populated_database(path, fixture):
    with sqlite3.connect(path) as db:
        db.executescript((FIXTURES / fixture).read_text())
        if fixture == "watch_schema_v7.sql":
            db.execute("INSERT INTO watch_cve(cve_id,status,description,cvss_json,cwes_json,products_json,"
                       "references_json,first_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                       ("CVE-2026-0001", "published", "retained history", "[]", "[]", "[]", "[]", STAMP, STAMP))
            db.execute("INSERT INTO watch_event VALUES (1,'critical','CVE-2026-0001','new','[]','{}','one',0,?)", (STAMP,))
            db.execute("INSERT INTO watch_delivery VALUES (1,'bot','sent',2,NULL,?,?)", (STAMP, STAMP))
            db.execute("INSERT INTO watch_report(cve_id,action,by,at,chain,chain_version) VALUES "
                       "('CVE-2026-0001','report','operator',?,'retained-chain',1)", (STAMP,))
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name!='watch_meta'")]
        return {name: db.execute("SELECT * FROM " + name).fetchall() for name in tables}


@pytest.mark.parametrize("fixture", ["watch_schema_v7.sql", "watch_schema_v8.sql"])
def test_released_schema_upgrade_creates_teams_storage_and_preserves_data(tmp_path, fixture):
    path = tmp_path / "watch.db"
    before = populated_database(path, fixture)
    store = WatchStore(path)
    store.initialize()
    store.initialize()
    metadata = store.metadata()
    assert metadata["schema_version"] == "10"
    assert metadata["provider_storage"] == "sparse-v1"
    assert metadata["teams_bot_storage"] == "durable-v1"
    with sqlite3.connect(path) as db:
        assert {name: db.execute("SELECT * FROM " + name).fetchall() for name in before} == before
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"watch_provider", "watch_search", "watch_origin", "watch_teams_bot_batch",
                "watch_teams_bot_delivery", "watch_teams_bot_conversation"} <= tables
        assert db.execute("SELECT count(*) FROM watch_teams_bot_batch").fetchone() == (0,)
        assert {r[1] for r in db.execute("PRAGMA table_info(watch_search)")} == {"cve_id", "source", "text"}
        cve_ddl = db.execute("SELECT sql FROM sqlite_master WHERE name='watch_cve'").fetchone()[0]
        # The legacy status constraint is left unchanged by the in-place upgrade.
        assert "reserved" not in cve_ddl


def test_schema_eight_fixture_keeps_provider_and_search_rows(tmp_path):
    path = tmp_path / "watch.db"
    populated_database(path, "watch_schema_v8.sql")
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT cve_id,source FROM watch_provider").fetchall() == [("CVE-2026-0002", "cve_list")]
        assert db.execute("SELECT text FROM watch_search").fetchone() == ("retained source text",)
    WatchStore(path).initialize()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT cve_id,source FROM watch_provider").fetchall() == [("CVE-2026-0002", "cve_list")]
        assert db.execute("SELECT text FROM watch_search").fetchone() == ("retained source text",)
        assert db.execute("SELECT cve_id,source FROM watch_origin").fetchall() == [("CVE-2026-0002", "cve_list")]


def test_version_and_markers_never_skip_damaged_bot_layout(tmp_path):
    path = tmp_path / "watch.db"
    populated_database(path, "watch_schema_v7.sql")
    store = WatchStore(path)
    store.initialize()
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE watch_teams_bot_delivery DROP COLUMN not_before")
        db.execute("UPDATE watch_meta SET value='sparse-v1' WHERE key='provider_storage'")
        db.execute("UPDATE watch_meta SET value='10' WHERE key='schema_version'")
    for _ in range(2):
        with pytest.raises(StateError, match="Teams bot storage layout"):
            store.initialize()


def test_fresh_install_admits_its_own_status_constraint(tmp_path):
    path = tmp_path / "watch.db"
    WatchStore(path).initialize()
    with sqlite3.connect(path) as db:
        ddl = db.execute("SELECT sql FROM sqlite_master WHERE name='watch_cve'").fetchone()[0]
        assert "reserved" in ddl
        assert dict(db.execute("SELECT key,value FROM watch_meta"))["schema_version"] == "10"


@pytest.mark.parametrize("version", [7, 8, 9])
def test_schema_ten_chain_preserves_history_and_initial_exploitation(tmp_path, version):
    from dataclasses import replace

    from cvebeacon.watch.cve_list import parse_record
    from cvebeacon.watch.records import WatchView, canonical_json
    from cvebeacon.watch.rules import parse_rules, providers_hash, rule_hash, snapshot_for
    from cvebeacon.watch.store import _nvd_content
    from test_cve_explorer import vulnrichment_record

    path = tmp_path / "watch.db"
    populated_database(path, f"watch_schema_v{version}.sql")
    tracked, active = parse_rules([
        {"name": "tracked", "condition": {"status": "published"}, "channels": ["bot"],
         "events": ["exploitation_active"]},
        {"name": "active", "condition": {"exploitation": "active"}, "channels": ["bot"],
         "events": ["match"], "old_cves": "alert"},
    ])
    active_ids = [f"CVE-2026-{index:05d}" for index in range(10000, 10120)]
    explicit_none = "CVE-2026-11000"
    identifiers = [*active_ids, explicit_none] if version >= 8 else active_ids[:1]
    bot_tables = ("watch_teams_bot_conversation", "watch_teams_bot_batch", "watch_teams_bot_delivery")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO watch_meta VALUES ('cve_list_cursor','retained-cursor')")
        if version == 9:
            db.execute("INSERT INTO watch_teams_bot_conversation VALUES "
                       "('tenant','app','recipient','https://example.com/','conversation')")
            db.execute("INSERT INTO watch_teams_bot_batch VALUES ('bot','tenant','app','batch','[1]','[]')")
            db.execute("INSERT INTO watch_teams_bot_delivery VALUES "
                       "('bot','tenant','app','recipient','message','sent',1,NULL,0,?)", (STAMP,))
        tables = ("watch_event", "watch_delivery", "watch_report", *(bot_tables if version == 9 else ()))
        before = {table: db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall() for table in tables}

        for identifier in identifiers:
            status = "active" if version == 7 else None
            db.execute(
                "INSERT INTO watch_cve(cve_id,status,description,cvss_json,cwes_json,products_json,"
                "references_json,ssvc_exploitation,first_seen,updated_at) "
                "VALUES (?,'published','Existing CVE','[]','[]','[]','[]',?,?,?)",
                (identifier, status, STAMP, STAMP),
            )
            snapshot = snapshot_for(WatchView(identifier, "published", ssvc_exploitation=status), tracked)
            db.execute("INSERT INTO watch_alert_state VALUES (?,?,?,?,?,?)",
                       ("tracked", identifier, STAMP, canonical_json(snapshot.as_dict()),
                        rule_hash(tracked), providers_hash(tracked)))
            if version >= 8:
                payload = vulnrichment_record(identifier, "none" if identifier == explicit_none else "active")
                content = _nvd_content(replace(parse_record(payload), ssvc_exploitation=None))
                db.execute("INSERT INTO watch_provider VALUES (?,'cve_list',?,?,?,?)",
                           (identifier, canonical_json(content), canonical_json(payload), STAMP, STAMP))
            else:
                db.execute("INSERT INTO watch_touched VALUES (?,?)", (identifier, STAMP))

    store = WatchStore(path)
    assert store.metadata()["schema_version"] == str(version)
    store.initialize()
    store.initialize()
    meta = store.metadata()
    assert meta["schema_version"] == "10"
    assert meta["provider_storage"] == "sparse-v1"
    assert meta["teams_bot_storage"] == "durable-v1"
    assert meta["explorer_storage"] == "indexed-v1"
    assert meta["cve_list_cursor"] == "retained-cursor"
    with store.read() as db:
        assert {table: [tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY 1")]
                for table in tables} == before
        assert db.execute("SELECT COUNT(*) FROM watch_initial_ssvc").fetchone()[0] == (
            len(active_ids) if version >= 8 else 0
        )
        assert db.execute("SELECT 1 FROM watch_touched WHERE cve_id=?", (explicit_none,)).fetchone() is None
    catalogs = ("nvd", "cve_list")
    rules = (tracked, active) if version >= 8 else (tracked,)
    result = store.evaluate_touched(rules, catalogs=catalogs, limit=19)
    assert result.by_kind == ((("match", len(active_ids)),) if version >= 8 else ())
    assert not store.delivery_events("bot", catalogs=catalogs)
    events = [event for event in store.events(limit=250) if event.rule == "active"]
    assert len(events) == (len(active_ids) if version >= 8 else 0)
    assert all(event.initial for event in events)
    if version >= 8:
        assert store.view(explicit_none, catalogs=catalogs).exploitation[0] == "none"
        assert store.search(exploitation="active", catalogs=catalogs).total == len(active_ids)
    assert store.evaluate_touched(rules, catalogs=catalogs).events == 0
