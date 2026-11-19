"""Combined provider and Teams storage upgrade regressions."""

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
        db.execute("INSERT INTO watch_cve(cve_id,status,description,cvss_json,cwes_json,products_json,"
                   "references_json,first_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                   ("CVE-2026-0001", "published", "retained history", "[]", "[]", "[]", "[]", STAMP, STAMP))
        db.execute("INSERT INTO watch_event VALUES (1,'critical','CVE-2026-0001','new','[]','{}','one',0,?)", (STAMP,))
        db.execute("INSERT INTO watch_delivery VALUES (1,'bot','sent',2,NULL,?,?)", (STAMP, STAMP))
        db.execute("INSERT INTO watch_report(cve_id,action,by,at,chain,chain_version) VALUES "
                   "('CVE-2026-0001','report','operator',?,'retained-chain',1)", (STAMP,))
        if fixture != "watch_schema_v7.sql":
            db.execute("INSERT INTO watch_provider VALUES ('CVE-2026-0002','cve_list','{}','{}',NULL,?)", (STAMP,))
            db.execute("INSERT INTO watch_search VALUES ('CVE-2026-0002','cve_list','retained source text')")
            db.execute("INSERT INTO watch_origin VALUES ('CVE-2026-0002','cve_list')")
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name!='watch_meta'")]
        return {name: db.execute("SELECT * FROM " + name).fetchall() for name in tables}


@pytest.mark.parametrize("fixture", ["watch_schema_v7.sql", "watch_schema_cve_v8_upgraded.sql",
                                     "watch_schema_cve_v8.sql"])
def test_combined_upgrade_creates_both_features_and_preserves_history(tmp_path, fixture):
    path = tmp_path / "watch.db"
    before = populated_database(path, fixture)
    store = WatchStore(path)
    store.initialize()
    store.initialize()
    metadata = store.metadata()
    assert metadata["schema_version"] == "9"
    assert metadata["provider_storage"] == "sparse-v1"
    assert metadata["teams_bot_storage"] == "durable-v1"
    with sqlite3.connect(path) as db:
        assert {name: db.execute("SELECT * FROM " + name).fetchall() for name in before} == before
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"watch_provider", "watch_search", "watch_origin", "watch_teams_bot_batch",
                "watch_teams_bot_delivery", "watch_teams_bot_conversation"} <= tables
        assert {r[1] for r in db.execute("PRAGMA table_info(watch_search)")} == {"cve_id", "source", "text"}
        cve_ddl = db.execute("SELECT sql FROM sqlite_master WHERE name='watch_cve'").fetchone()[0]
        assert ("reserved" in cve_ddl) == (fixture == "watch_schema_cve_v8.sql")


def test_provider_marker_never_skips_damaged_bot_layout(tmp_path):
    path = tmp_path / "watch.db"
    populated_database(path, "watch_schema_cve_v8_upgraded.sql")
    store = WatchStore(path)
    store.initialize()
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE watch_teams_bot_delivery DROP COLUMN not_before")
        db.execute("UPDATE watch_meta SET value='sparse-v1' WHERE key='provider_storage'")
    for _ in range(2):
        with pytest.raises(StateError, match="Teams bot storage layout"):
            store.initialize()


def test_provider_layout_is_checked_even_with_current_version_and_markers(tmp_path):
    path = tmp_path / "watch.db"
    populated_database(path, "watch_schema_cve_v8_upgraded.sql")
    store = WatchStore(path)
    store.initialize()
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE watch_provider RENAME COLUMN payload_json TO damaged")
    with pytest.raises(StateError, match="provider storage layout"):
        store.initialize()


def test_upgraded_cve_fixture_keeps_the_legacy_status_constraint():
    with sqlite3.connect(":memory:") as db:
        db.executescript((FIXTURES / "watch_schema_cve_v8_upgraded.sql").read_text())
        ddl = db.execute("SELECT sql FROM sqlite_master WHERE name='watch_cve'").fetchone()[0]
        assert "reserved" not in ddl
        assert dict(db.execute("SELECT key,value FROM watch_meta"))["provider_storage"] == "sparse-v1"
