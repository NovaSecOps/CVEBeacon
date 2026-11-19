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
    assert metadata["schema_version"] == "9"
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
        db.execute("UPDATE watch_meta SET value='9' WHERE key='schema_version'")
    for _ in range(2):
        with pytest.raises(StateError, match="Teams bot storage layout"):
            store.initialize()


def test_fresh_install_admits_its_own_status_constraint(tmp_path):
    path = tmp_path / "watch.db"
    WatchStore(path).initialize()
    with sqlite3.connect(path) as db:
        ddl = db.execute("SELECT sql FROM sqlite_master WHERE name='watch_cve'").fetchone()[0]
        assert "reserved" in ddl
        assert dict(db.execute("SELECT key,value FROM watch_meta"))["schema_version"] == "9"
