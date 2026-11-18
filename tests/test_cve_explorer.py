from __future__ import annotations

from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.records import WatchRecord


def official(identifier="CVE-2026-10001", state="PUBLISHED", description="Spring4Shell alias"):
    return {
        "dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {"cveId": identifier, "state": state,
                        "datePublished": "2026-11-01T00:00:00Z",
                        "dateUpdated": "2026-11-02T00:00:00Z"},
        "containers": {"cna": {
            "providerMetadata": {"shortName": "Example CNA", "dateUpdated": "2026-11-02T00:00:00Z"},
            "descriptions": [{"lang": "en", "value": description}],
            "affected": [{"vendor": "Example", "product": "Widget"}],
            "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8}}],
            "references": [{"url": "https://example.com/advisory"}],
        }},
    }


def test_cve_list_only_record_enters_watch_database(tmp_path):
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_cve_list([official()], catalogs=("cve_list",))
    view = store.view("CVE-2026-10001", catalogs=("cve_list",))
    assert view.description == "Spring4Shell alias"
    assert view.cvss[0].provider == "cna"
    assert view.vendors == ("Example",)


def test_search_normalizes_id_and_finds_description_alias(tmp_path):
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([WatchRecord("CVE-2026-10001", "published", description="Spring4Shell alias")])
    for query in (" cve-2026-10001 ", "Spring4Shell"):
        result = store.search(query=query)
        assert result.total == 1
        assert result.records[0].cve_id == "CVE-2026-10001"


def test_search_bounds_fts_fallback_and_provider_descriptions(tmp_path, monkeypatch):
    import pytest
    from cvebeacon.errors import StateError
    store = WatchStore(tmp_path / 'watch.db')
    payload = official(description='A' * 1100 + ' LongAliasBeyondPreview')
    store.upsert_cve_list([payload])
    assert store.search(query='LongAliasBeyondPreview').total == 1
    assert store.search(query='LongAliasBeyondPreview', use_fts=False).total == 1
    with pytest.raises(StateError, match='256'):
        store.search(query='x' * 257)
    assert store.search(query='" OR * ( )').total == 0
    assert store.search(query='%', use_fts=False).total == 0
    # Simulate a stdlib build without the FTS5 module from database creation.
    monkeypatch.setattr(WatchStore, '_ensure_search', lambda db: None)
    fallback = WatchStore(tmp_path / 'fallback.db')
    fallback.upsert_cve_list([official()])
    result = fallback.search(query='Spring4Shell')
    assert result.total == 1
    assert not result.fts


def test_search_filter_sort_and_pagination(tmp_path):
    from datetime import date
    from cvebeacon.watch.records import KEVFields
    store = WatchStore(tmp_path / 'watch.db')
    store.upsert_cve_list([official(), official('CVE-2026-10002')])
    store.upsert_nvd([WatchRecord('CVE-2026-10003', 'published', published='2020-01-01')])
    store.replace_kev('cisa', {'CVE-2026-10001': KEVFields('2026-11-01')})
    assert store.search(source='cve_list').total == 2
    assert store.search(source='nvd').total == 1
    assert store.search(severity='critical').total == 2
    assert store.search(kev='yes').records[0].cve_id == 'CVE-2026-10001'
    assert store.search(kev='no').total == 2
    assert store.search(has_events='yes').total == 0
    assert store.search(since=date(2026, 1, 1)).total == 2
    assert store.search(until=date(2020, 12, 31)).total == 1
    assert store.search(client_ids=('CVE-2026-10001',)).total == 1
    first = store.search(sort='published', limit=1)
    assert first.total == 3 and len(first.records) == 1
    assert store.search(sort='published', limit=1, offset=1).records != first.records
    assert len(store.search(limit=1000).records) == 3


def test_schema_seven_upgrade_preserves_records_events_and_resume(tmp_path):
    import sqlite3
    from pathlib import Path
    path = tmp_path / 'watch.db'
    schema = Path(__file__).with_name('fixtures') / 'watch_schema_v7.sql'
    with sqlite3.connect(path) as db:
        db.executescript(schema.read_text())
        db.execute("INSERT INTO watch_cve(cve_id,status,description,cvss_json,cwes_json,products_json,references_json,first_seen,updated_at) VALUES ('CVE-2026-10001','published','Stored alias','[]','[]','[]','[]','2026-11-01','2026-11-02')")
        db.execute("INSERT INTO watch_event(rule,cve_id,kind,reasons_json,details_json,occurrence,initial,created_at) VALUES ('critical','CVE-2026-10001','match','[]','{}','match',0,'2026-11-02')")
        db.execute("INSERT INTO watch_delivery(event_id,channel,status,attempts,updated_at) VALUES (1,'sink','sent',1,'2026-11-02')")
        db.execute("INSERT INTO watch_meta VALUES ('euvd_page_cursor','unchanged cursor')")
    store = WatchStore(path)
    store.initialize()
    assert store.metadata()['schema_version'] == '8'
    assert store.metadata()['euvd_page_cursor'] == 'unchanged cursor'
    assert store.search(query='Stored').total == 1
    assert store.view('CVE-2026-10001').first_seen == '2026-11-01'
    assert len(store.events()) == 1
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT status,attempts FROM watch_delivery').fetchone() == ('sent', 1)
    assert store.source_presence('CVE-2026-10001')[0]['state'] == 'present'
    store.upsert_cve_list([official('CVE-2026-10002', state='RESERVED')])
    assert store.view('CVE-2026-10002').status == 'reserved'
