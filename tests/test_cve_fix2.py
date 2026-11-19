"""Archive batching and sparse-state behavior after the archive-only redesign."""
import json

from cvebeacon.watch import cve_list
from cvebeacon.watch.store import WatchStore
from test_cve_explorer import official
from test_cve_list_feed import Release
from watch_support import NOW, mock_client, write_config

ID = 'CVE-2026-10001'
OTHER = 'CVE-2026-10002'


def test_batch_budget_is_bytes_not_only_record_count(tmp_path, monkeypatch):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='full')
    store=WatchStore(config.watch.database)
    records=[official(f'CVE-2026-{20000+i}',description='x'*100_000) for i in range(4)]
    fixture=Release(records)
    batch_sizes=[]
    original=store.upsert_cve_list
    def observe(batch,**kwargs):
        batch_sizes.append(sum(len(json.dumps(p,ensure_ascii=False).encode()) for p in batch))
        return original(batch,**kwargs)
    monkeypatch.setattr(store,'upsert_cve_list',observe)
    monkeypatch.setattr(cve_list,'BATCH_BYTES',150_000,raising=False)
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert len(batch_sizes)==4
    assert max(batch_sizes)<150_000


def test_sparse_schema_reinitialize_does_not_rebuild_existing_fts(tmp_path,monkeypatch):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_cve_list([official()])
    original=store._connect
    statements=[]
    def observed(*args,**kwargs):
        db=original(*args,**kwargs)
        db.set_trace_callback(statements.append)
        return db
    monkeypatch.setattr(store,'_connect',observed)
    store.initialize()
    assert not any("'rebuild'" in sql for sql in statements)
    assert store.search(query='Spring4Shell').total==1


def test_archive_only_schema_has_no_delta_repair_tables(tmp_path):
    store=WatchStore(tmp_path/'watch.db')
    store.initialize()
    with store.read() as db:
        names={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'watch_cve_list_queue' not in names
    assert 'watch_cve_list_observation' not in names
