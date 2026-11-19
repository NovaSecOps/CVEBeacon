"""Audit regressions for source precedence, upgrade cost and isolated reads."""
from dataclasses import replace
from pathlib import Path
import sqlite3

import httpx
import pytest

from cvebeacon.errors import StateError
from cvebeacon.watch.records import CVSSEntry, EUVDUpdate, KEVFields, WatchRecord
from cvebeacon.watch.refresh import refresh_watch
from cvebeacon.watch.store import WatchStore
from test_cve_explorer import official
from watch_support import NOW, mock_client, write_config

ID = 'CVE-2026-10001'
OTHER = 'CVE-2026-10002'


@pytest.mark.parametrize('nvd_status,cve_status', [('rejected','PUBLISHED'), ('published','REJECTED'), ('published','RESERVED')])
@pytest.mark.parametrize('reverse', [False, True])
def test_nvd_status_and_description_keep_precedence(tmp_path, nvd_status, cve_status, reverse):
    store = WatchStore(tmp_path / 'watch.db')
    nvd = WatchRecord(ID, nvd_status, description='NVDOnlyKeyword ' + 'N' * 980,
                      last_modified='2026-11-03T00:00:00Z')
    payload = official(state=cve_status, description='CNAOnlyKeyword ' + 'C' * 980)
    actions = [lambda: store.upsert_nvd([nvd]), lambda: store.upsert_cve_list([payload])]
    for action in reversed(actions) if reverse else actions:
        action()
    view = store.view(ID, catalogs=('nvd','cve_list'))
    assert view.status == nvd_status
    assert view.description == nvd.description
    assert store.search(query='NVDOnlyKeyword').total == 1
    assert store.search(query='CNAOnlyKeyword').total == 1


def test_disabled_cve_source_cannot_supply_fields_or_filter_scores(tmp_path):
    store = WatchStore(tmp_path / 'watch.db')
    store.upsert_nvd([WatchRecord(ID, 'published')])
    store.upsert_cve_list([official()])
    assert store.view(ID, catalogs=('nvd','cve_list')).cvss
    store.apply_view_policy(('nvd',))
    view = store.view(ID, catalogs=('nvd',))
    assert not view.cvss and view.description is None and view.status == 'published'
    assert store.search(severity='critical', catalogs=('nvd',)).total == 0
    assert store.search(query='Spring4Shell', catalogs=('nvd',)).total == 0


def test_disabled_enrichment_filters_agree_with_views(tmp_path):
    store = WatchStore(tmp_path / 'watch.db')
    store.upsert_nvd([WatchRecord(ID, 'published', cvss=(CVSSEntry('nvd','nvd','3.1',4.0),))])
    store.replace_euvd_items([EUVDUpdate((ID,), 'EUVD-1', None, CVSSEntry('euvd','euvd','3.1',9.8))])
    store.replace_kev('eu', {ID: KEVFields('2026-11-01')})
    assert store.search(severity='critical', catalogs=('nvd',)).total == 0
    assert store.search(kev='yes', catalogs=('nvd',)).total == 0
    assert store.search(severity='critical', catalogs=('nvd','euvd')).total == 1


def test_refresh_leaves_shared_advisory_siblings_unchanged(tmp_path):
    config = write_config(tmp_path, sources=('nvd','euvd'))
    store = WatchStore(config.watch.database)
    store.upsert_nvd([WatchRecord(ID,'published'), WatchRecord(OTHER,'published')], catalogs=config.watch.sources)
    store.replace_euvd_items([EUVDUpdate((ID,OTHER), 'EUVD-1', None, CVSSEntry('euvd','euvd','3.1',4.0))], catalogs=config.watch.sources)
    before = store.view(OTHER, catalogs=config.watch.sources)
    def handler(request):
        if request.url.host == 'services.nvd.nist.gov':
            return httpx.Response(404)
        return httpx.Response(200, json={'total':1,'items':[{'id':'EUVD-1','aliases':ID + ',' + OTHER,'baseScore':9.8,'baseScoreVersion':'3.1'}]})
    with mock_client(handler) as http:
        refresh_watch(config, http, ID)
    assert store.view(OTHER, catalogs=config.watch.sources) == before
    assert store.pending_evaluations() == (OTHER,)
    assert store.view(ID, catalogs=config.watch.sources).cvss[0].score == 9.8


@pytest.mark.parametrize('operation', ['metadata','view','status','search','source_presence','provider_records'])
def test_read_operations_never_use_write_transaction(tmp_path, monkeypatch, operation):
    store = WatchStore(tmp_path / 'watch.db')
    store.upsert_nvd([WatchRecord(ID,'published')])
    def forbidden(*args, **kwargs):
        pytest.fail('read operation requested a write transaction')
    monkeypatch.setattr(WatchStore, 'transaction', forbidden)
    method = getattr(store, operation)
    method(ID) if operation in {'view','source_presence','provider_records'} else method()


def schema_seven(path, *, corrupt=False, extra=False):
    with sqlite3.connect(path) as db:
        db.executescript((Path(__file__).parent / 'fixtures/watch_schema_v7.sql').read_text())
        if extra:
            db.execute('ALTER TABLE watch_cve ADD COLUMN legacy_extra TEXT')
        db.execute("INSERT INTO watch_cve(cve_id,status,description,cvss_json,cwes_json,products_json,references_json,first_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                   (ID,'published','retained', 'invalid' if corrupt else '[]','[]','[]','[]','2026-11-01','2026-11-02'))


@pytest.mark.parametrize('corrupt,extra', [(False,False),(True,False),(False,True)])
def test_migration_adds_no_copies_and_tolerates_legacy_rows(tmp_path, corrupt, extra):
    path = tmp_path / 'watch.db'
    schema_seven(path, corrupt=corrupt, extra=extra)
    store = WatchStore(path)
    store.initialize()
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT count(*) FROM watch_provider').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM watch_search').fetchone()[0] == 0
        assert db.execute('SELECT description FROM watch_cve').fetchone()[0] == 'retained'
        assert db.execute("SELECT value FROM watch_meta WHERE key='schema_version'").fetchone()[0] == '9'
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert 'watch_cve_list_queue' not in names
        assert 'watch_cve_list_observation' not in names
    if corrupt:
        with pytest.raises(StateError, match=ID):
            store.view(ID)


def test_payload_display_is_bounded_but_storage_retains_record(tmp_path):
    store = WatchStore(tmp_path / 'watch.db')
    payload = official(description='x' * 100_000)
    store.upsert_cve_list([payload])
    display = store.provider_records(ID)[0]
    assert display['truncated']
    assert len(display['display']) <= 65_536
    with sqlite3.connect(store.path) as db:
        assert len(db.execute('SELECT payload_json FROM watch_provider').fetchone()[0]) > 100_000


def test_latest_absent_check_is_visible_with_retained_data(tmp_path):
    config = write_config(tmp_path, sources=('nvd',))
    store = WatchStore(config.watch.database)
    store.upsert_nvd([WatchRecord(ID,'published')])
    with mock_client(lambda _: httpx.Response(404)) as http:
        refresh_watch(config, http, ID)
    assert 'last check absent' in store.source_presence(ID)[0]['state']


def test_migration_rolls_back_all_added_tables_on_failure(tmp_path,monkeypatch):
    path=tmp_path/'watch.db'
    schema_seven(path,extra=True)
    def fail(_):
        raise StateError('injected migration failure')
    monkeypatch.setattr(WatchStore,'_ensure_search',fail)
    with pytest.raises(StateError,match='injected'):
        WatchStore(path).initialize()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT value FROM watch_meta WHERE key='schema_version'").fetchone()[0]=='7'
        assert db.execute('SELECT description FROM watch_cve').fetchone()[0]=='retained'
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='watch_provider'").fetchone()


def test_new_nvd_rejection_is_not_hidden_by_old_published_record(tmp_path):
    from cvebeacon.watch.rules import parse_rules
    store=WatchStore(tmp_path/'watch.db')
    rules=parse_rules([{'name':'critical','condition':{'cvss_min':9},'channels':['sink']}])
    store.upsert_cve_list([official()])
    store.evaluate_touched(rules,catalogs=('nvd','cve_list'))
    store.upsert_nvd([WatchRecord(ID,'rejected',last_modified='2026-11-04T00:00:00Z')],catalogs=('nvd','cve_list'))
    store.evaluate_touched(rules,catalogs=('nvd','cve_list'))
    assert store.view(ID,catalogs=('nvd','cve_list')).status=='rejected'
    assert [event.kind for event in store.events()].count('match')==1
    assert 'rejected' in [event.kind for event in store.events()]


def test_read_snapshot_proceeds_while_writer_is_open(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_nvd([WatchRecord(ID,'published',description='concurrent')])
    with ThreadPoolExecutor(max_workers=1) as pool:
        with store.transaction() as db:
            db.execute("UPDATE watch_cve SET description='uncommitted' WHERE cve_id=?",(ID,))
            future=pool.submit(store.search,query='concurrent')
            assert future.result(timeout=1).total==1


def test_later_positive_observation_supersedes_an_absent_check(tmp_path):
    from datetime import datetime,timezone
    config=write_config(tmp_path,sources=('nvd','cve_list'))
    store=WatchStore(config.watch.database)
    store.upsert_cve_list([official()])
    with store.transaction() as db:
        db.execute("INSERT INTO watch_source_check VALUES (?,'cve_list',0,'2020-01-01',NULL)",(ID,))
    assert {row['source']:row['state'] for row in store.source_presence(ID)}['cve_list']=='present'


def test_adding_an_empty_provider_does_not_requeue_existing_nvd(tmp_path):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_nvd([WatchRecord(ID,'published')])
    store.acknowledge([ID])
    store.set_metadata({'view_policy':'euvd,epss'})
    assert store.apply_view_policy(('nvd','euvd','epss','cve_list'))==()
    assert store.pending_evaluations()==()


def test_real_legacy_wide_columns_survive_version_one_upgrade(tmp_path):
    path=tmp_path/'watch.db'
    schema_seven(path)
    extras={'eu_kev_added':'TEXT','euvd_id':'TEXT','euvd_exploited_since':'TEXT',
            'epss':'REAL','epss_percentile':'REAL','epss_date':'TEXT','fingerprint':'TEXT'}
    with sqlite3.connect(path) as db:
        for name,kind in extras.items():
            db.execute(f'ALTER TABLE watch_cve ADD COLUMN {name} {kind}')
        db.execute("UPDATE watch_meta SET value='1' WHERE key='schema_version'")
        db.execute("UPDATE watch_cve SET euvd_id='EUVD-2026-1',epss=0.5")
    WatchStore(path).initialize()
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT description,euvd_id,epss FROM watch_cve').fetchone()==('retained','EUVD-2026-1',0.5)
        assert db.execute('SELECT count(*) FROM watch_provider').fetchone()[0]==0


def test_payload_preview_cap_is_utf8_bytes_not_characters(tmp_path):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_cve_list([official(description='😀'*100_000)])
    display=store.provider_records(ID)[0]
    assert display['truncated']
    assert len(display['display'].encode('utf-8'))<=65_536
