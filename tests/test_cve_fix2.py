"""Second verification regressions: durable revision obligations and cursor proof."""
from datetime import timedelta
import json
import sqlite3

import httpx
import pytest

from cvebeacon.errors import SourceError
from cvebeacon.watch import cve_list
from cvebeacon.watch.records import WatchRecord
from cvebeacon.watch.store import WatchStore
from test_cve_explorer import official
from test_cve_list_feed import Release, zipped
from watch_support import NOW, mock_client, write_config

ID = 'CVE-2026-10001'
OTHER = 'CVE-2026-10002'


def setup_repair(tmp_path, *, expected='2026-11-03T10:55:00Z', archive=None, raw=None, omit=False):
    config=write_config(tmp_path,sources=('nvd','cve_list'))
    store=WatchStore(config.watch.database)
    start=(NOW-timedelta(days=1)).isoformat()
    store.set_metadata({'cve_list_start':start,'cve_list_cursor':start,'cve_list_initial_mode':'baseline'})
    stale=official(description='stale body')
    stale['cveMetadata']['dateUpdated']='2026-11-03T09:00:00Z'
    fixture=Release([official()], [archive or stale])
    groups=[{'fetchTime':NOW.isoformat(),'numberOfChanges':0 if omit else 1,'new':[] if omit else [{'cveId':ID,'dateUpdated':expected}],'updated':[],'error':[]},
            {'fetchTime':(NOW-timedelta(days=30)).isoformat(),'numberOfChanges':0,'new':[],'updated':[],'error':[]}]
    def handler(request):
        if str(request.url)==cve_list.DELTA_LOG_URL:
            return httpx.Response(200,json=groups)
        if request.url.path.endswith(ID+'.json'):
            return httpx.Response(200,json=raw or stale)
        if '/tags/' in request.url.path:
            return httpx.Response(404)
        return fixture(request)
    return config,store,handler,fixture


def test_stale_revision_stays_queued_across_restart(tmp_path):
    config,store,handler,_=setup_repair(tmp_path)
    for _ in range(2):
        with mock_client(handler) as http:
            try:
                cve_list.sync(http,WatchStore(store.path),config.watch,NOW)
            except SourceError:
                pass
        with store.read() as db:
            assert db.execute('SELECT count(*) FROM watch_cve_list_queue').fetchone()[0]==1
        assert store.metadata()['cve_list_cursor'] < NOW.isoformat()


def test_incomplete_log_cannot_hide_archive_member(tmp_path):
    config,store,handler,fixture=setup_repair(tmp_path,omit=True)
    with mock_client(handler) as http:
        try:
            cve_list.sync(http,store,config.watch,NOW)
        except SourceError:
            pass
    assert store.view(ID) is not None
    assert any('_delta_' in r.url.path for r in fixture.requests)


def test_corrected_date_in_hourly_delta_survives_midnight(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'))
    store=WatchStore(config.watch.database)
    previous=official(description='old pre-correction')
    previous['cveMetadata']['dateUpdated']='2026-11-02T00:00:00Z'
    store.upsert_cve_list([previous])
    store.set_metadata({'cve_list_start':'2026-11-02T00:00:00Z','cve_list_cursor':'2026-11-03T10:00:00Z','cve_list_initial_mode':'baseline'})
    corrected=official(description='corrected record')
    corrected['cveMetadata']['dateUpdated']='2026-11-01T00:00:00Z'
    fixture=Release([previous],[corrected])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.view(ID).description=='corrected record'


def test_log_selects_revision_by_observation_not_largest_record_date():
    groups=[]
    for observed,revision in [('2026-11-03T11:00:00Z','2026-11-02T00:00:00Z'),('2026-11-03T12:00:00Z','2026-11-01T00:00:00Z')]:
        groups.append({'fetchTime':observed,'numberOfChanges':1,'new':[],'updated':[{'cveId':ID,'dateUpdated':revision}],'error':[]})
    groups.reverse()  # Upstream order is not the revision order.
    with mock_client(lambda _:httpx.Response(200,json=groups)) as http:
        changes,_,_=cve_list._log(http,NOW-timedelta(hours=1))
    assert changes[ID][1]=='2026-11-01T00:00:00.000Z'


def test_stale_log_cannot_move_cursor_backwards(tmp_path):
    config,store,handler,_=setup_repair(tmp_path)
    stale=[{'fetchTime':(NOW-timedelta(days=5)).isoformat(),'numberOfChanges':0,'new':[],'updated':[],'error':[]}]
    def response(request):
        return httpx.Response(200,json=stale) if str(request.url)==cve_list.DELTA_LOG_URL else handler(request)
    before=store.metadata()['cve_list_cursor']
    with mock_client(response) as http,pytest.raises(SourceError,match='older|cursor'):
        cve_list.sync(http,store,config.watch,NOW)
    assert store.metadata()['cve_list_cursor']==before


def test_midnight_gap_is_durable_even_with_an_empty_log_queue(tmp_path):
    config,store,handler,_=setup_repair(tmp_path,omit=True)
    before=store.metadata()['cve_list_cursor']
    with mock_client(handler) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.metadata()['cve_list_cursor']==before
    assert store.metadata()['cve_list_coverage_gap']


def test_explicit_history_reset_cannot_regress_previous_delta(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'))
    store=WatchStore(config.watch.database)
    old=official(description='midnight')
    current=official(description='current delta')
    current['cveMetadata']['dateUpdated']='2026-11-03T11:00:00Z'
    fixture=Release([old],[current])
    store.set_metadata({'cve_list_start':'2026-11-03T00:00:00Z','cve_list_cursor':'2026-11-03T10:00:00Z','cve_list_initial_mode':'baseline'})
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    def stop_at_delta(request):
        if '_delta_' in request.url.path:
            raise SourceError('cve_list','interrupted after baseline')
        return fixture(request)
    with mock_client(stop_at_delta) as http,pytest.raises(SourceError):
        cve_list.sync(http,store,config.watch,NOW+timedelta(hours=1),initial_mode='full')
    assert store.view(ID).description=='current delta'
    assert not store.metadata()['cve_list_delta_asset']


def test_batch_budget_is_bytes_not_only_record_count(tmp_path,monkeypatch):
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


def test_stale_target_cannot_replace_newer_archive_snapshot(tmp_path):
    current=official(description='new archive snapshot')
    current['cveMetadata']['dateUpdated']='2026-11-03T11:30:00Z'
    old=official(description='old log revision')
    old['cveMetadata']['dateUpdated']='2026-11-03T10:55:00Z'
    config,store,handler,_=setup_repair(tmp_path,archive=current,raw=old)
    with mock_client(handler) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.view(ID).description=='new archive snapshot'
    with store.read() as db:
        assert db.execute('SELECT count(*) FROM watch_cve_list_queue').fetchone()[0]==1


def test_corrected_date_persists_through_hourly_to_midnight_sequence(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'))
    store=WatchStore(config.watch.database)
    store.upsert_cve_list([official(description='old pre-correction')])
    store.set_metadata({'cve_list_start':'2026-11-02T00:00:00Z','cve_list_cursor':'2026-11-03T10:00:00Z','cve_list_initial_mode':'baseline'})
    corrected=official(description='corrected body')
    corrected['cveMetadata']['dateUpdated']='2026-11-01T00:00:00Z'
    phase=[0]
    names=['2026-11-03_delta_CVEs_at_1200Z.zip','2026-11-03_delta_CVEs_at_2300Z.zip','2026-11-04_delta_CVEs_at_0000Z.zip']
    fixture=Release([official()],[corrected])
    requests=[]
    def handler(request):
        import hashlib
        requests.append(request)
        body=zipped([] if phase[0]==2 else [corrected])
        assets=fixture.assets()
        assets[1].update(name=names[phase[0]],browser_download_url=cve_list.ASSET_PREFIX+'fake/'+names[phase[0]],size=len(body),digest='sha256:'+hashlib.sha256(body).hexdigest())
        if str(request.url)==cve_list.RELEASE_URL:
            return httpx.Response(200,json={'assets':assets})
        if str(request.url)==cve_list.DELTA_LOG_URL:
            return httpx.Response(200,json=[{'fetchTime':'2026-11-04T00:00:00Z','numberOfChanges':0,'new':[],'updated':[],'error':[]},
                {'fetchTime':'2026-11-03T11:00:00Z','numberOfChanges':1,'new':[],'updated':[{'cveId':ID,'dateUpdated':corrected['cveMetadata']['dateUpdated']}],'error':[]},
                {'fetchTime':'2026-10-04T00:00:00Z','numberOfChanges':0,'new':[],'updated':[],'error':[]}])
        if '/tags/' in request.url.path:
            return httpx.Response(404)
        return httpx.Response(200,content=body)
    with mock_client(handler) as http:
        for hour in (0,11,12):
            cve_list.sync(http,store,config.watch,NOW+timedelta(hours=hour))
            assert store.view(ID).description=='corrected body'
            phase[0]+=1
    assert store.metadata()['cve_list_cursor'].startswith('2026-11-03T23:00')
    assert store.metadata()['cve_list_coverage_gap']
    assert not any('_all_CVEs_' in r.url.path for r in requests)


def test_change_summary_byte_budget_keeps_committed_progress(tmp_path,monkeypatch):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='full')
    store=WatchStore(config.watch.database)
    fixture=Release([official(ID),official(OTHER)])
    monkeypatch.setattr(cve_list,'TOUCHED_BYTES',200,raising=False)
    with mock_client(fixture) as http:
        with pytest.raises(SourceError,match='memory budget'):
            cve_list.sync(http,store,config.watch,NOW)
        assert store.search().total==2
        cve_list.sync(http,store,config.watch,NOW)
    assert sum('_all_CVEs_' in r.url.path for r in fixture.requests)==1
    assert not store.metadata()['cve_list_initial_pending']=='1'


def test_sparse_schema_evolution_does_not_recover_provider_copies(tmp_path,monkeypatch):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_nvd([WatchRecord(ID,'published',description='retained')])
    with sqlite3.connect(store.path) as db:
        if 'expected_revision' in {row[1] for row in db.execute('PRAGMA table_info(watch_cve_list_queue)')}:
            db.execute('ALTER TABLE watch_cve_list_queue DROP COLUMN expected_revision')
        db.execute('DROP TABLE IF EXISTS watch_cve_list_observation')
    original=store._connect
    def guarded(*args,**kwargs):
        connection=original(*args,**kwargs)
        def authorize(action,table,column,*_):
            assert not (action==sqlite3.SQLITE_READ and table=='watch_provider' and column in ('payload_json','record_json')), 'sparse state re-entered provider-copy recovery'
            return sqlite3.SQLITE_OK
        connection.set_authorizer(authorize)
        return connection
    monkeypatch.setattr(store,'_connect',guarded)
    store.initialize()
    with store.read() as db:
        assert 'expected_revision' in {r['name'] for r in db.execute('PRAGMA table_info(watch_cve_list_queue)')}
        assert db.execute('SELECT count(*) FROM watch_cve_list_observation').fetchone()[0]==0
    assert store.view(ID).description=='retained'


def test_fix_one_asset_tokens_are_not_treated_as_archive_proof(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'))
    store=WatchStore(config.watch.database)
    fixture=Release([official()],[official(description='previously omitted')])
    cursor='2026-11-03T10:00:00+00:00'
    store.set_metadata({'cve_list_start':cursor,'cve_list_cursor':cursor,'cve_list_initial_mode':'baseline','cve_list_delta_asset':cve_list._asset_token(fixture.assets()[1])})
    with sqlite3.connect(store.path) as db:
        if 'expected_revision' in {row[1] for row in db.execute('PRAGMA table_info(watch_cve_list_queue)')}:
            db.execute('ALTER TABLE watch_cve_list_queue DROP COLUMN expected_revision')
        db.execute('DROP TABLE IF EXISTS watch_cve_list_observation')
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.view(ID).description=='previously omitted'
    assert store.metadata()['cve_list_coverage_gap']==cursor
    assert store.metadata()['cve_list_cursor']==cursor
    assert any('_delta_' in r.url.path for r in fixture.requests)


def test_sparse_queue_upgrade_does_not_rebuild_existing_fts(tmp_path,monkeypatch):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_cve_list([official()])
    with sqlite3.connect(store.path) as db:
        if 'expected_revision' in {row[1] for row in db.execute('PRAGMA table_info(watch_cve_list_queue)')}:
            db.execute('ALTER TABLE watch_cve_list_queue DROP COLUMN expected_revision')
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


def test_restored_pending_queue_does_not_require_cache_directory(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'))
    store=WatchStore(config.watch.database)
    fixture=Release([official()],[official()])
    assets=dict(zip(('baseline','delta'),fixture.assets()))
    cursor='2026-11-03T10:00:00+00:00'
    store.set_metadata({'cve_list_start':cursor,'cve_list_cursor':cursor,'cve_list_initial_mode':'baseline','cve_list_pending_until':NOW.isoformat(),'cve_list_pending_release':json.dumps(assets),'cve_list_repair_days':'[]','cve_list_delta_asset':cve_list._asset_token(assets['delta'])})
    with store.transaction() as db:
        db.execute('INSERT INTO watch_cve_list_queue(cve_id,fetch_time,expected_revision) VALUES (?,?,?)',(ID,NOW.isoformat(),cve_list._record_date(official()['cveMetadata']['dateUpdated'])))
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.view(ID) is not None
    assert not store.metadata()['cve_list_pending_until']


def test_unverified_retry_reloads_corrected_log_revision(tmp_path):
    config,store,original,_=setup_repair(tmp_path)
    with mock_client(original) as http:
        cve_list.sync(http,store,config.watch,NOW)
    corrected=official(description='later observed correction')
    corrected['cveMetadata']['dateUpdated']='2026-11-03T09:00:00Z'
    fixture=Release([official()],[corrected])
    later=NOW+timedelta(hours=1)
    groups=[{'fetchTime':later.isoformat(),'numberOfChanges':1,'new':[],'updated':[{'cveId':ID,'dateUpdated':corrected['cveMetadata']['dateUpdated']}],'error':[]},
            {'fetchTime':(NOW-timedelta(days=30)).isoformat(),'numberOfChanges':0,'new':[],'updated':[],'error':[]}]
    requests=[]
    def updated(request):
        requests.append(request)
        if str(request.url)==cve_list.DELTA_LOG_URL:
            return httpx.Response(200,json=groups)
        return fixture(request)
    with mock_client(updated) as http:
        cve_list.sync(http,store,config.watch,later)
    assert any(str(r.url)==cve_list.DELTA_LOG_URL for r in requests)
    assert store.view(ID).description=='later observed correction'
    with store.read() as db:
        assert db.execute('SELECT count(*) FROM watch_cve_list_queue').fetchone()[0]==0


def test_refreshing_log_does_not_requeue_verified_or_regress_newer_obligations(tmp_path):
    store=WatchStore(tmp_path/'watch.db')
    payload=official()
    revision=cve_list._record_date(payload['cveMetadata']['dateUpdated'])
    store.upsert_cve_list([payload])
    with store.transaction() as db:
        db.execute('INSERT INTO watch_cve_list_observation VALUES (?,?)',(ID,NOW.isoformat()))
        db.execute('INSERT INTO watch_cve_list_queue VALUES (?,?,?)',(OTHER,(NOW+timedelta(hours=1)).isoformat(),'2026-11-01T00:00:00.000Z'))
        cve_list._queue_revisions(db,{ID:(NOW,revision),OTHER:(NOW,'2026-11-02T00:00:00.000Z')})
        rows=db.execute('SELECT cve_id,expected_revision FROM watch_cve_list_queue').fetchall()
    assert [(row[0],row[1]) for row in rows]==[(OTHER,'2026-11-01T00:00:00.000Z')]
