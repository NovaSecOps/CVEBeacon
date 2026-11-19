"""Archive-only feed coverage, initial semantics and independent manual refresh."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from cvebeacon.errors import SourceError
from cvebeacon.watch import cve_list
from cvebeacon.watch.records import WatchRecord
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.refresh import refresh_watch
from cvebeacon.watch.rules import parse_rules
from test_cve_explorer import official
from test_cve_list_feed import zipped
from watch_support import NOW, mock_client, write_config

ID='CVE-2026-10001'
OTHER='CVE-2026-10002'


def record(identifier=ID, *, updated=None, description='archive record'):
    payload=official(identifier,description=description)
    if updated is not None:
        payload['cveMetadata']['dateUpdated']=updated
    return payload


class Archives:
    def __init__(self, *, day=None, hour=12, baseline=(), delta=(), closed=None, baseline_day=None):
        self.day=day or NOW.date()
        self.baseline_day=baseline_day or self.day
        self.hour=hour
        self.baseline=list(baseline)
        self.delta=list(delta)
        self.closed=closed or {}
        self.requests=[]
        self.fail=set()
        self.files={}

    def asset(self,name,body,tag='fixture'):
        self.files[name]=body
        return {'name':name,'size':len(body),'digest':'sha256:'+hashlib.sha256(body).hexdigest(),
                'browser_download_url':cve_list.ASSET_PREFIX+tag+'/'+name}

    def __call__(self,request):
        self.requests.append(request)
        if '/tags/' in request.url.path:
            tag=request.url.path.rsplit('/',1)[1]
            for day,records in self.closed.items():
                if tag=='cve_'+str(day)+'_at_end_of_day':
                    name=str(day)+'_delta_CVEs_at_end_of_day.zip'
                    return httpx.Response(200,json={'assets':[self.asset(name,zipped(records),tag)]})
            return httpx.Response(404)
        if str(request.url).split('?',1)[0]==cve_list.RELEASE_URL:
            assets=[self.asset(str(self.baseline_day)+'_all_CVEs_at_midnight.zip.zip',zipped(self.baseline,nested=True)),
                    self.asset(f'{self.day}_delta_CVEs_at_{self.hour:02d}00Z.zip',zipped(self.delta))]
            etag='"'+hashlib.sha256(json.dumps(assets).encode()).hexdigest()+'"'
            release={'tag_name':f'cve_{self.day}_{self.hour:02d}00Z','assets':assets}
            return httpx.Response(304) if request.headers.get('if-none-match')==etag else httpx.Response(200,json=[release],headers={'etag':etag})
        name=request.url.path.rsplit('/',1)[1]
        if name in self.files:
            return httpx.Response(503) if name in self.fail else httpx.Response(200,content=self.files[name])
        pytest.fail('archive sync made an unexpected request: '+str(request.url))


def started(tmp_path, cursor=None, mode='full'):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial=mode)
    store=WatchStore(config.watch.database)
    cursor=cursor or NOW.replace(hour=2)
    store.set_metadata({'cve_list_initial_mode':mode,'cve_list_start':cursor.isoformat(),
                        'cve_list_cursor':cursor.isoformat(),'cve_list_initial_pending':'0'})
    return config,store


def test_same_day_hourly_delta_advances_only_after_import(tmp_path):
    config,store=started(tmp_path)
    fixture=Archives(delta=[record(updated=NOW.replace(hour=11).isoformat())])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
        assert cve_list.sync(http,store,config.watch,NOW)[:3]==(0,0,0)
    assert store.view(ID) is not None
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()
    assert sum('_delta_' in r.url.path and '/download/' in r.url.path for r in fixture.requests)==1
    assert not any('_all_CVEs_' in r.url.path for r in fixture.requests)


def test_missed_days_use_actual_end_of_day_archives(tmp_path):
    start=NOW-timedelta(days=2)
    config,store=started(tmp_path,start)
    fixture=Archives(delta=[record('CVE-2026-10003',updated=NOW.replace(hour=11).isoformat())],closed={
        start.date():[record(updated=start.replace(hour=23,minute=59).isoformat())],
        (start+timedelta(days=1)).date():[record(OTHER,updated=(start+timedelta(days=1,hours=12)).isoformat())]})
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.search().total==3
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()
    assert sum('_at_end_of_day' in r.url.path and '/tags/' in r.url.path for r in fixture.requests)==2
    assert not any('_all_CVEs_' in r.url.path for r in fixture.requests)


def test_missing_day_falls_back_to_one_baseline(tmp_path):
    config,store=started(tmp_path,NOW-timedelta(days=2))
    fixture=Archives(baseline=[record()],delta=[record(OTHER,updated=NOW.replace(hour=1).isoformat())])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.search().total==2
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()
    assert sum('_all_CVEs_' in r.url.path for r in fixture.requests)==1


def test_failed_archive_keeps_its_previous_cursor(tmp_path):
    config,store=started(tmp_path)
    before=store.metadata()['cve_list_cursor']
    fixture=Archives(delta=[record(updated=NOW.replace(hour=11).isoformat())])
    fixture.fail.add(f'{fixture.day}_delta_CVEs_at_1200Z.zip')
    with mock_client(fixture) as http,pytest.raises(SourceError):
        cve_list.sync(http,store,config.watch,NOW)
    assert store.metadata()['cve_list_cursor']==before
    fixture.fail.clear()
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.view(ID) is not None
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()


def test_baseline_mode_defers_alerts_until_after_the_initial_boundary(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='baseline')
    store=WatchStore(config.watch.database)
    old=record(updated=NOW.replace(hour=10).isoformat())
    fresh=record(OTHER,updated=(NOW+timedelta(minutes=30)).isoformat())
    fixture=Archives(baseline=[old],delta=[old])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
        assert len(fixture.requests)==1  # metadata, never a history body
        assert store.metadata()['cve_list_cursor']==NOW.isoformat()
        fixture.hour=13
        fixture.delta=[old,fresh]
        cve_list.sync(http,store,config.watch,NOW+timedelta(hours=1))
    rules=parse_rules([{'name':'critical','condition':{'cvss_min':9},'channels':['sink']}])
    store.evaluate_touched(rules,catalogs=('cve_list',))
    assert store.view(ID) is None
    assert store.view(OTHER) is not None
    assert [event.cve_id for event in store.events() if not event.initial]==[OTHER]


def test_baseline_mode_skips_end_of_day_records_at_or_before_cursor(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='baseline')
    store=WatchStore(config.watch.database)
    fixture=Archives(baseline=[],delta=[])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    old=record(updated=NOW.replace(hour=10).isoformat())
    fresh=record(OTHER,updated=NOW.replace(hour=13).isoformat())
    next_day=Archives(day=NOW.date()+timedelta(days=1),hour=1,delta=[],closed={NOW.date():[old,fresh]})
    with mock_client(next_day) as http:
        cve_list.sync(http,store,config.watch,NOW+timedelta(days=1,hours=1))
    rules=parse_rules([{'name':'critical','condition':{'cvss_min':9},'channels':['sink']}])
    store.evaluate_touched(rules,catalogs=('cve_list',))
    assert store.view(ID) is None
    assert store.view(OTHER) is not None
    assert [event.cve_id for event in store.events() if not event.initial]==[OTHER]


@pytest.mark.parametrize('mode',['baseline','backfill','full'])
def test_gap_fallback_imports_and_alerts_every_post_cursor_change(tmp_path,mode):
    cursor=NOW-timedelta(days=9)
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial=mode)
    store=WatchStore(config.watch.database)
    store.set_metadata({'cve_list_initial_mode':mode,
                        'cve_list_start':(NOW-timedelta(days=60)).isoformat(),
                        'cve_list_cursor':cursor.isoformat(),
                        'cve_list_initial_pending':'0'})
    ancient=record('CVE-2026-19999',updated=(NOW-timedelta(days=90)).isoformat())
    first=record('CVE-2026-10003',updated=(NOW-timedelta(days=6)).isoformat())
    second=record('CVE-2026-10004',updated=(NOW-timedelta(days=3)).isoformat())
    current=record(OTHER,updated=NOW.replace(hour=11).isoformat())
    fixture=Archives(baseline=[ancient,first,second],delta=[current])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()
    assert store.view('CVE-2026-19999') is None
    for identifier in ('CVE-2026-10003','CVE-2026-10004',OTHER):
        assert store.view(identifier) is not None
    rules=parse_rules([{'name':'critical','condition':{'cvss_min':9},'channels':['sink']}])
    store.evaluate_touched(rules,catalogs=('cve_list',))
    assert {event.cve_id for event in store.events() if not event.initial}=={
        'CVE-2026-10003','CVE-2026-10004',OTHER}


def test_fallback_failure_never_advances_the_cursor(tmp_path):
    cursor=NOW-timedelta(days=9)
    config,store=started(tmp_path,cursor)
    gap=record(updated=(NOW-timedelta(days=4)).isoformat())
    fixture=Archives(baseline=[gap])
    fixture.fail.add('2026-11-03_all_CVEs_at_midnight.zip.zip')
    with mock_client(fixture) as http,pytest.raises(SourceError):
        cve_list.sync(http,store,config.watch,NOW)
    assert store.metadata()['cve_list_cursor']==cursor.isoformat()
    assert store.view(ID) is None
    fixture.fail.clear()
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.view(ID) is not None
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()


def test_midnight_publication_window_holds_the_cursor_then_retries(tmp_path):
    cursor=NOW.replace(hour=23)
    config,store=started(tmp_path,cursor)
    next_day=NOW.date()+timedelta(days=1)
    early_at=datetime.combine(next_day,datetime.min.time(),timezone.utc)+timedelta(minutes=35)
    early=Archives(day=next_day,hour=0,baseline_day=NOW.date(),delta=[])
    with mock_client(early) as http,pytest.raises(SourceError,match='end-of-day'):
        cve_list.sync(http,store,config.watch,early_at)
    assert store.metadata()['cve_list_cursor']==cursor.isoformat()
    late=record(updated=NOW.replace(hour=23,minute=30).isoformat())
    retry=Archives(day=next_day,hour=1,baseline_day=NOW.date(),delta=[],closed={NOW.date():[late]})
    with mock_client(retry) as http:
        cve_list.sync(http,store,config.watch,early_at+timedelta(hours=1))
    assert store.view(ID) is not None
    assert store.metadata()['cve_list_cursor']==(
        datetime.combine(next_day,datetime.min.time(),timezone.utc)+timedelta(hours=1)).isoformat()


@pytest.mark.parametrize('broken',['missing','invalid'])
def test_missing_or_invalid_date_after_initialisation_is_imported_and_counted(tmp_path,broken):
    config,store=started(tmp_path)
    payload=record(description='no usable date')
    if broken=='missing':
        del payload['cveMetadata']['dateUpdated']
    else:
        payload['cveMetadata']['dateUpdated']='not-a-date'
    fixture=Archives(delta=[payload])
    with mock_client(fixture) as http:
        result=cve_list.sync(http,store,config.watch,NOW)
    assert result[0]==1
    assert store.view(ID) is not None
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()


@pytest.mark.parametrize('status',[200,404,503])
def test_manual_refresh_never_changes_feed_state_or_hides_full_import(tmp_path,status):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='full')
    store=WatchStore(config.watch.database)
    store.initialize()
    before={key:value for key,value in store.metadata().items() if key.startswith('cve_list_')}
    stale=record(updated='2020-01-01T00:00:00Z',description='stale manual body')
    with mock_client(lambda request:httpx.Response(404) if request.url.host=='services.nvd.nist.gov' else httpx.Response(status,json=stale if status==200 else {})) as http:
        refresh_watch(config,http,ID)
    assert {key:value for key,value in store.metadata().items() if key.startswith('cve_list_')}==before
    fixture=Archives(baseline=[record()])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.view(ID).description=='archive record'
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()


def test_full_import_accepts_record_without_updated_date(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='full')
    payload=record()
    del payload['cveMetadata']['dateUpdated']
    fixture=Archives(baseline=[payload])
    store=WatchStore(config.watch.database)
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.view(ID) is not None
    assert not any(r.url.path.endswith('.json') for r in fixture.requests)


def test_records_never_move_backwards_after_manual_refresh(tmp_path):
    config,store=started(tmp_path)
    newer=record(updated=NOW.replace(hour=11).isoformat(),description='newer manual body')
    store.upsert_cve_list([newer])
    fixture=Archives(delta=[record(updated=NOW.replace(hour=10).isoformat(),description='older archive')])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert store.view(ID).description=='newer manual body'
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()


def test_official_end_of_day_metadata_fixture():
    payload=json.loads((Path(__file__).parent/'fixtures/cvelist_release_end_of_day.json').read_text())
    with mock_client(lambda _:httpx.Response(200,json=payload)) as http:
        asset=cve_list.end_of_day(http,datetime(2026,11,18).date())
    assert asset['name']=='2026-11-18_delta_CVEs_at_end_of_day.zip'


def test_manual_refresh_preserves_existing_archive_cursor_and_token(tmp_path):
    config,store=started(tmp_path)
    store.set_metadata({'cve_list_archive_asset':'last fully imported archive'})
    before={key:value for key,value in store.metadata().items() if key.startswith('cve_list_')}
    with mock_client(lambda request:httpx.Response(404) if request.url.host=='services.nvd.nist.gov' else httpx.Response(200,json=record())) as http:
        refresh_watch(config,http,ID)
    assert {key:value for key,value in store.metadata().items() if key.startswith('cve_list_')}==before
    assert store.view(ID) is not None


def test_full_sized_baseline_finishes_in_one_call_with_bounded_batches(tmp_path,monkeypatch):
    from cvebeacon.watch.store import StepCounts
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='full')
    store=WatchStore(config.watch.database)
    fixture=Archives()
    count=430_000
    consumed=0
    largest=0
    def records(http,asset,**kwargs):
        if '_all_CVEs_' in asset['name']:
            for index in range(count):
                yield {'dataVersion':'5.1','cveMetadata':{'cveId':f'CVE-2026-{10000+index}','state':'PUBLISHED','dateUpdated':'2026-11-02T00:00:00Z'},'containers':{'cna':{'descriptions':[{'lang':'en','value':'synthetic'}]}}}
    def upsert(batch,**kwargs):
        nonlocal consumed,largest
        consumed+=len(batch)
        largest=max(largest,len(batch))
        assert sum(len(json.dumps(item,ensure_ascii=False).encode()) for item in batch)<=cve_list.BATCH_BYTES
        return StepCounts(new=len(batch),touched_ids=tuple(item['cveMetadata']['cveId'] for item in batch))
    monkeypatch.setattr(cve_list,'archive_records',records)
    monkeypatch.setattr(store,'upsert_cve_list',upsert)
    with mock_client(fixture) as http:
        result=cve_list.sync(http,store,config.watch,NOW)
    assert result[:3]==(count,count,0)
    assert consumed==count and largest<=cve_list.BATCH
    assert store.metadata()['cve_list_cursor']==NOW.isoformat()
    assert store.metadata()['cve_list_initial_pending']=='0'


def _release_entry(day, hour, *, baseline_day=None):
    baseline = f'{baseline_day or day}_all_CVEs_at_midnight.zip.zip'
    delta = f'{day}_delta_CVEs_at_{hour:02d}00Z.zip'
    assets = []
    for name in (baseline, delta):
        body = name.encode()
        assets.append({'name': name, 'size': len(body), 'digest': 'sha256:' + hashlib.sha256(body).hexdigest(),
                       'browser_download_url': cve_list.ASSET_PREFIX + 'fake/' + name})
    return {'tag_name': f'cve_{day}_{hour:02d}00Z', 'assets': assets}


def _end_of_day_entry(day):
    name = f'{day}_delta_CVEs_at_end_of_day.zip'
    body = name.encode()
    return {'tag_name': f'cve_{day}_at_end_of_day',
            'assets': [{'name': name, 'size': len(body), 'digest': 'sha256:' + hashlib.sha256(body).hexdigest(),
                        'browser_download_url': cve_list.ASSET_PREFIX + 'fake/' + name}]}


@pytest.mark.parametrize('first_kind', ['hourly', 'midnight', 'end_of_day', 'prerelease'])
def test_release_list_selects_newest_hourly_not_latest(first_kind):
    hourly = _release_entry('2026-11-19', 1)
    midnight = _release_entry('2026-11-19', 0, baseline_day='2026-11-18')
    end_of_day = _end_of_day_entry('2026-11-18')
    prerelease = _release_entry('2026-11-19', 2)
    prerelease['prerelease'] = True
    releases = {'hourly': [hourly, midnight, end_of_day],
                'midnight': [midnight, hourly, end_of_day],
                'end_of_day': [end_of_day, midnight, hourly],
                'prerelease': [prerelease, hourly, midnight, end_of_day]}[first_kind]
    seen = []
    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json=releases)
    with mock_client(handler) as http:
        assets, cache = cve_list.release(http, {})
    assert assets['delta']['name'] == '2026-11-19_delta_CVEs_at_0100Z.zip'
    assert assets['baseline']['name'] == '2026-11-19_all_CVEs_at_midnight.zip.zip'
    assert not any(url.endswith('/latest') for url in seen)
    assert 'per_page=' in seen[0]
    assert json.loads(cache['cve_list_release'])['assets'][:2]


def test_end_of_day_latest_falls_back_to_the_midnight_release():
    releases = [_end_of_day_entry('2026-11-18'), _release_entry('2026-11-19', 0, baseline_day='2026-11-18')]
    with mock_client(lambda _: httpx.Response(200, json=releases)) as http:
        assets, _ = cve_list.release(http, {})
    assert assets['delta']['name'] == '2026-11-19_delta_CVEs_at_0000Z.zip'
    assert assets['baseline']['name'] == '2026-11-18_all_CVEs_at_midnight.zip.zip'


def test_baseline_disk_preflight_accepts_expanded_archive_plus_margin(tmp_path, monkeypatch):
    from collections import namedtuple
    usage = namedtuple('usage', 'total used free')
    payload = official(description='x' * 200_000)
    fixture = Archives(baseline=[payload])
    asset = fixture.asset('2026-11-03_all_CVEs_at_midnight.zip.zip', zipped([payload], nested=True))
    # Three times the expanded archive plus the fixed reserve fits. The former
    # eight-times rule rejected this realistic free-space level.
    monkeypatch.setattr(cve_list.shutil, 'disk_usage', lambda _: usage(10**9, 0, 64*1024*1024 + 1_000_000))
    with mock_client(fixture) as http:
        assert len(list(cve_list.archive_records(http, asset, cache_directory=tmp_path/'cache'))) == 1


def test_watch_status_and_dashboard_show_cve_list_feed_state(tmp_path):
    from cvebeacon import dashboard
    from cvebeacon.watch.users import UserStore
    from cvebeacon.watch.sync import watch_status
    from test_dashboard_watch import PASSWORD, login
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='baseline')
    store=WatchStore(config.watch.database)
    store.set_metadata({'cve_list_cursor':'2026-11-03T12:00:00+00:00',
                        'cve_list_initial_mode':'baseline',
                        'cve_list_start':'2026-11-03T09:00:00+00:00',
                        'cve_list_initial_pending':'0'})
    output=watch_status(config.watch)
    assert 'cve_list cursor: 2026-11-03T12:00:00+00:00' in output
    assert 'initial baseline' in output and 'start 2026-11-03T09:00:00+00:00' in output
    users=UserStore(config.watch.users_database)
    users.add('admin',password=PASSWORD,is_admin=True)
    app=dashboard.create_app(config)
    try:
        client=app.test_client()
        login(client,'admin')
        page=client.get('/watch')
        assert 'CVE List cursor' in page.text
        assert '2026-11-03T12:00:00+00:00' in page.text
        assert 'CVE List initial mode' in page.text
        assert 'baseline' in page.text
    finally:
        app.extensions['dashboard_jobs'].shutdown()

def test_boundary_record_is_imported_after_the_cursor(tmp_path):
    config,store=started(tmp_path,NOW)
    boundary=record(updated=NOW.isoformat(),description='exactly on the boundary')
    fixture=Archives(hour=13,delta=[boundary])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW+timedelta(hours=1))
    assert store.view(ID) is not None
    assert store.metadata()['cve_list_cursor']==(NOW+timedelta(hours=1)).isoformat()


def test_boundary_replay_does_not_create_a_duplicate_event(tmp_path):
    config,store=started(tmp_path,NOW.replace(hour=11))
    boundary=record(updated=NOW.isoformat(),description='boundary replay')
    fixture=Archives(hour=12,delta=[boundary])
    rules=parse_rules([{'name':'critical','condition':{'cvss_min':9},'channels':['sink']}])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    store.evaluate_touched(rules,catalogs=('cve_list',))
    assert len(store.events(cve=ID))==1
    # Force the same boundary archive to be read again. The record is at the
    # cursor exactly; it must be re-offered idempotently, not alerted twice.
    store.set_metadata({'cve_list_archive_asset':'force-replay'})
    with mock_client(fixture) as http:
        result=cve_list.sync(http,store,config.watch,NOW)
    assert result[0]==1
    store.evaluate_touched(rules,catalogs=('cve_list',))
    assert len(store.events(cve=ID))==1


def test_new_reserved_record_with_old_date_reserved_is_imported(tmp_path):
    config,store=started(tmp_path,NOW.replace(hour=9))
    payload=official('CVE-2026-30001',state='RESERVED')
    del payload['containers']
    del payload['cveMetadata']['dateUpdated']
    payload['cveMetadata']['dateReserved']='2026-01-01T00:00:00Z'
    fixture=Archives(hour=13,delta=[payload])
    with mock_client(fixture) as http:
        result=cve_list.sync(http,store,config.watch,NOW+timedelta(hours=1))
    assert result[0]==1
    assert store.view('CVE-2026-30001') is not None


@pytest.mark.parametrize('broken',['missing','invalid'])
def test_existing_record_update_without_usable_date_is_stored(tmp_path,broken):
    config,store=started(tmp_path,NOW.replace(hour=9))
    first=record(description='version one',updated=NOW.replace(hour=10,minute=30).isoformat())
    with mock_client(Archives(hour=11,delta=[first])) as http:
        cve_list.sync(http,store,config.watch,NOW)
    corrected=record(description='corrected version two')
    if broken=='missing':
        del corrected['cveMetadata']['dateUpdated']
    else:
        corrected['cveMetadata']['dateUpdated']='not-a-date'
    with mock_client(Archives(hour=13,delta=[corrected])) as http:
        result=cve_list.sync(http,store,config.watch,NOW+timedelta(hours=1))
    assert result[0]==1
    assert store.view(ID).description=='corrected version two'
    with store.read() as db:
        row=db.execute("SELECT source_updated FROM watch_provider WHERE cve_id=? AND source='cve_list'",(ID,)).fetchone()
    assert row['source_updated']==cve_list._record_date(NOW.replace(hour=10,minute=30).isoformat())


def test_release_selection_skips_an_invalid_newest_candidate():
    invalid=_release_entry('2026-11-19',2)
    invalid['assets'][0]['size']=cve_list.ARCHIVE_CAP+1
    valid=_release_entry('2026-11-19',1)
    with mock_client(lambda _:httpx.Response(200,json=[invalid,valid])) as http:
        assets,_=cve_list.release(http,{})
    assert assets['delta']['name']=='2026-11-19_delta_CVEs_at_0100Z.zip'
