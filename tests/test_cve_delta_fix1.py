"""Real release names, delta continuity and independent source initialization."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import httpx
import pytest

from cvebeacon.watch import cve_list
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.sync import sync_watch
from test_cve_explorer import official
from test_cve_list_feed import Release
from watch_support import NOW, mock_client, nvd_page, write_config


def test_observed_midnight_release_names_are_accepted():
    payload = json.loads((Path(__file__).parent/'fixtures/cvelist_release_midnight.json').read_text())
    with mock_client(lambda _: httpx.Response(200,json=[payload])) as http:
        assets,_ = cve_list.release(http,{})
    assert assets['baseline']['name'].endswith('.zip.zip')
    assert assets['delta']['size'] == 22
    assert assets['baseline']['name'][:10] != assets['delta']['name'][:10]


@pytest.mark.parametrize('initial',['full','backfill'])
def test_added_source_defaults_to_no_history(tmp_path,initial):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial=initial)
    store=WatchStore(config.watch.database)
    store.record_baseline(nvd_cursor=NOW.isoformat(),initialized_at=NOW.isoformat(),initial_mode=initial)
    fixture=Release([official()])
    with mock_client(fixture) as http:
        assert cve_list.sync(http,store,config.watch,NOW)[:3] == (0,0,0)
    assert not any('/download/' in request.url.path for request in fixture.requests)
    assert store.metadata()['cve_list_initial_mode'] == 'baseline'


def test_cve_failure_cannot_hold_other_initial_sources_open(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='backfill')
    def handler(request):
        return httpx.Response(200,json=nvd_page([])) if request.url.host=='services.nvd.nist.gov' else httpx.Response(503)
    store=WatchStore(config.watch.database)
    with mock_client(handler) as http:
        report=sync_watch(config,http,clock=lambda:NOW)
    assert report.failures == ('cve_list',)
    assert store.metadata().get('initial_sync_completed_at')
    store.evaluate_touched((),initial=report.initial_evaluation,complete=not report.failures)
    assert store.metadata().get('initial_evaluated_at')


def test_zip_member_limit_precedes_zipfile_allocation(monkeypatch):
    from io import BytesIO
    import zipfile
    from cvebeacon.errors import SourceError
    data=BytesIO()
    with zipfile.ZipFile(data,'w') as archive:
        for index in range(100):
            archive.writestr(str(index),'')
    monkeypatch.setattr(cve_list,'MAX_MEMBERS',10)
    monkeypatch.setattr(cve_list.zipfile,'ZipFile',lambda *args,**kwargs:pytest.fail('ZipFile allocated entries before checking the limit'))
    with pytest.raises(SourceError,match='directory|member'):
        tuple(cve_list._members(BytesIO(data.getvalue())))


def test_explicit_added_history_marks_only_its_matches_initial(tmp_path):
    from dataclasses import replace
    from cvebeacon.watch.records import WatchRecord,CVSSEntry
    from cvebeacon.watch.rules import parse_rules
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='full')
    rules=parse_rules([{'name':'critical','condition':{'cvss_min':9},'channels':['sink']}])
    config=replace(config,watch=replace(config.watch,rules=rules))
    store=WatchStore(config.watch.database)
    store.record_baseline(nvd_cursor=NOW.isoformat(),initialized_at='2026-01-01T00:00:00+00:00',initial_mode='full',initial_window_start='1999-01-01')
    store.set_metadata({'initial_sync_completed_at':'2026-01-01','initial_evaluated_at':'2026-01-01'})
    store.upsert_nvd([WatchRecord('CVE-2026-10002','published',published='2026-11-01',cvss=(CVSSEntry('nvd','nvd','3.1',9.8),))])
    with mock_client(Release([official()])) as http:
        report=sync_watch(config,http,clock=lambda:NOW,cve_list_initial='full',assume_yes=True)
    assert not report.initial_evaluation
    store.evaluate_touched(rules,catalogs=config.watch.sources,initial=report.initial_evaluation)
    events={event.cve_id:event for event in store.events()}
    assert events['CVE-2026-10001'].initial
    assert not events['CVE-2026-10002'].initial
    assert store.metadata()['cve_list_initial_evaluated_at']


def test_history_choice_requires_confirmation_before_requests(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='baseline')
    with mock_client(lambda _:pytest.fail('unconfirmed history reached a source')) as http:
        result=sync_watch(config,http,cve_list_initial='backfill',confirm=lambda _:False)
    assert result.cancelled


def test_retention_gap_uses_one_baseline_then_returns_to_deltas(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'))
    store=WatchStore(config.watch.database)
    start=(NOW-timedelta(days=60)).isoformat()
    store.set_metadata({'cve_list_start':start,'cve_list_cursor':start,'cve_list_initial_mode':'baseline'})
    fixture=Release([official()])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
        cve_list.sync(http,store,config.watch,NOW+timedelta(hours=1))
    assert sum('_all_CVEs_' in request.url.path for request in fixture.requests)==1
    assert store.view('CVE-2026-10001') is not None


def test_inconsistent_zip_counts_cannot_allocate_directory_objects(tmp_path,monkeypatch):
    import struct
    from cvebeacon.errors import SourceError
    path=tmp_path/'metadata.zip'
    # The declaration lies about the count. Headers are scanned with constant
    # memory before ZipFile may construct even one ZipInfo object.
    header=struct.pack('<4s6H3L5H2L',b'PK\x01\x02',20,20,0,0,0,0,0,0,0,1,0,0,0,0,0,0)+b'x'
    with path.open('wb') as file:
        for _ in range(50_000):
            file.write(header)
        size=file.tell()
        file.write(struct.pack('<4s4H2LH',b'PK\x05\x06',0,0,1,1,size,0,0))
    monkeypatch.setattr(cve_list,'MAX_MEMBERS',1000)
    monkeypatch.setattr(cve_list.zipfile,'ZipFile',lambda *a,**kw:pytest.fail('unbounded directory allocation'))
    with path.open('rb') as file,pytest.raises(SourceError,match='directory'):
        tuple(cve_list._members(file))


def test_unconfirmed_pre_fix_history_marker_does_not_authorize_download(tmp_path):
    config=write_config(tmp_path,sources=('nvd','cve_list'),initial='full')
    store=WatchStore(config.watch.database)
    store.record_baseline(nvd_cursor=NOW.isoformat(),initialized_at=NOW.isoformat(),initial_mode='full')
    store.set_metadata({'cve_list_start':NOW.isoformat(),'cve_list_initial_mode':'full'})
    fixture=Release([official()])
    with mock_client(fixture) as http:
        cve_list.sync(http,store,config.watch,NOW)
    assert not any('/download/' in request.url.path for request in fixture.requests)
    assert store.metadata()['cve_list_initial_mode']=='baseline'
