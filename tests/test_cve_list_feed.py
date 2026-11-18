"""Offline release archives, initial modes, retry cursors and provider merges."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
from io import BytesIO
import json
import sqlite3
import zipfile

import httpx
import pytest

from cvebeacon.errors import SourceError, StateError
from cvebeacon.watch import cve_list
from cvebeacon.watch.records import WatchRecord
from cvebeacon.watch.rules import parse_rules
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.sync import sync_watch
from test_cve_explorer import official
from watch_support import NOW, mock_client, nvd_cve, nvd_page, write_config


def zipped(records, *, nested=False):
    data = BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for payload in records:
            name = payload['cveMetadata']['cveId']
            archive.writestr(f"cves/2026/10xxx/{name}.json", json.dumps(payload))
    if nested:
        outer = BytesIO()
        with zipfile.ZipFile(outer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("cves.zip", data.getvalue())
        return outer.getvalue()
    return data.getvalue()


class Release:
    def __init__(self, baseline, delta=(), *, nested=False):
        self.baseline = zipped(baseline, nested=nested)
        self.delta = zipped(delta)
        self.fail_delta = False
        self.conditional = False
        self.requests = []

    def assets(self):
        return [
            {"id": number, "name": name, "browser_download_url": cve_list.ASSET_PREFIX + 'fake/' + name,
             "size": len(body), "digest": 'sha256:' + hashlib.sha256(body).hexdigest()}
            for number, name, body in (
                (1, "2026-11-03_all_CVEs_at_midnight.zip", self.baseline),
                (2, "2026-11-03_delta_CVEs_at_1200Z.zip", self.delta),
            )
        ]

    def __call__(self, request):
        self.requests.append(request)
        if str(request.url) == cve_list.RELEASE_URL:
            if self.conditional and request.headers.get('if-none-match') == '"release"':
                return httpx.Response(304)
            return httpx.Response(200, json={"assets": self.assets()}, headers={"etag": '"release"'})
        if request.url.path.endswith('midnight.zip'):
            return httpx.Response(200, content=self.baseline)
        if request.url.path.endswith('1200Z.zip'):
            return httpx.Response(503) if self.fail_delta else httpx.Response(200, content=self.delta)
        if 'nvd.nist.gov' in request.url.host:
            return httpx.Response(200, json=nvd_page([]))
        raise AssertionError(f"unexpected request: {request.url}")


@pytest.mark.parametrize('nested', [False, True])
def test_full_baseline_and_hourly_delta(nested, tmp_path):
    baseline = official(description='Initial description')
    changed = official(description='Changed Spring4Shell alias')
    changed['cveMetadata']['dateUpdated'] = '2026-11-03T10:00:00Z'
    fixture = Release([baseline], [changed], nested=nested)
    config = write_config(tmp_path, sources=('nvd', 'cve_list'), initial='full')
    store = WatchStore(config.watch.database)
    with mock_client(fixture) as http:
        counts = cve_list.sync(http, store, config.watch, NOW)
    assert counts[:3] == (2, 1, 0)  # description alone does not change alert fingerprint
    assert store.view(baseline['cveMetadata']['cveId']).description == changed['containers']['cna']['descriptions'][0]['value']
    assert store.search(query='Spring4Shell').total == 1
    assert store.metadata()['cve_list_cursor'] == NOW.isoformat()
    assert not fixture.requests[0].headers.get('authorization')


def test_baseline_makes_no_requests_then_reads_cumulative_delta(tmp_path):
    fresh = official()
    fresh['cveMetadata']['dateUpdated'] = (NOW + timedelta(minutes=30)).isoformat()
    config = write_config(tmp_path, sources=('nvd', 'cve_list'))
    store = WatchStore(config.watch.database)
    fixture = Release([official('CVE-2026-10002')], [fresh])
    with mock_client(fixture) as http:
        assert cve_list.sync(http, store, config.watch, NOW)[:3] == (0, 0, 0)
        assert http.requests == 0
        cve_list.sync(http, store, config.watch, NOW + timedelta(hours=1))
    assert store.view('CVE-2026-10001') is not None
    assert store.view('CVE-2026-10002') is None
    assert len(fixture.requests) == 2


def test_backfill_filters_baseline_by_modified_date(tmp_path):
    recent, old = official(), official('CVE-2026-10002')
    old['cveMetadata']['dateUpdated'] = '2020-01-01T00:00:00Z'
    config = write_config(tmp_path, sources=('nvd', 'cve_list'), initial='backfill')
    store = WatchStore(config.watch.database)
    with mock_client(Release([recent, old])) as http:
        cve_list.sync(http, store, config.watch, NOW)
    assert store.search().total == 1


def test_resume_after_delta_failure_keeps_completed_baseline(tmp_path):
    fixture = Release([official()], [official('CVE-2026-10002')])
    fixture.fail_delta = True
    config = write_config(tmp_path, sources=('nvd', 'cve_list'), initial='full')
    store = WatchStore(config.watch.database)
    with mock_client(fixture) as http:
        with pytest.raises(SourceError):
            cve_list.sync(http, store, config.watch, NOW)
        assert 'cve_list_baseline_asset' in store.metadata()
        assert 'cve_list_cursor' not in store.metadata()
        fixture.fail_delta = False
        fixture.requests.clear()
        cve_list.sync(http, store, config.watch, NOW)
    assert store.search().total == 2
    assert not any(r.url.path.endswith('midnight.zip') for r in fixture.requests)


def test_conditionals_do_not_redownload_completed_archives(tmp_path):
    fixture = Release([official()])
    config = write_config(tmp_path, sources=('nvd', 'cve_list'), initial='full')
    store = WatchStore(config.watch.database)
    with mock_client(fixture) as http:
        cve_list.sync(http, store, config.watch, NOW)
        fixture.conditional = True
        fixture.requests.clear()
        assert cve_list.sync(http, store, config.watch, NOW)[:3] == (0, 0, 0)
    assert len(fixture.requests) == 1
    assert fixture.requests[0].headers['if-none-match'] == '"release"'


@pytest.mark.parametrize('state', ['PUBLISHED', 'REJECTED', 'RESERVED'])
def test_record_states_and_raw_containers_survive(state, tmp_path):
    payload = official(state=state)
    payload['containers']['adp'] = [{'providerMetadata': {'shortName': 'Example ADP'},
                                     'descriptions': [{'lang': 'en', 'value': 'Additional alias'}]}]
    store = WatchStore(tmp_path / 'watch.db')
    store.upsert_cve_list([payload])
    assert store.view('CVE-2026-10001').status == state.lower()
    assert store.provider_records('CVE-2026-10001')[0]['payload'] == payload
    store.evaluate_one('CVE-2026-10001', parse_rules([{'name': 'state', 'condition': {'status': state.lower()}, 'channels': ['sink']}]))
    assert store.search(query='Additional').total == 1


def test_reserved_record_can_omit_containers(tmp_path):
    payload = official(state='RESERVED')
    del payload['containers']
    store = WatchStore(tmp_path / 'watch.db')
    store.upsert_cve_list([payload])
    assert store.view('CVE-2026-10001').status == 'reserved'


@pytest.mark.parametrize('failure', ['corrupt', 'digest', 'size', 'expanded', 'record', 'http_cap'])
def test_archive_integrity_and_limits(failure, monkeypatch):
    fixture = Release([official()])
    asset = fixture.assets()[0]
    if failure == 'corrupt':
        fixture.baseline = b'not a zip'
        asset.update(size=len(fixture.baseline), digest=None)
    elif failure == 'digest':
        asset['digest'] = 'sha256:' + '0' * 64
    elif failure == 'size':
        asset['size'] += 1
    elif failure == 'expanded':
        monkeypatch.setattr(cve_list, 'EXPANDED_CAP', 1)
    elif failure == 'record':
        monkeypatch.setattr(cve_list, 'JSON_CAP', 1)
    else:
        monkeypatch.setattr(cve_list, 'ARCHIVE_CAP', 1)
    with mock_client(fixture) as http, pytest.raises(SourceError):
        tuple(cve_list.archive_records(http, asset))


def test_nvd_later_does_not_duplicate_new_cve_match(tmp_path):
    store = WatchStore(tmp_path / 'watch.db', clock=lambda: NOW)
    rules = parse_rules([{'name': 'critical', 'condition': {'cvss_min': 9}, 'channels': ['sink']}])
    store.upsert_cve_list([official()])
    store.evaluate_touched(rules)
    store.upsert_nvd([WatchRecord('CVE-2026-10001', 'published', description='NVD later')])
    store.evaluate_touched(rules)
    assert len([event for event in store.events() if event.kind == 'match']) == 1
    assert {row['source'] for row in store.provider_records('CVE-2026-10001')} == {'nvd', 'cve_list'}


def test_new_source_initializes_without_resetting_euvd_resume(tmp_path):
    config = write_config(tmp_path, sources=('nvd', 'cve_list'), initial='backfill')
    store = WatchStore(config.watch.database)
    store.record_baseline(nvd_cursor=NOW.isoformat(), initialized_at=NOW.isoformat(), initial_mode='backfill')
    cursor = '{"start":"2026-10-01","end":"2026-10-02","page":0,"total":0,"size":100,"phase":"scan","verify":0}'
    store.set_metadata({'euvd_page_cursor': cursor})
    with mock_client(Release([official()])) as http:
        report = sync_watch(config, http, clock=lambda: NOW)
    assert not report.failures
    assert store.view('CVE-2026-10001') is not None
    assert store.metadata()['euvd_page_cursor'] == cursor


def test_reserved_does_not_match_regular_severity_rule(tmp_path):
    store = WatchStore(tmp_path / 'watch.db')
    store.upsert_cve_list([official(state='RESERVED')])
    rule = parse_rules([{'name': 'critical', 'condition': {'cvss_min': 9}, 'channels': ['sink']}])
    assert store.evaluate_one('CVE-2026-10001', rule).events == 0


def test_partial_baseline_replays_committed_batch_after_failure(tmp_path, monkeypatch):
    payloads = [official(f'CVE-2026-{10000 + index}') for index in range(4)]
    broken = official('CVE-2026-20000')
    broken['cveMetadata']['state'] = 'INVALID'
    fixture = Release([*payloads, broken])
    config = write_config(tmp_path, sources=('nvd', 'cve_list'), initial='full')
    store = WatchStore(config.watch.database)
    monkeypatch.setattr(cve_list, 'BATCH', 2)
    with mock_client(fixture) as http:
        with pytest.raises(SourceError):
            cve_list.sync(http, store, config.watch, NOW)
        assert store.search().total == 4
        assert 'cve_list_baseline_asset' not in store.metadata()
        assert 'cve_list_cursor' not in store.metadata()
        fixture.baseline = zipped(payloads)
        cve_list.sync(http, store, config.watch, NOW)
    assert store.search().total == 4
    assert len(store.pending_evaluations()) == 4


@pytest.mark.parametrize('target,allowed', [
    ('https://release-assets.githubusercontent.com/fake/archive', True),
    ('https://example.com/archive', False),
    ('http://release-assets.githubusercontent.com/archive', False),
    ('https://user@release-assets.githubusercontent.com/archive', False),
])
def test_archive_redirects_are_bounded_and_allowlisted(target, allowed):
    fixture = Release([official()])
    asset = fixture.assets()[0]
    requests = []
    def handler(request):
        requests.append(request)
        if str(request.url) == asset['browser_download_url']:
            return httpx.Response(302, headers={'location': target})
        assert allowed
        return httpx.Response(200, content=fixture.baseline)
    with mock_client(handler) as http:
        if allowed:
            assert len(tuple(cve_list.archive_records(http, asset))) == 1
        else:
            with pytest.raises(SourceError, match='unsafe redirect'):
                tuple(cve_list.archive_records(http, asset))
    assert len(requests) == (2 if allowed else 1)


def test_release_rejects_oversize_metadata_and_asset_size(monkeypatch):
    fixture = Release([official()])
    monkeypatch.setattr(cve_list, 'JSON_CAP', 10)
    with mock_client(fixture) as http, pytest.raises(SourceError, match='size limit'):
        cve_list.release(http, {})
    monkeypatch.setattr(cve_list, 'JSON_CAP', 4 * 1024 * 1024)
    assets = fixture.assets()
    assets[0]['size'] = cve_list.ARCHIVE_CAP + 1
    with mock_client(lambda _: httpx.Response(200, json={'assets': assets})) as http, pytest.raises(SourceError, match='size limit'):
        cve_list.release(http, {})
