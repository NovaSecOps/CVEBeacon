"""Targeted refresh normalisation, rule evaluation, job authorization and audit."""
from __future__ import annotations

from dataclasses import replace
import sqlite3

import httpx
import pytest

from cvebeacon import cli
from cvebeacon.dashboard_jobs import build_command
from cvebeacon.errors import ConfigurationError
from cvebeacon.locking import RunLock, run_lock_path
from cvebeacon.sources.epss import EPSS_URL
from cvebeacon.sources.euvd import SEARCH_URL
from cvebeacon.sources.kev import CISA_URL, EU_URL
from cvebeacon.sources.nvd import CVE_URL
from cvebeacon.watch.records import WatchRecord
from cvebeacon.watch.refresh import refresh_watch
from cvebeacon.watch.rules import parse_rules
from cvebeacon.watch.store import WatchStore
from test_cve_explorer import official
from watch_support import mock_client, nvd_cve, nvd_page, write_config

ID = 'CVE-2026-10001'


class Lookups:
    def __init__(self):
        self.description = 'Initial alias'
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        url = str(request.url).split('?')[0]
        if url == CVE_URL:
            assert request.url.params['cveId'] == ID
            assert not any(key.startswith('lastMod') for key in request.url.params)
            return httpx.Response(200, json=nvd_page([nvd_cve(ID, descriptions=[{'lang': 'en', 'value': self.description}])]))
        if url == SEARCH_URL:
            assert request.url.params['text'] == ID
            assert 'fromUpdatedDate' not in request.url.params
            return httpx.Response(200, json={'total': 1, 'items': [{'id': 'EUVD-2026-1', 'aliases': ID, 'dateUpdated': '2026-11-03', 'baseScore': 9.5, 'baseScoreVersion': '3.1'}]})
        if url == EPSS_URL:
            assert request.url.params['cve'] == ID
            return httpx.Response(200, json={'data': [{'cve': ID, 'epss': '0.8', 'percentile': '0.9', 'date': '2026-11-03'}]})
        if url == CISA_URL:
            return httpx.Response(200, json={'vulnerabilities': [{'cveID': ID, 'dateAdded': '2026-11-03'}]})
        if url == EU_URL:
            return httpx.Response(200, json=[{'cveId': ID, 'dateAdded': '2026-11-03', 'sources': ['eukev_kev']}])
        if url.endswith(ID + '.json'):
            return httpx.Response(200, json=official(description=self.description))
        raise AssertionError('Unexpected full-sync or delivery request')


def config_for(tmp_path):
    config = write_config(tmp_path, sources=('nvd', 'euvd', 'cve_list', 'epss', 'cisa_kev', 'eu_kev'))
    rules = parse_rules([{'name': 'critical', 'condition': {'any': [{'cvss_min': 9}, {'kev': 'any'}]}, 'channels': ['sink']}])
    return replace(config, watch=replace(config.watch, rules=rules))


def test_refresh_missing_then_update_evaluates_only_target(tmp_path):
    config = config_for(tmp_path)
    fixture = Lookups()
    store = WatchStore(config.watch.database)
    store.upsert_nvd([WatchRecord('CVE-2026-10002', 'published')])
    store.set_metadata({'nvd_cursor': 'unchanged', 'euvd_page_cursor': 'unchanged'})
    with mock_client(fixture) as http:
        report, result = refresh_watch(config, http, ID.lower())
        assert not report.failures
        assert result.evaluated == 1
        assert result.events == 1
        view = store.view(ID, catalogs=config.watch.sources)
        assert view.epss == 0.8 and view.cisa_kev_added and view.eu_kev_added
        assert view.euvd_id == 'EUVD-2026-1'
        assert all(row['state'] == 'present' for row in store.source_presence(ID))
        assert store.pending_evaluations() == ('CVE-2026-10002',)
        assert store.metadata()['nvd_cursor'] == 'unchanged'
        assert store.metadata()['euvd_page_cursor'] == 'unchanged'
        fixture.description = 'Updated alias'
        refresh_watch(config, http, ID)
        assert store.search(query='Updated').total == 1
    assert len([event for event in store.events(cve=ID) if event.kind == 'match']) == 1
    assert len(fixture.requests) == 12
    with sqlite3.connect(config.watch.database) as db:
        assert db.execute('SELECT status FROM watch_delivery').fetchone() == ('pending',)


def test_cve_list_still_inserts_when_nvd_not_found(tmp_path):
    config = write_config(tmp_path, sources=('nvd', 'cve_list'))
    def handler(request):
        if request.url.host == 'services.nvd.nist.gov':
            return httpx.Response(404)
        return httpx.Response(200, json=official())
    with mock_client(handler) as http:
        report, _ = refresh_watch(config, http, ID)
    store = WatchStore(config.watch.database)
    assert not report.failures
    assert store.view(ID) is not None
    presence = {row['source']: row['state'] for row in store.source_presence(ID)}
    assert presence['nvd'] == 'absent' and presence['cve_list'] == 'present'


@pytest.mark.parametrize('identifier', ['CVE-2026-1', 'CVE-2026-10001;echo', '../CVE-2026-10001', '', 'CVE-2026-10001\n--yes'])
def test_invalid_id_cannot_build_job_or_make_requests(tmp_path, identifier):
    config = config_for(tmp_path)
    with mock_client(lambda _: pytest.fail('invalid ID reached source')) as http:
        with pytest.raises(ConfigurationError):
            refresh_watch(config, http, identifier)
    with pytest.raises(ConfigurationError):
        build_command(config, 'watch-refresh', cve_id=identifier)


def test_refresh_cli_uses_run_lock_and_targeted_path(tmp_path, monkeypatch):
    config = write_config(tmp_path, sources=('nvd', 'cve_list'))
    fixture = Lookups()
    monkeypatch.setattr(cli, 'HttpClient', lambda _: mock_client(fixture))
    argv = ['--config', str(config.config_path), 'watch', 'refresh', ID]
    with RunLock(run_lock_path(config)):
        assert cli.main(argv) == 2
    assert fixture.requests == []
    assert cli.main(argv) == 0
    assert len(fixture.requests) == 2
    assert WatchStore(config.watch.database).view(ID) is not None


def test_refresh_job_permission_csrf_audit_and_command(tmp_path, monkeypatch):
    from test_dashboard_watch import seeded, login, csrf
    config, users, _, app, client = seeded(tmp_path)
    manager = app.extensions['dashboard_jobs']
    monkeypatch.setattr(manager, 'start_thread', lambda: None)
    path = '/watch/cve/' + ID + '/refresh'
    login(client, 'reader')
    assert client.get('/watch/cves').status_code == 200
    token = csrf(client, '/account')
    assert client.post(path, data={'csrf': token}).status_code == 403
    assert not manager.store.recent()
    login(client, 'admin')
    assert client.post(path).status_code == 400
    token = csrf(client, '/account')
    assert client.post('/watch/cve/invalid/refresh', data={'csrf': token}).status_code == 404
    response = client.post(path, data={'csrf': token})
    assert response.status_code == 303
    job = manager.store.recent()[0]
    assert job.operation == 'watch-refresh'
    assert list(job.argv)[-3:] == ['watch', 'refresh', ID]
    assert any(entry.action == f'job_started:{job.id}:watch-refresh' for entry in users.audit_entries())
    assert users.verify_audit() is None
    manager.shutdown()
