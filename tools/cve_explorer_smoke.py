"""Exercise CVE sync, search, detail and refresh using loopback fakes only.

Run with the development environment: python tools/cve_explorer_smoke.py.
No source endpoints or notification channels are contacted.
"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
from pathlib import Path
import sys
import tempfile
from threading import Thread
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import zipfile

import httpx

from cvebeacon import cli, dashboard
from cvebeacon.config import load_config
from cvebeacon.http import HttpClient
from cvebeacon.sources import cve_list as source_list, euvd, nvd
from cvebeacon.watch import cve_list, feeds
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.sync import sync_watch

NOW = datetime(2026, 11, 18, 23, tzinfo=timezone.utc)


def record(identifier, description):
    return {"dataVersion": "5.1", "cveMetadata": {"cveId": identifier, "state": "PUBLISHED", "datePublished": "2026-11-18T00:00:00Z", "dateUpdated": "2026-11-18T23:00:00Z"},
            "containers": {"cna": {"providerMetadata": {"shortName": "Example CNA"}, "descriptions": [{"lang": "en", "value": description}], "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8}}], "affected": [{"vendor": "Example", "product": "Widget"}]}}}


def archive(payload=None):
    file = BytesIO()
    with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        if payload is not None:
            for item in payload if isinstance(payload, list) else [payload]:
                zip_file.writestr(item['cveMetadata']['cveId'] + '.json', json.dumps(item))
    return file.getvalue()


def main():
    baseline = record('CVE-2026-10001', 'Baseline alias')
    delta = record('CVE-2026-10001', 'Spring4Shell synthetic alias')
    missing = record('CVE-2026-10002', 'Fetched critical synthetic record')
    # Match the real double-suffix release artifact, including its inner ZIP.
    wrapped = BytesIO()
    with zipfile.ZipFile(wrapped, 'w') as outer:
        outer.writestr('cves.zip', archive(baseline))
    late = record('CVE-2026-10003', 'Late cross-midnight update')
    late['cveMetadata']['dateUpdated'] = '2026-11-18T23:55:00Z'
    next_day = record('CVE-2026-10003', 'Next-day delta update')
    next_day['cveMetadata']['dateUpdated'] = '2026-11-19T01:00:00Z'
    omitted = record('CVE-2026-10004', 'Delta member omitted from the log')
    omitted['cveMetadata']['dateUpdated'] = '2026-11-19T01:00:00Z'
    bodies = {'2026-11-18_all_CVEs_at_midnight.zip.zip': wrapped.getvalue(),
              '2026-11-19_all_CVEs_at_midnight.zip.zip': wrapped.getvalue(),
              '2026-11-18_delta_CVEs_at_2300Z.zip': archive(delta),
              '2026-11-19_delta_CVEs_at_0000Z.zip': archive(),
              '2026-11-19_delta_CVEs_at_0100Z.zip': archive([next_day, omitted])}
    phase = [0]
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            parsed = urlsplit(self.path)
            seen.append(parsed.path)
            if parsed.path == '/release':
                names = ["2026-11-18_all_CVEs_at_midnight.zip.zip" if phase[0] < 2 else "2026-11-19_all_CVEs_at_midnight.zip.zip",
                         ["2026-11-18_delta_CVEs_at_2300Z.zip", "2026-11-19_delta_CVEs_at_0000Z.zip", "2026-11-19_delta_CVEs_at_0100Z.zip"][phase[0]]]
                assets = [{"name": name, "size": len(bodies[name]), "digest": 'sha256:' + hashlib.sha256(bodies[name]).hexdigest(), "browser_download_url": base + '/assets/' + name} for name in names]
                body = json.dumps({'assets': assets}).encode()
            elif parsed.path == '/deltaLog':
                groups = [{'fetchTime': NOW.isoformat(), 'numberOfChanges': 1, 'new': [{'cveId': 'CVE-2026-10001', 'dateUpdated': delta['cveMetadata']['dateUpdated']}], 'updated': [], 'error': []},
                          {'fetchTime': (NOW-timedelta(days=30)).isoformat(), 'numberOfChanges': 0, 'new': [], 'updated': [], 'error': []}]
                if phase[0] > 0:
                    groups.insert(0, {'fetchTime': '2026-11-19T00:01:00Z', 'numberOfChanges': 1, 'new': [{'cveId': 'CVE-2026-10003', 'dateUpdated': late['cveMetadata']['dateUpdated']}], 'updated': [], 'error': []})
                if phase[0] > 1:
                    groups.insert(0, {'fetchTime': '2026-11-19T01:00:00Z', 'numberOfChanges': 1, 'new': [], 'updated': [{'cveId': 'CVE-2026-10003', 'dateUpdated': next_day['cveMetadata']['dateUpdated']}], 'error': []})
                body = json.dumps(groups).encode()
            elif parsed.path.startswith('/assets/'):
                body = bodies[parsed.path.rsplit('/', 1)[1]]
            elif parsed.path.startswith('/cves/'):
                identifier = parsed.path.rsplit('/', 1)[1][:-5]
                body = json.dumps({'CVE-2026-10001':delta, 'CVE-2026-10002':missing, 'CVE-2026-10003':late}[identifier]).encode()
            elif parsed.path == '/nvd':
                query = parse_qs(parsed.query)
                identifier = query.get('cveId', [None])[0]
                rows = [] if not identifier else [{'cve': {'id': identifier, 'vulnStatus': 'Published', 'published': '2026-11-02T00:00:00.000', 'lastModified': '2026-11-03T00:00:00.000', 'descriptions': [{'lang': 'en', 'value': 'Targeted NVD fake'}]}}]
                body = json.dumps({'resultsPerPage': len(rows), 'startIndex': 0, 'totalResults': len(rows), 'vulnerabilities': rows}).encode()
            elif parsed.path == '/euvd':
                body = json.dumps({'total': 0, 'items': []}).encode()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    base = 'http://127.0.0.1:' + str(server.server_port)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='cve-explorer-smoke-') as temporary, ExitStack() as stack:
            config_path = Path(temporary) / 'config.toml'
            config_path.write_text('''[state]
database = "state.db"
[watch]
enabled = true
database = "watch.db"
sources = ["nvd", "euvd", "cve_list"]
initial = "backfill"
[watch.channels.sink]
type = "webhook"
enabled = false
url = "https://example.com/disabled"
[[watch.rules]]
name = "critical"
condition = {cvss_min = 9}
channels = ["sink"]
''')
            config = load_config(config_path)
            for module, name, value in ((cve_list, 'RELEASE_URL', base + '/release'), (cve_list, 'ASSET_PREFIX', base + '/assets/'), (cve_list, 'DELTA_LOG_URL', base + '/deltaLog'), (source_list, 'RAW_BASE', base + '/cves'), (feeds, 'CVE_URL', base + '/nvd'), (feeds, 'SEARCH_URL', base + '/euvd'), (euvd, 'SEARCH_URL', base + '/euvd')):
                stack.enter_context(patch.object(module, name, value))
            def local_only(request):
                assert request.url.host == '127.0.0.1' and request.url.port == server.server_port, 'Nonlocal request refused'
            def local_http(settings):
                return HttpClient(settings, client=httpx.Client(event_hooks={'request': [local_only]}, trust_env=False), sleep=lambda _: None)
            stack.enter_context(patch.object(cli, 'HttpClient', local_http))
            http = local_http(config.http)
            try:
                report = sync_watch(config, http, clock=lambda: NOW)
                assert not report.failures
                store = WatchStore(config.watch.database)
                store.evaluate_touched(config.watch.rules, catalogs=config.watch.sources, initial=report.initial_evaluation, complete=report.initial_complete)
                assert store.search(query='Spring4Shell').total == 1
                phase[0] = 1
                midnight = datetime(2026, 11, 19, 0, 35, tzinfo=timezone.utc)
                midnight_report = sync_watch(config, http, clock=lambda: midnight)
                assert midnight_report.failures == ('cve_list',)
                assert midnight_report.initial_complete
                assert store.metadata()['cve_list_coverage_gap']
                assert store.metadata()['cve_list_cursor'] == NOW.isoformat()
                assert store.view('CVE-2026-10003', catalogs=config.watch.sources).description == late['containers']['cna']['descriptions'][0]['value']
                phase[0] = 2
                assert sync_watch(config, http, clock=lambda: midnight+timedelta(hours=1)).failures == ('cve_list',)
                assert store.metadata()['cve_list_cursor'] == NOW.isoformat()
                assert store.view('CVE-2026-10004', catalogs=config.watch.sources).description == omitted['containers']['cna']['descriptions'][0]['value']
                assert store.view('CVE-2026-10003', catalogs=config.watch.sources).description == next_day['containers']['cna']['descriptions'][0]['value']
                assert sum('_all_CVEs_' in path for path in seen) == 1
                app = dashboard.create_app(config)
                client = app.test_client()
                assert client.get('/watch/cves?q=Spring4Shell').status_code == 200
                assert 'Source presence' in client.get('/watch/cve/CVE-2026-10001').text
                assert store.view('CVE-2026-10002') is None
                assert cli.main(['--config', str(config_path), 'watch', 'refresh', 'CVE-2026-10002']) == 0
                assert store.view('CVE-2026-10002').description == 'Targeted NVD fake'
                assert any(event.kind == 'match' for event in store.events(cve='CVE-2026-10002'))
                assert 'Fetched critical' in client.get('/watch/cve/CVE-2026-10002').text
                app.extensions['dashboard_jobs'].shutdown()
            finally:
                http.close()
        print('PASS: real release names + nested baseline → 23:00/00:00/01:00 deltas + omitted log member + durable unproven gap → search/detail → targeted refresh/event; baseline downloads: 1')
        print(f'Local fake requests: {len(seen)}; external requests and notifications: 0')
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == '__main__':
    sys.exit(main())
