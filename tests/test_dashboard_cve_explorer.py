"""CVE explorer pages and bounded scan-state correlation."""
from test_cve_explorer import official


def test_source_presence_and_escaped_dashboard(tmp_path):
    from test_dashboard_watch import seeded, login
    from cvebeacon.watch.records import KEVFields
    _, _, store, app, client = seeded(tmp_path)
    store.upsert_cve_list([official('CVE-2026-0001', description='<script>bad()</script>')])
    store.set_metadata({'sync_euvd_success_at': '2026-11-01T00:00:00Z'})
    rows = {row['source']: row for row in store.source_presence('CVE-2026-0001')}
    assert rows['nvd']['state'] == 'present'
    assert rows['cve_list']['state'] == 'present'
    assert rows['euvd']['state'] == 'present'
    assert rows['cisa_kev']['state'] == 'not synced'
    absent = {row['source']: row for row in store.source_presence('CVE-2026-9999')}
    assert absent['euvd']['state'] == 'absent'
    login(client, 'reader')
    page = client.get('/watch/cves?q=cve-2026-0001')
    assert page.status_code == 200
    assert 'CVE-2026-0001' in page.text and '<script>bad()' not in page.text
    page = client.get('/watch/cve/CVE-2026-0001')
    assert 'Source presence' in page.text and 'Scan findings' in page.text
    assert 'cve_list' in page.text and '<script>bad()' not in page.text
    missing = client.get('/watch/cves?q=CVE-2026-9999')
    assert 'Not in our database' in missing.text and '2026-11-03' in missing.text
    assert 'Fetch or refresh this CVE now' not in missing.text
    assert client.get('/watch/cves?q=' + 'x' * 257).status_code == 400
    app.extensions['dashboard_jobs'].shutdown()



def test_detail_findings_clients_and_delivery_timestamps(tmp_path):
    from test_dashboard_clients import with_scan
    from test_dashboard_watch import login
    config, _, store, app, client = with_scan(tmp_path)
    with store.transaction() as db:
        db.execute("UPDATE watch_delivery SET status='sent',updated_at='2026-11-03T13:01:00+00:00'")
    login(client, 'reader')
    page = client.get('/watch/cve/CVE-2026-0001')
    assert 'Scan findings' in page.text
    assert 'a1' in page.text and 'g1' in page.text
    assert 'Acme' in page.text and 'Globex' in page.text
    assert 'Notified at 2026-11-03 13:01 UTC' in page.text
    page = client.get('/watch/cves?client=Acme')
    assert 'CVE-2026-0001' in page.text and 'CVE-2026-0002' not in page.text
    assert client.get('/watch/cves?source=invalid').status_code == 400
    app.extensions['dashboard_jobs'].shutdown()
