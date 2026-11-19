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


def test_refresh_explains_queue_and_offers_deliver_now(tmp_path,monkeypatch):
    from test_dashboard_watch import seeded,login,csrf
    _,_,store,app,client=seeded(tmp_path)
    manager=app.extensions['dashboard_jobs']
    monkeypatch.setattr(manager,'start_thread',lambda:None)
    login(client,'reader')
    page=client.get('/watch/cve/CVE-2026-0001')
    assert 'Deliver now' not in page.text
    login(client,'admin')
    page=client.get('/watch/cve/CVE-2026-0001')
    assert 'next watch notify or watch run' in page.text
    assert 'Deliver now' in page.text
    token=csrf(client,'/account')
    response=client.post('/watch/cve/CVE-2026-10001/refresh',data={'csrf':token})
    assert response.status_code==303
    job_page=client.get(response.location)
    assert 'next watch notify or watch run' in job_page.text
    assert 'Deliver now' in job_page.text
    assert client.post('/operations/run',data={'operation':'watch-notify'}).status_code==400
    response=client.post('/operations/run',data={'csrf':token,'operation':'watch-notify'})
    assert response.status_code==303
    assert manager.store.recent()[0].operation=='watch-notify'
    manager.shutdown()


def test_large_provider_page_shows_truncated_escaped_preview(tmp_path):
    from test_dashboard_watch import seeded,login
    _,_,store,app,client=seeded(tmp_path)
    store.upsert_cve_list([official('CVE-2026-0001',description='<script>x</script>'+'A'*100_000)])
    login(client,'reader')
    page=client.get('/watch/cve/CVE-2026-0001')
    assert 'Payload preview truncated' in page.text
    assert '<script>x</script>' not in page.text
    assert len(page.data)<150_000
    app.extensions['dashboard_jobs'].shutdown()


def test_explorer_avoids_unused_client_options_query(tmp_path,monkeypatch):
    from cvebeacon import dashboard_watch
    from test_dashboard_watch import seeded,login
    _,_,_,app,client=seeded(tmp_path)
    login(client,'reader')
    monkeypatch.setattr(dashboard_watch,'client_options',lambda *_: (_ for _ in ()).throw(AssertionError('unused client query')))
    assert client.get('/watch/cves').status_code==200
    app.extensions['dashboard_jobs'].shutdown()
