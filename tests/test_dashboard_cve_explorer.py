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
    assert '<span class="badge badge-success">Present</span>' in page.text
    assert '<span class="badge badge-warning">Not synced yet</span>' in page.text
    assert '<span class="badge badge-success">present</span>' not in page.text
    assert '<span class="badge badge-warning">not synced</span>' not in page.text
    assert 'cve_list' in page.text and '<script>bad()' not in page.text
    missing = client.get('/watch/cves?q=CVE-2026-9999')
    assert 'Not in our database' in missing.text and '2026-11-03' in missing.text
    assert 'Fetch or refresh this CVE now' not in missing.text
    assert client.get('/watch/cves?q=' + 'x' * 257).status_code == 400
    app.extensions['dashboard_jobs'].shutdown()



def test_source_presence_explains_a_latest_absent_check(tmp_path):
    from test_dashboard_watch import seeded, login

    _, _, store, app, client = seeded(tmp_path)
    with store.transaction() as db:
        db.execute(
            "INSERT INTO watch_source_check (cve_id, source, present, checked_at, error)"
            " VALUES (?, 'nvd', 0, ?, NULL)",
            ("CVE-2026-0001", "2026-11-04T00:00:00Z"),
        )
    states = {row["source"]: row["state"] for row in store.source_presence("CVE-2026-0001")}
    assert states["nvd"] == "present (last check absent)"
    login(client, "reader")
    page = client.get("/watch/cve/CVE-2026-0001")
    assert page.status_code == 200
    assert "Present, but the latest check found it absent" in page.text
    assert "its latest check did not find this CVE" in page.text
    assert '<span class="muted">(present (last check absent))</span>' in page.text
    app.extensions["dashboard_jobs"].shutdown()


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


def test_explorer_preserves_repeated_filters_across_pagination(tmp_path):
    import html
    import re
    from urllib.parse import parse_qs, urlsplit

    from cvebeacon.watch.records import CVSSEntry
    from test_dashboard_watch import seeded, login, record

    config, _, store, app, client = seeded(tmp_path)
    scores = (CVSSEntry("nvd", "nvd", "2.0", 8.5),
              CVSSEntry("cna", "Example", "3.1", 7.0),
              CVSSEntry("nvd", "nvd", "4.0", 9.8, "CVSS:4.0/AV:N"))
    store.upsert_nvd(
        [record(f"CVE-2026-{index:06d}", cvss=scores, description="Synthetic filter fixture")
         for index in range(10000, 10051)],
        catalogs=config.watch.sources,
    )
    login(client, "reader")
    page = client.get("/watch/cves?q=Synthetic&source=nvd&source=epss&cvss_version=4.0&cvss_version=3.1"
                      "&cvss_provider=nvd&cvss_min=9.5&exploitation=active&severity=critical"
                      "&since=2026-11-01&modified_until=2026-11-02&kev=neither")
    assert page.status_code == 200
    assert "51 CVEs · Page 1" in page.text
    assert "Active filters:" in page.text
    assert "KEV: Neither catalog" in page.text
    assert "<summary>Filter</summary>" in page.text
    assert 'href="/watch/cves">Clear filters</a>' in page.text
    assert '<summary>9.8 v4.0</summary>' in page.text
    assert "7 v3.1" in page.text and "8.5 v2.0" in page.text
    assert "active (NVD SSVC)" in page.text
    assert "Severity differs between CVSS versions" in page.text
    target = html.unescape(re.search(r'href="([^"]+)">Next</a>', page.text)[1])
    filters = parse_qs(urlsplit(target).query)
    assert filters["source"] == ["nvd", "epss"]
    assert filters["cvss_version"] == ["4.0", "3.1"]
    assert filters["modified_until"] == ["2026-11-02"]
    assert filters["page"] == ["2"]
    following = client.get(target)
    assert "51 CVEs · Page 2" in following.text
    assert 'name="cvss_version" value="3.1" checked' in following.text
    assert "CVE-2026-010000" in following.text
    for query in ("cvss_provider=nvd%27%29%20OR%201%3D1--", "epss_min=nan",
                  "cvss_min=9&cvss_max=8", "since=2026-11-02&until=2026-11-01",
                  "client=x%0Ay", "source=nvd&" * 7, "ignored=" + "x" * 8200):
        assert client.get("/watch/cves?" + query).status_code == 400
    app.extensions["dashboard_jobs"].shutdown()


def test_explorer_combines_client_names_using_or(tmp_path):
    from test_dashboard_clients import with_scan
    from test_dashboard_watch import login

    _, _, _, app, client = with_scan(tmp_path)
    login(client, "reader")
    for query in ("client=Acme&client=Missing", "client_names=Missing%0D%0AAcme"):
        result = client.get("/watch/cves?" + query + "&reported=yes&source=nvd")
        assert result.status_code == 200
        assert "1 CVEs · Page 1" in result.text
        assert "CVE-2026-0001" in result.text and "CVE-2026-0002" not in result.text
    app.extensions["dashboard_jobs"].shutdown()


def test_event_list_and_detail_show_all_scores_and_version_disagreement(tmp_path, monkeypatch):
    from cvebeacon.watch.records import CVSSEntry
    from cvebeacon.watch.store import WatchStore
    from test_dashboard_watch import seeded, login, record

    config, _, store, app, client = seeded(tmp_path)
    scores = (CVSSEntry("nvd", "nvd", "2.0", 8.5),
              CVSSEntry("cna", "Example", "3.1", 7.0),
              CVSSEntry("nvd", "nvd", "4.0", 9.6, "CVSS:4.0/AV:N"))
    store.upsert_nvd([record(cvss=scores)], catalogs=config.watch.sources)
    login(client, "reader")

    def forbidden(*args):
        raise AssertionError("the event page needs only scores")

    with monkeypatch.context() as only_scores:
        only_scores.setattr(WatchStore, "_view", forbidden)
        events = client.get("/watch/events?cve=CVE-2026-0001")
    assert events.status_code == 200
    assert all(label in events.text for label in ("8.5 v2.0", "7 v3.1", "9.6 v4.0", "CVSS:4.0/AV:N"))
    assert "Severity differs between CVSS versions" in events.text

    detail = client.get("/watch/cve/CVE-2026-0001")
    assert detail.status_code == 200
    assert all(label in detail.text for label in ("v2.0</td>", "v3.1</td>", "v4.0</td>", "CVSS:4.0/AV:N"))
    assert "Severity differs between CVSS versions" in detail.text
    app.extensions["dashboard_jobs"].shutdown()


def test_cve_detail_keeps_uncertainty_next_to_scores(tmp_path):
    from test_dashboard_watch import seeded, login

    _, _, _, app, client = seeded(tmp_path)
    login(client, "reader")
    page = client.get("/watch/cve/CVE-2026-0002")
    assert page.status_code == 200
    assert "Neither proves the flaw is not exploited" in page.text
    assert "not proof that the flaw is not exploited" in page.text
    assert "are not the same as “not affected”" in page.text
    app.extensions["dashboard_jobs"].shutdown()
