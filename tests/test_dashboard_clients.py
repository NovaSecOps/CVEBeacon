from __future__ import annotations

from io import BytesIO

from test_dashboard_watch import csrf, login, seeded

from cvebeacon.models import (
    Applicability,
    Asset,
    Finding,
    QueryResult,
    Vulnerability,
)
from cvebeacon.state import StateStore


def with_scan(tmp_path):
    config, users, store, app, client = seeded(tmp_path)
    state = StateStore(config.database_path)
    acme = Asset("a1", "Acme", "Widget", "1", client="Acme")
    globex = Asset("g1", "Acme", "Widget", "2", client="Globex")
    initech = Asset("i1", "Acme", "Widget", "3", client="Initech")

    def finding(asset, cve_id, status):
        return Finding(
            asset, Vulnerability(cve_id), status, "high", "test"
        )

    state.record_scan(
        [
            QueryResult(
                acme,
                (
                    finding(acme, "CVE-2026-0001", Applicability.AFFECTED),
                ),
                (),
            ),
            QueryResult(
                globex,
                (
                    finding(
                        globex, "CVE-2026-0001", Applicability.NEEDS_REVIEW
                    ),
                    finding(globex, "CVE-2026-0002", Applicability.AFFECTED),
                ),
                (),
            ),
            QueryResult(initech, (), ()),
        ]
    )
    return config, users, store, app, client


def test_clients_page_lists_assets_and_affected_cves(tmp_path):
    _, _, _, _, client = with_scan(tmp_path)
    login(client, "reader")
    response = client.get("/watch/clients")
    assert response.status_code == 200
    text = response.text
    assert "Clients" in text
    assert "Acme" in text and "Globex" in text and "Initech" in text
    assert "Currently affected CVEs" in text
    assert "CVE-2026-0001" in text and "CVE-2026-0002" in text
    assert "review" in text
    assert 'href="/watch/events?client=Acme"' in text


def test_clients_page_without_a_scan_explains_the_missing_state(tmp_path):
    _, _, _, _, client = seeded(tmp_path)
    login(client, "reader")
    response = client.get("/watch/clients")
    assert response.status_code == 200
    assert "No successful inventory scan is available" in response.text


def test_cve_detail_shows_affected_clients(tmp_path):
    _, _, _, _, client = with_scan(tmp_path)
    login(client, "reader")
    response = client.get("/watch/cve/CVE-2026-0001")
    assert response.status_code == 200
    text = response.text
    assert "Affected clients" in text
    assert "Acme" in text and "Globex" in text
    assert "review" in text


def test_cve_detail_without_a_scan_explains_the_missing_state(tmp_path):
    _, _, _, _, client = seeded(tmp_path)
    login(client, "reader")
    response = client.get("/watch/cve/CVE-2026-0001")
    assert response.status_code == 200
    assert "No successful inventory scan is available" in response.text


def test_events_page_filters_by_client(tmp_path):
    _, _, _, _, client = with_scan(tmp_path)
    login(client, "reader")
    acme = client.get("/watch/events", query_string={"client": "Acme"})
    assert acme.status_code == 200
    assert "CVE-2026-0001" in acme.text
    assert "CVE-2026-0002" not in acme.text
    globex = client.get("/watch/events", query_string={"client": "Globex"})
    assert globex.status_code == 200
    assert "CVE-2026-0001" in globex.text
    assert "CVE-2026-0002" in globex.text
    initech = client.get("/watch/events", query_string={"client": "Initech"})
    assert initech.status_code == 200
    assert "No matching events" in initech.text
    unknown = client.get("/watch/events", query_string={"client": "Missing"})
    assert unknown.status_code == 400


def test_clients_and_filter_require_view_permission(tmp_path):
    _, _, _, _, client = with_scan(tmp_path)
    login(client, "nobody")
    assert client.get("/watch/clients").status_code == 403
    assert (
        client.get("/watch/events", query_string={"client": "Acme"}).status_code
        == 403
    )


def test_statement_download_contains_affected_clients(tmp_path):
    _, _, _, _, client = with_scan(tmp_path)
    login(client, "ops")
    token = csrf(client, "/watch/cve/CVE-2026-0001/statement")
    response = client.post(
        "/watch/cve/CVE-2026-0001/statement",
        data={
            "csrf": token,
            "template": "upload",
            "template_file": (
                BytesIO(b"Clients: ${affected_clients}\n"),
                "custom.md",
            ),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"Clients: Acme, Globex (review)" in response.data
