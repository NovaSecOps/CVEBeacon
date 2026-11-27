"""Client technology exposure reports use saved inventory and local state."""

import csv
from datetime import date, datetime, timedelta, timezone
from html import unescape
from io import BytesIO, StringIO
import json
from pathlib import Path
import re
from types import SimpleNamespace

from openpyxl import load_workbook
import pytest
from werkzeug.datastructures import MultiDict

from cvebeacon import tech_report, web_assets
from cvebeacon.dashboard import create_app
from cvebeacon.models import Applicability, Asset, Finding, Vulnerability
from cvebeacon.state import StateStore
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.users import BOOTSTRAP, UserStore

from test_dashboard_accounts import PASSWORD, login
from test_web_assets_inventory import PRODUCTS, save_snapshot, write_managed
from test_web_inventory import snapshot
from watch_support import write_config

PAGE = "/web-assets/report"
EXPORT = PAGE + "/export"
CLIENT = "Ácme / Q2"
TODAY = datetime.now(timezone.utc).date()


def day(days=0):
    return (TODAY - timedelta(days=days)).isoformat()


def id_for(number):
    return f"CVE-2024-{number:04}"


def save_review(config, products, client=CLIENT):
    allowlist, snapshot = web_assets.paths(config, client)
    web_assets.replace_bytes(allowlist, json.dumps({"client": client, "assets": []}).encode("utf-8"))
    review = {"client": client, "products": products, "reviews": []}
    web_assets.replace_bytes(Path(str(snapshot) + ".review.json"), json.dumps(review).encode("utf-8"))


def write_finding(db, number, *, asset_id="w-nginx-m", client=CLIENT, published=10,
                  modified=40, first_seen=40, applicability=Applicability.AFFECTED, **vuln):
    asset = Asset(asset_id, vendor="nginx", product="nginx", version="1.25.3", client=client)
    vulnerability = Vulnerability(cve_id=id_for(number), published=None if published is None else day(published),
                                  modified=day(modified), **vuln)
    finding = Finding(asset, vulnerability, applicability, "high", "Saved finding")
    db.execute("INSERT INTO current_findings VALUES (?,?,?,?,?,?)",
               (asset_id, vulnerability.primary_id, day(first_seen) + "T23:59:59Z",
                day() + "T00:00:00Z", "", json.dumps(finding.to_dict())))


@pytest.fixture
def seeded(tmp_path):
    config = write_config(tmp_path, inventory=False)
    products = [dict(p) for p in PRODUCTS]
    products[0]["name"] = "=nginx"
    products[0]["versions"] = ["+1.25.3"]
    products += [dict(products[0], asset_id="w-other", hostname="c.example"),
                 dict(products[0], asset_id="w-extra-path", versions=["1.25.4"]),
                 dict(products[2], asset_id="w-service", category="analytics",
                      categories=["analytics"], name="Analytics", product="analytics")]
    save_review(config, products)
    write_managed(config, [
        Asset("w-nginx-m", vendor="nginx", product="nginx", version="+1.25.3", client=CLIENT),
        Asset("w-extra-path-m", vendor="nginx", product="nginx", version="1.25.4", client=CLIENT),
        Asset(f"web-{'0' * 32}-m", vendor="nginx", product="nginx", version="+1.25.3",
              system_id="archived.example", client=CLIENT),
    ], CLIENT)
    state = StateStore(config.database_path)
    state.initialize()
    with state.transaction() as db:
        write_finding(db, 1, cvss_score=9.8, epss_score=0.72, cisa_kev=True, fixed_versions=("1.26",))
        write_finding(db, 2, published=29, cvss_score=7.5, epss_score=0.91, eu_kev=True, first_seen=2)
        write_finding(db, 3, published=0, cvss_score=2.3, epss_score=0.15, modified=1)
        write_finding(db, 4, published=40, modified=0, first_seen=0)
        write_finding(db, 5, published=None, modified=40)
        write_finding(db, 6, applicability=Applicability.NOT_AFFECTED, cvss_score=10)
        write_finding(db, 7, cvss_score=10)
        db.execute("INSERT INTO advisory_aliases VALUES (?,?,?)", ("w-nginx-m", id_for(7), id_for(1)))
        write_finding(db, 8, client="Different Client", cvss_score=10)
        write_finding(db, 9, asset_id="unrelated", cvss_score=10)
        write_finding(db, 10, asset_id=f"web-{'0' * 32}-m", cvss_score=10)
        write_finding(db, 1, asset_id="w-extra-path-m", cvss_score=9.2, first_seen=35)
    app = create_app(config)
    try:
        yield config, app.test_client()
    finally:
        app.extensions["dashboard_jobs"].shutdown()


@pytest.fixture
def watch_views(seeded, monkeypatch):
    config, _ = seeded
    WatchStore(config.watch.database).initialize()
    views = {
        id_for(1): SimpleNamespace(ssvc_exploitation="active", ssvc_source="CISA ADP", euvd_exploited_since=None),
        id_for(2): SimpleNamespace(ssvc_exploitation="none", ssvc_source="SSVC", euvd_exploited_since=day()),
        id_for(3): SimpleNamespace(ssvc_exploitation="poc", ssvc_source=None, euvd_exploited_since=None),
        id_for(4): SimpleNamespace(ssvc_exploitation="none", ssvc_source=None, euvd_exploited_since=None),
    }
    monkeypatch.setattr(WatchStore, "_view", lambda self, db, identifier, catalogs: views.get(identifier))


def page(seeded, **query):
    response = seeded[1].get(PAGE, query_string={"client": CLIENT, **query})
    assert response.status_code == 200, response.text
    return response


def export(seeded, kind="json", **query):
    response = seeded[1].get(EXPORT, query_string={"client": CLIENT, "format": kind, **query})
    assert response.status_code == 200, response.text
    return response


def technology(report, site="a.example"):
    return next(row for row in report["technologies"] if row["technology"] == "=nginx" and row["site"] == site)


def cve_ids(response):
    return {cve["cve_id"] for cve in technology(response.json)["cves"]}


def test_unknown_client_has_an_empty_report(tmp_path):
    app = create_app(write_config(tmp_path, inventory=False))
    try:
        client = app.test_client()
        response = client.get(PAGE, query_string={"client": "Unknown"})
        assert response.status_code == 200
        assert "No detected technologies" in response.text
        assert client.get(PAGE).status_code == 400
        assert client.get(EXPORT, query_string={"client": "Unknown", "format": "bin"}).status_code == 400
    finally:
        app.extensions["dashboard_jobs"].shutdown()


def test_windows(seeded):
    assert cve_ids(export(seeded)) == {id_for(i) for i in (1, 2, 3)}
    assert cve_ids(export(seeded, window="days", days="11")) == {id_for(1), id_for(3)}
    assert cve_ids(export(seeded, window="days", days="1")) == {id_for(3)}
    assert cve_ids(export(seeded, window="range", **{"from": day(29), "to": day(10)})) == {id_for(1), id_for(2)}
    assert cve_ids(export(seeded, field="first_seen")) == {id_for(2), id_for(4)}
    assert cve_ids(export(seeded, field="modified")) == {id_for(3), id_for(4)}
    assert cve_ids(export(seeded, window="all")) == {id_for(i) for i in range(1, 6)}
    for n in (7, 30, 60, 90):
        window = export(seeded, window=str(n)).json["window"]
        assert window == {"kind": str(n), "field": "published", "from": day(n - 1), "to": day()}


def test_window_uses_utc_days_and_maximum_inclusive_span():
    today = date(2026, 1, 1)
    assert tech_report._timestamp("2026-01-02T00:30:00+01:00").startswith("2026-01-01T")
    window, invalid = tech_report.read_window(MultiDict({"window": "days", "days": "3650"}), today)
    assert not invalid and (window.end - window.start).days == 3649
    query = {"window": "range", "from": window.start.isoformat(), "to": window.end.isoformat()}
    assert not tech_report.read_window(MultiDict(query), today)[1]
    query["from"] = (window.start - timedelta(days=1)).isoformat()
    assert tech_report.read_window(MultiDict(query), today)[1]


@pytest.mark.parametrize("query", [
    {"window": "days", "days": "0"},
    {"window": "days", "days": "99999"},
    {"window": "days", "days": "1" * 4000},
    {"window": "range", "from": day(), "to": day(1)},
    {"window": "range", "from": "2024-02-30", "to": day()},
    {"window": "range", "from": day(), "to": day(-1)},
    {"window": "<script>invalid()</script>"},
    {"window": "range", "from": "<script>invalid()</script>", "to": day()},
    {"field": "first_seen" * 50},
    {"field": ["first_seen", "modified"]},
])
def test_invalid_window_resets_safely(seeded, query):
    response = page(seeded, **query)
    assert "Invalid time window. Showing the last 30 days by CVE published date." in response.text
    assert '<option value="30" selected>' in response.text
    assert '<option value="published" selected>' in response.text
    assert "invalid()" not in response.text
    assert cve_ids(export(seeded, **query)) == {id_for(i) for i in (1, 2, 3)}


@pytest.mark.parametrize(("query", "kind", "field", "span"), [
    ({}, "30", "published", 30),
    ({"window": "7"}, "7", "published", 7),
    ({"window": "days", "days": "11", "field": "first_seen"}, "days", "first_seen", 11),
])
def test_relative_exports_keep_the_page_window_across_utc_midnight(seeded, monkeypatch, query, kind, field, span):
    current = datetime.combine(TODAY, datetime.max.time(), tzinfo=timezone.utc)

    class Clock(datetime):
        @classmethod
        def now(cls, tz):
            return current.astimezone(tz)

    monkeypatch.setattr(tech_report, "datetime", Clock)
    rendered = page(seeded, **query).text
    assert f"{day(span - 1)} to {day()} UTC" in rendered
    current += timedelta(microseconds=1)
    window = {"kind": kind, "field": field, "from": day(span - 1), "to": day()}
    for fmt in ("json", "xlsx", "csv"):
        href = re.search(r'href="([^"]+/export\?[^"]+)"[^>]*>Export ' + fmt.upper(), rendered)[1]
        response = seeded[1].get(unescape(href))
        assert response.status_code == 200
        if fmt == "json":
            assert response.json["window"] == window
        elif fmt == "csv":
            assert json.loads(response.headers["X-CVEBeacon-Report-Window"]) == window
        else:
            book = load_workbook(BytesIO(response.data))
            try:
                sheet = book["Technologies"]
                assert sheet["B2"].value == f"{day(span - 1)} to {day()} UTC · {tech_report.FIELDS[field]}"
                assert sheet["B3"].value == kind
            finally:
                book.close()
        assert f"-{day(span - 1)}-{day()}.{fmt}" in response.headers["Content-Disposition"]


def test_relative_window_anchor_validation():
    today = date(2026, 1, 1)
    valid_end = today - timedelta(days=3650)
    window, invalid = tech_report.read_window(MultiDict({"window": "7", "end": valid_end.isoformat()}), today)
    assert not invalid and window.end == valid_end and (window.end - window.start).days == 6
    for value in ([(valid_end - timedelta(days=1)).isoformat()], ["2026-01-02"], ["2025-02-30"],
                  ["2026-01-01 "], ["2026-01-01", "2026-01-01"]):
        args = MultiDict({"window": "7", "end": value})
        assert tech_report.read_window(args, today)[1]


@pytest.mark.parametrize("route", [PAGE, EXPORT])
@pytest.mark.parametrize("query", [
    {"conf": ["high"] * 4},
    {"conf": "h" * 1024},
    {"conf": ["high", " LOW "]},
    {"filters": ["1", "1"]},
    {"filters": ["1", "0"]},
    {"filters": "0"},
    {"filters": "1 "},
    {"filters": "1" * 1024},
    {"client": CLIENT + " " * 256},
])
def test_malformed_report_filters_are_rejected(seeded, route, query):
    response = seeded[1].get(route, query_string={"client": CLIENT, "format": "json", **query})
    assert response.status_code == 400


def test_report_query_size_and_raw_format_length(seeded):
    for route in (PAGE, EXPORT):
        response = seeded[1].get(route, query_string={"client": CLIENT, "format": "json", "extra": "x" * 8192})
        assert response.status_code == 414
        assert "Report query string exceeds 8 KiB." in response.text
    assert seeded[1].get(EXPORT, query_string={"client": CLIENT, "format": "json "}).status_code == 400


def test_confidence_filters_deduplicate_valid_choices(seeded):
    result = export(seeded, conf=["medium", "high", "medium"]).json
    assert result["filters"]["conf"] == ["high", "medium"]


def test_correlation_and_status(seeded):
    report = export(seeded).json
    row = technology(report)
    assert row["status"] == "monitored"
    assert row["asset_ids"] == ["w-extra-path", "w-nginx"]
    assert row["versions"] == ["+1.25.3", "1.25.4"]
    assert row["window_count"] == 3 and row["current_count"] == 5
    assert row["severity"] == "critical" and row["max_cvss"] == 9.8
    assert row["cisa_kev"] and row["eu_kev"] and row["max_epss"] == 0.91
    assert row["newest_published"].startswith(day())
    assert row["first_found"].startswith(day(40))
    assert all(cve["exploitation"] == "unknown" for cve in row["cves"])
    other = technology(report, "c.example")
    assert other["status"] == "ready" and other["cves"] == [] and other["current_count"] == 0
    rendered = page(seeded).text
    assert "5 detected technologies are not covered by CVE scans" in rendered
    assert "CVEs (3)" in rendered and "91.00%" in rendered and "Fixed versions" in rendered
    assert f'/watch/cve/{id_for(1)}' in rendered
    assert "Critical · 1" in rendered and "High · 1" in rendered


@pytest.mark.parametrize("saved_client", ["", "Other Client", "ＡＣＭＥ"])
def test_findings_require_the_saved_web_client_key(seeded, saved_client):
    config, client = seeded
    save_review(config, [PRODUCTS[0]], "ACME")
    write_managed(config, [Asset("w-nginx-m", vendor="nginx", product="nginx",
                                 version="1.25.3", client="ACME")], "ACME")
    with StateStore(config.database_path).transaction() as db:
        write_finding(db, 20, client=saved_client)
        write_finding(db, 21, client="acme")
    row = export((config, client), client="ACME").json["technologies"][0]
    assert row["covered_ids"] == ["w-nginx-m"]
    assert {cve["cve_id"] for cve in row["cves"]} == {id_for(21)}


def test_managed_inventory_owner_must_match_the_web_client_key(seeded):
    config, client = seeded
    save_review(config, [PRODUCTS[0]], "ACME")
    write_managed(config, [Asset("w-nginx-m", vendor="nginx", product="nginx",
                                 version="1.25.3", client="ＡＣＭＥ")], "ACME")
    with StateStore(config.database_path).transaction() as db:
        write_finding(db, 20, client="ACME")
    result = export((config, client), client="ACME").json
    assert result["technologies"][0]["covered_ids"] == []
    assert result["technologies"][0]["cves"] == []
    assert any("managed inventory could not be read" in notice for notice in result["notices"])


def test_managed_identity_matches_require_the_detection_site(seeded):
    config, _ = seeded
    product = PRODUCTS[0]
    save_review(config, [product, dict(product, asset_id="w-second-nginx", hostname="b.example"),
                         {key: value for key, value in dict(product, asset_id="w-unknown").items()
                          if key != "hostname"}])
    write_managed(config, [
        Asset(asset_id, vendor="nginx", product="nginx", version="1.25.3", system_id=site, client=CLIENT)
        for asset_id, site in (("w-nginx-m", "different.example"), ("imported-widget", "a.example"),
                               ("other-site", "c.example"), ("unknown-site", ""))
    ], CLIENT)
    with StateStore(config.database_path).transaction() as db:
        for number, asset_id in enumerate(("imported-widget", "other-site", "unknown-site"), start=20):
            write_finding(db, number, asset_id=asset_id)
    rows = {row["site"]: row for row in export(seeded).json["technologies"]}
    assert rows["a.example"]["covered_ids"] == ["imported-widget", "w-nginx-m"]
    assert id_for(20) in {cve["cve_id"] for cve in rows["a.example"]["cves"]}
    assert rows["b.example"]["covered_ids"] == rows["Site not recorded"]["covered_ids"] == []


@pytest.mark.parametrize("snapshot_id", ["w-nginx", "w-lodash", "foreign", None])
def test_snapshot_coverage_requires_a_saved_snapshot_row(seeded, snapshot_id):
    config, _ = seeded
    with StateStore(config.database_path).transaction() as db:
        write_finding(db, 19, asset_id="w-nginx", cvss_score=6)
    config.config_path.write_text("[inventory]\nweb_snapshots = true\n\n"
                                  + config.config_path.read_text(encoding="utf-8"),
                                  encoding="utf-8", newline="\n")
    if snapshot_id == "foreign":
        _, output = web_assets.paths(config, CLIENT)
        snapshot(output.parent, name=output.stem, asset_id="w-nginx", client="Other Client")
    elif snapshot_id:
        save_snapshot(config, snapshot_id, client=CLIENT)
    products = [dict(product) for product in PRODUCTS]
    if snapshot_id == "w-nginx":
        for product in products:
            product.pop("inventory")
    save_review(config, products)
    from cvebeacon.config import load_config
    app = create_app(load_config(config.config_path))
    try:
        row = next(row for row in export((config, app.test_client())).json["technologies"]
                   if row["technology"] == "nginx")
        present = snapshot_id == "w-nginx"
        assert ("w-nginx" in row["covered_ids"]) == present
        assert (id_for(19) in {cve["cve_id"] for cve in row["cves"]}) == present
    finally:
        app.extensions["dashboard_jobs"].shutdown()


def test_watch_exploitation_and_sources(seeded, watch_views):
    row = technology(export(seeded, window="all").json)
    assert row["exploitation"] == "active"
    by_id = {cve["cve_id"]: (cve["exploitation"], cve["exploitation_sources"]) for cve in row["cves"]}
    assert by_id == {
        id_for(1): ("active", ["CISA ADP"]),
        id_for(2): ("active", ["SSVC", "euvd"]),
        id_for(3): ("poc", ["SSVC"]),
        id_for(4): ("none", ["SSVC"]),
        id_for(5): ("unknown", []),
    }
    text = page(seeded).text
    assert "CISA ADP" in text and "SSVC, euvd" in text and ">PoC<" in text
    assert "Actively exploited · 2" in text


def test_unreadable_watch_database_is_unknown(seeded):
    seeded[0].watch.database.write_bytes(b"invalid database")
    assert technology(export(seeded).json)["exploitation"] == "unknown"
    assert "Unknown" in page(seeded).text


def test_unreadable_findings_are_reported_as_unavailable(seeded):
    seeded[0].database_path.write_bytes(b"invalid database")
    response = page(seeded, show_empty="0")
    assert "Current CVE findings could not be read" in response.text
    row = technology(export(seeded, show_empty="0").json)
    assert row["coverage"] == "unavailable"
    assert row["window_count"] is row["current_count"] is None


@pytest.mark.parametrize(("query", "expected"), [
    ({"site": "b.example"}, {"WordPress", "jQuery", "Analytics"}),
    ({"category": "js-library"}, {"Lodash", "jQuery"}),
    ({"conf": ["medium", "low"]}, {"Lodash", "WordPress", "jQuery", "Analytics"}),
    ({"status": "ready"}, {"Lodash", "=nginx"}),
    ({"status": "monitored"}, {"=nginx"}),
    ({"status": "review"}, {"WordPress", "jQuery"}),
    ({"status": "service"}, {"Analytics"}),
    ({"filters": "1"}, {"=nginx"}),
    ({"show_empty": "0"}, {"=nginx"}),
])
def test_technology_filters(seeded, query, expected):
    assert {row["technology"] for row in export(seeded, **query).json["technologies"]} == expected


@pytest.mark.parametrize(("query", "numbers"), [
    ({"severity": "low"}, (1, 2, 3)),
    ({"severity": "medium"}, (1, 2)),
    ({"severity": "high"}, (1, 2)),
    ({"severity": "critical"}, (1,)),
    ({"kev": "cisa"}, (1,)),
    ({"kev": "eu"}, (2,)),
    ({"kev": "either"}, (1, 2)),
    ({"exploited": "active"}, (1, 2)),
    ({"exploited": "poc"}, (1, 2, 3)),
    ({"severity": "high", "kev": "eu", "exploited": "active"}, (2,)),
])
def test_cve_filters(seeded, watch_views, query, numbers):
    response = export(seeded, **query)
    assert cve_ids(response) == {id_for(i) for i in numbers}
    assert technology(response.json)["current_count"] == 5


def test_exports_match_page_and_keep_spreadsheet_values_literal(seeded):
    query = {"window": "range", "from": day(29), "to": day(), "severity": "high", "site": "a.example"}
    page_text = page(seeded, **query).text
    assert id_for(1) in page_text and id_for(2) in page_text and id_for(3) not in page_text
    responses = {}
    for kind in ("xlsx", "csv", "json"):
        href = re.search(r'href="([^"]+/export\?[^"]+)"[^>]*>Export ' + kind.upper(), page_text)[1]
        response = seeded[1].get(unescape(href))
        assert response.status_code == 200
        assert response.headers["Content-Disposition"] == (
            f"attachment; filename=cvebeacon-acme-q2-{day(29)}-{day()}.{kind}"
        )
        responses[kind] = response

    result = responses["json"].json
    assert set(result) == {"client", "window", "generated_at", "filters", "technologies"}
    assert result["client"] == CLIENT and result["filters"]["severity"] == "high"
    assert result["window"] == {"kind": "range", "field": "published", "from": day(29), "to": day()}
    assert cve_ids(responses["json"]) == {id_for(1), id_for(2)}
    assert technology(result)["technology"] == "=nginx"
    assert responses["json"].headers["Cache-Control"] == "no-store"

    book = load_workbook(BytesIO(responses["xlsx"].data))
    try:
        assert book.sheetnames == ["Technologies", "CVEs"]
        for sheet in book:
            assert sheet["A1"].value == "Client" and sheet["B1"].value == CLIENT
            assert sheet["A2"].value == "Window" and day(29) in sheet["B2"].value
            assert sheet["A4"].value == "Generated at (UTC)"
            assert json.loads(sheet["B5"].value)["site"] == "a.example"
        assert book["Technologies"]["B8"].value == "'=nginx"
        assert book["Technologies"]["B8"].data_type == "s"
        assert book["Technologies"]["C8"].value == "'+1.25.3, 1.25.4"
        assert book["CVEs"]["F8"].value == id_for(1)
        assert book["CVEs"]["F9"].value == id_for(2)
    finally:
        book.close()

    reader = csv.DictReader(StringIO(responses["csv"].text))
    assert reader.fieldnames[:7] == ["Site", "Technology", "Versions", "Confidence", "Status", "CVE ID", "Advisory ID"]
    rows = list(reader)
    assert [(row["Technology"], row["CVE ID"]) for row in rows] == [
        ("'=nginx", id_for(1)), ("'=nginx", id_for(2)), ("Lodash", ""),
    ]
    assert rows[0]["Versions"] == "'+1.25.3, 1.25.4"
    assert rows[0]["EPSS (%)"] == "72.0"
    assert rows[2]["Exploitation"] == ""
    assert "Lodash" not in export(seeded, "csv", **query, show_empty="0").text


@pytest.mark.parametrize("prefix", ("=", "+", "-", "@", "\t", "\r"))
def test_spreadsheet_prefixes_are_literal(seeded, prefix):
    config, _ = seeded
    save_review(config, [dict(PRODUCTS[2], name=prefix + "technology")])
    row = next(csv.DictReader(StringIO(export(seeded, "csv").text)))
    assert row["Technology"] == "'" + prefix + "technology"
    book = load_workbook(BytesIO(export(seeded, "xlsx").data))
    try:
        cell = book["Technologies"]["B8"]
        assert cell.value.replace("\r", "\n") == "'" + prefix.replace("\r", "\n") + "technology"
        assert cell.data_type == "s"
    finally:
        book.close()


def test_report_limits_keep_counts_and_export_all_technologies(seeded, monkeypatch):
    assert (tech_report.PAGE_ROWS, tech_report.PAGE_CVES_PER_ROW, tech_report.EXPORT_CVES) == (1000, 200, 50000)
    monkeypatch.setattr(tech_report, "PAGE_ROWS", 2)
    monkeypatch.setattr(tech_report, "PAGE_CVES_PER_ROW", 1)
    monkeypatch.setattr(tech_report, "EXPORT_CVES", 2)
    response = page(seeded)
    assert "Showing the first" in response.text and "Counts include all matching CVEs" in response.text
    assert response.text.count('scope="row"') == 2 and "CVEs (3)" in response.text
    assert id_for(1) in response.text and id_for(2) not in response.text
    result = export(seeded)
    assert result.headers["X-CVEBeacon-Report-Truncated"] == "true"
    assert len(result.json["technologies"]) == 6
    capped = technology(result.json)
    assert capped["window_count"] == 3 and len(capped["cves"]) == 2 and capped["cves_capped"]


def test_report_stops_at_the_scoped_findings_cap(seeded, monkeypatch):
    config, _ = seeded
    with StateStore(config.database_path).transaction() as db:
        write_finding(db, 0, asset_id="w-extra-path-m", client="Other Client")
    assert tech_report.FINDINGS_CAP == 200_000
    monkeypatch.setattr(tech_report, "FINDINGS_CAP", 2)
    decoded = []
    original = tech_report._finding

    def record_decode(record):
        decoded.append(record["cve_id"])
        return original(record)

    monkeypatch.setattr(tech_report, "_finding", record_decode)
    notice = "Results were truncated at 2 findings; narrow the window or filters."
    assert notice in page(seeded, window="all").text
    assert decoded == [id_for(1), id_for(1)]
    result = export(seeded, window="all")
    assert result.headers["X-CVEBeacon-Report-Truncated"] == "true"
    assert notice in result.json["notices"]
    assert technology(result.json)["current_count"] == 1
    assert result.json["technologies"][0]["cves_capped"] is False
    assert export(seeded, "csv").headers["X-CVEBeacon-Report-Notices"] == notice
    book = load_workbook(BytesIO(export(seeded, "xlsx").data))
    try:
        assert ("Notices", notice) in book["Technologies"].iter_rows(max_col=2, values_only=True)
    finally:
        book.close()


def test_watch_cache_retains_only_cves_in_the_output(seeded, monkeypatch):
    config, _ = seeded
    other = dict(PRODUCTS[0], name="Second technology", product="other", asset_id="second")
    save_review(config, [dict(PRODUCTS[0], name="=nginx"), other])
    write_managed(config, [
        Asset(asset_id, vendor="example", product=product, version="1", client=CLIENT)
        for asset_id, product in (("w-nginx-m", "nginx"), ("second-m", "other"))
    ], CLIENT)
    with StateStore(config.database_path).transaction() as db:
        write_finding(db, 1, asset_id="second-m", cvss_score=9.8)
        write_finding(db, 2, asset_id="second-m", cvss_score=7.5)
    WatchStore(config.watch.database).initialize()
    calls = []

    def view(self, db, identifier, catalogs):
        calls.append(identifier)
        return None

    monkeypatch.setattr(WatchStore, "_view", view)
    monkeypatch.setattr(tech_report, "PAGE_CVES_PER_ROW", 1)
    page(seeded)
    assert calls.count(id_for(1)) == 1
    assert calls.count(id_for(2)) == 2


def test_links_csp_and_table_header_widths(seeded):
    response = page(seeded)
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert not re.search(r"<style\b|\sstyle=|<script(?![^>]*\ssrc=)", response.text)
    classes = re.findall(r'<th scope="col" class="([^"]+)">', response.text)
    assert len(classes) == len(set(classes)) == 14
    css = seeded[1].get("/static/tech_report.css").text
    assert "nth-child" not in css
    assert all(re.search(rf"th\.{name}\s*{{\s*width:", css) for name in classes)
    assert '<div class="table-wrap" role="region" aria-label="Technology exposure"' in response.text
    web = seeded[1].get("/web-assets", query_string={"client": CLIENT})
    assert re.search(r'href="/web-assets/report\?client=[^"]+">Technology report', web.text)


def test_requests_respect_login_and_view_permission(tmp_path):
    config = write_config(tmp_path, inventory=False)
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("run-only", {"run"}, authorization=admin)
    users.save_role("view-only", {"view"}, authorization=admin)
    users.add("runner", password=PASSWORD, role="run-only")
    users.add("viewer", password=PASSWORD, role="view-only")
    app = create_app(config)
    try:
        for username, expected in ((None, 303), ("runner", 403), ("viewer", 200)):
            client = app.test_client()
            if username:
                login(client, username)
            for url in (PAGE, EXPORT):
                response = client.get(url, query_string={"client": "Unknown", "format": "json"})
                assert response.status_code == expected
                if username is None:
                    assert response.location == "/login"
    finally:
        app.extensions["dashboard_jobs"].shutdown()


def test_printable_view_expands_cve_lists_and_drops_controls(seeded):
    normal = page(seeded)
    assert normal.status_code == 200
    link = re.search(r'href="([^"]*print=1[^"]*)">Printable view', normal.text)
    assert link is not None
    assert 'class="tech-report-cves">' in normal.text and "tech-report-filters" in normal.text
    printable = page(seeded, print="1", filters="1")
    assert printable.status_code == 200
    assert 'class="tech-report-cves" open>' in printable.text
    assert "tech-report-filters" not in printable.text and "Printable view" not in printable.text
    assert "Save as PDF" in printable.text and "Back to the report" in printable.text
    assert not re.search(r"<style\b|\sstyle=|<script(?![^>]*\ssrc=)", printable.text)
