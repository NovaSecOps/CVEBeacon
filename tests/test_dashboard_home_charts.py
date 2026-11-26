"""Home severity chart counts, states and accessible markup."""

from datetime import timedelta
from html.parser import HTMLParser
import hashlib
import json
import re

import pytest

from cvebeacon import dashboard, dashboard_setup
from cvebeacon.config import load_config
from cvebeacon.models import Applicability as A, Asset, Finding, QueryResult, Vulnerability, utc_now
from cvebeacon.private_storage import private_directory
from cvebeacon.state import StateStore
from cvebeacon.web_assets import save_allowlist


@pytest.fixture(autouse=True)
def _no_host_scheduler(monkeypatch):
    monkeypatch.setattr(dashboard_setup, "schedule_scan_state", lambda config: "none")


def make_home(tmp_path, *, inventory=True, web_snapshots=False, watch_enabled=False):
    config_path = tmp_path / "config.toml"
    text = "[state]\ndatabase = 'state.db'\n[output]\ndirectory = 'reports'\n"
    if inventory:
        text += "[inventory]\npath = 'inventory.csv'\n"
        if web_snapshots:
            text += "web_snapshots = true\n"
    if watch_enabled:
        text += "[watch]\nenabled = true\n"
    text += "[sources]\n" + "\n".join(
        f"{name}_enabled = false"
        for name in ("nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")
    ) + "\n"
    config_path.write_text(text, encoding="utf-8", newline="\n")
    if inventory:
        (tmp_path / "inventory.csv").write_text(
            "asset_id,vendor,product,version\na,Acme,Widget,1\n",
            encoding="utf-8",
            newline="\n",
        )
    config = load_config(config_path)
    app = dashboard.create_app(config)
    return config, app.test_client()


def make_finding(asset, identifier, score, applicability=A.AFFECTED):
    vulnerability = Vulnerability(
        cve_id=identifier,
        summary="Synthetic finding",
        cvss_score=score,
    )
    return Finding(asset, vulnerability, applicability, "high", "Synthetic evidence")


def record_scan(config, grouped_findings):
    results = [
        QueryResult(asset, tuple(findings), ())
        for asset, findings in grouped_findings
    ]
    StateStore(config.database_path).record_scan(results)


def chart_fragment(page):
    marker = 'id="home-severity-chart-card"'
    if marker not in page:
        return ""
    start = page.rfind("<section", 0, page.index(marker))
    end = page.find("</section>", page.index(marker)) + len("</section>")
    return page[start:end]


class ChartMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.images = []
        self.title_ids = set()
        self.desc_ids = set()
        self.bar_values = []
        self.tables = []
        self.table_rows = None
        self.in_tbody = False
        self.current_row = None
        self.current_cell = None
        self.capture_class = None
        self.capture_text = []
        self.style_attribute = False
        self.style_element = False
        self.inline_scripts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "svg" and attrs.get("role") == "img":
            self.images.append(attrs)
        if tag == "title" and attrs.get("id"):
            self.title_ids.add(attrs["id"])
        if tag == "desc" and attrs.get("id"):
            self.desc_ids.add(attrs["id"])
        if any(name.lower() == "style" for name, _ in attrs.items()):
            self.style_attribute = True
        if tag == "style":
            self.style_element = True
        if tag == "script" and "src" not in attrs:
            self.inline_scripts.append(attrs)
        if tag == "text" and "home-chart-bar-value" in attrs.get("class", "").split():
            self.capture_class = "bar-value"
            self.capture_text = []
        if tag == "table":
            self.table_rows = []
        elif tag == "tbody":
            self.in_tbody = True
        elif tag == "tr" and self.in_tbody:
            self.current_row = []
        elif tag in {"td", "th"} and self.current_row is not None:
            self.current_cell = []

    def handle_data(self, data):
        if self.capture_class:
            self.capture_text.append(data)
        if self.current_cell is not None:
            self.current_cell.append(data)

    def handle_endtag(self, tag):
        if tag == "text" and self.capture_class:
            self.bar_values.append("".join(self.capture_text).strip())
            self.capture_class = None
        elif tag in {"td", "th"} and self.current_cell is not None:
            self.current_row.append("".join(self.current_cell).strip())
            self.current_cell = None
        elif tag == "tr" and self.current_row is not None:
            self.table_rows.append(self.current_row)
            self.current_row = None
        elif tag == "tbody":
            self.in_tbody = False
        elif tag == "table" and self.table_rows is not None:
            self.tables.append(self.table_rows)
            self.table_rows = None


def test_severity_bands_count_only_affected_current_findings_and_sum_to_card(tmp_path):
    config, client = make_home(tmp_path)
    asset = Asset("a", "Acme", "Widget", "1")
    changed = Asset("changed", "Acme", "Other", "1")
    (tmp_path / "inventory.csv").write_text(
        "asset_id,vendor,product,version\na,Acme,Widget,1\nchanged,Acme,Other,2\n",
        encoding="utf-8",
        newline="\n",
    )
    findings = [
        make_finding(asset, "CVE-2026-0001", 9.0),
        make_finding(asset, "CVE-2026-0002", 7.0),
        make_finding(asset, "CVE-2026-0003", 4.0),
        make_finding(asset, "CVE-2026-0004", 0.1),
        make_finding(asset, "CVE-2026-0005", 0),
        make_finding(asset, "CVE-2026-0006", None),
        make_finding(asset, "CVE-2026-0007", 9.8, A.NEEDS_REVIEW),
        make_finding(asset, "CVE-2026-0008", 9.8, A.NOT_AFFECTED),
    ]
    record_scan(config, [(asset, findings), (changed, [make_finding(changed, "CVE-2026-0009", 9.8)])])

    # This is an obsolete alias row. StateStore.dashboard_snapshot() excludes it.
    superseded = make_finding(asset, "CVE-2026-0010", 9.9).to_dict()
    store = StateStore(config.database_path)
    timestamp = utc_now().isoformat()
    with store.transaction() as db:
        db.execute(
            "INSERT INTO current_findings VALUES (?,?,?,?,?,?)",
            ("a", "CVE-2026-0010", timestamp, timestamp, "superseded", json.dumps(superseded)),
        )
        db.execute(
            "INSERT INTO advisory_aliases(asset_id,alias,primary_id) VALUES (?,?,?)",
            ("a", "CVE-2026-0010", "CVE-2026-0001"),
        )

    page = client.get("/").text
    chart = chart_fragment(page)
    assert chart
    parser = ChartMarkup()
    parser.feed(chart)
    expected_bands = [
        ("Critical", "1"),
        ("High", "1"),
        ("Medium", "1"),
        ("Low", "1"),
        ("None", "1"),
        ("Unknown score", "1"),
    ]
    assert parser.bar_values == [value for _label, value in expected_bands]
    assert parser.tables == [[list(pair) for pair in expected_bands]]
    assert sum(map(int, parser.bar_values)) == 6
    assert '<span class="stat-value">6</span><span class="stat-label">Affected findings</span>' in page


def test_valid_empty_severity_chart_keeps_six_zero_bands_and_explains_empty(tmp_path):
    config, client = make_home(tmp_path)
    asset = Asset("a", "Acme", "Widget", "1")
    record_scan(config, [(asset, [])])
    chart = chart_fragment(client.get("/").text)
    assert chart
    parser = ChartMarkup()
    parser.feed(chart)
    assert parser.bar_values == ["0"] * 6
    assert "No affected findings recorded for this inventory." in chart


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("no_inventory", "Add inventory to see these numbers."),
        ("unreadable", "Could not check."),
        ("partial", "Could not check."),
        ("no_scan", "No scan recorded."),
    ],
)
def test_uncheckable_severity_chart_reuses_inventory_states_without_bars_or_zero(
    tmp_path, state, expected
):
    config, client = make_home(
        tmp_path,
        inventory=state != "no_inventory",
        web_snapshots=state == "partial",
        watch_enabled=state == "no_inventory",
    )
    if state == "unreadable":
        (tmp_path / "inventory.csv").write_text("not a valid inventory\n", encoding="utf-8", newline="\n")
    elif state == "partial":
        snapshots = config.database_path.parent / "web-inventory"
        private_directory(snapshots, owner_only=True)
        save_allowlist(snapshots / "broken.json", {"bad": "snapshot"})

    chart = chart_fragment(client.get("/").text)
    assert chart
    assert expected in chart
    assert "<rect" not in chart
    assert not re.search(r">\s*0\s*</(?:text|td|span)>|\bCount:? 0\b", chart)


def test_stale_chart_keeps_counts_and_carries_the_home_stale_cue(tmp_path):
    config, client = make_home(tmp_path)
    asset = Asset("a", "Acme", "Widget", "1")
    record_scan(config, [(asset, [make_finding(asset, "CVE-2026-0200", 8.0)])])
    old = (utc_now() - timedelta(days=2)).isoformat()
    with StateStore(config.database_path).transaction() as db:
        db.execute("UPDATE runs SET completed_at=?", (old,))
    chart = chart_fragment(client.get("/").text)
    assert chart
    parser = ChartMarkup()
    parser.feed(chart)
    assert parser.bar_values == ["0", "1", "0", "0", "0", "0"]
    assert "Stale scan data" in chart


def test_readable_partial_web_snapshot_counts_findings_in_the_chart(tmp_path):
    config, client = make_home(tmp_path, web_snapshots=True)
    asset = Asset("a", "Acme", "Widget", "1")
    record_scan(config, [(asset, [make_finding(asset, "CVE-2026-0300", 9.0)])])
    snapshots = config.database_path.parent / "web-inventory"
    private_directory(snapshots, owner_only=True)
    snapshot = snapshots / "partial.json"
    save_allowlist(snapshot, [dict(asset_id="web-item", vendor="Acme", product="Part", version="1")])
    timestamp = utc_now().isoformat()
    save_allowlist(snapshot.with_name(snapshot.name + ".manifest.json"), {
        "contract": "cvebeacon.inventory.v1",
        "collector": "web-detect",
        "collector_version": "0.1.0",
        "source_id": "test-web",
        "generated_at": timestamp,
        "observed_at": timestamp,
        "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
        "record_count": 1,
        "status": "partial",
        "omissions": ["blocked"],
    })

    page = client.get("/").text
    chart = chart_fragment(page)
    assert chart
    parser = ChartMarkup()
    parser.feed(chart)
    assert parser.bar_values == ["1", "0", "0", "0", "0", "0"]
    assert "Could not check" not in chart


def test_severity_chart_svg_ids_accessibility_table_and_no_inline_markup(tmp_path):
    config, client = make_home(tmp_path)
    asset = Asset("a", "Acme", "Widget", "1")
    record_scan(config, [(asset, [make_finding(asset, "CVE-2026-0400", None)])])
    page = client.get("/").text
    chart = chart_fragment(page)
    parser = ChartMarkup()
    parser.feed(chart)
    assert len(parser.images) == 1
    image = parser.images[0]
    assert image.get("id") == "home-severity-chart"
    assert image.get("aria-labelledby", "").split() == [
        "home-severity-chart-title", "home-severity-chart-desc"
    ]
    assert "home-severity-chart-title" in parser.title_ids
    assert "home-severity-chart-desc" in parser.desc_ids
    page_parser = ChartMarkup()
    page_parser.feed(page)
    assert len(page_parser.ids) == len(set(page_parser.ids))
    assert "Severity band" in chart and "Affected findings (count)" in chart
    assert parser.tables == [[
        ["Critical", "0"],
        ["High", "0"],
        ["Medium", "0"],
        ["Low", "0"],
        ["None", "0"],
        ["Unknown score", "1"],
    ]]
    assert "<details" in chart and "<details open" not in chart
    assert "<caption>" in chart
    assert not parser.style_attribute
    assert not parser.style_element
    assert not parser.inline_scripts
    assert "default-src 'none'; style-src 'self'; script-src 'self'" in client.get("/").headers[
        "Content-Security-Policy"
    ]

