"""Filters, summary chips and the by-technology view on the Web assets page."""
import json
import re
from pathlib import Path

import pytest

from cvebeacon import web_assets
from cvebeacon.web_assets import paths

from test_dashboard import setup  # noqa: F401
from test_dashboard_accounts import accounts  # noqa: F401
from test_dashboard_web import save, web  # noqa: F401


def product(host, name, *, versions=(), confidence="high", category="framework", **extra):
    return {"hostname": host, "vendor": name.lower(), "product": name.lower(), "name": name,
            "category": category, "confidence": confidence, "versions": list(versions),
            "evidence_types": ["header"], **extra}


def seed(web, products):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    detail = {"client": "Acme", "products": products, "reviews": []}
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    return client


def results(client, **query):
    page = client.get("/web-assets", query_string={"client": "Acme", **query})
    assert page.status_code == 200, page.text
    return page.text.split("Filter results", 1)[1].split("Entries to review", 1)[0]


SAMPLE = [
    product("a.example", "Alpha", versions=["1.0"], confidence="high", category="framework"),
    product("b.example", "Alpha", versions=["1.0"], confidence="low", category="framework"),
    product("c.example", "Alpha", versions=["2.0"], confidence="medium", category="framework"),
    product("a.example", "Beta", confidence="medium", category="server"),
    product("b.example", "Gamma", confidence="low", category="js-library"),
    product("b.example", "Delta", versions=["9"], confidence="low", category="js-library"),
]


def names(table):
    return re.findall(r"<strong>([^<]+)</strong>", table)


def test_each_filter_alone_and_combined(web):
    client = seed(web, SAMPLE)
    assert len(names(results(client))) == 6
    assert sorted(names(results(client, conf="high"))) == ["Alpha"]
    assert sorted(names(results(client, conf=["high", "low"]))) == ["Alpha", "Alpha", "Delta", "Gamma"]
    assert sorted(names(results(client, version="with"))) == ["Alpha", "Alpha", "Alpha", "Delta"]
    assert sorted(names(results(client, version="without"))) == ["Beta", "Gamma"]
    assert sorted(names(results(client, inv="review"))) == ["Beta", "Gamma"]
    assert len(names(results(client, inv="in"))) == 4
    assert sorted(names(results(client, category="server"))) == ["Beta"]
    assert sorted(names(results(client, site="b.example"))) == ["Alpha", "Delta", "Gamma"]
    assert sorted(names(results(client, tech="ALP"))) == ["Alpha"] * 3
    assert names(results(client, conf="low", version="with", site="b.example", tech="del")) == ["Delta"]
    assert "Showing 1 of 6 products." in client.get(
        "/web-assets", query_string={"client": "Acme", "category": "server"}).text


def test_unknown_and_oversized_parameters_are_ignored_and_escaped(web):
    client = seed(web, SAMPLE)
    assert len(names(results(client, conf="bogus", version="x", inv="y", category="nope", site="nope", view="zzz"))) == 6
    assert len(names(results(client, tech="x" * 81))) == 6
    assert len(names(results(client, tech="a\x01b"))) == 6
    page = client.get("/web-assets", query_string={"client": "Acme", "tech": "<script>alert(1)</script>"})
    assert page.status_code == 200
    assert "<script>alert(1)" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert names(results(client, tech="<script>")) == []
    assert "No products match these filters." in client.get(
        "/web-assets", query_string={"client": "Acme", "tech": "zzz"}).text


def test_by_technology_view(web):
    client = seed(web, SAMPLE)
    table = results(client, view="tech")
    assert names(table) == ["Alpha", "Beta", "Delta", "Gamma"]
    alpha = table.split("<tr>")[2]
    assert '<td class="num">3</td>' in alpha
    assert 'web-version-badge">1.0</span> <span class="muted">x2</span>' in alpha
    assert 'web-version-badge">2.0</span> <span class="muted">x1</span>' in alpha
    assert 'badge-high">High</span>' in alpha
    assert "Sites (3)" in alpha
    beta = table.split("<tr>")[3]
    assert "version not disclosed x1" in beta and "badge-medium" in beta
    assert "Sites (1)" in beta
    assert len(names(results(client, view="tech", conf="low"))) == 3


def test_chips_limits_and_clear_filters(web):
    client = seed(web, SAMPLE)
    page = client.get("/web-assets", query_string={"client": "Acme", "conf": "high"})
    text = page.text
    assert "Showing 1 of 6 products." in text
    assert "High confidence: 1" in text and "Medium confidence: 2" in text and "Low confidence: 3" in text
    assert "With version: 4" in text and "Without version: 2" in text
    assert "Technologies: 4" in text and "Sites: 3" in text
    assert re.search(r'href="/web-assets\?client=Acme&amp;view=site&amp;conf=low"', text)
    assert re.search(r'href="/web-assets\?client=Acme&amp;view=site&amp;version=without"', text)
    clear = re.search(r'<a href="([^"]+)">Clear filters</a>', text)[1].replace("&amp;", "&")
    cleared = client.get(clear)
    assert "Showing 6 of 6 products." in cleared.text
    assert "Clear filters</a></p>" not in cleared.text.split("Showing 6 of 6")[1][:60]
    assert 'name="client" value="Acme"' in text and 'value="Acme"' in cleared.text


def test_row_cap_and_note(web):
    many = [product(f"h{i % 40}.example", f"Tech{i}", versions=["1"]) for i in range(700)]
    client = seed(web, many)
    for view in ("site", "tech"):
        text = client.get("/web-assets", query_string={"client": "Acme", "view": view}).text
        assert "Showing the first 500; refine the filters." in text
        assert text.count("<strong>Tech") == 500
    assert "Showing the first 500" not in client.get(
        "/web-assets", query_string={"client": "Acme", "tech": "Tech69"}).text


def test_markup_has_no_inline_code_and_disclosures_are_closed(web):
    client = seed(web, SAMPLE)
    for view in ("site", "tech"):
        text = client.get("/web-assets", query_string={"client": "Acme", "view": view}).text
        assert not re.search(r"(?i)\sstyle\s*=", text)
        assert not re.search(r"(?is)<style\b", text)
        assert not re.search(r"(?is)<script\b(?![^>]*\bsrc=)[^>]*>", text)
        assert not re.search(r"<details[^>]*\bopen", text.split("Filter results", 1)[1].split("Entries to review", 1)[0])
