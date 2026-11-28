"""Web assets section shell, page placement and legacy URL behaviour."""
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cvebeacon import web_assets
from cvebeacon.models import Asset, QueryResult
from cvebeacon.state import StateStore
from cvebeacon.web_assets import paths

from test_dashboard import setup  # noqa: F401
from test_dashboard_accounts import PASSWORD, accounts, csrf, login  # noqa: F401
from test_dashboard_web import grant, save, web  # noqa: F401


def seed_products(config, products):
    _, output = paths(config, "Acme")
    detail = {"client": "Acme", "products": products, "reviews": []}
    web_assets.replace_bytes(Path(str(output) + ".review.json"),
                             json.dumps(detail).encode("utf-8"))


def tab_markup(text):
    match = re.search(r'<nav class="section-tabs"[^>]*>.*?</nav>', text, re.S)
    assert match, "section tabs are missing"
    return match.group(0)


def test_overview_and_sites_render_for_view_only_and_manage_users(web):
    config, users, _, client = web
    assert save(client).status_code == 303
    grant(users, {"view"})
    login(client, "reader")
    for path in ("/web-assets?client=Acme", "/web-assets/sites?client=Acme",
                 "/web-assets/detection?client=Acme", "/web-assets/products?client=Acme"):
        page = client.get(path)
        assert page.status_code == 200, page.text
    site_page = client.get("/web-assets/sites?client=Acme").text
    assert 'name="hostname"' not in site_page
    assert "Remove this site" not in site_page
    assert 'name="csv_file"' not in site_page
    detection_page = client.get("/web-assets/detection?client=Acme").text
    assert 'value="web-detect"' not in detection_page and 'value="web-plan"' not in detection_page
    products_page = client.get("/web-assets/products?client=Acme").text
    assert "Add selected to inventory" not in products_page
    assert "Mark selected as reported" not in products_page

    users.save_role("web-editor", {"view", "manage_web_assets"}, authorization=users.authenticate("admin", PASSWORD))
    users.edit_user("reader", role="web-editor", disabled=False,
                    authorization=users.authenticate("admin", PASSWORD))
    login(client)
    site_page = client.get("/web-assets/sites?client=Acme").text
    assert 'name="hostname"' in site_page
    assert "Remove this site" in site_page and 'name="csv_file"' in site_page
    overview = client.get("/web-assets?client=Acme").text
    assert 'name="hostname"' not in overview
    assert 'name="csv_file"' not in overview
    assert "Remove all assets" not in overview
    assert client.get("/web-assets/detection?client=Acme").status_code == 200
    assert client.get("/web-assets/products?client=Acme").status_code == 200


def test_section_tabs_mark_exactly_one_current_page(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    overview = tab_markup(client.get("/web-assets?client=Acme").text)
    assert overview.count('aria-current="page"') == 1
    assert re.search(r'<a href="/web-assets\?client=Acme"[^>]*aria-current="page">Overview', overview)
    assert ">Sites <span" in overview and ">Report<" in overview

    sites = tab_markup(client.get("/web-assets/sites?client=Acme").text)
    assert sites.count('aria-current="page"') == 1
    assert re.search(r'<a href="/web-assets/sites\?client=Acme"[^>]*aria-current="page">Sites', sites)
    assert 'role="tablist"' not in sites

    detection = tab_markup(client.get("/web-assets/detection?client=Acme").text)
    assert detection.count('aria-current="page"') == 1
    assert re.search(r'<a href="/web-assets/detection\?client=Acme"[^>]*aria-current="page">Detection', detection)
    assert 'role="tablist"' not in detection

    products = tab_markup(client.get("/web-assets/products?client=Acme").text)
    assert products.count('aria-current="page"') == 1
    assert re.search(r'<a href="/web-assets/products\?client=Acme"[^>]*aria-current="page">Products', products)
    assert 'role="tablist"' not in products


def test_changes_tab_and_summary_only_when_inventory_sync_is_on(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    overview = tab_markup(client.get("/web-assets?client=Acme").text)
    assert ">Changes" not in overview
    assert "Open changes" not in client.get("/web-assets?client=Acme").text
    response = client.post("/web-assets/inventory/sync", data={
        "csrf": csrf(client), "client": "Acme", "action": "mode", "mode": "review",
        "auto_remove": "default"})
    assert response.status_code == 303, response.text
    page = client.get("/web-assets?client=Acme").text
    assert ">Changes" in tab_markup(page)
    assert "Open changes" in page
    assert config.managed_inventory


def test_sites_page_owns_the_site_forms_and_bulk_import(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    overview = client.get("/web-assets?client=Acme").text
    assert 'id="add-asset"' not in overview
    assert 'id="import-sites"' not in overview
    assert "Remove all assets" not in overview
    sites = client.get("/web-assets/sites?client=Acme").text
    assert 'id="add-asset"' in sites and 'id="import-sites"' in sites
    assert "Remove all assets" in sites
    assert "/web-assets/import-template" in sites


def test_legacy_imported_prefill_and_overview_alias_redirect(web):
    _, _, _, client = web
    assert save(client).status_code == 303

    alias = client.get("/web-assets/overview", query_string={"client": "Acme"})
    assert alias.status_code == 302
    assert urlsplit(alias.headers["Location"]).path == "/web-assets"
    assert parse_qs(urlsplit(alias.headers["Location"]).query) == {"client": ["Acme"]}

    imported = client.get("/web-assets", query_string={"client": "Acme", "imported": "2"})
    assert imported.status_code == 302
    location = urlsplit(imported.headers["Location"])
    assert location.path == "/web-assets/sites"
    assert parse_qs(location.query) == {"client": ["Acme"], "imported": ["2"]}
    page = client.get(imported.headers["Location"])
    assert page.status_code == 200
    assert "Imported 2 sites. Run detection when you're ready." in page.text

    prefill = client.get("/web-assets", query_string={
        "client": "Acme", "prefill_url": "https://www.example.invalid:443/"})
    assert prefill.status_code == 302
    location = urlsplit(prefill.headers["Location"])
    assert location.path == "/web-assets/sites" and location.fragment == "add-asset"
    assert parse_qs(location.query)["prefill_url"] == ["https://www.example.invalid:443/"]
    form = client.get(prefill.headers["Location"]).text
    assert 'id="add-asset" open' in form
    assert 'name="hostname" value="www.example.invalid"' in form
    assert 'name="port" type="number" min="1" max="65535" value="443"' in form


def test_overview_alias_preserves_known_parameters_and_ignores_unknown(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [{
        "asset_id": "web-nginx", "hostname": "example.invalid", "vendor": "nginx",
        "product": "nginx", "name": "nginx", "category": "web-server",
        "categories": ["web-server"], "confidence": "high", "versions": ["1.0"],
        "evidence_types": ["header"]}])
    response = client.get("/web-assets/overview", query_string={
        "client": "Acme", "view": "tech", "unknown": "1", "tech": "nginx"})
    assert response.status_code == 302
    location = urlsplit(response.headers["Location"])
    query = parse_qs(location.query)
    assert location.path == "/web-assets"
    assert query == {"client": ["Acme"], "view": ["tech"], "tech": ["nginx"]}
    page = client.get(response.headers["Location"], follow_redirects=True)
    assert page.status_code == 200 and "Detected products by technology" in page.text


def test_legacy_product_filter_and_notice_parameters_redirect_to_products(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    cases = (
        ({"view": "tech"}, {"view": ["tech"]}),
        ({"view": "site"}, {"view": ["site"]}),
        ({"view": "category"}, {"view": ["category"]}),
        ({"conf": "high"}, {"conf": ["high"]}),
        ({"conf": ["high", "low"]}, {"conf": ["high", "low"]}),
        ({"version": "with"}, {"version": ["with"]}),
        ({"inv": "ready"}, {"inv": ["ready"]}),
        ({"rep": "not"}, {"rep": ["not"]}),
        ({"category": "framework"}, {"category": ["framework"]}),
        ({"site": "example.invalid"}, {"site": ["example.invalid"]}),
        ({"tech": "nginx"}, {"tech": ["nginx"]}),
        ({"added": "1"}, {"added": ["1"]}),
        ({"marked": "1"}, {"marked": ["1"]}),
        ({"withdrawn": "1"}, {"withdrawn": ["1"]}),
    )
    for query, expected in cases:
        response = client.get("/web-assets", query_string={"client": "Acme", **query})
        assert response.status_code == 302, (query, response.text)
        location = urlsplit(response.headers["Location"])
        assert location.path == "/web-assets/products", query
        assert parse_qs(location.query) == {"client": ["Acme"], **expected}, query
        page = client.get(response.headers["Location"])
        assert page.status_code == 200 and "Choose a client" not in page.text, query
        assert "Detected products" in page.text, query


def test_sync_parameters_stay_on_overview_until_the_changes_page(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    for query in ({"sync_page": "1"}, {"sync_result": "mode"}):
        page = client.get("/web-assets", query_string={"client": "Acme", **query})
        assert page.status_code == 200, (query, page.text)
        assert "Changes since the last scan" in page.text, query
        assert "Choose a client" not in page.text


def test_sites_without_a_client_shows_the_chooser_not_an_error(web):
    _, _, _, client = web
    page = client.get("/web-assets/sites")
    assert page.status_code == 200
    assert "Choose a client" in page.text and 'id="add-asset"' not in page.text
    assert client.get("/web-assets/sites", query_string={"client": ""}).status_code == 200


def test_web_assets_pages_have_no_inline_script_or_style_and_load_bulk_script(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    for path in ("/web-assets?client=Acme", "/web-assets/sites?client=Acme",
                 "/web-assets/detection?client=Acme", "/web-assets/products?client=Acme"):
        text = client.get(path).text
        assert not re.search(r"(?i)\sstyle\s*=", text)
        assert not re.search(r"(?is)<style\b", text)
        assert not re.search(r"(?is)<script\b(?![^>]*\bsrc=)[^>]*>", text)
        assert not re.search(r"(?i)\son[a-z]+\s*=", text)
    overview = client.get("/web-assets?client=Acme").text
    assert '<script src="/static/web-assets.js" defer></script>' not in overview
    products = client.get("/web-assets/products?client=Acme").text
    assert '<script src="/static/web-assets.js" defer></script>' in products


def test_bulk_select_controls_are_marked_for_the_script(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [{
        "asset_id": "web-1", "hostname": "example.invalid", "vendor": "nginx", "product": "nginx",
        "name": "nginx", "category": "web-server", "categories": ["web-server"], "confidence": "high",
        "versions": ["1.25.3"], "evidence_types": ["header"]}])
    page = client.get("/web-assets/products?client=Acme").text
    form = page.split("data-bulk-form", 1)[1].split("</form>", 1)[0]
    assert "data-bulk-select-all" in form
    assert "data-bulk-clear" in form
    assert "data-bulk-count" in form
    assert "data-bulk-controls" in form
    assert "data-bulk-ready" not in form
    assert 'name="pick" value="web-1"' in form
    assert 'formaction="/web-assets/reported"' in form
    assert 'name="action" value="mark"' in form and 'name="action" value="withdraw"' in form


def test_sites_page_does_not_inspect_inventory_sync(web, monkeypatch):
    from cvebeacon import web_inventory_sync as sync

    def unexpected(*args, **kwargs):
        raise AssertionError("the Sites page must not inspect inventory sync")

    monkeypatch.setattr(sync, "inspect", unexpected)
    _, _, _, client = web
    assert save(client).status_code == 303
    assert client.get("/web-assets/sites?client=Acme").status_code == 200


def test_products_page_does_not_inspect_inventory_sync(web, monkeypatch):
    from cvebeacon import web_inventory_sync as sync

    def unexpected(*args, **kwargs):
        raise AssertionError("the Products page must not inspect inventory sync")

    monkeypatch.setattr(sync, "inspect", unexpected)
    _, _, _, client = web
    assert save(client).status_code == 303
    assert client.get("/web-assets/products?client=Acme").status_code == 200


def test_products_default_to_collapsed_site_groups(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [
        {"asset_id": "web-nginx", "hostname": "a.example", "vendor": "nginx", "product": "nginx",
         "name": "nginx", "category": "web-server", "categories": ["web-server"],
         "confidence": "high", "versions": ["1.25.3"], "evidence_types": ["header"]},
        {"asset_id": "web-wp", "hostname": "a.example", "vendor": "wordpress", "product": "wordpress",
         "name": "WordPress", "category": "cms", "categories": ["cms"], "confidence": "low",
         "versions": [], "evidence_types": ["meta"]},
        {"asset_id": "web-react", "hostname": "b.example", "vendor": "react", "product": "react",
         "name": "React", "category": "js-library", "categories": ["js-library"],
         "confidence": "high", "versions": ["18.2.0"], "evidence_types": ["script"]},
    ])
    page = client.get("/web-assets/products?client=Acme").text
    assert re.search(r'href="/web-assets/products\?client=Acme&amp;view=site"[^>]*aria-current="page"', page)
    groups = re.findall(r'<details class="product-group"([^>]*)>', page)
    assert len(groups) == 2
    assert all("open" not in attributes.split() for attributes in groups)
    assert re.search(r'<summary><span class="group-title">a\.example</span><span class="group-meta">2 products</span>.*?badge-info">1 ready</span>.*?badge-warning">1 needs review</span>', page, re.S)
    assert re.search(r'<summary><span class="group-title">b\.example</span><span class="group-meta">1 product</span>.*?badge-info">1 ready</span>', page, re.S)
    assert "2 site groups, all collapsed." in page


def test_view_switch_preserves_the_active_filters(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [
        {"asset_id": "web-1", "hostname": "a.example", "vendor": "nginx", "product": "nginx",
         "name": "Alpha", "category": "web-server", "categories": ["web-server"],
         "confidence": "high", "versions": ["1.0"], "evidence_types": ["header"]},
    ])
    page = client.get("/web-assets/products", query_string={
        "client": "Acme", "view": "site", "conf": "high", "tech": "Alpha"}).text
    tech = re.search(r'href="([^"]*view=tech[^"]*)"', page)[1].replace("&amp;", "&")
    category = re.search(r'href="([^"]*view=category[^"]*)"', page)[1].replace("&amp;", "&")
    assert "conf=high" in tech and "tech=Alpha" in tech
    assert "conf=high" in category and "tech=Alpha" in category
    switched = client.get(tech)
    assert switched.status_code == 200
    assert "Detected products by technology" in switched.text
    assert "Alpha" in switched.text


def test_category_view_groups_once_in_detector_order(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [
        {"asset_id": "web-multi", "hostname": "a.example", "vendor": "lodash", "product": "lodash",
         "name": "Multi", "category": "js-library",
         "categories": ["js-library", "web-server", "reverse-proxy"],
         "confidence": "high", "versions": ["1.0"], "evidence_types": ["script"]},
        {"asset_id": "web-wp", "hostname": "a.example", "vendor": "wordpress", "product": "wordpress",
         "name": "WordPress", "category": "cms", "categories": ["cms"], "confidence": "low",
         "versions": [], "evidence_types": ["meta"]},
        {"asset_id": "web-nginx", "hostname": "b.example", "vendor": "nginx", "product": "nginx",
         "name": "nginx", "category": "web-server", "categories": ["web-server"],
         "confidence": "high", "versions": ["1.25.3"], "evidence_types": ["header"]},
    ])
    page = client.get("/web-assets/products", query_string={
        "client": "Acme", "view": "category"}).text
    assert page.index('group-title">web-server') < page.index('group-title">cms') < page.index('group-title">js-library')
    assert page.count("<strong>Multi</strong>") == 1
    group = page.split('group-title">js-library', 1)[1].split("</details>", 1)[0]
    assert "badge-info\">1 ready" in group
    assert 'badge-neutral">web-server' in group and 'badge-neutral">reverse-proxy' in group
    assert 'badge-neutral">js-library' not in group


def test_select_all_reveal_is_script_ready(web):
    from cvebeacon import dashboard_web
    static = Path(dashboard_web.__file__).parent / "static"
    css = (static / "dashboard.css").read_text(encoding="utf-8")
    script = (static / "web-assets.js").read_text(encoding="utf-8")
    assert ".bulk-select-controls[data-bulk-ready]" in css
    assert ".js .bulk-select-controls" not in css
    assert 'setAttribute("data-bulk-ready", "true")' in script
    assert "data-bulk-controls" in script


def test_products_without_a_client_or_with_a_bad_client(web):
    _, _, _, client = web
    page = client.get("/web-assets/products")
    assert page.status_code == 200 and "Choose a client" in page.text
    assert client.get("/web-assets/products", query_string={"client": ""}).status_code == 200
    assert client.get("/web-assets/products", query_string={"client": "x" * 200}).status_code == 400


def test_clients_list_links_to_each_clients_web_assets(web):
    config, _, _, client = web
    StateStore(config.database_path).record_scan([QueryResult(
        Asset("inventory-asset", vendor="Example", product="Widget", version="1", client="Acme"), (), ())])
    page = client.get("/watch/clients")
    assert page.status_code == 200
    assert 'href="/web-assets?client=Acme"' in page.text


def test_shared_section_components_are_styled():
    from cvebeacon import dashboard_web
    css = (Path(dashboard_web.__file__).parent / "static" / "dashboard.css").read_text(encoding="utf-8")
    for selector in (".section-tabs", ".product-group", ".filter-bar", ".bulk-bar",
                     ".table-dense", ".empty-state", ".field-grid", ".attestation"):
        assert re.search(re.escape(selector) + r"\b", css), selector
    assert re.search(r"\.filters > label\s*\{", css)
    assert not re.search(r"\.filters label\s*\{", css)
    assert re.search(r"\.section-tabs\s*\{[^}]*flex-wrap:\s*nowrap;[^}]*overflow-x:\s*auto;", css, re.S)
    assert ".section-tabs a:focus-visible" in css
    assert re.search(r"details\.danger-zone\s*\{[^}]*border-color:\s*var\(--danger-border\)", css, re.S)
    assert re.search(r"details\.danger-zone > summary\s*\{[^}]*color:\s*var\(--danger-text\)", css, re.S)
    assert re.search(r"details\.site-item > summary\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\) auto", css, re.S)
    script = (Path(dashboard_web.__file__).parent / "static" / "web-assets.js").read_text(encoding="utf-8")
    assert "data-bulk-select-all" in script and "data-bulk-clear" in script
    ui_script = (Path(dashboard_web.__file__).parent / "static" / "ui.js").read_text(encoding="utf-8")
    assert 'querySelector(\'[aria-current="page"]\')' in ui_script and "scrollLeft" in ui_script


def test_web_assets_is_a_separate_sidebar_section(web):
    _, _, _, client = web
    page = client.get("/web-assets?client=Acme").text
    sidebar = page.split('<nav class="sidebar"', 1)[1].split("</nav>", 1)[0]
    assert '<p class="nav-heading">Web assets</p>' in sidebar
    assert '<a href="/web-assets"' in sidebar
    assert '<a href="/web-assets/sites"' in sidebar
    assert '<a href="/web-assets/detection"' in sidebar
    assert '<a href="/web-assets/products"' in sidebar
    assert '<a href="/web-assets" aria-current="page">' in sidebar
    sites_sidebar = client.get("/web-assets/sites?client=Acme").text.split(
        '<nav class="sidebar"', 1)[1].split("</nav>", 1)[0]
    assert '<a href="/web-assets/sites" aria-current="page">' in sites_sidebar
    detection_sidebar = client.get("/web-assets/detection?client=Acme").text.split(
        '<nav class="sidebar"', 1)[1].split("</nav>", 1)[0]
    assert '<a href="/web-assets/detection" aria-current="page">' in detection_sidebar
    products_sidebar = client.get("/web-assets/products?client=Acme").text.split(
        '<nav class="sidebar"', 1)[1].split("</nav>", 1)[0]
    assert '<a href="/web-assets/products" aria-current="page">' in products_sidebar
    clients_group = sidebar.split('<p class="nav-heading">Clients</p>', 1)[1].split("</div>", 1)[0]
    assert "/web-assets" not in clients_group


def test_overview_alias_and_sites_reject_invalid_clients(web):
    _, _, _, client = web
    assert client.get("/web-assets/overview", query_string={"client": "x" * 200}).status_code == 400
    assert client.get("/web-assets/sites", query_string={"client": "x" * 200}).status_code == 400
    assert client.get("/web-assets/sites", query_string={
        "client": "Acme", "prefill_url": "not a URL"}).status_code == 400
    assert client.get("/web-assets/detection", query_string={"client": "x" * 200}).status_code == 400
    assert client.get("/web-assets/products", query_string={"client": "x" * 200}).status_code == 400


def seed_detection(config, *, run=None, reviews=()):
    _, output = paths(config, "Acme")
    detail = {"client": "Acme", "products": [], "reviews": list(reviews)}
    if run is not None:
        detail["run"] = run
    web_assets.replace_bytes(Path(str(output) + ".review.json"),
                             json.dumps(detail).encode("utf-8"))


RUN = {
    "status": "success", "started_at": "2026-11-27T09:15:00Z",
    "ended_at": "2026-11-27T09:16:39Z", "duration_seconds": 99.0,
    "request_count": 21, "asset_count": 1, "fetched_count": 1,
    "products_recognized": 0, "products_with_version": 0,
    "saved_snapshot_generated_at": "2026-11-27T09:15:00+00:00",
    "snapshot_updated": False,
}


def test_detection_page_owns_run_controls_summary_and_reviews(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_detection(config, run=RUN, reviews=[{
        "asset_id": "web-example", "reason": "version-unknown", "detail": "fixed safe detail"}])
    overview = client.get("/web-assets?client=Acme").text
    assert overview.count('value="web-detect"') == 1
    assert 'value="web-plan"' not in overview and "Check the saved sites" not in overview
    assert 'id="detection"' not in overview
    assert "Entries to review" not in overview and "Run details" not in overview
    assert "Detection details" not in overview and "Latest detection" not in overview
    assert 'href="/web-assets/detection?client=Acme"' in overview
    assert "Review 1 detection entry" in overview

    detection = client.get("/web-assets/detection?client=Acme").text
    assert 'value="web-detect"' in detection and 'value="web-plan"' in detection
    assert 'action="/web-assets/run"' in detection
    assert "Latest run" in detection and "Last checked" in detection
    assert "Sites fetched" in detection and "21" in detection
    assert "Entries to review" in detection
    assert "1 entry needs review." in detection
    assert "Version not disclosed" in detection
    assert '<span class="muted">version-unknown</span>' in detection
    assert 'class="table-dense review-table"' in detection
    assert 'data-label="Reason"' in detection


def test_detection_controls_follow_run_permission(web):
    _, users, _, client = web
    assert save(client).status_code == 303
    grant(users, {"view"})
    login(client, "reader")
    page = client.get("/web-assets/detection?client=Acme").text
    assert 'value="web-detect"' not in page and 'value="web-plan"' not in page
    assert "Detection is read-only for your account." in page

    users.save_role("web-editor", {"view", "manage_web_assets"},
                    authorization=users.authenticate("admin", PASSWORD))
    login(client)
    page = client.get("/web-assets/detection?client=Acme").text
    assert 'value="web-detect"' not in page and 'value="web-plan"' not in page

    users.save_role("web-editor", {"view", "run"},
                    authorization=users.authenticate("admin", PASSWORD))
    login(client)
    page = client.get("/web-assets/detection?client=Acme").text
    assert page.count('value="web-detect"') == 2 and page.count('value="web-plan"') == 1


def test_detection_page_without_sites_offers_the_sites_page(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    assert save(client, action="remove", index="0").status_code == 303
    page = client.get("/web-assets/detection?client=Acme").text
    assert "Add a site before running detection" in page
    assert 'value="web-detect"' not in page
    assert 'href="/web-assets/sites?client=Acme#add-asset"' in page


def test_detection_without_a_client_or_with_a_bad_client(web):
    _, _, _, client = web
    page = client.get("/web-assets/detection")
    assert page.status_code == 200 and "Choose a client" in page.text
    assert client.get("/web-assets/detection", query_string={"client": ""}).status_code == 200


def test_legacy_detection_anchor_is_gone_and_the_summary_links_to_detection(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    page = client.get("/web-assets?client=Acme").text
    assert 'id="detection"' not in page
    assert "Last detection" in page
    assert 'href="/web-assets/detection?client=Acme"' in page
