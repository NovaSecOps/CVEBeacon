"""Web assets section shell, page placement and legacy URL behaviour."""
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cvebeacon import web_assets
from cvebeacon.models import Asset, QueryResult
from cvebeacon.private_storage import private_directory, private_file
from cvebeacon.state import StateStore
from cvebeacon.web_assets import paths

from test_dashboard import setup  # noqa: F401
from test_dashboard_accounts import PASSWORD, accounts, csrf, login  # noqa: F401
from test_dashboard_web import grant, save, web  # noqa: F401
from test_web_inventory import snapshot


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
                 "/web-assets/detection?client=Acme", "/web-assets/products?client=Acme",
                 "/web-assets/changes?client=Acme"):
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
    changes_page = client.get("/web-assets/changes?client=Acme").text
    assert "Save sync settings" not in changes_page
    assert 'name="action" value="mode"' not in changes_page

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
    assert client.get("/web-assets/changes?client=Acme").status_code == 200
    assert "Save sync settings" not in client.get("/web-assets/changes?client=Acme").text


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
    overview = client.get("/web-assets?client=Acme").text
    assert ">Changes" not in tab_markup(overview)
    assert "Open changes" not in overview
    assert "Changes since the last scan" not in overview
    assert ("/web-assets/changes?client=Acme#sync-settings" in overview
            and "Turn on inventory sync" in overview)
    assert "/web-assets/inventory/sync" not in overview
    changes = client.get("/web-assets/changes?client=Acme").text
    assert ">Changes" not in tab_markup(changes)
    assert "Inventory sync" in changes and "Save sync settings" in changes
    response = client.post("/web-assets/inventory/sync", data={
        "csrf": csrf(client), "client": "Acme", "action": "mode", "mode": "review",
        "auto_remove": "default"})
    assert response.status_code == 303, response.text
    assert urlsplit(response.headers["Location"]).path == "/web-assets/changes"
    assert parse_qs(urlsplit(response.headers["Location"]).query)["sync_result"] == ["mode"]
    assert "Inventory sync setting saved." in client.get(response.headers["Location"]).text
    page = client.get("/web-assets?client=Acme").text
    tabs = tab_markup(page)
    assert ">Changes" in tabs
    assert re.search(r'href="/web-assets/changes\?client=Acme"', tabs)
    assert "Open changes" in page
    assert 'href="/web-assets/changes?client=Acme"' in page
    changes = client.get("/web-assets/changes?client=Acme").text
    changes_tabs = tab_markup(changes)
    assert changes_tabs.count('aria-current="page"') == 1
    assert re.search(r'<a href="/web-assets/changes\?client=Acme"[^>]*aria-current="page">Changes', changes_tabs)
    assert config.managed_inventory


def test_changes_page_owns_sync_settings_and_overview_keeps_a_summary(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    assert client.post("/web-assets/inventory/sync", data={
        "csrf": csrf(client), "client": "Acme", "action": "mode", "mode": "review",
        "auto_remove": "default"}).status_code == 303
    overview = client.get("/web-assets?client=Acme").text
    summary = overview.split('id="inventory-sync"', 1)[1].split("Next steps", 1)[0]
    assert 'href="/web-assets/changes?client=Acme"' in summary
    assert "Open changes" in summary
    assert "Changes since the last scan" not in overview
    assert 'name="action" value="mode"' not in overview
    changes = client.get("/web-assets/changes?client=Acme").text
    assert "Mode: Review (client override)" in changes
    assert "Automatic removal: off" in changes
    assert 'name="action" value="mode"' in changes
    assert 'action="/web-assets/inventory/sync"' in changes
    assert 'name="mode"' in changes and 'name="auto_remove"' in changes
    assert "Save sync settings" in changes
    assert "What the modes mean" in changes
    assert "Changes since the last scan" in changes


def test_changes_without_a_client_shows_the_chooser(web):
    _, _, _, client = web
    page = client.get("/web-assets/changes")
    assert page.status_code == 200 and "Choose a client" in page.text
    assert 'action="/web-assets/changes"' in page.text
    assert client.get("/web-assets/changes", query_string={"client": ""}).status_code == 200


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


def test_sync_parameters_redirect_to_changes(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    assert client.post("/web-assets/inventory/sync", data={
        "csrf": csrf(client), "client": "Acme", "action": "mode", "mode": "review",
        "auto_remove": "default"}).status_code == 303
    for query, expected in (
            ({"sync_page": "1"}, {"sync_page": ["1"]}),
            ({"sync_result": "mode"}, {"sync_result": ["mode"]}),
            ({"sync_page": "2", "sync_result": "update"},
             {"sync_page": ["2"], "sync_result": ["update"]}),
            ({"sync_page": "1", "unknown": "x"}, {"sync_page": ["1"]})):
        response = client.get("/web-assets", query_string={"client": "Acme", **query})
        assert response.status_code == 302, (query, response.text)
        location = urlsplit(response.headers["Location"])
        assert location.path == "/web-assets/changes", query
        assert parse_qs(location.query) == {"client": ["Acme"], **expected}, query
        page = client.get(response.headers["Location"])
        assert page.status_code == 200 and "Choose a client" not in page.text, query
        assert "Changes since the last scan" in page.text, query


def test_sites_without_a_client_shows_the_chooser_not_an_error(web):
    _, _, _, client = web
    page = client.get("/web-assets/sites")
    assert page.status_code == 200
    assert "Choose a client" in page.text and 'id="add-asset"' not in page.text
    assert client.get("/web-assets/sites", query_string={"client": ""}).status_code == 200


def test_client_chooser_opens_the_page_it_is_on(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    for page, destination in (("/web-assets", "/web-assets"),
                              ("/web-assets/sites", "/web-assets/sites"),
                              ("/web-assets/detection", "/web-assets/detection"),
                              ("/web-assets/products", "/web-assets/products"),
                              ("/web-assets/changes", "/web-assets/changes")):
        response = client.get(page)
        assert response.status_code == 200
        chooser = response.text.split("Choose a client", 1)[1].split("</section>", 1)[0]
        assert f'action="{destination}"' in chooser
        assert f'<a href="{destination}?client=Acme">Acme</a>' in chooser


def test_web_assets_pages_have_no_inline_script_or_style_and_load_bulk_script(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    for path in ("/web-assets?client=Acme", "/web-assets/sites?client=Acme",
                 "/web-assets/detection?client=Acme", "/web-assets/products?client=Acme",
                 "/web-assets/changes?client=Acme"):
        text = client.get(path).text
        assert not re.search(r"(?i)\sstyle\s*=", text)
        assert not re.search(r"(?is)<style\b", text)
        assert not re.search(r"(?is)<script\b(?![^>]*\bsrc=)[^>]*>", text)
        assert not re.search(r"(?i)\son[a-z]+\s*=", text)
    overview = client.get("/web-assets?client=Acme").text
    assert '<script src="/static/web-assets.js" defer></script>' in overview
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


def test_product_rows_carry_stable_anchor_targets(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [
        {"asset_id": "w-nginx", "hostname": "a.example", "vendor": "nginx", "product": "nginx",
         "name": "nginx", "category": "web-server", "categories": ["web-server"],
         "confidence": "high", "versions": ["1.25.3"], "evidence_types": ["header"]},
        {"asset_id": "w-wp", "hostname": "b.example", "vendor": "wordpress", "product": "wordpress",
         "name": "WordPress", "category": "cms", "categories": ["cms"],
         "confidence": "low", "versions": [], "evidence_types": ["meta"]},
        {"hostname": "c.example", "vendor": "example", "product": "widget", "name": "Widget",
         "category": "framework", "categories": ["framework"], "confidence": "medium",
         "versions": ["2.0"], "evidence_types": ["header"]},
    ])
    site_page = client.get("/web-assets/products?client=Acme").text
    assert site_page.count('id="product-w-nginx"') == 1
    assert site_page.count('id="product-w-wp"') == 1
    assert site_page.count('<tr id="product-') == 2
    category_page = client.get("/web-assets/products", query_string={
        "client": "Acme", "view": "category"}).text
    assert category_page.count('id="product-w-nginx"') == 1
    assert category_page.count('id="product-w-wp"') == 1
    assert category_page.count('<tr id="product-') == 2


def test_empty_filter_result_keeps_client_wide_add_actions(web):
    config, users, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [
        {"asset_id": "web-ready", "hostname": "a.example", "vendor": "nginx", "product": "nginx",
         "name": "nginx", "category": "web-server", "categories": ["web-server"],
         "confidence": "high", "versions": ["1.25.3"], "evidence_types": ["header"]},
        {"asset_id": "web-other", "hostname": "b.example", "vendor": "apache", "product": "apache",
         "name": "Apache", "category": "web-server", "categories": ["web-server"],
         "confidence": "medium", "versions": ["2.4.58"], "evidence_types": ["header"]},
    ])
    page = client.get("/web-assets/products", query_string={
        "client": "Acme", "tech": "zzz"}).text
    assert "No products match these filters" in page
    assert "Add all 2 ready products" in page
    assert "Add all High confidence ready products (1)" in page
    assert "Add all except Low confidence (2)" in page
    card = page.split('id="detected-products"', 1)[1].split("</main>", 1)[0]
    assert 'action="/web-assets/inventory/preview"' in card
    assert 'name="action" value="all"' in card
    assert 'name="csrf"' in card and not re.search(r'name="csrf" value=""', card)
    assert 'name="tech" value="zzz"' in card

    grant(users, {"view"})
    login(client, "reader")
    readonly = client.get("/web-assets/products", query_string={
        "client": "Acme", "tech": "zzz"}).text
    assert "No products match these filters" in readonly
    assert "Add all 2 ready products" not in readonly
    assert "Add all High confidence ready products" not in readonly


def test_category_view_labels_every_product_cell_with_its_site(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [
        {"asset_id": "web-alpha-a", "hostname": "a.example", "vendor": "example",
         "product": "alpha", "name": "Alpha", "category": "framework",
         "categories": ["framework"], "confidence": "low", "versions": [],
         "evidence_types": ["header"]},
        {"asset_id": "web-alpha-b", "hostname": "b.example", "vendor": "example",
         "product": "alpha", "name": "Alpha", "category": "framework",
         "categories": ["framework"], "confidence": "low", "versions": [],
         "evidence_types": ["header"]},
        {"asset_id": "web-nosite", "vendor": "example", "product": "nohost", "name": "NoHost",
         "category": "cms", "categories": ["cms"], "confidence": "high",
         "versions": ["1.0"], "evidence_types": ["meta"]},
    ])
    page = client.get("/web-assets/products", query_string={
        "client": "Acme", "view": "category"}).text
    rows = {}
    for asset_id in ("web-alpha-a", "web-alpha-b", "web-nosite"):
        rows[asset_id] = next(chunk for chunk in page.split("<tr") if f'id="product-{asset_id}"' in chunk)
    assert '<div class="muted web-product-site">a.example</div>' in rows["web-alpha-a"]
    assert '<div class="muted web-product-site">b.example</div>' in rows["web-alpha-b"]
    assert '<div class="muted web-product-site">Site not recorded</div>' in rows["web-nosite"]
    assert 'aria-label="Select Alpha on a.example"' in rows["web-alpha-a"]
    assert 'aria-label="Select Alpha on b.example"' in rows["web-alpha-b"]
    assert 'aria-label="Select NoHost on Site not recorded"' in rows["web-nosite"]
    assert "Version of Alpha on a.example" in rows["web-alpha-a"]
    assert "Version of Alpha on b.example" in rows["web-alpha-b"]


def test_status_tiles_keep_the_current_view(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [
        {"asset_id": "web-ready", "hostname": "a.example", "vendor": "nginx", "product": "nginx",
         "name": "nginx", "category": "web-server", "categories": ["web-server"],
         "confidence": "high", "versions": ["1.25.3"], "evidence_types": ["header"]},
    ])
    page = client.get("/web-assets/products", query_string={
        "client": "Acme", "view": "tech"}).text
    tiles = dict((label, href.replace("&amp;", "&")) for href, label in re.findall(
        r'<a class="stat[^"]*" href="([^"]+)">.*?<span class="stat-label">([^<]+)</span>', page, re.S))
    for label, status in (("Monitored", "monitored"), ("Ready to add", "ready"),
                          ("Needs review", "review"), ("Third-party services", "service")):
        query = parse_qs(urlsplit(tiles[label]).query)
        assert query["inv"] == [status], label
        assert query["view"] == ["tech"], label
    ready = client.get(tiles["Ready to add"])
    assert ready.status_code == 200
    assert re.search(r'href="[^"]*view=tech[^"]*"[^>]*aria-current="page">By technology', ready.text)
    assert "Detected products by technology" in ready.text


def test_legacy_product_redirects_keep_first_values_and_notice_text(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [
        {"asset_id": "web-ready", "hostname": "a.example", "vendor": "nginx", "product": "nginx",
         "name": "nginx", "category": "web-server", "categories": ["web-server"],
         "confidence": "high", "versions": ["1.25.3"], "evidence_types": ["header"]},
    ])
    cases = (
        ({"view": ["tech", "site"]}, {"view": ["tech"]}),
        ({"tech": ["nginx", "apache"]}, {"tech": ["nginx"]}),
        ({"conf": ["high", "low"]}, {"conf": ["high", "low"]}),
        ({"conf": ["high", "unknown", "low"]}, {"conf": ["high", "low"]}),
        ({"tech": ""}, {}),
        ({"conf": "unknown"}, {}),
        ({"version": "bogus"}, {}),
        ({"marked": "000001"}, {"marked": ["000001"]}),
        ({"added": "000002"}, {"added": ["000002"]}),
    )
    for query, expected in cases:
        response = client.get("/web-assets", query_string={"client": "Acme", **query})
        assert response.status_code == 302, (query, response.text)
        location = urlsplit(response.headers["Location"])
        assert location.path == "/web-assets/products", query
        assert parse_qs(location.query) == {"client": ["Acme"], **expected}, query
        page = client.get(response.headers["Location"])
        assert page.status_code == 200 and "Choose a client" not in page.text, query

    marked = client.get("/web-assets", query_string={"client": "Acme", "marked": "000001"})
    assert "Marked 1 technology as reported." in client.get(marked.headers["Location"]).text
    repeated = client.get("/web-assets/products", query_string={
        "client": "Acme", "view": ["tech", "site"]}).text
    assert "Detected products by technology" in repeated



def test_products_without_a_client_or_with_a_bad_client(web):
    _, _, _, client = web
    page = client.get("/web-assets/products")
    assert page.status_code == 200 and "Choose a client" in page.text
    assert client.get("/web-assets/products", query_string={"client": ""}).status_code == 200
    assert client.get("/web-assets/products", query_string={"client": "x" * 200}).status_code == 400


def test_sites_page_does_not_read_job_history_or_findings(web, monkeypatch):
    config, _, app, client = web
    assert save(client).status_code == 303
    seed_products(config, [{
        "asset_id": "web-1", "hostname": "example.invalid", "vendor": "nginx", "product": "nginx",
        "name": "nginx", "category": "web-server", "categories": ["web-server"], "confidence": "high",
        "versions": ["1.25.3"], "evidence_types": ["header"]}])

    def unexpected(*args, **kwargs):
        raise AssertionError("a Sites GET must not read job history or findings")

    monkeypatch.setattr(app.extensions["dashboard_jobs"].store, "recent", unexpected)
    monkeypatch.setattr(StateStore, "finding_summary", unexpected)
    page = client.get("/web-assets/sites?client=Acme")
    assert page.status_code == 200, page.text


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
    assert ".review-table td:empty" not in css
    assert re.search(r"details\.danger-zone\s*\{[^}]*border-color:\s*var\(--danger-border\)", css, re.S)
    assert re.search(r"details\.danger-zone > summary\s*\{[^}]*color:\s*var\(--danger-text\)", css, re.S)
    assert re.search(r"details\.site-item > summary\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\) auto", css, re.S)
    script = (Path(dashboard_web.__file__).parent / "static" / "web-assets.js").read_text(encoding="utf-8")
    assert "data-bulk-select-all" in script and "data-bulk-clear" in script
    ui_script = (Path(dashboard_web.__file__).parent / "static" / "ui.js").read_text(encoding="utf-8")
    assert 'querySelector(\'[aria-current="page"]\')' in ui_script and "scrollLeft" in ui_script


def test_filter_panel_sticks_on_desktop_and_collapses_the_mobile_technology_cards():
    from cvebeacon import dashboard_web
    css = (Path(dashboard_web.__file__).parent / "static" / "dashboard.css").read_text(encoding="utf-8")
    desktop = css.split("@media (min-width: 901px)", 1)[1]
    assert re.search(
        r"\.filter-panel\s*\{[^}]*position:\s*sticky;[^}]*top:\s*var\(--topbar-height\);[^}]*z-index:\s*\d+",
        desktop, re.S)
    assert ".filter-bar { position: sticky" not in css
    assert ".filter-panel { position: sticky" not in css.split("@media (min-width: 901px)", 1)[0]
    mobile = css.split("@media (max-width: 640px)", 1)[1]
    assert re.search(r"\.web-tech-table-wrap\s*\{\s*display:\s*none;", mobile)
    assert re.search(r"\.web-tech-groups\s*\{\s*display:\s*grid;", mobile)
    assert re.search(r"\.web-tech-groups\s*\{\s*display:\s*none;", css)



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
    assert client.get("/web-assets/changes", query_string={"client": "x" * 200}).status_code == 400


def seed_detection(config, *, run=None, reviews=()):
    _, output = paths(config, "Acme")
    detail = {"client": "Acme", "products": [], "reviews": list(reviews)}
    if run is not None:
        detail["run"] = run
    web_assets.replace_bytes(Path(str(output) + ".review.json"),
                             json.dumps(detail).encode("utf-8"))


def review_table(page):
    start = '<table class="table-dense review-table" role="table">'
    assert start in page
    return page.split(start, 1)[1].split("</table>", 1)[0]


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
    assert "Entries to review" not in overview and "Run details" not in overview
    assert 'id="detection"' in overview
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


def test_review_table_keeps_seven_cells_and_header_associations(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_detection(config, run=RUN, reviews=[
        {"asset_id": "web-example", "reason": "blocked", "detail": "fixed safe detail",
         "status": 429, "retry_after": 120},
        {"asset_id": "web-other", "reason": "version-unknown", "detail": ""},
    ])
    page = client.get("/web-assets/detection?client=Acme").text
    table = review_table(page)
    assert table.count('role="columnheader"') == 7
    assert table.count('role="rowgroup"') == 2
    assert table.count('role="row"') == 3
    assert table.count('role="cell"') == 14
    assert table.count("<td") == 14
    headers = re.findall(
        r'<th id="([^"]+)"[^>]*scope="col" role="columnheader">([^<]+)</th>', table)
    assert [label for _, label in headers] == [
        "Asset", "Reason", "Detail", "Product", "Conflicting versions",
        "HTTP status", "Retry after (seconds)"]
    for row in re.findall(r'<tr role="row">(.*?)</tr>', table, re.S)[1:]:
        assert re.findall(r'headers="([^"]+)"', row) == [item[0] for item in headers]
    assert ('<td role="cell" headers="review-status" data-label="HTTP status">429</td>'
            in table)
    assert ('<td role="cell" headers="review-retry" data-label="Retry after (seconds)"'
            ' class="num">120</td>' in table)
    assert '<td role="cell" headers="review-product" data-label="Product">—</td>' in table
    assert ('<td role="cell" headers="review-versions"'
            ' data-label="Conflicting versions">—</td>' in table)
    assert '<td role="cell" headers="review-detail" data-label="Detail">—</td>' in table


def test_failed_run_callout_counts_fetch_failure_reasons_before_the_display_cap(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    reviews = [{"asset_id": f"web-{index}", "reason": "no-technologies",
                "detail": "ordinary detail"} for index in range(1000)]
    reviews += [
        {"asset_id": "web-blocked-a", "reason": "blocked", "detail": "private raw detail"},
        {"asset_id": "web-blocked-b", "reason": "blocked"},
        {"asset_id": "web-timeout", "reason": "timeout"},
    ]
    seed_detection(config, run={**RUN, "status": "failed", "fetched_count": 0},
                   reviews=reviews)
    page = client.get("/web-assets/detection?client=Acme").text
    assert '<span class="badge badge-danger">Failed</span>' in page
    callout = page.split('class="callout callout-danger"', 1)[1].split("</div></div>", 1)[0]
    assert "Request blocked: 2" in callout
    assert "Request timed out: 1" in callout
    assert "private raw detail" not in callout
    assert "example.invalid" not in callout


def test_failed_run_without_saved_reasons_says_counts_are_unavailable(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_detection(config, run={**RUN, "status": "failed"}, reviews=[
        {"asset_id": "web-example", "reason": "version-unknown"}])
    page = client.get("/web-assets/detection?client=Acme").text
    callout = page.split('class="callout callout-danger"', 1)[1].split("</div></div>", 1)[0]
    assert "Reason counts are unavailable." in callout


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
    assert 'id="detection"' in page
    summary = page.split('id="detection"', 1)[1].split("</section>", 1)[0]
    assert 'href="/web-assets/detection?client=Acme"' in summary
    assert "Detection details" in summary or "Open Detection" in summary


def test_sites_get_does_not_create_web_storage(web):
    config, _, _, client = web
    data = config.database_path.parent
    assert not (data / "web-assets").exists()
    assert not (data / "web-inventory").exists()
    page = client.get("/web-assets/sites?client=Acme")
    assert page.status_code == 200, page.text
    assert not (data / "web-assets").exists()
    assert not (data / "web-inventory").exists()


def test_sites_get_does_not_recover_the_inventory_journal(web):
    config, _, _, client = web
    directory = config.inventory_directory
    private_directory(directory, owner_only=True)
    staging = directory / ".inventory-pending-current"
    descriptor = private_file(staging, create=True, exclusive=True)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(b'[{"asset_id":"orphan"}]\n')
    page = client.get("/web-assets/sites?client=Acme")
    assert page.status_code == 200, page.text
    assert staging.read_bytes() == b'[{"asset_id":"orphan"}]\n'


def test_sites_get_leaves_the_saved_allowlist_unchanged(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    path, output = paths(config, "Acme")
    before = path.read_bytes()
    page = client.get("/web-assets/sites?client=Acme")
    assert page.status_code == 200, page.text
    assert path.read_bytes() == before
    assert not output.exists()


def test_snapshot_and_manifest_keep_danger_zone_and_provenance(web):
    config, _, _, client = web
    _, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    review = Path(str(output) + ".review.json")
    review.unlink()
    assert not paths(config, "Acme")[0].exists()
    assert not Path(str(output) + ".removed").exists()

    sites = client.get("/web-assets/sites?client=Acme")
    assert sites.status_code == 200, sites.text
    assert "Remove all assets" in sites.text

    overview = client.get("/web-assets?client=Acme")
    assert overview.status_code == 200, overview.text
    manifest = json.loads(Path(str(output) + ".manifest.json").read_text(encoding="utf-8"))
    assert f"{manifest['record_count']} saved inventory record" in overview.text
    assert manifest["generated_at"][:10] in overview.text


def test_malformed_prefill_is_rejected_before_any_redirect(web):
    _, _, _, client = web
    assert client.get("/web-assets", query_string={
        "prefill_url": "not a URL"}).status_code == 400
    assert client.get("/web-assets", query_string={
        "client": "Acme", "prefill_url": "not a URL"}).status_code == 400
    valid = client.get("/web-assets", query_string={
        "client": "Acme", "prefill_url": "https://www.example.invalid:443/"})
    assert valid.status_code == 302


def test_bulk_controls_are_revealed_only_by_the_bulk_script(web):
    from cvebeacon import dashboard_web

    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [{
        "asset_id": "web-1", "hostname": "example.invalid", "vendor": "nginx", "product": "nginx",
        "name": "nginx", "category": "web-server", "categories": ["web-server"], "confidence": "high",
        "versions": ["1.25.3"], "evidence_types": ["header"]}])
    form = client.get("/web-assets/products?client=Acme").text.split(
        "data-bulk-form", 1)[1].split("</form>", 1)[0]
    assert "data-bulk-select-all" in form and "data-bulk-clear" in form
    assert "data-bulk-ready" not in form
    pick = re.search(r'<input type="checkbox" name="pick" value="web-1"[^>]*>', form)
    assert pick and "disabled" not in pick.group(0)
    assert "Add selected to inventory" in form

    static = Path(dashboard_web.__file__).parent / "static"
    css = (static / "dashboard.css").read_text(encoding="utf-8")
    assert re.search(r"\.bulk-select-controls\s*\{[^}]*display:\s*none;", css, re.S)
    assert re.search(r"form\[data-bulk-ready\]\s+\.bulk-select-controls\s*\{[^}]*display:\s*flex;",
                     css, re.S)
    assert ".js .bulk-select-controls" not in css
    script = (static / "web-assets.js").read_text(encoding="utf-8")
    assert re.search(r'update\(\);\s*\n\s*form\.dataset\.bulkReady\s*=\s*"true";\s*\n\s*\}', script)
