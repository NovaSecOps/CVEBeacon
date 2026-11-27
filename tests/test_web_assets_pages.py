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
    for path in ("/web-assets?client=Acme", "/web-assets/sites?client=Acme"):
        page = client.get(path)
        assert page.status_code == 200, page.text
    site_page = client.get("/web-assets/sites?client=Acme").text
    assert 'name="hostname"' not in site_page
    assert "Remove this site" not in site_page
    assert 'name="csv_file"' not in site_page

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
    _, _, _, client = web
    assert save(client).status_code == 303
    response = client.get("/web-assets/overview", query_string={
        "client": "Acme", "view": "tech", "unknown": "1", "tech": "nginx"})
    assert response.status_code == 302
    location = urlsplit(response.headers["Location"])
    query = parse_qs(location.query)
    assert location.path == "/web-assets"
    assert query == {"client": ["Acme"], "view": ["tech"], "tech": ["nginx"]}
    page = client.get(response.headers["Location"])
    assert page.status_code == 200 and "Detected products by technology" in page.text


def test_legacy_product_filter_notices_and_sync_parameters_still_render(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    for query in ({"view": "tech"}, {"view": "site"}, {"conf": "high"}, {"version": "with"},
                  {"inv": "ready"}, {"rep": "not"}, {"category": "framework"}, {"site": "example.invalid"},
                  {"tech": "nginx"}, {"added": "1"}, {"marked": "1"}, {"withdrawn": "1"},
                  {"sync_page": "1"}, {"sync_result": "mode"}):
        page = client.get("/web-assets", query_string={"client": "Acme", **query})
        assert page.status_code == 200, (query, page.text)
        assert "Web assets" in page.text and "Choose a client" not in page.text


def test_sites_without_a_client_shows_the_chooser_not_an_error(web):
    _, _, _, client = web
    page = client.get("/web-assets/sites")
    assert page.status_code == 200
    assert "Choose a client" in page.text and 'id="add-asset"' not in page.text
    assert client.get("/web-assets/sites", query_string={"client": ""}).status_code == 200


def test_overview_and_sites_have_no_inline_script_or_style_and_load_bulk_script(web):
    _, _, _, client = web
    assert save(client).status_code == 303
    for path in ("/web-assets?client=Acme", "/web-assets/sites?client=Acme"):
        text = client.get(path).text
        assert not re.search(r"(?i)\sstyle\s*=", text)
        assert not re.search(r"(?is)<style\b", text)
        assert not re.search(r"(?is)<script\b(?![^>]*\bsrc=)[^>]*>", text)
        assert not re.search(r"(?i)\son[a-z]+\s*=", text)
    overview = client.get("/web-assets?client=Acme").text
    assert '<script src="/static/web-assets.js" defer></script>' in overview


def test_bulk_select_controls_are_marked_for_the_script(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed_products(config, [{
        "asset_id": "web-1", "hostname": "example.invalid", "vendor": "nginx", "product": "nginx",
        "name": "nginx", "category": "web-server", "categories": ["web-server"], "confidence": "high",
        "versions": ["1.25.3"], "evidence_types": ["header"]}])
    page = client.get("/web-assets?client=Acme").text
    form = page.split("data-bulk-form", 1)[1].split("</form>", 1)[0]
    assert "data-bulk-select-all" in form
    assert "data-bulk-clear" in form
    assert "data-bulk-count" in form
    assert 'name="pick" value="web-1"' in form


def test_sites_page_does_not_inspect_inventory_sync(web, monkeypatch):
    from cvebeacon import web_inventory_sync as sync

    def unexpected(*args, **kwargs):
        raise AssertionError("the Sites page must not inspect inventory sync")

    monkeypatch.setattr(sync, "inspect", unexpected)
    _, _, _, client = web
    assert save(client).status_code == 303
    assert client.get("/web-assets/sites?client=Acme").status_code == 200


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
    script = (Path(dashboard_web.__file__).parent / "static" / "web-assets.js").read_text(encoding="utf-8")
    assert "data-bulk-select-all" in script and "data-bulk-clear" in script


def test_web_assets_is_a_separate_sidebar_section(web):
    _, _, _, client = web
    page = client.get("/web-assets?client=Acme").text
    sidebar = page.split('<nav class="sidebar"', 1)[1].split("</nav>", 1)[0]
    assert '<p class="nav-heading">Web assets</p>' in sidebar
    assert '<a href="/web-assets"' in sidebar
    assert '<a href="/web-assets/sites"' in sidebar
    assert '<a href="/web-assets" aria-current="page">' in sidebar
    sites_sidebar = client.get("/web-assets/sites?client=Acme").text.split(
        '<nav class="sidebar"', 1)[1].split("</nav>", 1)[0]
    assert '<a href="/web-assets/sites" aria-current="page">' in sites_sidebar
    clients_group = sidebar.split('<p class="nav-heading">Clients</p>', 1)[1].split("</div>", 1)[0]
    assert "/web-assets" not in clients_group


def test_overview_alias_and_sites_reject_invalid_clients(web):
    _, _, _, client = web
    assert client.get("/web-assets/overview", query_string={"client": "x" * 200}).status_code == 400
    assert client.get("/web-assets/sites", query_string={"client": "x" * 200}).status_code == 400
    assert client.get("/web-assets/sites", query_string={
        "client": "Acme", "prefill_url": "not a URL"}).status_code == 400
