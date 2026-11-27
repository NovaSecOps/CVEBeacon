"""Honest inventory status, "Add to inventory" from Web assets, confidence colours and known CVEs."""
import html
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from cvebeacon import dashboard_web, web_assets, web_inventory_actions as actions
from cvebeacon.config import load_config
from cvebeacon.dashboard import create_app
from cvebeacon.inventory import load_inventory
from cvebeacon.locking import OperationLock
from cvebeacon.managed_inventory import client_key, read_inventory
from cvebeacon.models import (Applicability as A, Asset, Evidence, Finding, HealthStatus as H,
                              QueryResult, SourceHealth, Vulnerability, utc_now)
from cvebeacon.state import StateStore
from cvebeacon.web_assets import paths
from cvebeacon.watch.users import BOOTSTRAP, UserStore

from test_dashboard_accounts import PASSWORD, csrf, login
from test_dashboard_web import save
from test_web_inventory import snapshot
from watch_support import write_config

PRODUCTS = [
    dict(asset_id="w-nginx", hostname="a.example", vendor="nginx", product="nginx", name="nginx",
         category="web-server", categories=["web-server"], confidence="high", versions=["1.25.3"],
         evidence_types=["header"], inventory=True),
    dict(asset_id="w-lodash", hostname="a.example", vendor="lodash", product="lodash", name="Lodash",
         category="js-library", categories=["js-library"], confidence="medium", versions=["4.17.21"],
         evidence_types=["script"], ecosystem="npm", package="lodash", inventory=True),
    dict(asset_id="w-wp", hostname="b.example", vendor="wordpress", product="wordpress", name="WordPress",
         category="cms", categories=["cms"], confidence="low", versions=[],
         evidence_types=["meta"], inventory=False),
    dict(asset_id="w-multi", hostname="b.example", vendor="jquery", product="jquery", name="jQuery",
         category="js-library", categories=["js-library"], confidence="low", versions=["1.0", "2.0"],
         evidence_types=["script"], inventory=False),
]


def build(tmp_path, *, snapshots=False):
    pytest.importorskip("cvebeacon_extensions")
    config = write_config(tmp_path, inventory=False)
    config.config_path.chmod(0o644)
    if snapshots:
        text = config.config_path.read_text(encoding="utf-8")
        config.config_path.write_text("[inventory]\nweb_snapshots = true\n\n" + text,
                                      encoding="utf-8", newline="\n")
        config = load_config(config.config_path)
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("web-only", {"view", "manage_web_assets"}, authorization=admin)
    users.add("webonly", password=PASSWORD, role="web-only")
    app = create_app(config)
    client = app.test_client()
    login(client, "admin")
    yield config, users, app, client
    app.extensions["dashboard_jobs"].shutdown()


@pytest.fixture
def blank(tmp_path):
    yield from build(tmp_path)


@pytest.fixture
def snapshots_on(tmp_path):
    yield from build(tmp_path, snapshots=True)


def seed(env, products=PRODUCTS):
    config, _, _, client = env
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    detail = {"client": "Acme", "products": [dict(item) for item in products], "reviews": []}
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    return client


def save_snapshot(config, *asset_ids, client="Acme"):
    _, output = paths(config, client)
    rows = [dict(asset_id=asset_id, vendor="nginx", product="nginx", version="1.25.3", client=client)
            for asset_id in asset_ids]
    snapshot(output.parent, name=output.stem, client=client, rows=rows)


def page(client, **query):
    response = client.get("/web-assets", query_string={"client": "Acme", **query})
    assert response.status_code == 200, response.text
    return response.text


def products_card(text):
    return text.split("Detected products", 1)[1].split("Entries to review", 1)[0]


def row(text, name):
    return next(chunk for chunk in text.split("<tr>") if f"<strong>{name}</strong>" in chunk)


def preview(client, picks=(), versions=None, action="selected", **extra):
    data = {"csrf": csrf(client), "client": "Acme", "action": action, "pick": list(picks), **extra}
    for key, value in (versions or {}).items():
        data["v-" + key] = value
    return client.post("/web-assets/inventory/preview", data=data)


def confirmation(response):
    """The hidden fields of the confirmation form, as the browser would send them."""
    form = response.text.split('action="/web-assets/inventory/save"', 1)[1].split("</form>", 1)[0]
    data = {}
    for name, value in re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', form):
        data.setdefault(name, []).append(html.unescape(value))
    return data


def save_inventory(client, response, **override):
    data = confirmation(response)
    data.update(override)
    return client.post("/web-assets/inventory/save", data=data)


def managed_rows(config, client_name="Acme"):
    path = config.inventory_directory / f"{client_key(client_name)}.json"
    return read_inventory(path.read_bytes())


def write_managed(config, assets, client_name="Acme"):
    from dataclasses import asdict
    from cvebeacon.private_storage import private_directory
    private_directory(config.inventory_directory, owner_only=True)
    path = config.inventory_directory / f"{client_key(client_name)}.json"
    web_assets.replace_bytes(path, json.dumps([asdict(asset) for asset in assets]).encode("utf-8"))
    web_assets.replace_bytes(path.with_suffix(".client"), json.dumps(
        {"name": client_name, "notes": "", "contact": ""}).encode("utf-8"))


# Status ----------------------------------------------------------------------

def test_blank_install_shows_ready_to_add_never_monitored(blank):
    config = blank[0]
    client = seed(blank)
    assert not config.inventory_directory.exists()
    text = page(client)
    card = products_card(text)
    assert "badge-success" not in card
    assert "Ready to add" in row(card, "nginx") and "Ready to add" in row(card, "Lodash")
    assert "Needs review" in row(card, "WordPress") and "Needs review" in row(card, "jQuery")
    assert "2 detected products are not covered by CVE scans yet." in text
    assert "Include saved web snapshots in scans" in text
    assert text.count("Include saved web snapshots in scans") == 1
    assert "Not monitored" in row(card, "nginx")


def test_web_snapshots_on_marks_rows_monitored(snapshots_on):
    save_snapshot(snapshots_on[0], "w-nginx", "w-lodash")
    client = seed(snapshots_on)
    text = page(client)
    card = products_card(text)
    assert "badge-success\">Monitored" in row(card, "nginx")
    assert "badge-success\">Monitored" in row(card, "Lodash")
    assert "Needs review" in row(card, "WordPress")
    assert "not covered by CVE scans yet" not in text


def test_managed_rows_make_products_monitored_by_manual_id_purl_or_text(blank):
    config = blank[0]
    client = seed(blank)
    write_managed(config, [
        Asset("w-nginx-m", vendor="Other", product="Other", version="9", client="Acme"),
        Asset("unrelated", vendor="x", product="lodash", version="4.17.21",
              purl="pkg:npm/lodash@4.17.21", ecosystem="npm", client="Acme"),
        Asset("third", vendor="JQUERY", product="JQuery", version="2.0", client="Acme"),
    ])
    card = products_card(page(client))
    assert "badge-success\">Monitored" in row(card, "nginx")
    assert "badge-success\">Monitored" in row(card, "Lodash")
    assert "badge-success\">Monitored" in row(card, "jQuery")
    assert "Needs review" in row(card, "WordPress")
    assert page(client, inv="monitored").count("<strong>") >= 3
    # The notice only appears while nothing is monitored.
    assert "not covered by CVE scans yet" not in page(client)


def test_broad_coverage_uses_the_strongest_identity_and_the_observed_site():
    def widget_cpe(*, part="a", platform="*"):
        return f"cpe:2.3:{part}:example:widget:*:*:*:*:*:{platform}:*:*"

    broad = Asset("broad", vendor="Example", product="Widget", system_id="a.example",
                  cpe=widget_cpe(platform="linux"))
    for cpe in (widget_cpe(platform="windows"), widget_cpe(part="o")):
        item = dict(asset_id="w-widget", hostname="a.example", vendor="Example", product="Widget",
                    versions=["2.1"], cpe=cpe, in_inventory=True, category="framework",
                    confidence="high")
        assert actions.classify(item, snapshots_on=False, snapshot_ids=set(),
                                managed=actions.ManagedIndex([broad])) == ("ready", [])
    item = dict(asset_id="w-widget", hostname="a.example", vendor="Example", product="Widget",
                versions=["2.1"], cpe=widget_cpe(platform="linux"), in_inventory=True,
                category="framework", confidence="high")
    assert actions.classify(item, snapshots_on=False, snapshot_ids=set(),
                            managed=actions.ManagedIndex([broad])) == ("monitored", ["broad"])
    same_site = dict(item, hostname=broad.system_id)
    assert actions.classify(same_site, snapshots_on=False, snapshot_ids=set(),
                            managed=actions.ManagedIndex([broad])) == ("monitored", ["broad"])


def test_broad_package_coverage_keeps_the_purl_scope_and_qualifiers():
    row = Asset("scope-a", vendor="npm", product="core", version="1", ecosystem="npm",
                purl="pkg:npm/@scope-a/core@1", system_id="a.example")
    item = dict(asset_id="w-core", hostname="a.example", vendor="npm", product="core",
                package="@scope-b/core", ecosystem="npm", versions=["1"], in_inventory=True,
                category="js-library", confidence="high")
    assert actions.classify(item, snapshots_on=False, snapshot_ids=set(),
                            managed=actions.ManagedIndex([row])) == ("ready", [])
    qualified = replace(row, asset_id="qualified", product="core",
                        purl="pkg:npm/core@1?repository_url=https://example.invalid/repo")
    plain = dict(asset_id="w-core", hostname="a.example", vendor="npm", product="core",
                 ecosystem="npm", package="core", versions=["1"], in_inventory=True,
                 category="js-library", confidence="high")
    assert actions.classify(plain, snapshots_on=False, snapshot_ids=set(),
                            managed=actions.ManagedIndex([qualified])) == ("ready", [])


def test_broad_coverage_does_not_cross_sites():
    row = Asset("broad", vendor="Example", product="Widget", system_id="a.example")
    item = dict(asset_id="w-widget", hostname="b.example", vendor="Example", product="Widget",
                versions=["2.1"], in_inventory=True, category="framework", confidence="high")
    assert actions.classify(item, snapshots_on=False, snapshot_ids=set(),
                            managed=actions.ManagedIndex([row])) == ("ready", [])
    assert actions.classify(dict(item, hostname="a.example"), snapshots_on=False,
                            snapshot_ids=set(),
                            managed=actions.ManagedIndex([row])) == ("monitored", ["broad"])


def test_exact_coverage_wins_over_a_broad_row_at_the_same_site():
    rows = [
        Asset("broad", vendor="Example", product="Widget", system_id="a.example"),
        Asset("exact", vendor="Example", product="Widget", version="2.1", system_id="a.example"),
    ]
    item = dict(asset_id="w-widget", hostname="a.example", vendor="Example", product="Widget",
                versions=["2.1"], in_inventory=True, category="framework", confidence="high")
    assert actions.classify(item, snapshots_on=False, snapshot_ids=set(),
                            managed=actions.ManagedIndex(rows)) == ("monitored", ["exact"])
    assert actions.ManagedIndex(rows).covering(item) == ["exact", "broad"]


def test_a_broad_cpe_row_for_another_platform_leaves_the_detection_ready(blank):
    config = blank[0]
    write_managed(config, [Asset(
        "linux-widget", vendor="Example", product="Widget", system_id="a.example", client="Acme",
        cpe="cpe:2.3:a:example:widget:*:*:*:*:*:linux:*:*")])
    server = dict(asset_id="w-widget", hostname="a.example", vendor="Example", product="Widget",
                  name="Widget", category="framework", categories=["framework"],
                  confidence="high", versions=["2.1"], evidence_types=["header"],
                  inventory=True, cpe="cpe:2.3:a:example:widget:*:*:*:*:*:windows:*:*")
    client = seed(blank, [server])
    card = products_card(page(client))
    assert "Ready to add" in row(card, "Widget") and "Monitored" not in row(card, "Widget")
    added = preview(client, ["w-widget"])
    assert confirmation(added)["pick"] == ["w-widget"]


def test_older_review_files_without_inventory_flag_keep_working(blank):
    old = [{key: value for key, value in item.items() if key != "inventory"} for item in PRODUCTS]
    client = seed(blank, old)
    card = products_card(page(client))
    assert "Ready to add" in row(card, "nginx")
    assert "Needs review" in row(card, "WordPress")


def test_unreadable_managed_inventory_warns_and_page_still_renders(blank):
    config = blank[0]
    client = seed(blank)
    config.inventory_directory.mkdir(mode=0o700)
    (config.inventory_directory / f"{client_key('Acme')}.json").write_bytes(b"not json")
    text = page(client)
    assert "could not be read" in text
    assert "Ready to add" in products_card(text)


def test_inventory_status_filter_values(blank):
    config = blank[0]
    client = seed(blank)
    write_managed(config, [Asset("w-nginx-m", vendor="nginx", product="nginx", version="1.25.3", client="Acme")])
    names = lambda text: re.findall(r"<strong>([^<]+)</strong>", products_card(text).split("Entries", 1)[0])
    assert names(page(client, inv="monitored")) == ["nginx"]
    assert names(page(client, inv="ready")) == ["Lodash"]
    assert sorted(names(page(client, inv="review"))) == ["WordPress", "jQuery"]
    assert len(names(page(client, inv="in"))) == 4
    assert len(names(page(client, inv="bogus"))) == 4
    tech = page(client, view="tech", inv="ready")
    assert "Lodash" in tech and "Ready to add" in tech and "nginx<" not in tech


# Add flow --------------------------------------------------------------------

def test_first_add_on_a_blank_install_creates_inventory_profile_and_file(blank):
    config, users, _, _ = blank
    client = seed(blank)
    assert config.effective_inventory is None and not config.inventory_directory.exists()
    response = preview(client, ["w-nginx", "w-lodash"])
    assert response.status_code == 200, response.text
    assert "has no inventory yet" in response.text
    assert not config.inventory_directory.exists()  # a preview writes nothing
    assert "pkg:npm/lodash@4.17.21" in response.text and "1.25.3" in response.text
    saved = save_inventory(client, response)
    assert saved.status_code == 303, saved.text
    assert "added=2" in saved.location

    key = client_key("Acme")
    assert (config.inventory_directory / f"{key}.client").is_file()
    assert json.loads((config.inventory_directory / f"{key}.client").read_text(encoding="utf-8")) == {
        "name": "Acme", "notes": "", "contact": ""}
    rows = {asset.asset_id: asset for asset in managed_rows(config)}
    assert sorted(rows) == ["w-lodash-m", "w-nginx-m"]
    nginx, lodash = rows["w-nginx-m"], rows["w-lodash-m"]
    assert (nginx.vendor, nginx.product, nginx.version, nginx.category) == ("nginx", "nginx", "1.25.3", "web-server")
    assert nginx.system_id == "a.example" and nginx.client == "Acme" and nginx.purl == ""
    assert (lodash.product, lodash.ecosystem, lodash.purl, lodash.version) == (
        "lodash", "npm", "pkg:npm/lodash@4.17.21", "4.17.21")

    assert config.effective_inventory is not None
    assert {asset.asset_id for asset in load_inventory(config.effective_inventory)} == {"w-nginx-m", "w-lodash-m"}
    assert config.has_managed_dashboard
    detail = client.get(f"/watch/clients/{key}?name=Acme")
    assert detail.status_code == 200 and "<dd>2</dd>" in detail.text
    assert f"/watch/clients/{key}" in client.get("/watch/clients").text
    actions = [entry.action for entry in users.audit_entries()]
    assert any(action.startswith("inventory_saved:") and '"mode":"add"' in action.replace(" ", "")
               for action in actions)
    assert not users.verify_audit()

    followed = client.get(saved.location)
    assert "Added 2 products to Acme's inventory. The next scan checks them for CVEs." in followed.text
    card = products_card(followed.text)
    assert "badge-success\">Monitored" in row(card, "nginx")
    assert "badge-success\">Monitored" in row(card, "Lodash")


def test_add_all_ready_ignores_filters_and_skips_the_rest(blank):
    config = blank[0]
    client = seed(blank)
    response = preview(client, action="all", site="b.example", tech="zzz")
    assert sorted(confirmation(response)["pick"]) == ["w-lodash", "w-nginx"]
    assert save_inventory(client, response).status_code == 303
    assert sorted(asset.asset_id for asset in managed_rows(config)) == ["w-lodash-m", "w-nginx-m"]


def test_add_appends_to_an_existing_inventory_and_keeps_old_rows(blank):
    config = blank[0]
    client = seed(blank)
    old = Asset("keep-me", vendor="Example", product="Widget", version="1", client="Acme")
    write_managed(config, [old])
    response = preview(client, ["w-nginx"])
    assert "has no inventory yet" not in response.text
    assert save_inventory(client, response).status_code == 303
    assert sorted(asset.asset_id for asset in managed_rows(config)) == ["keep-me", "w-nginx-m"]
    again = preview(client, ["w-nginx"])
    assert "Already monitored" in again.text and "/web-assets/inventory/save" not in again.text


def test_review_rows_accept_a_typed_version_or_no_version(blank):
    config = blank[0]
    client = seed(blank)
    missing = preview(client, ["w-wp"])
    assert "No version" in missing.text
    assert confirmation(missing)["pick"] == ["w-wp"]
    assert not confirmation(missing)["v-w-wp"][0]
    assert save_inventory(client, missing).status_code == 303
    typed = preview(client, ["w-multi"], {"w-multi": "2.0"})
    fields = confirmation(typed)
    assert fields["v-w-multi"] == ["2.0"]
    assert save_inventory(client, typed).status_code == 303
    rows = {asset.asset_id: asset for asset in managed_rows(config)}
    assert rows["w-wp-m"].version == "" and rows["w-multi-m"].version == "2.0"
    for bad in ("x" * 101, "1.0\x07", "\t"):
        refused = preview(client, ["w-multi"], {"w-multi": bad})
        assert "/web-assets/inventory/save" not in refused.text and refused.status_code == 200
    page_text = page(client)
    assert "badge-success\">Monitored" in row(products_card(page_text), "WordPress")



def test_label_and_generic_versions_need_review_and_generic_rows_name_no_vendor(blank):
    config = blank[0]
    labelled = dict(asset_id="w-ga", hostname="a.example", vendor="google", product="google-analytics",
                    name="Google Analytics", category="hosted-platform", categories=["hosted-platform"],
                    confidence="high", versions=["GA4"], evidence_types=["script"], inventory=False)
    generic = dict(asset_id="w-swiper", hostname="a.example", vendor="banner", product="swiper",
                   name="Swiper", category="js-library", categories=["js-library"], confidence="low",
                   versions=["8.4.5"], evidence_types=["script"], inventory=False)
    labelled_service = dict(labelled, asset_id="w-ga-cms", name="Example Analytics CMS", category="cms",
                            categories=["cms"])
    client = seed(blank, [labelled, labelled_service, generic])
    card = products_card(page(client))
    for name, version in (("Example Analytics CMS", ""), ("Swiper", "8.4.5")):
        assert "Needs review" in row(card, name)
        assert f'value="{version}" placeholder="Enter version (optional)"' in row(card, name)
    service = row(card, "Google Analytics")
    assert "Third-party service" in service and 'name="v-w-ga"' not in service and "Enter version" not in service
    assert "Not covered by CVE scans yet" not in page(client)
    assert "Google Analytics" in products_card(page(client, inv="service"))
    assert "Swiper" not in products_card(page(client, inv="service"))
    everything = preview(client, action="all")
    assert "/web-assets/inventory/save" not in everything.text
    forged = preview(client, ["w-ga"], {"w-ga": "GA4"})
    assert "has no installed version to scan" in forged.text
    assert "/web-assets/inventory/save" not in forged.text
    typed = preview(client, ["w-swiper"], {"w-swiper": "8.4.5"})
    assert save_inventory(client, typed).status_code == 303
    (row_added,) = managed_rows(config)
    assert (row_added.vendor, row_added.product, row_added.version) == ("swiper", "swiper", "8.4.5")


def test_label_only_and_missing_versions_are_ready_when_a_snapshot_row_exists(blank):
    config = blank[0]
    products = [
        dict(asset_id="w-react", hostname="a.example", vendor="facebook", product="react",
             name="React", category="js-library", categories=["js-library"], confidence="high",
             versions=[], evidence_types=["html"], inventory=True, ecosystem="npm", package="react"),
        dict(asset_id="w-label", hostname="a.example", vendor="example", product="analytics-cms",
             name="Example Analytics CMS", category="cms", categories=["cms"], confidence="high",
             versions=["GA4"], evidence_types=["script"], inventory=True),
    ]
    client = seed(blank, products)
    card = products_card(page(client))
    for name in ("React", "Example Analytics CMS"):
        assert "Ready to add" in row(card, name) and "No version" in row(card, name)
    assert "Add all 2 ready products" in page(client, view="tech")
    added = preview(client, action="all")
    assert "2 products have no version" in added.text
    assert "No version: may be affected; confirm the version to be sure." in added.text
    fields = confirmation(added)
    assert sorted(fields["pick"]) == ["w-label", "w-react"]
    assert save_inventory(client, added).status_code == 303
    rows = {asset.asset_id: asset for asset in managed_rows(config)}
    assert rows["w-react-m"].version == "" and rows["w-react-m"].purl == "pkg:npm/react"
    assert rows["w-label-m"].version == ""
    record(config, "w-react-m", 7.5)
    card = products_card(page(client))
    react = row(card, "React")
    assert "Monitored" in react and "No version" in react and "1 CVE" in react
    download = client.get(f"/watch/clients/{client_key('Acme')}/download")
    assert download.status_code == 200
    downloaded = {asset["asset_id"]: asset for asset in json.loads(download.data)}
    assert downloaded["w-react-m"]["version"] == "" and downloaded["w-react-m"]["purl"] == "pkg:npm/react"


def test_a_cpe_product_is_added_without_a_version_and_keeps_its_cpe(blank):
    config = blank[0]
    server = dict(asset_id="w-srv", hostname="a.example", vendor="f5", product="nginx", name="Nginx",
                  category="web-server", categories=["web-server"], confidence="high", versions=[],
                  evidence_types=["header"], inventory=True, cpe="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")
    client = seed(blank, [server])
    assert "Ready to add" in row(products_card(page(client)), "Nginx")
    added = preview(client, ["w-srv"])
    assert save_inventory(client, added).status_code == 303
    (row_added,) = managed_rows(config)
    assert row_added.cpe == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*" and row_added.version == ""

def test_a_typed_version_is_preferred_for_a_ready_product_without_one(blank):
    config = blank[0]
    server = dict(asset_id="w-srv", hostname="a.example", vendor="f5", product="nginx", name="Nginx",
                  category="web-server", categories=["web-server"], confidence="high", versions=[],
                  evidence_types=["header"], inventory=True, cpe="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")
    client = seed(blank, [server])
    typed = preview(client, ["w-srv"], {"w-srv": " 1.25.3 "})
    assert confirmation(typed)["v-w-srv"] == ["1.25.3"]
    assert save_inventory(client, typed).status_code == 303
    (row_added,) = managed_rows(config)
    assert row_added.version == "1.25.3" and row_added.cpe == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


def test_npm_purl_and_version_agree_for_a_typed_version(blank):
    config = blank[0]
    products = [dict(PRODUCTS[1], asset_id="w-npm-none", versions=[], inventory=False)]
    client = seed(blank, products)
    assert save_inventory(client, preview(client, ["w-npm-none"], {"w-npm-none": "3.1.0"})).status_code == 303
    asset = managed_rows(config)[0]
    assert (asset.version, asset.purl) == ("3.1.0", "pkg:npm/lodash@3.1.0")


def test_typed_version_rejects_controls_before_stripping():
    assert actions.typed_version("") == "" and actions.typed_version("   ") == ""
    for value in ("\t", "\n", "\x7f"):
        with pytest.raises(actions.RowRefused, match="unsupported character"):
            actions.typed_version(value)


def test_rows_are_rebuilt_from_the_saved_review_not_the_form(blank):
    config = blank[0]
    client = seed(blank)
    response = preview(client, ["w-nginx", "no-such-id"], vendor="evil", product="evil",
                       category="evil", version="9.9.9", **{"v-w-nginx": "9.9.9"})
    assert "1 selected product was not found" in response.text
    assert "evil" not in response.text and "9.9.9" not in response.text
    forged = confirmation(response)
    forged.update(vendor=["evil"], product=["evil"], category=["evil"], version=["9.9.9"])
    assert client.post("/web-assets/inventory/save", data=forged).status_code == 303
    asset = managed_rows(config)[0]
    assert (asset.vendor, asset.version, asset.category) == ("nginx", "1.25.3", "web-server")


def test_more_than_2000_picks_are_refused_politely(blank):
    config = blank[0]
    client = seed(blank)
    response = preview(client, [f"id-{index}" for index in range(2001)])
    assert response.status_code == 400
    assert "Too many products were selected at once" in response.text
    assert not config.inventory_directory.exists()
    nothing = preview(client, [])
    assert nothing.status_code == 400 and "Select at least one product" in nothing.text


# Requests ----------------------------------------------------------------------

def test_permission_and_csrf_are_enforced(blank, tmp_path):
    config, _, app, client = blank
    seed(blank)
    token = csrf(client)
    assert client.post("/web-assets/inventory/preview", data={
        "client": "Acme", "action": "all"}).status_code == 400
    assert client.post("/web-assets/inventory/save", data={
        "csrf": "0" * 64, "client": "Acme", "action": "selected", "revision": "empty", "digest": "x"}).status_code == 400
    limited = app.test_client()
    login(limited, "webonly")
    text = limited.get("/web-assets?client=Acme").text
    assert 'name="pick"' not in text and "Add selected to inventory" not in text
    assert "You need permission to manage inventories" in text
    for endpoint in ("preview", "save"):
        assert limited.post(f"/web-assets/inventory/{endpoint}", data={
            "csrf": csrf(limited), "client": "Acme", "action": "all",
            "revision": "empty", "digest": "x"}).status_code == 403
    assert not config.inventory_directory.exists()
    assert token


def test_managed_inventories_turned_off_hides_and_refuses(tmp_path):
    for env in build(tmp_path):
        config, _, app, client = env
        seed(env)
        config.config_path.write_text(
            config.config_path.read_text(encoding="utf-8").replace(
                "[state]", "[inventory]\nmanaged = false\n\n[state]", 1), encoding="utf-8", newline="\n")
        off = create_app(load_config(config.config_path))
        browser = off.test_client()
        login(browser, "admin")
        text = browser.get("/web-assets?client=Acme").text
        assert "Managed inventories are turned off" in text
        assert "Add selected to inventory" not in text and 'name="action" value="all"' not in text
        assert browser.post("/web-assets/inventory/preview", data={
            "csrf": csrf(browser), "client": "Acme", "action": "all"}).status_code == 403
        off.extensions["dashboard_jobs"].shutdown()


def test_a_changed_inventory_between_preview_and_save_writes_nothing(blank):
    config = blank[0]
    client = seed(blank)
    response = preview(client, ["w-nginx"])
    write_managed(config, [Asset("late", vendor="Example", product="Widget", version="1", client="Acme")])
    before = (config.inventory_directory / f"{client_key('Acme')}.json").read_bytes()
    refused = save_inventory(client, response)
    assert refused.status_code == 409 and "Nothing was added" in refused.text
    assert (config.inventory_directory / f"{client_key('Acme')}.json").read_bytes() == before


def test_changed_detection_results_between_preview_and_save_write_nothing(blank):
    config = blank[0]
    client = seed(blank)
    response = preview(client, ["w-nginx"])
    seed_again = [dict(item, versions=["1.26.0"]) if item["asset_id"] == "w-nginx" else item for item in PRODUCTS]
    _, output = paths(config, "Acme")
    detail = {"client": "Acme", "products": seed_again, "reviews": []}
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    assert save_inventory(client, response).status_code == 409
    assert not config.inventory_directory.exists()


def test_a_busy_inventory_lock_is_refused_without_writing(blank):
    config = blank[0]
    client = seed(blank)
    response = preview(client, ["w-nginx"])
    lock = OperationLock(config, "client-inventory")
    assert lock.acquire()
    try:
        refused = save_inventory(client, response)
    finally:
        lock.release()
    assert refused.status_code == 409 and "in progress" in refused.text
    assert not config.inventory_directory.exists()
    assert save_inventory(client, response).status_code == 303


def test_turning_web_snapshots_on_later_causes_no_collision(tmp_path):
    for env in build(tmp_path):
        config, _, app, client = env
        seed(env)
        assert save_inventory(client, preview(client, ["w-nginx", "w-lodash"])).status_code == 303
    # Web snapshots on: the snapshot of the same detections uses the plain asset IDs.
    from test_web_inventory import snapshot
    text = config.config_path.read_text(encoding="utf-8")
    config.config_path.write_text("[inventory]\nweb_snapshots = true\n\n" + text, encoding="utf-8", newline="\n")
    reloaded = load_config(config.config_path)
    _, output = paths(reloaded, "Acme")
    snapshot(output.parent, name=output.stem)
    assets = load_inventory(reloaded.effective_inventory, snapshot_directory=output.parent)
    assert {"w-nginx-m", "w-lodash-m"} <= {asset.asset_id for asset in assets}


# Confidence ---------------------------------------------------------------------

def test_confidence_badges_read_high_is_good(blank):
    client = seed(blank)
    for view in ("site", "tech"):
        card = products_card(page(client, view=view))
        assert 'badge-conf-high">High' in card and 'badge-conf-medium">Medium' in card
        assert 'badge-conf-low">Low' in card
        assert not re.search(r'badge-(high|medium|low)">(High|Medium|Low)', card)
    css = (Path(dashboard_web.__file__).parent / "static" / "dashboard.css").read_text(encoding="utf-8")
    assert re.search(r"\.badge-conf-high\s*{[^}]*--success-", css)
    assert re.search(r"\.badge-conf-medium\s*{[^}]*--info-", css)
    assert re.search(r"\.badge-conf-low\s*{[^}]*--warning-", css)


# Known CVEs -----------------------------------------------------------------------

def record(config, asset_id, *scores):
    asset = Asset(asset_id, vendor="nginx", product="nginx", version="1.25.3", client="Acme")
    findings = tuple(
        Finding(asset, Vulnerability(f"CVE-2026-{1000 + index}", cvss_score=score), A.AFFECTED, "high",
                "reason", (Evidence("cve_list", "cna", "statement"),))
        for index, score in enumerate(scores))
    StateStore(config.database_path).record_scan([QueryResult(
        asset, findings, (SourceHealth("cve_list", H.OK, utc_now(), "ok"),), None, None)])


def test_known_cves_column_for_monitored_unmonitored_and_clear(blank):
    config = blank[0]
    client = seed(blank)
    assert save_inventory(client, preview(client, ["w-nginx", "w-lodash"])).status_code == 303
    record(config, "w-nginx-m", 9.8, 5.0)
    card = products_card(page(client))
    nginx = row(card, "nginx")
    assert 'badge-critical">Critical' in nginx and ">2 CVEs</a>" in nginx
    assert "asset=w-nginx-m" in nginx
    assert "No CVEs found yet" in row(card, "Lodash")
    assert "Not monitored" in row(card, "WordPress")
    tech = products_card(page(client, view="tech"))
    assert 'badge-critical">Critical' in row(tech, "nginx") and "2 CVEs" in row(tech, "nginx")
    assert "Not monitored" in row(tech, "WordPress")


def test_known_cves_aggregate_in_the_technology_view_and_one_finding_wording(snapshots_on):
    config = snapshots_on[0]
    save_snapshot(config, "s1", "s2")
    products = [dict(PRODUCTS[0], asset_id="s1"), dict(PRODUCTS[0], asset_id="s2", hostname="c.example")]
    client = seed(snapshots_on, products)
    record(config, "s1", 5.0)
    record(config, "s2", 7.5)
    tech = row(products_card(page(client, view="tech")), "nginx")
    assert 'badge-high">High' in tech and "2 CVEs" in tech
    sites = products_card(page(client))
    assert ">1 CVE</a>" in row(sites, "nginx")


def test_known_cves_uses_only_the_exact_row_when_broad_and_exact_rows_coexist(blank):
    config = blank[0]
    client = seed(blank)
    write_managed(config, [
        Asset("broad-nginx", vendor="nginx", product="nginx", system_id="a.example", client="Acme"),
        Asset("exact-nginx", vendor="nginx", product="nginx", version="1.25.3",
              system_id="a.example", client="Acme"),
    ])
    record(config, "broad-nginx", 9.8)
    record(config, "exact-nginx", 5.0)
    nginx = row(products_card(page(client)), "nginx")
    assert ">1 CVE</a>" in nginx and 'badge-medium">Medium' in nginx
    assert "Critical" not in nginx and "2 CVEs" not in nginx


def test_known_cves_lookup_failure_shows_unavailable_and_keeps_the_page(snapshots_on, monkeypatch):
    save_snapshot(snapshots_on[0], "w-nginx")
    client = seed(snapshots_on)
    from cvebeacon.errors import StateError

    def broken(self, asset_ids):
        raise StateError("boom")
    monkeypatch.setattr(StateStore, "finding_summary", broken)
    text = page(client)
    assert "Unavailable" in row(products_card(text), "nginx")


@pytest.mark.parametrize("has_snapshot", [False, True])
def test_review_prediction_does_not_provide_snapshot_status_or_known_cves(snapshots_on, has_snapshot):
    config = snapshots_on[0]
    if has_snapshot:
        save_snapshot(config, "w-lodash")
    client = seed(snapshots_on)
    record(config, "w-nginx", 9.8)
    card = products_card(page(client))
    nginx = row(card, "nginx")
    assert "Ready to add" in nginx and "Not monitored" in nginx
    assert "Critical" not in nginx and "1 CVE" not in nginx
    if has_snapshot:
        assert "badge-success\">Monitored" in row(card, "Lodash")


def test_finding_summary_is_chunked_and_read_only(tmp_path):
    store = StateStore(tmp_path / "state.db")
    assert store.finding_summary(["a"]) == {}
    assert not (tmp_path / "state.db").exists()
    asset = Asset("asset-1", vendor="v", product="p", version="1", client="Acme")
    store.record_scan([QueryResult(asset, (Finding(
        asset, Vulnerability("CVE-2026-1", cvss_score=7.0), A.AFFECTED, "high", "r",
        (Evidence("cve_list", "cna", "s"),)),), (SourceHealth("cve_list", H.OK, utc_now(), "ok"),), None, None)])
    ids = [f"other-{index}" for index in range(1200)] + ["asset-1"]
    assert store.finding_summary(ids) == {"asset-1": (1, 7.0)}


# Markup ----------------------------------------------------------------------------

def test_markup_has_no_inline_code_and_forms_are_not_nested(blank):
    client = seed(blank)
    preview_text = preview(client, ["w-nginx"]).text
    for text in (page(client), page(client, view="tech"), preview_text):
        assert not re.search(r"(?i)\sstyle\s*=", text)
        assert not re.search(r"(?is)<style\b", text)
        assert not re.search(r"(?is)<script\b(?![^>]*\bsrc=)[^>]*>", text)
        depth = 0
        for tag in re.findall(r"(?i)</?form\b", text):
            depth += -1 if tag.startswith("</") else 1
            assert depth in (0, 1)
    site = page(client)
    pick = site.index('name="pick"')
    assert site.rfind("<form", 0, pick) > site.rfind("</form>", 0, pick)
    assert 'action="/web-assets/inventory/preview"' in site
    assert 'name="pick"' not in page(client, view="tech")
    assert "Add all 2 ready products" in page(client, view="tech")
    assert "switch to By site" in page(client, view="tech")
    assert re.search(r'<label class="visually-hidden" for="ver-\d+">Version of WordPress', site)


def test_table_columns_take_widths_from_header_classes_not_positions(blank):
    client = seed(blank)
    css = (Path(dashboard_web.__file__).parent / "static" / "dashboard.css").read_text(encoding="utf-8")
    assert "web-products-table thead th:nth-child" not in css
    for view, table in (("site", "web-products-table"), ("tech", "web-tech-table")):
        text = page(client, view=view)
        head = text.split(f'class="{table}"', 1)[1].split("</thead>", 1)[0]
        for name in ("web-product-cell", "web-version-cell", "web-confidence-cell", "web-cve-cell",
                     "web-reported-cell", "web-evidence-cell"):
            assert f'<th class="{name}"' in head, (view, name)
            assert f".{table} thead th.{name} {{ width:" in css, (table, name)
