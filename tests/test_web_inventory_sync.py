"""Inventory sync uses saved observations and publishes reversible client changes."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import re
import subprocess

import pytest

from cvebeacon import web_assets, web_inventory_sync as sync
from cvebeacon.config import WebConfig, load_config
from cvebeacon.errors import ConfigurationError
from cvebeacon.locking import OperationLock
from cvebeacon.managed_inventory import client_key, versions
from cvebeacon.models import Asset
from cvebeacon.web_inventory import read_bytes, web_asset_id

from test_dashboard_accounts import PASSWORD, csrf, login
from test_dashboard_config import confirm, preview
from test_dashboard_inventory import change
from test_dashboard_web import save
from test_web_assets_inventory import blank, managed_rows, page, save_inventory, write_managed

HOST = "example.invalid"
BASE_SITE = ("https", HOST, 443, "/")
PATH_SITE = ("https", HOST, 443, "/about")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCOPED_IDENTITY = ["\0".join(("product", "sample", "sample", "o", *("*",) * 7)), ""]


def product(name, version, *, npm=False, site=BASE_SITE, client="Acme", identity=None):
    identity = identity or [name, name]
    item = dict(asset_id=web_asset_id(client, *site, *identity),
                site_id=web_asset_id(client, *site), hostname=site[1], vendor=name,
                product=name, versions=[version], inventory=True, sync_identity=identity)
    if npm:
        item.update(ecosystem="npm", package=name)
    return item


def row(name, version, *, client="Acme", site=BASE_SITE, npm=False, manual=True):
    identity = web_asset_id(client, *site, name, name)
    return Asset(identity + ("-m" if manual else ""), name, name, version, system_id=site[1],
                 ecosystem="npm" if npm else "", purl=f"pkg:npm/{name}@{version}" if npm else "",
                 client=client)


def run(config, number, products=(), *, sites=None, status="success", started=True, stopped=0,
        client="Acme", sync_schema=True):
    allowlist, output = web_assets.paths(config, client)
    _, revision = web_assets.read_allowlist(allowlist, client)
    sites = {BASE_SITE: True} if sites is None else sites
    date = (NOW + timedelta(hours=number)).isoformat()
    metadata = dict(started_at=date, ended_at=date, status=status, asset_count=len(sites),
                    fetched_count=sum(sites.values()) + stopped, products_recognized=len(products),
                    products_with_version=len(products), analysis_stopped=stopped,
                    review_truncated=False)
    if started:
        metadata["inventory_sync"] = {"id": f"{number:032x}",
                                      "previous": f"{number - 1:032x}" if number > 1 else "",
                                      "allowlist": revision,
                                      "sites": {web_asset_id(client, *site): [*site, complete]
                                                for site, complete in sites.items()}}
        if sync_schema:
            metadata["inventory_sync"]["schema"] = 1
    detail = {"client": client, "products": list(products), "reviews": [], "run": metadata}
    web_assets.replace_bytes(output.with_name(output.name + ".review.json"), json.dumps(detail).encode("utf-8"))


def card(text):
    return text.split("Changes since the last scan", 1)[1].split("Filter results", 1)[0]


def post(client, action, **fields):
    return client.post("/web-assets/inventory/sync", data={
        "csrf": csrf(client), "client": "Acme", "action": action, **fields,
    })


def setup(env, mode="review", *, auto_remove="default"):
    config, users, _, client = env
    assert save(client).status_code == 303
    assert post(client, "mode", mode=mode, auto_remove=auto_remove).status_code == 303
    return config, users, client


def selection(text, item):
    identity = item["asset_id"]
    found = re.search(fr'name="asset_id" value="{identity}"><input type="hidden" '
                      r'name="sync_token" value="([a-f0-9]{64})"', card(text))
    assert found, text
    return {"asset_id": identity, "sync_token": found[1]}


def audit(users, action, *, actor="admin"):
    assert any(entry.actor == actor and action in entry.action for entry in users.audit_entries())


def test_global_settings_are_validated(tmp_path):
    path = tmp_path / "config.toml"
    base = '[inventory]\nmanaged = true\n'
    path.write_text(base, encoding="utf-8", newline="\n")
    assert load_config(path).web.inventory_sync == "off"
    assert load_config(path).web.removal_grace_days == 30
    assert load_config(path).web.inventory_auto_remove is False
    for mode in ("off", "review", "auto"):
        path.write_text(base + f'[web]\ninventory_sync = "{mode}"\nremoval_grace_days = 0\n',
                        encoding="utf-8", newline="\n")
        assert load_config(path).web.inventory_sync == mode
        assert load_config(path).web.removal_grace_days == 0
    for field in ('inventory_sync = "unknown"', 'inventory_sync = true',
                  'removal_grace_days = true', 'removal_grace_days = -1',
                  'removal_grace_days = 366', 'removal_grace_days = 1.5'):
        path.write_text(base + "[web]\n" + field + "\n", encoding="utf-8", newline="\n")
        with pytest.raises(ConfigurationError, match=r"web\."):
            load_config(path)
    path.write_text(base + '[web]\ninventory_auto_remove = "true"\n', encoding="utf-8", newline="\n")
    with pytest.raises(ConfigurationError, match="inventory_auto_remove must be true or false"):
        load_config(path)


def test_inventory_settings_form_shows_sync_options(blank):
    response = blank[3].get("/config/inventory")
    assert response.status_code == 200
    assert 'name="g1_inventory_sync"' in response.text
    assert 'name="g1_removal_grace_days"' in response.text
    assert 'name="g1_inventory_auto_remove"' in response.text
    assert 'min="0"' in response.text and 'max="365"' in response.text
    reviewed = preview(blank[3], "inventory", g1_inventory_sync="review", g1_removal_grace_days="365",
                       g1_inventory_auto_remove="true")
    assert reviewed.status_code == 200, reviewed.text
    assert confirm(blank[3], reviewed, "inventory").status_code == 303
    assert load_config(blank[0].config_path).web == WebConfig("review", 365, True)


def test_global_sync_changes_require_inventory_management(blank):
    config, users, app, _ = blank
    proof = users.authenticate("admin", PASSWORD)
    users.save_role("settings-only", {"view", "edit_inventory"}, authorization=proof)
    users.add("settingsonly", password=PASSWORD, role="settings-only")
    client = app.test_client()
    login(client, "settingsonly")
    reviewed = preview(client, "inventory", g1_inventory_sync="auto", g1_inventory_auto_remove="true")
    assert reviewed.status_code == 200
    assert confirm(client, reviewed, "inventory").status_code == 403
    assert load_config(config.config_path).web == WebConfig()


def test_off_preserves_inventory_and_override_is_validated(blank):
    config, users, client = setup(blank, "off")
    old = row("older", "1")
    write_managed(config, [old])
    run(config, 1, [product("fresh", "2")])
    run(config, 2, [product("fresh", "2")])
    text = page(client)
    assert "Rescans flag missing products. Additions and version updates are manual." in text
    assert "New ·" not in card(text)
    assert managed_rows(config) == [old]
    assert post(client, "mode", mode="invalid").status_code == 409
    assert post(client, "mode", mode="auto", auto_remove="bad").status_code == 409
    assert post(client, "mode", mode="default").status_code == 303
    assert "(global default)" in page(client)
    assert not sync.mode_path(web_assets.paths(config, "Acme")[0]).exists()
    audit(users, "web_inventory_sync_mode:")


def test_review_add_update_remove_ignore_and_keep(blank):
    config, users, client = setup(blank)
    missing = product("missing", "1")
    newest, ignored = product("fresh", "3"), product("ignored", "4")
    changed, kept = product("changed", "2", npm=True), product("kept", "8")
    old = [row("missing", "1"), row("changed", "1", npm=True), row("kept", "7")]
    write_managed(config, old)
    observations = [newest, ignored, changed, kept]
    run(config, 1, observations)
    assert "Not detected since" not in card(page(client))
    run(config, 2, observations)
    text = page(client)
    assert "New · 3" in card(text) and "Version changed · 1 → 2" in card(text)
    assert "Not detected since" in card(text) and managed_rows(config) == old

    pick = selection(text, newest)
    proposed = client.post("/web-assets/inventory/preview", data={
        **pick, "pick": pick["asset_id"], "action": "sync-add", "client": "Acme", "csrf": csrf(client),
    })
    assert proposed.status_code == 200 and "To add (1)" in proposed.text
    assert save_inventory(client, proposed).status_code == 303
    for action, item in [("ignore", ignored), ("keep-version", kept), ("update", changed),
                         ("keep-removal", missing)]:
        assert post(client, action, **selection(page(client), item)).status_code == 303
    audit(users, '"mode":"web-sync-add"')
    audit(users, '"mode":"web-sync-update"')
    for action in ("ignore", "keep_version", "keep_removal"):
        audit(users, f"web_inventory_sync_{action}:")
    assert {asset.product: (asset.version, asset.purl) for asset in managed_rows(config)} == {
        "missing": ("1", ""), "changed": ("2", "pkg:npm/changed@2"),
        "kept": ("7", ""), "fresh": ("3", ""),
    }

    run(config, 3, observations)
    text = page(client)
    assert "Kept in inventory." in card(text) and "Undo keep" in card(text)
    assert ">ignored</th>" not in card(text) and ">kept</th>" not in card(text)
    assert post(client, "reconsider", **selection(text, missing)).status_code == 303
    assert post(client, "remove", **selection(page(client), missing)).status_code == 303
    assert "missing" not in {asset.product for asset in managed_rows(config)}
    audit(users, "web_inventory_sync_reconsider:")
    audit(users, '"mode":"web-sync-remove"')
    assert not users.verify_audit()

    run(config, 4, [newest, product("ignored", "5"), changed, product("kept", "9")])
    text = card(page(client))
    assert "New · 5" in text and "Version changed · 7 → 9" in text


def test_auto_applies_additions_and_versions_and_respects_grace_and_keep(blank, monkeypatch):
    config, users, client = setup(blank, "auto", auto_remove="on")
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    missing, kept = product("missing", "1"), product("kept", "1")
    write_managed(config, [row("missing", "1"), row("kept", "1"), row("changed", "1", npm=True)])
    detected = [product("fresh", "3"), product("changed", "2", npm=True)]
    run(config, 1, detected)
    first = card(page(client))
    assert "1 added · 1 updated · 0 removed." in first
    assert next(asset for asset in managed_rows(config) if asset.product == "changed").purl == "pkg:npm/changed@2"
    run(config, 2, detected)
    text = page(client)
    assert card(text).count("Pending removal from") == 2
    assert post(client, "keep-removal", **selection(text, kept)).status_code == 303
    clock[0] += timedelta(days=29)
    assert "Pending removal from" in card(page(client))
    assert {asset.product for asset in managed_rows(config)} >= {"missing", "kept"}
    clock[0] += timedelta(days=1)
    text = page(client)
    assert "0 added · 0 updated · 1 removed." in card(text)
    assert "Kept in inventory." in card(text)
    assert {asset.product for asset in managed_rows(config)} == {"kept", "fresh", "changed"}
    audit(users, '"mode":"web-sync-auto"', actor="system (inventory sync)")
    assert post(client, "reconsider", **selection(text, kept)).status_code == 303
    page(client)
    assert {asset.product for asset in managed_rows(config)} == {"fresh", "changed"}
    assert not users.verify_audit()


def test_version_update_keeps_an_exact_cpe_consistent(blank):
    config, _, client = setup(blank, "auto")
    cpe = "cpe:2.3:a:example:sample:1:*:*:*:*:*:*:*"
    write_managed(config, [replace(row("sample", "1"), cpe=cpe)])
    run(config, 1, [product("sample", "2")])
    page(client)
    (updated,) = managed_rows(config)
    assert updated.version == "2"
    assert updated.cpe == "cpe:2.3:a:example:sample:2:*:*:*:*:*:*:*"


def test_partial_failed_duplicate_and_returned_runs_break_the_miss_streak(blank):
    config, _, client = setup(blank)
    write_managed(config, [row("missing", "1", site=PATH_SITE)])
    assert save(client, path="/about").status_code == 303
    partial = {BASE_SITE: True, PATH_SITE: False}
    complete = {BASE_SITE: True, PATH_SITE: True}
    for number, flags in enumerate([complete, partial, complete, complete, complete, complete,
                                    {BASE_SITE: False, PATH_SITE: False}, complete], 1):
        items = [product("missing", "1", site=PATH_SITE)] if number == 5 else []
        run(config, number, items, sites=flags, status="failed" if number == 7 else "success",
            stopped=1 if number == 2 else 0)
        for _ in range(2):
            text = card(page(client))
            assert ("Not detected since" in text) == (number == 4)


def test_unfinished_result_keeps_a_flag_visible_but_cannot_remove(blank, monkeypatch):
    config, _, client = setup(blank, "auto", auto_remove="on")
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    old = row("missing", "1")
    write_managed(config, [old])
    for number in (1, 2):
        run(config, number)
        page(client)
    clock[0] += timedelta(days=31)
    run(config, 3, started=False)
    text = page(client)
    assert "Not detected since 2026-01-01" in card(text)
    assert managed_rows(config) == [old]
    missing = selection(text, product("missing", "1"))
    assert post(client, "remove", **missing).status_code == 409


def test_auto_zero_grace_publishes_on_detection_completion_and_restores(blank, monkeypatch):
    config, users, client = setup(blank, "auto")
    config = replace(config, web=WebConfig(removal_grace_days=0, inventory_auto_remove=True))
    gone = row("gone", "1")
    other = row("other", "1", client="Other")
    unsuffixed = row("unsuffixed", "1", manual=False)
    unrelated = Asset("custom-m", "example", "unrelated", "1", client="Acme")
    wrong_client = replace(row("foreign", "1", client="Other"), client="Acme")
    write_managed(config, [gone, unsuffixed, unrelated, wrong_client])
    write_managed(config, [other], "Other")
    run(config, 1)
    sync.inspect(config, "Acme")

    class Child:
        def wait(self, *, timeout):
            run(config, 2)
            return 0

    lock = OperationLock(config, "web-detect")
    assert lock.acquire()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(web_assets.subprocess, "Popen", lambda *args, **kwargs: Child())
            assert web_assets.run_detection(config, "Acme") == 0
    finally:
        lock.release()
    assert managed_rows(config) == [unsuffixed, unrelated, wrong_client]
    assert managed_rows(config, "Other") == [other]
    audit(users, '"removed":1', actor="system (inventory sync)")

    path = config.inventory_directory / f"{client_key('Acme')}.json"
    (archive,) = versions(path)
    url = f"/watch/clients/{path.stem}?name=Acme"
    response = change(client, url, "restore", version=archive.name.split(".")[1])
    assert response.status_code == 303, response.text
    page(client)
    assert gone in managed_rows(config)


def test_requests_fail_closed_on_csrf_permission_stale_or_corrupt_state(blank):
    config, _, client = setup(blank)
    item = product("fresh", "2")
    run(config, 1, [item])
    selected = selection(page(client), item)
    denied = client.post("/web-assets/inventory/sync", data={**selected, "client": "Acme", "action": "ignore"})
    assert denied.status_code == 400
    other = blank[2].test_client()
    login(other, "webonly")
    assert post(other, "ignore", **selected).status_code == 403
    assert post(other, "mode", mode="auto").status_code == 403
    run(config, 2, [item])
    assert post(client, "ignore", **selected).status_code == 409
    assert post(client, "mode", mode="auto").status_code == 303
    saved = sync.state_path(config, "Acme")
    web_assets.replace_bytes(saved, b"{")
    assert "No sync changes were made." in page(client)
    assert not (config.inventory_directory / f"{client_key('Acme')}.json").exists()
    assert read_bytes(saved) == b"{"


def test_auto_leaves_unreadable_inventory_untouched(blank):
    config, _, client = setup(blank, "auto", auto_remove="on")
    write_managed(config, [row("missing", "1")])
    path = config.inventory_directory / f"{client_key('Acme')}.json"
    web_assets.replace_bytes(path, b"{")
    run(config, 1, [product("fresh", "2")])
    assert "The saved inventory for this client could not be read." in page(client)
    assert read_bytes(path) == b"{"
    assert not versions(path)


@pytest.mark.parametrize("mode", ["off", "review", "auto"])
def test_missing_products_stay_scanned_by_default_and_manual_remove_works(blank, monkeypatch, mode):
    config, users, client = setup(blank, mode)
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    missing = row("missing", "1")
    returned = row("returned", "1")
    write_managed(config, [missing, returned])
    run(config, 1)
    assert "Not detected since" not in card(page(client))
    run(config, 2)
    assert card(page(client)).count("Not detected since 2026-01-01") == 2
    clock[0] += timedelta(days=365)
    text = page(client)
    assert "Automatic removal is off." in text
    assert "Pending removal from" not in card(text)
    assert managed_rows(config) == [missing, returned]
    assert post(client, "remove", **selection(text, product("missing", "1"))).status_code == 303
    audit(users, '"mode":"web-sync-remove"')
    run(config, 3, [product("returned", "1")])
    assert "Not detected since" not in card(page(client))
    assert managed_rows(config) == [returned]


@pytest.mark.parametrize("mode", ["off", "review"])
def test_automatic_removal_requires_auto_mode(blank, mode):
    config, _, client = setup(blank, mode, auto_remove="on")
    config = replace(config, web=WebConfig(removal_grace_days=0, inventory_auto_remove=True))
    old = row("missing", "1")
    write_managed(config, [old])
    run(config, 1)
    sync.inspect(config, "Acme")
    run(config, 2)
    sync.inspect(config, "Acme")
    assert managed_rows(config) == [old]
    assert "Not detected since" in card(page(client))


def test_keep_on_second_proposal_page_survives_deadline(blank, monkeypatch):
    config, _, client = setup(blank, "auto", auto_remove="on")
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    rows = [row(f"sample-{index:03}", "1") for index in range(501)]
    write_managed(config, rows)
    for number in (1, 2):
        run(config, number)
        first = page(client)
    last = product("sample-500", "1")
    assert "sync_page=2" in card(first) and last["asset_id"] not in card(first)
    second = page(client, sync_page=2)
    assert post(client, "keep-removal", **selection(second, last)).status_code == 303
    clock[0] += timedelta(days=30)
    page(client)
    assert managed_rows(config) == [rows[-1]]


@pytest.mark.parametrize("update,grace", [(False, 0), (False, 30), (True, 0)])
def test_auto_covers_detected_versions_after_selected_inventory_changes(blank, monkeypatch, update, grace):
    config, users, client = setup(blank, "auto", auto_remove="off" if update else "on")
    config = replace(config, web=WebConfig(removal_grace_days=grace))
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    assert save(client, path="/about").status_code == 303
    original = row("sample", "1")
    replacement = row("sample", "1", site=PATH_SITE)
    write_managed(config, [original])
    detected = [product("sample", "1", site=PATH_SITE)]
    if update:
        detected.insert(0, product("sample", "2"))
    for number in range(1, 2 if update else 3):
        run(config, number, detected if update or number == 2 else [],
            sites={BASE_SITE: True, PATH_SITE: True})
        sync.inspect(config, "Acme")
    if grace:
        assert managed_rows(config) == [original]
        clock[0] += timedelta(days=grace)
        page(client)
    expected = {replacement.asset_id: "1"}
    if update:
        expected[original.asset_id] = "2"
    assert {asset.asset_id: asset.version for asset in managed_rows(config)} == expected
    audit(users, '"added":1', actor="system (inventory sync)")
    journal_count = len(users.audit_entries())
    page(client)
    page(client)
    assert {asset.asset_id: asset.version for asset in managed_rows(config)} == expected
    assert len(users.audit_entries()) == journal_count


@pytest.mark.parametrize("status,headers,padding,body_complete", [
    (206, {}, b"<html>", True),
    (200, {"content-range": ("bytes 0-5/100",)}, b"<html>", True),
    (200, {"content-type": ("multipart/byteranges; boundary=range",)}, b"<html>", True),
    (200, {}, b"<html>", False),
    (200, {}, b'<meta name="generator" content="other">' * 4096, True),
])
def test_incomplete_producer_observations_do_not_count_as_misses(blank, status, headers, padding,
                                                               body_complete):
    from cvebeacon_extensions.web import _Response, detect_web

    config, _, _ = setup(blank, "auto", auto_remove="on")
    config = replace(config, web=WebConfig(removal_grace_days=0))
    allowlist, output = web_assets.paths(config, "Acme")
    document, _ = web_assets.read_allowlist(allowlist, "Acme")
    document["assets"][0].update(hostname="example.com", authorized_at="2026-01-01T00:00:00Z",
                                 expires_at="2027-01-01T00:00:00Z")
    web_assets.save_allowlist(allowlist, document)
    responses = {
        "/robots.txt": _Response(404, {}, b""),
        "/favicon.ico": _Response(404, {}, b""),
    }

    class Transport:
        def fetch(self, endpoint, address, **kwargs):
            return responses[endpoint.path]

    class Resolver:
        def resolve(self, hostname, port):
            return ("93.184.216.34",)

    def observe(body, code=200, fields=None, *, complete=True):
        responses["/"] = _Response(code, fields or {}, body, body_complete=complete)
        detect_web(allowlist, output, client="Acme", source_id="test-web",
                   resolver=Resolver(), transport=Transport(),
                   host_interval=0, max_workers=1, now=lambda: NOW + timedelta(days=1))
        return json.loads(read_bytes(output.with_name(output.name + ".review.json")))

    generator = b'<meta name="generator" content="WordPress 6.2">'
    first = observe(generator)
    (item,) = [item for item in first["products"] if item["product"] == "wordpress"]
    assert all(site[-1] for site in first["run"]["inventory_sync"]["sites"].values())
    old = Asset(item["asset_id"] + "-m", item["vendor"], item["product"], "6.2",
                system_id="example.com", client="Acme")
    write_managed(config, [old])
    sync.inspect(config, "Acme")
    for _ in range(2):
        detail = observe(padding + (generator if len(padding) > 6 else b""), status,
                         {"server": ("nginx/1.25.3",), **headers}, complete=body_complete)
        assert any(item["product"] == "nginx" for item in detail["products"])
        current = sync.inspect(config, "Acme")
        assert old in managed_rows(config)
        assert current.state["entries"][old.asset_id[:-2]]["misses"] == 0
        assert not any(site[-1] for site in detail["run"]["inventory_sync"]["sites"].values())


@pytest.mark.parametrize("inputs", [["sample", "sample"], SCOPED_IDENTITY])
def test_foreign_product_ids_cannot_drive_sync(blank, inputs):
    config, _, client = setup(blank)
    item = product("sample", "2", identity=inputs)
    foreign = web_asset_id("Other", *BASE_SITE, *inputs)
    imported = replace(row("sample", "1"), asset_id=foreign + "-m")
    write_managed(config, [imported])
    run(config, 1, [item])
    assert "New · 2" in card(page(client))
    run(config, 2, [{**item, "asset_id": foreign}])
    text = page(client)
    assert sync.RESULTS_WARNING in text
    assert "Version changed ·" not in text
    assert managed_rows(config) == [imported]


def test_scoped_product_association_cannot_move_to_another_endpoint(blank):
    config, _, client = setup(blank, "auto", auto_remove="on")
    config = replace(config, web=WebConfig(removal_grace_days=0))
    assert save(client, path="/about").status_code == 303
    item = product("sample", "1", identity=SCOPED_IDENTITY)
    sites = {BASE_SITE: True, PATH_SITE: True}
    old = replace(row("sample", "1"), asset_id=item["asset_id"] + "-m")
    write_managed(config, [old])
    run(config, 1, [item], sites=sites)
    current = sync.inspect(config, "Acme")
    current.state["entries"][item["asset_id"]]["site"] = web_asset_id("Acme", *PATH_SITE)
    web_assets.replace_bytes(sync.state_path(config, "Acme"), sync._encoded(current.state))
    for number in (2, 3):
        run(config, number, sites=sites)
        current = sync.inspect(config, "Acme")
        assert current.state["entries"][item["asset_id"]]["misses"] == 0
        assert old in managed_rows(config)


def test_previous_producer_schema_cannot_authorize_absence(blank):
    config, _, client = setup(blank)
    old = row("missing", "1")
    write_managed(config, [old])
    for number in (1, 2):
        run(config, number, sync_schema=False)
        assert "Not detected since" not in card(page(client))
    assert managed_rows(config) == [old]


def test_unrepresentable_flag_deadline_warns_without_changing_inventory(blank):
    config, _, client = setup(blank, "auto", auto_remove="on")
    old = row("missing", "1")
    write_managed(config, [old])
    run(config, 1)
    current = sync.inspect(config, "Acme")
    current.state["entries"][old.asset_id[:-2]]["since"] = "9999-12-31T00:00:00Z"
    web_assets.replace_bytes(sync.state_path(config, "Acme"), sync._encoded(current.state))
    assert sync.STATE_WARNING in page(client)
    assert managed_rows(config) == [old]


@pytest.mark.parametrize("write_fails", [True, False])
def test_detection_requires_start_marker_and_blocks_unchanged_review_on_timeout(blank, monkeypatch, write_fails):
    config, _, client = setup(blank, "auto", auto_remove="on")
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    old = row("missing", "1")
    write_managed(config, [old])
    for number in (1, 2):
        run(config, number)
        page(client)
    started = []

    class Child:
        def wait(self, *, timeout):
            if timeout != web_assets.CHILD_STOP_GRACE:
                raise subprocess.TimeoutExpired("web detection", timeout)
            return -15

        def terminate(self):
            pass

    def launch(*args, **kwargs):
        started.append(True)
        return Child()

    def refuse(*args, **kwargs):
        raise OSError("test marker write failure")

    monkeypatch.setattr(web_assets.subprocess, "Popen", launch)
    lock = OperationLock(config, "web-detect")
    assert lock.acquire()
    try:
        if write_fails:
            with monkeypatch.context() as patch:
                patch.setattr(web_assets, "replace_bytes", refuse)
                with pytest.raises(ConfigurationError, match="could not finish"):
                    web_assets.run_detection(config, "Acme")
            assert not started
        else:
            with pytest.raises(ConfigurationError, match=re.escape(web_assets.RUN_TIMEOUT_REASON)):
                web_assets.run_detection(config, "Acme")
            assert started == [True]
    finally:
        lock.release()
    if not write_fails:
        clock[0] += timedelta(days=30)
        assert "Not detected since" in card(page(client))
        assert managed_rows(config) == [old]


def test_idle_get_displays_flags_while_scan_holds_lock(blank):
    config, _, client = setup(blank, "off")
    old = row("missing", "1")
    write_managed(config, [old])
    for number in (1, 2):
        run(config, number)
        page(client)
    lock = OperationLock(config, "web-detect")
    assert lock.acquire()
    try:
        text = page(client)
        assert "Not detected since" in card(text)
        assert "A scan or inventory change is in progress" not in text
    finally:
        lock.release()


def test_legacy_allowlists_have_independent_state_and_migrate_to_the_embedded_owner(blank):
    config, _, client = setup(blank, "off")
    legacy_label = "Ａcme"
    assert client_key(legacy_label) == client_key("Acme")
    assert web_assets.client_key(legacy_label) != web_assets.client_key("Acme")
    allowlist, _ = web_assets.paths(config, "Acme")
    document, _ = web_assets.read_allowlist(allowlist, "Acme")
    legacy_allowlist, _ = web_assets.paths(config, legacy_label)
    web_assets.save_allowlist(legacy_allowlist, {**document, "client": legacy_label})
    run(config, 1, client=legacy_label)
    state = sync._empty_state(legacy_label)
    state["run"] = f"{1:032x}"
    old_path = config.inventory_directory / f"{client_key(legacy_label)}.web-sync"
    old_path.parent.mkdir(mode=0o700, exist_ok=True)
    web_assets.replace_bytes(old_path, sync._encoded(state))
    for number, label in [(1, "Acme"), (2, legacy_label), (2, "Acme"), (3, legacy_label)]:
        run(config, number, client=label)
        response = client.get("/web-assets", query_string={"client": label})
        assert response.status_code == 200 and sync.STATE_WARNING not in response.text
    assert sync.state_path(config, "Acme") != sync.state_path(config, legacy_label)
    assert not old_path.exists()
    for label, number in [("Acme", 2), (legacy_label, 3)]:
        stored = json.loads(read_bytes(sync.state_path(config, label)))
        assert stored["client"] == web_assets.client_key(label)
        assert stored["run"] == f"{number:032x}"
