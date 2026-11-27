"""Inventory sync uses saved observations and publishes reversible client changes."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
import os
import re
import subprocess

import pytest

from cvebeacon import update_state, web_assets, web_inventory_sync as sync
from cvebeacon.config import WebConfig, load_config
from cvebeacon.errors import ConfigurationError
from cvebeacon.locking import OperationLock
from cvebeacon.managed_inventory import client_key, versions
from cvebeacon.models import Asset
from cvebeacon.web_inventory import WEB_SYNC_SCHEMA, read_bytes, web_asset_id

from test_dashboard_accounts import PASSWORD, csrf, login
from test_dashboard_config import confirm, preview
from test_dashboard_inventory import change
from test_dashboard_web import save
from test_web_assets_inventory import blank, managed_rows, page, save_inventory, snapshots_on, write_managed

HOST = "example.invalid"
BASE_SITE = ("https", HOST, 443, "/")
PATH_SITE = ("https", HOST, 443, "/about")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
SAMPLE_CPE = "cpe:2.3:o:sample:sample:*:*:*:*:*:*:*:*"
SCOPED_IDENTITY = ["\0".join(("product", "sample", "sample", "o", *("*",) * 7)), ""]


def product(name, version, *, npm=False, site=BASE_SITE, client="Acme", identity=None):
    identity = identity or [name, name]
    item = dict(asset_id=web_asset_id(client, *site, *identity),
                site_id=web_asset_id(client, *site), hostname=site[1], vendor=name,
                product=name, versions=[version], inventory=True, sync_identity=identity)
    if identity == SCOPED_IDENTITY:
        item["cpe"] = SAMPLE_CPE
    if npm:
        item.update(ecosystem="npm", package=name)
    return item


def row(name, version, *, client="Acme", site=BASE_SITE, npm=False, manual=True):
    identity = web_asset_id(client, *site, name, name)
    return Asset(identity + ("-m" if manual else ""), name, name, version, system_id=site[1],
                 ecosystem="npm" if npm else "", purl=f"pkg:npm/{name}@{version}" if npm else "",
                 client=client)


def run(config, number, products=(), *, sites=None, status="success", started=True, stopped=0,
        client="Acme", sync_schema=True, run_id=None):
    allowlist, output = web_assets.paths(config, client)
    _, revision = web_assets.read_allowlist(allowlist, client)
    sites = {BASE_SITE: True} if sites is None else sites
    date = (NOW + timedelta(hours=number)).isoformat()
    metadata = dict(started_at=date, ended_at=date, status=status, asset_count=len(sites),
                    fetched_count=sum(sites.values()) + stopped, products_recognized=len(products),
                    products_with_version=len(products), analysis_stopped=stopped,
                    review_truncated=False)
    if started:
        metadata["inventory_sync"] = {"id": run_id or f"{number:032x}",
                                      "previous": f"{number - 1:032x}" if number > 1 else "",
                                      "allowlist": revision,
                                      "sites": {web_asset_id(client, *site): [*site, complete]
                                                for site, complete in sites.items()}}
        if sync_schema:
            metadata["inventory_sync"]["schema"] = (WEB_SYNC_SCHEMA if sync_schema is True else sync_schema)
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
        def __init__(self, run_id):
            self.run_id = run_id

        def wait(self, *, timeout):
            run(config, 2, run_id=self.run_id)
            return 0

    lock = OperationLock(config, "web-detect")
    assert lock.acquire()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(web_assets.subprocess, "Popen",
                          lambda args, *, env, **kwargs: Child(env["CVEBEACON_WEB_RUN_ID"]))
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
    assert "until someone clicks <strong>Remove</strong>" in text
    assert 'name="action" value="remove">Remove</button>' in card(text)
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


def test_review_only_product_keeps_its_identity_without_becoming_a_row(blank):
    config, _, client = setup(blank, "auto")
    review_only = product("cdn", "", identity=["cdn", ""])
    review_only.update(product="", name="CDN library", versions=[], inventory=False)
    run(config, 1, [review_only, product("sample", "1")])
    text = page(client)
    assert "CDN library" in text and sync.RESULTS_WARNING not in text
    assert managed_rows(config) == [row("sample", "1")]


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


@pytest.mark.parametrize("schema", [False, 1])
def test_previous_producer_schema_cannot_authorize_absence(blank, schema):
    config, _, client = setup(blank)
    old = row("missing", "1")
    write_managed(config, [old])
    for number in (1, 2):
        run(config, number, sync_schema=schema)
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


@pytest.mark.parametrize("managed,write_fails", [(True, True), (True, False), (False, False)])
def test_detection_requires_start_marker_and_blocks_unchanged_review_on_timeout(blank, monkeypatch,
                                                                               managed, write_fails):
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
                web_assets.run_detection(replace(config, managed_inventory=managed), "Acme")
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


def test_upgrade_rollback_restores_keep_decisions(blank, monkeypatch, tmp_path_factory):
    config, _, client = setup(blank, "auto", auto_remove="on")
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    old = row("missing", "1")
    write_managed(config, [old])
    for number in (1, 2):
        run(config, number)
        page(client)
    item = product("missing", "1")
    assert post(client, "keep-removal", **selection(page(client), item)).status_code == 303
    clock[0] += timedelta(days=31)
    data = config.config_path.parent
    snapshot = tmp_path_factory.mktemp("sync-upgrade-snapshot")
    update_state.backup(config, data, snapshot)
    assert post(client, "reconsider", **selection(page(client), item)).status_code == 303
    page(client)
    assert not (config.inventory_directory / f"{client_key('Acme')}.json").exists()
    update_state.restore(config, data, snapshot)
    update_state.verify_restore(config, data, snapshot)
    assert managed_rows(config) == [old]
    for number in (3, 4):
        run(config, number)
        assert "Kept in inventory." in card(page(client))
        assert managed_rows(config) == [old]


def test_older_upgrade_manifest_preserves_live_sync_state(blank, tmp_path_factory):
    config, _, client = setup(blank)
    write_managed(config, [row("missing", "1")])
    data = config.config_path.parent
    snapshot = tmp_path_factory.mktemp("old-upgrade-snapshot")
    update_state.backup(config, data, snapshot)
    manifest_path = snapshot / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest.pop("managed_web_sync") is True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8", newline="\n")
    for number in (1, 2):
        run(config, number)
        page(client)
    item = product("missing", "1")
    assert post(client, "keep-removal", **selection(page(client), item)).status_code == 303
    saved = sync.state_path(config, "Acme")
    decision = read_bytes(saved)
    update_state.restore(config, data, snapshot)
    update_state.verify_restore(config, data, snapshot)
    assert read_bytes(saved) == decision


@pytest.mark.parametrize("limit", [
    "inline-imports", "chunk-map", "nested-budget", "external-resource", "cached-error",
    *[pytest.param(kind, marks=pytest.mark.skipif(os.name == "nt", reason="fingerprints are POSIX-only"))
      for kind in ("meta", "dom", "text")],
])
def test_omitted_producer_evidence_cannot_count_as_absence(blank, monkeypatch, limit):
    from cvebeacon_extensions import web, webfingerprints

    config, _, client = setup(blank, "auto", auto_remove="on")
    config = replace(config, web=WebConfig(removal_grace_days=0))
    cached = limit == "cached-error"
    if cached:
        assert save(client, path="/about").status_code == 303
    allowlist, output = web_assets.paths(config, "Acme")
    document, _ = web_assets.read_allowlist(allowlist, "Acme")
    for entry in document["assets"]:
        entry.update(hostname="example.com", allow_private_address=True, authorized_at="2026-01-01T00:00:00Z",
                     expires_at="2027-01-01T00:00:00Z")
    web_assets.save_allowlist(allowlist, document)

    fingerprints = None
    external = limit in {"meta", "dom", "text"}
    if external:
        fingerprints = web_assets.fingerprint_directory(config)
        directory = fingerprints / "technologies"
        directory.mkdir(parents=True)
        (fingerprints / "categories.json").write_text(
            '{"2": {"name": "JavaScript libraries"}}', encoding="utf-8", newline="\n")
        pattern = {
            "meta": {"meta": {"application-name": r"Demo ([0-9.]+)\;version:\1"}},
            "dom": {"dom": {"#example": {"text": r"Demo ([0-9.]+)\;version:\1"}}},
            "text": {"text": [r"Demo ([0-9.]+)\;version:\1"]},
        }
        rules = {"Demo": {"cats": [2], **pattern[limit]}}
        (directory / "d.json").write_text(json.dumps(rules), encoding="utf-8", newline="\n")

    style_import = b'@import "/framework.css";'
    empty_import = b'@import "/empty.css";'
    empty_imports = empty_import * web.RESOURCE_MAX_REFERENCES
    root = b'<style>' + style_import + b'</style>'
    if limit == "meta":
        root = b'<meta name="application-name" content="Demo 2.4.0">'
    elif limit == "dom":
        monkeypatch.setattr(webfingerprints, "MAX_DOM_NODES", 64)
        root = b'<span id="example">Demo 2.4.0</span>'
    elif limit == "text":
        monkeypatch.setattr(webfingerprints, "MAX_TEXT_LENGTH", 64)
        root = b'<span>Demo 2.4.0</span>'
    elif limit == "cached-error":
        root = b'<link rel="stylesheet" href="/framework.css">'
    elif limit == "chunk-map":
        root = b'<script type="module" src="/loader.js"></script>'
    elif limit == "nested-budget":
        root = b'<link rel="stylesheet" href="/nested.css">'

    loader = b'__vite__mapDeps=["/framework.css"];'
    prefix = b""
    if limit == "inline-imports":
        prefix = b'<style>' + empty_imports + style_import + b'</style>'
    elif limit == "nested-budget":
        prefix = root + b'<style>' + empty_import * (web.RESOURCE_MAX_REFERENCES - 1) + b'</style>'
    elif limit == "external-resource":
        prefix = b'<link rel="stylesheet" href="https://example.invalid/framework.css">'
    elif limit == "meta":
        prefix = b'<meta name="other" content="unrelated">' * webfingerprints.MAX_META_TAGS
    elif limit == "dom":
        prefix = b'<div></div>' * webfingerprints.MAX_DOM_NODES
    elif limit == "text":
        prefix = b'x' * webfingerprints.MAX_TEXT_LENGTH
    actual_page = root
    fail_resource = False
    detect_builtin = web._detect_builtin

    def builtin(page, **kwargs):
        if fail_resource and any(resource.url.endswith("/framework.css") for resource in page.resources):
            raise ValueError("test resource analysis failure")
        return detect_builtin(page, **kwargs)

    class Transport:
        def fetch(self, endpoint, address, **kwargs):
            if endpoint.path in {"/", "/about"}:
                return web._Response(200, {"server": ("nginx/1.25.3",),
                                           "referrer-policy": ("no-referrer",)}, actual_page)
            if endpoint.path == "/loader.js":
                return web._Response(200, {"content-type": ("application/javascript",)}, loader)
            styles = {"/framework.css": b"/*! Bootstrap v5.3.3 | https://getbootstrap.com/ */",
                      "/nested.css": style_import, "/empty.css": b""}
            if endpoint.path in styles:
                return web._Response(200, {"content-type": ("text/css",)}, styles[endpoint.path])
            return web._Response(404, {}, b"")

    class Resolver:
        def resolve(self, hostname, port):
            return ("203.0.113.10",)

    def observe():
        web.detect_web(allowlist, output, client="Acme", source_id="test-web",
                       resolver=Resolver(), transport=Transport(), fingerprints=fingerprints,
                       host_interval=0, max_workers=1, now=lambda: NOW + timedelta(days=1))
        detail = json.loads(read_bytes(output.with_name(output.name + ".review.json")))
        return detail["run"]["inventory_sync"]["sites"], detail["products"]

    monkeypatch.setattr(web, "_detect_builtin", builtin)
    sites, products = observe()
    assert all(site[-1] for site in sites.values())
    name = "Demo" if external else "bootstrap"
    detected = [item for item in products if item.get("name") == name or item["product"] == name]
    assert len(detected) == (2 if cached else 1)
    old = [Asset(item["asset_id"] + "-m", item["vendor"], item["product"], item["versions"][0],
                 system_id=item["hostname"], client="Acme") for item in detected]
    write_managed(config, old)
    sync.inspect(config, "Acme")
    if prefix:
        actual_page = prefix + (root if external else b"")
    if limit == "chunk-map":
        loader = b'__vite__mapDeps=[' + b'"/empty.css",' * web.RESOURCE_MAX_REFERENCES + b'"/framework.css"];'
    fail_resource = cached
    for _ in range(2):
        sites, products = observe()
        assert any(item["product"] == "nginx" for item in products)
        assert not {item["asset_id"] for item in detected} & {item["asset_id"] for item in products}
        current = sync.inspect(config, "Acme")
        assert all(asset in managed_rows(config) for asset in old)
        assert all(current.state["entries"][asset.asset_id[:-2]]["misses"] == 0 for asset in old)
        assert not any(site[-1] for site in sites.values())


@pytest.mark.parametrize("snapshot", ["missing", "invalid", "wrong-version", "valid"])
@pytest.mark.parametrize("detected_version", ["1", "2"])
def test_due_removal_rechecks_projected_snapshot_coverage(snapshots_on, monkeypatch, snapshot,
                                                          detected_version):
    from cvebeacon_extensions.contract import write_snapshot

    config, users, client = setup(snapshots_on, "auto", auto_remove="on")
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    assert save(client, path="/about").status_code == 303
    old = row("sample", "1")
    other = product("sample", detected_version, site=PATH_SITE)
    write_managed(config, [old])
    _, output = web_assets.paths(config, "Acme")

    def publish(version):
        write_snapshot(output, [{"asset_id": other["asset_id"], "vendor": "sample", "product": "sample",
                                 "version": version, "system_id": HOST, "client": "Acme"}],
                       source_id="test-web", collector="web-detect", observed_at=NOW.isoformat())

    publish(detected_version)
    for number in (1, 2):
        run(config, number, [other], sites={BASE_SITE: True, PATH_SITE: True})
        page(client)
    assert managed_rows(config) == [old]
    if snapshot == "missing":
        output.unlink()
    elif snapshot == "invalid":
        web_assets.replace_bytes(output, b"{}")
    elif snapshot == "wrong-version":
        publish("9")
    clock[0] += timedelta(days=30)
    count = len(users.audit_entries())
    for _ in range(2):
        text = page(client)
        assert (sync.COVERAGE_WARNING in text) == (snapshot != "valid")
        if snapshot == "valid":
            assert not (config.inventory_directory / f"{client_key('Acme')}.json").exists()
            assert len(users.audit_entries()) == count + 1
        else:
            assert managed_rows(config) == [old]
            assert len(users.audit_entries()) == count


@pytest.mark.parametrize("snapshot", ["matching", "missing", "wrong-scope"])
def test_due_removal_accepts_a_version_less_snapshot_row(snapshots_on, monkeypatch, snapshot):
    from cvebeacon_extensions.contract import write_snapshot

    config, users, client = setup(snapshots_on, "auto", auto_remove="on")
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    assert save(client, path="/about").status_code == 303
    old = row("sample", "1")
    other = product("sample", "", site=PATH_SITE, identity=SCOPED_IDENTITY)
    write_managed(config, [old])
    _, output = web_assets.paths(config, "Acme")
    if snapshot != "missing":
        cpe = SAMPLE_CPE if snapshot == "matching" else SAMPLE_CPE.replace(":o:", ":a:")
        write_snapshot(output, [asdict(Asset(
            other["asset_id"], "sample", "sample", "", system_id=HOST, cpe=cpe, client="Acme"))],
            source_id="test-web", collector="web-detect", observed_at=NOW.isoformat())
    for number in (1, 2):
        run(config, number, [other], sites={BASE_SITE: True, PATH_SITE: True})
        page(client)
    assert managed_rows(config) == [old]
    clock[0] += timedelta(days=30)
    count = len(users.audit_entries())
    text = page(client)
    if snapshot == "matching":
        assert sync.COVERAGE_WARNING not in text
        assert not (config.inventory_directory / f"{client_key('Acme')}.json").exists()
        assert len(users.audit_entries()) == count + 1
    else:
        assert sync.COVERAGE_WARNING in text
        assert managed_rows(config) == [old]
        assert len(users.audit_entries()) == count


def test_conflicting_scoped_product_identity_cannot_update_same_site_row(blank):
    config, _, client = setup(blank)
    item = product("sample", "1", identity=SCOPED_IDENTITY)
    old = replace(row("sample", "1"), asset_id=item["asset_id"] + "-m", cpe=SAMPLE_CPE)
    write_managed(config, [old])
    run(config, 1, [item])
    assert sync.RESULTS_WARNING not in page(client)
    run(config, 2, [dict(item, vendor="wrong", product="wrong", versions=["9"],
                         cpe=SAMPLE_CPE.replace(":sample:sample:", ":wrong:wrong:"))])
    text = page(client)
    assert sync.RESULTS_WARNING in text
    assert "Version changed ·" not in text
    assert managed_rows(config) == [old]


@pytest.mark.parametrize("source", ["managed", "snapshot"])
@pytest.mark.parametrize("conflict", ["cpe-part", "cpe-qualifier", "unstructured", "npm-package"])
def test_due_removal_requires_matching_product_identity(snapshots_on, monkeypatch, source, conflict):
    from cvebeacon_extensions.contract import write_snapshot

    config, users, client = setup(snapshots_on, "auto", auto_remove="on")
    clock = [NOW]
    monkeypatch.setattr(sync, "_now", lambda: clock[0])
    assert save(client, path="/about").status_code == 303
    original = product("sample", "1", identity=SCOPED_IDENTITY)
    old = replace(row("sample", "1"), asset_id=original["asset_id"] + "-m", cpe=SAMPLE_CPE)
    if conflict == "npm-package":
        detected = product("sample", "1", site=PATH_SITE, npm=True)
        detected["package"] = "@scope/sample"
        matching = replace(row("@scope/sample", "1", npm=True),
                           asset_id=detected["asset_id"], vendor="sample")
        replacement = replace(matching, product="sample", purl="pkg:npm/sample@1")
    else:
        detected = product("sample", "1", site=PATH_SITE, identity=SCOPED_IDENTITY)
        matching = replace(old, asset_id=detected["asset_id"],
                           cpe=SAMPLE_CPE.replace(":sample:sample:*:", ":sample:sample:1:"))
        replacement = replace(matching, cpe={
            "cpe-part": SAMPLE_CPE.replace(":o:", ":a:"),
            "cpe-qualifier": SAMPLE_CPE.replace(":o:sample:sample:*:*:", ":o:sample:sample:*:sp1:"),
            "unstructured": "",
        }[conflict])
    write_managed(config, [old])
    sites = {BASE_SITE: True, PATH_SITE: True}
    run(config, 1, [original], sites=sites)
    page(client)
    for number in (2, 3):
        run(config, number, [detected], sites=sites)
        text = page(client)
        assert ("Not detected since" in card(text)) == (number == 3)

    _, output = web_assets.paths(config, "Acme")

    def publish(candidate):
        if source == "managed":
            write_managed(config, [old, replace(candidate, asset_id="other")])
        else:
            write_snapshot(output, [asdict(candidate)], source_id="test-web",
                           collector="web-detect", observed_at=NOW.isoformat())

    publish(replacement)
    before = managed_rows(config)
    count = len(users.audit_entries())
    clock[0] += timedelta(days=30)
    assert sync.COVERAGE_WARNING in page(client)
    assert managed_rows(config) == before
    assert len(users.audit_entries()) == count

    publish(matching)
    assert sync.COVERAGE_WARNING not in page(client)
    assert len(users.audit_entries()) == count + 1
    if source == "managed":
        assert [asset.asset_id for asset in managed_rows(config)] == ["other"]
    else:
        assert not (config.inventory_directory / f"{client_key('Acme')}.json").exists()


def test_review_cannot_substitute_another_path_at_the_same_origin(blank):
    config, _, client = setup(blank, "auto", auto_remove="on")
    config = replace(config, web=WebConfig(removal_grace_days=0))
    old = row("sample", "1", site=PATH_SITE)
    write_managed(config, [old])
    allowlist, _ = web_assets.paths(config, "Acme")
    document, _ = web_assets.read_allowlist(allowlist, "Acme")
    entry = document["assets"][0]
    entry.pop("hostname")
    entry["url"] = "HTTPS://EXAMPLE.INVALID./"
    web_assets.save_allowlist(allowlist, document)
    run(config, 1)
    assert sync.RESULTS_WARNING not in page(client)
    for number in (2, 3):
        run(config, number, sites={PATH_SITE: True})
        assert sync.RESULTS_WARNING in page(client)
        with pytest.raises(ConfigurationError, match=re.escape(sync.RESULTS_WARNING)):
            sync.inspect(config, "Acme")
    assert managed_rows(config) == [old]


@pytest.mark.parametrize("unconfirmed_review", ["unchanged", "legacy", "different-id"])
def test_invalid_old_review_can_be_replaced_but_timeout_still_blocks_evidence(blank, monkeypatch,
                                                                             unconfirmed_review):
    config, _, client = setup(blank, "auto")
    _, output = web_assets.paths(config, "Acme")
    run(config, 1)
    page(client)
    web_assets.replace_bytes(output.with_name(output.name + ".review.json"), b'{"run":')
    item = product("sample", "1")
    launches = []

    class Child:
        def __init__(self, run_id, num):
            self.run_id = run_id
            self.num = num

        def wait(self, *, timeout):
            if timeout == web_assets.CHILD_STOP_GRACE:
                return -15
            if self.num != 3:
                run(config, self.num, [item], run_id=self.run_id)
            elif unconfirmed_review != "unchanged":
                # An older companion can succeed and publish a review without echoing this ID.
                run(config, self.num, [item], started=unconfirmed_review != "legacy")
            if self.num == 2:
                raise subprocess.TimeoutExpired("web detection", timeout)
            return 0

        def terminate(self):
            pass

    def launch(command, *, env, **kwargs):
        launches.append(env["CVEBEACON_WEB_RUN_ID"])
        return Child(launches[-1], len(launches) + 1)

    monkeypatch.setattr(web_assets.subprocess, "Popen", launch)
    lock = OperationLock(config, "web-detect")
    assert lock.acquire()
    try:
        with pytest.raises(ConfigurationError, match=re.escape(web_assets.RUN_TIMEOUT_REASON)):
            web_assets.run_detection(config, "Acme")
    finally:
        lock.release()
    assert sync.WAITING in page(client)
    assert not (config.inventory_directory / f"{client_key('Acme')}.json").exists()
    for _ in range(2):
        assert lock.acquire()
        try:
            assert web_assets.run_detection(config, "Acme") == 0
        finally:
            lock.release()
        if len(launches) == 2:
            assert sync.WAITING in page(client)
            assert not (config.inventory_directory / f"{client_key('Acme')}.json").exists()
    assert len(launches) == 3
    assert managed_rows(config) == [row("sample", "1")]


def test_successful_detection_can_retry_inventory_publication_on_get(blank, monkeypatch, caplog):
    config, users, client = setup(blank, "auto")
    item = product("sample", "1")
    published = sync._publish
    attempts = []

    def publish(*args, **kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            raise OSError("test inventory publication failure")
        return published(*args, **kwargs)

    class Child:
        def __init__(self, run_id):
            self.run_id = run_id

        def wait(self, *, timeout):
            run(config, 1, [item], run_id=self.run_id)
            return 0

    monkeypatch.setattr(sync, "_publish", publish)
    monkeypatch.setattr(web_assets.subprocess, "Popen",
                        lambda command, *, env, **kwargs: Child(env["CVEBEACON_WEB_RUN_ID"]))
    lock = OperationLock(config, "web-detect")
    assert lock.acquire()
    try:
        assert web_assets.run_detection(config, "Acme") == 0
    finally:
        lock.release()
    assert sync.WRITE_WARNING in caplog.text
    assert not (config.inventory_directory / f"{client_key('Acme')}.json").exists()
    assert attempts == [True]
    page(client)
    assert managed_rows(config) == [row("sample", "1")]
    audit(users, '"added":1', actor="system (inventory sync)")
    count = len(users.audit_entries())
    page(client)
    assert attempts == [True, True]
    assert len(users.audit_entries()) == count


def test_review_proposes_the_version_for_a_version_less_row(blank):
    config, _, client = setup(blank, "review")
    versionless = replace(row("sample", "2", npm=True), version="", purl="pkg:npm/sample")
    write_managed(config, [versionless])
    item = product("sample", "2", npm=True)
    run(config, 1, [item])
    text = page(client)
    assert "Version changed" in card(text)
    assert post(client, "update", **selection(text, item)).status_code == 303
    (updated,) = managed_rows(config)
    assert (updated.version, updated.purl) == ("2", "pkg:npm/sample@2")


def test_auto_applies_the_version_for_a_version_less_row(blank):
    config, _, client = setup(blank, "auto")
    versionless = replace(row("sample", "2", npm=True), version="", purl="pkg:npm/sample")
    write_managed(config, [versionless])
    item = product("sample", "2", npm=True)
    run(config, 1, [item])
    sync.inspect(config, "Acme")
    (updated,) = managed_rows(config)
    assert (updated.version, updated.purl) == ("2", "pkg:npm/sample@2")
    assert "1 updated" in card(page(client))


def test_review_updates_the_version_of_a_version_less_scoped_row(blank):
    config, _, client = setup(blank, "review")
    item = product("sample", "1", identity=SCOPED_IDENTITY)
    versionless = replace(row("sample", "1"), asset_id=item["asset_id"] + "-m",
                          version="", cpe=SAMPLE_CPE)
    write_managed(config, [versionless])
    run(config, 1, [item])
    text = page(client)
    assert "Version changed" in card(text)
    assert post(client, "update", **selection(text, item)).status_code == 303
    (updated,) = managed_rows(config)
    assert (updated.asset_id, updated.version, updated.cpe) == (
        item["asset_id"] + "-m", "1", SAMPLE_CPE)


def test_a_plain_row_covers_a_versioned_unqualified_application_cpe(blank):
    config, _, client = setup(blank, "review")
    write_managed(config, [Asset("existing-sample", "sample", "sample", "2.1",
                                 system_id=HOST, client="Acme")])
    item = dict(product("sample", "2.1"), inventory=True,
                cpe="cpe:2.3:a:sample:sample:*:*:*:*:*:*:*:*")
    run(config, 1, [item])
    assert "New · 1" not in card(page(client))


def test_a_version_less_row_for_another_identity_does_not_hide_a_detection(blank):
    config, _, client = setup(blank, "review")
    item = dict(product("sample", "1"), inventory=True)
    versionless = replace(row("sample", "1"), asset_id="other-platform", version="",
                          cpe="cpe:2.3:a:sample:sample:*:*:*:*:*:linux:*:*")
    write_managed(config, [versionless])
    run(config, 1, [item])
    assert "New · 1" in card(page(client))
