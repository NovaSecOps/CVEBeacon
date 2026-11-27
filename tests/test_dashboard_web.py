"""Authorisation, private persistence and companion job boundaries for web assets."""

from dataclasses import replace
from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest

from cvebeacon import dashboard, dashboard_web, web_assets
from cvebeacon.dashboard_jobs import build_command
from cvebeacon.errors import ConfigurationError
from cvebeacon.locking import OperationLock, RunInProgress, operation_lock_paths
from cvebeacon.models import Asset, QueryResult
from cvebeacon.state import StateStore
from cvebeacon.web_assets import client_key, paths, read_allowlist, save_allowlist, validate_allowlist
from cvebeacon.watch.permissions import PERMISSIONS
from test_dashboard import setup
from test_dashboard_accounts import accounts, login, csrf, PASSWORD
from test_dashboard_config import preview, confirm
from test_web_inventory import snapshot


@pytest.fixture
def web(accounts):
    pytest.importorskip("cvebeacon_extensions")
    config, users, app, client = accounts
    config.config_path.chmod(0o644)
    login(client, "admin")
    yield config, users, app, client
    app.extensions["dashboard_jobs"].shutdown()


def save(client, *, action="add", **values):
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200, page.text
    version = re.search(r'name="version" value="([^"]+)"', page.text)
    return client.post("/web-assets/save", data={
        "csrf": csrf(client), "version": version[1] if version else "new",
        "client": "Acme", "action": action, "hostname": "example.invalid", "scheme": "https",
        "port": "443", "path": "/", "max_redirects": "2", "allow_redirects": "yes", "attest": "yes",
        **values,
    })


def grant(users, permissions):
    proof = users.authenticate("admin", PASSWORD)
    users.save_role("web-editor", permissions, authorization=proof)
    users.edit_user("reader", role="web-editor", disabled=False, authorization=proof)


def test_crud_attestation_and_audit(web):
    config, users, _, client = web
    before = datetime.now(timezone.utc)
    response = save(client, authorized_by="forged", authorized_at="2000-01-01T00:00:00Z")
    assert response.status_code == 303, response.text
    path, _ = paths(config, "Acme")
    document, _ = read_allowlist(path, "Acme")
    entry = document["assets"][0]
    assert entry["authorized_by"] == "admin"
    assert datetime.fromisoformat(entry["authorized_at"]) >= before
    assert save(client, action="change", index="0", path="/about").status_code == 303
    assert read_allowlist(path, "Acme")[0]["assets"][0]["path"] == "/about"
    assert save(client, action="remove", index="0").status_code == 303
    assert read_allowlist(path, "Acme")[0]["assets"] == []
    entries = users.audit_entries()
    for action in ("web_asset_add", "web_asset_change", "web_asset_remove"):
        entry = next(item for item in entries if item.action.startswith(action + ":"))
        assert entry.actor == "admin" and "example.invalid" in entry.action and "Acme" in entry.action
    assert not users.verify_audit()
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


def test_fresh_attestation_and_stale_form_are_refused(web):
    config, _, _, client = web
    assert save(client, attest="").status_code == 400
    path, _ = paths(config, "Acme")
    assert not path.exists()
    assert save(client).status_code == 303
    before = path.read_bytes()
    assert save(client, action="change", index="0", attest="").status_code == 400
    assert save(client, version="new").status_code == 400
    assert path.read_bytes() == before


@pytest.mark.parametrize("permissions,can_view,can_edit,can_run", [
    ({"view"}, True, False, False), ({"view", "run"}, True, False, True),
    ({"view", "manage_web_assets"}, True, True, False), (set(), False, False, False),
])
def test_permissions(web, permissions, can_view, can_edit, can_run, monkeypatch):
    _, users, app, client = web
    assert "manage_web_assets" in PERMISSIONS
    assert save(client).status_code == 303
    grant(users, permissions)
    login(client)
    assert client.get("/web-assets?client=Acme").status_code == (200 if can_view else 403)
    token = csrf(client)
    response = client.post("/web-assets/save", data={"csrf": token, "client": "Acme", "action": "add"})
    assert response.status_code == (400 if can_edit else 403)
    manager = app.extensions["dashboard_jobs"]
    monkeypatch.setattr(manager, "start_thread", lambda: None)
    response = client.post("/web-assets/run", data={"csrf": token, "client": "Acme", "action": "web-plan"})
    assert response.status_code == (303 if can_run else 403)


def test_csrf_shared_mode_and_unknown_actions(web, setup):
    config, _, _, client = web
    assert client.post("/web-assets/save", data={"client": "Acme"}).status_code == 400
    assert client.post("/web-assets/run", data={"client": "Acme"}).status_code == 400
    assert save(client, action="invalid").status_code == 400
    assert client.post("/web-assets/run", data={"csrf": csrf(client), "client": "Acme", "action": "scan --flag"}).status_code == 400
    shared = dashboard.create_app(replace(config, watch=replace(config.watch, database=config.watch.database.parent / "other" / "watch.db"))).test_client()
    assert shared.get("/web-assets?client=Acme").status_code == 200
    with shared.session_transaction() as session:
        token = session["csrf"]
    assert shared.post("/web-assets/save", data={"csrf": token, "client": "Acme"}).status_code == 403


@pytest.mark.parametrize("changes", [
    {"hostname": "https://bad.invalid"}, {"port": "0"}, {"path": "/?secret=1"},
    {"scheme": "ftp"}, {"max_redirects": "11"}, {"expires_at": "2000-01-01T00:00:00Z"},
])
def test_forms_use_the_companion_validator(web, changes):
    config, _, _, client = web
    assert save(client, **changes).status_code == 400
    assert not paths(config, "Acme")[0].exists()


def test_validator_parity_with_td1_and_plan_only(web, monkeypatch):
    web_module = pytest.importorskip("cvebeacon_extensions.web")
    contract = pytest.importorskip("cvebeacon_extensions.contract")
    load_allowlist, ExtensionError = web_module.load_allowlist, contract.ExtensionError
    config, _, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    base, _ = read_allowlist(path, "Acme")
    for change in ({"authorized_by": ""}, {"expires_at": "yesterday"}, {"allow_private_address": "true"},
                   {"max_redirects": 11}, {"hostname": "bad/host"}, {"path": "/bad#fragment"}, {"unexpected": 1}):
        document = json.loads(json.dumps(base))
        document["assets"][0].update(change)
        temporary = web_assets.temporary_json(path.parent, document)
        try:
            with pytest.raises(ExtensionError):
                load_allowlist(temporary, client="Acme")
            with pytest.raises(ConfigurationError):
                validate_allowlist(config, path, document)
        finally:
            temporary.unlink()
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, b"planned", b"")
    monkeypatch.setattr(web_assets.subprocess, "run", run)
    validate_allowlist(config, path, base)
    argv, kwargs = calls[0]
    assert argv[-1] == "--plan" and "--allow-partial" in argv
    assert kwargs["stdin"] == subprocess.DEVNULL and kwargs["timeout"] == 30
    assert not list(path.parent.glob(".web-assets-*.tmp"))


def test_form_offers_ten_redirects_with_updated_help(web):
    config, _, _, client = web
    assert save(client, max_redirects="10").status_code == 303
    page = client.get("/web-assets?client=Acme")
    assert 'name="max_redirects" type="number" min="0" max="10"' in page.text
    assert "0 to 10. Each redirect must stay on a listed host and port." in page.text


def test_fixed_jobs_and_missing_companion(web, monkeypatch):
    config, _, app, client = web
    assert save(client).status_code == 303
    manager = app.extensions["dashboard_jobs"]
    monkeypatch.setattr(manager, "start_thread", lambda: None)
    for action in ("web-plan", "web-detect"):
        command = build_command(config, action, client="Acme")
        expected_tail = ["web-detect", "Acme", "--plan"] if action == "web-plan" else ["web-detect", "Acme"]
        assert command[-len(expected_tail):] == expected_tail
        response = client.post("/web-assets/run", data={"csrf": csrf(client), "client": "Acme", "action": action, "flags": "--insecure"})
        assert response.status_code == 303
        job = manager.store.recent(1)[0]
        assert list(job.argv) == command and job.operation == action
    monkeypatch.setattr(web_assets, "companion_available", lambda: False)
    page = client.get("/web-assets?client=Acme")
    assert "optional Extensions package" in page.text and "disabled" in page.text
    assert client.post("/web-assets/run", data={"csrf": csrf(client), "client": "Acme", "action": "web-detect"}).status_code == 400
    assert save(client).status_code == 400
    with pytest.raises(ConfigurationError, match="optional Extensions"):
        build_command(config, "web-plan", client="Acme")


def test_scan_lock_blocks_jobs_and_edits(web, monkeypatch):
    config, _, app, client = web
    assert save(client).status_code == 303
    manager = app.extensions["dashboard_jobs"]
    monkeypatch.setattr(manager, "start_thread", lambda: None)
    lock = OperationLock(config, "scan")
    assert lock.acquire()
    try:
        assert operation_lock_paths(config, "web-detect") == operation_lock_paths(config, "scan")
        for operation in ("web-plan", "web-detect"):
            job = manager.submit(operation, started_by="admin", argv=build_command(config, operation, client="Acme"))
            assert manager.store.get(job.id).status == "queued"
            response = client.post("/web-assets/run", data={"csrf": csrf(client), "client": "Acme", "action": operation})
            assert response.status_code == 303
        assert save(client).status_code == 409
    finally:
        lock.release()


def test_detection_companion_argument_list(web, monkeypatch):
    config, _, _, client = web
    assert save(client).status_code == 303
    asset_path, output = paths(config, "Acme")
    calls = []
    child = MagicMock()
    child.wait.return_value = 0
    monkeypatch.setenv("CVEBEACON_WEB_RUN_ID", "parent-value")
    monkeypatch.setattr(web_assets.subprocess, "Popen",
                        lambda argv, **kwargs: calls.append((argv, kwargs)) or child)
    assert web_assets.run_detection(config, "Acme") == 0
    assert calls[0][0] == [sys.executable, "-I", "-u", "-m", "cvebeacon_extensions", "web", "detect",
                           "--client", "Acme", "--assets", str(asset_path), "--output", str(output),
                           "--source-id", "web-" + client_key("Acme"), "--allow-partial"]
    assert re.fullmatch(r"[a-f0-9]{32}", calls[0][1]["env"]["CVEBEACON_WEB_RUN_ID"])
    assert os.environ["CVEBEACON_WEB_RUN_ID"] == "parent-value"
    web_assets.run_detection(config, "Acme", plan=True)
    assert calls[-1][0][-1] == "--plan"
    assert "CVEBEACON_WEB_RUN_ID" not in calls[-1][1]["env"]


def test_private_atomic_storage_does_not_follow_links(web, monkeypatch):
    config, _, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    before = path.read_bytes()
    original_replace = web_assets.os.replace
    def fail_asset_replace(source, destination):
        if Path(destination) == path:
            raise OSError("failure")
        return original_replace(source, destination)
    monkeypatch.setattr(web_assets.os, "replace", fail_asset_replace)
    assert save(client, action="change", index="0", path="/updated").status_code == 400
    assert path.read_bytes() == before and not list(path.parent.glob(".web-assets-*.tmp"))
    monkeypatch.undo()
    if os.name == "posix":
        outside = path.parent / "outside"
        path.rename(outside)
        path.symlink_to(outside)
        assert save(client).status_code == 400
        assert outside.read_bytes() == before


def test_results_render_only_metadata(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    generated = snapshot(output.parent, name=output.stem, partial=True)
    assert generated == output
    secret = "PRIVATE_RESPONSE_BODY_OR_COOKIE"
    saved_time = "2026-11-05T12:00:00+00:00"
    save_allowlist(Path(str(output) + ".review.json"), {
        "client": "Acme", "body": secret, "cookies": secret,
        "run": dict(started_at="2026-11-05T12:00:00Z", ended_at="2026-11-05T12:00:01Z",
                    status="partial", request_count=2, duration_seconds=1.0, body=secret,
                    asset_count=2, fetched_count=1, products_recognized=1,
                    products_with_version=1, saved_snapshot_generated_at=saved_time,
                    snapshot_updated=False),
        "products": [dict(hostname="example.invalid", vendor="nginx", product="nginx", versions=["1.26.2"],
                          evidence_types=["header"], category="server", confidence="high", body=secret)],
        "reviews": [dict(asset_id="web-acme", reason=reason, detail="fixed safe detail", body=secret) for reason in
                    ("unreachable", "blocked", "version-unknown", "version-conflict")],
    })
    response = client.get("/web-assets?client=Acme")
    assert response.status_code == 200, response.text
    for value in ("1.26.2", "nginx", "header", "Fetched 1 of 2 authorised sites",
                  "1 product recognised", "1 product had a disclosed version", "requests: 2",
                  "duration: 1.0", "Conflicting versions", "version-conflict"):
        assert value in response.text
    assert secret not in response.text
    assert "Include saved web snapshots in scans" in response.text
    assert "Inventory settings" in response.text


def test_review_file_accepts_the_analytics_category(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem, partial=True)
    save_allowlist(Path(str(output) + ".review.json"), {
        "client": "Acme",
        "run": dict(started_at="2026-11-05T12:00:00Z", ended_at="2026-11-05T12:00:01Z",
                    status="partial", request_count=1, duration_seconds=1.0,
                    asset_count=1, fetched_count=1, products_recognized=1,
                    products_with_version=0, saved_snapshot_generated_at="2026-11-05T12:00:00+00:00",
                    snapshot_updated=False),
        "products": [dict(hostname="example.invalid", vendor="google", product="google-analytics",
                          name="Google Analytics", versions=["GA4"], evidence_types=["url"],
                          category="analytics", categories=["analytics"], confidence="high")],
        "reviews": [],
    })
    response = client.get("/web-assets?client=Acme")
    assert response.status_code == 200, response.text
    assert "Google Analytics" in response.text and "GA4" in response.text


@pytest.mark.parametrize(("run_status", "asset_count", "fetched_count", "recognized", "versioned",
                          "saved_time", "outcome", "saved_word"), [
    ("failed", 1, 0, 0, 0, "2026-11-05T12:00:00+00:00", "Could not fetch any of 1 authorised site", "earlier run"),
    ("partial", 2, 1, 1, 1, "2026-11-25T11:00:00+00:00", "Fetched 1 of 2 authorised sites", "this run"),
    ("no-usable-versions", 1, 1, 3, 0, "2026-11-05T12:00:00+00:00", "Fetched all 1 authorised site", "earlier run"),
    ("success", 1, 1, 1, 1, "2026-11-25T11:00:00+00:00", "Fetched all 1 authorised site", "this run"),
])
def test_latest_detection_card_describes_fetch_products_and_saved_snapshot(
        web, run_status, asset_count, fetched_count, recognized, versioned, saved_time, outcome, saved_word):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    reviews = [{"asset_id": "web-acme", "reason": "version-unknown", "product": "nginx/"}]
    products = [dict(asset_id="web-nginx", hostname="example.invalid", vendor="nginx", product="nginx",
                     versions=["1.26.2"] if versioned else [], evidence_types=["header"],
                     category="server", confidence="high") for _ in range(recognized)]
    save_allowlist(Path(str(output) + ".review.json"), {
        "client": "Acme", "products": products, "reviews": reviews,
        "run": dict(started_at="2026-11-25T10:59:00Z", ended_at="2026-11-25T11:00:00Z",
                    status=run_status, request_count=2, duration_seconds=1.0,
                    asset_count=asset_count, fetched_count=fetched_count,
                    products_recognized=recognized, products_with_version=versioned,
                    saved_snapshot_generated_at=saved_time,
                    snapshot_updated=(saved_word == "this run")),
    })
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200
    assert outcome in page.text
    assert f"{recognized} product{'s' if recognized != 1 else ''} recognised" in page.text
    assert f"{versioned} product{'s' if versioned != 1 else ''} had a disclosed version" in page.text
    assert f"Saved results are from an {saved_word}" in page.text if saved_word == "earlier run" else f"Saved results are from {saved_word}" in page.text
    assert "2026-11-25" in page.text


def test_reason_labels_and_hidden_version_hint(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    reasons = ("version-unknown", "redirect-blocked", "unreachable", "tls-error", "blocked",
               "timeout", "too-large", "unsupported-encoding", "no-technologies", "version-conflict")
    save_allowlist(Path(str(output) + ".review.json"), {
        "client": "Acme", "products": [],
        "reviews": [dict(asset_id=f"web-{index}", reason=reason, detail="fixed safe detail")
                    for index, reason in enumerate(reasons)],
    })
    page = client.get("/web-assets?client=Acme")
    for label in ("Version not disclosed", "Too many redirects or redirect not allowed",
                  "Could not reach site", "TLS certificate or handshake problem", "Request blocked",
                  "Request timed out", "Page too large", "Unsupported response encoding",
                  "No products recognised", "Conflicting versions"):
        assert label in page.text
    for reason in reasons:
        assert f'<span class="muted">{reason}</span>' in page.text
    assert "Many sites hide version numbers. Products without a version are marked Needs review. Enter the version yourself to add one to the inventory." in page.text


def test_redirect_detail_prefills_add_site_form_without_saving(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    detail = "redirect target is not an allowlisted host and port"
    target = {"scheme": "https", "host": "www.example.invalid", "port": 443}
    save_allowlist(Path(str(output) + ".review.json"), {
        "client": "Acme", "products": [], "reviews": [dict(
            asset_id="web-example", reason="redirect-blocked", detail=detail,
            redirect_target=target)],
    })
    page = client.get("/web-assets?client=Acme")
    assert detail in page.text
    assert "This site redirects to https://www.example.invalid:443, which is not on the authorised list. If the client authorises it, add it as a site." in page.text
    match = re.search(r'<a[^>]+href="([^"]+)"[^>]*>Add this redirect target as an authorised site</a>', page.text)
    assert match
    href = html.unescape(match[1])
    query = parse_qs(urlsplit(href).query)
    assert query["prefill_url"] == ["https://www.example.invalid:443/"]
    form = client.get(href)
    assert form.status_code == 200
    assert 'id="add-asset" open' in form.text
    assert 'name="hostname" value="www.example.invalid"' in form.text
    assert 'name="scheme"' in form.text
    assert 'name="port"' in form.text and 'value="443"' in form.text
    assert 'name="attest" type="checkbox" value="yes" required' in form.text
    allowlist, _ = paths(config, "Acme")
    assert len(read_allowlist(allowlist, "Acme")[0]["assets"]) == 1


def test_inventory_client_picker_canonicalizes_case_variant_and_links_web_assets(web):
    config, _, _, client = web
    StateStore(config.database_path).record_scan([QueryResult(
        Asset("inventory-asset", vendor="Example", product="Widget", version="1", client="Acme Corp"), (), ())])
    page = client.get("/web-assets?client=acme%20corp")
    assert page.status_code == 200
    assert '<option value="Acme Corp">' in page.text
    version = re.search(r'name="version" value="([^"]+)"', page.text)[1]
    response = client.post("/web-assets/save", data={
        "csrf": csrf(client), "version": version, "client": "acme corp", "action": "add",
        "hostname": "example.invalid", "scheme": "https", "port": "443", "path": "/",
        "max_redirects": "2", "allow_redirects": "yes", "attest": "yes",
    })
    assert response.status_code == 303
    allowlist, _ = paths(config, "Acme Corp")
    document, _ = read_allowlist(allowlist, "Acme Corp")
    assert document["client"] == "Acme Corp"
    assert len(document["assets"]) == 1
    detail = client.get(f"/watch/clients/{client_key('Acme Corp')}?name=Acme%20Corp")
    assert detail.status_code == 200
    assert 'class="btn btn-secondary btn-small"' in detail.text
    assert "Web assets" in detail.text and "1 authorised site" in detail.text


def test_inventory_detail_has_compact_web_assets_link_and_site_count(web):
    config, _, _, client = web
    StateStore(config.database_path).record_scan([QueryResult(
        Asset("inventory-asset", vendor="Example", product="Widget", version="1", client="Acme"), (), ())])
    assert save(client).status_code == 303
    detail = client.get(f"/watch/clients/{client_key('Acme')}?name=Acme")
    assert detail.status_code == 200
    assert 'class="btn btn-secondary btn-small"' in detail.text
    assert 'href="/web-assets?client=Acme"' in detail.text
    assert "Web assets · 1 authorised site" in detail.text


def test_nonadmin_can_enable_snapshot_boolean(web):
    config, users, _, client = web
    grant(users, {"view", "edit_inventory"})
    login(client)
    page = client.get("/config/inventory")
    assert 'name="g0_web_snapshots"' in page.text
    response = preview(client, "inventory", g0_web_snapshots="true")
    assert confirm(client, response, "inventory").status_code == 303
    from cvebeacon.config import load_config
    assert load_config(config.config_path).inventory.web_snapshots


def test_expired_allowlist_can_be_cleared_without_target_access(web):
    config, users, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    document, _ = read_allowlist(path, "Acme")
    first = document["assets"][0]
    first.update(authorized_at="2000-01-01T00:00:00Z", expires_at="2001-01-01T00:00:00Z")
    document["assets"].append({**first, "hostname": "second.invalid"})
    save_allowlist(path, document)
    response = save(client, action="remove-all", confirm="yes")
    assert response.status_code == 303, response.text
    assert read_allowlist(path, "Acme")[0]["assets"] == []
    removals = [item.action for item in users.audit_entries() if item.action.startswith("web_asset_remove:")]
    assert any("example.invalid" in item for item in removals)
    assert any("second.invalid" in item for item in removals)


def test_missing_companion_notice_and_refusal_without_extensions(accounts, monkeypatch):
    config, _, app, client = accounts
    monkeypatch.setattr(web_assets, "companion_available", lambda: False)
    login(client, "admin")
    path, _ = paths(config, "Acme")
    save_allowlist(path, {"client": "Acme", "assets": [{"hostname": "example.invalid"}]})
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200 and "optional Extensions package" in page.text and "disabled" in page.text
    for action in ("web-plan", "web-detect"):
        response = client.post("/web-assets/run", data={"csrf": csrf(client), "client": "Acme", "action": action})
        assert response.status_code == 400 and "optional Extensions package" in response.text
    app.extensions["dashboard_jobs"].shutdown()


def test_missing_companion_disables_per_site_remove(accounts, monkeypatch):
    config, _, app, client = accounts
    monkeypatch.setattr(web_assets, "companion_available", lambda: False)
    login(client, "admin")
    path, _ = paths(config, "Acme")
    save_allowlist(path, {"client": "Acme", "assets": [{"hostname": "example.invalid"}]})
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200
    remove = re.search(r"<button[^>]*>Remove this site</button>", page.text)
    assert remove is not None and "disabled" in remove.group(0)
    app.extensions["dashboard_jobs"].shutdown()


@pytest.mark.parametrize("client_name", ["--help", "--plan"])
def test_client_labels_are_values_never_companion_flags(accounts, client_name):
    from cvebeacon.cli import _parser
    parser = pytest.importorskip("cvebeacon_extensions.cli").parser
    config = accounts[0]
    for action in ("web-plan", "web-detect"):
        command = build_command(config, action, client=client_name)
        arguments = command[command.index("--config"):]
        parsed = _parser().parse_args(arguments)
        assert parsed.client == client_name and parsed.plan == (action == "web-plan")
        assets, output = paths(config, client_name)
        companion = web_assets.companion_command(client_name, assets, output, plan=parsed.plan)
        parsed_companion = parser().parse_args(companion[companion.index("web"):])
        assert parsed_companion.client == client_name and parsed_companion.plan == parsed.plan


@pytest.mark.parametrize("revocation", ["permission", "disabled", "password", "admin"])
def test_save_rechecks_account_after_validation(web, monkeypatch, revocation):
    from cvebeacon import dashboard_web
    config, users, _, client = web
    assert save(client).status_code == 303
    proof = users.authenticate("admin", PASSWORD)
    if revocation == "admin":
        users.add("second-admin", password=PASSWORD, is_admin=True, authorization=proof)
        users.save_role("web-editor", {"view", "manage_web_assets"}, authorization=proof)
    else:
        grant(users, {"view", "manage_web_assets"})
        login(client)
    path, _ = paths(config, "Acme")
    before = path.read_bytes()
    validate = dashboard_web.validate_allowlist
    def revoke(*args):
        validate(*args)
        if revocation == "permission":
            users.save_role("web-editor", {"view"}, authorization=proof)
        elif revocation == "disabled":
            users.edit_user("reader", role="web-editor", disabled=True, authorization=proof)
        elif revocation == "password":
            users.set_password("reader", PASSWORD + " changed", authorization=proof)
        else:
            users.edit_user("admin", role="web-editor", disabled=False,
                            authorization=users.authenticate("second-admin", PASSWORD))
    monkeypatch.setattr(dashboard_web, "validate_allowlist", revoke)
    # Removing an old CA path exercises the administrator-only commit check.
    if revocation == "admin":
        document, _ = read_allowlist(path, "Acme")
        document["ca_bundle"] = "old-ca.pem"
        save_allowlist(path, document)
        before = path.read_bytes()
    response = save(client, action="change", index="0", hostname="changed.invalid")
    assert response.status_code == 400
    assert path.read_bytes() == before
    assert not any('changed.invalid' in entry.action for entry in users.audit_entries())


@pytest.mark.skipif(os.name != "posix", reason="POSIX shared parent permissions")
def test_shared_state_parent_keeps_web_subdirectories_private(web):
    config, _, _, client = web
    config.database_path.parent.chmod(0o755)
    page = client.get("/web-assets?client=Acme")
    assert 'name="hostname"' in page.text
    assert save(client).status_code == 303
    assert config.database_path.parent.stat().st_mode & 0o777 == 0o755
    for directory in web_assets.directories(config):
        assert directory.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("url,scheme,port,path_value", [
    ("https://example.invalid/app", "https", 443, "/app"),
    ("http://example.invalid:8080/a%20b", "http", 8080, "/a%20b"),
])
def test_url_entries_display_and_save_equivalent_target(web, url, scheme, port, path_value):
    config, _, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    document, _ = read_allowlist(path, "Acme")
    entry = document["assets"][0]
    for key in ("hostname", "scheme", "port", "path"):
        entry.pop(key)
    entry["url"] = url
    save_allowlist(path, document)
    page = client.get("/web-assets?client=Acme")
    assert f'example.invalid · {scheme}:{port}{path_value}' in page.text
    form = page.text.split('<summary>Change this site</summary>', 1)[1].split('</form>', 1)[0]
    # Submit the actual rendered controls, so a wrong default cannot pass unnoticed.
    fields = dict(re.findall(r'name="([^"]+)"[^>]*value="([^"]*)"', form))
    fields["scheme"] = re.search(r'<option selected>([^<]+)</option>', form)[1]
    fields.update(attest="yes", max_redirects="2")
    response = client.post("/web-assets/save", data=fields)
    assert response.status_code == 303, response.text
    updated = read_allowlist(path, "Acme")[0]["assets"][0]
    assert "url" not in updated
    assert (updated["hostname"], updated["scheme"], updated["port"], updated["path"]) == (
        "example.invalid", scheme, port, path_value)


@pytest.mark.parametrize("route,action", [("save", "add"), ("run", "web-detect")])
def test_invalid_client_labels_return_bad_request(web, route, action):
    client = web[3]
    response = client.post("/web-assets/" + route,
                           data={"csrf": csrf(client), "client": "x" * 200, "action": action})
    assert response.status_code == 400


@pytest.mark.parametrize("malformed", [False, True])
def test_remove_all_recovers_malformed_url_and_retires_results(web, malformed):
    config, users, _, client = web
    assert save(client).status_code == 303
    path, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    document, _ = read_allowlist(path, "Acme")
    if malformed:
        document["assets"].append({"url": "http://[::1"})
    save_allowlist(path, document)
    assert save(client, action="remove-all", confirm="yes").status_code == 303
    assert read_allowlist(path, "Acme")[0]["assets"] == []
    assert not any(path.exists() for path in (output, Path(str(output) + ".manifest.json"),
                                               Path(str(output) + ".review.json")))
    assert any(entry.action.startswith("web_snapshot_remove:") for entry in users.audit_entries())
    assert not users.verify_audit()


def test_single_removal_warns_until_next_detection(web, monkeypatch):
    config, _, _, client = web
    assert save(client).status_code == 303
    assert save(client, hostname="second.invalid").status_code == 303
    _, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    assert save(client, action="remove", index="0").status_code == 303
    warning = "Results include assets removed since the last run"
    assert warning in client.get("/web-assets?client=Acme").text
    child = MagicMock()
    wait = child.wait
    wait.side_effect = [0, 2, 0]
    monkeypatch.setattr(web_assets.subprocess, "Popen", lambda *a, **k: child)
    assert web_assets.run_detection(config, "Acme", plan=True) == 0
    assert warning in client.get("/web-assets?client=Acme").text
    before = output.read_bytes()
    assert web_assets.run_detection(config, "Acme") == 2
    assert output.read_bytes() == before
    assert warning in client.get("/web-assets?client=Acme").text
    assert web_assets.run_detection(config, "Acme") == 0
    assert warning not in client.get("/web-assets?client=Acme").text


@pytest.mark.parametrize("section,field,value", [
    ("products", "versions", None), ("products", "evidence_types", None),
    ("reviews", "versions", None), ("products", "hostname", {"body": "SECRET_BODY"}),
    ("run", "request_count", ["SECRET_BODY"]),
    ("products", "hostname", "\ud800"), ("reviews", "versions", ["\udfff"]),
    ("run", "status", "\ud800"),
])
def test_corrupt_review_fields_are_rejected_before_rendering(web, section, field, value):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    detail = {"client": "Acme", "products": [], "reviews": []}
    detail[section] = {field: value} if section == "run" else [{field: value}]
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200
    assert "review the local files" in page.text
    assert "SECRET_BODY" not in page.text


@pytest.mark.parametrize("section,field,value", [
    ("products", "name", {"body": "not text"}),
    ("products", "ecosystem", 7),
    ("products", "package", None),
    ("products", "implied_by", "Angular"),
    ("products", "implied_by", ["Angular", 7]),
    ("products", "categories", "framework"),
    ("products", "categories", ["framework", 7]),
    ("products", "categories", ["unknown-category"]),
    ("products", "categories", ["application"] * 65),
    ("products", "categories", ["x" * 8193]),
    ("products", "name", ""),
    ("products", "name", "x" * 257),
    ("products", "package", "react"),
    ("products", "ecosystem", "npm"),
    ("products", "package", "../react"),
    ("products", "package", "@../react"),
    ("products", "evidence", "not a list"),
    ("products", "evidence", [{"kind": 7, "source": "page", "excerpt": "x"}]),
    ("products", "evidence", [{"kind": "unknown", "source": "page", "excerpt": "x"}]),
    ("products", "evidence", [{"kind": "script", "source": "page", "excerpt": "x" * 161}]),
    ("products", "evidence", [{"kind": "script", "source": "page", "excerpt": "x", "sha256": "bad"}]),
    ("products", "evidence", [{"kind": "script", "source": "page", "excerpt": "x", "sha256": "a" * 64}]),
    ("products", "evidence", [{"kind": "script", "source": "page", "excerpt": "x", "bytes": 512}]),
    ("products", "evidence", [{"kind": "script", "source": "page", "excerpt": "x", "bytes": True}]),
    ("products", "evidence", [{"kind": "script", "source": "page", "excerpt": "x", "bytes": -1}]),
    ("products", "evidence", [{"kind": "script", "source": "page", "excerpt": "x"}] * 21),
    ("run", "resources_fetched", -1),
    ("run", "resources_skipped", True),
    ("run", "resources_skipped_by_reason", {"blocked": 1}),
])
def test_new_review_fields_are_validated_before_rendering(web, section, field, value):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    detail = {"client": "Acme", "products": [], "reviews": []}
    detail[section] = {field: value} if section == "run" else [{field: value}]
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200
    assert "review the local files" in page.text


def test_skip_reason_counts_must_sum_to_total(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    detail = {
        "client": "Acme", "products": [], "reviews": [],
        "run": {"resources_skipped": 2, "resources_skipped_by_reason": {"blocked": 1}},
    }
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200
    assert "review the local files" in page.text


def test_detected_product_table_groups_sorts_and_uses_product_tags(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    detail = {
        "client": "Acme",
        "products": [
            {"hostname": "b.example", "vendor": "npm", "product": "package", "name": "Package",
             "category": "js-library", "confidence": "high", "versions": ["1.2.3"],
             "evidence_types": ["style"]},
            {"hostname": "a.example", "vendor": "angular", "product": "angular", "name": "React",
             "category": "framework", "confidence": "high", "versions": [],
             "evidence_types": ["header", "cookie", "html", "url", "script"],
             "ecosystem": "npm", "package": "react", "implied_by": ["Next.js"],
             "evidence": [{"kind": "script", "source": "https://assets.example.invalid/react.js",
                           "excerpt": "/*! @license React v18.2.0 */", "sha256": "a" * 64,
                           "bytes": 512}]},
            {"hostname": "a.example", "vendor": "angular", "product": "angular", "name": "Angular",
             "category": "framework", "confidence": "low", "versions": [],
             "evidence_types": ["implied"], "implied_by": ["TypeScript"]},
            {"hostname": "a.example", "vendor": "lodash", "product": "lodash",
             "category": "js-library", "confidence": "medium", "versions": ["4.17.21"],
             "categories": ["js-library", "web-server", "reverse-proxy"],
             "evidence_types": ["url"]},
        ],
        "reviews": [{"reason": "version-unknown"}],
        "run": {"status": "success", "resources_fetched": 4, "resources_skipped": 2},
    }
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200
    table = (
        page.text.split("Detected products", 1)[1].split("Entries to review", 1)[0]
    )
    assert table.index("a.example") < table.index("b.example")
    assert table.index("Angular") < table.index("React") < table.index("lodash")
    assert '<span class="badge badge-conf-high">High</span>' in table
    assert '<span class="badge badge-conf-medium">Medium</span>' in table
    assert '<span class="badge badge-conf-low">Low</span>' in table
    assert '<span class="badge badge-info web-version-badge">4.17.21</span>' in table
    assert '<span class="muted">Version not disclosed</span>' in table
    assert "Ready to add" in table and "Needs review" in table
    assert '<summary>Evidence (1)</summary>' in table
    assert '<summary>Evidence (0)</summary>' in table
    assert re.search(r'<details class="web-evidence"(?![^>]*\bopen)', table)
    assert 'class="badge badge-neutral">framework</span>' in table
    for category in ("js-library", "web-server", "reverse-proxy"):
        assert f'class="badge badge-neutral">{category}</span>' in table
    for label in ("header", "cookie", "markup", "link", "script", "stylesheet",
                  "Inferred from TypeScript", "Inferred from Next.js"):
        assert label in table
    for label in ("https://assets.example.invalid/react.js",
                  "/*! @license React v18.2.0 */", "SHA-256", "512 bytes"):
        assert label in table
    assert "Read 4 script and style files from the sites (2 skipped)." in page.text
    assert "Many sites hide version numbers. Products without a version are marked Needs review. Enter the version yourself to add one to the inventory." in page.text


def test_detected_product_with_cpe_is_marked_in_inventory(web, monkeypatch):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    detail = {
        "client": "Acme",
        "products": [{
            "asset_id": "web-cpe-only", "hostname": "example.invalid", "vendor": "Example",
            "product": "Widget", "name": "Widget", "category": "framework",
            "confidence": "medium", "versions": [], "evidence_types": ["header"],
        }],
        "reviews": [],
    }
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    cpe_asset = Asset("web-cpe-only", vendor="Example", product="Widget",
                      cpe="cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*")
    monkeypatch.setattr(dashboard_web, "read_web_snapshot", lambda path: (
        [cpe_asset], {"generated_at": "2026-11-25T00:00:00Z", "record_count": 1}))
    page = client.get("/web-assets?client=Acme")
    table = (
        page.text.split("Detected products", 1)[1].split("Entries to review", 1)[0]
    )
    # Web snapshots are off, so no scan covers the product yet; it has no version to add as it is.
    assert "Widget" in table and "Needs review" in table
    assert "badge-success" not in table


def test_web_assets_page_renders_without_inline_styles_or_scripts(web):
    _, _, _, client = web
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200
    assert not re.search(r"(?i)\sstyle\s*=", page.text)
    assert not re.search(r"(?is)<style\b", page.text)
    assert not re.search(r"(?is)<script\b(?![^>]*\bsrc=)[^>]*>", page.text)


def test_product_and_evidence_markup_sentinel_is_rendered_as_text(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    sentinel = "<script>alert(1)</script>"
    detail = {
        "client": "Acme",
        "products": [{
            "hostname": "example.invalid", "vendor": "npm", "product": "react",
            "name": sentinel, "category": "js-library", "confidence": "high",
            "versions": ["18.3.1"], "evidence_types": ["script"],
            "ecosystem": "npm", "package": "react",
            "evidence": [{"kind": "script", "source": sentinel, "excerpt": sentinel}],
        }],
        "reviews": [],
    }
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    response = client.get("/web-assets?client=Acme")
    assert response.status_code == 200
    assert sentinel not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text



def test_invalid_client_label_on_view_is_bad_request(web):
    assert web[3].get("/web-assets", query_string={"client": "x" * 200}).status_code == 400


def test_account_transaction_covers_final_allowlist_write(web, monkeypatch):
    import sqlite3
    from cvebeacon import dashboard_web
    config, users, _, client = web
    write = dashboard_web.save_allowlist
    observed = []
    def checked_write(path, document):
        with sqlite3.connect(users.path, timeout=0) as connection:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                connection.execute("BEGIN IMMEDIATE")
        observed.append(True)
        return write(path, document)
    monkeypatch.setattr(dashboard_web, "save_allowlist", checked_write)
    assert save(client).status_code == 303
    assert observed == [True]
    assert not users.verify_audit()


def test_transaction_failure_restores_allowlist_and_retired_results(web, monkeypatch):
    from contextlib import contextmanager
    from cvebeacon.errors import StateError
    config, users, app, client = web
    assert save(client).status_code == 303
    path, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    files = (path, output, Path(str(output) + ".manifest.json"), Path(str(output) + ".review.json"))
    before = {file: file.read_bytes() for file in files}
    audit_before = users.audit_entries()
    active_users = app.extensions["dashboard_users"]
    transaction = active_users.transaction
    @contextmanager
    def failed_transaction():
        with transaction() as db:
            yield db
            raise StateError("synthetic transaction failure")
    monkeypatch.setattr(active_users, "transaction", failed_transaction)
    assert save(client, action="remove-all", confirm="yes").status_code == 400
    assert {file: file.read_bytes() for file in files} == before
    assert users.audit_entries() == audit_before


def test_ca_change_renews_and_audits_every_entry(web):
    config, users, _, client = web
    assert save(client).status_code == 303
    assert save(client, hostname="second.invalid").status_code == 303
    path, _ = paths(config, "Acme")
    document, _ = read_allowlist(path, "Acme")
    document["ca_bundle"] = "old-ca.pem"
    for row in document["assets"]:
        row.update(authorized_by="previous-user", authorized_at="2026-01-01T00:00:00Z")
    save_allowlist(path, document)
    assert save(client, action="change", index="0", ca_bundle="").status_code == 303
    updated = read_allowlist(path, "Acme")[0]
    assert "ca_bundle" not in updated
    assert {row["authorized_by"] for row in updated["assets"]} == {"admin"}
    assert len({row["authorized_at"] for row in updated["assets"]}) == 1
    changes = [entry.action for entry in users.audit_entries() if entry.action.startswith("web_asset_change:")]
    assert any("example.invalid" in entry for entry in changes)
    assert any("second.invalid" in entry for entry in changes)



def test_last_single_removal_keeps_bulk_result_removal_available(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    assert save(client, action="remove", index="0").status_code == 303
    page = client.get("/web-assets?client=Acme")
    assert "Remove all assets" in page.text
    assert save(client, action="remove-all", confirm="yes").status_code == 303
    assert not output.exists()


@pytest.mark.parametrize("entry", [{"url": "http://\ud800/"}, {"hostname": "\udfff"}])
def test_surrogate_allowlist_entries_keep_bulk_recovery_available(web, entry):
    config, users, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    document, _ = read_allowlist(path, "Acme")
    document["assets"].append(entry)
    web_assets.replace_bytes(path, json.dumps(document).encode("utf-8"))
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200 and "Remove all assets" in page.text
    assert save(client, action="remove-all", confirm="yes").status_code == 303
    assert read_allowlist(path, "Acme")[0]["assets"] == []
    assert not users.verify_audit()


@pytest.mark.parametrize("fault", ["oversized", "unreadable", "linked"])
def test_remove_all_retires_unreadable_results(web, monkeypatch, fault):
    from cvebeacon import dashboard_web
    config, users, _, client = web
    assert save(client).status_code == 303
    path, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    outside = output.parent / "outside"
    if fault == "oversized":
        with output.open("r+b") as handle:
            handle.truncate(33 * 1024 * 1024)
    elif fault == "linked":
        if os.name != "posix":
            pytest.skip("symbolic link creation requires privileges on Windows")
        output.rename(outside)
        output.symlink_to(outside)
    else:
        read = dashboard_web.read_bytes
        def unreadable(target):
            if target == output:
                raise PermissionError("unreadable result")
            return read(target)
        monkeypatch.setattr(dashboard_web, "read_bytes", unreadable)
    response = save(client, action="remove-all", confirm="yes")
    assert response.status_code == 303, response.text
    assert read_allowlist(path, "Acme")[0]["assets"] == []
    assert not any(file.exists() or file.is_symlink() for file in (
        output, Path(str(output) + ".manifest.json"), Path(str(output) + ".review.json")))
    if fault == "linked":
        assert outside.read_bytes()
    assert any(entry.action.startswith("web_snapshot_remove:") for entry in users.audit_entries())
    assert not users.verify_audit()


def test_bulk_removal_rollback_restores_only_readable_results(web, monkeypatch):
    from contextlib import contextmanager
    from cvebeacon.errors import StateError
    config, users, app, client = web
    assert save(client).status_code == 303
    path, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    with output.open("r+b") as handle:
        handle.truncate(33 * 1024 * 1024)
    readable = (path, Path(str(output) + ".manifest.json"), Path(str(output) + ".review.json"))
    before = {file: file.read_bytes() for file in readable}
    audit_before = users.audit_entries()
    active_users = app.extensions["dashboard_users"]
    transaction = active_users.transaction
    @contextmanager
    def failed_transaction():
        with transaction() as db:
            yield db
            raise StateError("synthetic transaction failure")
    monkeypatch.setattr(active_users, "transaction", failed_transaction)
    assert save(client, action="remove-all", confirm="yes").status_code == 400
    assert {file: file.read_bytes() for file in readable} == before
    assert not output.exists()
    assert users.audit_entries() == audit_before


@pytest.mark.parametrize("action", ["remove", "change", "remove-all"])
def test_oversized_stored_hostname_can_be_recovered_with_bounded_audit(web, action):
    config, users, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    document, _ = read_allowlist(path, "Acme")
    document["assets"][0]["hostname"] = "x" * 2000
    save_allowlist(path, document)
    before, audit_before = path.read_bytes(), users.audit_entries()
    response = save(client, action=action, index="0", confirm="yes")
    assert response.status_code == 303, response.text
    assets = read_allowlist(path, "Acme")[0]["assets"]
    assert [row["hostname"] for row in assets] == (["example.invalid"] if action == "change" else [])
    added = users.audit_entries()
    added = [entry for entry in added if entry not in audit_before]
    assert added and all(len(entry.action.split(":", 1)[1]) <= 1024 for entry in added)
    assert any(json.loads(entry.action.split(":", 1)[1]).get("host") == "invalid" for entry in added)
    assert path.read_bytes() != before and not users.verify_audit()


def test_stored_control_characters_are_escaped_in_audit_details(web):
    config, users, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    document, _ = read_allowlist(path, "Acme")
    document["assets"][0]["hostname"] = "host\n\x00.invalid"
    save_allowlist(path, document)
    assert save(client, action="remove-all", confirm="yes").status_code == 303
    detail = next(item.action.split(":", 1)[1] for item in users.audit_entries()
                  if item.action.startswith("web_asset_remove:"))
    assert len(detail) <= 1024 and all(ord(char) >= 32 for char in detail)
    assert json.loads(detail)["host"] == "host\n\x00.invalid"


@pytest.mark.parametrize("hostname", ["x" * 2000, "host\n\x00.invalid"])
def test_invalid_submitted_hostname_still_leaves_storage_and_audit_unchanged(web, hostname):
    config, users, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    before, audit_before = path.read_bytes(), users.audit_entries()
    assert save(client, action="change", index="0", hostname=hostname).status_code == 400
    assert path.read_bytes() == before and users.audit_entries() == audit_before


def test_surrogate_ca_bundle_keeps_bulk_recovery_available(web):
    config, users, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    document, _ = read_allowlist(path, "Acme")
    document["ca_bundle"] = "\ud800"
    web_assets.replace_bytes(path, json.dumps(document).encode("utf-8"))
    before = path.read_bytes()
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200 and "Remove all assets" in page.text
    assert path.read_bytes() == before
    assert save(client, action="remove-all", confirm="yes").status_code == 303
    recovered = read_allowlist(path, "Acme")[0]
    assert recovered["assets"] == [] and recovered["ca_bundle"] == "\ud800"
    assert not users.verify_audit()


@pytest.mark.parametrize("suffix", ["", ".manifest.json", ".review.json", ".removed"])
def test_bulk_removal_reports_directory_before_any_write(web, monkeypatch, suffix):
    from cvebeacon import dashboard_web
    config, users, _, client = web
    assert save(client).status_code == 303
    path, output = paths(config, "Acme")
    target = Path(str(output) + suffix)
    target.mkdir()
    (target / "keep").write_bytes(b"private data")
    before, audit_before = path.read_bytes(), users.audit_entries()
    def unexpected_write(*args):
        pytest.fail("directory results must be classified before writing")
    monkeypatch.setattr(dashboard_web, "save_allowlist", unexpected_write)
    response = save(client, action="remove-all", confirm="yes")
    assert response.status_code == 400
    assert "saved result path is a directory" in response.text
    assert "web-inventory" in response.text
    assert path.read_bytes() == before and users.audit_entries() == audit_before
    assert (target / "keep").read_bytes() == b"private data"


def test_bulk_removal_reports_delete_failure_and_rolls_back(web, monkeypatch):
    config, users, _, client = web
    assert save(client).status_code == 303
    path, output = paths(config, "Acme")
    snapshot(output.parent, name=output.stem)
    before, audit_before = path.read_bytes(), users.audit_entries()
    unlink = Path.unlink
    def blocked(target, *args, **kwargs):
        if target == output:
            raise PermissionError("SECRET_PATH")
        return unlink(target, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", blocked)
    response = save(client, action="remove-all", confirm="yes")
    assert response.status_code == 400
    assert "Saved results could not be removed" in response.text
    assert "close open readers" in response.text and "SECRET_PATH" not in response.text
    assert path.read_bytes() == before and users.audit_entries() == audit_before
    assert output.read_bytes()


def test_save_shows_path_free_publication_timeout_guidance(web, monkeypatch):
    from types import SimpleNamespace
    from cvebeacon import publication
    _, _, _, client = web
    assert save(client).status_code == 303
    elapsed = [0.0]
    def blocked(*args):
        raise PermissionError("SECRET_PATH")
    monkeypatch.setattr(publication, "os", SimpleNamespace(name="nt", replace=blocked))
    monkeypatch.setattr(publication, "time", SimpleNamespace(
        monotonic=lambda: elapsed[0], sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay)))
    response = save(client, action="change", index="0", path="/updated")
    assert response.status_code == 400
    assert "Atomic publication" in response.text and "close open readers and retry" in response.text
    assert "SECRET_PATH" not in response.text


def test_legacy_allowlist_label_stays_reachable_without_a_new_file(web):
    config, _, _, client = web
    assert save(client).status_code == 303
    saved, _ = paths(config, "Acme")
    document, _ = read_allowlist(saved, "Acme")
    legacy_label = "Ａcme"  # fullwidth A: normalises to "Acme" for inventory grouping
    legacy, _ = paths(config, legacy_label)
    assert legacy != saved
    save_allowlist(legacy, {**document, "client": legacy_label})
    saved.unlink()
    page = client.get("/web-assets", query_string={"client": legacy_label})
    assert page.status_code == 200
    assert "example.invalid" in page.text
    assert not saved.exists()


def test_redirect_prefill_action_needs_manage_web_assets(web):
    config, users, _, client = web
    assert save(client).status_code == 303
    _, output = paths(config, "Acme")
    save_allowlist(Path(str(output) + ".review.json"), {
        "client": "Acme", "products": [], "reviews": [dict(
            asset_id="web-example", reason="redirect-blocked",
            detail="redirect target is not an allowlisted host and port",
            redirect_target={"scheme": "https", "host": "www.example.invalid", "port": 443})],
    })
    grant(users, ["view"])
    client.post("/logout", data={"csrf": csrf(client)})
    login(client, "reader")
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200
    assert "This site redirects to https://www.example.invalid:443" in page.text
    assert "Add this redirect target as an authorised site" not in page.text
    assert "If the client authorises it, add it as a site." not in page.text


@pytest.mark.parametrize("field,value", [
    ("review_truncated", "yes"), ("fingerprint_error", []), ("fingerprint_stopped", -1),
    ("fingerprint_technologies", True), ("analysis_stopped", "1"),
])
def test_review_run_flags_are_validated_by_type(field, value):
    from cvebeacon.dashboard_web import _review_metadata

    with pytest.raises(ValueError):
        _review_metadata({"client": "Acme", "run": {field: value}}, "Acme")


@pytest.mark.parametrize("persisted_entry_count", [1, 1001])
def test_dashboard_distinguishes_collection_truncation_from_display_limit(setup, persisted_entry_count):
    config, _, client = setup
    assets, output = paths(config, "Acme")
    save_allowlist(assets, {"client": "Acme", "assets": []})
    detail = {"client": "Acme", "reviews": [{}] * persisted_entry_count, "run": {
        "status": "partial", "review_truncated": True, "fingerprint_error": True,
        "fingerprint_stopped": 2, "analysis_stopped": 1,
    }}
    web_assets.replace_bytes(Path(str(output) + ".review.json"), json.dumps(detail).encode("utf-8"))
    page = client.get("/web-assets?client=Acme")
    assert page.status_code == 200
    assert "The saved review reached its size limit" in page.text
    assert "Fingerprint analysis stopped early for 2 sites" in page.text
    assert "Fingerprint analysis encountered an error" in page.text
    assert "Web analysis reached its time limit on 1 site" in page.text
    assert ("Showing the first 1,000 saved entries per table" in page.text) == (persisted_entry_count > 1000)
