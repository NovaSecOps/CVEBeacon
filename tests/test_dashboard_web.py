"""Authorisation, private persistence and companion job boundaries for web assets."""

from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from cvebeacon import dashboard, web_assets
from cvebeacon.dashboard_jobs import build_command
from cvebeacon.errors import ConfigurationError
from cvebeacon.locking import OperationLock, RunInProgress, operation_lock_paths
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
    {"scheme": "ftp"}, {"max_redirects": "3"}, {"expires_at": "2000-01-01T00:00:00Z"},
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
                   {"max_redirects": 5}, {"hostname": "bad/host"}, {"path": "/bad#fragment"}, {"unexpected": 1}):
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
            with pytest.raises(RunInProgress):
                manager.submit(operation, started_by="admin", argv=build_command(config, operation, client="Acme"))
            response = client.post("/web-assets/run", data={"csrf": csrf(client), "client": "Acme", "action": operation})
            assert response.status_code == 409
        assert save(client).status_code == 409
    finally:
        lock.release()


def test_detection_companion_argument_list(web, monkeypatch):
    config, _, _, client = web
    assert save(client).status_code == 303
    asset_path, output = paths(config, "Acme")
    calls = []
    monkeypatch.setattr(web_assets.subprocess, "call", lambda argv, **kwargs: calls.append((argv, kwargs)) or 0)
    assert web_assets.run_detection(config, "Acme") == 0
    assert calls[0][0] == [sys.executable, "-I", "-u", "-m", "cvebeacon_extensions", "web", "detect",
                           "--client", "Acme", "--assets", str(asset_path), "--output", str(output),
                           "--source-id", "web-" + client_key("Acme"), "--allow-partial"]
    web_assets.run_detection(config, "Acme", plan=True)
    assert calls[-1][0][-1] == "--plan"


def test_private_atomic_storage_does_not_follow_links(web, monkeypatch):
    config, _, _, client = web
    assert save(client).status_code == 303
    path, _ = paths(config, "Acme")
    before = path.read_bytes()
    monkeypatch.setattr(web_assets.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("failure")))
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
    save_allowlist(Path(str(output) + ".review.json"), {
        "client": "Acme", "body": secret, "cookies": secret,
        "run": dict(started_at="2026-11-05T12:00:00Z", ended_at="2026-11-05T12:00:01Z",
                    status="partial", request_count=2, duration_seconds=1.0, body=secret),
        "products": [dict(hostname="example.invalid", vendor="nginx", product="nginx", versions=["1.26.2"],
                          evidence_types=["header"], category="server", confidence="high", body=secret)],
        "reviews": [dict(asset_id="web-acme", reason=reason, detail=secret, body=secret) for reason in
                    ("unreachable", "blocked", "version-unknown", "version-conflict")],
    })
    response = client.get("/web-assets?client=Acme")
    assert response.status_code == 200, response.text
    for value in ("1.26.2", "nginx", "header", "partial", "requests: 2", "duration: 1.0", "version-conflict"):
        assert value in response.text
    assert secret not in response.text
    assert "web_snapshots = true" in response.text


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
