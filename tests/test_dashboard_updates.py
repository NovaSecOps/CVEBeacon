"""Update permissions, request audit and escaped release status."""
from dataclasses import replace
import json
import pytest

from cvebeacon import dashboard, dashboard_update, updater
from cvebeacon.config import UpdateConfig
from cvebeacon.dashboard_config import check_document, dashboard_authority_changed
from test_dashboard_operations import login, make_config, new_accounts, submit


@pytest.fixture
def updates(tmp_path, monkeypatch):
    config = replace(make_config(tmp_path), update=UpdateConfig(enabled=True))
    users = new_accounts(config)
    app = dashboard.create_app(config)
    monkeypatch.setattr(dashboard_update, "unsupported_reason", lambda: None)
    return config, users, app.test_client()


def test_view_can_read_status_and_notes_are_escaped(updates):
    config, _, client = updates
    updater.atomic_json(config.watch.database.parent / updater.STATUS,
                        {"available": "0.1.1", "notes": "<script>alert(1)</script>", "last_check": "2026-01-01"})
    login(client, "viewer")
    page = client.get("/updates/")
    assert page.status_code == 200
    assert "0.1.1" in page.text and "&lt;script&gt;" in page.text
    assert "<script>alert" not in page.text and "Update now" not in page.text
    assert submit(client, "/updates/request", version="0.1.1").status_code == 403
    assert submit(client, "/updates/check").status_code == 403
    assert not (config.watch.database.parent / updater.REQUEST).exists()


def test_admin_request_only_queues_version_and_audits(updates):
    config, users, client = updates
    login(client)
    result = submit(client, "/updates/request", version="0.1.1")
    assert result.status_code == 303
    payload = json.loads((config.watch.database.parent / updater.REQUEST).read_text())
    assert set(payload) == {"version", "user", "time"}
    assert payload["version"] == "0.1.1" and payload["user"] == "admin"
    assert updater.read_request(config.watch.database.parent / updater.REQUEST) == "0.1.1"
    assert any(entry.action == "update_request:0.1.1" for entry in users.audit_entries())


def test_update_check_is_attributed_to_the_administrator(updates, monkeypatch):
    config, users, client = updates
    login(client)
    monkeypatch.setattr(dashboard_update, "check", lambda *args: None)
    assert submit(client, "/updates/check").status_code == 303
    entry = users.audit_entries()[-1]
    assert entry.action == "update_check"
    assert entry.actor == "admin"


def test_request_needs_account_admin_and_valid_csrf(updates):
    config, _, client = updates
    login(client)
    assert client.post("/updates/request", data={"version": "0.1.1", "csrf": "0" * 64}).status_code == 400
    assert submit(client, "/updates/request", version="../../escape").status_code == 400
    assert not (config.watch.database.parent / updater.REQUEST).exists()


def test_shared_password_or_unauthenticated_dashboard_cannot_request(tmp_path):
    config = replace(make_config(tmp_path), update=UpdateConfig(enabled=True))
    client = dashboard.create_app(config).test_client()
    token = "a" * 64
    with client.session_transaction() as session:
        session["csrf"] = token
    assert client.post("/updates/request", data={"csrf": token, "version": "0.1.1"}).status_code == 403


def test_loopback_health_probe_needs_no_account_and_blocks_remote(updates):
    _, _, client = updates
    from importlib.metadata import version
    import os
    assert client.get("/healthz").json == {"status": "ok", "version": version("cvebeacon"), "pid": os.getpid()}
    assert client.get("/healthz", environ_base={"REMOTE_ADDR": "203.0.113.10"}).status_code == 403


def test_update_settings_are_preserved_by_existing_config_editor():
    check_document({"update": {"enabled": True, "repository": "NovaSecOps/CVEBeacon", "daily": False}})


def test_rollback_cannot_change_update_settings_without_admin(tmp_path):
    config = make_config(tmp_path)
    changed = replace(config, update=UpdateConfig(enabled=True))
    assert dashboard_authority_changed(changed, config, config)


def test_admin_revocation_after_request_guard_cannot_publish(updates, monkeypatch):
    config, users, client = updates
    login(client)
    original = dashboard_update.request_update
    def revoke_then_request(*args, **kwargs):
        proof = users.authenticate("admin", "Synthetic operations password 123")
        users.add("backup", password="Synthetic backup password 123", is_admin=True, authorization=proof)
        users.edit_user("admin", role="viewer", disabled=False, authorization=proof)
        return original(*args, **kwargs)
    monkeypatch.setattr(dashboard_update, "request_update", revoke_then_request)
    assert submit(client, "/updates/request", version="0.1.1").status_code == 400
    assert not (config.watch.database.parent / updater.REQUEST).exists()
