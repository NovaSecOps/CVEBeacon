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


@pytest.fixture
def feedback_updates(updates):
    return updates


def test_view_can_read_status_and_notes_are_escaped(updates):
    config, _, client = updates
    updater.atomic_json(config.watch.database.parent / updater.STATUS,
                        {"available": "0.1.1", "notes": "<!-- publishing checklist -->\n<script>alert(1)</script>", "last_check": "2026-01-01"})
    login(client, "viewer")
    page = client.get("/updates/")
    assert page.status_code == 200
    assert "0.1.1" in page.text and "&lt;script&gt;" in page.text
    assert "<script>alert" not in page.text and "Update now" not in page.text
    assert "publishing checklist" not in page.text
    assert submit(client, "/updates/request", version="0.1.1").status_code == 403
    assert submit(client, "/updates/check").status_code == 403
    assert not (config.watch.database.parent / updater.REQUEST).exists()


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("preflight-crontab-unreadable", "The crontab could not be read inside the update service."),
        ("backup-database-busy", "A database stayed busy while the update backup was being created."),
    ],
)
def test_update_failure_reason_is_plain_language_and_includes_cli_next_step(updates, reason, expected):
    config, _, client = updates
    updater.atomic_json(
        config.watch.database.parent / updater.STATUS,
        {"last_update": {"result": "refused", "version": "0.1.1", "time": updater.stamp(),
                         "reason": reason}},
    )
    login(client, "viewer")
    page = client.get("/updates/")
    assert expected in page.text
    assert "Run <code>cvebeacon update apply</code> as an administrator to see details" in page.text


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


@pytest.mark.parametrize(
    ("check_result", "failure", "expected"),
    [
        ({"current": "0.1.0", "available": None}, None,
         "Checked just now. You have the latest release (0.1.0)."),
        ({"current": "0.1.0", "available": "0.1.1"}, None,
         "Version 0.1.1 is available."),
        (None, updater.UpdateError("release check unavailable"),
         "The release check failed. Try again later."),
    ],
)
def test_update_check_feedback_is_shown_on_updates_page(
    feedback_updates, monkeypatch, check_result, failure, expected
):
    _, _, client = feedback_updates
    login(client)

    def check(*args, **kwargs):
        if failure:
            raise failure
        return check_result

    monkeypatch.setattr(dashboard_update, "check", check)

    response = submit(client, "/updates/check")
    assert response.status_code == 303
    page = client.get("/updates/")
    assert expected in page.text


def test_disabled_update_check_does_not_use_cached_status_or_audit(
    tmp_path, monkeypatch
):
    config = replace(
        make_config(tmp_path), update=UpdateConfig(enabled=False)
    )
    users = new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    updater.atomic_json(
        config.watch.database.parent / updater.STATUS,
        {"current": "0.1.0", "available": "0.1.1", "last_check": "2026-11-24T00:00:00+00:00"},
    )

    def unexpected_check(*args, **kwargs):
        pytest.fail("a disabled release check must not call the updater")

    monkeypatch.setattr(dashboard_update, "check", unexpected_check)
    login(client)
    response = submit(client, "/updates/check")
    assert response.status_code == 303
    page = client.get("/updates/")
    assert "Release checks are turned off. An administrator can turn them on in the configuration." in page.text
    assert "Version 0.1.1 is available." not in page.text
    assert not any(entry.action == "update_check" for entry in users.audit_entries())


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


@pytest.mark.parametrize(("notes", "visible"), [
    ("before<!-- outer\n<!-- inner --> tail -->after", "beforeafter"),
    ("before<!-- outer\n--!>after", "beforeafter"),
    ("before<!-- outer\n<!-- unclosed", "before"),
    ("before<!-- multiline\ncomment -->after", "beforeafter"),
])
def test_release_notes_comment_scan(updates, monkeypatch, notes, visible):
    config, _, client = updates
    monkeypatch.setattr(dashboard_update, "read_status", lambda config: {"notes": notes + "<b>escaped</b>"})
    login(client, "viewer")
    page = client.get("/updates/")
    assert page.status_code == 200
    assert f'<pre class="break">{visible}' in page.text
    assert all(text not in page.text for text in ("outer", "inner", "tail --&gt;", "multiline", "<b>escaped"))
    if "after" in visible:
        assert "&lt;b&gt;escaped&lt;/b&gt;" in page.text


@pytest.mark.parametrize(("older", "latest", "expected"), [
    (("last_request", "busy", "lock-failed"), ("last_update", "updated", None), None),
    (("last_update", "refused", "probe-unhealthy"), ("last_request", "busy", "lock-failed"), "acquire the required locks"),
    (("last_request", "busy", "lock-failed"), ("last_attempt", "refused", "version-invalid"), "canonical release version"),
    (("last_request", "refused", "recovery-incomplete"), ("last_update", "rolled-back", "migrate-failed"), "state migration did not complete"),
])
def test_latest_attempt_controls_primary_callout(updates, monkeypatch, older, latest, expected):
    def attempt(row, time):
        _, result, reason = row
        return {"result": result, "reason": reason, "time": time}

    _, _, client = updates
    state = {older[0]: attempt(older, "2026-01-01T00:00:00+00:00"),
             latest[0]: attempt(latest, "2026-01-01T00:00:01+00:00")}
    monkeypatch.setattr(dashboard_update, "read_status", lambda config: state)
    login(client, "viewer")
    page = client.get("/updates/").text
    assert dashboard_update.UPDATE_REASON_TEXT[older[2]] not in page
    if expected is None:
        assert "The last update needs attention" not in page
    else:
        assert "The last update needs attention" in page
        assert expected in page.split("The last update needs attention", 1)[1]


@pytest.mark.parametrize("reason", [[], {"code": "check-network"}, "unknown-reason", None])
def test_malformed_reason_ignores_injected_text_and_preserves_legacy_result(updates, monkeypatch, reason):
    _, _, client = updates
    state = {"last_request": {"result": "refused", "reason": reason, "reason_text": "synthetic injected text"}}
    monkeypatch.setattr(dashboard_update, "read_status", lambda config: state)
    login(client, "viewer")
    page = client.get("/updates/")
    assert page.status_code == 200
    assert "Last request: refused" in page.text
    assert "synthetic injected text" not in page.text
    assert "The last update needs attention" not in page.text


@pytest.mark.parametrize("followup", ["recovery_reason", "finalization_reason"])
def test_incomplete_recovery_and_finalization_offer_recover_even_after_a_newer_request(updates, monkeypatch, followup):
    _, _, client = updates
    recovery = followup == "recovery_reason"
    state = {"last_update": {"time": "2026-01-01T00:00:00+00:00",
                              "result": "rollback-failed" if recovery else "updated",
                              followup: "probe-unhealthy" if recovery else "finalize-archive-failed"},
             "last_request": {"time": "2026-01-01T00:00:01+00:00", "result": "busy", "reason": "lock-failed"}}
    monkeypatch.setattr(dashboard_update, "read_status", lambda config: state)
    login(client, "viewer")
    page = client.get("/updates/").text
    assert "Run <code>cvebeacon update recover</code>" in page
    assert ("writes remain blocked" if recovery else "could not archive the completed transaction") in page
