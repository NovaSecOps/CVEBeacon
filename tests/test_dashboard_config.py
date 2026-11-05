"""Configuration editing must preserve authorization, secrets and live state."""

from copy import deepcopy
from datetime import datetime, timezone
import html
import os
from pathlib import Path
import re
import stat
import tomllib

import pytest

from cvebeacon import dashboard, dashboard_config as editor_module
from cvebeacon.config import load_config
from cvebeacon.dashboard_config import dumps, SECTIONS
from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from test_dashboard import setup
from test_dashboard_accounts import accounts as account_fixture, login, csrf, PASSWORD


@pytest.fixture
def accounts(account_fixture):
    account_fixture[0].config_path.chmod(0o644)
    return account_fixture


@pytest.mark.parametrize("document", [
    {"quoted.key": "quotes \" and slash \\ and newline\n\t\x01"},
    {"table": {"nested": {"array": [True, 1, 1.25, "é"]}, "empty": {}}},
    {"rows": [{"name": "a", "condition": {"any": [{"kev": True}, {"cvss_min": 9.0}]}},
              {"name": "b", "empty": []}]},
])
def test_serializer_round_trip(document):
    assert tomllib.loads(dumps(document)) == document


def test_every_repository_toml_round_trips():
    root = Path(__file__).resolve().parents[1]
    for path in root.rglob("*.toml"):
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        assert tomllib.loads(dumps(document)) == document, path


def form(page, action="preview"):
    """Submit the controls in the real rendered form, as a browser would."""
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", page, re.S)
    source = next(source for source in forms if f'name="action" value="{action}"' in source)
    data = {}
    for tag in re.findall(r"<input\b[^>]*>", source):
        attributes = dict(re.findall(r'([\w-]+)="([^"]*)"', tag))
        if attributes.get("type") != "checkbox":
            data[attributes["name"]] = html.unescape(attributes.get("value", ""))
    for name, contents in re.findall(r'<textarea name="([^"]+)"[^>]*>(.*?)</textarea>', source, re.S):
        data[name] = html.unescape(contents)
    for name, contents in re.findall(r'<select name="([^"]+)"[^>]*>(.*?)</select>', source, re.S):
        options = re.findall(r"<option([^>]*)>(.*?)</option>", contents, re.S)
        selected = next(((attr, text) for attr, text in options if "selected" in attr), options[0] if options else ("", ""))
        match = re.search(r'value="([^"]*)"', selected[0])
        data[name] = html.unescape(match[1] if match else selected[1])
    return data


def preview(client, section="http", **changes):
    page = client.get("/config/" + section)
    assert page.status_code == 200, page.text
    data = form(page.text)
    data.update(changes)
    return client.post("/config/" + section, data=data)


def confirm(client, response, section="http", **changes):
    assert response.status_code == 200, response.text
    data = form(response.text, "confirm")
    data.update(changes)
    return client.post("/config/" + section, data=data)


@pytest.mark.parametrize("section,permission", SECTIONS.items())
@pytest.mark.parametrize("grants", ["neither", "view", "edit", "both"])
def test_section_permissions(accounts, section, permission, grants):
    _, users, _, client = accounts
    proof = users.authenticate("admin", PASSWORD)
    permissions = set()
    if grants in {"view", "both"}:
        permissions.add("view")
    if grants in {"edit", "both"}:
        permissions.add(permission)
    users.save_role("limited", permissions, authorization=proof)
    users.edit_user("reader", role="limited", disabled=False, authorization=proof)
    login(client)
    response = client.get("/config/" + section)
    assert response.status_code == (200 if grants == "both" else 403)
    denied = client.post("/config/" + section, data={"csrf": csrf(client), "action": "preview"})
    if grants != "both":
        assert denied.status_code == 403


def test_shared_and_anonymous_modes_cannot_edit(setup, monkeypatch):
    config, _, client = setup
    assert client.get("/config/http").status_code == 403
    from cvebeacon.passwords import hash_password_value
    monkeypatch.setenv(config.dashboard.password_hash_env, hash_password_value(PASSWORD))
    client = dashboard.create_app(config).test_client()
    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/login").text)[1]
    assert client.post("/login", data={"csrf": token, "password": PASSWORD}).status_code == 303
    assert client.get("/config/http").status_code == 403


def test_preview_does_not_write_then_atomic_save_backup_audit_and_reload(accounts, monkeypatch):
    config, users, app, client = accounts
    login(client, "admin")
    original = config.config_path.read_bytes()
    before = config.config_path.stat()
    saved_wsgi = app.extensions["dashboard_config"].target
    response = preview(client, g0_retries="4")
    assert config.config_path.read_bytes() == original
    assert "Review changes" in response.text and '+"retries" = 4' in html.unescape(response.text)
    calls = []
    real_replace = os.replace
    def record(source, target):
        calls.append((Path(source), Path(target)))
        assert Path(source).parent == Path(target).parent
        return real_replace(source, target)
    monkeypatch.setattr(editor_module.os, "replace", record)
    assert confirm(client, response).status_code == 303
    assert load_config(config.config_path).http.retries == 4
    assert client.get("/").status_code == 303
    editor = app.extensions["dashboard_config"]
    assert editor.target != saved_wsgi and editor.config.http.retries == 4
    after = config.config_path.stat()
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert any(target == config.config_path for _, target in calls)
    backup = editor.backup_dir / editor.backups()[0]
    assert backup.read_bytes() == original
    if os.name == "posix":
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    audit = users.audit_entries()[-1]
    assert audit.actor == "admin" and audit.action.startswith("config_save:http:changed_lines=")
    assert users.verify_audit() is None
    login(client, "admin")
    assert 'value="4"' in client.get("/config/http").text


@pytest.mark.parametrize("field,value", [("g0_retries", "-1"), ("g0_retries", '"invalid"'),
                                        ("g0_connect_timeout", "0"), ("g0_retries", "true"),
                                        ("g0_connect_timeout", "nan"), ("g0_read_timeout", "inf")])
def test_loader_rejection_preserves_file_and_audit(accounts, field, value):
    config, users, app, client = accounts
    login(client, "admin")
    before, audit = config.config_path.read_bytes(), users.audit_count()
    response = preview(client, **{field: value})
    assert response.status_code == 400
    assert "Configuration could not be loaded or saved" in response.text
    assert "must be" in response.text
    assert config.config_path.read_bytes() == before and users.audit_count() == audit
    assert not app.extensions["dashboard_config"].backups()


@pytest.mark.parametrize("phase", ["form", "preview"])
def test_concurrent_change_refused(accounts, phase):
    config, users, _, client = accounts
    login(client, "admin")
    response = preview(client, g0_retries="4") if phase == "preview" else client.get("/config/http")
    config.config_path.write_text(config.config_path.read_text() + "\n# External edit\n")
    changed = config.config_path.read_bytes()
    data = form(response.text, "confirm" if phase == "preview" else "preview")
    assert client.post("/config/http", data=data).status_code == 409
    assert config.config_path.read_bytes() == changed


def test_preview_is_bound_to_session_section_single_use_and_expiry(accounts):
    _, _, app, client = accounts
    login(client, "admin")
    response = preview(client, g0_retries="4")
    data = form(response.text, "confirm")
    other = app.test_client()
    login(other, "admin")
    assert other.post("/config/http", data={**data, "csrf": csrf(other)}).status_code == 400
    assert client.post("/config/sources", data=data).status_code == 400
    editor = app.extensions["dashboard_config"]
    editor.pending[data["preview"]].expires = 0
    assert client.post("/config/http", data=data).status_code == 400
    response = preview(client, g0_retries="4")
    data = form(response.text, "confirm")
    assert confirm(client, response).status_code == 303
    login(client, "admin")
    assert client.post("/config/http", data={**data, "csrf": csrf(client)}).status_code == 400


def test_permission_revocation_between_guard_and_commit_is_rechecked(accounts, monkeypatch):
    config, users, app, client = accounts
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("editor", {"view", "edit_http"}, authorization=admin)
    users.edit_user("reader", role="editor", disabled=False, authorization=admin)
    login(client)
    response = preview(client, g0_retries="4")
    before = config.config_path.read_bytes()
    real_validate = app.extensions["dashboard_config"].validate
    def revoke(document):
        users.save_role("editor", {"view"}, authorization=admin)
        return real_validate(document)
    monkeypatch.setattr(app.extensions["dashboard_config"], "validate", revoke)
    assert confirm(client, response).status_code == 400
    assert config.config_path.read_bytes() == before


def test_lockout_change_requires_additional_confirmation(accounts):
    config, _, _, client = accounts
    login(client, "admin")
    original = config.config_path.read_bytes()
    response = preview(client, "dashboard", g0_session_lifetime_seconds="120")
    assert 'name="lockout"' in response.text
    assert confirm(client, response, "dashboard").status_code == 400
    assert config.config_path.read_bytes() == original
    assert confirm(client, response, "dashboard", lockout="yes").status_code == 303
    assert load_config(config.config_path).dashboard.session_lifetime_seconds == 120


def test_rollback_validates_previews_backs_up_and_reloads(accounts):
    config, users, app, client = accounts
    login(client, "admin")
    original = tomllib.loads(config.config_path.read_text())
    assert confirm(client, preview(client, g0_retries="4")).status_code == 303
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "backups")
    assert config.config_path.read_bytes() == before
    assert confirm(client, response, "backups").status_code == 303
    assert tomllib.loads(config.config_path.read_text()) == original
    assert len(app.extensions["dashboard_config"].backups()) == 2
    assert users.audit_entries()[-1].action.startswith("config_save:rollback:")


def test_backup_retention_is_bounded_and_other_files_preserved(accounts, monkeypatch):
    _, _, app, client = accounts
    monkeypatch.setattr(editor_module, "KEEP_BACKUPS", 2)
    login(client, "admin")
    for retries in (1, 2, 3):
        assert confirm(client, preview(client, g0_retries=str(retries))).status_code == 303
        login(client, "admin")
    editor = app.extensions["dashboard_config"]
    assert len(list(editor.backup_dir.iterdir())) == 2
    unrelated = editor.backup_dir / "keep.txt"
    unrelated.write_text("retained")
    assert confirm(client, preview(client, g0_retries="4")).status_code == 303
    assert unrelated.read_text() == "retained"


@pytest.mark.parametrize("failure", ["replace", "audit", "reload", "commit"])
def test_failure_never_leaves_an_unreviewed_live_config(accounts, monkeypatch, failure):
    config, users, app, client = accounts
    login(client, "admin")
    response = preview(client, g0_retries="4")
    before, count = config.config_path.read_bytes(), users.audit_count()
    editor = app.extensions["dashboard_config"]
    target = editor.target
    def fail(*args, **kwargs):
        raise OSError("synthetic failure")
    if failure == "replace":
        real = editor_module.os.replace
        def fail_live(source, destination):
            if Path(destination) == config.config_path:
                fail()
            return real(source, destination)
        monkeypatch.setattr(editor_module.os, "replace", fail_live)
    elif failure == "audit":
        monkeypatch.setattr(app.extensions["dashboard_users"], "_append_audit", fail)
    elif failure == "reload":
        monkeypatch.setattr(dashboard, "create_app", fail)
    else:
        from contextlib import contextmanager
        real = app.extensions["dashboard_users"].transaction
        @contextmanager
        def fail_commit():
            with real() as db:
                yield db
                fail()
        monkeypatch.setattr(app.extensions["dashboard_users"], "transaction", fail_commit)
    assert confirm(client, response).status_code == 503
    assert config.config_path.read_bytes() == before and editor.target is target
    assert users.audit_count() == count
    assert not editor.backups()


def test_file_secret_never_round_trips_and_rule_can_use_channel(accounts, monkeypatch, caplog):
    config, users, app, client = accounts
    login(client, "admin")
    secret = "Synthetic-only SMTP password !DO-NOT-ECHO!"
    monkeypatch.setenv("DB4_SECRET_ENV", "Synthetic environment value !DO-NOT-ECHO!")
    response = preview(client, "channels", g0_name="soc", g0_type="smtp", g0_host="smtp.example.invalid",
                       g0_from="sender@example.invalid", g0_to='["soc@example.invalid"]',
                       g0_username="alerts", g0_password_file_new=secret)
    assert response.status_code == 200, response.text
    assert secret not in response.text and os.environ["DB4_SECRET_ENV"] not in response.text
    assert "name=\"g0_password_file_new\"" not in response.text
    assert confirm(client, response, "channels").status_code == 303
    channel = load_config(config.config_path).watch.channels[0]
    secret_path = channel.secret("password").file
    assert secret_path.parent == app.extensions["dashboard_config"].secret_dir
    assert secret_path.read_text() == secret
    assert channel.secret("password").peek() == secret
    if os.name == "posix":
        assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(secret_path.parent.stat().st_mode) == 0o700
    login(client, "admin")
    page = client.get("/config/channels")
    assert secret not in page.text and os.environ["DB4_SECRET_ENV"] not in page.text
    assert confirm(client, preview(client, "rules", g0_name="critical", g0_condition="{ cvss_min = 9.0 }",
                                   g0_channels='["soc"]', g0_events='["match"]'), "rules").status_code == 303
    assert load_config(config.config_path).watch.rules[0].channels == ("soc",)
    assert secret not in config.config_path.read_text()
    assert secret not in str(users.audit_entries()) and secret not in caplog.text
    for backup in app.extensions["dashboard_config"].backup_dir.iterdir():
        assert secret not in backup.read_text()


def test_invalid_preview_and_expiration_remove_staged_secrets(accounts):
    _, _, app, client = accounts
    login(client, "admin")
    editor = app.extensions["dashboard_config"]
    response = preview(client, "sources", g0_nvd_api_key_file_new="Synthetic secret", g0_minimum_request_interval="0")
    assert response.status_code == 400
    assert not list(editor.secret_dir.iterdir())
    response = preview(client, "sources", g0_nvd_api_key_file_new="Synthetic secret")
    pending = editor.pending[form(response.text, "confirm")["preview"]]
    path = pending.staged[0]
    pending.expires = 0
    editor.cleanup()
    assert not path.exists()


@pytest.mark.parametrize("link", ["config", "backup-dir", "secret-dir", "hardlink"])
def test_unsafe_files_and_directories_refused(accounts, tmp_path, link):
    config, _, app, client = accounts
    login(client, "admin")
    editor = app.extensions["dashboard_config"]
    outside = tmp_path / "outside"
    outside.mkdir()
    original = config.config_path.read_bytes()
    if link == "config":
        target = outside / "other.toml"
        config.config_path.rename(target)
        config.config_path.symlink_to(target)
        assert client.get("/config/http").status_code in {400, 503}
        assert target.read_bytes() == original
    elif link == "hardlink":
        os.link(config.config_path, outside / "other.toml")
        assert client.get("/config/http").status_code == 400
    elif link == "backup-dir":
        editor.backup_dir.symlink_to(outside, target_is_directory=True)
        response = preview(client, g0_retries="4")
        assert confirm(client, response).status_code == 400
        assert config.config_path.read_bytes() == original and not list(outside.iterdir())
    else:
        editor.secret_dir.symlink_to(outside, target_is_directory=True)
        response = preview(client, "sources", g0_nvd_api_key_file_new="Synthetic secret")
        assert response.status_code == 400 and not list(outside.iterdir())


def test_write_new_secret_ignores_user_selected_destination(accounts, tmp_path):
    config, _, _, client = accounts
    login(client, "admin")
    destination = tmp_path / "must-not-overwrite"
    destination.write_text("unchanged")
    response = preview(client, "sources", g0_nvd_api_key_file=str(destination),
                       g0_nvd_api_key_file_new="Synthetic secret")
    assert response.status_code == 200
    assert confirm(client, response, "sources").status_code == 303
    assert destination.read_text() == "unchanged"
    assert load_config(config.config_path).sources.nvd_api_key_file != destination


@pytest.mark.parametrize("field,secret", [("g0_nvd_api_key_env", "https://secret.example/token"),
                                         ("g0_nvd_api_key_env", "KEY=secret-value")])
def test_pasted_secret_env_reference_rejected_without_echo(accounts, field, secret, caplog):
    config, users, _, client = accounts
    login(client, "admin")
    original = config.config_path.read_bytes()
    response = preview(client, "sources", **{field: secret})
    assert response.status_code == 400 and secret not in response.text and secret not in caplog.text
    assert config.config_path.read_bytes() == original and secret not in str(users.audit_entries())


def test_unknown_inline_credentials_never_render_or_rewrite(accounts):
    config, _, _, client = accounts
    login(client, "admin")
    secret = "INLINE-SYNTHETIC-SECRET"
    config.config_path.write_text(config.config_path.read_text() + f'\npassword="{secret}"\n')
    original = config.config_path.read_bytes()
    response = client.get("/config/sources")
    assert response.status_code == 400 and secret not in response.text
    assert config.config_path.read_bytes() == original


def test_loader_error_redacts_channel_labels_and_endpoint(accounts, caplog):
    _, users, _, client = accounts
    login(client, "admin")
    secret = "SensitiveLabelForRegression"
    response = preview(client, "channels", g0_name=secret, g0_host="", g0_type="smtp")
    assert response.status_code == 400
    assert secret not in response.text and secret not in caplog.text and secret not in str(users.audit_entries())


def test_forged_fields_cannot_change_a_different_section(accounts):
    config, _, _, client = accounts
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, g0_retries="4", g0_password_hash_env="ATTACK")
    assert response.status_code == 400 and config.config_path.read_bytes() == before


def test_wizard_output_round_trips(tmp_path):
    from cvebeacon.setup import _render_config, InventoryChoice, WatchSettings, RuleDraft, ChannelDraft, NvdKey
    generated = _render_config(now=datetime.now(timezone.utc), inventory=InventoryChoice("inventory.csv", "csv"),
                               watch=WatchSettings(("nvd",), "baseline", 7),
                               rules=[RuleDraft("critical", {"cvss_min": 9.0}, "digest", ("soc",))],
                               channels=[ChannelDraft("soc", "smtp", {"type": "smtp", "host": "smtp.example.invalid",
                                                                       "from": "a@example.invalid", "to": ["b@example.invalid"]})],
                               nvd_key=NvdKey())
    original = tmp_path / "wizard.toml"
    original.write_text(generated)
    rewritten = tmp_path / "rewritten.toml"
    rewritten.write_text(dumps(tomllib.loads(generated)))
    from dataclasses import replace
    assert replace(load_config(original), config_path=rewritten) == load_config(rewritten)


def test_all_core_examples_load_equal_after_serialization(tmp_path):
    from dataclasses import replace
    root = Path(__file__).resolve().parents[1]
    paths = [root / "cvebeacon.example.toml", *sorted((root / "examples").glob("*.toml")),
             *sorted((root / "deploy").rglob("*.toml")),
             *sorted((root / "automation").rglob("core*.toml"))]
    for index, path in enumerate(paths):
        original = tmp_path / f"original{index}.toml"
        rewritten = tmp_path / f"rewritten{index}.toml"
        original.write_text(path.read_text())
        rewritten.write_text(dumps(tomllib.loads(path.read_text())))
        assert replace(load_config(original), config_path=rewritten) == load_config(rewritten), path


def test_backup_content_is_validated_and_cannot_traverse(accounts):
    config, _, app, client = accounts
    login(client, "admin")
    assert confirm(client, preview(client, g0_retries="4")).status_code == 303
    login(client, "admin")
    editor = app.extensions["dashboard_config"]
    backup = editor.backup_dir / editor.backups()[0]
    backup.write_text('[http]\nretries=-1\n[inventory]\npath="inventory.csv"\n')
    before = config.config_path.read_bytes()
    assert preview(client, "backups").status_code == 400
    assert preview(client, "backups", backup="../config.toml").status_code == 400
    assert config.config_path.read_bytes() == before


def test_rollback_requires_every_edit_permission(accounts):
    _, users, _, client = accounts
    proof = users.authenticate("admin", PASSWORD)
    users.save_role("limited", {"view", "edit_http"}, authorization=proof)
    users.edit_user("reader", role="limited", disabled=False, authorization=proof)
    login(client)
    assert client.get("/config/backups").status_code == 403
    assert client.post("/config/backups", data={"csrf": csrf(client)}).status_code == 403


@pytest.mark.parametrize("section", [*SECTIONS, "backups"])
def test_configuration_posts_require_session_csrf(accounts, section):
    _, _, app, client = accounts
    login(client, "admin")
    assert client.post("/config/" + section, data={"action": "preview"}).status_code == 400
    other = app.test_client()
    login(other, "admin")
    assert client.post("/config/" + section, data={"csrf": csrf(other), "action": "preview"}).status_code == 400


@pytest.mark.parametrize("permission", ["edit_watch", "edit_system"])
def test_delegated_editor_cannot_move_effective_account_database(accounts, tmp_path, permission):
    config, users, _, client = accounts
    proof = users.authenticate("admin", PASSWORD)
    users.save_role("limited", {"view", permission}, authorization=proof)
    users.edit_user("reader", role="limited", disabled=False, authorization=proof)
    login(client)
    original = config.config_path.read_bytes()
    section = "watch" if permission == "edit_watch" else "system"
    assert preview(client, section, g0_database=str(tmp_path / "new" / "state.db")).status_code == 403
    assert config.config_path.read_bytes() == original


def test_account_database_change_requires_existing_store_and_access_confirmation(accounts, tmp_path):
    config, _, app, client = accounts
    login(client, "admin")
    directory = tmp_path / "other-data"
    response = preview(client, "watch", g0_database=str(directory / "watch.db"))
    assert response.status_code == 400
    assert not (directory / "cvebeacon-users.db").exists()
    other_users = UserStore(directory / "cvebeacon-users.db")
    other_users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    response = preview(client, "watch", g0_database=str(directory / "watch.db"))
    assert response.status_code == 200 and 'name="lockout"' in response.text
    assert confirm(client, response, "watch").status_code == 400
    assert confirm(client, response, "watch", lockout="yes").status_code == 303
    login(client, "admin")
    assert client.get("/config/watch").status_code == 200
    assert app.extensions["dashboard_config"].config.watch.users_database == other_users.path


def test_webhook_endpoint_is_redacted_and_blank_retains_it(accounts, monkeypatch):
    config, users, _, client = accounts
    secret_endpoint = "https://example.invalid/private-token/secret-path"
    monkeypatch.setenv("DB4_WEBHOOK_ENDPOINT", secret_endpoint)
    login(client, "admin")
    page = client.get("/config/channels?new_type=webhook")
    data = form(page.text)
    data.update(g0_name="hook", g0_url_env="DB4_WEBHOOK_ENDPOINT")
    response = client.post("/config/channels", data=data)
    assert response.status_code == 200 and secret_endpoint not in response.text
    assert confirm(client, response, "channels").status_code == 303
    login(client, "admin")
    page = client.get("/config/channels")
    assert secret_endpoint not in page.text
    assert confirm(client, preview(client, "channels"), "channels").status_code == 303
    channel = load_config(config.config_path).watch.channels[0]
    assert channel.secret("url").peek() == secret_endpoint
    assert secret_endpoint not in config.config_path.read_text()
    assert secret_endpoint not in str(users.audit_entries())


def test_stale_preview_in_second_application_refused(accounts):
    config, _, _, client = accounts
    other = dashboard.create_app(config).test_client()
    login(client, "admin")
    login(other, "admin")
    first = preview(client, g0_retries="4")
    second = preview(other, g0_retries="5")
    assert confirm(client, first).status_code == 303
    assert confirm(other, second).status_code == 409
    assert load_config(config.config_path).http.retries == 4


def test_invalid_current_nested_secret_is_not_rendered(accounts, caplog):
    config, _, _, client = accounts
    login(client, "admin")
    secret = "SyntheticNestedSecretNeverDisplay"
    config.config_path.write_text(config.config_path.read_text() +
                                '\n[[watch.rules]]\nname="broken"\nchannels=[]\ncondition={password="' + secret + '"}\n')
    response = client.get("/config/rules")
    assert response.status_code == 400 and secret not in response.text and secret not in caplog.text


@pytest.mark.parametrize("mode", [0o664, 0o666])
def test_writable_config_refused(accounts, mode):
    if os.name != "posix":
        pytest.skip("POSIX permissions")
    config, _, _, client = accounts
    login(client, "admin")
    original = config.config_path.read_bytes()
    config.config_path.chmod(mode)
    assert client.get("/config/http").status_code == 400
    assert config.config_path.read_bytes() == original


def test_defaults_visible_without_materializing_them(accounts):
    config, _, _, client = accounts
    login(client, "admin")
    original = config.config_path.read_bytes()
    page = client.get("/config/http")
    assert "Default: 10.0" in page.text and "Default: 30.0" in page.text
    assert form(page.text)["g0_connect_timeout"] == ""
    assert config.config_path.read_bytes() == original


def test_destination_administrator_rechecked_at_confirmation(accounts, tmp_path):
    config, _, _, client = accounts
    login(client, "admin")
    destination = UserStore(tmp_path / "destination" / "cvebeacon-users.db")
    destination.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    response = preview(client, "watch", g0_database=str(destination.path.parent / "watch.db"))
    original = config.config_path.read_bytes()
    with destination.transaction() as db:
        db.execute("UPDATE cb_user SET disabled=1")
    assert confirm(client, response, "watch", lockout="yes").status_code == 400
    assert config.config_path.read_bytes() == original
