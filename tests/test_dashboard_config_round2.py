"""Regressions for the second configuration-editor review round."""

import json
import os
from pathlib import Path
import re
import time
import tomllib

import pytest

from cvebeacon import dashboard, dashboard_config as dc
from cvebeacon.config import load_config
from cvebeacon.errors import ConfigurationError
from cvebeacon.locking import LOCK_NAME
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from test_dashboard import setup  # noqa: F401 - registers the shared fixture
from test_dashboard_accounts import PASSWORD, accounts as account_fixture, login
from test_dashboard_config_fixes import (
    BASE,
    confirm,
    form,
    make_secret,
    preview,
    preview_channels,
    set_role,
    with_file,
)


@pytest.fixture
def accounts(account_fixture):
    account_fixture[0].config_path.chmod(0o644)
    return account_fixture


def channel_config(text):
    return BASE + "\n[watch]\nenabled = true\nsources = [\"nvd\"]\n" + text


def _smtp(name="mail", reference="password_file", extra=""):
    source = "password_env" if reference == "password_env" else "password_file"
    if source == "password_env":
        value = "SMTP_PASSWORD"
    else:
        value = reference
    return f'''
[watch.channels.{name}]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
{source} = {json.dumps(str(value))}
{extra}
'''


@pytest.mark.parametrize("kind,channel,field,new", [
    ("smtp", _smtp(reference="password_env"), "g0_host", "attacker.example.invalid"),
    ("matrix", '''
[watch.channels.matrix]
type = "matrix"
homeserver = "https://matrix.example.invalid"
room_id = "!room:example.invalid"
access_token_env = "MATRIX_TOKEN"
''', "g0_homeserver", "https://attacker.example.invalid"),
    ("ntfy", '''
[watch.channels.ntfy]
type = "ntfy"
server = "https://ntfy.example.invalid"
topic = "alerts"
token_env = "NTFY_TOKEN"
''', "g0_server", "https://attacker.example.invalid"),
    ("gotify", '''
[watch.channels.gotify]
type = "gotify"
server = "https://gotify.example.invalid"
app_token_env = "GOTIFY_TOKEN"
''', "g0_server", "https://attacker.example.invalid"),
])
def test_credential_destination_change_requires_manage_secrets(
        accounts, monkeypatch, kind, channel, field, new):
    config, users, app, client = accounts
    if kind == "smtp":
        # An environment reference names the secret; the value is never needed.
        channel = _smtp(name="mail", reference="password_env")
    config.config_path.write_text(channel_config(channel), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    page = client.get("/config/channels")
    assert page.status_code == 200, page.text
    assert 'name="g0_host" value="smtp.example.invalid" readonly' in page.text or kind != "smtp"
    before = config.config_path.read_bytes()
    response = preview(client, "channels", **{field: new})
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before

    login(client, "admin")
    response = preview(client, "channels", **{field: new})
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    assert load_config(config.config_path).watch.channels[0].options


def test_adding_an_existing_credential_to_a_channel_needs_manage_secrets(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "shared-password", "synthetic password")
    config.config_path.write_text(channel_config(f'''
[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]

[watch.channels.other]
type = "smtp"
host = "smtp2.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_file = "{secret.name}"
'''), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "channels", g0_password_file=secret.name)
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_webhook_header_credential_destination_requires_manage_secrets(accounts, monkeypatch):
    config, users, app, client = accounts
    monkeypatch.setenv("HOOK_URL", "https://example.invalid/hook")
    config.config_path.write_text(channel_config('''
[watch.channels.hook]
type = "webhook"
url_env = "HOOK_URL"
header_name = "X-Token"
header_value_env = "HOOK_TOKEN"
'''), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    page = client.get("/config/channels")
    assert page.status_code == 200
    assert 'name="g0_allow_insecure"' in page.text
    before = config.config_path.read_bytes()
    assert preview(client, "channels", g0_allow_insecure="true").status_code == 403
    assert config.config_path.read_bytes() == before
    # Any edit of a credential-bearing channel requires manage_secrets.
    assert preview(client, "channels", g0_max_items="7").status_code == 403

    login(client, "admin")
    response = preview(client, "channels", g0_allow_insecure="true")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303


def test_channel_without_a_secret_keeps_destination_editable(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(channel_config('''
[watch.channels.ntfy]
type = "ntfy"
server = "https://ntfy.example.invalid"
topic = "alerts"
'''), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", g0_server="https://ntfy2.example.invalid")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303


def test_credential_destination_rechecked_in_commit_transaction(accounts, monkeypatch):
    config, users, app, client = accounts
    config.config_path.write_text(channel_config(_smtp(reference="password_env")), encoding="utf-8")
    login(client, "admin")
    response = preview(client, "channels", g0_host="attacker.example.invalid")
    assert response.status_code == 200, response.text
    real_permissions = app.extensions["dashboard_users"].permissions_in

    def without_manage(db, user):
        return real_permissions(db, user) - {"manage_secrets"}

    monkeypatch.setattr(app.extensions["dashboard_users"], "permissions_in", without_manage)
    before = config.config_path.read_bytes()
    saved = confirm(client, response, "channels")
    assert saved.status_code == 403
    assert config.config_path.read_bytes() == before


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal", ".lock"])
def test_operational_paths_reject_account_sidecars(accounts, suffix):
    config, users, _, client = accounts
    account = config.watch.users_database
    sidecar = account.with_name(account.name + suffix)
    login(client, "admin")
    for section, field, value in (
            ("system", "g0_database", str(sidecar / "state.db")),
            ("system", "g1_directory", str(sidecar)),
            ("watch", "g0_database", str(sidecar))):
        before = config.config_path.read_bytes()
        response = preview(client, section, **{field: value})
        assert response.status_code == 400, (section, field, suffix, response.text)
        assert config.config_path.read_bytes() == before


def test_operational_paths_reject_config_lock_secret_and_inventory(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "channel-password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=secret.name)), encoding="utf-8")
    lock = config.config_path.with_name(".config-" + config.config_path.name + ".lock")
    protected = [lock, secret, config.inventory.path,
                 config.watch.users_database.with_name(config.watch.users_database.name + "-wal")]
    login(client, "admin")
    for target in protected:
        before = config.config_path.read_bytes()
        response = preview(client, "system", g0_database=str(target))
        assert response.status_code == 400, (target, response.text)
        assert config.config_path.read_bytes() == before


def test_credential_channel_repoint_needs_manage_secrets(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(channel_config('''
[watch.channels.alpha]
type = "smtp"
host = "alpha.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_env = "PASS_A"

[watch.channels.beta]
type = "smtp"
host = "beta.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_env = "PASS_B"
'''), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    before = config.config_path.read_bytes()
    assert preview(client, "channels", g1_password_env="PASS_A").status_code == 403
    assert preview(client, "channels", g0_password_env="PASS_B",
                   g1_password_env="PASS_A").status_code == 403
    assert config.config_path.read_bytes() == before


def test_credential_channel_file_repoint_needs_manage_secrets(accounts):
    config, users, _, client = accounts
    first = make_secret(config.config_path.parent / "first-password", "first synthetic")
    second = make_secret(config.config_path.parent / "second-password", "second synthetic")
    config.config_path.write_text(channel_config(_smtp(reference="password_file")), encoding="utf-8")
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8").replace(
            'password_file = "password_file"', f'password_file = "{first.name}"'),
        encoding="utf-8")
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8") +
        f'\n[watch.channels.other]\ntype = "smtp"\nhost = "other.example.invalid"\n'
        f'from = "sender@example.invalid"\nto = ["soc@example.invalid"]\n'
        f'password_file = "{second.name}"\n', encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    page = client.get("/config/channels")
    assert page.status_code == 200
    assert "This channel carries a credential" in page.text
    assert 'name="g0_password_file_new"' not in page.text
    before = config.config_path.read_bytes()
    assert preview(client, "channels", g1_password_file=first.name).status_code == 403
    assert config.config_path.read_bytes() == before


def test_rollback_to_a_repointed_channel_needs_manage_secrets(accounts):
    config, users, app, client = accounts
    config.config_path.write_text(channel_config('''
[watch.channels.alpha]
type = "smtp"
host = "alpha.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_env = "PASS_A"

[watch.channels.beta]
type = "smtp"
host = "beta.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_env = "PASS_B"
'''), encoding="utf-8")
    login(client, "admin")
    assert confirm(client, preview(client, g0_retries="4")).status_code == 303
    login(client, "admin")
    original = config.config_path.read_text(encoding="utf-8")
    config.config_path.write_text(original.replace('"password_env" = "PASS_A"', '"password_env" = "TEMP_A"')
                                  .replace('"password_env" = "PASS_B"', '"password_env" = "PASS_A"')
                                  .replace('"password_env" = "TEMP_A"', '"password_env" = "PASS_B"'),
                                  encoding="utf-8")
    set_role(users, "all-editor", set(dc.SECTIONS.values()) | {"view"})
    login(client)
    page = client.get("/config/backups")
    assert page.status_code == 200
    data = form(page.text)
    data["backup"] = sorted(app.extensions["dashboard_config"].backups())[0]
    response = client.post("/config/backups", data=data)
    assert response.status_code == 403


def test_webhook_url_rotation_requires_manage_secrets(accounts):
    config, users, _, client = accounts
    url = make_secret(config.config_path.parent / "url-secret",
                      "https://example.invalid/hook")
    header = make_secret(config.config_path.parent / "header-secret", "synthetic header")
    config.config_path.write_text(channel_config(f'''
[watch.channels.hook]
type = "webhook"
url_file = "{url.name}"
header_name = "X-Token"
header_value_file = "{header.name}"
'''), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "channels", g0_url_file_new="https://attacker.example.invalid/hook")
    assert response.status_code in {400, 403}
    assert "manage_secrets" in response.text or response.status_code == 403
    assert url.read_text(encoding="utf-8").startswith("https://example.invalid/")
    assert header.read_text(encoding="utf-8") == "synthetic header"
    assert config.config_path.read_bytes() == before


def test_inventory_input_cannot_alias_protected_storage(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "channel-password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=secret.name)), encoding="utf-8")
    login(client, "admin")
    jobs = config.database_path.parent / "dashboard-jobs" / "dashboard-jobs.db"
    for target in (secret, config.watch.users_database,
                   config.database_path, jobs, config.config_path):
        before = config.config_path.read_bytes()
        response = preview(client, "inventory", g0_path=str(target))
        assert response.status_code == 400, (target, response.text)
        assert config.config_path.read_bytes() == before


def test_missing_live_file_can_be_restored_from_a_backup(accounts):
    config, users, app, client = accounts
    original = load_config(config.config_path)
    _create_backup(config, client)
    backup = app.extensions["dashboard_config"].backups()[0]
    config.config_path.unlink()
    assert client.get("/config/backups").status_code == 200
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text
    assert "Current configuration is invalid or missing" in response.text
    confirm_data = form(response.text, "confirm")
    confirm_data["lockout"] = "yes"
    assert client.post("/config/backups", data=confirm_data).status_code == 303
    assert config.config_path.exists()
    assert load_config(config.config_path).http.retries == original.http.retries


@pytest.mark.parametrize("damage", [
    '\n[unknown]\nvalue = "SyntheticUnknownSecret"\n',
    '\n[watch.channels.bad]\ntype = "ntfy"\ntopic = "alerts"\nunknown = "SyntheticUnknownSecret"\n',
])
def test_invalid_live_file_rollback_hides_unvalidated_values(accounts, damage):
    config, users, app, client = accounts
    original = load_config(config.config_path)
    _create_backup(config, client)
    backup = app.extensions["dashboard_config"].backups()[0]
    config.config_path.write_text(config.config_path.read_text(encoding="utf-8") + damage,
                                  encoding="utf-8")
    set_role(users, "all-editor", set(dc.SECTIONS.values()) | {"view"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text
    assert "Current configuration is invalid or missing" in response.text
    assert "SyntheticUnknownSecret" not in response.text
    confirm_data = form(response.text, "confirm")
    confirm_data["lockout"] = "yes"
    assert client.post("/config/backups", data=confirm_data).status_code == 303
    assert load_config(config.config_path).http.retries == original.http.retries


def test_configuration_writer_lock_is_created_lazily(accounts):
    config, _, _, client = accounts
    lock = config.config_path.with_name(".config-" + config.config_path.name + ".lock")
    assert not lock.exists()
    login(client, "admin")
    assert not lock.exists()
    assert client.get("/config/").status_code == 200
    assert lock.exists()


def test_channel_reference_removal_requires_manage_secrets(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(
        BASE.replace('nvd_api_key_env = "NVD_API_KEY"', 'nvd_api_key_env = "CUSTOM_NVD_KEY"'),
        encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    # An environment reference is not a filesystem path; removal still needs
    # manage_secrets.
    set_role(users, "source-editor", {"view", "edit_sources"})
    login(client)
    before = config.config_path.read_bytes()
    assert preview(client, "sources", g0_nvd_api_key_env="").status_code == 403
    assert config.config_path.read_bytes() == before

    set_role(users, "source-manager", {"view", "edit_sources", "manage_secrets"})
    login(client)
    response = preview(client, "sources", g0_nvd_api_key_env="")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "sources").status_code == 303


@pytest.mark.parametrize("damage", [
    'watch = "broken"\n',
    '\n[watch]\nchannels = "broken"\n',
])
def test_malformed_live_table_shapes_do_not_block_rollback(accounts, monkeypatch, damage):
    config, users, app, client = accounts
    original = load_config(config.config_path)
    _create_backup(config, client)
    backup = app.extensions["dashboard_config"].backups()[0]
    text = config.config_path.read_text(encoding="utf-8")
    config.config_path.write_text(
        damage + text if damage.startswith("watch") else text + damage,
        encoding="utf-8",
    )
    set_role(users, "all-editor", set(dc.SECTIONS.values()) | {"view"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text
    assert "Current configuration is invalid or missing" in response.text

    login(client, "admin")
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text

    confirm_data = form(response.text, "confirm")
    confirm_data["lockout"] = "yes"
    assert client.post("/config/backups", data=confirm_data).status_code == 303
    assert load_config(config.config_path).http.retries == original.http.retries


def test_staged_secret_contents_require_manage_secrets_at_commit(accounts, monkeypatch):
    config, users, app, client = accounts
    secret = make_secret(config.config_path.parent / "nvd-key", "old value")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_file_new="new value")
    assert response.status_code == 200, response.text
    dashboard_users = app.extensions["dashboard_users"]
    real_permissions = dashboard_users.permissions_in

    def without_manage(db, user):
        return real_permissions(db, user) - {"manage_secrets"}

    monkeypatch.setattr(dashboard_users, "permissions_in", without_manage)
    before = config.config_path.read_bytes()
    saved = confirm(client, response, "sources")
    assert saved.status_code == 403
    assert secret.read_text(encoding="utf-8") == "old value"
    assert config.config_path.read_bytes() == before


def test_credential_channel_textareas_render_read_only(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=secret.name)), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    page = client.get("/config/channels")
    assert page.status_code == 200
    assert re.search(r'name="g0_to"[^>]*readonly', page.text)


def test_explicit_empty_strings_do_not_block_unrelated_channel_edits(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(channel_config('''
[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
username = ""
password_env = "SMTP_PASSWORD"

[watch.channels.alerts]
type = "ntfy"
server = "https://ntfy.example.invalid"
topic = "alerts"
'''), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", g1_max_items="7")
    assert response.status_code == 200, response.text


def test_dashboard_settings_require_administrator(accounts):
    config, users, _, client = accounts
    set_role(users, "dashboard-editor", {"view", "edit_dashboard"})
    login(client)
    page = client.get("/config/dashboard")
    assert page.status_code == 200
    assert 'name="g0_secure_cookie"' in page.text
    assert "administrator-only" in page.text
    response = preview(client, "dashboard", g0_secure_cookie="true")
    assert response.status_code == 403

    login(client, "admin")
    response = preview(client, "dashboard", g0_secure_cookie="true")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "dashboard", lockout="yes").status_code == 303


def test_same_directory_database_renames_are_not_storage_moves(accounts):
    config, users, _, client = accounts
    login(client, "admin")
    for section, field, value in (("system", "g0_database", "state2.db"),
                                  ("watch", "g0_database", "watch2.db")):
        response = preview(client, section, **{field: value})
        assert response.status_code == 200, (section, response.text)
        assert confirm(client, response, section, lockout="yes").status_code == 303
        login(client, "admin")


def test_manage_secrets_can_rename_a_file_reference_channel(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=secret.name)), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "channel-manager", {"view", "edit_channels", "manage_secrets"})
    login(client)
    response = preview(client, "channels", g0_name="renamed")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    assert [channel.name for channel in load_config(config.config_path).watch.channels] == ["renamed"]


@pytest.mark.parametrize("damage", ["missing", "unparseable", "minimal"])
def test_delegated_manage_can_restore_missing_or_unparseable_live_file(accounts, damage):
    config, users, app, client = accounts
    original = load_config(config.config_path)
    _create_backup(config, client)
    backup = app.extensions["dashboard_config"].backups()[0]
    if damage == "missing":
        config.config_path.unlink()
    elif damage == "unparseable":
        config.config_path.write_text("[http\n", encoding="utf-8")
    else:
        config.config_path.write_text('watch = "broken"\n', encoding="utf-8")
    set_role(users, "all-manager", set(dc.SECTIONS.values()) | {"view", "manage_secrets"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text
    confirm_data = form(response.text, "confirm")
    confirm_data["lockout"] = "yes"
    assert client.post("/config/backups", data=confirm_data).status_code == 303
    assert load_config(config.config_path).http.retries == original.http.retries


def test_admin_file_secret_help_mentions_content_replacement(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "nvd-key", "synthetic key")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    login(client, "admin")
    page = client.get("/config/sources")
    assert page.status_code == 200
    assert "Replace the contents of the existing owner-only file" in page.text
    assert "A new owner-only file is staged" not in page.text


def test_external_deleted_channel_secret_is_administrator_responsibility(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "channel-password",
                         "asset_id,vendor,product,version\na,Acme,Widget,1\n")
    config.config_path.write_text(channel_config(_smtp(reference=secret.name)), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", remove0="yes")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303

    set_role(users, "inventory-editor", {"view", "edit_inventory"})
    login(client)
    assert preview(client, "inventory", g0_path=str(secret)).status_code == 403

    login(client, "admin")
    response = preview(client, "inventory", g0_path=str(secret))
    assert response.status_code == 200, response.text


def test_dashboard_missing_live_rollback_rejects_default_signing_settings(accounts):
    config, users, app, client = accounts
    config.config_path.write_text('[dashboard]\nsecure_cookie = true\n\n' + BASE,
                                  encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    editor = app.extensions["dashboard_config"]
    backup = _manual_backup(editor, BASE)
    config.config_path.unlink()
    set_role(users, "all-manager", set(dc.SECTIONS.values()) | {"view", "manage_secrets"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 403


def _manual_backup(editor, text):
    editor.backup_dir.mkdir(mode=0o700, exist_ok=True)
    name = "20260101T000000000000Z-0123456789abcdef.toml"
    path = editor.backup_dir / name
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)
    return name


def test_loader_normalised_paths_cannot_bypass_administrator_boundary(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(
        BASE.replace('database = "state.db"', 'database = "state.db"').replace(
            '[state]', '[state]').replace(
            '[output]\ndirectory = "reports"',
            '[output]\ndirectory = "reports"\n\n[watch]\ndatabase = "watch.db "'),
        encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "watch-editor", {"view", "edit_watch"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "watch", g0_database="watch.db /.")
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_loader_normalised_file_reference_cannot_bypass_administrator_boundary(
        accounts, tmp_path):
    config, users, _, client = accounts
    inside_path = config.config_path.parent / "tmp" / "outside-key"
    inside_path.parent.mkdir(parents=True, exist_ok=True)
    inside = make_secret(inside_path, "inside synthetic")
    outside = make_secret(tmp_path.parents[2] / "outside-key", "outside synthetic")
    config.config_path.write_text(with_file(config, inside), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "source-manager", {"view", "edit_sources", "manage_secrets"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "sources", g0_nvd_api_key_file=" /.." + str(outside))
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_dashboard_rollback_cannot_change_signing_settings(accounts):
    config, users, app, client = accounts
    dashboard_text = '[dashboard]\nsecure_cookie = true\n\n'
    config.config_path.write_text(dashboard_text + BASE, encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    editor = app.extensions["dashboard_config"]
    # The retained backup omits [dashboard], so it restores the loader defaults.
    backup = _manual_backup(editor, BASE)
    config.config_path.write_text('watch = "broken"\n' + config.config_path.read_text(),
                                  encoding="utf-8")
    set_role(users, "all-editor", set(dc.SECTIONS.values()) | {"view"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    assert client.post("/config/backups", data=data).status_code == 403

    login(client, "admin")
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text


def test_dashboard_rollback_allows_matching_signing_settings(accounts):
    config, users, app, client = accounts
    config.config_path.write_text('[dashboard]\nsecure_cookie = true\n\n' + BASE,
                                  encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    editor = app.extensions["dashboard_config"]
    backup = _manual_backup(editor, '[dashboard]\nsecure_cookie = true\n\n' + BASE)
    config.config_path.unlink()
    set_role(users, "all-manager", set(dc.SECTIONS.values()) | {"view", "manage_secrets"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text


def test_dashboard_defaults_beside_state_allow_delegated_rollback(accounts):
    config, users, app, client = accounts
    config.config_path.write_text(
        BASE.replace('[state]\ndatabase = "state.db"',
                     '[state]\ndatabase = ".cvebeacon/state.db"'), encoding="utf-8")
    loaded = load_config(config.config_path)
    users = UserStore(loaded.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    users.add("reader", password=PASSWORD)
    client = dashboard.create_app(loaded).test_client()
    _create_backup(config, client)
    set_role(users, "all-manager", set(dc.SECTIONS.values()) | {"view", "manage_secrets"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = app.extensions["dashboard_config"].backups()[0]
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text


def test_explicit_empty_output_directory_is_administrator_only(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(
        BASE.replace('[output]\ndirectory = "reports"', '[output]\ndirectory = ""'),
        encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "system-editor", {"view", "edit_system"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "system", g1_directory="reports")
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_rollback_that_removes_a_credential_channel_is_a_deletion(accounts):
    config, users, app, client = accounts
    secret = make_secret(config.config_path.parent / "password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=str(secret))),
                                  encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    editor = app.extensions["dashboard_config"]
    backup = _manual_backup(editor, BASE)
    set_role(users, "all-editor", set(dc.SECTIONS.values()) | {"view"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    assert client.post("/config/backups", data=data).status_code == 200


def test_path_fields_require_an_administrator(accounts, tmp_path):
    config, users, _, client = accounts
    set_role(users, "path-editor", {"view", *dc.SECTIONS.values(), "manage_secrets"})
    login(client)
    for section, field in (("system", "g0_database"), ("system", "g1_directory"),
                           ("watch", "g0_database"), ("inventory", "g0_path")):
        page = client.get("/config/" + section)
        assert page.status_code == 200
        assert re.search(rf'name="{field}"[^>]*readonly', page.text)
        response = preview(client, section, **{field: str(tmp_path / "moved" / "value")})
        assert response.status_code == 403, (section, field, response.text)

    secret = make_secret(config.config_path.parent / "nvd-key", "synthetic key")
    other = make_secret(tmp_path / "other-key", "other key")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    login(client)
    response = preview(client, "sources", g0_nvd_api_key_file=str(other))
    assert response.status_code == 403


@pytest.mark.parametrize("relative", [
    "cvebeacon-run.lock",
    "state.db-wal",
    "dashboard-jobs/job-1.log",
])
def test_candidate_derived_storage_cannot_overlap_a_secret(accounts, relative):
    config, _, _, client = accounts
    target = config.config_path.parent / "moved" / relative
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret = make_secret(target, "synthetic credential")
    config.config_path.write_text(channel_config(_smtp(reference=str(secret))), encoding="utf-8")
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "system", g0_database=str(config.config_path.parent / "moved" / "state.db"))
    assert response.status_code == 400, response.text
    assert "derived dashboard storage" in response.text
    assert config.config_path.read_bytes() == before


def test_deleting_a_credential_channel_keeps_its_secret_directory_file_protected(accounts):
    config, users, _, client = accounts
    secret_directory = config.watch.users_database.parent / "dashboard-secrets"
    secret_directory.mkdir(mode=0o700, exist_ok=True)
    secret = make_secret(secret_directory / "channel-password",
                         "asset_id,vendor,product,version\na,Acme,Widget,1\n")
    config.config_path.write_text(channel_config(_smtp(reference=str(secret))), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", remove0="yes")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303

    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "inventory", g0_path=str(secret))
    assert response.status_code == 400, response.text
    assert config.config_path.read_bytes() == before


def test_operational_paths_reject_dashboard_jobs_storage(accounts):
    config, users, _, client = accounts
    jobs = config.database_path.parent / "dashboard-jobs"
    protected = [
        jobs,
        jobs / "dashboard-jobs.db",
        jobs / "job-1.log",
        config.database_path.parent / LOCK_NAME,
        config.watch.database.parent / LOCK_NAME,
    ]
    login(client, "admin")
    for target in protected:
        before = config.config_path.read_bytes()
        response = preview(client, "system", g0_database=str(target))
        assert response.status_code == 400, (target, response.text)
        assert config.config_path.read_bytes() == before


def test_secret_rotation_rejects_dashboard_jobs_storage(accounts):
    config, users, _, client = accounts
    jobs = config.database_path.parent / "dashboard-jobs"
    jobs.mkdir(mode=0o700, exist_ok=True)
    secret = make_secret(jobs / "job-secret", "synthetic job storage")
    config.config_path.write_text(channel_config(_smtp(reference=str(secret))), encoding="utf-8")
    login(client, "admin")
    response = preview(client, "channels", g0_password_file_new="replacement")
    assert response.status_code == 400
    assert secret.read_text(encoding="utf-8") == "synthetic job storage"


def test_operational_paths_cannot_alias_each_other(accounts):
    config, users, _, client = accounts
    login(client, "admin")
    watch = load_config(config.config_path).watch.database
    response = preview(client, "system", g0_database=str(watch))
    assert response.status_code == 400
    assert "state.database" in response.text


def test_shared_file_with_environment_consumer_validates_staged_bytes(accounts, monkeypatch):
    config, users, _, client = accounts
    monkeypatch.setenv("SLACK_URL", "https://hooks.slack.com/services/TEST/TEST/TEST")
    secret = make_secret(
        config.config_path.parent / "shared-url",
        "https://hooks.slack.com/services/TEST/TEST/TEST",
    )
    config.config_path.write_text(channel_config(f'''
[watch.channels.slack]
type = "slack"
webhook_url_env = "SLACK_URL"
webhook_url_file = "{secret.name}"

[watch.channels.teams]
type = "teams"
webhook_url_file = "{secret.name}"
'''), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "channel-editor", {"view", "edit_channels", "manage_secrets"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "channels",
                       g1_webhook_url_file_new="https://example.invalid/teams-only")
    assert response.status_code == 400, response.text
    assert secret.read_text(encoding="utf-8").startswith("https://hooks.slack.com/")
    assert config.config_path.read_bytes() == before

    # A URL valid for both consumers is accepted and remains loadable when the
    # environment variable is later absent.
    response = preview(client, "channels",
                       g1_webhook_url_file_new="https://hooks.slack.com/services/NEW/NEW/NEW")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    monkeypatch.delenv("SLACK_URL")
    assert load_config(config.config_path).watch.channels


def test_reference_change_is_rejected_before_any_target_read(accounts, monkeypatch):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "nvd-key", "synthetic key")
    other = make_secret(config.config_path.parent / "other-nvd-key", "other key")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "source-editor", {"view", "edit_sources"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "sources", g0_nvd_api_key_file=str(other))
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_reference_permission_is_rechecked_before_commit_preparation(accounts, monkeypatch):
    config, users, app, client = accounts
    first = make_secret(config.config_path.parent / "nvd-key", "synthetic key")
    second = make_secret(config.config_path.parent / "other-key", "other synthetic key")
    config.config_path.write_text(with_file(config, first), encoding="utf-8")
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_file=str(second))
    assert response.status_code == 200, response.text
    real_permissions = app.extensions["dashboard_users"].permissions_in

    def without_manage(db, user):
        return real_permissions(db, user) - {"manage_secrets"}

    def forbidden(*args, **kwargs):
        raise AssertionError("new reference target was prepared before the permission check")

    monkeypatch.setattr(app.extensions["dashboard_users"], "permissions_in", without_manage)
    monkeypatch.setattr(dc, "replacement_document", forbidden)
    before = config.config_path.read_bytes()
    saved = confirm(client, response, "sources")
    assert saved.status_code == 403
    assert config.config_path.read_bytes() == before


def _create_backup(config, client):
    login(client, "admin")
    response = preview(client, g0_retries="4")
    assert response.status_code == 200
    assert confirm(client, response).status_code == 303
    login(client, "admin")
    return response


def test_invalid_current_file_can_be_recovered_through_a_backup(accounts):
    config, users, app, client = accounts
    original = load_config(config.config_path)
    _create_backup(config, client)
    editor = app.extensions["dashboard_config"]
    backup = editor.backups()[0]
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8").replace(
            '"retries" = 4', '"retries" = -1'),
        encoding="utf-8",
    )
    assert client.get("/config/backups").status_code == 200
    assert "Current configuration is invalid or missing" in client.get("/config/backups").text
    assert client.get("/config/http").status_code == 400
    # A delegated editor without manage_secrets may still restore a parseable
    # but loader-invalid file after the access confirmation.
    set_role(users, "all-editor", set(dc.SECTIONS.values()) | {"view"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text
    assert 'name="lockout"' in response.text
    confirm_data = form(response.text, "confirm")
    assert client.post("/config/backups", data=confirm_data).status_code == 400
    confirm_data["lockout"] = "yes"
    assert client.post("/config/backups", data=confirm_data).status_code == 303
    assert load_config(config.config_path).http.retries == original.http.retries


def test_unparseable_current_file_requires_manage_secrets_for_rollback(accounts):
    config, users, app, client = accounts
    _create_backup(config, client)
    editor = app.extensions["dashboard_config"]
    backup = editor.backups()[0]
    config.config_path.write_text("[http\nretries = 4\n", encoding="utf-8")
    assert client.get("/config/backups").status_code == 200

    set_role(users, "all-editor", set(dc.SECTIONS.values()) | {"view"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    assert client.post("/config/backups", data=data).status_code == 403

    login(client, "admin")
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text
    assert 'name="lockout"' in response.text
    confirm_data = form(response.text, "confirm")
    confirm_data["lockout"] = "yes"
    assert client.post("/config/backups", data=confirm_data).status_code == 303
    assert load_config(config.config_path).http.retries == 3


def test_missing_current_secret_file_does_not_block_backups(accounts):
    config, _, app, client = accounts
    _create_backup(config, client)
    secret = config.config_path.parent / "missing-password"
    secret.write_text("temporary synthetic value", encoding="utf-8")
    secret.chmod(0o600)
    config.config_path.write_text(channel_config(_smtp(reference=secret.name)), encoding="utf-8")
    secret.unlink()
    assert client.get("/config/backups").status_code == 200
    assert client.get("/config/channels").status_code == 400


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes block writes")
def test_read_only_configuration_directory_shows_notice_and_blocks_saves(accounts):
    config, _, _, client = accounts
    login(client, "admin")
    directory = config.config_path.parent
    mode = directory.stat().st_mode & 0o777
    os.chmod(directory, 0o500)
    try:
        page = client.get("/config/")
        assert page.status_code == 200 and "Read-only configuration" in page.text
        page = client.get("/config/http")
        assert page.status_code == 200 and "Read-only configuration" in page.text
        data = form(page.text)
        before = config.config_path.read_bytes()
        response = client.post("/config/http", data=data)
        assert response.status_code == 400
        assert "read-only" in response.text.lower()
        assert config.config_path.read_bytes() == before
        page = client.get("/config/backups")
        assert page.status_code == 200 and "Rollback is disabled" in page.text
        data = form(page.text)
        response = client.post("/config/backups", data=data)
        assert response.status_code == 400
        assert "read-only" in response.text.lower()
    finally:
        os.chmod(directory, mode)


def test_channel_names_that_look_like_references_stay_editable(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(channel_config('''
[watch.channels.data_env]
type = "ntfy"
server = "https://ntfy.example.invalid"
topic = "alerts"

[watch.channels.data_file]
type = "ntfy"
server = "https://ntfy.example.invalid"
topic = "alerts"

[watch.channels.data_url]
type = "ntfy"
server = "https://ntfy.example.invalid"
topic = "alerts"
'''), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    page = client.get("/config/channels")
    assert page.status_code == 200, page.text
    response = preview(client, "channels", g0_max_items="7")
    assert response.status_code == 200, response.text
    assert "data_env" in response.text and "data_file" in response.text and "data_url" in response.text
    assert confirm(client, response, "channels").status_code == 303


def test_credential_channel_rename_needs_manage_but_delete_does_not(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=secret.name)), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", g0_name="renamed")
    assert response.status_code == 403
    assert "manage_secrets" in response.text or response.status_code == 403

    response = preview(client, "channels", remove0="yes")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    assert load_config(config.config_path).watch.channels == ()


def test_no_secret_channel_rename_still_needs_only_edit_channels(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(channel_config(
        '[watch.channels.alerts]\ntype = "ntfy"\nserver = "https://ntfy.example.invalid"\ntopic = "alerts"\n'
    ), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", g0_name="renamed")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    assert [channel.name for channel in load_config(config.config_path).watch.channels] == ["renamed"]


def test_legacy_direct_webhook_converts_to_a_reference(accounts, monkeypatch):
    config, users, _, client = accounts
    monkeypatch.setenv("HOOK_URL", "https://example.invalid/converted")
    config.config_path.write_text(channel_config('''
[watch.channels.hook]
type = "webhook"
url = "https://example.invalid/legacy"
'''), encoding="utf-8")
    login(client, "admin")
    response = preview(client, "channels", g0_url="", g0_url_env="HOOK_URL")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    document = tomllib.loads(config.config_path.read_text(encoding="utf-8"))
    assert document["watch"]["channels"]["hook"]["url_env"] == "HOOK_URL"
    assert "url" not in document["watch"]["channels"]["hook"]

    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", g0_url_env="OTHER_HOOK_URL")
    assert response.status_code == 403


def test_status_errors_render_configuration_guidance(accounts):
    config, _, _, client = accounts
    login(client, "admin")
    response = preview(client, g0_retries="4")
    config.config_path.write_text(config.config_path.read_text() + "\n# external edit\n",
                                  encoding="utf-8")
    data = form(response.text, "confirm")
    response = client.post("/config/http", data=data)
    assert response.status_code == 409
    assert "Configuration changed" in response.text


def test_channel_and_rule_schemas_expose_every_known_field():
    for kind, type_keys in dc.TYPE_KEYS.items():
        groups = dc.groups_for("channels", {}, row_types=[kind], count=1)
        keys = {control["key"] for control in groups[0]["controls"]}
        assert dc.COMMON_KEYS | type_keys <= keys
    groups = dc.groups_for("rules", {}, count=1)
    assert set(dc.RULE_FIELDS) <= {control["key"] for control in groups[0]["controls"]}


def test_safe_error_keeps_schema_names(tmp_path):
    error = ConfigurationError("[product_mappings] entry 1 must use a CPE 2.3 name")
    message = dc.safe_error(error, {"product_mappings": [{"vendor": "acme", "product": "widget", "cpe": "bad"}]},
                            tmp_path / "config.toml")
    assert "CPE 2.3 name" in message
    assert "acme" not in message and "widget" not in message
    message = dc.safe_error(ConfigurationError("[state] must be a table"),
                            {"state": {"database": "state.db"}}, tmp_path / "config.toml")
    assert "state" in message and "[value] must be a table" not in message


@pytest.mark.skipif(os.name != "posix",
                    reason="Windows drops trailing spaces from file names")
def test_rotation_uses_loader_resolved_file_target(accounts):
    config, users, _, client = accounts
    effective = make_secret(config.config_path.parent / "credential", "old effective")
    shadow = make_secret(config.config_path.parent / "credential ", "shadow")
    config.config_path.write_text(
        BASE.replace('nvd_api_key_env = "NVD_API_KEY"\n',
                     'nvd_api_key_file = "credential "\n'), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "source-manager", {"view", "edit_sources", "manage_secrets"})
    login(client)
    response = preview(client, "sources", g0_nvd_api_key_file_new="new effective")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "sources").status_code == 303
    assert effective.read_text(encoding="utf-8") == "new effective"
    assert shadow.read_text(encoding="utf-8") == "shadow"


def test_shared_consumer_uses_loader_resolved_file_target(accounts):
    config, users, _, client = accounts
    shared = make_secret(config.config_path.parent / "shared",
                         "https://hooks.slack.com/services/TEST/TEST/TEST")
    config.config_path.write_text(
        BASE.replace('nvd_api_key_env = "NVD_API_KEY"\n',
                     'nvd_api_key_file = "shared"\n')
        + '''
[watch.channels.slack]
type = "slack"
webhook_url_file = "shared "
''', encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "source-manager", {"view", "edit_sources", "manage_secrets"})
    login(client)
    before = shared.read_text(encoding="utf-8")
    response = preview(client, "sources", g0_nvd_api_key_file_new="not a URL")
    assert response.status_code == 400, response.text
    assert shared.read_text(encoding="utf-8") == before


def test_legacy_notification_channels_are_credential_bearing(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(
        BASE + '''
[notifications.email]
enabled = true
sender = "sender@example.invalid"
recipients = ["soc@example.invalid"]
''', encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    page = client.get("/config/notifications")
    assert page.status_code == 200
    assert "Legacy notification channels are credential-bearing" in page.text
    before = config.config_path.read_bytes()
    response = preview(client, "notifications", g1_sender="changed@example.invalid")
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_stale_live_credential_change_needs_manage_secrets(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=str(secret))),
                                  encoding="utf-8")
    # The app still runs the older BASE configuration; the live file gained a
    # credential-bearing channel through an external edit.
    set_role(users, "http-editor", {"view", "edit_http"})
    login(client)
    response = preview(client, "http", g0_retries="4")
    assert response.status_code == 403


def test_malformed_notification_baseline_needs_manage_secrets(accounts):
    config, users, app, client = accounts
    config.config_path.write_text(
        BASE + '''
[notifications.teams]
webhook_env = "CUSTOM_TEAMS_URL"
''', encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    editor = app.extensions["dashboard_config"]
    backup = _manual_backup(editor, BASE)
    config.config_path.write_text('notifications = "broken"\n' + BASE, encoding="utf-8")
    set_role(users, "all-editor", set(dc.SECTIONS.values()) | {"view"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    assert client.post("/config/backups", data=data).status_code == 403


def test_dashboard_container_mounts_read_only_secrets_and_owner():
    root = Path(__file__).resolve().parents[1]
    compose = (root / "deploy" / "container" / "compose.yml").read_text(encoding="utf-8")
    dashboard = compose.split("dashboard:", 1)[1]
    assert "- ./secrets:/config/secrets:ro" in dashboard
    deploy = (root / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
    assert "install -o 65532 -g 65532 -m 0644" in deploy


def test_stale_live_destination_change_needs_manage_secrets(accounts):
    config, users, _, client = accounts
    original = channel_config(_smtp(reference="password_env")) .replace(
        'password_env = "SMTP_PASSWORD"', 'password_env = "SMTP_PASSWORD"')
    config.config_path.write_text(original, encoding="utf-8")
    app = dashboard.create_app(load_config(config.config_path))
    client = app.test_client()
    # External edit changes the destination while the process still runs the
    # previous configuration.
    config.config_path.write_text(original.replace(
        'host = "smtp.example.invalid"', 'host = "attacker.example.invalid"'),
        encoding="utf-8")
    set_role(users, "http-editor", {"view", "edit_http"})
    login(client)
    response = preview(client, "http", g0_retries="4")
    assert response.status_code == 403


def test_watch_only_configuration_editor_saves_and_rolls_back(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(
        BASE.replace('[inventory]\npath = "inventory.csv"\n\n', '')
        + '\n[watch]\nenabled = true\nsources = ["nvd"]\n',
        encoding="utf-8",
    )
    app = dashboard.create_app(load_config(config.config_path))
    client = app.test_client()
    login(client, "admin")
    response = preview(client, "http", g0_retries="4")
    assert response.status_code == 200, response.text
    assert confirm(client, response).status_code == 303
    login(client, "admin")
    assert load_config(config.config_path).inventory is None
    page = client.get("/config/backups")
    assert page.status_code == 200
    data = form(page.text)
    data["backup"] = sorted(app.extensions["dashboard_config"].backups())[0]
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text
    assert confirm(client, response, "backups").status_code == 303


def test_new_reference_target_is_not_read_before_authorization(accounts, monkeypatch):
    config, users, _, client = accounts
    old = make_secret(config.config_path.parent / "old-url",
                      "https://hooks.slack.com/services/OLD/OLD/OLD")
    target = make_secret(config.config_path.parent / "new-url", "invalid private text")
    config.config_path.write_text(channel_config(f'''
[watch.channels.slack]
type = "slack"
webhook_url_file = "{old.name}"
'''), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    real_read = Path.read_text

    def guarded(path, *args, **kwargs):
        if path == target:
            raise AssertionError("new reference target was read before authorization")
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)
    for role, permissions in (
            ("channel-editor", {"view", "edit_channels"}),
            ("channel-manager", {"view", "edit_channels", "manage_secrets"})):
        set_role(users, role, permissions)
        login(client)
        response = preview(client, "channels", g0_webhook_url_file=str(target))
        assert response.status_code == 403


def test_path_identity_removal_requires_administrator(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=str(secret))),
                                  encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "channel-manager", {"view", "edit_channels", "manage_secrets"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "channels", g0_password_file="")
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before

    set_role(users, "inventory-manager", {"view", "edit_inventory"})
    config.config_path.write_text(
        BASE.replace('[output]\ndirectory = "reports"',
                     '[output]\ndirectory = "reports"\n\n[watch]\nenabled = true'),
        encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    login(client)
    response = preview(client, "inventory", g0_path="")
    assert response.status_code == 403

    set_role(users, "source-manager", {"view", "edit_sources", "manage_secrets"})
    source_secret = make_secret(config.config_path.parent / "source-key", "synthetic key")
    config.config_path.write_text(with_file(config, source_secret), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    login(client)
    response = preview(client, "sources", g0_nvd_api_key_file="")
    assert response.status_code == 403


def test_committed_generated_secret_is_never_auto_deleted(accounts):
    config, users, _, client = accounts
    secret_dir = config.watch.users_database.parent / "dashboard-secrets"
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    generated = make_secret(secret_dir / ".dashboard-secret-live",
                            "https://hooks.slack.com/services/LIVE/LIVE/LIVE")
    old = time.time() - dc.PREVIEW_SECONDS - 30
    os.utime(generated, (old, old))
    config.config_path.write_text(channel_config(
        f'[watch.channels.slack]\ntype = "slack"\nwebhook_url_file = "dashboard-secrets/{generated.name} "\n'
    ), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    login(client, "admin")
    assert client.get("/config/").status_code == 200
    assert generated.exists()
    assert load_config(config.config_path).watch.channels


def test_renaming_and_removing_a_credential_reference_is_rejected(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(channel_config(
        '[watch.channels.mail]\ntype = "smtp"\nhost = "smtp.example.invalid"\n'
        'from = "sender@example.invalid"\nto = ["soc@example.invalid"]\n'
        'password_env = "SMTP_PASSWORD"\n'), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "channels", g0_name="renamed", g0_password_env="")
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_renaming_and_removing_a_file_reference_needs_administrator(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=str(secret))),
                                  encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "channel-manager", {"view", "edit_channels", "manage_secrets"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "channels", g0_name="renamed", g0_password_file="")
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_rollback_renamed_credential_free_channel_needs_manage_secrets(accounts):
    config, users, app, client = accounts
    secret = make_secret(config.config_path.parent / "password", "synthetic password")
    config.config_path.write_text(channel_config(_smtp(reference=str(secret))),
                                  encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    editor = app.extensions["dashboard_config"]
    backup = _manual_backup(editor, channel_config('''
[watch.channels.renamed]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
'''))
    set_role(users, "all-editor", set(dc.SECTIONS.values()) | {"view"})
    login(client)
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    assert client.post("/config/backups", data=data).status_code == 403


def test_empty_environment_reference_matches_the_loader(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(channel_config(
        '[watch.channels.mail]\ntype = "smtp"\nhost = "smtp.example.invalid"\n'
        'from = "sender@example.invalid"\nto = ["soc@example.invalid"]\n'
        'password_env = ""\n'), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    login(client, "admin")
    assert client.get("/config/channels").status_code == 200


def test_committed_staged_reference_is_never_auto_deleted(accounts):
    config, users, _, client = accounts
    secret_dir = config.watch.users_database.parent / "dashboard-secrets"
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    staged = make_secret(secret_dir / ".dashboard-staged-live", "synthetic staged")
    old = time.time() - dc.PREVIEW_SECONDS - 30
    os.utime(staged, (old, old))
    config.config_path.write_text(channel_config(
        f'[watch.channels.mail]\ntype = "smtp"\nhost = "smtp.example.invalid"\n'
        f'from = "sender@example.invalid"\nto = ["soc@example.invalid"]\n'
        f'password_file = "dashboard-secrets/{staged.name}"\n'), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    login(client, "admin")
    assert client.get("/config/").status_code == 200
    assert staged.exists()
    assert load_config(config.config_path).watch.channels


def test_backup_only_staged_reference_is_not_deleted(accounts):
    config, _, app, _ = accounts
    editor = app.extensions["dashboard_config"]
    secret_dir = config.watch.users_database.parent / "dashboard-secrets"
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    staged = make_secret(secret_dir / ".dashboard-staged-backup", "synthetic backup staged")
    old = time.time() - dc.PREVIEW_SECONDS - 30
    os.utime(staged, (old, old))
    editor.backup_dir.mkdir(mode=0o700, exist_ok=True)
    backup = editor.backup_dir / "20260101T000000000000Z-0123456789abcdef.toml"
    backup.write_text(channel_config(
        f'[watch.channels.mail]\ntype = "smtp"\nhost = "smtp.example.invalid"\n'
        f'from = "sender@example.invalid"\nto = ["soc@example.invalid"]\n'
        f'password_file = "dashboard-secrets/{staged.name}"\n'), encoding="utf-8")
    os.chmod(backup, 0o600)
    editor.cleanup()
    assert staged.exists()


@pytest.mark.parametrize("damage", [
    b"[http\n\xff\xfe",
    b"[unknown]\nvalue = 1\n[state]\ndatabase = 5\n",
])
def test_undecodable_or_malformed_live_file_keeps_configuration_pages_available(
        accounts, damage):
    # Staged-secret discovery must fail closed and quietly: the section page
    # explains the problem and the backups page stays usable for recovery.
    config, _, _, client = accounts
    login(client, "admin")
    assert client.get("/config/http").status_code == 200
    config.config_path.write_bytes(damage)
    assert client.get("/config/http").status_code == 400
    assert client.get("/config/backups").status_code == 200


def test_whitespace_environment_reference_keeps_a_channel_editable(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(channel_config(
        '[watch.channels.mail]\ntype = "smtp"\nhost = "smtp.example.invalid"\n'
        'from = "sender@example.invalid"\nto = ["soc@example.invalid"]\n'
        'password_env = "   "\n'), encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    page = client.get("/config/channels")
    assert page.status_code == 200
    host = re.search(r'<input[^>]*name="g0_host"[^>]*>', page.text)[0]
    assert "readonly" not in host
    data = form(page.text)
    data["g0_host"] = "smtp2.example.invalid"
    assert client.post("/config/channels", data=data).status_code == 200


def test_whitespace_environment_does_not_block_file_rotation(accounts):
    assert dc.effective_environment({"a": {"b_env": "   "}}, ("a", "b_env")) is None
    assert dc.effective_environment_row({"b_env": " X "}, "b_env", ("watch",)) == "X"
