"""Regressions for the second configuration-editor review round."""

import os
from pathlib import Path
import re
import tomllib

import pytest

from cvebeacon import dashboard_config as dc
from cvebeacon.config import load_config
from cvebeacon.errors import ConfigurationError
from cvebeacon.locking import LOCK_NAME
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
{source} = "{value}"
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
    config.config_path.write_text(BASE, encoding="utf-8")
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
    assert client.post("/config/backups", data=data).status_code == 403

    login(client, "admin")
    page = client.get("/config/backups")
    data = form(page.text)
    data["backup"] = backup
    response = client.post("/config/backups", data=data)
    assert response.status_code == 200, response.text
    assert "Current configuration is invalid or missing" in response.text

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
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", g1_max_items="7")
    assert response.status_code == 200, response.text


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


def test_deleting_a_credential_channel_keeps_its_backup_reference_protected(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "channel-password",
                         "asset_id,vendor,product,version\na,Acme,Widget,1\n")
    config.config_path.write_text(channel_config(_smtp(reference=secret.name)), encoding="utf-8")
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
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    set_role(users, "source-editor", {"view", "edit_sources"})
    login(client)
    before = config.config_path.read_bytes()

    def forbidden(*args, **kwargs):
        raise AssertionError("new reference target was read before the permission check")

    monkeypatch.setattr(dc, "replacement_document", forbidden)
    response = preview(client, "sources",
                       g0_nvd_api_key_file=str(config.config_path.parent / "missing-target"))
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
