"""Regressions for the final independent configuration-editor review."""

import os
from pathlib import Path
import threading
import time

import pytest

from cvebeacon import dashboard, dashboard_config as dc
from cvebeacon.config import load_config
from cvebeacon.dashboard import create_app
from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.delivery import DeliveryFailure
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


@pytest.mark.parametrize("kind,old_url,key", [
    ("slack", "https://hooks.slack.com/services/TEST/TEST/TEST", "webhook_url_file"),
    ("teams", "https://example.invalid/teams-hook", "webhook_url_file"),
    ("discord", "https://discord.com/api/webhooks/TEST/TEST", "webhook_url_file"),
    ("webhook", "https://example.invalid/hook", "url_file"),
])
def test_rotated_file_contents_are_validated(accounts, kind, old_url, key):
    config, users, app, client = accounts
    secret = make_secret(config.config_path.parent / "url-secret", old_url)
    config.config_path.write_text(
        BASE + f'\n[watch.channels.hook]\ntype = "{kind}"\n{key} = "{secret.name}"\n',
        encoding="utf-8",
    )
    set_role(users, "editor", {"view", "edit_channels"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "channels", **{f"g0_{key}_new": "invalid synthetic credential URL"})
    assert response.status_code == 400
    assert secret.read_text(encoding="utf-8") == old_url
    assert config.config_path.read_bytes() == before


def test_new_file_contents_are_validated_before_publish(accounts):
    config, _, app, client = accounts
    login(client, "admin")
    response = preview_channels(client, g0_name="hook", g0_type="webhook",
                               g0_url_file_new="http://example.invalid/not-allowed")
    assert response.status_code == 400
    assert not list((config.watch.users_database.parent / "dashboard-secrets").iterdir())


@pytest.mark.parametrize("symlink", [False, True])
def test_rotation_cannot_overwrite_outside_data_directory(accounts, tmp_path, symlink):
    config, users, app, client = accounts
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir(mode=0o700)
    target = make_secret(outside / "unrelated-private-file", "original synthetic value")
    reference = target
    if symlink:
        reference = tmp_path / "secret-alias"
        reference.symlink_to(target)
    config.config_path.write_text(with_file(config, reference), encoding="utf-8")
    set_role(users, "editor", {"view", "edit_sources"})
    login(client)
    response = preview(client, "sources", g0_nvd_api_key_file_new="replacement synthetic value")
    assert response.status_code == 400
    assert target.read_text(encoding="utf-8") == "original synthetic value"


def test_rotation_rejects_hardlinks_and_protected_aliases(accounts, tmp_path):
    config, users, _, client = accounts
    outside = tmp_path / "outside-secret"
    make_secret(outside, "original synthetic value")
    inside = config.config_path.parent / "hardlinked-secret"
    os.link(outside, inside)
    config.config_path.write_text(with_file(config, inside), encoding="utf-8")
    set_role(users, "editor", {"view", "edit_sources"})
    login(client)
    response = preview(client, "sources", g0_nvd_api_key_file_new="replacement synthetic value")
    assert response.status_code == 400
    assert outside.read_text(encoding="utf-8") == "original synthetic value"

    config.config_path.chmod(0o600)
    config.config_path.write_text(with_file(config, config.config_path), encoding="utf-8")
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_file_new="replacement synthetic value")
    assert response.status_code == 400


def test_implicit_nvd_environment_precedence_blocks_rotation(accounts, monkeypatch):
    config, users, app, client = accounts
    monkeypatch.setenv("NVD_API_KEY", "synthetic environment takes precedence")
    secret = make_secret(config.config_path.parent / "nvd-key", "original synthetic file")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "sources", g0_nvd_api_key_env="",
                       g0_nvd_api_key_file_new="replacement synthetic file")
    assert response.status_code == 400
    assert "NVD_API_KEY" in response.text
    assert secret.read_text(encoding="utf-8") == "original synthetic file"
    assert config.config_path.read_bytes() == before


def test_secret_is_restored_when_directory_sync_fails(accounts, monkeypatch):
    config, _, app, client = accounts
    secret = make_secret(config.config_path.parent / "nvd-key", "original synthetic value")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_file_new="replacement synthetic value")
    before = config.config_path.read_bytes()
    real_sync = dc.sync_directory
    triggered = []

    def fail_once(directory):
        if directory == secret.parent and not triggered:
            triggered.append(True)
            raise OSError("synthetic directory sync failure after secret replace")
        return real_sync(directory)

    monkeypatch.setattr(dc, "sync_directory", fail_once)
    saved = confirm(client, response, "sources")
    assert saved.status_code == 503 and triggered
    assert config.config_path.read_bytes() == before
    assert secret.read_text(encoding="utf-8") == "original synthetic value"


def test_unknown_live_references_do_not_allow_deletion(accounts, monkeypatch):
    config, _, app, client = accounts
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_env="",
                       g0_nvd_api_key_file_new="synthetic staged value")
    editor = app.extensions["dashboard_config"]
    pending = editor.pending[form(response.text, "confirm")["preview"]]
    staged = pending.staged[0]
    adopted = preview(client, "sources", g0_nvd_api_key_env="",
                      g0_nvd_api_key_file=str(staged))
    assert confirm(client, adopted, "sources").status_code == 303
    pending.expires = 0
    real_read = dc.read_regular

    def unreadable_backup(path, **kwargs):
        if path.parent == editor.backup_dir:
            raise OSError("synthetic backup read error")
        return real_read(path, **kwargs)

    monkeypatch.setattr(dc, "read_regular", unreadable_backup)
    editor.cleanup()
    assert staged.exists()


def test_successful_save_keeps_secret_when_backup_read_fails(accounts, monkeypatch):
    config, _, app, client = accounts
    editor = app.extensions["dashboard_config"]
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_env="",
                       g0_nvd_api_key_file_new="synthetic staged value")
    pending = editor.pending[form(response.text, "confirm")["preview"]]
    staged = pending.staged[0]
    real_read = dc.read_regular

    def unreadable_backup(path, **kwargs):
        if path.parent == editor.backup_dir:
            raise OSError("synthetic backup read error")
        return real_read(path, **kwargs)

    monkeypatch.setattr(dc, "read_regular", unreadable_backup)
    saved = confirm(client, response, "sources")
    assert saved.status_code == 303
    assert staged.exists()


@pytest.mark.parametrize("second_app", [False, True])
def test_real_second_preview_adopts_reference(accounts, second_app):
    config, _, app, client = accounts
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_env="",
                       g0_nvd_api_key_file_new="synthetic staged value")
    editor = app.extensions["dashboard_config"]
    first = editor.pending[form(response.text, "confirm")["preview"]]
    staged = first.staged[0]
    adopter_client = client
    adopter_editor = editor
    if second_app:
        from cvebeacon.dashboard import create_app

        other_app = create_app(config)
        adopter_client = other_app.test_client()
        adopter_editor = other_app.extensions["dashboard_config"]
        login(adopter_client, "admin")
    second_response = preview(adopter_client, "sources", g0_nvd_api_key_env="",
                              g0_nvd_api_key_file=str(staged))
    assert second_response.status_code == 200, second_response.text
    second = adopter_editor.pending[form(second_response.text, "confirm")["preview"]]
    first.expires = 0
    editor.cleanup()
    assert staged.exists()
    assert confirm(adopter_client, second_response, "sources").status_code == 303
    assert staged.exists()


def test_expired_pending_references_are_retained(accounts):
    config, _, app, client = accounts
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_env="",
                       g0_nvd_api_key_file_new="synthetic staged value")
    editor = app.extensions["dashboard_config"]
    pending = editor.pending[form(response.text, "confirm")["preview"]]
    staged = pending.staged[0]
    adopted = preview(client, "sources", g0_nvd_api_key_env="",
                      g0_nvd_api_key_file=str(staged))
    second = editor.pending[form(adopted.text, "confirm")["preview"]]
    pending.expires = 0
    second.expires = 0
    old = time.time() - dc.PREVIEW_SECONDS - 30
    os.utime(staged, (old, old))
    editor.cleanup()
    assert staged.exists()


@pytest.mark.parametrize("key", ["url_env", "url_file"])
def test_existing_reference_channel_cannot_accept_inline_url(accounts, tmp_path, key):
    config, _, _, client = accounts
    value = "https://example.invalid/original"
    lines = BASE + '\n[watch.channels.hook]\ntype = "webhook"\n'
    if key == "url_env":
        lines += 'url_env = "SYNTHETIC_URL"\n'
    else:
        secret = make_secret(config.config_path.parent / "hook-url", value)
        lines += f'url_file = "{secret.name}"\n'
    config.config_path.write_text(lines, encoding="utf-8")
    login(client, "admin")
    response = preview(client, "channels", g0_url_env="", g0_url_file="",
                       g0_url="https://example.invalid/new-inline-secret")
    assert response.status_code == 400
    assert "new-inline-secret" not in config.config_path.read_text(encoding="utf-8")


def test_generic_url_reference_rechecks_transport_at_use(accounts, monkeypatch):
    from cvebeacon.watch import delivery

    config, _, _, client = accounts
    monkeypatch.setenv("SYNTHETIC_URL", "https://example.invalid/original")
    config.config_path.write_text(
        BASE + '\n[watch.channels.hook]\ntype = "webhook"\nurl_env = "SYNTHETIC_URL"\n',
        encoding="utf-8",
    )
    loaded = load_config(config.config_path)
    channel = loaded.watch.channels[0]
    assert not channel.options["allow_insecure"]
    monkeypatch.setenv("SYNTHETIC_URL", "http://example.invalid/new-insecure-endpoint")
    calls = []

    def fake_transport(http, method, url, **kwargs):
        calls.append(url)
        return type("Result", (), {"status_code": 200})()

    monkeypatch.setattr(delivery, "_http_call", fake_transport)
    with pytest.raises(DeliveryFailure):
        delivery._send_webhook(channel, (), object(), 5, {})
    outcome = delivery.send_test(loaded, object(), "hook")
    assert not outcome.ok
    assert not calls


def test_generic_url_http_opt_in_is_rechecked_at_use(accounts, monkeypatch):
    from cvebeacon.watch import delivery

    config, _, _, client = accounts
    monkeypatch.setenv("SYNTHETIC_URL", "http://example.invalid/allowed")
    config.config_path.write_text(
        BASE + '\n[watch.channels.hook]\ntype = "webhook"\nurl_env = "SYNTHETIC_URL"\nallow_insecure = true\n',
        encoding="utf-8",
    )
    loaded = load_config(config.config_path)
    calls = []

    def fake_transport(http, method, url, **kwargs):
        calls.append(url)
        return type("Result", (), {"status_code": 200})()

    monkeypatch.setattr(delivery, "_http_call", fake_transport)
    delivery._send_webhook(loaded.watch.channels[0], (), object(), 5, {})
    assert calls == ["http://example.invalid/allowed"]


@pytest.mark.parametrize("kind", ["config", "account", "symlink", "hardlink"])
def test_output_directory_cannot_alias_protected_file(accounts, tmp_path, kind):
    config, _, _, client = accounts
    target = config.config_path if kind == "config" else config.watch.users_database
    if kind == "symlink":
        alias = tmp_path / "output-alias"
        alias.symlink_to(target)
        value = alias
    elif kind == "hardlink":
        value = tmp_path / "output-hardlink"
        os.link(target, value)
    else:
        value = target
    login(client, "admin")
    response = preview(client, "system", g1_directory=str(value))
    assert response.status_code == 400


def test_post_commit_temp_cleanup_error_is_not_reported_as_failed(accounts, monkeypatch):
    config, _, app, client = accounts
    login(client, "admin")
    response = preview(client, "http", g0_retries="4")
    original = config.config_path.read_bytes()
    editor = app.extensions["dashboard_config"]
    generation = editor.target
    real_write = dc.write_temp
    real_unlink = Path.unlink
    recoveries = []

    def capture_recovery(directory, content, **kwargs):
        path = real_write(directory, content, **kwargs)
        if content == original and kwargs.get("info") is not None:
            recoveries.append(path)
        return path

    def fail_recovery_cleanup(path, *args, **kwargs):
        if path in recoveries:
            raise OSError("synthetic recovery temporary unlink error")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(dc, "write_temp", capture_recovery)
    monkeypatch.setattr(Path, "unlink", fail_recovery_cleanup)
    saved = confirm(client, response, "http")
    assert saved.status_code == 303
    assert config.config_path.read_bytes() != original
    assert editor.target is not generation


@pytest.mark.parametrize("kind,bad", [
    ("slack", "https://example.invalid/services/TEST/TEST/TEST"),
    ("discord", "https://example.invalid/api/webhooks/TEST/TEST"),
])
def test_rotation_rejects_wrong_webhook_host(accounts, kind, bad):
    config, users, _, client = accounts
    old = "https://hooks.slack.com/services/TEST/TEST/TEST" if kind == "slack" else "https://discord.com/api/webhooks/TEST/TEST"
    secret = make_secret(config.config_path.parent / "url-secret", old)
    config.config_path.write_text(
        BASE + f'\n[watch.channels.hook]\ntype = "{kind}"\nwebhook_url_file = "{secret.name}"\n',
        encoding="utf-8",
    )
    set_role(users, "editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", g0_webhook_url_file_new=bad)
    assert response.status_code == 400
    assert secret.read_text(encoding="utf-8") == old


@pytest.mark.parametrize("kind,bad", [
    ("slack", "https://example.invalid/services/TEST/TEST/TEST"),
    ("discord", "https://example.invalid/api/webhooks/TEST/TEST"),
])
def test_creation_rejects_wrong_webhook_host(accounts, kind, bad):
    config, _, _, client = accounts
    login(client, "admin")
    response = preview_channels(client, new_type=kind, g0_name="hook", g0_type=kind,
                               g0_webhook_url_file_new=bad)
    assert response.status_code == 400
    assert not (config.watch.users_database.parent / "dashboard-secrets").exists() or not list(
        (config.watch.users_database.parent / "dashboard-secrets").iterdir()
    )


def test_current_file_read_failure_does_not_delete_staged_secret(accounts, monkeypatch):
    config, _, app, client = accounts
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_env="",
                       g0_nvd_api_key_file_new="synthetic staged value")
    editor = app.extensions["dashboard_config"]
    pending = editor.pending[form(response.text, "confirm")["preview"]]
    staged = pending.staged[0]
    pending.expires = 0
    real_read = dc.read_regular

    def unreadable_current(path, **kwargs):
        if path == config.config_path:
            raise OSError("synthetic current config read error")
        return real_read(path, **kwargs)

    monkeypatch.setattr(dc, "read_regular", unreadable_current)
    editor.cleanup()
    assert staged.exists()


@pytest.mark.parametrize("url", [
    "https://user:password@example.invalid/hook",
    "not a URL",
])
def test_runtime_rejects_invalid_generic_urls(accounts, monkeypatch, url):
    from cvebeacon.watch import delivery

    config, _, _, client = accounts
    monkeypatch.setenv("SYNTHETIC_URL", "https://example.invalid/original")
    config.config_path.write_text(
        BASE + '\n[watch.channels.hook]\ntype = "webhook"\nurl_env = "SYNTHETIC_URL"\n',
        encoding="utf-8",
    )
    loaded = load_config(config.config_path)
    monkeypatch.setenv("SYNTHETIC_URL", url)
    calls = []
    monkeypatch.setattr(delivery, "_http_call",
                        lambda *args, **kwargs: calls.append(args[2]) or type("Result", (), {"status_code": 200})())
    with pytest.raises(DeliveryFailure):
        delivery._send_webhook(loaded.watch.channels[0], (), object(), 5, {})
    assert not calls


MINIMAL = """[inventory]
path = "inventory.csv"

[state]
database = "state.db"

[output]
directory = "reports"
"""


def test_redaction_covers_normalized_rule_names(accounts):
    _, _, _, client = accounts
    login(client, "admin")
    label = " S3cretLabel "
    page = client.get("/config/rules")
    data = form(page.text)
    data.update(g0_name=label, g0_condition="{ kev = true }", g0_channels="[]")
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert "S3cretLabel" not in response.text
    assert "s3cretlabel" not in response.text


def test_redaction_covers_normalized_watch_sources(accounts):
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")
    data = form(page.text)
    data.update(g0_sources='["nvd", " S3cretSource "]')
    response = client.post("/config/watch", data=data)
    assert response.status_code == 400
    assert "S3cretSource" not in response.text
    assert "s3cretsource" not in response.text


def test_redaction_covers_normalized_product_mappings(accounts):
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/product-mappings")
    data = form(page.text)
    data.update(row_count="2",
                g0_vendor=" S3cretVendor ", g0_product="Widget",
                g0_cpe="cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*",
                g1_vendor=" S3cretVendor ", g1_product="Widget",
                g1_cpe="cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*")
    response = client.post("/config/product-mappings", data=data)
    assert response.status_code == 400
    assert "S3cretVendor" not in response.text
    assert "s3cretvendor" not in response.text


def test_sources_only_new_file_secret_is_staged_and_saved(accounts, monkeypatch):
    config, users, app, client = accounts
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    config.config_path.write_text(MINIMAL, encoding="utf-8")
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_file_new="synthetic only file value")
    assert response.status_code == 200, response.text
    editor = app.extensions["dashboard_config"]
    pending = editor.pending[form(response.text, "confirm")["preview"]]
    assert pending.staged and pending.staged[0].exists()
    assert "nvd_api_key_file" in response.text
    assert confirm(client, response, "sources").status_code == 303
    loaded = load_config(config.config_path)
    assert loaded.sources.nvd_api_key_file is not None
    assert loaded.sources.nvd_api_key_file.read_text(encoding="utf-8") == "synthetic only file value"
    assert loaded.nvd_api_key() == "synthetic only file value"
    assert users.audit_entries()[-1].action.endswith(":secrets=1")


def test_loader_casefolded_channel_type_is_editable(accounts, monkeypatch):
    config, _, _, client = accounts
    monkeypatch.setenv("SYNTHETIC_URL", "https://example.invalid/hook")
    config.config_path.write_text(
        BASE + '\n[watch.channels.hook]\ntype = "WEBHOOK"\nurl_env = "SYNTHETIC_URL"\n',
        encoding="utf-8",
    )
    login(client, "admin")
    page = client.get("/config/channels")
    assert page.status_code == 200, page.text
    response = preview(client, "channels")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    assert load_config(config.config_path).watch.channels[0].type == "webhook"


def test_existing_other_channel_cannot_become_inline_webhook(accounts):
    config, _, _, client = accounts
    config.config_path.write_text(
        BASE + """
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
""",
        encoding="utf-8",
    )
    login(client, "admin")
    page = client.get("/config/channels")
    base = form(page.text)
    before = config.config_path.read_bytes()
    data = {key: base[key] for key in ("csrf", "version", "action", "row_count")}
    data.update(row_count="1", g0_name="mail", g0_type="webhook",
                g0_url="https://example.invalid/new-inline-secret",
                g0_url_env="", g0_url_file="", g0_header_name="")
    response = client.post("/config/channels", data=data)
    assert response.status_code == 400
    assert "Inline generic webhook URLs" in response.text
    assert "new-inline-secret" not in config.config_path.read_text(encoding="utf-8")
    assert config.config_path.read_bytes() == before


def test_unreadable_backup_retains_an_uncommitted_staged_file(accounts, monkeypatch):
    config, _, app, client = accounts
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_env="",
                       g0_nvd_api_key_file_new="synthetic staged value")
    editor = app.extensions["dashboard_config"]
    pending = editor.pending[form(response.text, "confirm")["preview"]]
    staged = pending.staged[0]
    pending.expires = 0
    real_read = dc.read_regular

    def unreadable_backup(path, **kwargs):
        if path.parent == editor.backup_dir:
            raise OSError("synthetic backup read error")
        return real_read(path, **kwargs)

    editor.backup_dir.mkdir(mode=0o700, exist_ok=True)
    (editor.backup_dir / ("20260101T000000000000Z-" + "b" * 16 + ".toml")).write_text(
        MINIMAL, encoding="utf-8"
    )
    monkeypatch.setattr(dc, "read_regular", unreadable_backup)
    editor.cleanup()
    assert staged.exists()


def test_new_nvd_file_secret_is_blocked_by_implicit_environment(accounts, monkeypatch):
    config, _, _, client = accounts
    monkeypatch.setenv("NVD_API_KEY", "synthetic environment takes precedence")
    config.config_path.write_text(MINIMAL, encoding="utf-8")
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_file_new="synthetic new file value")
    assert response.status_code == 400
    assert "NVD_API_KEY" in response.text
    secret_dir = config.watch.users_database.parent / "dashboard-secrets"
    assert not secret_dir.exists() or not list(secret_dir.iterdir())


def _smtp_pair(reference):
    return BASE + "\n" + "\n".join(
        f'''[watch.channels.{name}]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_file = "{reference}"
'''
        for name in ("first", "second")
    )


@pytest.mark.parametrize("revocation", ["disable", "password", "permission"])
def test_revoked_actor_never_writes_a_live_secret(accounts, monkeypatch, revocation):
    config, users, app, client = accounts
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    secret = make_secret(config.config_path.parent / "existing-key", "original synthetic value")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    app = dashboard.create_app(load_config(config.config_path))
    client = app.test_client()
    set_role(users, "source-editor", {"view", "edit_sources", "manage_secrets"})
    admin = users.authenticate("admin", PASSWORD)
    login(client)
    response = preview(client, "sources", g0_nvd_api_key_file_new="revoked synthetic value")
    editor = app.extensions["dashboard_config"]
    real_commit = editor.commit
    real_replace = dc.os.replace
    writes = []

    def revoke_then_commit(*args, **kwargs):
        if revocation == "disable":
            users.disable("reader", authorization=admin)
        elif revocation == "password":
            users.set_password("reader", "new synthetic password 123456", authorization=admin)
        else:
            users.save_role("source-editor", {"view"}, authorization=admin)
        return real_commit(*args, **kwargs)

    def capture_replace(source, destination):
        real_replace(source, destination)
        if Path(destination) == secret:
            writes.append(load_config(config.config_path).nvd_api_key())

    monkeypatch.setattr(editor, "commit", revoke_then_commit)
    monkeypatch.setattr(dc.os, "replace", capture_replace)
    saved = confirm(client, response, "sources")
    assert saved.status_code in {400, 403}
    assert secret.read_text(encoding="utf-8") == "original synthetic value"
    assert writes == []


def test_failed_writer_does_not_restore_over_another_successful_rotation(accounts, monkeypatch):
    config, _, app_a, client_a = accounts
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    secret = make_secret(config.config_path.parent / "existing-key", "original synthetic value")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    app_b = create_app(load_config(config.config_path))
    client_b = app_b.test_client()
    login(client_a, "admin")
    login(client_b, "admin")
    preview_a = preview(client_a, "sources", g0_nvd_api_key_file_new="writer A synthetic value")
    preview_b = preview(client_b, "sources", g0_nvd_api_key_file_new="writer B synthetic value")
    ready = threading.Event()
    resume = threading.Event()
    done_b = threading.Event()
    real_sync = dc.sync_directory
    result_a = []
    result_b = []
    errors = []

    def pause_a_after_its_replacement(directory):
        if threading.current_thread().name == "writer-a" and directory == secret.parent and not ready.is_set():
            ready.set()
            if not resume.wait(15):
                raise AssertionError("synthetic writer interleaving timed out")
        real_sync(directory)

    def run_a():
        try:
            result_a.append(confirm(client_a, preview_a, "sources").status_code)
        except BaseException as exc:
            errors.append(exc)

    def run_b():
        try:
            result_b.append(confirm(client_b, preview_b, "sources").status_code)
        except BaseException as exc:
            errors.append(exc)
        finally:
            done_b.set()

    monkeypatch.setattr(dc, "sync_directory", pause_a_after_its_replacement)
    worker = threading.Thread(target=run_a, name="writer-a")
    other = threading.Thread(target=run_b, name="writer-b")
    worker.start()
    try:
        assert ready.wait(10), "first writer did not reach the secret replacement"
        other.start()
        completed_while_a_paused = done_b.wait(2)
    finally:
        resume.set()
        worker.join(15)
        if other.ident is not None:
            other.join(15)
    assert not worker.is_alive() and not other.is_alive() and not errors, errors
    assert sorted([*result_a, *result_b]) == [303, 409]
    winner = "writer A synthetic value" if result_a == [303] else "writer B synthetic value"
    assert secret.read_text(encoding="utf-8") == winner
    assert completed_while_a_paused is False


def test_conflicting_rotations_of_one_physical_file_are_rejected(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "shared-password", "original synthetic value")
    config.config_path.write_text(_smtp_pair(secret.name), encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", g0_password_file_new="first synthetic password",
                       g1_password_file_new="second synthetic password")
    assert response.status_code == 400
    assert secret.read_text(encoding="utf-8") == "original synthetic value"


def test_shared_consumer_constraints_are_checked_before_any_live_write(accounts, monkeypatch):
    config, users, _, client = accounts
    old = "https://hooks.slack.com/services/TEST/TEST/TEST"
    secret = make_secret(config.config_path.parent / "shared-url", old)
    config.config_path.write_text(BASE + f'''
[watch.channels.slack]
type = "slack"
webhook_url_file = "{secret.name}"

[watch.channels.teams]
type = "teams"
webhook_url_file = "{secret.name}"
''', encoding="utf-8")
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    response = preview(client, "channels", g1_webhook_url_file_new="https://example.invalid/teams-only")
    assert response.status_code == 400
    assert secret.read_text(encoding="utf-8") == old


def test_failed_cross_app_lease_renewal_rejects_preview(accounts, monkeypatch):
    config, _, app_a, client_a = accounts
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    login(client_a, "admin")
    first_response = preview(client_a, "sources", g0_nvd_api_key_env="",
                             g0_nvd_api_key_file_new="synthetic staged value")
    editor_a = app_a.extensions["dashboard_config"]
    pending_a = editor_a.pending[form(first_response.text, "confirm")["preview"]]
    staged = pending_a.staged[0]
    app_b = create_app(config)
    client_b = app_b.test_client()
    login(client_b, "admin")
    real_utime = dc.os.utime

    def fail_lease_once(path, *args, **kwargs):
        if Path(path) == staged:
            raise OSError("synthetic generated-file lease renewal failure")
        return real_utime(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(dc.os, "utime", fail_lease_once)
        second_response = preview(client_b, "sources", g0_nvd_api_key_env="",
                                  g0_nvd_api_key_file=str(staged))
    assert second_response.status_code == 400


def test_loader_whitespace_channel_type_remains_editable(accounts, monkeypatch):
    config, _, _, client = accounts
    monkeypatch.setenv("SYNTHETIC_URL", "https://example.invalid/hook")
    config.config_path.write_text(
        BASE + '\n[watch.channels.hook]\ntype = " \tWEBHOOK "\nurl_env = "SYNTHETIC_URL"\n',
        encoding="utf-8",
    )
    assert load_config(config.config_path).watch.channels[0].type == "webhook"
    login(client, "admin")
    assert client.get("/config/channels").status_code == 200


def test_rename_and_rotate_existing_channel_is_a_guided_error(accounts):
    config, _, _, client = accounts
    secret = make_secret(config.config_path.parent / "password", "original synthetic value")
    config.config_path.write_text(_smtp_pair(secret.name), encoding="utf-8")
    login(client, "admin")
    response = preview(client, "channels", g0_name="renamed",
                       g0_password_file_new="renamed synthetic value")
    assert response.status_code == 400
    assert "separate saves" in response.text


def _operational_config(config, database_line, channel_file):
    config.config_path.write_text(
        BASE.replace('[state]\ndatabase = "state.db"', database_line)
        + f'''
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_file = "{channel_file}"
''',
        encoding="utf-8",
    )


def test_secret_rotation_rejects_state_database_target(accounts):
    config, _, _, client = accounts
    target = make_secret(config.config_path.parent / "operational.db", "operational state")
    _operational_config(config, '[state]\ndatabase = "operational.db"', target.name)
    login(client, "admin")
    response = preview(client, "channels", g0_password_file_new="replacement")
    assert response.status_code == 400
    assert target.read_text(encoding="utf-8") == "operational state"


def test_secret_rotation_rejects_watch_database_target(accounts):
    config, _, _, client = accounts
    target = make_secret(config.config_path.parent / "operational-watch.db", "operational watch")
    _operational_config(
        config,
        '[state]\ndatabase = "state.db"',
        target.name,
    )
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8").replace(
            '[watch]\nenabled = true',
            '[watch]\nenabled = true\ndatabase = "operational-watch.db"',
        ),
        encoding="utf-8",
    )
    login(client, "admin")
    response = preview(client, "channels", g0_password_file_new="replacement")
    assert response.status_code == 400
    assert target.read_text(encoding="utf-8") == "operational watch"


def test_secret_rotation_rejects_inventory_and_account_sidecar_targets(accounts):
    config, _, _, client = accounts
    inventory = config.inventory.path
    inventory.chmod(0o600)
    _operational_config(config, '[state]\ndatabase = "state.db"', inventory.name)
    login(client, "admin")
    response = preview(client, "channels", g0_password_file_new="replacement")
    assert response.status_code == 400

    sidecar = make_secret(
        Path(str(config.watch.users_database) + ".lock"),
        "operational sidecar",
    )
    _operational_config(config, '[state]\ndatabase = "state.db"', str(sidecar))
    login(client, "admin")
    response = preview(client, "channels", g0_password_file_new="replacement")
    assert response.status_code == 400
    assert sidecar.read_text(encoding="utf-8") == "operational sidecar"


def test_secret_target_rejects_output_directory_itself(accounts):
    config, _, app, _ = accounts
    editor = app.extensions["dashboard_config"]
    with pytest.raises(ConfigurationError):
        dc.secret_target(str(config.output_dir), config.config_path.parent,
                         [config], editor.backup_dir)


def test_generated_secret_files_remain_rotatable(accounts):
    config, _, app, client = accounts
    secret_dir = config.watch.users_database.parent / "dashboard-secrets"
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    target = make_secret(secret_dir / (dc.SECRET_PREFIX + "generated"), "original generated")
    config.config_path.write_text(
        BASE + f'''
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_file = "{target}"
''',
        encoding="utf-8",
    )
    login(client, "admin")
    response = preview(client, "channels", g0_password_file_new="replacement generated")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    assert target.read_text(encoding="utf-8") == "replacement generated"


def test_malformed_retained_backup_does_not_crash_cleanup(accounts):
    config, _, app, _ = accounts
    editor = app.extensions["dashboard_config"]
    editor.backup_dir.mkdir(mode=0o700, exist_ok=True)
    backup = editor.backup_dir / ("20260101T000000000000Z-" + "c" * 16 + ".toml")
    backup.write_text('[sources]\nnvd_api_key_file = "\\u0000"\n', encoding="utf-8")
    os.chmod(backup, 0o600)
    staged = make_secret(config.watch.users_database.parent / (dc.SECRET_PREFIX + "orphan"),
                         "synthetic orphan")
    old = time.time() - dc.PREVIEW_SECONDS - 30
    os.utime(staged, (old, old))
    editor.cleanup()
    assert staged.exists()
    assert create_app(load_config(config.config_path)).extensions["dashboard_config"] is not None


def test_reserved_secret_temporaries_in_data_root_are_cleaned(accounts):
    config, _, app, _ = accounts
    editor = app.extensions["dashboard_config"]
    os.chmod(config.config_path.parent, 0o700)
    orphan = make_secret(config.config_path.parent / (dc.STAGE_PREFIX + "orphan-root"),
                         "synthetic orphan")
    old = time.time() - dc.PREVIEW_SECONDS - 30
    os.utime(orphan, (old, old))
    editor.cleanup()
    assert not orphan.exists()


@pytest.mark.skipif(os.name != "posix", reason="native POSIX writer guard")
def test_writer_guard_unlock_error_preserves_commit_and_releases(accounts, monkeypatch):
    import fcntl

    config, _, _, client = accounts
    login(client, "admin")
    response = preview(client, "http", g0_retries="4")
    before = config.config_path.read_bytes()
    real_flock = fcntl.flock
    failed_descriptors = []
    acquired_elsewhere = []
    guard = dc._config_thread_lock(config.config_path)

    def fail_post_commit_unlock(descriptor, operation):
        if (operation == fcntl.LOCK_UN and not failed_descriptors
                and config.config_path.read_bytes() != before):
            failed_descriptors.append(descriptor)
            raise OSError("synthetic lock release failure after successful commit")
        return real_flock(descriptor, operation)

    def contender():
        acquired = guard.acquire(timeout=0.2)
        acquired_elsewhere.append(acquired)
        if acquired:
            guard.release()

    monkeypatch.setattr(fcntl, "flock", fail_post_commit_unlock)
    saved = confirm(client, response, "http")
    other = threading.Thread(target=contender)
    other.start()
    other.join(2)
    try:
        assert not other.is_alive()
        assert acquired_elsewhere == [True]
        assert saved.status_code == 303
        assert config.config_path.read_bytes() != before
    finally:
        for descriptor in failed_descriptors:
            try:
                real_flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            except OSError:
                pass
        if acquired_elsewhere == [False]:
            guard.release()


@pytest.mark.skipif(os.name != "posix", reason="native POSIX writer guard")
def test_writer_guard_close_error_preserves_commit_and_releases(accounts, monkeypatch):
    config, _, _, client = accounts
    login(client, "admin")
    response = preview(client, "http", g0_retries="4")
    before = config.config_path.read_bytes()
    lock_path = config.config_path.with_name(".config-" + config.config_path.name + ".lock")
    lock_inode = os.stat(lock_path).st_ino
    real_close = dc.os.close
    failed_descriptors = []
    acquired_elsewhere = []
    guard = dc._config_thread_lock(config.config_path)

    def fail_post_commit_close(descriptor):
        try:
            info = os.fstat(descriptor)
        except OSError:
            return real_close(descriptor)
        if (info.st_ino == lock_inode and not failed_descriptors
                and config.config_path.read_bytes() != before):
            failed_descriptors.append(descriptor)
            raise OSError("synthetic lock descriptor close failure after successful commit")
        return real_close(descriptor)

    def contender():
        acquired = guard.acquire(timeout=0.2)
        acquired_elsewhere.append(acquired)
        if acquired:
            guard.release()

    monkeypatch.setattr(dc.os, "close", fail_post_commit_close)
    saved = confirm(client, response, "http")
    other = threading.Thread(target=contender)
    other.start()
    other.join(2)
    try:
        assert not other.is_alive()
        assert acquired_elsewhere == [True]
        assert saved.status_code == 303
        assert config.config_path.read_bytes() != before
    finally:
        for descriptor in failed_descriptors:
            try:
                real_close(descriptor)
            except OSError:
                pass
        if acquired_elsewhere == [False]:
            guard.release()


def test_malformed_retained_backup_rollback_returns_400(accounts):
    config, _, app, client = accounts
    editor = app.extensions["dashboard_config"]
    editor.backup_dir.mkdir(mode=0o700, exist_ok=True)
    backup = editor.backup_dir / ("20260101T000000000000Z-" + "d" * 16 + ".toml")
    backup.write_text('[sources]\nnvd_api_key_file = "\\u0000"\n', encoding="utf-8")
    os.chmod(backup, 0o600)
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "backups", backup=backup.name)
    assert response.status_code == 400
    assert config.config_path.read_bytes() == before


def test_nul_file_reference_form_returns_400(accounts):
    config, _, _, client = accounts
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "sources", g0_nvd_api_key_file="\x00")
    assert response.status_code == 400
    assert config.config_path.read_bytes() == before


def test_secret_rotation_rejects_files_inside_output_directory(accounts):
    config, _, _, client = accounts
    output = config.config_path.parent / "reports"
    output.mkdir(mode=0o700, exist_ok=True)
    target = make_secret(output / "existing-report-secret", "original report value")
    config.config_path.write_text(
        BASE + f'''
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_file = "{target}"
''', encoding="utf-8")
    login(client, "admin")
    response = preview(client, "channels", g0_password_file_new="replacement")
    assert response.status_code == 400
    assert target.read_text(encoding="utf-8") == "original report value"


def test_generated_secret_remains_rotatable_when_output_contains_it(accounts):
    config, _, _, client = accounts
    secret_dir = config.watch.users_database.parent / "dashboard-secrets"
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    target = make_secret(secret_dir / (dc.SECRET_PREFIX + "inside-output"), "original generated")
    config.config_path.write_text(
        BASE.replace('[output]\ndirectory = "reports"', '[output]\ndirectory = "."')
        + f'''
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_file = "{target}"
''', encoding="utf-8")
    login(client, "admin")
    response = preview(client, "channels", g0_password_file_new="replacement generated")
    assert response.status_code == 200, response.text
