"""Regressions for the reviewed configuration-editor security boundaries."""

import html
import os
from pathlib import Path
import time

import pytest

from cvebeacon import dashboard_config as editor_module
from cvebeacon.config import load_config
from cvebeacon.watch.permissions import PERMISSIONS
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from test_dashboard import setup  # noqa: F401 - registers the shared fixture
from test_dashboard_accounts import PASSWORD, accounts as account_fixture, login


BASE = """[inventory]
path = "inventory.csv"

[state]
database = "state.db"

[output]
directory = "reports"

[sources]
nvd_api_key_env = "NVD_API_KEY"
nvd_enabled = false
cve_enabled = false
euvd_enabled = false
cisa_kev_enabled = false
eu_kev_enabled = false
epss_enabled = false
"""


@pytest.fixture
def accounts(account_fixture):
    account_fixture[0].config_path.chmod(0o644)
    return account_fixture


def set_role(users, name, permissions):
    proof = users.authenticate("admin", PASSWORD)
    users.save_role(name, set(permissions), authorization=proof)
    users.edit_user("reader", role=name, disabled=False, authorization=proof)


def form(page, action="preview"):
    import re

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


def make_secret(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)
    return path


def with_file(config, path: Path) -> str:
    try:
        reference = path.relative_to(config.config_path.parent).as_posix()
    except ValueError:
        reference = str(path)
    return BASE.replace('nvd_api_key_env = "NVD_API_KEY"\n', "").replace(
        "[sources]\n",
        f'[sources]\nnvd_api_key_file = "{reference}"\n',
    )


def preview_channels(client, new_type="webhook", **changes):
    page = client.get("/config/channels", query_string={"new_type": new_type})
    assert page.status_code == 200, page.text
    data = form(page.text)
    data.update(changes)
    return client.post("/config/channels", data=data)


def test_manage_secrets_is_a_documented_permission(accounts):
    _, users, _, _ = accounts
    assert "manage_secrets" in PERMISSIONS
    admin = users.authenticate("admin", PASSWORD)
    with users.transaction() as db:
        assert "manage_secrets" in users.permissions_in(db, admin.user)
    root = Path(__file__).resolve().parents[1]
    assert "`manage_secrets`" in (root / "docs" / "DASHBOARD.md").read_text(encoding="utf-8")


def test_secret_references_render_read_only_without_manage_secrets(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "smtp-password.txt", "Synthetic secret")
    config.config_path.write_text(
        BASE
        + f"""
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_file = "{secret.name}"
""",
        encoding="utf-8",
    )
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    page = client.get("/config/channels")
    assert page.status_code == 200
    assert 'name="g0_password_file" value="smtp-password.txt" readonly' in page.text


def test_secret_reference_change_requires_manage_secrets(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "smtp-password.txt", "Synthetic secret")
    config.config_path.write_text(
        BASE
        + f"""
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_file = "{secret.name}"
""",
        encoding="utf-8",
    )
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "channels", g0_password_env="OTHER_SECRET")
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before

    set_role(users, "channel-editor", {"view", "edit_channels", "manage_secrets"})
    login(client)
    response = preview(client, "channels", g0_password_env="OTHER_SECRET")
    assert response.status_code == 200
    assert confirm(client, response, "channels").status_code == 303
    channel = load_config(config.config_path).watch.channels[0]
    assert channel.secret("password").env == "OTHER_SECRET"


def test_manage_secrets_revocation_is_rechecked_inside_commit(accounts, monkeypatch):
    config, users, app, client = accounts
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("channel-editor", {"view", "edit_channels", "manage_secrets"}, authorization=admin)
    users.edit_user("reader", role="channel-editor", disabled=False, authorization=admin)
    login(client)
    response = preview_channels(client, g0_name="hook", g0_type="webhook",
                                g0_url_env="SYNTHETIC_HOOK_URL")
    before = config.config_path.read_bytes()
    editor = app.extensions["dashboard_config"]
    real_validate = editor.validate

    def revoke(document):
        users.save_role("channel-editor", {"view", "edit_channels"}, authorization=admin)
        return real_validate(document)

    monkeypatch.setattr(editor, "validate", revoke)
    assert confirm(client, response, "channels").status_code in {400, 403}
    assert config.config_path.read_bytes() == before


def test_existing_file_secret_contents_replaced_without_reference_change(accounts):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "nvd-key.txt", "old Synthetic value")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    set_role(users, "source-editor", {"view", "edit_sources"})
    login(client)
    response = preview(client, "sources", g0_nvd_api_key_file_new="new Synthetic value")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "sources").status_code == 303
    assert secret.read_text(encoding="utf-8") == "new Synthetic value"
    assert load_config(config.config_path).sources.nvd_api_key_file == secret.resolve()
    assert users.audit_entries()[-1].action.endswith(":secrets=1")


def test_changing_a_file_secret_reference_requires_manage_secrets(accounts, tmp_path):
    config, users, _, client = accounts
    secret = make_secret(config.config_path.parent / "nvd-key.txt", "old value")
    other = make_secret(tmp_path / "other-key.txt", "other value")
    config.config_path.write_text(with_file(config, secret), encoding="utf-8")
    set_role(users, "source-editor", {"view", "edit_sources"})
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "sources", g0_nvd_api_key_file=str(other))
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_new_file_secret_with_paired_environment_is_rejected(accounts):
    config, _, _, client = accounts
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "sources", g0_nvd_api_key_env="NVD_API_KEY",
                       g0_nvd_api_key_file_new="Synthetic replacement")
    assert response.status_code == 400
    assert "environment" in response.text.casefold()
    assert config.config_path.read_bytes() == before


def test_section_preview_does_not_disclose_other_sections(accounts):
    config, users, _, client = accounts
    config.config_path.write_text(
        BASE.replace(
            '[output]\ndirectory = "reports"',
            '[output]\ndirectory = "reports"\n\n[http]\nretries = 3\n\n'
            '[dashboard]\nsession_lifetime_seconds = 4321\n\n'
            '[watch]\nenabled = true\nsources = ["nvd"]\n\n'
            '[watch.reporting]\nidentity = "registered"',
        ),
        encoding="utf-8",
    )
    set_role(users, "http-editor", {"view", "edit_http"})
    login(client)
    response = preview(client, "http", g0_retries="4")
    assert response.status_code == 200, response.text
    assert '+"retries" = 4' in html.unescape(response.text)
    assert "4321" not in response.text
    assert "registered" not in response.text


@pytest.mark.parametrize("delimiter", ["\t", " "])
def test_inventory_delimiter_whitespace_is_preserved(accounts, delimiter):
    config, _, _, client = accounts
    escaped = "\\t" if delimiter == "\t" else " "
    config.config_path.write_text(
        BASE.replace(
            '[inventory]\npath = "inventory.csv"',
            f'[inventory]\npath = "inventory.csv"\ndelimiter = "{escaped}"',
        ),
        encoding="utf-8",
    )
    login(client, "admin")
    response = preview(client, "inventory")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "inventory").status_code == 303
    assert load_config(config.config_path).inventory.delimiter == delimiter


@pytest.mark.parametrize("name", ["Sensitive\\Label", 'Sensitive"Label',
                                  "Sensitive\u202eLabel", "Sensitive\x01Label"])
def test_loader_errors_redact_escaped_values(accounts, name):
    _, _, _, client = accounts
    login(client, "admin")
    response = preview(client, "channels", g0_name=name, g0_type="smtp", g0_host="")
    assert response.status_code == 400
    assert name not in response.text
    assert repr(name) not in response.text
    assert repr(name)[1:-1] not in response.text


def test_serializer_accepts_loader_accepted_integers():
    from cvebeacon.dashboard_config import dumps
    import tomllib

    document = {"http": {"read_timeout": 2**63, "backup": -(2**80)}}
    assert tomllib.loads(dumps(document)) == document


def test_inventory_rejects_unknown_column_keys_without_rendering(accounts):
    config, _, _, client = accounts
    config.config_path.write_text(
        BASE.replace(
            '[inventory]\npath = "inventory.csv"',
            '[inventory]\npath = "inventory.csv"\n\n[inventory.columns]\n'
            'asset_id = "asset_id"\nvendor = "vendor"\nproduct = "product"\n'
            'version = "version"\nhidden = "INLINE-SYNTHETIC-SECRET"',
        ),
        encoding="utf-8",
    )
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = client.get("/config/inventory")
    assert response.status_code == 400
    assert "INLINE-SYNTHETIC-SECRET" not in response.text
    assert config.config_path.read_bytes() == before


def test_rollback_compares_against_current_file_and_running_config(accounts, tmp_path):
    config, users, app, client = accounts
    login(client, "admin")
    assert confirm(client, preview(client, g0_retries="4")).status_code == 303
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("all-editor", {"view", *editor_module.SECTIONS.values()}, authorization=admin)
    users.edit_user("reader", role="all-editor", disabled=False, authorization=admin)
    other = tmp_path / "other-data"
    other_users = UserStore(other / "cvebeacon-users.db")
    other_users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    config.config_path.write_text(
        BASE.replace('[state]\ndatabase = "state.db"',
                     f'[state]\ndatabase = "{other / "state.db"}"').replace(
            '[output]\ndirectory = "reports"',
            f'[output]\ndirectory = "reports"\n\n[watch]\nenabled = true\n'
            f'sources = ["nvd"]\ndatabase = "{other / "watch.db"}"'),
        encoding="utf-8",
    )
    login(client)
    before = config.config_path.read_bytes()
    response = preview(client, "backups")
    assert response.status_code == 403
    assert config.config_path.read_bytes() == before


def test_staging_uses_current_file_data_directory(accounts, tmp_path):
    config, _, app, client = accounts
    login(client, "admin")
    other = tmp_path / "other-data"
    other_users = UserStore(other / "cvebeacon-users.db")
    other_users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    config.config_path.write_text(
        BASE.replace('nvd_api_key_env = "NVD_API_KEY"\n', "").replace(
            '[state]\ndatabase = "state.db"',
            f'[state]\ndatabase = "{other / "state.db"}"').replace(
            '[output]\ndirectory = "reports"',
            f'[output]\ndirectory = "reports"\n\n[watch]\nenabled = true\n'
            f'sources = ["nvd"]\ndatabase = "{other / "watch.db"}"'),
        encoding="utf-8",
    )
    response = preview(client, "sources", g0_nvd_api_key_file_new="Synthetic staging value")
    assert response.status_code == 200, response.text
    pending = app.extensions["dashboard_config"].pending[form(response.text, "confirm")["preview"]]
    assert pending.staged[0].parent == other / "dashboard-secrets"


@pytest.mark.parametrize("section,field,value", [
    ("watch", "g0_database", "config"),
    ("watch", "g0_database", "users"),
    ("system", "g0_database", "users"),
    ("system", "g1_directory", "backups"),
    ("system", "g1_directory", "secrets"),
])
def test_paths_aliasing_protected_stores_are_rejected(accounts, section, field, value):
    config, _, app, client = accounts
    editor = app.extensions["dashboard_config"]
    paths = {
        "config": config.config_path,
        "users": config.watch.users_database,
        "backups": editor.backup_dir,
        "secrets": editor.secret_dir,
    }
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, section, **{field: str(paths[value])})
    assert response.status_code == 400
    assert config.config_path.read_bytes() == before


def test_hardlink_alias_to_account_store_is_rejected(accounts, tmp_path):
    config, _, _, client = accounts
    alias = tmp_path / "state-alias.db"
    os.link(config.watch.users_database, alias)
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "system", g0_database=str(alias))
    assert response.status_code == 400
    assert config.config_path.read_bytes() == before


def test_generated_configuration_artifacts_are_ignored():
    root = Path(__file__).resolve().parents[1]
    ignored = (root / ".gitignore").read_text(encoding="utf-8")
    for pattern in ("dashboard-secrets/", ".*.backups/", ".config-*"):
        assert pattern in ignored


def test_unnamed_channel_does_not_stage_a_secret(accounts):
    config, _, app, client = accounts
    login(client, "admin")
    response = preview(client, "channels", g0_name="", g0_type="smtp",
                       g0_password_file_new="Synthetic unused secret")
    assert response.status_code == 200, response.text
    editor = app.extensions["dashboard_config"]
    assert not editor.secret_dir.exists() or not list(editor.secret_dir.iterdir())


def test_pending_previews_are_limited_per_session(accounts, monkeypatch):
    _, _, app, client = accounts
    monkeypatch.setattr(editor_module, "MAX_PENDING_PER_SESSION", 2)
    login(client, "admin")
    assert preview(client, g0_retries="1").status_code == 200
    assert preview(client, g0_retries="2").status_code == 200
    assert preview(client, g0_retries="3").status_code == 400


def test_abandoned_staging_is_removed_but_live_references_kept(accounts):
    config, _, app, client = accounts
    editor = app.extensions["dashboard_config"]
    secret_dir = config.watch.users_database.parent / "dashboard-secrets"
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    orphan = secret_dir / (editor_module.SECRET_PREFIX + "orphan")
    make_secret(orphan, "orphan Synthetic value")
    old = time.time() - editor_module.PREVIEW_SECONDS - 30
    os.utime(orphan, (old, old))
    editor.cleanup()
    assert not orphan.exists()

    live = secret_dir / (editor_module.SECRET_PREFIX + "live")
    make_secret(live, "live Synthetic value")
    os.utime(live, (old, old))
    config.config_path.write_text(
        BASE
        + f"""
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "sender@example.invalid"
to = ["soc@example.invalid"]
password_file = "{live}"
""",
        encoding="utf-8",
    )
    editor.cleanup()
    assert live.exists()


def test_expired_preview_does_not_delete_a_committed_reference(accounts):
    config, _, app, client = accounts
    editor = app.extensions["dashboard_config"]
    secret_dir = config.watch.users_database.parent / "dashboard-secrets"
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    staged = make_secret(secret_dir / (editor_module.SECRET_PREFIX + "pending"), "Synthetic value")
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_file_new="Synthetic value")
    assert response.status_code == 200, response.text
    pending = editor.pending[form(response.text, "confirm")["preview"]]
    pending.staged = (staged,)
    config.config_path.write_text(with_file(config, staged), encoding="utf-8")
    pending.expires = 0
    editor.cleanup()
    assert staged.exists()


def test_malformed_channel_type_is_a_safe_400(accounts):
    config, _, _, client = accounts
    config.config_path.write_text(
        BASE + '\n[watch.channels.bad]\ntype = ["smtp"]\n',
        encoding="utf-8",
    )
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = client.get("/config/channels")
    assert response.status_code == 400
    assert config.config_path.read_bytes() == before


def test_generic_webhook_accepts_url_references_and_hides_values(accounts, monkeypatch):
    config, users, _, client = accounts
    endpoint = "https://example.invalid/private-token/secret-path"
    monkeypatch.setenv("SYNTHETIC_HOOK_URL", endpoint)
    login(client, "admin")
    response = preview_channels(client, g0_name="hook", g0_type="webhook",
                                g0_url="", g0_url_env="SYNTHETIC_HOOK_URL")
    assert response.status_code == 200, response.text
    assert endpoint not in response.text
    assert confirm(client, response, "channels").status_code == 303
    channel = load_config(config.config_path).watch.channels[0]
    assert channel.secret("url").peek() == endpoint
    login(client, "admin")
    page = client.get("/config/channels")
    assert endpoint not in page.text
    assert endpoint not in config.config_path.read_text(encoding="utf-8")
    assert endpoint not in str(users.audit_entries())


def test_legacy_generic_webhook_direct_url_is_preserved_and_hidden(accounts):
    config, _, _, client = accounts
    endpoint = "https://example.invalid/legacy-private-token"
    config.config_path.write_text(
        BASE
        + f"""
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.hook]
type = "webhook"
url = "{endpoint}"
""",
        encoding="utf-8",
    )
    login(client, "admin")
    page = client.get("/config/channels")
    assert page.status_code == 200 and endpoint not in page.text
    assert confirm(client, preview(client, "channels"), "channels").status_code == 303
    assert load_config(config.config_path).watch.channels[0].options["url"] == endpoint


def test_new_generic_webhook_rejects_a_direct_url(accounts):
    _, _, _, client = accounts
    login(client, "admin")
    response = preview_channels(client, g0_name="hook", g0_type="webhook",
                                g0_url="https://example.invalid/direct-secret")
    assert response.status_code == 400
    assert "url_env" in response.text


def test_cleanup_preserves_a_backup_only_reference(accounts):
    config, _, app, client = accounts
    editor = app.extensions["dashboard_config"]
    secret_dir = config.watch.users_database.parent / "dashboard-secrets"
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    staged = make_secret(secret_dir / (editor_module.SECRET_PREFIX + "backup"), "Synthetic value")
    old = time.time() - editor_module.PREVIEW_SECONDS - 30
    os.utime(staged, (old, old))
    editor.backup_dir.mkdir(mode=0o700, exist_ok=True)
    backup = editor.backup_dir / ("20260101T000000000000Z-" + "a" * 16 + ".toml")
    backup.write_text(with_file(config, staged), encoding="utf-8")
    os.chmod(backup, 0o600)
    live = editor._live_reference_paths()
    assert live is not None and staged.resolve() in live
    editor.cleanup()
    assert staged.exists()


def test_pending_limit_is_per_session(accounts, monkeypatch):
    _, _, app, client = accounts
    monkeypatch.setattr(editor_module, "MAX_PENDING_PER_SESSION", 1)
    login(client, "admin")
    assert preview(client, g0_retries="1").status_code == 200
    assert preview(client, g0_retries="2").status_code == 400
    other = app.test_client()
    login(other, "admin")
    assert preview(other, g0_retries="3").status_code == 200


def test_commit_rechecks_running_config_for_lockout(accounts):
    from dataclasses import replace

    config, _, app, client = accounts
    login(client, "admin")
    response = preview(client, g0_retries="4")
    before = config.config_path.read_bytes()
    editor = app.extensions["dashboard_config"]
    editor.config = replace(
        editor.config,
        dashboard=replace(editor.config.dashboard, session_lifetime_seconds=1234),
    )
    assert confirm(client, response).status_code == 400
    assert config.config_path.read_bytes() == before


def test_symlink_alias_to_account_store_is_rejected(accounts, tmp_path):
    config, _, _, client = accounts
    alias = tmp_path / "state-alias.db"
    alias.symlink_to(config.watch.users_database)
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "system", g0_database=str(alias))
    assert response.status_code == 400
    assert config.config_path.read_bytes() == before


def test_staged_secret_is_adopted_across_pending_previews(accounts):
    from cvebeacon.dashboard_config import Pending

    config, _, app, client = accounts
    editor = app.extensions["dashboard_config"]
    login(client, "admin")
    response = preview(client, "sources", g0_nvd_api_key_file_new="Synthetic value")
    assert response.status_code == 200, response.text
    pending = editor.pending[form(response.text, "confirm")["preview"]]
    staged = pending.staged[0]
    adopted = Pending("other-session", "sources", "version", {}, time.monotonic() + 60,
                      (staged,), (), False)
    editor.pending["other-preview"] = adopted
    pending.expires = 0
    editor.cleanup()
    assert staged.exists()
    config.config_path.write_text(with_file(config, staged), encoding="utf-8")
    adopted.expires = 0
    editor.cleanup()
    assert staged.exists()
