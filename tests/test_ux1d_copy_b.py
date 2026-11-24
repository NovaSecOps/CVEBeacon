"""Plain-language copy checks for the settings and admin pages."""

from __future__ import annotations

from dataclasses import replace
import html as html_module
from pathlib import Path
import re

from cvebeacon import backup, dashboard, dashboard_ops, dashboard_update
from cvebeacon.config import UpdateConfig
from cvebeacon.dashboard_config import FIELD_METADATA
from cvebeacon.dashboard_config_fields import FIELD_LABELS
from cvebeacon.state import StateStore
from cvebeacon.watch.store import WatchStore
from test_dashboard_operations import login, make_config, new_accounts

BANNED_WORDS = re.compile(r"\b(safe|protected|working|healthy|all set|not affected)\b", re.I)
RAW_DETAILS = ("SIGINT", "TOML", "cron", "watch notify", "cvebeacon users add", "[inventory]")


def page_text(markup: str) -> str:
    value = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", markup)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html_module.unescape(value))


def outside_technical(markup: str) -> str:
    value = re.sub(r"(?is)<details\b.*?</details>", " ", markup)
    value = re.sub(r"(?is)<(code|pre)\b.*?</\1>", " ", value)
    value = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", value)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html_module.unescape(value))


def admin_app(tmp_path, monkeypatch, *, updates=False):
    config = make_config(tmp_path)
    if updates:
        config = replace(config, update=UpdateConfig(enabled=True))
    users = new_accounts(config)
    monkeypatch.setattr(dashboard_ops.scheduling, "status", lambda **kwargs: "not installed")
    monkeypatch.setattr(dashboard_ops, "_running_as_root", lambda: False)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    return config, users, app, client


def test_every_config_field_has_a_plain_label():
    missing = sorted(set(FIELD_METADATA) - set(FIELD_LABELS))
    extra = sorted(set(FIELD_LABELS) - set(FIELD_METADATA))
    assert not missing
    assert not extra
    for identity, label in FIELD_LABELS.items():
        assert label.strip(), identity
        assert "_" not in label, identity
        assert label != identity.rsplit(".", 1)[-1], identity
        assert not BANNED_WORDS.search(label), (identity, label)


def test_settings_and_admin_pages_avoid_banned_words_and_raw_details(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch)
    pages = (
        "/operations/schedule",
        "/backups/",
        "/updates/",
        "/roles",
        "/audit",
        "/users",
        "/users/viewer",
        "/account",
        "/web-assets?client=Acme",
    )
    for path in pages:
        response = client.get(path)
        assert response.status_code == 200, path
        text = page_text(response.text)
        match = BANNED_WORDS.search(text)
        assert match is None, (path, match.group(0) if match else "")
        visible = outside_technical(response.text)
        for token in RAW_DETAILS:
            assert token not in visible, (path, token)


def test_login_and_bootstrap_pages_use_plain_account_words(tmp_path, monkeypatch):
    _, _, app, _ = admin_app(tmp_path, monkeypatch)
    login_page = app.test_client().get("/login")
    assert login_page.status_code == 200
    assert "Sign in" in login_page.text
    login_text = page_text(login_page.text)
    assert "session" not in login_text.lower()
    assert BANNED_WORDS.search(login_text) is None
    assert all(token not in outside_technical(login_page.text) for token in RAW_DETAILS)

    bootstrap_dir = tmp_path / "bootstrap"
    bootstrap_dir.mkdir(mode=0o700)
    bootstrap_dir.chmod(0o700)
    bootstrap_config = make_config(bootstrap_dir)
    bootstrap_app = dashboard.create_app(bootstrap_config)
    bootstrap = bootstrap_app.test_client().get(
        "/bootstrap", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
    )
    assert bootstrap.status_code == 200
    text = page_text(bootstrap.text)
    assert "administrator account" in text
    assert "admin account" not in text
    assert "session" not in text.lower()
    assert BANNED_WORDS.search(text) is None
    assert all(token not in outside_technical(bootstrap.text) for token in RAW_DETAILS)


def test_schedule_uses_plain_time_and_task_labels(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch)
    response = client.get("/operations/schedule")
    assert response.status_code == 200
    for expected in (
        "How often",
        "Every N hours",
        "At fixed times",
        "What to run",
        "Check software (scan)",
        "Watch for new flaws",
        "Windows only",
        "Command-line fallback",
    ):
        assert expected in response.text, expected
    for old in ("Schedule type", "Interval in hours", "Fixed local times", "Scan inventory"):
        assert old not in response.text, old


def test_backups_use_readable_and_plain_columns(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    StateStore(config.database_path).initialize()
    WatchStore(config.watch.database).initialize()
    backup.create(config, created_by="admin")
    users = new_accounts(config)
    monkeypatch.setattr(dashboard_ops.scheduling, "status", lambda **kwargs: "not installed")
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    response = client.get("/backups/")
    assert response.status_code == 200
    for expected in (
        "<th>Files</th>",
        "<th>Passwords and keys</th>",
        "<th>Format version</th>",
        "Delete expired backups",
        "Readable is not proof it can be restored. Use Verify.",
        ">Readable<",
        "Running backups automatically",
    ):
        assert expected in response.text, expected
    for old in (
        "Prune expired backups",
        "<th>Secrets</th>",
        "<th>Schema</th>",
        "<th>Databases</th>",
        ">Ready<",
        "equally protected",
    ):
        assert old not in response.text, old


def test_updates_explain_signature_and_backup_without_feed_jargon(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch, updates=True)
    monkeypatch.setattr(dashboard_update, "unsupported_reason", lambda: None)
    response = client.get("/updates/")
    assert response.status_code == 200
    assert (
        "CVEBeacon can check for new versions and, if you allow it, install them. "
        "It checks the release signature and makes a backup first."
    ) in response.text
    assert "signed release feed" not in response.text
    assert "backs up state" not in response.text
    assert "Check for updates" in response.text


def test_roles_lead_with_plain_permission_descriptions(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch)
    response = client.get("/roles")
    assert response.status_code == 200
    assert "<h1>Roles</h1>" in response.text
    assert "A role is a set of things people may do." in response.text
    assert "A person with the Manage users permission, but not an administrator" in response.text
    assert (
        '<td>Open pages and read findings, alerts and reports<br>'
        '<code class="muted">view</code></td>'
    ) in response.text
    assert "<th>What it allows</th>" not in response.text
    assert "non-admin" not in response.text


def test_audit_uses_record_check_wording_and_no_raw_action_titles(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch)
    response = client.get("/audit")
    assert response.status_code == 200
    assert "<h1>Audit</h1>" in response.text
    assert "Record check passed" in response.text
    assert "tamper-evident" not in response.text
    assert "Chain" not in response.text
    assert "<span title=" not in response.text
    assert '<code class="muted">login</code>' not in response.text
    assert "Signed in" in response.text


def test_account_and_user_edit_avoid_session_jargon(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch)
    account = client.get("/account")
    assert account.status_code == 200
    account_text = page_text(account.text)
    assert "session" not in account_text.lower()
    assert "Where you are signed in" in account.text
    assert "Log out everywhere" in account.text

    edit = client.get("/users/viewer")
    assert edit.status_code == 200
    assert "This signs them out everywhere." in edit.text


def test_web_assets_points_to_the_inventory_settings():
    template = Path(__file__).resolve().parents[1] / "src/cvebeacon/templates/web_assets.html"
    source = template.read_text(encoding="utf-8")
    assert "web_snapshots = true" not in source
    assert "turn on web snapshots in the" in source
    assert "Inventory settings" in source
