"""Plain-language copy checks for the settings and admin pages."""

from __future__ import annotations

from dataclasses import replace
import html as html_module
import json
import re

from flask import url_for

from cvebeacon import backup, dashboard, dashboard_ops, dashboard_update, dashboard_web
from cvebeacon.config import UpdateConfig
from cvebeacon.dashboard_config import FIELD_METADATA
from cvebeacon.dashboard_config_fields import FIELD_LABELS
from cvebeacon.state import StateStore
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.permissions import PERMISSIONS
from test_dashboard_operations import login, make_config, new_accounts

BANNED_WORDS = re.compile(r"\b(safe|protected|working|healthy|all set|not affected)\b", re.I)
RAW_DETAILS = ("SIGINT", "TOML", "cron", "watch notify", "cvebeacon users add", "[inventory]")


def page_text(markup: str) -> str:
    value = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", markup)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html_module.unescape(value))


def outside_technical(markup: str) -> str:
    value = re.sub(
        r"(?is)<details\b[^>]*>\s*<summary>\s*Technical details\s*</summary>.*?</details>",
        " ",
        markup,
    )
    value = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", value)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html_module.unescape(value))


def test_raw_code_is_exempt_only_inside_technical_details():
    assert "SIGINT" in outside_technical("<code>SIGINT</code>")
    assert "SIGINT" in outside_technical(
        "<details class='disclosure'><summary>More information</summary><pre>SIGINT</pre></details>"
    )
    assert "SIGINT" not in outside_technical(
        "<details class='disclosure'><summary>Technical details</summary><pre>SIGINT</pre></details>"
    )


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
    for value in ("interval", "times", "scan", "watch", "both"):
        assert f'<option value="{value}"' in response.text, value


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
        "Not requested",
        "Monitoring data version",
        "Watch data version",
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
        '<code class="muted">state ',
        '<code class="muted">watch ',
    ):
        assert old not in response.text, old


def test_backups_describe_coverage_and_managed_inventory_separately(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch)
    response = client.get("/backups/")
    assert response.status_code == 200
    visible = page_text(response.text)
    for expected in (
        "configured state databases",
        "monitoring and inventory state",
        "watch history",
        "account records",
        "dashboard job history",
        "other SQLite databases CVEBeacon owns in its data directory",
        "the configuration file",
        "password and key files the configuration refers to, only when you choose to include them.",
        "Missing files and symbolic links are skipped, and the backup stops if a chosen file cannot be copied.",
        "Dashboard-managed inventory files are not included",
        "Copy the private inventory directory separately",
    ):
        assert expected in visible, expected
    assert "every data file" not in visible


def test_backup_format_versions_use_plain_names(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    StateStore(config.database_path).initialize()
    WatchStore(config.watch.database).initialize()
    backup.create(config, created_by="admin")
    new_accounts(config)
    monkeypatch.setattr(dashboard_ops.scheduling, "status", lambda **kwargs: "not installed")
    client = dashboard.create_app(config).test_client()
    login(client)
    response = client.get("/backups/")
    assert response.status_code == 200
    visible = outside_technical(response.text)
    assert "Monitoring data version" in visible
    assert "Watch data version" in visible
    assert re.search(r"<code[^>]*>\s*(?:state|watch)\s+\d+\s*</code>", response.text) is None


def test_requested_secrets_with_missing_file_are_not_reported_as_included(tmp_path, monkeypatch):
    secret_file = tmp_path / "missing-secret.txt"
    secret_file.write_text("synthetic password", encoding="utf-8")
    secret_file.chmod(0o600)
    channels = '''
[watch.channels.mail]
type = "smtp"
host = "mail.example.com"
from = "alerts@example.com"
to = ["security@example.com"]
password_file = "missing-secret.txt"
'''
    config = make_config(tmp_path, channels=channels)
    secret_file.unlink()
    StateStore(config.database_path).initialize()
    WatchStore(config.watch.database).initialize()
    created = backup.create(config, include_secrets=True, created_by="admin")
    manifest = json.loads((created.path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["include_secrets"] is True
    assert manifest["secrets"] == []
    assert manifest["skipped_secrets"] == ["watch.channels.mail.password"]

    new_accounts(config)
    monkeypatch.setattr(dashboard_ops.scheduling, "status", lambda **kwargs: "not installed")
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    response = client.get("/backups/")
    assert response.status_code == 200
    assert "<td>Requested</td>" in response.text
    assert "<td>Included</td>" not in response.text


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
        '<td>Read dashboard pages, findings and alerts<br>'
        '<code class="muted">view</code></td>'
    ) in response.text
    assert "<th>What it allows</th>" not in response.text
    assert "non-admin" not in response.text


def test_every_role_capability_has_a_plain_description_and_matches_its_boundary(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch)
    response = client.get("/roles")
    assert response.status_code == 200
    rows = re.findall(
        r'<td>(.*?)<br><code class="muted">([^<]+)</code></td>', response.text
    )
    descriptions = {capability: page_text(description) for description, capability in rows}
    assert set(descriptions) == set(PERMISSIONS)
    for capability, description in descriptions.items():
        assert description.strip(), capability
        assert description != capability, capability
        assert "_" not in description, (capability, description)

    assert descriptions["view"].strip() == "Read dashboard pages, findings and alerts"
    assert descriptions["run"].strip() == (
        "Start scans, data updates and other tasks. Manual queries and report exports "
        "need both Run and View."
    )
    assert descriptions["edit_channels"].strip() == (
        "Change where alerts are sent. Credential values need Manage secrets; file "
        "reference paths need an administrator."
    )
    assert descriptions["edit_reporting"].strip() == (
        "Choose how a person is identified when they mark a CVE as reported."
    )
    assert descriptions["manage_secrets"].strip() == (
        "Change credential values and secret file contents. An administrator must "
        "change file reference paths."
    )
    assert descriptions["manage_inventory"].strip() == (
        "Upload and manage dashboard-managed client software lists."
    )
    assert descriptions["view_audit"].strip() == (
        "Read the account activity log and export the full history of CVEs reported to clients."
    )
    assert descriptions["edit_system"].strip() == (
        "See where CVEBeacon stores its data and reports, and change backup retention and "
        "download settings. Only an administrator can change the storage locations."
    )
    visible = page_text(response.text)
    assert (
        "Editing a configuration section needs View and that section's Edit permission. "
        "Managing inventories needs View and Manage inventory. Changing channel passwords "
        "or tokens also needs Manage secrets."
    ) in visible


def test_disabled_updates_separate_release_checks_from_installing(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch)
    response = client.get("/updates/")
    assert response.status_code == 200
    visible = page_text(response.text)
    assert "Updates are disabled" in visible
    assert (
        "An administrator can turn on release checks in the configuration. Installing an "
        "update from this page also needs the updater to be set up on the server by an "
        "administrator."
    ) in visible
    assert "turn on update checks in the configuration" not in visible


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


def test_unknown_audit_action_uses_plain_fallback_and_keeps_raw_code_in_details(tmp_path, monkeypatch):
    _, users, _, client = admin_app(tmp_path, monkeypatch)
    users.record_action("future_action", username="admin", actor="admin", detail="support note")
    response = client.get("/audit")
    assert response.status_code == 200
    assert "Other recorded action" in response.text
    assert "future_action:support note" in response.text
    assert "future_action:support note" not in outside_technical(response.text)


def test_confirmation_text_remains_copy_pinned(tmp_path, monkeypatch):
    _, _, _, client = admin_app(tmp_path, monkeypatch, updates=True)
    account = client.get("/account")
    backups = client.get("/backups/")
    monkeypatch.setattr(dashboard_update, "read_status", lambda config: {"available": "1.2.3"})
    monkeypatch.setattr(dashboard_update, "unsupported_reason", lambda: None)
    updates = client.get("/updates/")
    assert account.status_code == backups.status_code == updates.status_code == 200
    assert 'data-confirm="Log out everywhere, including this browser?"' in account.text
    assert (
        'data-confirm="Delete backups older than 7 day(s)? The newest 3 readable backups are always kept."'
        in backups.text
    )
    assert (
        'data-confirm="Queue the update to version 1.2.3? The updater checks the release signature and makes a backup first."'
        in updates.text
    )


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


def test_web_assets_points_to_the_inventory_settings(tmp_path, monkeypatch):
    _, _, app, client = admin_app(tmp_path, monkeypatch)
    allowlist = tmp_path / "allowlist.json"
    snapshot_file = tmp_path / "snapshot.json"
    snapshot_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        dashboard_web,
        "paths",
        lambda config, client_name: (allowlist, snapshot_file),
    )
    monkeypatch.setattr(
        dashboard_web,
        "read_allowlist",
        lambda path, client_name: ({"client": client_name, "assets": []}, "v1"),
    )
    monkeypatch.setattr(
        dashboard_web,
        "read_web_snapshot",
        lambda path: ([], {"generated_at": "2026-11-25T00:00:00Z", "status": "success", "record_count": 0}),
    )
    (tmp_path / "snapshot.json.review.json").write_text(json.dumps({"client": "Acme", "reviews": [], "products": [{
        "asset_id": "web-1", "hostname": "a.example", "vendor": "nginx", "product": "nginx",
        "category": "web-server", "confidence": "high", "versions": ["1.25.3"],
        "evidence_types": ["header"]}]}), encoding="utf-8")
    monkeypatch.setattr(dashboard_web, "read_bytes", lambda path: path.read_bytes())
    response = client.get("/web-assets?client=Acme")
    assert response.status_code == 200
    with app.test_request_context():
        expected_destination = url_for("config_editor.inventory")
    print(response.text[response.text.find("Latest detection"):][:3000]);     link = re.search(r'<a href="([^"]+)">Inventory settings</a>', response.text)
    assert link is not None
    assert link.group(1) == expected_destination
    assert "web_snapshots = true" not in response.text
    assert "turn on 'Include saved web snapshots in scans' in the" in response.text
