"""Guided channel setup: schema coverage, permissions and the shared save path."""

from __future__ import annotations

import html
import os
from pathlib import Path
import re
import stat
import tomllib

import pytest
from werkzeug.datastructures import MultiDict

from cvebeacon import dashboard, dashboard_config as config_module
from cvebeacon.config import load_config
from cvebeacon.dashboard_channel_wizard import (
    ADVANCED_NOTE,
    ADVANCED_TYPES,
    DUPLICATE_NAME,
    EXPIRED_REVIEW,
    INVALID_NAME,
    SECRET_CAPABILITY,
    STALE_CONFIG,
    WIZARD_TYPES,
    WIZARD_TYPES_BY_KIND,
    consistency_errors,
)
from cvebeacon.passwords import hash_password_value
from cvebeacon.watch.channels import CHANNEL_TYPES, COMMON_KEYS, TYPE_KEYS
from cvebeacon.dashboard_config_fields import CHANNEL_REQUIRED
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from watch_support import write_config

PASSWORD = "Synthetic wizard password 123"
SECRET_VALUES = {
    "smtp": "Synthetic mail password 123",
    "graph": "Synthetic application secret 123",
    "teams": "https://example.org/teams-webhook",
    "slack": "https://hooks.slack.com/services/TEST/TEST/TEST",
    "discord": "https://discord.com/api/webhooks/123456789/abcdef",
    "telegram": "123456:SyntheticTelegramToken",
    "matrix": "syt_SyntheticMatrixToken",
    "ntfy": "SyntheticNtfyToken",
    "gotify": "SyntheticGotifyToken",
    "webhook": "https://example.org/hooks/alerts",
}


def csrf(client, path="/account"):
    page = client.get(path)
    assert page.status_code == 200
    match = re.search(r'name="csrf" value="([^"]+)"', page.text)
    assert match
    return match[1]


def login(client, username="admin"):
    token = csrf(client, "/login")
    response = client.post(
        "/login",
        data={"csrf": token, "username": username, "password": PASSWORD},
    )
    assert response.status_code == 303


def form_values(page, action):
    """Read the hidden inputs of the form with the given action value."""
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", page, re.S)
    source = next(source for source in forms
                  if f'name="action" value="{action}"' in source)
    data = {}
    for tag in re.findall(r"<input\b[^>]*>", source):
        attributes = dict(re.findall(r'([\w-]+)="([^"]*)"', tag))
        if attributes.get("type") != "checkbox":
            data[attributes["name"]] = html.unescape(attributes.get("value", ""))
    return data


def make_accounts(config):
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    for name in ("editor", "viewer", "operator"):
        users.add(name, password=PASSWORD)
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("channel-editor", {"view", "edit_channels"}, authorization=admin)
    users.save_role("viewer-only", {"view"}, authorization=admin)
    users.save_role("operator-only", {"view", "run", "test_channel"}, authorization=admin)
    users.edit_user("editor", role="channel-editor", disabled=False, authorization=admin)
    users.edit_user("viewer", role="viewer-only", disabled=False, authorization=admin)
    users.edit_user("operator", role="operator-only", disabled=False, authorization=admin)
    return users


def make_config(tmp_path, channels=""):
    config = write_config(tmp_path, sources=("nvd",), initial="baseline", channels=channels)
    config.config_path.chmod(0o644)
    (tmp_path / "missing-inventory.csv").write_text(
        "asset_id,vendor,product,version\na,Acme,Widget,1\n", encoding="utf-8"
    )
    return config


@pytest.fixture
def wizard(tmp_path):
    config = make_config(tmp_path)
    users = make_accounts(config)
    app = dashboard.create_app(config)
    return config, users, app, app.test_client()


def wizard_page(client, kind):
    page = client.get(f"/config/channels/new/{kind}")
    assert page.status_code == 200, page.text
    return page


def post_preview(client, kind, **values):
    page = wizard_page(client, kind)
    data = form_values(page.text, "preview")
    data.update(values)
    return client.post(f"/config/channels/new/{kind}", data=data)


def required_values(kind, name="alerts", index=0):
    """Valid form values for one wizard type, keyed by posted field name."""
    item = WIZARD_TYPES_BY_KIND[kind]
    values = {f"g{index}_name": name}
    supplied = {
        "smtp": {"host": "smtp.example.com", "from": "alerts@example.com",
                 "to": "alerts@example.com, security@example.com", "security": "starttls"},
        "graph": {"tenant_id": "00000000-0000-0000-0000-000000000000",
                  "client_id": "11111111-1111-1111-1111-111111111111",
                  "sender": "alerts@example.com", "to": "alerts@example.com"},
        "teams": {}, "slack": {}, "discord": {},
        "telegram": {"chat_id": "123456789"},
        "matrix": {"homeserver": "https://matrix.example.org",
                   "room_id": "!room:example.org"},
        "ntfy": {"topic": "security-alerts", "server": ""},
        "gotify": {"server": "https://gotify.example.org"},
        "webhook": {},
    }[kind]
    for field in item.fields:
        if field.control == "secret":
            values[f"g{index}_{field.key}_new"] = SECRET_VALUES[kind]
        else:
            values[f"g{index}_{field.key}"] = supplied.get(field.key, "")
    return values


def test_wizard_types_match_the_channel_schema():
    assert consistency_errors() == []
    assert "teams_bot" not in WIZARD_TYPES_BY_KIND
    assert set(ADVANCED_TYPES) == {"teams_bot"}
    listed = set(WIZARD_TYPES_BY_KIND) | set(ADVANCED_TYPES)
    assert listed == set(CHANNEL_TYPES)
    for item in WIZARD_TYPES:
        offered = {field.key for field in item.fields}
        assert offered <= COMMON_KEYS | TYPE_KEYS[item.kind]
        assert CHANNEL_REQUIRED.get(item.kind, set()) <= offered
        secret = item.secret()
        assert secret is not None
        assert secret.key.endswith("_file")
        assert secret.key in TYPE_KEYS[item.kind]
        for field in item.fields:
            assert field.control in {"text", "select", "addresses", "secret"}
            if field.key in CHANNEL_REQUIRED.get(item.kind, set()):
                assert field.required
            if field.control == "select":
                assert field.options
        assert secret.required is (item.kind not in {"smtp", "ntfy"})


def test_every_type_renders_both_steps(wizard):
    _, _, _, client = wizard
    login(client)
    page = client.get("/config/channels/new")
    assert page.status_code == 200
    assert "Add an alert channel" in page.text
    assert "Where should alerts go?" in page.text
    for item in WIZARD_TYPES:
        assert item.title in page.text
        assert "kind-" + item.kind in page.text
    assert ADVANCED_NOTE in page.text
    assert 'href="/config/channels?new_type=teams_bot"' in page.text

    for item in WIZARD_TYPES:
        page = wizard_page(client, item.kind)
        assert item.title in page.text
        assert "Details" in page.text
        assert 'name="action" value="preview"' in page.text
        for field in item.fields:
            expected = f"g0_{field.key}"
            if field.control == "secret":
                expected += "_new"
                assert f'name="{expected}"' in page.text
                assert field.label in page.text
                assert 'type="password"' in page.text
                assert 'autocomplete="new-password"' in page.text
            else:
                assert f'name="{expected}"' in page.text
                assert field.label in page.text


def test_step_one_redirects_a_valid_kind(wizard):
    _, _, _, client = wizard
    login(client)
    response = client.get("/config/channels/new", query_string={"kind": "slack"})
    assert response.status_code == 303
    assert response.headers["Location"] == "/config/channels/new/slack"
    assert client.get("/config/channels/new", query_string={"kind": "unknown"}).status_code == 404
    assert client.get("/config/channels/new", query_string={"kind": "teams_bot"}).status_code == 404
    assert client.get("/config/channels/new/teams_bot").status_code == 404
    assert client.get("/config/channels/new/unknown").status_code == 404


def test_permissions_for_the_wizard(wizard):
    _, _, _, client = wizard
    login(client, "viewer")
    assert client.get("/config/channels/new").status_code == 403
    assert client.get("/config/channels/new/smtp").status_code == 403
    client.get("/logout")

    login(client, "operator")
    assert client.get("/config/channels/new").status_code == 403
    client.get("/logout")

    login(client, "editor")
    page = client.get("/config/channels/new")
    assert page.status_code == 200
    assert "Needs an administrator who may manage secrets." in page.text
    assert client.get("/config/channels/new/smtp").status_code == 200
    assert client.get("/config/channels/new/ntfy").status_code == 200
    assert client.get("/config/channels/new/slack").status_code == 403
    client.get("/logout")

    login(client)
    assert client.get("/config/channels/new/slack").status_code == 200


def test_account_less_mode_is_forbidden(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    monkeypatch.setenv(config.dashboard.password_hash_env, hash_password_value(PASSWORD))
    other = dashboard.create_app(config).test_client()
    token = re.search(r'name="csrf" value="([^"]+)"', other.get("/login").text)[1]
    assert other.post("/login", data={"csrf": token, "password": PASSWORD}).status_code == 303
    assert other.get("/config/channels/new").status_code == 403
    assert other.get("/config/channels/new/smtp").status_code == 403


def test_post_needs_csrf(wizard):
    _, _, app, client = wizard
    login(client)
    page = wizard_page(client, "smtp")
    data = form_values(page.text, "preview")
    data.pop("csrf")
    assert client.post("/config/channels/new/smtp", data=data).status_code == 400
    stranger = app.test_client()
    foreign = csrf(stranger, "/login")
    data["csrf"] = foreign
    assert client.post("/config/channels/new/smtp", data=data).status_code == 400


def test_required_fields_are_reported_per_field(wizard):
    _, _, _, client = wizard
    login(client)
    page = wizard_page(client, "smtp")
    data = form_values(page.text, "preview")
    response = client.post("/config/channels/new/smtp", data=data)
    assert response.status_code == 400
    assert "Name is required." in response.text
    assert "Mail server address is required." in response.text
    assert "Send from is required." in response.text
    assert "Send to is required." in response.text
    assert 'href="#f-g0_host"' in response.text
    assert 'href="#f-g0_name"' in response.text

    page = wizard_page(client, "graph")
    data = form_values(page.text, "preview")
    response = client.post("/config/channels/new/graph", data=data)
    assert response.status_code == 400
    assert "Application secret is required." in response.text
    assert 'href="#f-g0_client_secret_file_new"' in response.text

    page = wizard_page(client, "slack")
    data = form_values(page.text, "preview")
    response = client.post("/config/channels/new/slack", data=data)
    assert response.status_code == 400
    assert "Slack webhook address is required." in response.text


def test_bad_field_values_are_reported_without_echo(wizard):
    _, _, _, client = wizard
    login(client)
    values = required_values("smtp", name="mail")
    values["g0_to"] = "not-an-address"
    response = post_preview(client, "smtp", **values)
    assert response.status_code == 400
    assert "Send to needs one or more email addresses, separated by commas." in response.text

    values = required_values("smtp", name="mail")
    values["g0_port"] = "not-a-number"
    response = post_preview(client, "smtp", **values)
    assert response.status_code == 400
    assert "Port is not valid. Use the example shown." in response.text

    values = required_values("smtp", name="mail")
    values["g0_security"] = "insecure"
    response = post_preview(client, "smtp", **values)
    assert response.status_code == 400
    assert "Security: choose one of the listed options." in response.text


def test_duplicate_and_invalid_names_are_field_errors(tmp_path):
    config = make_config(tmp_path, channels="""
[watch.channels.Sink]
type = "webhook"
url_env = "SINK_URL"
""")
    make_accounts(config)
    client = dashboard.create_app(config).test_client()
    login(client)
    values = required_values("smtp", name="sink", index=1)
    values["g1_password_file_new"] = ""
    response = post_preview(client, "smtp", **values)
    assert response.status_code == 400
    assert DUPLICATE_NAME in response.text
    assert 'href="#f-g1_name"' in response.text

    values = required_values("smtp", name="bad name", index=1)
    response = post_preview(client, "smtp", **values)
    assert response.status_code == 400
    assert INVALID_NAME in response.text


def test_preview_keeps_the_secret_out_of_the_page(wizard):
    config, _, app, client = wizard
    login(client)
    before = config.config_path.read_bytes()
    response = post_preview(client, "slack", **required_values("slack", name="security-team"))
    assert response.status_code == 200, response.text
    assert "Review changes" in response.text
    assert 'action="/config/channels/new/slack"' in response.text
    assert 'href="/config/channels/new/slack"' in response.text
    assert 'name="preview" value="' in response.text
    assert re.search(r'name="preview" value="[0-9a-f]{64}"', response.text)
    assert "security-team" in response.text
    assert SECRET_VALUES["slack"] not in response.text
    assert config.config_path.read_bytes() == before
    editor = app.extensions["dashboard_config"]
    assert len(editor.pending) == 1
    pending = next(iter(editor.pending.values()))
    assert pending.section == "channels"
    assert pending.lockout is False
    assert pending.staged
    assert pending.staged[0].read_text(encoding="utf-8") == SECRET_VALUES["slack"]


def test_confirm_saves_the_channel_and_the_secret(wizard):
    config, users, app, client = wizard
    login(client)
    response = post_preview(client, "slack", **required_values("slack", name="security-team"))
    assert response.status_code == 200
    confirm = form_values(response.text, "confirm")
    saved = client.post("/config/channels/new/slack", data=confirm)
    assert saved.status_code == 303
    document = tomllib.loads(config.config_path.read_text(encoding="utf-8"))
    channel = document["watch"]["channels"]["security-team"]
    assert channel["type"] == "slack"
    assert ".dashboard-secret-" in channel["webhook_url_file"]
    secret_path = Path(channel["webhook_url_file"])
    assert secret_path.read_text(encoding="utf-8") == SECRET_VALUES["slack"]
    if os.name == "posix":
        assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
    assert SECRET_VALUES["slack"] not in config.config_path.read_text(encoding="utf-8")
    loaded = load_config(config.config_path)
    assert [item.name for item in loaded.watch.channels] == ["security-team"]
    assert loaded.watch.channels[0].type == "slack"
    assert loaded.watch.channels[0].enabled is True
    actions = [entry.action for entry in users.audit_entries()]
    assert any(action.startswith("config_save:channels:") for action in actions)
    assert app.extensions["dashboard_config"].backups()


def test_confirm_redirects_to_the_test_step_when_it_exists(wizard):
    config, _, app, client = wizard
    if "operations.channel_test_form" not in app.view_functions:
        app.add_url_rule("/operations/channels/<name>/test",
                         endpoint="operations.channel_test_form",
                         view_func=lambda name: "", methods=["GET"])
    login(client)
    response = post_preview(client, "smtp", **required_values("smtp", name="mail"))
    confirm = form_values(response.text, "confirm")
    saved = client.post("/config/channels/new/smtp", data=confirm)
    assert saved.status_code == 303
    assert saved.headers["Location"] == "/operations/channels/mail/test"

    reloaded_app = dashboard.create_app(load_config(config.config_path), session_app=app)
    if "operations.channel_test_form" not in reloaded_app.view_functions:
        reloaded_app.add_url_rule("/operations/channels/<name>/test",
                                  endpoint="operations.channel_test_form",
                                  view_func=lambda name: "", methods=["GET"])
    client.application = reloaded_app
    followed = client.get(saved.headers["Location"])
    assert followed.status_code == 200, followed.text


def test_confirm_without_the_test_endpoint_still_saves(wizard, monkeypatch):
    config, _, app, client = wizard
    monkeypatch.delitem(app.view_functions, "operations.channel_test_form", raising=False)
    login(client)
    response = post_preview(client, "smtp", **required_values("smtp", name="mail"))
    confirm = form_values(response.text, "confirm")
    saved = client.post("/config/channels/new/smtp", data=confirm)
    assert saved.status_code == 303
    assert saved.headers["Location"] == "/config/channels?saved=1"
    document = tomllib.loads(config.config_path.read_text(encoding="utf-8"))
    assert document["watch"]["channels"]["mail"]["type"] == "smtp"


ALL_CHANNELS = """
[watch.channels.mail]
type = "smtp"
host = "smtp.example.com"
from = "alerts@example.com"
to = ["alerts@example.com"]
password_env = "SMTP_PASSWORD"

[watch.channels.graph]
type = "graph"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "11111111-1111-1111-1111-111111111111"
sender = "alerts@example.com"
to = ["alerts@example.com"]
client_secret_env = "GRAPH_SECRET"

[watch.channels.teams]
type = "teams"
webhook_url_env = "TEAMS_WEBHOOK"

[watch.channels.bot]
type = "teams_bot"
tenant_id = "22222222-2222-2222-2222-222222222222"
app_id = "33333333-3333-3333-3333-333333333333"
client_secret_file = "bot-secret.txt"
recipients = ["alerts@example.com"]

[watch.channels.chat]
type = "slack"
webhook_url_env = "SLACK_WEBHOOK"

[watch.channels.forum]
type = "discord"
webhook_url_env = "DISCORD_WEBHOOK"

[watch.channels.phone]
type = "telegram"
chat_id = "123456789"
bot_token_env = "TELEGRAM_TOKEN"

[watch.channels.room]
type = "matrix"
homeserver = "https://matrix.example.org"
room_id = "!room:example.org"
access_token_env = "MATRIX_TOKEN"

[watch.channels.push]
type = "ntfy"
topic = "security-alerts"
token_env = "NTFY_TOKEN"

[watch.channels.gotify]
type = "gotify"
server = "https://gotify.example.org"
app_token_env = "GOTIFY_TOKEN"

[watch.channels.legacy]
type = "webhook"
url = "https://example.invalid/legacy"
"""


def test_each_channel_type_persists_existing_shapes_unchanged(tmp_path):
    secret = tmp_path / "bot-secret.txt"
    secret.write_text("Synthetic bot secret", encoding="utf-8")
    secret.chmod(0o600)
    config = make_config(tmp_path, channels=ALL_CHANNELS)
    make_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    original = tomllib.loads(config.config_path.read_text(encoding="utf-8"))["watch"]["channels"]
    editor = app.extensions["dashboard_config"]
    assert len(original) == 11
    added = []
    for item in WIZARD_TYPES:
        response = post_preview(client, item.kind,
                                **required_values(item.kind, name="new-" + item.kind,
                                                  index=len(original) + len(added)))
        assert response.status_code == 200, (item.kind, response.text[-2000:])
        identifier = re.search(r'name="preview" value="([0-9a-f]{64})"', response.text)[1]
        pending = editor.pending[identifier]
        candidate = pending.document["watch"]["channels"]
        for name, row in original.items():
            assert _typed_equal(candidate[name], row), (item.kind, name)
        assert candidate["new-" + item.kind]["type"] == item.kind
        confirm = form_values(response.text, "confirm")
        saved = client.post(f"/config/channels/new/{item.kind}", data=confirm)
        assert saved.status_code == 303, (item.kind, saved.text[-2000:])
        added.append("new-" + item.kind)
        persisted = tomllib.loads(config.config_path.read_text(encoding="utf-8"))["watch"]["channels"]
        assert list(persisted) == [*original, *added]
        for name, row in original.items():
            assert _typed_equal(persisted[name], row), (item.kind, name)
        assert persisted["new-" + item.kind]["type"] == item.kind


def _typed_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (list(left) == list(right)
                and all(_typed_equal(left[key], right[key]) for key in left))
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _typed_equal(a, b) for a, b in zip(left, right))
    return left == right


@pytest.mark.parametrize("username", ["admin", "editor"])
def test_append_preserves_existing_channel_shapes_after_confirm(tmp_path, monkeypatch, username):
    monkeypatch.setenv("AUDIT_TELEGRAM_TOKEN", "Synthetic Telegram token")
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "https://example.invalid/current")
    channels = '''
[watch.channels.telegram-legacy]
type = "telegram"
chat_id = -123456789
bot_token_env = "AUDIT_TELEGRAM_TOKEN"

[watch.channels.mail]
type = "smtp"
host = "smtp.example.com"
from = "alerts@example.com"
to = [" alerts@example.com ", "alerts@example.com", "Last, First <ops@example.com>"]
cc = []
username = ""

[watch.channels.push]
type = "ntfy"
topic = "security-alerts"
server = ""

[watch.channels.reference-hook]
type = "webhook"
url = ""
url_env = "AUDIT_WEBHOOK_URL"

[watch.channels.legacy-hook]
type = "webhook"
url = "https://example.invalid/legacy"
url_env = " "
'''
    config = make_config(tmp_path, channels=channels)
    make_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client, username)
    original = tomllib.loads(config.config_path.read_text(encoding="utf-8"))["watch"]["channels"]
    response = post_preview(client, "ntfy", **required_values("ntfy", name="new-push",
                                                                index=len(original)))
    assert response.status_code == 200, response.text[-2000:]
    confirm = form_values(response.text, "confirm")
    saved = client.post("/config/channels/new/ntfy", data=confirm)
    assert saved.status_code == 303, saved.text[-2000:]
    reloaded = tomllib.loads(config.config_path.read_text(encoding="utf-8"))["watch"]["channels"]
    assert set(reloaded) - set(original) == {"new-push"}
    for name, row in original.items():
        assert _typed_equal(reloaded[name], row), (name, reloaded[name], row)


def _full_channel_preview(client, kind, *, name, secret):
    page = client.get(f"/config/channels?new_type={kind}")
    assert page.status_code == 200, page.text[-2000:]
    data = form_values(page.text, "preview")
    data.update({"g0_type": kind, "g0_name": name, f"g0_{'url_file' if kind == 'webhook' else 'webhook_url_file'}_new": secret})
    return client.post("/config/channels", data=data)


@pytest.mark.parametrize("flow", ["wizard", "full"])
def test_secret_preview_expires_through_the_real_ttl_check(wizard, monkeypatch, flow):
    _, _, app, client = wizard
    login(client)
    if flow == "wizard":
        response = post_preview(client, "webhook", **required_values("webhook", name="hook"))
        confirm_path = "/config/channels/new/webhook"
    else:
        response = _full_channel_preview(client, "webhook", name="hook",
                                         secret=SECRET_VALUES["webhook"])
        confirm_path = "/config/channels"
    assert response.status_code == 200, response.text[-2000:]
    confirm = form_values(response.text, "confirm")
    editor = app.extensions["dashboard_config"]
    pending = editor.pending[confirm["preview"]]
    created = tuple(pending.staged)
    assert created and all(path.exists() for path in created)
    monkeypatch.setattr(config_module.clock, "monotonic", lambda: pending.expires + 1)
    expired = client.post(confirm_path, data=confirm)
    assert expired.status_code == 400
    assert confirm["preview"] not in editor.pending
    assert all(not path.exists() for path in created)


@pytest.mark.parametrize("flow", ["wizard", "full"])
def test_stale_secret_confirmation_discards_its_temporary_file(wizard, flow):
    config, _, app, client = wizard
    login(client)
    if flow == "wizard":
        response = post_preview(client, "webhook", **required_values("webhook", name="hook"))
        confirm_path = "/config/channels/new/webhook"
    else:
        response = _full_channel_preview(client, "webhook", name="hook",
                                         secret=SECRET_VALUES["webhook"])
        confirm_path = "/config/channels"
    assert response.status_code == 200, response.text[-2000:]
    confirm = form_values(response.text, "confirm")
    editor = app.extensions["dashboard_config"]
    pending = editor.pending[confirm["preview"]]
    created = tuple(pending.staged)
    assert created and all(path.exists() for path in created)
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8") + "\n# External edit\n",
        encoding="utf-8",
    )
    stale = client.post(confirm_path, data=confirm)
    assert stale.status_code == 409
    assert confirm["preview"] not in editor.pending
    assert all(not path.exists() for path in created)


@pytest.mark.parametrize("flow", ["wizard", "full"])
def test_committed_secret_survives_pending_cleanup(wizard, flow):
    config, _, app, client = wizard
    login(client)
    if flow == "wizard":
        response = post_preview(client, "webhook", **required_values("webhook", name="hook"))
        confirm_path = "/config/channels/new/webhook"
    else:
        response = _full_channel_preview(client, "webhook", name="hook",
                                         secret=SECRET_VALUES["webhook"])
        confirm_path = "/config/channels"
    assert response.status_code == 200, response.text[-2000:]
    confirm = form_values(response.text, "confirm")
    pending_id = confirm["preview"]
    pending = app.extensions["dashboard_config"].pending[pending_id]
    created = tuple(pending.staged)
    assert client.post(confirm_path, data=confirm).status_code == 303
    assert all(path.exists() for path in created)
    app.extensions["dashboard_config"].cleanup()
    assert all(path.exists() for path in created)


def test_discard_refuses_a_symlink_in_place_of_a_preview_file(wizard, tmp_path):
    config, _, app, _ = wizard
    secret_dir = config_module._secret_directory(config)
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    original = secret_dir / "mail-password"
    original.write_text("Synthetic original password", encoding="utf-8")
    original.chmod(0o600)
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8") + '''
[watch.channels.mail]
type = "smtp"
host = "smtp.example.com"
from = "alerts@example.com"
to = ["alerts@example.com"]
password_file = "dashboard-secrets/mail-password"
''', encoding="utf-8")
    app = dashboard.create_app(load_config(config.config_path))
    client = app.test_client()
    login(client)
    page = client.get("/config/channels")
    data = form_values(page.text, "preview")
    data.update({"g0_type": "smtp", "g1_type": "smtp",
                 "g0_password_file_new": "Synthetic replacement"})
    response = client.post("/config/channels", data=data)
    assert response.status_code == 200, response.text[-2000:]
    editor = app.extensions["dashboard_config"]
    identifier = form_values(response.text, "confirm")["preview"]
    staged = editor.pending[identifier].staged[0]
    assert staged.name.startswith(config_module.STAGE_PREFIX)
    staged.unlink()
    staged.symlink_to(original)
    editor.discard(identifier)
    assert staged.is_symlink()
    assert original.read_text(encoding="utf-8") == "Synthetic original password"


@pytest.mark.parametrize("bad_field,bad_value,kind", [
    ("port", "70000", "smtp"),
    ("chat_id", "not-a-chat!", "telegram"),
    ("homeserver", "https://matrix.example.org/path", "matrix"),
    ("url_file_new", "not a URL", "webhook"),
])
def test_loader_field_errors_are_linked_to_the_wizard_control(wizard, bad_field, bad_value, kind):
    _, _, _, client = wizard
    login(client)
    values = required_values(kind, name="bad-channel")
    field_name = f"g0_{bad_field}"
    values[field_name] = bad_value
    response = post_preview(client, kind, **values)
    assert response.status_code == 400
    assert f'href="#f-{field_name}"' in response.text
    control = re.search(rf'<input\b[^>]*name="{re.escape(field_name)}"[^>]*>', response.text)
    assert control and 'aria-invalid="true"' in control[0]
    assert f'aria-describedby="f-{field_name}-help f-{field_name}-error"' in control[0]
    if kind == "webhook":
        assert bad_value not in response.text


def test_repeated_wizard_field_is_rejected_before_staging_a_secret(wizard):
    _, _, app, client = wizard
    login(client)
    page = wizard_page(client, "webhook")
    data = form_values(page.text, "preview")
    values = required_values("webhook", name="hook")
    data.update(values)
    submitted = MultiDict([*data.items(), ("g0_name", "another-hook")])
    response = client.post("/config/channels/new/webhook", data=submitted)
    assert response.status_code == 400
    editor = app.extensions["dashboard_config"]
    assert not editor.pending
    secret_dir = config_module._secret_directory(editor.config)
    assert not list(secret_dir.glob(config_module.SECRET_PREFIX + "*"))


def test_wizard_append_accepts_101_existing_rows(tmp_path):
    channels = "\n".join(
        f'[watch.channels.push-{index}]\ntype = "ntfy"\ntopic = "topic-{index}"'
        for index in range(101)
    )
    config = make_config(tmp_path, channels=channels)
    make_accounts(config)
    client = dashboard.create_app(config).test_client()
    login(client)
    response = post_preview(client, "ntfy", **required_values("ntfy", name="last-push",
                                                                index=101))
    assert response.status_code == 200, response.text[-2000:]
    confirm = form_values(response.text, "confirm")
    assert client.post("/config/channels/new/ntfy", data=confirm).status_code == 303
    reloaded = tomllib.loads(config.config_path.read_text(encoding="utf-8"))["watch"]["channels"]
    assert len(reloaded) == 102
    assert reloaded["last-push"]["type"] == "ntfy"


def test_full_config_size_limit_still_applies_to_wizard_append(tmp_path):
    address = "a" * 286 + "@example.com"
    tables = []
    for index, count in enumerate([100] * 8 + [55]):
        recipients = ", ".join('"' + address + '"' for _ in range(count))
        tables.append(
            f'[watch.channels.mail-{index}]\ntype = "smtp"\nhost = "smtp.example.com"\n'
            f'from = "alerts@example.com"\nto = [{recipients}]'
        )
    channels = "\n\n".join(tables)
    config = make_config(tmp_path, channels=channels)
    current = tomllib.loads(config.config_path.read_text(encoding="utf-8"))
    assert len(config_module.dumps(current).encode("utf-8")) < config_module.MAX_CONFIG
    make_accounts(config)
    client = dashboard.create_app(config).test_client()
    login(client)
    values = required_values("smtp", name="last-mail", index=9)
    values["g9_to"] = ", ".join(
        f"{index}{'a' * 275}@example.com" for index in range(15))
    values.pop("g9_password_file_new")
    response = post_preview(client, "smtp", **values)
    assert response.status_code == 400
    assert "configuration exceeds the size limit" in response.text.lower()


def test_full_form_preview_cannot_be_confirmed_as_a_wizard_addition(wizard):
    config, _, app, client = wizard
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8") + '''
[watch.channels.old-push]
type = "ntfy"
topic = "old-topic"
''', encoding="utf-8")
    app = dashboard.create_app(load_config(config.config_path))
    client = app.test_client()
    login(client)
    page = client.get("/config/channels")
    data = form_values(page.text, "preview")
    data.update({"remove0": "yes", "g0_type": "ntfy", "g1_type": "smtp"})
    preview = client.post("/config/channels", data=data)
    assert preview.status_code == 200, preview.text[-2000:]
    confirm = form_values(preview.text, "confirm")
    editor = app.extensions["dashboard_config"]
    before = config.config_path.read_bytes()
    refused = client.post("/config/channels/new/ntfy", data=confirm)
    assert refused.status_code == 400
    assert confirm["preview"] in editor.pending
    assert config.config_path.read_bytes() == before


def test_wizard_preview_of_one_type_cannot_be_confirmed_as_another(wizard):
    config, _, app, client = wizard
    login(client)
    values = required_values("smtp", name="mail")
    values.pop("g0_password_file_new")
    preview = post_preview(client, "smtp", **values)
    assert preview.status_code == 200, preview.text[-2000:]
    confirm = form_values(preview.text, "confirm")
    editor = app.extensions["dashboard_config"]
    before = config.config_path.read_bytes()
    refused = client.post("/config/channels/new/ntfy", data=confirm)
    assert refused.status_code == 400
    assert confirm["preview"] in editor.pending
    assert config.config_path.read_bytes() == before


def test_wizard_refuses_a_wrong_origin_before_rendering_review(wizard, monkeypatch):
    _, _, app, client = wizard
    login(client)
    editor = app.extensions["dashboard_config"]
    real_preview = editor.preview

    def wrong_origin(*args, **kwargs):
        identifier, lockout = real_preview(*args, **kwargs)
        editor.pending[identifier].origin = ("full", None)
        return identifier, lockout

    monkeypatch.setattr(editor, "preview", wrong_origin)
    values = required_values("smtp", name="mail")
    values.pop("g0_password_file_new")
    response = post_preview(client, "smtp", **values)
    assert response.status_code == 400
    assert len(editor.pending) == 1


def test_a_read_only_credential_row_is_carried_through_unchanged(tmp_path):
    config = make_config(tmp_path, channels="""
[watch.channels.team]
type = "teams"
webhook_url_env = "TEAMS_WEBHOOK"
""")
    make_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client, "editor")
    page = wizard_page(client, "smtp")
    assert 'type="password"' not in page.text
    assert "Mail password" not in page.text
    values = required_values("smtp", name="mail", index=1)
    values.pop("g1_password_file_new", None)
    data = form_values(page.text, "preview")
    data.update(values)
    response = client.post("/config/channels/new/smtp", data=data)
    assert response.status_code == 200, response.text[-2000:]
    identifier = re.search(r'name="preview" value="([0-9a-f]{64})"', response.text)[1]
    editor = app.extensions["dashboard_config"]
    candidate = editor.pending[identifier].document["watch"]["channels"]
    assert candidate["team"] == {"type": "teams", "webhook_url_env": "TEAMS_WEBHOOK"}
    assert candidate["mail"]["type"] == "smtp"
    assert "password_file" not in candidate["mail"]


def test_lockout_confirmation_is_required(wizard, monkeypatch):
    config, _, _, client = wizard
    monkeypatch.setattr(config_module, "access_settings_changed", lambda *args, **kwargs: True)
    login(client)
    response = post_preview(client, "smtp", **required_values("smtp", name="mail"))
    assert response.status_code == 200
    assert 'name="lockout"' in response.text
    confirm = form_values(response.text, "confirm")
    before = config.config_path.read_bytes()
    refused = client.post("/config/channels/new/smtp", data=confirm)
    assert refused.status_code == 400
    assert "Confirm the access and session changes before saving" in refused.text
    assert config.config_path.read_bytes() == before
    confirm = form_values(refused.text, "confirm")
    confirm["lockout"] = "yes"
    saved = client.post("/config/channels/new/smtp", data=confirm)
    assert saved.status_code == 303
    assert saved.headers["Location"] == "/login"
    assert config.config_path.read_bytes() != before


def test_expired_and_foreign_previews_are_refused(wizard):
    config, _, app, client = wizard
    login(client)
    response = post_preview(client, "smtp", **required_values("smtp", name="mail"))
    confirm = form_values(response.text, "confirm")
    editor = app.extensions["dashboard_config"]
    before = config.config_path.read_bytes()

    other = app.test_client()
    login(other)
    foreign = {"csrf": csrf(other, "/account"), "action": "confirm",
               "preview": confirm["preview"], "lockout": "yes"}
    refused = other.post("/config/channels/new/smtp", data=foreign)
    assert refused.status_code == 400
    assert EXPIRED_REVIEW in refused.text
    assert config.config_path.read_bytes() == before

    editor.discard(confirm["preview"])
    expired = client.post("/config/channels/new/smtp", data=confirm)
    assert expired.status_code == 400
    assert EXPIRED_REVIEW in expired.text
    assert config.config_path.read_bytes() == before


def test_an_unknown_action_is_rejected(wizard):
    _, _, _, client = wizard
    login(client)
    page = wizard_page(client, "smtp")
    data = form_values(page.text, "preview")
    data.update(required_values("smtp", name="mail"))
    data["action"] = "delete"
    response = client.post("/config/channels/new/smtp", data=data)
    assert response.status_code == 400
    assert "Unsupported configuration action" in response.text


def test_a_stale_version_is_refused(wizard):
    config, _, _, client = wizard
    login(client)
    page = wizard_page(client, "smtp")
    data = form_values(page.text, "preview")
    data.update(required_values("smtp", name="mail"))
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8") + "\n# External edit\n",
        encoding="utf-8",
    )
    response = client.post("/config/channels/new/smtp", data=data)
    assert response.status_code == 409
    assert STALE_CONFIG in response.text
    assert '"watch"."channels"' not in response.text


def test_a_stale_version_is_refused_on_confirm(wizard):
    config, _, _, client = wizard
    login(client)
    response = post_preview(client, "smtp", **required_values("smtp", name="mail"))
    confirm = form_values(response.text, "confirm")
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8") + "\n# External edit\n",
        encoding="utf-8",
    )
    refused = client.post("/config/channels/new/smtp", data=confirm)
    assert refused.status_code == 409
    assert STALE_CONFIG in refused.text


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes block writes")
def test_a_read_only_directory_shows_the_notice_and_blocks_preview(wizard):
    config, _, _, client = wizard
    login(client)
    directory = config.config_path.parent
    mode = directory.stat().st_mode & 0o777
    os.chmod(directory, 0o500)
    try:
        page = client.get("/config/channels/new")
        assert page.status_code == 200
        assert "Read-only configuration" in page.text
        page = client.get("/config/channels/new/smtp")
        assert page.status_code == 200
        assert "Read-only configuration" in page.text
        assert "disabled" in page.text
        data = form_values(page.text, "preview")
        data.update(required_values("smtp", name="mail"))
        before = config.config_path.read_bytes()
        response = client.post("/config/channels/new/smtp", data=data)
        assert response.status_code == 400
        assert "read-only" in response.text.lower()
        assert config.config_path.read_bytes() == before
    finally:
        os.chmod(directory, mode)


def test_a_secret_is_never_repeated_in_an_error(wizard):
    _, _, _, client = wizard
    login(client)
    secret = "SyntheticWebhookSecretValue123"
    values = required_values("webhook", name="mail")
    values["g0_url_file_new"] = secret
    response = post_preview(client, "webhook", **values)
    assert response.status_code == 400
    assert secret not in response.text


def test_the_type_step_has_one_fieldset_and_no_disabled_choices_are_selected(wizard):
    _, _, _, client = wizard
    login(client, "editor")
    page = client.get("/config/channels/new")
    assert page.status_code == 200
    assert page.text.count("<fieldset>") == 1
    assert "<legend>Where should alerts go?</legend>" in page.text
    assert 'name="kind" value="smtp" required' in page.text
    assert 'name="kind" value="slack" disabled' in page.text
    assert 'name="kind" value="teams_bot"' not in page.text
    assert SECRET_CAPABILITY in page.text


def test_wizard_templates_avoid_inline_styles_and_scripts():
    root = Path(__file__).resolve().parents[1] / "src" / "cvebeacon" / "templates"
    for name in ("channel_wizard_type.html", "channel_wizard_form.html"):
        text = (root / name).read_text(encoding="utf-8")
        assert not re.search(r"(?i)\sstyle\s*=", text), name
        assert not re.search(r"(?i)\son[a-z]+\s*=", text), name
        assert not re.search(r"(?is)<script\b", text), name
        assert not re.search(r"(?is)<style\b", text), name


def test_channels_page_hides_guided_setup_from_a_view_only_user(wizard):
    from flask import render_template

    _, _, app, _ = wizard
    values = {
        "section": "channels",
        "groups": [],
        "version": "version",
        "read_only": False,
        "saved": False,
        "channel_types": [],
        "events": [],
        "leaves": [],
        "condition_schema": {},
        "toml_value": str,
    }
    with app.test_request_context("/config/channels"):
        viewer = render_template("config_section.html", **values, permissions={"view"})
        editor = render_template("config_section.html", **values,
                                 permissions={"view", "edit_channels"})
    assert "Guided setup" not in viewer
    assert "Guided setup" in editor


def test_a_secret_is_not_accepted_from_a_user_who_cannot_manage_secrets(tmp_path):
    config = make_config(tmp_path)
    make_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client, "editor")
    page = wizard_page(client, "smtp")
    values = required_values("smtp", name="mail")
    data = form_values(page.text, "preview")
    data.update(values)
    response = client.post("/config/channels/new/smtp", data=data)
    assert response.status_code == 200, response.text[-2000:]
    identifier = re.search(r'name="preview" value="([0-9a-f]{64})"', response.text)[1]
    editor = app.extensions["dashboard_config"]
    pending = editor.pending[identifier]
    assert "password_file" not in pending.document["watch"]["channels"]["mail"]
    assert pending.staged == ()
    secret_directory = config.watch.users_database.parent / "dashboard-secrets"
    assert not list(secret_directory.glob(".dashboard-secret-*"))


def test_entered_values_are_retained_but_credential_looking_text_is_not(wizard):
    _, _, _, client = wizard
    login(client)
    values = required_values("smtp", name="mail")
    values["g0_from"] = ""
    response = post_preview(client, "smtp", **values)
    assert response.status_code == 400
    assert "Send from is required." in response.text
    assert "For safety, enter the secret again." in response.text
    assert 'value="mail"' in response.text
    assert 'value="smtp.example.com"' in response.text

    values = required_values("smtp", name="mail")
    values["g0_host"] = "https://credential-looking.example/secret"
    values["g0_from"] = ""
    response = post_preview(client, "smtp", **values)
    assert response.status_code == 400
    assert "https://credential-looking.example/secret" not in response.text


def test_the_wizard_preview_reloads_after_a_save(wizard):
    _, _, app, client = wizard
    login(client)
    response = post_preview(client, "smtp", **required_values("smtp", name="mail"))
    confirm = form_values(response.text, "confirm")
    assert client.post("/config/channels/new/smtp", data=confirm).status_code == 303
    editor = app.extensions["dashboard_config"]
    assert [channel.name for channel in editor.config.watch.channels] == ["mail"]
    assert editor.config.watch.channels[0].enabled is True


def test_a_required_secret_type_cannot_be_opened_by_a_non_admin(wizard):
    _, _, _, client = wizard
    login(client, "editor")
    page = wizard_page(client, "smtp")
    data = form_values(page.text, "preview")
    data.update(required_values("slack", name="chat"))
    assert client.post("/config/channels/new/slack", data=data).status_code == 403
    assert client.get("/config/channels/new", query_string={"kind": "slack"}).status_code == 403


def _write_unparseable_backup(config):
    from datetime import datetime, timezone
    import secrets as token_source

    backup_dir = config.config_path.parent / ("." + config.config_path.name + ".backups")
    backup_dir.mkdir(mode=0o700, exist_ok=True)
    backup_dir.chmod(0o700)
    name = (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ-")
            + token_source.token_hex(8) + ".toml")
    path = backup_dir / name
    path.write_text("this is = = not toml\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _temporary_secret_files(config):
    directory = config_module._secret_directory(config)
    if not directory.exists():
        return set()
    return {path for path in directory.iterdir()
            if path.name.startswith((config_module.SECRET_PREFIX, config_module.STAGE_PREFIX))}


@pytest.mark.parametrize("form", ["wizard", "full"])
def test_failed_preview_file_is_retried_when_reference_discovery_was_incomplete(tmp_path, form):
    config = make_config(tmp_path)
    make_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    bad_backup = _write_unparseable_backup(config)
    if form == "wizard":
        values = required_values("webhook", name="hook")
        values["g0_url_file_new"] = "not a URL"
        response = post_preview(client, "webhook", **values)
    else:
        response = _full_channel_preview(client, "webhook", name="hook", secret="not a URL")
    assert response.status_code == 400
    # An unreadable retained backup means references cannot be checked, so the
    # file is kept for now, but it must stay tracked for a later cleanup.
    left = _temporary_secret_files(config)
    assert left
    bad_backup.unlink()
    app.extensions["dashboard_config"].cleanup()
    assert not _temporary_secret_files(config)
