"""Teams bot controls inherit the channel editor's secret boundary."""

import re

from cvebeacon import dashboard
from cvebeacon.config import load_config
from cvebeacon.dashboard_config import groups_for
from test_dashboard import setup  # noqa: F401
from test_dashboard_accounts import accounts, login  # noqa: F401
from test_dashboard_config_fixes import BASE, confirm, make_secret, preview, set_role
from test_watch_teams_bot import APP, OTHER, SECRET, TENANT, USER


def test_teams_bot_field_metadata():
    groups = groups_for("channels", {}, new_type="teams_bot", can_manage=True, can_admin=True)
    controls = {field["key"]: field for field in groups[0]["controls"]}
    assert controls["recipients"]["kind"] == "toml"
    assert controls["conversation_references"]["kind"] == "toml"
    assert controls["format"]["default"] == "adaptive_card"
    assert "UUID" in controls["app_id"]["help"]
    assert controls["app_id"]["default"] == ""
    assert controls["recipients"]["default"] == "[]"
    assert controls["client_secret_file"]["secret"]
    assert controls["client_secret_file"]["allow_new_secret"]
    assert controls["tenant_id"]["required"] and controls["app_id"]["required"]
    assert controls["client_secret_file"]["required"] and not controls["recipients"]["required"]
    assert "client_secret_env" not in controls


def test_credential_row_requires_manage_secrets_for_recipient_change(accounts):
    config, users, _, _ = accounts
    secret = make_secret(config.config_path.parent / "teams-secret", SECRET)
    config.config_path.chmod(0o644)
    config.config_path.write_text(BASE + f'''
[watch]
enabled = true
sources = ["nvd"]

[watch.channels.bot]
type = "teams_bot"
tenant_id = "{TENANT}"
app_id = "{APP}"
client_secret_file = "{secret.name}"
recipients = ["{USER}"]
''', encoding="utf-8")
    client = dashboard.create_app(load_config(config.config_path)).test_client()
    set_role(users, "channel-editor", {"view", "edit_channels"})
    login(client)
    page = client.get("/config/channels?new_type=teams_bot")
    assert page.status_code == 200 and "teams_bot" in page.text
    assert re.search(r'<input type="text" name="g0_r_r0"[^>]*\breadonly\b', page.text)
    assert 'name="g0_client_secret_file" value="teams-secret" readonly' in page.text
    assert SECRET not in page.text
    before = config.config_path.read_bytes()
    denied = preview(client, "channels", g0_recipients=f'["{OTHER}"]')
    assert denied.status_code == 403
    assert config.config_path.read_bytes() == before
    set_role(users, "channel-manager", {"view", "edit_channels", "manage_secrets"})
    login(client)
    allowed = preview(client, "channels", g0_recipients=f'["{OTHER}"]')
    assert allowed.status_code == 200
    assert SECRET not in allowed.text
    assert confirm(client, allowed, "channels").status_code == 303
    assert load_config(config.config_path).watch.channels[0].options["recipients"] == (OTHER,)
