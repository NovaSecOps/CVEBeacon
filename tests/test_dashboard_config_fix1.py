"""Configuration review regressions: disclosure, compatibility and fail-closed saves."""

import html
import tomllib

import pytest

from cvebeacon import dashboard_config as dc
from cvebeacon.config import load_config
from test_dashboard import setup
from test_dashboard_config import accounts, account_fixture, preview, confirm, form
from test_dashboard_accounts import login


CREDENTIAL = "https://secret.example/token/SYNTHETIC-CREDENTIAL"


@pytest.mark.parametrize("key,pasted", [
    ("nvd_api_key_file", CREDENTIAL), ("nvd_api_key_file", "SYNTHETICTOKEN123"),
    ("nvd_api_key_env", "SYNTHETICTOKEN123"),
])
def test_failed_reference_controls_keep_baseline(accounts, key, pasted):
    config, _, _, client = accounts
    login(client, "admin")
    before = config.config_path.read_bytes()
    response = preview(client, "sources", **{"g0_" + key: pasted, "g0_minimum_request_interval": "oops"})
    assert response.status_code == 400
    assert pasted not in html.unescape(response.text)
    assert config.config_path.read_bytes() == before


@pytest.mark.parametrize("key", sorted({key for keys in dc.TYPE_KEYS.values() for key in keys if key.endswith("_file")}))
def test_channel_file_reference_not_redisplayed(accounts, key):
    _, _, _, client = accounts
    login(client, "admin")
    kind = next(kind for kind, keys in dc.TYPE_KEYS.items() if key in keys)
    page = client.get("/config/channels?new_type=" + kind)
    data = form(page.text)
    data.update({"g0_name": "example", "g0_max_items": "oops", "g0_" + key: "SYNTHETICTOKEN123"})
    response = client.post("/config/channels", data=data)
    assert response.status_code == 400
    assert "SYNTHETICTOKEN123" not in html.unescape(response.text)


@pytest.mark.parametrize("section,changes,pasted", [
    ("watch", {"g0_initial": CREDENTIAL}, CREDENTIAL),
    ("watch", {"g0_initial": "KEY=SYNTHETIC-CREDENTIAL"}, "KEY=SYNTHETIC-CREDENTIAL"),
    ("rules", {"g0_condition": '{ kev = "' + CREDENTIAL + '" }'}, CREDENTIAL),
    ("rules", {"g0_condition": '{ kev = "KEY=SYNTHETIC-CREDENTIAL" }'}, "KEY=SYNTHETIC-CREDENTIAL"),
    ("rules", {"g0_condition": '{ kev = "' + CREDENTIAL + '"'}, CREDENTIAL),
    ("rules", {"g0_condition": '{ kev = "KEY=SYNTHETIC-CREDENTIAL"'}, "KEY=SYNTHETIC-CREDENTIAL"),
    ("http", {"g0_user_agent": CREDENTIAL, "g0_retries": "oops"}, CREDENTIAL),
])
def test_rejected_structured_and_scalar_values_do_not_echo_credentials(accounts, section, changes, pasted):
    _, _, _, client = accounts
    login(client, "admin")
    if section == "rules":
        changes = {"g0_name": "example", "g0_channels": '["email"]', **changes}
    response = preview(client, section, **changes)
    assert response.status_code == 400
    assert pasted not in html.unescape(response.text)


def email_channel():
    return {"type": "smtp", "host": "smtp.example.com", "from": "alerts@example.com", "to": ["alerts@example.com"]}


@pytest.mark.parametrize("key", ["to", "cc", "bcc"])
@pytest.mark.parametrize("addresses", [
    ['"Doe, John" <john@example.com>'], ["one@example.com, two@example.com"],
])
def test_existing_address_arrays_round_trip(accounts, key, addresses):
    config, _, _, client = accounts
    document = tomllib.loads(config.config_path.read_text())
    channel = email_channel()
    channel[key] = addresses
    document["watch"] = {"channels": {"email": channel}}
    config.config_path.write_text(dc.dumps(document))
    assert load_config(config.config_path).watch.channels[0].options[key] == tuple(addresses)
    login(client, "admin")
    response = preview(client, "channels")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    assert list(load_config(config.config_path).watch.channels[0].options[key]) == addresses


@pytest.mark.parametrize("recipients", [["soc-distribution"], [f"list-{index}" for index in range(101)],
                                          ["one@example.com, two@example.com"], ["list", "list"]])
def test_legacy_recipients_keep_loader_semantics(accounts, recipients):
    config, _, _, client = accounts
    document = tomllib.loads(config.config_path.read_text())
    document["notifications"] = {"email": {"recipients": recipients}}
    config.config_path.write_text(dc.dumps(document))
    assert load_config(config.config_path).email.recipients == tuple(recipients)
    login(client, "admin")
    response = preview(client, "notifications")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "notifications").status_code == 303
    assert load_config(config.config_path).email.recipients == tuple(recipients)


def test_fixed_channel_error_identity_survives_redaction(accounts):
    config, _, _, client = accounts
    document = tomllib.loads(config.config_path.read_text())
    document["watch"] = {"channels": {"email": email_channel()}}
    config.config_path.write_text(dc.dumps(document))
    login(client, "admin")
    response = preview(client, "channels", g0_to="broken")
    assert response.status_code == 400
    assert "watch.channels.smtp.to (row 1)" in html.unescape(response.text)


@pytest.mark.parametrize("count", ["²", "9" * 5000])
def test_row_count_bad_digits_are_a_client_error(accounts, count):
    login(accounts[3], "admin")
    response = preview(accounts[3], row_count=count)
    assert response.status_code == 400


def test_notification_required_check_survives_group_reordering(accounts, monkeypatch):
    login(accounts[3], "admin")
    monkeypatch.setitem(dc.SCHEMAS, "notifications", list(reversed(dc.SCHEMAS["notifications"])))
    response = preview(accounts[3], "notifications", g0_enabled="true")
    assert response.status_code == 400
    assert "notifications.email.sender is required" in response.text


def test_checkbox_script_submits_both_states_and_preserves_untouched_defaults():
    import shutil
    import subprocess
    from pathlib import Path
    node = shutil.which("node")
    if node is None:
        pytest.skip("optional JavaScript runtime unavailable")
    script = r'''
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const submitted = {value: ""};
const checkbox = {
    dataset: {boolean: "g0_enabled"}, checked: true,
    form: {elements: {namedItem(name) {assert.equal(name, "g0_enabled"); return submitted;}}},
    addEventListener(event, listener) {assert.equal(event, "change"); this.change = listener;}
};
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf8"), {
    document: {querySelectorAll(selector) {assert.equal(selector, "[data-boolean]"); return [checkbox];}}
});
assert.equal(submitted.value, "");
checkbox.checked = false;
checkbox.change();
assert.equal(submitted.value, "false");
checkbox.checked = true;
checkbox.change();
assert.equal(submitted.value, "true");
'''
    path = Path(__file__).resolve().parents[1] / "src/cvebeacon/static/config.js"
    subprocess.run([node, "-e", script, str(path)], check=True, capture_output=True, text=True)


@pytest.mark.parametrize("section,changes", [
    ("sources", {"g0_nvd_api_key_env": "SYNTHETICTOKEN123", "g0_nvd_api_key_file_new": "Synthetic replacement contents"}),
    ("channels", {"g0_name": "email", "g0_host": "smtp.example.com", "g0_from": "alerts@example.com", "g0_to": "alerts@example.com", "g0_password_env": "SYNTHETICTOKEN123", "g0_password_file_new": "Synthetic replacement contents"}),
])
def test_staging_errors_do_not_repeat_submitted_reference_tokens(accounts, section, changes):
    login(accounts[3], "admin")
    response = preview(accounts[3], section, **changes)
    assert response.status_code == 400
    assert "SYNTHETICTOKEN123" not in html.unescape(response.text)
    assert "Synthetic replacement contents" not in html.unescape(response.text)
