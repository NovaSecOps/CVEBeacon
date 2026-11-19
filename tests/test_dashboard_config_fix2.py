"""Remaining disclosure and unchanged-form compatibility regressions."""

import html
import tomllib

import pytest

from cvebeacon import dashboard_config as dc
from cvebeacon.config import load_config
from test_dashboard import setup
from test_dashboard_config import accounts, account_fixture, preview, confirm, form
from test_dashboard_accounts import login
from test_dashboard_config_fix1 import email_channel


TOKEN = "SYNTHETIC-CREDENTIAL"
URL = "https://secret.example/token/" + TOKEN


@pytest.mark.parametrize("section,changes,secret", [
    ("rules", {"g0_condition": '{ kev = true } # ' + URL}, URL),
    ("rules", {"g0_condition": '{ kev = true } # KEY=' + TOKEN}, "KEY=" + TOKEN),
    ("rules", {"g0_condition": '{ kev = ["' + TOKEN + '"] }'}, TOKEN),
    ("watch", {"g0_sources": '["nvd"] # ' + URL, "g0_backfill_days": "oops"}, URL),
    ("watch", {"g0_sources": '["nvd"]\n# KEY=' + TOKEN, "g0_backfill_days": "oops"}, "KEY=" + TOKEN),
    ("rules", {"g0_condition": '{ kev = "cisa" } # ' + URL, "g0_channels": "broken"}, URL),
    ("rules", {"g0_condition": '{ cvss_min = ["' + TOKEN + '"] }'}, TOKEN),
    ("rules", {"g0_condition": '{ kev = { kev = "' + TOKEN + '" } }'}, TOKEN),
])
def test_structured_error_output_inspects_all_returned_text(accounts, section, changes, secret):
    config, users, _, client = accounts
    login(client, "admin")
    before, audit = config.config_path.read_bytes(), users.audit_count()
    if section == "rules":
        changes = {"g0_name": "example", "g0_channels": '["email"]', **changes}
    response = preview(client, section, **changes)
    assert response.status_code == 400
    assert secret not in html.unescape(response.text)
    assert config.config_path.read_bytes() == before
    assert users.audit_count() == audit


@pytest.mark.parametrize("key", ["to", "cc", "bcc", "recipients"])
@pytest.mark.parametrize("recipient", ["[alerts@example.com]", " [alerts@example.com]", '["alerts@example.com"]'])
def test_bracket_prefixed_existing_recipients_round_trip(accounts, key, recipient):
    config, _, _, client = accounts
    document = tomllib.loads(config.config_path.read_text())
    if key == "recipients":
        section = "notifications"
        document["notifications"] = {"email": {"recipients": [recipient]}}
    else:
        section = "channels"
        channel = email_channel()
        channel[key] = [recipient]
        document["watch"] = {"channels": {"email": channel}}
    config.config_path.write_text(dc.dumps(document))
    expected = load_config(config.config_path)
    login(client, "admin")
    response = preview(client, section)
    assert response.status_code == 200, response.text
    assert confirm(client, response, section).status_code == 303
    actual = load_config(config.config_path)
    if key == "recipients":
        assert actual.email.recipients == expected.email.recipients
    else:
        assert actual.watch.channels[0].options[key] == expected.watch.channels[0].options[key]


def test_untrusted_field_error_message_cannot_bypass_redaction(accounts, monkeypatch):
    login(accounts[3], "admin")
    def fail(*args, **kwargs):
        raise dc.FieldValidationError("watch.initial must not contain " + TOKEN)
    monkeypatch.setattr(dc, "parse_form", fail)
    response = preview(accounts[3], "watch", g0_initial=TOKEN)
    assert response.status_code == 400
    assert TOKEN not in html.unescape(response.text)


def test_legacy_required_message_accepts_recipient_names(accounts):
    login(accounts[3], "admin")
    response = preview(accounts[3], "notifications", g1_enabled="true", g1_sender="alerts@example.com")
    assert response.status_code == 400
    assert "notifications.email.recipients is required when enabled; expected a recipient list" in response.text


@pytest.mark.parametrize("literal", [
    '"quoted # hash"', "'literal # hash'", r'"escaped \" # hash"',
    '"""multiline\n# literal hash\nvalue"""', '"""suffix""""', '"""suffix"""""',
    "'''multiline\n# literal hash\nvalue'''", "'''suffix''''", "'''suffix'''''",
])
def test_comment_removal_preserves_all_toml_string_forms(accounts, literal):
    condition = '{ keyword = [' + literal + '], kev = true } # KEY=' + TOKEN
    expected = tomllib.loads("value = " + condition)["value"]
    login(accounts[3], "admin")
    response = preview(accounts[3], "rules", g0_name="example", g0_channels='["email"]', g0_condition=condition)
    assert response.status_code == 400
    assert TOKEN not in html.unescape(response.text)
    retained = form(response.text)["g0_condition"]
    assert tomllib.loads("value = " + retained)["value"] == expected
    assert "# KEY=" not in retained


def test_safe_kev_boolean_stays_available_for_correction(accounts):
    login(accounts[3], "admin")
    response = preview(accounts[3], "rules", g0_name="example", g0_channels='["email"]', g0_condition="{ kev = true }")
    assert response.status_code == 400
    assert form(response.text)["g0_condition"] == "{ kev = true }"
    assert "condition.kev must be one of cisa, eu, any" in response.text


@pytest.mark.parametrize("recipient", ["[example-distribution]", " [example-distribution]"])
def test_bracket_prefixed_legacy_distribution_names_round_trip(accounts, recipient):
    config, _, _, client = accounts
    document = tomllib.loads(config.config_path.read_text())
    document["notifications"] = {"email": {"recipients": [recipient]}}
    config.config_path.write_text(dc.dumps(document))
    expected = load_config(config.config_path).email.recipients
    login(client, "admin")
    response = preview(client, "notifications")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "notifications").status_code == 303
    assert load_config(config.config_path).email.recipients == expected


@pytest.mark.parametrize("condition", [
    '{ not = ["' + TOKEN + '"] }', '{ any = ["' + TOKEN + '"] }',
    '{ keyword = "' + TOKEN + '" }', '{ cwe = "' + TOKEN + '" }',
])
def test_wrong_condition_shapes_never_return_unclassified_strings(accounts, condition):
    login(accounts[3], "admin")
    response = preview(accounts[3], "rules", g0_name="example", g0_channels='["email"]', g0_condition=condition)
    assert response.status_code == 400
    assert TOKEN not in html.unescape(response.text)
