"""Structured configuration controls and narrowly scoped session invalidation."""

import html
import re
import tomllib

import pytest

from cvebeacon import dashboard_config as editor_module
from test_dashboard import setup
from test_dashboard_config import accounts, account_fixture, preview, confirm, form
from test_dashboard_accounts import login, csrf


@pytest.mark.parametrize("section,changes,ends", [
    ("http", {"g0_retries": "4"}, False),
    ("watch", {"g0_initial": "backfill"}, False),
    ("sources", {"g0_nvd_enabled": "false"}, False),
    ("inventory", {"g0_header_row": "2"}, False),
    ("dashboard", {"g0_session_idle_seconds": "120"}, True),
    ("reporting", {"g0_identity": "registered"}, True),
])
def test_session_policy_for_both_clients(accounts, section, changes, ends):
    _, _, app, client = accounts
    other = app.test_client()
    login(client, "admin")
    login(other, "admin")
    old_csrf = csrf(other)
    response = preview(client, section, **changes)
    assert confirm(client, response, section, lockout="yes").status_code == 303
    assert client.get("/").status_code == (303 if ends else 200)
    assert other.get("/").status_code == (303 if ends else 200)
    if not ends:
        assert csrf(other) == old_csrf
        assert "Saved; takes effect on the next run" in client.get("/config/" + section + "?saved=1").text


def test_unknown_changes_end_sessions():
    assert editor_module.session_settings_changed({}, {"future": {"enabled": True}})
    assert editor_module.session_settings_changed({}, {"watch": {"future": True}})
    assert not editor_module.session_settings_changed({}, {"http": {"retries": 4}})


@pytest.mark.parametrize("section,key,choices", [
    ("watch", "initial", ("baseline", "backfill", "full")),
    ("rules", "old_cves", ("digest", "alert", "ignore")),
    ("channels", "format", ("text", "html")),
    ("channels", "security", ("starttls", "tls", "none")),
    ("channels", "grouping", ("run", "event")),
])
def test_enum_controls(accounts, section, key, choices):
    login(accounts[3], "admin")
    page = accounts[3].get("/config/" + section).text
    select = re.search(r'<select name="g0_' + key + r'"[^>]*>(.*?)</select>', page, re.S)
    assert select
    for choice in choices:
        assert f'value="{choice}"' in select[1]


def test_checkbox_limits_required_and_help(accounts):
    login(accounts[3], "admin")
    page = accounts[3].get("/config/channels").text
    assert 'type="checkbox"' in page and 'data-boolean="g0_enabled"' in page
    assert 'name="g0_port"' in page and 'min="1" max="65535"' in page
    assert 'required</strong>' in page and 'Example:' in page
    page = accounts[3].get("/config/http").text
    assert 'placeholder="10.0"' in page


def test_addresses_normalized_and_channel_save_keeps_sessions(accounts):
    config, _, app, client = accounts
    login(client, "admin")
    other = app.test_client()
    login(other, "admin")
    response = preview(client, "channels", g0_name="email", g0_host="smtp.example.com",
                       g0_from="alerts@example.com", g0_to=" one@example.com, two@example.com, one@example.com ")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "channels").status_code == 303
    assert tomllib.loads(config.config_path.read_text())["watch"]["channels"]["email"]["to"] == ["one@example.com", "two@example.com"]
    response = preview(client, "channels", g0_format="html")
    assert confirm(client, response, "channels").status_code == 303
    assert other.get("/").status_code == 200 and client.get("/").status_code == 200


@pytest.mark.parametrize("section,changes,expected", [
    ("http", {"g0_retries": "oops", "g0_user_agent": "Example client"}, "http.retries"),
    ("channels", {"g0_name": "email", "g0_host": "smtp.example.com", "g0_from": "alerts@example.com", "g0_to": "broken"}, "to"),
    ("rules", {"g0_name": "example", "g0_condition": "{ kev = true }", "g0_channels": '["email"]'}, "condition.kev must be one of cisa, eu, any"),
])
def test_field_errors_retain_form(accounts, section, changes, expected):
    login(accounts[3], "admin")
    response = preview(accounts[3], section, **changes)
    assert response.status_code == 400
    assert expected in html.unescape(response.text)
    assert 'name="action" value="preview"' in response.text
    data = form(response.text)
    for key, value in changes.items():
        if key != "g0_name":
            assert data[key] == value


def test_condition_helper_from_schema(accounts):
    login(accounts[3], "admin")
    page = accounts[3].get("/config/rules").text
    from cvebeacon.watch.rules import LEAF_KEYS
    for key in LEAF_KEYS:
        assert f"{key} = " in html.unescape(page)
    assert 'kev = "cisa"' in html.unescape(page)


def test_secret_input_never_retained(accounts):
    login(accounts[3], "admin")
    response = preview(accounts[3], "channels", g0_name="email", g0_host="smtp.example.com",
                       g0_to="broken", g0_password_file_new="Synthetic secret contents 123")
    assert response.status_code == 400
    assert "Synthetic secret contents 123" not in response.text
    assert 'name="action" value="preview"' in response.text


def test_enum_metadata_covers_validator_enums():
    """Find enum validations in the loader rather than maintaining a UI-only list."""
    import ast
    import inspect
    from cvebeacon import config
    from cvebeacon.watch import catalog, channels, rules

    represented = [set(spec.choices) for spec in editor_module.FIELD_METADATA.values() if spec.choices]
    represented += [set(spec.item_choices) for spec in editor_module.FIELD_METADATA.values() if spec.item_choices]
    represented += [set(spec["choices"]) for spec in rules.CONDITION_SCHEMA.values() if "choices" in spec]
    functions = [(config, config.load_config), (channels, channels._common),
                 (channels, channels._parse_smtp), (channels, channels.parse_channels),
                 (catalog, catalog.canonical_language), (rules, rules._leaf_value),
                 (rules, rules._rule_old_cves), (rules, rules._rule_events), (rules, rules._rule_providers)]
    found = []
    for module, function in functions:
        for node in ast.walk(ast.parse(inspect.getsource(function))):
            allowed = None
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_enum":
                allowed = node.args[2]
            elif isinstance(node, ast.Compare) and any(isinstance(op, ast.NotIn) for op in node.ops):
                allowed = node.comparators[-1]
            if isinstance(allowed, ast.Name):
                values = getattr(module, allowed.id, None)
                if not isinstance(values, tuple) or not all(isinstance(value, str) for value in values):
                    continue
            elif isinstance(allowed, (ast.Set, ast.Tuple, ast.List)):
                try:
                    values = ast.literal_eval(allowed)
                except ValueError:
                    continue
                if not values or not all(isinstance(value, str) for value in values):
                    continue
            else:
                continue
            found.append(set(values))
    assert len(found) >= 10
    for values in found:
        assert values in represented, f"Missing enum metadata: {values}"


def test_metadata_covers_all_fields_and_condition_schema():
    from cvebeacon.watch import rules
    for specs in editor_module.SCHEMAS.values():
        for path, schema in specs:
            for key, default in schema.items():
                item = editor_module.FIELD_METADATA[f"{path}.{key}"]
                assert item.help and item.example is not None
                assert item.default == (str(default) if hasattr(default, "parts") else list(default) if isinstance(default, tuple) else default)
    assert set(rules.LEAF_KEYS) == set(rules.CONDITION_SCHEMA)
    for key, schema in rules.CONDITION_SCHEMA.items():
        assert rules.parse_condition({key: schema["example"]})
        if "choices" in schema:
            for choice in schema["choices"]:
                assert rules.parse_condition({key: choice})


@pytest.mark.parametrize("kind,values", [("ntfy", range(1, 6)), ("gotify", range(-2, 11))])
def test_priority_is_a_select(accounts, kind, values):
    login(accounts[3], "admin")
    page = accounts[3].get("/config/channels?new_type=" + kind).text
    select = re.search(r'<select name="g0_priority"[^>]*>(.*?)</select>', page, re.S)
    assert select
    for value in values:
        assert f'value="{value}"' in select[1]


@pytest.mark.parametrize("section,changes", [
    ("channels", {"g0_format": "html"}),
    ("rules", {"g0_name": "example", "g0_condition": "{ cvss_min = 9.0 }", "g0_channels": '["email"]'}),
    ("notifications", {"g1_recipients": "alerts@example.com"}),
    ("system", {"g1_directory": "new-reports"}),
    ("product-mappings", {"g0_vendor": "Example", "g0_product": "Widget", "g0_cpe": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"}),
])
def test_remaining_nonaccess_sections_keep_session_pool(accounts, section, changes):
    config, _, app, client = accounts
    document = tomllib.loads(config.config_path.read_text())
    document.setdefault("watch", {})["channels"] = {"email": {"type": "smtp", "host": "smtp.example.com", "from": "alerts@example.com", "to": ["alerts@example.com"]}}
    config.config_path.write_text(editor_module.dumps(document))
    login(client, "admin")
    sessions = app.extensions["account_sessions"]
    created = {key: entry.created for key, entry in sessions.sessions.items()}
    response = preview(client, section, **changes)
    assert confirm(client, response, section).status_code == 303
    assert client.get("/").status_code == 200
    assert app.extensions["dashboard_config"].active_app.extensions["account_sessions"] is sessions
    assert {key: entry.created for key, entry in sessions.sessions.items()} == created


def test_nonaccess_rollback_keeps_other_sessions(accounts):
    _, _, app, client = accounts
    other = app.test_client()
    login(client, "admin")
    login(other, "admin")
    assert confirm(client, preview(client, g0_retries="4")).status_code == 303
    assert confirm(client, preview(client, "backups"), "backups").status_code == 303
    assert client.get("/").status_code == 200
    assert other.get("/").status_code == 200


def test_numeric_metadata_matches_validator_bounds():
    import ast
    import inspect
    from cvebeacon import config
    from cvebeacon.watch import channels

    for module in (config, channels):
        for node in ast.walk(ast.parse(inspect.getsource(module))):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in {"_bounded_int", "_integer", "_number"}:
                continue
            if node.func.id == "_bounded_int":
                key, minimum, maximum = node.args[1:4]
                if not isinstance(key, ast.Constant):
                    continue
                specs = [editor_module.FIELD_METADATA[key.value]]
            else:
                key, minimum, maximum = node.args[1], node.args[-2], node.args[-1]
                if not isinstance(key, ast.Constant):
                    continue
                specs = [spec for identity, spec in editor_module.FIELD_METADATA.items()
                         if identity.startswith("watch.channels.") and identity.endswith("." + key.value)]
            minimum, maximum = ast.literal_eval(minimum), ast.literal_eval(maximum)
            assert specs
            if any(spec.choices for spec in specs):
                assert any(spec.choices and (min(spec.choices), max(spec.choices)) == (minimum, maximum) for spec in specs)
            else:
                for spec in specs:
                    assert spec.minimum == minimum or key.value == "min_interval_seconds" and spec.minimum == 3
                    assert spec.maximum == maximum


def test_pasted_condition_key_is_not_repeated(accounts):
    login(accounts[3], "admin")
    response = preview(accounts[3], "rules", g0_name="example", g0_condition="{ private_credential = true }", g0_channels='["email"]')
    assert response.status_code == 400
    assert "private_credential" not in response.text
    assert "watch.rules[0].condition" in response.text


@pytest.mark.parametrize("security,port", [("tls", 465), ("none", 25), ("starttls", 587)])
def test_smtp_port_placeholder_follows_security(security, port):
    document = {"watch": {"channels": {"email": {"type": "smtp", "security": security}}}}
    controls = editor_module.groups_for("channels", document)[0]["controls"]
    assert next(field for field in controls if field["key"] == "port")["default"] == str(port)
