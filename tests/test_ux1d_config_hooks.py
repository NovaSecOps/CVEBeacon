"""Regression tests for the configuration hooks used by the guided setup pages."""

import os
import time

from flask import request
import pytest
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest

from cvebeacon import dashboard_config as config_module
from cvebeacon import dashboard_rule_builder
from test_dashboard import setup as base_setup
from test_dashboard_accounts import accounts as account_fixture, login


@pytest.fixture
def setup(base_setup):
    base_setup[0].config_path.chmod(0o644)
    return base_setup


@pytest.fixture
def accounts(account_fixture):
    account_fixture[0].config_path.chmod(0o644)
    return account_fixture


def form_data(document, section, **changes):
    groups = config_module.groups_for(section, document)
    data = {"csrf": "a" * 64, "version": "test-version", "action": "preview",
            "row_count": str(len(groups))}
    for group in groups:
        for control in group["controls"]:
            data[control["id"]] = control["value"]
    data.update(changes)
    return data


def parse(editor, section, document, current, data, *, form=None, count=None):
    return config_module.parse_form(
        editor, section, document, current, {"view", config_module.SECTIONS[section]},
        count=count, form=form if form is not None else MultiDict(data))


def test_explicit_form_matches_request_form(setup):
    config, _, client = setup
    app = client.application
    editor = app.extensions["dashboard_config"]
    document, _, _, _, current = editor.read()
    data = form_data(document, "http", g0_retries="4")

    with app.test_request_context("/config/http", method="POST", data=data):
        implicit = parse(editor, "http", document, current, data)
        explicit = parse(editor, "http", document, current, data, form=request.form)

    assert implicit[0] == explicit[0]
    assert implicit[1:] == explicit[1:]
    assert explicit[0]["http"]["retries"] == 4


def test_explicit_form_does_not_read_request_form(setup):
    _, _, client = setup
    app = client.application
    editor = app.extensions["dashboard_config"]
    document, _, _, _, current = editor.read()
    submitted = form_data(document, "http", g0_retries="4")

    with app.test_request_context("/config/http", method="POST",
                                  data={"csrf": "b" * 64, "g0_retries": "9"}):
        result = parse(editor, "http", document, current, submitted,
                       form=MultiDict(submitted))

    assert result[0]["http"]["retries"] == 4


def test_explicit_form_still_rejects_unknown_fields(setup):
    _, _, client = setup
    app = client.application
    editor = app.extensions["dashboard_config"]
    document, _, _, _, current = editor.read()
    data = form_data(document, "http")
    data["b0_join"] = "any"

    with app.test_request_context("/config/http", method="POST", data=data):
        with pytest.raises(BadRequest):
            parse(editor, "http", document, current, data)


def test_field_error_exposes_key_and_reason(setup):
    _, _, client = setup
    app = client.application
    editor = app.extensions["dashboard_config"]
    document, _, _, _, current = editor.read()
    data = form_data(document, "http", g0_retries="not-a-number")

    with app.test_request_context("/config/http", method="POST", data=data):
        with pytest.raises(config_module.FieldValidationError) as caught:
            parse(editor, "http", document, current, data)

    assert caught.value.key == "retries"
    assert caught.value.reason == "value"
    assert str(caught.value) == "http.retries must be a TOML number"


def test_required_field_error_exposes_key_and_reason(setup):
    _, _, client = setup
    app = client.application
    editor = app.extensions["dashboard_config"]
    document, _, _, _, current = editor.read()
    data = {"csrf": "a" * 64, "version": "test-version", "action": "preview",
            "row_count": "1", "g0_name": "Example rule"}

    with app.test_request_context("/config/rules", method="POST", data=data):
        with pytest.raises(config_module.FieldValidationError) as caught:
            parse(editor, "rules", document, current, data, count=1)

    assert caught.value.key == "condition"
    assert caught.value.reason == "required"


def test_field_error_without_a_known_control_has_no_key():
    error = config_module.FieldValidationError("not a control", "value")
    assert error.key is None
    assert error.reason == "value"
    assert str(error) == "Invalid configuration field; use the expected format"


def test_form_row_count_uses_an_explicit_mapping(setup):
    _, _, client = setup
    app = client.application
    with app.test_request_context("/config/http", method="POST", data={"row_count": "1"}):
        assert config_module.form_row_count() == 1
        assert config_module.form_row_count(MultiDict({"row_count": "2"})) == 2
        with pytest.raises(BadRequest):
            config_module.form_row_count(MultiDict({"row_count": "102"}))


def test_rule_builder_hooks_leave_unconverted_fields_alone(setup):
    _, _, client = setup
    app = client.application
    editor = app.extensions["dashboard_config"]
    document, _, _, _, current = editor.read()
    posted = MultiDict({"row_count": "1", "g0_name": "Example rule", "g0_condition": "{}"})

    prepared = dashboard_rule_builder.prepare_rules_form(posted, document, current, 1)
    assert dict(prepared) == dict(posted)
    assert dashboard_rule_builder.match_preview(posted, document, current) is None


def test_rule_page_calls_the_builder_hook(accounts, monkeypatch):
    config, _, app, client = accounts
    login(client, "admin")
    config.config_path.write_text(
        config.config_path.read_text(encoding="utf-8")
        + '\n[watch.channels.email]\ntype = "smtp"\nhost = "smtp.example.com"\n'
          'from = "alerts@example.com"\nto = ["security@example.com"]\n',
        encoding="utf-8")
    calls = []

    def record(form, document, current_config, count):
        calls.append((dict(form), count))
        return form

    monkeypatch.setattr(dashboard_rule_builder, "prepare_rules_form", record)
    page = client.get("/config/rules")
    assert page.status_code == 200
    editor = app.extensions["dashboard_config"]
    document, _, _, version, _ = editor.read()
    data = form_data(document, "rules", g0_name="Example rule",
                     g0_condition='{ kev = "cisa" }', g0_channels='["email"]',
                     g0_events='["match"]')
    data["version"] = version
    data["csrf"] = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200
    assert calls and calls[0][1] == 1


def rules_request(client, editor, **changes):
    page = client.get("/config/rules")
    assert page.status_code == 200
    document, _, _, version, _ = editor.read()
    data = form_data(document, "rules", g0_name="Example rule",
                     g0_condition='{ kev = "cisa" }', g0_channels='["email"]',
                     g0_events='["match"]', **changes)
    data["version"] = version
    data["csrf"] = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    return data


def test_match_button_reaches_the_hook_from_the_rendered_form(accounts, monkeypatch):
    config, _, app, client = accounts
    login(client, "admin")
    editor = app.extensions["dashboard_config"]
    before = config.config_path.read_bytes()
    calls, rendered = [], []
    result = {"matches": [], "total": 0}

    def match(form, document, current_config):
        calls.append(dict(form))
        return result

    real_render = config_module.render_template

    def record_render(template, **context):
        if template == "config_section.html":
            rendered.append(context)
        return real_render(template, **context)

    monkeypatch.setattr(dashboard_rule_builder, "match_preview", match)
    monkeypatch.setattr(config_module, "render_template", record_render)

    data = rules_request(client, editor, match_rule="0")
    response = client.post("/config/rules", data=data)

    assert response.status_code == 200
    assert calls and calls[0]["match_rule"] == "0"
    assert calls[0]["action"] == "preview"
    assert rendered[-1]["match"] == result
    assert editor.pending == {}
    assert config.config_path.read_bytes() == before


def test_confirm_request_never_calls_the_match_hook(accounts, monkeypatch):
    _, _, app, client = accounts
    login(client, "admin")
    editor = app.extensions["dashboard_config"]
    page = client.get("/config/rules")
    assert page.status_code == 200
    calls = []
    monkeypatch.setattr(dashboard_rule_builder, "match_preview",
                        lambda form, document, current: calls.append(dict(form)))

    response = client.post("/config/rules", data={
        "csrf": page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0],
        "action": "confirm", "match_rule": "0", "preview": "missing"})

    assert response.status_code == 400
    assert calls == []


def test_match_request_does_not_clean_up_or_take_the_writer_lock(accounts, monkeypatch):
    _, _, app, client = accounts
    login(client, "admin")
    editor = app.extensions["dashboard_config"]
    page = client.get("/config/rules")
    assert page.status_code == 200
    document, _, _, version, _ = editor.read()
    data = form_data(document, "rules", g0_name="Example rule",
                     g0_condition='{ kev = "cisa" }', g0_channels='["email"]',
                     g0_events='["match"]', match_rule="0")
    data["version"] = version
    data["csrf"] = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    data.pop("action")  # The match dispatch also accepts an action-less check.

    editor.secret_dir.mkdir(mode=0o700, exist_ok=True)
    expired = editor.secret_dir / (config_module.STAGE_PREFIX + "expired-match-check")
    expired.write_text("synthetic staged value", encoding="utf-8")
    old = time.time() - config_module.PREVIEW_SECONDS - 60
    os.utime(expired, (old, old))
    lock_path = editor.path.with_name(".config-" + editor.path.name + ".lock")
    lock_path.unlink(missing_ok=True)

    monkeypatch.setattr(dashboard_rule_builder, "match_preview",
                        lambda form, document, current: {"matches": [], "total": 0})
    response = client.post("/config/rules", data=data)

    assert response.status_code == 200
    assert not lock_path.exists()
    assert expired.exists()


def test_config_confirm_defaults_and_optional_targets(setup):
    _, _, client = setup
    app = client.application
    template = app.jinja_env.get_template("config_confirm.html")
    with app.test_request_context("/config/http"):
        default = template.render(csrf="token", preview="preview", diff=None, lockout=False)
        custom = template.render(csrf="token", preview="preview", diff=None, lockout=False,
                                 confirm_action="/config/channels/new/slack",
                                 back_url="/config/channels")
    assert '<form method="post" class="stack">' in default
    assert 'href="/config/http"' in default
    assert 'action="/config/channels/new/slack"' in custom
    assert 'href="/config/channels"' in custom


def test_guided_setup_links_appear_when_the_wizard_exists(accounts):
    _, _, app, client = accounts
    if "config_editor.channel_wizard" not in app.view_functions:
        app.add_url_rule("/config/channels/new", endpoint="config_editor.channel_wizard",
                         view_func=lambda: "")
    login(client, "admin")

    channels = client.get("/config/channels")
    assert channels.status_code == 200
    assert "Guided setup" in channels.text
    assert 'href="/config/channels/new"' in channels.text

    index = client.get("/config/")
    assert index.status_code == 200
    assert "Guided setup" in index.text
    assert index.text.index("Guided setup") < index.text.index("Watch settings")
