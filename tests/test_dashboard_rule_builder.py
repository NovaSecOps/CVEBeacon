"""The visual rule builder must reuse the text form pipeline exactly."""

from __future__ import annotations

import html
import re
import sys
import tomllib
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlencode

import pytest
from werkzeug.datastructures import MultiDict

from cvebeacon import dashboard, dashboard_config, dashboard_rule_builder as builder
from cvebeacon.config import load_config
from cvebeacon.dashboard_watch import RULES_REQUEST_BYTES
from cvebeacon.errors import ConfigurationError
from cvebeacon.rule_builder import (
    CRITERIA,
    CRITERIA_BY_KEY,
    describe,
    read_condition,
)
from cvebeacon.watch.records import CVSSEntry, KEVFields, Product, WatchRecord
from cvebeacon.watch.rules import CONDITION_SCHEMA, parse_condition, rule_hash
from cvebeacon.watch.users import BOOTSTRAP, UserStore

PASSWORD = "Synthetic rule builder password"
CHANNEL = {
    "email": {
        "type": "smtp",
        "host": "smtp.example.com",
        "from": "alerts@example.com",
        "to": ["security@example.com"],
    }
}


def document(rules=(), channels=None, sources=None, watch_enabled=True):
    data = {
        "inventory": {"path": "inventory.csv"},
        "state": {"database": "state.db"},
        "output": {"directory": "reports"},
        "watch": {"enabled": watch_enabled, "rules": list(rules)},
    }
    if channels is None:
        channels = CHANNEL
    if channels:
        data["watch"]["channels"] = channels
    if sources is not None:
        data["watch"]["sources"] = list(sources)
    return data


def write_app(tmp_path, rules=(), channels=None, sources=None, watch_enabled=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    tmp_path.chmod(0o700)
    path = tmp_path / "config.toml"
    path.write_text(
        dashboard_config.dumps(
            document(rules, channels, sources, watch_enabled=watch_enabled)
        ),
        encoding="utf-8",
    )
    path.chmod(0o644)
    (tmp_path / "inventory.csv").write_text(
        "asset_id,vendor,product,version\na,Acme,Widget,1\n", encoding="utf-8"
    )
    config = load_config(path)
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    return config, app, client


def login(client, username="admin"):
    page = client.get("/login")
    assert page.status_code == 200
    token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    response = client.post(
        "/login", data={"csrf": token, "username": username, "password": PASSWORD}
    )
    assert response.status_code == 303


def page_form(text, action="preview"):
    """Return the controls a browser would submit for one real form."""
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", text, re.S)
    source = next(form for form in forms if f'name="action" value="{action}"' in form)
    data = MultiDict()
    for tag in re.findall(r"<input\b[^>]*>", source):
        attributes = dict(re.findall(r'([\w-]+)="([^"]*)"', tag))
        name = attributes.get("name")
        if not name:
            continue
        kind = attributes.get("type", "text")
        if kind in {"checkbox", "radio"} and " checked" not in tag:
            continue
        if " disabled" in tag:
            continue
        data.add(name, html.unescape(attributes.get("value", "")))
    for match in re.finditer(
        r"<textarea name=\"([^\"]+)\"([^>]*)>(.*?)</textarea>", source, re.S
    ):
        name, extra, contents = match.groups()
        if " disabled" in extra:
            continue
        data.add(name, html.unescape(contents))
    for match in re.finditer(r"<select\b([^>]*)>(.*?)</select>", source, re.S):
        extra, contents = match.groups()
        attributes = dict(re.findall(r'([\w-]+)="([^"]*)"', extra))
        name = attributes.get("name")
        if not name or " disabled" in extra:
            continue
        options = re.findall(r"<option([^>]*)>(.*?)</option>", contents, re.S)
        selected = next(
            ((option, text) for option, text in options if "selected" in option),
            options[0] if options else ("", ""),
        )
        value = re.search(r'value="([^"]*)"', selected[0])
        data.add(name, html.unescape(value[1] if value else selected[1]))
    return data


def confirm(client, response, section="rules"):
    assert response.status_code == 200, response.text
    data = page_form(response.text, "confirm")
    return client.post(f"/config/{section}", data=data)


def preview(client, page, **changes):
    data = page_form(page.text)
    data.update(changes)
    return client.post("/config/rules", data=data)


def row_summary(text, index):
    found = re.search(
        rf'<p class="muted" id="rule-{index}-summary">(.*?)</p>', text, re.S
    )
    return found.group(1).strip() if found else None


def mode_checked(text, index):
    found = re.search(rf'name="b{index}_mode" value="([a-z]+)" checked', text)
    return found.group(1) if found else None


def selected_use(text, index, key):
    match = re.search(
        rf'id="b{index}_{key}_use".*?</select>', text, re.S
    )
    if match is None:
        return None
    selected = re.search(r'<option value="([^"]*)"[^>]*selected', match.group(0))
    return selected.group(1) if selected else ""


def value_of(text, index, key):
    match = re.search(rf'id="b{index}_{key}_value"[^>]*>', text)
    if match is None:
        return None
    value = re.search(r'value="([^"]*)"', match.group(0))
    return html.unescape(value.group(1)) if value else None


def selected_option(text, identifier):
    match = re.search(rf'<select id="{re.escape(identifier)}".*?</select>', text, re.S)
    if match is None:
        return None
    selected = re.search(r'<option value="([^"]*)"[^>]*selected', match.group(0))
    return html.unescape(selected.group(1)) if selected else None


def assert_rendered_builder_state(text, index, condition):
    read = read_condition(condition)
    if read.model is None:
        assert mode_checked(text, index) == "text"
        assert read.reason in text
        assert f'id="rule-{index}-criteria"' not in text
        return

    model = read.model
    assert mode_checked(text, index) == "builder"
    assert selected_option(text, f"b{index}_join") == model.join
    for criterion in CRITERIA:
        expected = model.uses.get(criterion.key)
        assert selected_use(text, index, criterion.key) == (expected[0] if expected else "")
        if expected is None:
            continue
        value = (
            selected_option(text, f"b{index}_{criterion.key}_value")
            if CRITERIA_BY_KEY[criterion.key].kind == "enum"
            else value_of(text, index, criterion.key)
        )
        model_value = expected[1]
        if isinstance(model_value, tuple):
            assert value.split(", ") == list(model_value)
        elif isinstance(model_value, float):
            assert Decimal(value) == Decimal(repr(model_value))
        else:
            assert value == model_value
    assert row_summary(text, index) == describe(model)


def model_rule(condition, name="rule"):
    return {
        "name": name,
        "condition": condition,
        "channels": ["email"],
        "events": ["match"],
    }


REPRESENTABLE = [
    ({"kev": "cisa"}, "Alert when: on the CISA list."),
    (
        {"any": [{"kev": "cisa"}, {"cvss_min": 9.0}]},
        "Alert when ANY of: on the CISA list; severity score at least 9.0.",
    ),
    (
        {"all": [{"kev": "eu"}, {"epss_min": 0.5}]},
        "Alert when ALL of: on the EU list; exploitation chance at least 0.5.",
    ),
    (
        {"all": [{"kev": "cisa"}, {"not": {"status": "rejected"}}]},
        "Alert when: on the CISA list. Never alert when: status is Rejected.",
    ),
    (
        {
            "all": [
                {"any": [{"vendor": ["Example Corp"]}, {"product": ["Widget"]}]},
                {"not": {"any": [{"status": "rejected"}, {"cwe": [79]}]}},
            ]
        },
        "Alert when ANY of: vendor is Example Corp; product is Widget. "
        "Never alert when any of: weakness type is CWE-79; status is Rejected.",
    ),
    (
        {"all": [{"kev": "cisa"}]},
        "Alert when: on the CISA list.",
    ),
]

TEXT_MODE = [
    ({"kev": "cisa", "cvss_min": 9.0}, "several criteria in one block"),
    ({"any": [{"kev": "cisa"}, {"kev": "eu"}]}, "same criterion more than once"),
    ({"all": [{"any": [{"kev": "cisa"}, {"cvss_min": 9.0}]}, {"kev": "eu"}]}, "groups criteria"),
    ({"not": {"kev": "cisa"}}, "groups criteria"),
    (
        {"cvss_min": {"score": 9.0, "versions": ["4.0"]}},
        "score limits for particular versions or sources",
    ),
    ({"vendor": ["Example, Inc"]}, "contains a comma"),
]


def test_render_criteria_matches_the_model():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as directory:
        _, _, client = write_app(Path(directory))
        text = client.get("/config/rules").text
    table = text[text.index('class="criteria-table"'):]
    rows = re.findall(
        r'<tr class="criterion" data-criterion="([^"]+)">(.*?)</tr>', table, re.S
    )
    assert [key for key, _ in rows] == [criterion.key for criterion in CRITERIA]
    assert set(CONDITION_SCHEMA) == {criterion.key for criterion in CRITERIA}
    for key, body in rows:
        criterion = CRITERIA_BY_KEY[key]
        header = re.search(r"<th scope=\"row\">(.*?)<p class=\"help\"[^>]*>(.*?)</p>", body, re.S)
        assert header is not None
        assert header.group(1).strip() == criterion.label
        assert header.group(2).strip() == criterion.help
        if criterion.kind == "enum":
            options = re.findall(
                rf'id="b0_{key}_value".*?</select>', body, re.S
            )
            assert options
            values = re.findall(r'<option value="([^"]*)"', options[0])
            assert values == [choice for choice, _ in criterion.choices]
        elif criterion.kind == "number":
            assert f'min="{criterion.minimum}"' in body
            assert f'max="{criterion.maximum}"' in body
            assert f'step="{criterion.step}"' in body


def test_representable_conditions_open_in_the_form_and_describe_in_words(tmp_path):
    rules = [model_rule(condition, name=f"rule-{index}") for index, (condition, _) in enumerate(REPRESENTABLE)]
    _, _, client = write_app(tmp_path, rules)
    text = client.get("/config/rules").text
    for index, (condition, expected) in enumerate(REPRESENTABLE):
        assert mode_checked(text, index) == "builder"
        assert row_summary(text, index) == expected
        model = read_condition(condition).model
        assert describe(model) == expected
        assert_rendered_builder_state(text, index, condition)


DOCUMENTED = [
    {"any": [{"cvss_min": 9.0}, {"epss_min": 0.5}]},
    {"all": [{"cvss_min": 9.0}, {"epss_min": 0.5}]},
    {"cvss_min": 9.0},
    {"cvss_min": {"score": 9.0, "versions": ["4.0", "3.1"]}},
    {"epss_min": 0.5},
    {"kev": "any"},
    {"all": [{"kev": "any"}, {"any": [{"cvss_min": 8}, {"epss_min": 0.5}]}]},
    {"all": [{"vendor": ["microsoft"]}, {"cvss_min": 8}]},
    {"all": [{"cvss_min": 9}, {"not": {"vendor": ["examplecorp"]}}]},
    {"all": [{"vendor": ["palo_alto_networks"]}, {"not": {"product": ["globalprotect"]}}]},
]


def test_small_scores_are_described_in_plain_decimal(tmp_path):
    rules = [
        model_rule({"epss_min": 0.00001}, "tiny"),
        model_rule({"cvss_min": 9.55}, "precise"),
    ]
    _, _, client = write_app(tmp_path, rules)
    text = client.get("/config/rules").text
    for index, condition in enumerate(({"epss_min": 0.00001}, {"cvss_min": 9.55})):
        assert row_summary(text, index) == describe(read_condition(condition).model)
    assert value_of(text, 0, "epss_min") == "0.00001"
    assert value_of(text, 1, "cvss_min") == "9.55"


def test_every_schema_example_opens_in_the_form(tmp_path):
    rules = [
        model_rule({key: spec["example"]}, name=f"example-{key}")
        for key, spec in CONDITION_SCHEMA.items()
    ]
    _, _, client = write_app(tmp_path, rules)
    text = client.get("/config/rules").text
    for index, (key, spec) in enumerate(CONDITION_SCHEMA.items()):
        read = read_condition({key: spec["example"]})
        assert read.model is not None
        assert_rendered_builder_state(text, index, {key: spec["example"]})


def test_documented_conditions_render_the_same_model_as_the_rule_module(tmp_path):
    rules = [model_rule(condition, name=f"documented-{index}") for index, condition in enumerate(DOCUMENTED)]
    _, _, client = write_app(tmp_path, rules)
    text = client.get("/config/rules").text
    for index, condition in enumerate(DOCUMENTED):
        read = read_condition(condition)
        if read.model is not None:
            assert_rendered_builder_state(text, index, condition)
        else:
            assert_rendered_builder_state(text, index, condition)


def test_non_representable_conditions_stay_in_text_mode(tmp_path):
    rules = [model_rule(condition, name=f"rule-{index}") for index, (condition, _) in enumerate(TEXT_MODE)]
    _, _, client = write_app(tmp_path, rules)
    text = client.get("/config/rules").text
    for index, (condition, expected) in enumerate(TEXT_MODE):
        reason = read_condition(condition).reason
        assert expected in reason
        assert_rendered_builder_state(text, index, condition)
        assert f'name="g{index}_condition"' in text
        assert reason in text


def test_precise_threshold_renders_without_rounding(tmp_path):
    condition = {"cvss_min": 9.123456789123}
    _, _, client = write_app(tmp_path, [model_rule(condition)])
    text = client.get("/config/rules").text
    assert_rendered_builder_state(text, 0, condition)


def test_template_has_no_condition_reader_or_summary_mirror():
    template = Path(__file__).parents[1] / "src/cvebeacon/templates/_rule_builder.html"
    source = template.read_text(encoding="utf-8")
    for mirror in (
        "macro leaf_node",
        "macro flat_node",
        "macro classify",
        "macro describe_value",
        "macro describe_model",
        "macro number_text",
        "macro display_value",
    ):
        assert mirror not in source


@pytest.mark.parametrize(
    "condition",
    [
        {"not_a_key": 1},
        {},
        "not a table",
        {"kev": ["cisa"]},
        {"cvss_min": "high"},
    ],
)
def test_unreadable_conditions_use_the_p5_text_mode_reason(condition):
    rule = model_rule(condition)
    expected = read_condition(condition)
    state = builder.render_rule_builder_rows(document([rule]), count=1)[0]
    assert state == {
        "mode": "text",
        "join": "any",
        "uses": {},
        "values": {},
        "reason": expected.reason,
        "summary": "",
    }


def test_rules_render_hook_is_lazy_and_skips_an_absent_builder_module(monkeypatch):
    assert dashboard_config._rule_builder_render_context("http", {}, 0) == {}
    monkeypatch.setitem(sys.modules, "cvebeacon.dashboard_rule_builder", None)
    assert dashboard_config._rule_builder_render_context("rules", {}, 1) == {}


def test_initial_builder_values_channels_and_events(tmp_path):
    rule = {
        "name": "example",
        "condition": {"any": [{"kev": "cisa"}, {"cvss_min": 9.5}]},
        "channels": ["email"],
        "events": ["match", "kev_added"],
    }
    _, _, client = write_app(tmp_path, [rule])
    text = client.get("/config/rules").text
    assert selected_use(text, 0, "kev") == "include"
    assert selected_use(text, 0, "cvss_min") == "include"
    assert selected_use(text, 0, "status") == ""
    assert value_of(text, 0, "cvss_min") == "9.5"
    assert 'name="b0_channels" value="email" checked' in text
    assert 'name="b0_events" value="match" checked' in text
    assert 'name="b0_events" value="kev_added" checked' in text
    assert 'name="b0_events" value="rejected" checked' not in text
    assert '<option value="any" selected>' in text


def test_text_mode_keeps_the_existing_textareas(tmp_path):
    rule = model_rule({"kev": "cisa", "cvss_min": 9.0})
    _, _, client = write_app(tmp_path, [rule])
    text = client.get("/config/rules").text
    assert mode_checked(text, 0) == "text"
    assert 'name="g0_condition"' in text
    assert 'name="g0_channels"' in text
    assert 'name="g0_events"' in text
    assert "Edited as text" in text
    assert "b0_kev_use" not in text


def test_noop_save_keeps_every_rule_and_the_document_equal(tmp_path):
    rules = [
        model_rule({"kev": "cisa"}, "one"),
        model_rule({"any": [{"kev": "cisa"}, {"cvss_min": 9.0}]}, "two"),
        model_rule({"all": [{"kev": "eu"}, {"epss_min": 0.5}]}, "three"),
        {
            "name": "four",
            "condition": {"all": [{"kev": "cisa"}, {"not": {"status": "rejected"}}]},
            "channels": ["email"],
        },
        {
            "name": "five",
            "condition": {"vendor": ["Example Corp"]},
            "channels": ["email"],
            "events": ["rejected", "match"],
        },
        model_rule({"all": [{"kev": "cisa"}]}, "six"),
    ]
    config, app, client = write_app(tmp_path, rules)
    before_bytes = config.config_path.read_bytes()
    before = tomllib.loads(config.config_path.read_text(encoding="utf-8"))
    before_hashes = [rule_hash(rule) for rule in config.watch.rules]
    page = client.get("/config/rules")
    data = page_form(page.text)
    assert data.get("b0_mode") == "builder"
    assert data.get("b3_mode") == "builder"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200, response.text
    assert "No differences to show." in response.text
    assert confirm(client, response).status_code == 303
    assert config.config_path.read_bytes() == before_bytes
    after = tomllib.loads(config.config_path.read_text(encoding="utf-8"))
    assert after == before
    reloaded = load_config(config.config_path)
    assert [rule_hash(rule) for rule in reloaded.watch.rules] == before_hashes
    assert "events" not in after["watch"]["rules"][3]
    assert after["watch"]["rules"][4]["events"] == ["rejected", "match"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("kev", "cisa"),
        ("kev", "eu"),
        ("kev", "any"),
        ("exploitation", "poc"),
        ("exploitation", "active"),
        ("status", "published"),
        ("status", "rejected"),
        ("status", "reserved"),
    ],
)
def test_every_enum_value_is_selected_and_a_noop_save_keeps_it(tmp_path, key, value):
    condition = {key: value}
    config, _, client = write_app(tmp_path, [model_rule(condition)])
    page = client.get("/config/rules")
    data = page_form(page.text)
    assert data.get(f"b0_{key}_value") == value
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200, response.text
    assert confirm(client, response).status_code == 303
    saved = tomllib.loads(config.config_path.read_text(encoding="utf-8"))
    assert saved["watch"]["rules"][0]["condition"] == condition


def test_editing_one_rule_leaves_the_others_and_rule_hashes_alone(tmp_path):
    rules = [
        model_rule({"cvss_min": 9.0}, "first"),
        model_rule({"kev": "cisa"}, "second"),
    ]
    config, _, client = write_app(tmp_path, rules)
    before_second = config.watch.rules[1]
    before_second_hash = rule_hash(before_second)
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["b0_cvss_min_value"] = "9.5"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200, response.text
    assert confirm(client, response).status_code == 303
    saved = load_config(config.config_path)
    assert saved.watch.rules[0].condition == parse_condition({"cvss_min": 9.5})
    assert saved.watch.rules[1] == before_second
    assert rule_hash(saved.watch.rules[1]) == before_second_hash


def test_builder_mode_without_javascript_is_a_plain_post(tmp_path):
    rule = model_rule({"kev": "cisa"})
    _, _, client = write_app(tmp_path, [rule])
    page = client.get("/config/rules")
    data = page_form(page.text)
    assert data.get("b0_mode") == "builder"
    data["b0_kev_value"] = "eu"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200, response.text
    assert confirm(client, response).status_code == 303
    saved = load_config(client.application.extensions["dashboard_config"].path)
    assert saved.watch.rules[0].condition == parse_condition({"kev": "eu"})


def test_text_radio_without_javascript_uses_the_hidden_fallback(tmp_path):
    rule = model_rule({"kev": "cisa"})
    config, _, client = write_app(tmp_path, [rule])
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["b0_mode"] = "text"
    # Leave the builder controls in place, as a browser without JavaScript
    # would; the hidden text values are the fallback source.
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200, response.text
    assert confirm(client, response).status_code == 303
    saved = load_config(config.config_path)
    assert saved.watch.rules[0].condition == parse_condition({"kev": "cisa"})


@pytest.mark.parametrize(
    "change,message",
    [
        ("b0_cvss_min_value", "Severity score is at least: enter a number from 0 to 10."),
        ("b0_kev_value", "On a list of flaws known to be exploited: choose one of the options."),
        ("b0_vendor_value", "Vendor is one of: enter at least one value, separated by commas."),
        ("b0_cwe_value", "Weakness type is: use a CWE number such as 79 or CWE-787."),
    ],
)
def test_stage_a_errors_are_linked_to_the_field(tmp_path, change, message):
    _, _, client = write_app(tmp_path)
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["g0_name"] = "example"
    data["b0_kev_use"] = "include"
    data["b0_kev_value"] = "cisa"
    data["b0_channels"] = "email"
    data["b0_events"] = "match"
    if change == "b0_kev_value":
        data["b0_kev_value"] = "bad"
    elif change == "b0_vendor_value":
        data["b0_vendor_use"] = "include"
    elif change == "b0_cwe_value":
        data["b0_cwe_use"] = "include"
        data["b0_cwe_value"] = "not-a-cwe"
    elif change == "b0_cvss_min_value":
        data["b0_cvss_min_use"] = "include"
        data["b0_cvss_min_value"] = "11"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert "The rule was not saved" in response.text
    assert message in html.unescape(response.text)
    field = change
    assert f'href="#{field}"' in response.text
    assert 'aria-invalid="true"' in response.text
    assert f'id="{field.removesuffix("_value")}_error"' in response.text


def test_no_include_row_and_retained_values(tmp_path):
    _, _, client = write_app(tmp_path)
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["g0_name"] = "example"
    data["b0_channels"] = "email"
    data["b0_events"] = "match"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert "Choose at least one criterion to include." in response.text
    assert 'href="#rule-0-criteria"' in response.text
    assert 'aria-invalid="true"' in response.text

    data["b0_kev_use"] = "include"
    data["b0_kev_value"] = "cisa"
    data["b0_keyword_use"] = "include"
    data["b0_keyword_value"] = "https://example.invalid/private"
    data["b0_cvss_min_use"] = "include"
    data["b0_cvss_min_value"] = "11"
    response = client.post("/config/rules", data=data)
    # The keyword is credential-looking, so it is not echoed back on error.
    assert response.status_code == 400
    assert "https://example.invalid/private" not in response.text


def test_stage_b_backstop_maps_the_included_criterion(tmp_path, monkeypatch):
    _, _, client = write_app(tmp_path, [model_rule({"kev": "cisa"})])
    real = builder.parse_condition

    def broken(condition, *, path):
        raise ConfigurationError(
            f"{path}.any[1].cvss_min must be a number from 0 to 10"
        )

    monkeypatch.setattr(builder, "parse_condition", broken)
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["b0_kev_use"] = "include"
    data["b0_kev_value"] = "cisa"
    data["b0_cvss_min_use"] = "include"
    data["b0_cvss_min_value"] = "9.0"
    data["b0_channels"] = "email"
    data["b0_events"] = "match"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert "This criterion is not valid. Check the value and try again." in response.text
    assert 'href="#b0_cvss_min_value"' in response.text
    monkeypatch.setattr(builder, "parse_condition", real)


def test_stage_b_field_helper_maps_paths_to_included_criteria():
    model = read_condition(
        {"any": [{"kev": "cisa"}, {"cvss_min": 9.0}]}
    ).model
    assert builder._stage_b_field(
        ConfigurationError("watch.rules[0].condition.any[1].cvss_min is bad"), model
    ) == "cvss_min"
    assert builder._stage_b_field(
        ConfigurationError("watch.rules[0].condition must be a table"), model
    ) is None


def test_stage_c_source_errors_are_field_keyed(tmp_path):
    _, _, client = write_app(tmp_path, sources=["nvd"])
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["g0_name"] = "example"
    data["b0_kev_use"] = "include"
    data["b0_kev_value"] = "eu"
    data["b0_channels"] = "email"
    data["b0_events"] = "match"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert "The EU list is not turned on." in response.text

    data["b0_kev_value"] = "cisa"
    data["b0_epss_min_use"] = "include"
    data["b0_epss_min_value"] = "0.5"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert "EPSS data is not turned on." in response.text

    data.pop("b0_epss_min_use")
    data.pop("b0_epss_min_value")
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200, response.text


def test_missing_and_unknown_channels_and_events(tmp_path):
    _, _, client = write_app(tmp_path, channels={})
    text = client.get("/config/rules").text
    assert "No alert channel exists yet." in text

    page = client.get("/config/rules")
    data = page_form(page.text)
    data["g0_name"] = "example"
    data["b0_kev_use"] = "include"
    data["b0_kev_value"] = "cisa"
    data["b0_events"] = "match"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert "Choose at least one channel to send alerts to." in response.text
    assert 'href="#rule-0-channels"' in response.text

    _, _, client = write_app(tmp_path / "second", [model_rule({"kev": "cisa"})])
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["b0_channels"] = "other"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert "Choose an alert channel from the list." in response.text

    data = page_form(page.text)
    data["b0_events"] = "other"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert "Choose an alert type from the list." in response.text


def test_new_rule_without_events_keeps_the_defaults(tmp_path):
    _, _, client = write_app(tmp_path, channels=CHANNEL)
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["g0_name"] = "example"
    data["b0_kev_use"] = "include"
    data["b0_kev_value"] = "cisa"
    data["b0_channels"] = "email"
    # Every event stays checked, so the loader default should be used.
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200, response.text
    assert confirm(client, response).status_code == 303
    saved = tomllib.loads(client.application.extensions["dashboard_config"].path.read_text())
    assert "events" not in saved["watch"]["rules"][0]


@pytest.mark.parametrize(
    "field,value",
    [
        ("b0_unknown", "1"),
        ("b0_password_use", "include"),
        ("b9_mode", "builder"),
    ],
)
def test_forged_builder_fields_are_refused(tmp_path, field, value):
    config, _, client = write_app(tmp_path)
    before = config.config_path.read_bytes()
    page = client.get("/config/rules")
    data = page_form(page.text)
    data[field] = value
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert config.config_path.read_bytes() == before


def test_repeated_builder_field_is_refused(tmp_path):
    config, _, client = write_app(tmp_path)
    before = config.config_path.read_bytes()
    page = client.get("/config/rules")
    data = page_form(page.text)
    data.add("b0_kev_use", "include")
    response = client.post("/config/rules", data=data)
    assert response.status_code == 400
    assert config.config_path.read_bytes() == before


def test_missing_csrf_and_permission_are_refused(tmp_path):
    config, app, client = write_app(tmp_path, [model_rule({"kev": "cisa"})])
    page = client.get("/config/rules")
    data = page_form(page.text)
    data.pop("csrf")
    assert client.post("/config/rules", data=data).status_code == 400

    users = app.extensions["dashboard_users"]
    admin = users.authenticate("admin", PASSWORD)
    users.add("reader", password=PASSWORD)
    users.save_role("rules-reader", {"view"}, authorization=admin)
    users.edit_user("reader", role="rules-reader", disabled=False, authorization=admin)
    reader = app.test_client()
    login(reader, "reader")
    assert reader.get("/config/rules").status_code == 403
    token = re.search(r'name="csrf" value="([^"]+)"', reader.get("/account").text)[1]
    assert reader.post("/config/rules", data={"csrf": token}).status_code == 403


def test_match_preview_uses_the_same_evaluation_as_alerts(tmp_path):
    rules = [
        model_rule({"cvss_min": 9.0}, "critical"),
        model_rule({"kev": "cisa"}, "kev"),
        model_rule({"kev": "cisa", "cvss_min": 9.0}, "text"),
    ]
    config, app, client = write_app(tmp_path, rules)
    store = app.extensions["dashboard_watch"]["store"]
    store.upsert_nvd(
        [
            WatchRecord(
                cve_id="CVE-2026-0001",
                status="published",
                published="2026-11-01T00:00:00.000",
                last_modified="2026-11-02T00:00:00.000",
                description="Acme Widget flaw",
                source_identifier="security@example.test",
                cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8, "CVSS:3.1/AV:N", "CRITICAL"),),
                products=(Product("acme", "widget"),),
            ),
            WatchRecord(
                cve_id="CVE-2026-0002",
                status="published",
                published="2026-11-01T00:00:00.000",
                last_modified="2026-11-02T00:00:00.000",
                description="Acme Widget flaw",
                source_identifier="security@example.test",
                cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 7.5, "CVSS:3.1/AV:N", "HIGH"),),
                products=(Product("acme", "widget"),),
            ),
            WatchRecord(
                cve_id="CVE-2026-0003",
                status="rejected",
                published="2026-11-01T00:00:00.000",
                last_modified="2026-11-02T00:00:00.000",
                description="Acme Widget flaw",
                source_identifier="security@example.test",
                cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.9, "CVSS:3.1/AV:N", "CRITICAL"),),
                products=(Product("acme", "widget"),),
            ),
            WatchRecord(
                cve_id="CVE-2026-0004",
                status="published",
                published="2026-11-01T00:00:00.000",
                last_modified="2026-11-02T00:00:00.000",
                description="Acme Widget flaw",
                source_identifier="security@example.test",
                products=(Product("acme", "widget"),),
            ),
        ],
        catalogs=config.watch.sources,
    )
    store.replace_kev(
        "cisa",
        {"CVE-2026-0001": KEVFields("2026-11-02")},
        catalogs=config.watch.sources,
    )
    before = config.config_path.read_bytes()
    for index, expected in ((0, {"CVE-2026-0001"}), (1, {"CVE-2026-0001"}), (2, {"CVE-2026-0001"})):
        page = client.get("/config/rules")
        data = page_form(page.text)
        data["match_rule"] = str(index)
        response = client.post("/config/rules", data=data)
        assert response.status_code == 200, response.text
        assert "Recent CVE check" in response.text
        assert "1 of the 4 most recently changed stored CVEs match this rule." in response.text
        seen = set(re.findall(r"CVE-[0-9]{4}-[0-9]{4}", response.text))
        assert expected <= seen
    assert config.config_path.read_bytes() == before
    assert app.extensions["dashboard_config"].pending == {}

    page = client.get("/config/rules")
    data = page_form(page.text)
    data["match_rule"] = "99"
    assert client.post("/config/rules", data=data).status_code == 400


def test_match_preview_shows_the_text_condition_it_checked(tmp_path):
    config, app, client = write_app(
        tmp_path, [model_rule({"kev": "cisa", "cvss_min": 9.0}, "text")]
    )
    app.extensions["dashboard_watch"]["store"].upsert_nvd(
        [
            WatchRecord(
                cve_id="CVE-2026-0001",
                status="published",
                published="2026-11-01T00:00:00.000",
                last_modified="2026-11-02T00:00:00.000",
                description="Acme Widget flaw",
                source_identifier="security@example.test",
                cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8, "CVSS:3.1/AV:N", "CRITICAL"),),
                products=(Product("acme", "widget"),),
            )
        ],
        catalogs=config.watch.sources,
    )
    page = client.get("/config/rules")
    data = page_form(page.text)
    posted = '{ cvss_min = 9.0 }'
    data["g0_condition"] = posted
    data["match_rule"] = "0"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200
    assert "1 of the 1 most recently changed stored CVEs match this rule." in response.text
    textarea = re.search(
        r'<textarea name="g0_condition"[^>]*>(.*?)</textarea>', response.text, re.S
    )
    assert textarea is not None
    assert html.unescape(textarea.group(1)).strip() == posted


def test_match_preview_keeps_the_stored_score_providers(tmp_path):
    rule = {
        "name": "cna-only",
        "condition": {"cvss_min": 9.0},
        "channels": ["email"],
        "cvss_providers": ["cna"],
    }
    config, app, client = write_app(tmp_path, [rule])
    app.extensions["dashboard_watch"]["store"].upsert_nvd(
        [
            WatchRecord(
                cve_id="CVE-2026-0001",
                status="published",
                published="2026-11-01T00:00:00.000",
                last_modified="2026-11-02T00:00:00.000",
                description="Acme Widget flaw",
                source_identifier="security@example.test",
                cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8, "CVSS:3.1/AV:N", "CRITICAL"),),
                products=(Product("acme", "widget"),),
            )
        ],
        catalogs=config.watch.sources,
    )
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["match_rule"] = "0"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200
    assert "0 of the 1 most recently changed stored CVEs match this rule." in response.text


def test_match_preview_empty_store_and_invalid_builder(tmp_path):
    config, app, client = write_app(tmp_path, [model_rule({"cvss_min": 9.0})])
    assert not config.watch.database.exists()
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["match_rule"] = "0"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200
    assert "No CVEs are stored yet." in response.text

    data = page_form(page.text)
    data["match_rule"] = "0"
    data["b0_cvss_min_value"] = "11"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200
    assert "Check the highlighted criteria." in response.text
    assert app.extensions["dashboard_config"].pending == {}


def test_match_preview_requires_csrf(tmp_path):
    _, _, client = write_app(tmp_path, [model_rule({"kev": "cisa"})])
    page = client.get("/config/rules")
    data = page_form(page.text)
    data["match_rule"] = "0"
    data.pop("csrf")
    assert client.post("/config/rules", data=data).status_code == 400


def test_optional_script_is_external_and_the_page_needs_no_inline_code(tmp_path):
    _, _, client = write_app(tmp_path, [model_rule({"kev": "cisa"})])
    text = client.get("/config/rules").text
    assert '<script src="/static/rule_builder.js" defer></script>' in text
    assert not re.search(r"(?i)<script\b(?![^>]*\bsrc=)", text)
    assert "data-rule-use" in text
    assert client.get("/static/rule_builder.js").status_code == 200
    for word in ("protected", "all set", "working", "healthy", "not affected"):
        assert re.search(rf"\b{word}\b", text.lower()) is None


def test_read_only_builder_is_disabled(tmp_path):
    import os

    if os.name != "posix":
        pytest.skip("POSIX permissions")
    config, _, client = write_app(tmp_path, [model_rule({"kev": "cisa"})])
    tmp_path.chmod(0o555)
    try:
        text = client.get("/config/rules").text
        assert "Read-only configuration" in text
        assert "Check against recent CVEs" not in text
        assert re.search(r'name="b0_kev_use"[^>]* disabled', text)
    finally:
        tmp_path.chmod(0o700)


@pytest.mark.parametrize("watch_enabled", [True, False])
def test_maximum_rule_page_saves_as_a_byte_identical_noop(
    tmp_path, watch_enabled
):
    rules = [model_rule({"kev": "cisa"}, f"rule-{index}") for index in range(100)]
    config, _, client = write_app(
        tmp_path, rules, watch_enabled=watch_enabled
    )
    before = config.config_path.read_bytes()
    page = client.get("/config/rules")
    assert page.status_code == 200
    data = page_form(page.text)
    assert data.get("row_count") == "101"
    body_size = len(urlencode(list(data.items(multi=True))).encode("utf-8"))
    assert 8192 < body_size < RULES_REQUEST_BYTES

    response = client.post("/config/rules", data=data)
    assert response.status_code == 200, response.text
    assert "No differences to show." in response.text
    assert confirm(client, response).status_code == 303
    assert config.config_path.read_bytes() == before


def test_rules_post_just_over_its_body_limit_gets_413(tmp_path):
    _, _, client = write_app(tmp_path)
    page = client.get("/config/rules")
    token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    body = urlencode(
        {"csrf": token, "padding": "x" * RULES_REQUEST_BYTES}
    ).encode("utf-8")
    assert len(body) > RULES_REQUEST_BYTES
    response = client.post(
        "/config/rules",
        data=body,
        content_type="application/x-www-form-urlencoded",
    )
    assert response.status_code == 413


def test_another_post_route_keeps_the_8kib_body_limit(tmp_path):
    _, _, client = write_app(tmp_path)
    page = client.get("/config/http")
    data = page_form(page.text)
    data["padding"] = "x" * 8192
    response = client.post("/config/http", data=data)
    assert response.status_code == 413
