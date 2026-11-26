"""Structured list controls keep their stored TOML values on no-op saves."""

from copy import deepcopy
import html
import re
import tomllib

import pytest
from werkzeug.datastructures import MultiDict

from cvebeacon.dashboard_config import groups_for
from cvebeacon.errors import ConfigurationError
from cvebeacon.config import load_config
from test_dashboard_accounts import accounts as account_fixture, login
from test_dashboard import setup
from test_dashboard_config_structured import (
    _BASE,
    _confirm,
    _document,
    _write_config,
)


@pytest.fixture
def accounts(account_fixture):
    account_fixture[0].config_path.chmod(0o644)
    return account_fixture


_CHANNELS = '''[watch]
enabled = true
sources = ["nvd"]

[watch.channels.smtp]
type = "smtp"
host = "smtp.example.com"
from = "alerts@example.com"
to = ["Primary@example.com", "copy@example.com"]
cc = ["copy@example.com"]
bcc = ["hidden@example.com"]

[watch.channels.graph]
type = "graph"
tenant_id = "tenant-example"
client_id = "client-example"
client_secret_env = "EXAMPLE_GRAPH_SECRET"
sender = "alerts@example.com"
to = ["graph@example.com"]
cc = ["copy@example.com"]
bcc = []
'''

_RULES = '''[watch]
enabled = true
sources = ["nvd"]

[[watch.rules]]
name = "critical"
condition = { cvss_min = 9.0 }
channels = ["smtp"]
events = ["match"]
'''

_RULE_CHANNEL = '''[watch.channels.smtp]
type = "smtp"
host = "smtp.example.com"
from = "alerts@example.com"
to = ["alerts@example.com"]
'''

_BOT = '''[watch]
enabled = true
sources = ["nvd"]

[watch.channels.bot]
type = "teams_bot"
tenant_id = "123e4567-e89b-12d3-a456-426614174000"
app_id = "123e4567-e89b-12d3-a456-426614174001"
client_secret_file = "bot-secret.txt"
recipients = [" Agent@Example.com ", "second@example.com"]

[[watch.channels.bot.conversation_references]]
conversation_id = "conversation-one"

[[watch.channels.bot.conversation_references]]
conversation_id = "conversation-two"
service_url = "https://smba.trafficmanager.net/teams/"
'''


def _write_bot_config(accounts, extra=_BOT):
    path = _write_config(accounts, extra)
    secret = path.parent / "bot-secret.txt"
    secret.write_text("synthetic bot secret\n", encoding="utf-8", newline="\n")
    secret.chmod(0o600)
    return path


def _field(control_groups, key):
    return next(control for group in control_groups for control in group["controls"]
                if control["key"] == key)


def _post_pairs(client, section, pairs):
    return client.post("/config/" + section, data=MultiDict(pairs))


def _set(data, name, value):
    data.setlist(name, [value])


def _form_pairs(page, *, action="preview", click=None):
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", page, re.S)
    source = next(part for part in forms if f'name="action" value="{action}"' in part)
    pairs = []
    for tag in re.findall(r"<(?:input|button)\b[^>]*>", source):
        attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', tag))
        name = attrs.get("name")
        if not name:
            continue
        if tag.startswith("<button"):
            if click == (name, attrs.get("value", "")):
                pairs.append((name, html.unescape(attrs.get("value", ""))))
            continue
        if attrs.get("type") == "checkbox" and "checked" not in tag:
            continue
        pairs.append((name, html.unescape(attrs.get("value", ""))))
    for name, contents in re.findall(r'<textarea name="([^"]+)"[^>]*>(.*?)</textarea>', source, re.S):
        pairs.append((name, html.unescape(contents)))
    for attrs_text, contents in re.findall(r"<select\b([^>]*)>(.*?)</select>", source, re.S):
        attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', attrs_text))
        name = attrs.get("name")
        if not name:
            continue
        options = re.findall(r"<option([^>]*)>(.*?)</option>", contents, re.S)
        selected = next((item for item in options if "selected" in item[0]), options[0] if options else ("", ""))
        match = re.search(r'value="([^"]*)"', selected[0])
        pairs.append((name, html.unescape(match[1] if match else selected[1])))
    return pairs


def _browser_form(page, *, action="preview", click=None):
    return MultiDict(_form_pairs(page, action=action, click=click))


def _post_rendered(client, section, page, *, action="preview", click=None, changes=None):
    data = _browser_form(page, action=action, click=click)
    for key, value in (changes or {}).items():
        data.setlist(key, [value])
    return client.post("/config/" + section, data=data)


def _channel_document(path):
    return _document(path)["watch"]["channels"]


def _response_detail(response):
    start = response.text.find("Configuration could not be loaded or saved")
    if start >= 0:
        return response.text[start:start + 700]
    match = re.search(r"<pre>(.*?)</pre>", response.text, re.S)
    if match:
        return html.unescape(match[1])
    return response.text[:500]


def _confirmed_document(client, path, section, preview):
    assert preview.status_code == 200, _response_detail(preview)
    before_confirm = path.read_bytes()
    saved = _confirm(client, section, preview)
    assert saved.status_code == 303, saved.text
    return before_confirm, saved


def test_render_all_list_controls_and_distinguish_recipient_semantics(accounts):
    path = _write_config(accounts, _CHANNELS + _BOT[_BOT.index("[watch.channels.bot]"):])
    secret = path.parent / "bot-secret.txt"
    secret.write_text("synthetic bot secret\n", encoding="utf-8", newline="\n")
    secret.chmod(0o600)
    # Legacy recipient names are a separate control from the watch-channel rows.
    path.write_text(
        '[notifications.email]\nrecipients = ["Ops Team", "ops@example.com"]\n\n'
        + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n",
    )
    _, _, _, client = accounts
    login(client, "admin")

    rules = client.get("/config/rules")
    notifications = client.get("/config/notifications")
    channels = client.get("/config/channels")

    assert rules.status_code == 200, rules.text
    assert 'name="g0_p_nvd"' in rules.text
    assert "Score providers" in rules.text
    assert notifications.status_code == 200, notifications.text
    assert 'name="g1_r_r0"' in notifications.text
    assert "legacy recipient names or addresses" in notifications.text.lower()
    assert channels.status_code == 200, channels.text
    for field in ("to", "cc", "bcc"):
        suffix = {"to": "t", "cc": "c", "bcc": "b"}[field]
        assert f'name="g0_{suffix}_r0"' in channels.text
    assert 'name="g1_t_r0"' in channels.text
    assert 'name="g1_c_r0"' in channels.text
    assert 'name="g1_b_count" value="0"' in channels.text
    assert 'name="g2_r_r0"' in channels.text
    assert 'name="g2_q_r0c"' in channels.text
    assert 'name="g2_q_r0u"' in channels.text
    assert "object IDs or user principal names" in channels.text
    assert "email addresses" in channels.text.lower()


@pytest.mark.parametrize(
    "extra,section,path,expected",
    [
        (_RULES + 'cvss_providers = ["euvd", "cna", "nvd"]\n' + _RULE_CHANNEL,
         "rules", "watch.rules.0.cvss_providers", ["euvd", "cna", "nvd"]),
        (_RULES + _RULE_CHANNEL, "rules", "watch.rules.0.cvss_providers", None),
        (_CHANNELS, "channels", "watch.channels.smtp.to", ["Primary@example.com", "copy@example.com"]),
        (_CHANNELS, "channels", "watch.channels.graph.bcc", []),
        (_BOT, "channels", "watch.channels.bot.recipients", [" Agent@Example.com ", "second@example.com"]),
    ],
)
def test_untouched_list_controls_are_noop_saves(accounts, extra, section, path, expected):
    if "teams_bot" in extra:
        config_path = _write_bot_config(accounts, extra)
    else:
        config_path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    before = _document(config_path)
    raw_before = config_path.read_bytes()
    page = client.get("/config/" + section)
    assert page.status_code == 200, page.text
    if section == "rules":
        assert 'name="g0_p_mode" value="checkboxes"' in page.text
    preview = _post_rendered(client, section, page.text)

    assert preview.status_code == 200, _response_detail(preview)
    assert "Nothing has changed" in preview.text, _response_detail(preview)
    assert config_path.read_bytes() == raw_before
    saved = _confirm(client, section, preview)
    assert saved.status_code == 303, saved.text
    after = _document(config_path)
    assert after == before
    if expected is None:
        assert "cvss_providers" not in after["watch"]["rules"][0]
    else:
        value = after
        for part in path.split("."):
            value = value[int(part)] if part.isdigit() else value[part]
        assert value == expected


def test_noop_preserves_legacy_addresses_and_graph_rows(accounts):
    extra = '''[notifications.email]
recipients = [" Ops Team ", "Ops Team", "MiXeD@example.com"]

''' + _CHANNELS
    path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    before = _document(path)

    for section in ("notifications", "channels"):
        page = client.get("/config/" + section)
        assert page.status_code == 200, page.text
        preview = _post_rendered(client, section, page.text)
        assert preview.status_code == 200, preview.text
        assert "Nothing has changed" in preview.text
        _confirm(client, section, preview)
        assert _document(path) == before, (_document(path), before)


@pytest.mark.parametrize(
    "extra,section,control_id",
    [
        (_RULES + 'cvss_providers = ["nvd", "nvd"]\n' + _RULE_CHANNEL,
         "rules", "g0_cvss_providers"),
        (_RULES + 'cvss_providers = [" NVD "]\n' + _RULE_CHANNEL,
         "rules", "g0_cvss_providers"),
        (_CHANNELS.replace(
            'to = ["Primary@example.com", "copy@example.com"]',
            'to = ["Doe, John <john@example.com>"]',
        ), "channels", "g0_to"),
    ],
)
def test_fallback_values_survive_untouched_preview_and_save(accounts, extra, section, control_id):
    path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    before = _document(path)
    page = client.get("/config/" + section)

    assert page.status_code == 200, page.text
    assert 'name="' + control_id + '"' in page.text
    assert "edit it as" in page.text
    preview = _post_rendered(client, section, page.text)

    assert preview.status_code == 200, _response_detail(preview)
    assert "Nothing has changed" in preview.text
    _confirm(client, section, preview)
    assert _document(path) == before


def test_noop_preserves_omitted_conversation_service_url(accounts):
    path = _write_bot_config(accounts)
    _, _, _, client = accounts
    login(client, "admin")
    original = _document(path)
    page = client.get("/config/channels")
    preview = _post_rendered(client, "channels", page.text)

    assert preview.status_code == 200, preview.text
    assert "Nothing has changed" in preview.text, _response_detail(preview)
    _confirm(client, "channels", preview)
    after = _document(path)
    assert after == original
    references = after["watch"]["channels"]["bot"]["conversation_references"]
    assert "service_url" not in references[0]
    assert references[1]["service_url"] == "https://smba.trafficmanager.net/teams/"


def test_provider_checkbox_edit_uses_metadata_order_and_scoped_preview(accounts):
    extra = _RULES + 'cvss_providers = ["euvd", "nvd"]\n' + _RULE_CHANNEL
    path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    before = _document(path)
    page = client.get("/config/rules")
    data = _browser_form(page.text)
    data.pop("g0_p_euvd")
    _set(data, "g0_p_cna", "cna")
    preview = client.post("/config/rules", data=data)

    assert preview.status_code == 200, preview.text
    diff = html.unescape(preview.text)
    assert '"cvss_providers" = ["nvd", "cna"]' in diff
    assert "inventory" not in diff and "watch.sources" not in diff
    assert _document(path) == before
    saved = _confirm(client, "rules", preview)
    assert saved.status_code == 303, saved.text
    assert _document(path)["watch"]["rules"][0]["cvss_providers"] == ["nvd", "cna"]


def test_address_add_and_remove_actions_keep_other_unsaved_fields(accounts):
    path = _write_config(accounts, _CHANNELS)
    _, _, _, client = accounts
    login(client, "admin")
    original = _channel_document(path)
    original_bytes = path.read_bytes()
    page = client.get("/config/channels")
    added = _post_rendered(
        client, "channels", page.text,
        click=("g0_c_add", "yes"),
        changes={"g0_c_add_value": "new-copy@example.com", "g0_host": "mail2.example.com"},
    )

    assert added.status_code == 200, added.text
    assert 'value="mail2.example.com"' in added.text
    assert 'value="new-copy@example.com"' in added.text
    assert path.read_bytes() == original_bytes
    removed = _post_rendered(client, "channels", added.text, click=("g0_t_remove", "0"))
    assert removed.status_code == 200, removed.text
    preview = _post_rendered(client, "channels", removed.text)

    assert preview.status_code == 200, preview.text
    assert '"host" = "mail2.example.com"' in html.unescape(preview.text)
    assert path.read_bytes() == original_bytes
    _confirm(client, "channels", preview)
    after = _channel_document(path)
    assert after["smtp"]["to"] == ["copy@example.com"]
    assert after["smtp"]["cc"] == ["copy@example.com", "new-copy@example.com"]
    assert after["smtp"]["host"] == "mail2.example.com"
    assert after["graph"] == original["graph"]


def test_conversation_reference_add_and_remove_preserve_other_rows(accounts):
    path = _write_bot_config(accounts)
    _, _, _, client = accounts
    login(client, "admin")
    original = deepcopy(_document(path)["watch"]["channels"]["bot"]["conversation_references"])
    page = client.get("/config/channels")
    added = _post_rendered(
        client, "channels", page.text,
        click=("g0_q_add", "yes"),
        changes={
            "g0_q_add_c": "conversation-three",
            "g0_q_add_u": "https://smba.trafficmanager.net/teams/",
        },
    )
    assert added.status_code == 200, added.text
    assert "conversation-three" in added.text
    remove_data = _browser_form(added.text, click=("g0_q_remove", "0"))
    removed = client.post("/config/channels", data=remove_data)
    assert removed.status_code == 200, removed.text
    preview = _post_rendered(client, "channels", removed.text)
    assert preview.status_code == 200, preview.text
    assert 'name="lockout"' in preview.text
    confirm_data = _form_pairs(preview.text, action="confirm")
    confirm_data.append(("lockout", "yes"))
    saved = client.post("/config/channels", data=MultiDict(confirm_data))
    assert saved.status_code == 303, saved.text

    after = _document(path)["watch"]["channels"]["bot"]["conversation_references"]
    assert after == [
        original[1],
        {"conversation_id": "conversation-three", "service_url": "https://smba.trafficmanager.net/teams/"},
    ]


def test_bot_recipient_add_remove_keeps_object_id_strings_unformatted(accounts):
    path = _write_bot_config(accounts)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/channels")
    added = _post_rendered(
        client, "channels", page.text,
        click=("g0_r_add", "yes"),
        changes={"g0_r_add_value": "123e4567-e89b-12d3-a456-426614174002"},
    )
    assert added.status_code == 200, added.text
    assert "123e4567-e89b-12d3-a456-426614174002" in added.text
    removed = _post_rendered(client, "channels", added.text, click=("g0_r_remove", "0"))
    assert removed.status_code == 200, removed.text
    preview = _post_rendered(client, "channels", removed.text)
    assert preview.status_code == 200, preview.text
    _confirm(client, "channels", preview)
    recipients = _document(path)["watch"]["channels"]["bot"]["recipients"]
    assert recipients == ["second@example.com", "123e4567-e89b-12d3-a456-426614174002"]


@pytest.mark.parametrize(
    "key,raw,reason",
    [
        ("cvss_providers", ["nvd", "future"], "unsupported"),
        ("cvss_providers", ["nvd", "nvd"], "repeated"),
        ("cvss_providers", [" NVD "], "unsupported"),
        ("cvss_providers", [], "empty"),
        ("recipients", ["valid@example.com", 7], "non-text"),
        ("recipients", "valid@example.com", "list"),
        ("conversation_references", [{"conversation_id": "one", "extra": "x"}], "fields"),
        ("conversation_references", [{"conversation_id": "one", "service_url": 7}], "non-text"),
    ],
)
def test_nonrepresentable_lists_use_one_plain_text_fallback(key, raw, reason):
    if key == "cvss_providers":
        document = {"watch": {"rules": [{"name": "rule", key: raw}]}}
        control = _field(groups_for("rules", document, count=1), key)
    else:
        document = {"watch": {"channels": {"bot": {"type": "teams_bot", key: raw}}}}
        control = _field(groups_for("channels", document, row_types=["teams_bot"]), key)

    view = control["structured"]
    assert view["mode"] == "text"
    assert view["reason"].count(".") == 1
    assert reason in view["reason"].lower()


@pytest.mark.parametrize("field", ["to", "cc", "bcc"])
def test_loader_rejects_bad_channel_email_addresses_with_control_error(accounts, field):
    path = _write_config(accounts, _CHANNELS)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/channels")
    prefix = {"to": "t", "cc": "c", "bcc": "b"}[field]
    response = _post_rendered(
        client, "channels", page.text,
        changes={f"g0_{prefix}_r0": "invalid-address-token"},
    )

    assert response.status_code == 400
    assert 'href="#control-g0_' + field + '"' in response.text
    assert 'aria-invalid="true"' in response.text
    error = re.search(r'<p class="field-error"[^>]*>(.*?)</p>', response.text, re.S)
    assert error and "invalid-address-token" not in html.unescape(error[1])
    assert path.read_bytes() == ( _CHANNELS + _BASE).encode("utf-8")


def test_legacy_recipient_loader_error_links_without_echoing_names(accounts):
    extra = '[notifications.email]\nrecipients = ["Ops Team"]\n\n'
    path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/notifications")
    response = _post_rendered(
        client, "notifications", page.text,
        changes={"g1_r_r0": "   "},
    )

    assert response.status_code == 400
    assert 'href="#control-g1_recipients"' in response.text
    assert 'aria-invalid="true"' in response.text
    assert path.read_bytes() == (extra + _BASE).encode("utf-8")


def test_loader_rejects_bad_bot_recipient_with_control_error(accounts):
    path = _write_bot_config(accounts)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/channels")
    response = _post_rendered(
        client, "channels", page.text,
        changes={"g0_r_r0": "not-an-object-id-or-upn"},
    )

    assert response.status_code == 400
    assert 'href="#control-g0_recipients"' in response.text
    assert 'aria-invalid="true"' in response.text
    error = re.search(r'<p class="field-error"[^>]*>(.*?)</p>', response.text, re.S)
    assert error and "not-an-object-id-or-upn" not in html.unescape(error[1])
    assert path.read_bytes() == (_BOT + _BASE).encode("utf-8")


def test_loader_rejects_bad_reference_url_with_control_error(accounts):
    path = _write_bot_config(accounts)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/channels")
    response = _post_rendered(
        client, "channels", page.text,
        changes={"g0_q_r0u": "https://invalid.example/"},
    )

    assert response.status_code == 400
    assert 'href="#control-g0_conversation_references"' in response.text
    assert 'aria-invalid="true"' in response.text
    error = re.search(r'<p class="field-error"[^>]*>(.*?)</p>', response.text, re.S)
    assert error and "invalid.example" not in html.unescape(error[1])
    assert path.read_bytes() == (_BOT + _BASE).encode("utf-8")


def test_loader_rejects_conversation_reference_count_over_100_with_control_error(accounts):
    path = _write_bot_config(accounts)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/channels")
    data = _browser_form(page.text)
    _set(data, "g0_q_count", "101")
    data.pop("g0_q_add_c")
    data.pop("g0_q_add_u")
    for index in range(1, 101):
        _set(data, f"g0_q_r{index}c", f"conversation-{index}")
        _set(data, f"g0_q_r{index}u", "")
        _set(data, f"g0_q_r{index}p", "no")
    response = client.post("/config/channels", data=data)

    assert response.status_code == 400
    assert 'href="#control-g0_conversation_references"' in response.text
    assert 'aria-invalid="true"' in response.text
    error = re.search(r'<p class="field-error"[^>]*>(.*?)</p>', response.text, re.S)
    assert error and "conversation-100" not in html.unescape(error[1])
    assert path.read_bytes() == (_BOT + _BASE).encode("utf-8")


def test_loader_rejects_bad_reference_table_and_maps_it_to_control(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        _BOT.replace('conversation_id = "conversation-one"',
                     'conversation_id = "conversation-one"\nunknown = "value"') + _BASE,
        encoding="utf-8", newline="\n",
    )

    with pytest.raises(ConfigurationError, match="conversation reference has unknown fields") as caught:
        load_config(path)
    from cvebeacon.dashboard_config import _config_loader_field_key, _field_error_control_id
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    identity = _config_loader_field_key(caught.value, document)
    assert identity == "watch.channels[0].conversation_references"
    assert _field_error_control_id("channels", identity) == "g0_conversation_references"


def test_structured_and_fallback_fields_cannot_be_posted_together(accounts):
    path = _write_config(accounts, _CHANNELS)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/channels")
    assert 'name="g0_t_r0"' in page.text
    pairs = _form_pairs(page.text)
    pairs.append(("g0_to", '["forged@example.com"]'))
    before = path.read_bytes()

    response = _post_pairs(client, "channels", pairs)
    assert response.status_code == 400
    assert path.read_bytes() == before


def test_duplicate_extra_and_bad_count_list_fields_are_400_without_writes(accounts):
    path = _write_config(accounts, _CHANNELS)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/channels")
    assert 'name="g0_t_r0"' in page.text
    original = _form_pairs(page.text)
    cases = [
        [*original, ("g0_t_r0", "duplicate@example.com")],
        [*original, ("g0_t_r99", "extra@example.com")],
        [(name, "102" if name == "g0_t_count" else value) for name, value in original],
    ]
    before = path.read_bytes()
    for pairs in cases:
        response = _post_pairs(client, "channels", pairs)
        assert response.status_code == 400
        assert path.read_bytes() == before


@pytest.mark.parametrize(
    "extra,section",
    [
        (_RULES + "cvss_providers = []\n" + _RULE_CHANNEL, "rules"),
        (_RULES + 'cvss_providers = ["nvd", "INLINE-SYNTHETIC-PROVIDER"]\n' + _RULE_CHANNEL, "rules"),
        (_BOT + 'hidden = "INLINE-SYNTHETIC-SECRET"\n', "channels"),
    ],
)
def test_stored_list_values_the_loader_rejects_open_as_an_error_without_echo(accounts, extra, section):
    # Structured views are built only from documents that pass the existing
    # gate, so an invalid stored value is fixed in the file first.
    path = _write_bot_config(accounts, extra) if section == "channels" else _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    before = path.read_bytes()
    response = client.get("/config/" + section)

    assert response.status_code == 400
    assert "inline-synthetic" not in response.text.casefold()
    assert 'name="g0_' not in response.text
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "extra,expected",
    [
        ("", None),
        ("[http]\nretries = 4\nconnect_timeout = 7.0\n\n", ["retries", "connect_timeout"]),
    ],
)
def test_untouched_section_save_keeps_absent_tables_and_key_order(accounts, extra, expected):
    path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    before = _document(path)
    page = client.get("/config/http")

    assert page.status_code == 200, page.text
    preview = _post_rendered(client, "http", page.text)
    assert preview.status_code == 200, _response_detail(preview)
    assert "Nothing has changed" in preview.text
    _confirmed_document(client, path, "http", preview)
    after = _document(path)
    assert after == before
    if expected is None:
        assert "http" not in after
    else:
        assert list(after["http"]) == expected
