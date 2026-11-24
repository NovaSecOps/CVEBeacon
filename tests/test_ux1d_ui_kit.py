"""Rendering tests for the shared UI kit added for the guided setup work."""

import re
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from cvebeacon import dashboard

TEMPLATES = Path(dashboard.__file__).parent / "templates"
STYLESHEET = Path(dashboard.__file__).parent / "static" / "dashboard.css"


@pytest.fixture(scope="module")
def env():
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(("html", "xml")),
    )


def render(env, source, **context):
    return env.from_string(source).render(**context)


def item(key, state, **values):
    data = {
        "id": key,
        "title": f"Title for {key}",
        "state": state,
        "detail": f"Detail for {key}.",
        "action_url": None,
        "action_label": None,
        "hint": None,
    }
    data.update(values)
    return data


def test_setup_checklist_renders_every_state_and_progress(env):
    items = [
        item("sources", "done"),
        item("channel", "todo"),
        item("rule", "attention"),
        item("schedule", "unknown"),
        item("backup", "na"),
    ]
    text = render(
        env,
        "{% from 'ui.html' import setup_checklist %}"
        "{{ setup_checklist(items, 2, 6) }}",
        items=items,
    )

    assert (
        '<details class="card setup-checklist" id="getting-started" open '
        'aria-labelledby="getting-started-title">' in text
    )
    assert (
        '<summary><h2 class="card-title" id="getting-started-title">Getting started</h2>'
        '<span class="setup-progress">2 of 6 steps done</span></summary>' in text
    )
    assert (
        "These steps set up monitoring. Finishing them does not mean every flaw "
        "has been found." in text
    )
    assert '<ol class="setup-steps">' in text
    assert text.index("setup-sources") < text.index("setup-channel") < text.index("setup-rule")
    assert text.index("setup-rule") < text.index("setup-schedule") < text.index("setup-backup")

    states = [
        ("sources", "done", "Done", "success"),
        ("channel", "todo", "To do", "neutral"),
        ("rule", "attention", "Needs attention", "warning"),
        ("schedule", "unknown", "Could not check", "warning"),
        ("backup", "na", "Not available", "neutral"),
    ]
    for key, state, label, variant in states:
        assert f'<li class="setup-step setup-{state}" id="setup-{key}">' in text
        assert f'<span class="badge badge-{variant}">{label}</span>' in text
        assert f"Title for {key}" in text
        assert f"Detail for {key}." in text


def test_setup_checklist_unknown_suffix_only_when_present(env):
    items = [item("sources", "done")]
    default = render(
        env,
        "{% from 'ui.html' import setup_checklist %}"
        "{{ setup_checklist(items, 1, 1) }}",
        items=items,
    )
    explicit_zero = render(
        env,
        "{% from 'ui.html' import setup_checklist %}"
        "{{ setup_checklist(items, 1, 1, unknown=0) }}",
        items=items,
    )
    with_unknown = render(
        env,
        "{% from 'ui.html' import setup_checklist %}"
        "{{ setup_checklist(items, 4, 6, unknown=2) }}",
        items=items,
    )

    assert '<span class="setup-progress">1 of 1 steps done</span>' in default
    assert "could not be checked" not in default
    assert '<span class="setup-progress">1 of 1 steps done</span>' in explicit_zero
    assert "could not be checked" not in explicit_zero
    assert (
        '<span class="setup-progress">4 of 6 steps done; 2 could not be checked</span>'
        in with_unknown
    )


def test_setup_checklist_escapes_the_unknown_count(env):
    text = render(
        env,
        "{% from 'ui.html' import setup_checklist %}"
        "{{ setup_checklist(items, 1, 2, unknown='<b>3</b>') }}",
        items=[item("sources", "done")],
    )

    assert "&lt;b&gt;3&lt;/b&gt; could not be checked" in text
    assert "<b>3</b>" not in text


def test_setup_checklist_wraps_the_row_in_a_grid_container(env):
    text = render(
        env,
        "{% from 'ui.html' import setup_checklist %}"
        "{{ setup_checklist(items, 0, 1) }}",
        items=[item("channel", "todo")],
    )

    assert 'id="setup-channel"><div class="setup-row"><span class="setup-state">' in text


def test_setup_step_keeps_list_markers_and_grid_is_on_the_inner_row():
    css = STYLESHEET.read_text(encoding="utf-8").replace("\r\n", "\n")

    step_rule = css.split(".setup-step {", 1)[1].split("}", 1)[0]
    assert "display: list-item" in step_rule
    assert "display: grid" not in step_rule

    row_rule = css.split(".setup-row {", 1)[1].split("}", 1)[0]
    assert "display: grid" in row_rule
    assert "grid-template-columns: 8.5rem 1fr" in row_rule

    media = css.split("@media (max-width: 40rem) {", 1)[1].split("\n}", 1)[0]
    assert ".setup-row { grid-template-columns: 1fr; }" in media


def test_setup_checklist_action_and_hint_rules(env):
    items = [
        item(
            "channel",
            "todo",
            action_url="/config/channels/new",
            action_label="Add a channel",
            hint="Ask an administrator to add an alert channel.",
        ),
        item("schedule", "todo", hint="Ask an administrator to set a schedule."),
        item("backup", "done"),
    ]
    text = render(
        env,
        "{% from 'ui.html' import setup_checklist %}"
        "{{ setup_checklist(items, 0, 3, open=false) }}",
        items=items,
    )

    # A permitted action wins over the hint.
    assert (
        '<a class="btn btn-secondary btn-small" href="/config/channels/new">'
        "Add a channel</a>" in text
    )
    assert "Ask an administrator to add an alert channel." not in text
    # Without an action the hint explains who can act.
    assert '<p class="help">Ask an administrator to set a schedule.</p>' in text
    # A finished step has neither.
    assert "Title for backup" in text
    backup = text.split('id="setup-backup"', 1)[1].split("</li>", 1)[0]
    assert "<a class=" not in backup and "<p class=\"help\">" not in backup
    assert text.count("<a class=") == 1
    assert '<details class="card setup-checklist" id="getting-started" aria-labelledby=' in text


def test_setup_checklist_escapes_its_arguments(env):
    items = [
        item(
            'x"><script>alert(1)</script>',
            "todo",
            title="<b>Title</b>",
            detail="A & B",
            action_url='/next?a=1&b=<tag>',
            action_label="<em>Go</em>",
            hint="<i>Ask</i>",
        )
    ]
    text = render(
        env,
        "{% from 'ui.html' import setup_checklist %}"
        "{{ setup_checklist(items, '<b>1</b>', 3) }}",
        items=items,
    )

    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "<b>Title</b>" not in text
    assert "&lt;b&gt;Title&lt;/b&gt;" in text
    assert "A &amp; B" in text
    assert 'href="/next?a=1&amp;b=&lt;tag&gt;"' in text
    assert "&lt;em&gt;Go&lt;/em&gt;" in text
    assert "&lt;b&gt;1&lt;/b&gt; of 3 steps done" in text


def test_select_field_renders_label_options_and_help(env):
    text = render(
        env,
        "{% from 'ui.html' import select_field %}"
        "{{ select_field('Severity', 'severity', [('low', 'Low'), ('high', 'High')], "
        "value='high', help='Pick the closest match.', required=true) }}",
    )

    assert '<div class="field">' in text
    assert '<label for="f-severity">Severity</label>' in text
    assert (
        '<select id="f-severity" name="severity" required '
        'aria-describedby="f-severity-help">' in text
    )
    assert '<option value="low">Low</option>' in text
    assert '<option value="high" selected>High</option>' in text
    assert '<p class="help" id="f-severity-help">Pick the closest match.</p>' in text
    assert "aria-invalid" not in text
    assert "optional" not in text


def test_select_field_error_and_optional_annotations(env):
    text = render(
        env,
        "{% from 'ui.html' import select_field %}"
        "{{ select_field('Mode', 'mode', [('a', 'A')], value='a', "
        "help='Choose one.', error='Mode is required.', optional=true) }}",
    )

    assert '<label for="f-mode">Mode <span class="optional">(optional)</span></label>' in text
    assert (
        '<select id="f-mode" name="mode" '
        'aria-describedby="f-mode-help f-mode-error" aria-invalid="true">' in text
    )
    assert '<p class="help" id="f-mode-help">Choose one.</p>' in text
    assert '<p class="field-error" id="f-mode-error">Mode is required.</p>' in text


def test_select_field_error_without_help_links_only_the_error(env):
    text = render(
        env,
        "{% from 'ui.html' import select_field %}"
        "{{ select_field('Mode', 'mode', [('a', 'A')], error='Choose one of the options.') }}",
    )

    assert 'aria-describedby="f-mode-error" aria-invalid="true"' in text
    assert "f-mode-help" not in text


def test_select_field_without_help_or_error_has_no_aria_attributes(env):
    text = render(
        env,
        "{% from 'ui.html' import select_field %}"
        "{{ select_field('Mode', 'mode', [('a', 'A')]) }}",
    )

    assert "aria-describedby" not in text
    assert "aria-invalid" not in text
    assert "selected" not in text


def test_select_field_escapes_its_arguments(env):
    text = render(
        env,
        "{% from 'ui.html' import select_field %}"
        "{{ select_field('<Label>', 'mode', [('a&b', '<One>')], value='a&b', "
        "help='<Help>', error='<Error>') }}",
    )

    assert "&lt;Label&gt;" in text
    assert "<Label>" not in text
    assert 'value="a&amp;b" selected' in text
    assert "&lt;One&gt;" in text
    assert "&lt;Help&gt;" in text
    assert "&lt;Error&gt;" in text


def test_check_field_renders_default_value_and_help(env):
    text = render(
        env,
        "{% from 'ui.html' import check_field %}"
        "{{ check_field('Enabled', 'enabled', help='Alerts use this channel.') }}",
    )

    assert '<div class="field field-check">' in text
    assert (
        '<input id="f-enabled-yes" type="checkbox" name="enabled" value="yes" '
        'aria-describedby="f-enabled-yes-help">' in text
    )
    assert '<label for="f-enabled-yes">Enabled</label>' in text
    assert '<p class="help" id="f-enabled-yes-help">Alerts use this channel.</p>' in text
    assert "checked" not in text


def test_check_field_checked_value_and_custom_id(env):
    text = render(
        env,
        "{% from 'ui.html' import check_field %}"
        "{{ check_field('Email', 'channels', value='email', checked=true, id='channel-email') }}",
    )

    assert (
        '<input id="channel-email" type="checkbox" name="channels" value="email" checked>'
        in text
    )
    assert '<label for="channel-email">Email</label>' in text


def test_check_field_escapes_its_arguments(env):
    text = render(
        env,
        "{% from 'ui.html' import check_field %}"
        "{{ check_field('<Label>', 'name\"x', value='<value>', "
        "help='<Help>', id='<id>') }}",
    )

    assert "&lt;Label&gt;" in text
    assert "<Label>" not in text
    assert "&lt;value&gt;" in text
    assert "&lt;Help&gt;" in text
    assert "&lt;id&gt;" in text
    assert 'id="&lt;id&gt;"' in text
    assert 'name="name&#34;x"' in text


def test_explain_renders_a_closed_disclosure_with_the_call_block(env):
    text = render(
        env,
        "{% from 'ui.html' import explain %}"
        "{% call explain() %}<p>Plain words.</p>{% endcall %}",
    )

    assert (
        '<details class="disclosure explain"><summary>What does this mean?</summary>'
        '<div class="explain-body"><p>Plain words.</p></div></details>' in text
    )


def test_explain_escapes_a_custom_summary(env):
    text = render(
        env,
        "{% from 'ui.html' import explain %}"
        "{% call explain('<Summary>') %}Body.{% endcall %}",
    )

    assert "<summary>&lt;Summary&gt;</summary>" in text
    assert "<Summary>" not in text
    assert "<details" in text and " open" not in text.split(">", 1)[0]


def test_ui_kit_macros_add_no_inline_styles_or_scripts(env):
    items = [item("one", "todo", action_url="/next", action_label="Next")]
    outputs = [
        render(
            env,
            "{% from 'ui.html' import setup_checklist %}"
            "{{ setup_checklist(items, 0, 1) }}",
            items=items,
        ),
        render(
            env,
            "{% from 'ui.html' import select_field %}"
            "{{ select_field('Mode', 'mode', [('a', 'A')]) }}",
        ),
        render(
            env,
            "{% from 'ui.html' import check_field %}{{ check_field('Enabled', 'enabled') }}",
        ),
        render(
            env,
            "{% from 'ui.html' import explain %}{% call explain() %}Body.{% endcall %}",
        ),
    ]

    for text in outputs:
        assert not re.search(r"(?i)\sstyle\s*=", text)
        assert not re.search(r"(?i)\son[a-z]+\s*=", text)
        assert not re.search(r"(?is)<script\b", text)
        assert not re.search(r"(?is)<style\b", text)
        assert "javascript:" not in text


def test_setup_checklist_classes_are_styled_with_tokens():
    css = STYLESHEET.read_text(encoding="utf-8").replace("\r\n", "\n")

    for selector in (
        ".setup-checklist summary {",
        ".setup-steps {",
        ".setup-step {",
        ".setup-row {",
        ".setup-title {",
        ".setup-detail {",
        ".setup-attention .setup-title {",
        ".explain-body {",
        ".criteria {",
        ".criterion {",
        ".criterion-controls {",
    ):
        assert selector in css, selector
    assert "@media (max-width: 40rem)" in css
    assert ".setup-row { grid-template-columns: 1fr; }" in css

    new_rules = css.split(".setup-checklist summary {", 1)[1].split(
        "/* --------------------------------------------- 5. Legacy", 1
    )[0]
    assert "#" not in new_rules
