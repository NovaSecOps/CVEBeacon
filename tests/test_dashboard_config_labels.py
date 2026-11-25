"""Plain labels and technical disclosures on configuration pages."""

from __future__ import annotations

from html import escape
from html.parser import HTMLParser
import re

import pytest

from cvebeacon import dashboard_config as config_module
from cvebeacon.dashboard_config_fields import FIELD_LABELS
from cvebeacon.watch.channels import CHANNEL_TYPES
from cvebeacon.watch.users import UserStore
from test_dashboard import setup as base_setup
from test_dashboard_accounts import accounts as account_fixture, login
from test_dashboard_rule_builder import page_form


_BANNED = re.compile(r"\b(TOML|safe|protected|working|healthy|all\s+set|not\s+affected)\b", re.I)
_TABLE_NAME = re.compile(r"\[(?:watch\.channels|notifications\.(?:teams|email))\.[^]]+\]")


@pytest.fixture
def setup(base_setup, monkeypatch):
    monkeypatch.setattr(
        UserStore, "_trusted_directory_chain", staticmethod(lambda directory: ())
    )
    return base_setup


@pytest.fixture
def accounts(account_fixture):
    account_fixture[0].config_path.chmod(0o644)
    login(account_fixture[3], "admin")
    return account_fixture


class _OutsideDisclosure(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.details_depth = 0
        self.ignored = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "details":
            self.details_depth += 1
        elif tag in {"script", "style"}:
            self.ignored += 1

    def handle_endtag(self, tag):
        if tag == "details":
            self.details_depth = max(0, self.details_depth - 1)
        elif tag in {"script", "style"}:
            self.ignored = max(0, self.ignored - 1)

    def handle_data(self, data):
        if self.details_depth == 0 and self.ignored == 0:
            self.parts.append(data)


def outside_disclosures(markup):
    parser = _OutsideDisclosure()
    parser.feed(markup)
    return re.sub(r"\s+", " ", " ".join(parser.parts))


def _plain_label(markup, control):
    match = re.search(
        rf'<label for="control-{re.escape(control["id"])}">(.*?)</label>',
        markup,
        re.S,
    )
    assert match, control["identity"]
    return match.group(1)


def _rule_text_page(client):
    page = client.get("/config/rules")
    assert page.status_code == 200
    data = page_form(page.text)
    data["edit_as_text"] = "0"
    response = client.post("/config/rules", data=data)
    assert response.status_code == 200, response.text
    return response.text


def test_every_configuration_field_renders_its_plain_label_and_muted_key(accounts):
    config, _, app, client = accounts
    document, *_ = app.extensions["dashboard_config"].read()
    rendered_identities = set()

    for section in config_module.SECTIONS:
        markup = _rule_text_page(client) if section == "rules" else client.get(
            f"/config/{section}"
        ).text
        assert markup
        groups = config_module.groups_for(
            section, document, can_manage=True, can_admin=True
        )
        for group in groups:
            for control in group["controls"]:
                identity = control["identity"]
                rendered_identities.add(identity)
                label = _plain_label(markup, control)
                plain = FIELD_LABELS.get(
                    identity, control["key"].replace("_", " ").capitalize()
                )
                assert identity in FIELD_LABELS, f"render fell back for {identity}"
                assert label.startswith(
                    f'{escape(plain)} <small class="muted">{escape(control["key"])}</small>'
                ), identity

    for kind in CHANNEL_TYPES:
        markup = client.get(f"/config/channels?new_type={kind}").text
        groups = config_module.groups_for(
            "channels", document, new_type=kind, can_manage=True, can_admin=True
        )
        for group in groups:
            for control in group["controls"]:
                identity = control["identity"]
                rendered_identities.add(identity)
                label = _plain_label(markup, control)
                plain = FIELD_LABELS.get(
                    identity, control["key"].replace("_", " ").capitalize()
                )
                assert identity in FIELD_LABELS, f"render fell back for {identity}"
                assert label.startswith(
                    f'{escape(plain)} <small class="muted">{escape(control["key"])}</small>'
                ), identity

    assert rendered_identities == set(config_module.FIELD_METADATA)


def test_configuration_copy_keeps_syntax_inside_disclosures(accounts):
    _, _, _, client = accounts
    for section in config_module.SECTIONS:
        paths = [f"/config/{section}"]
        if section == "rules":
            paths.append("/config/rules?text=1")
        for path in paths:
            if section == "rules" and "text=1" in path:
                markup = _rule_text_page(client)
            else:
                response = client.get(path)
                assert response.status_code == 200, path
                markup = response.text
            visible = outside_disclosures(markup)
            assert not _BANNED.search(visible), (path, _BANNED.search(visible).group(0))
            assert not _TABLE_NAME.search(visible), (path, _TABLE_NAME.search(visible).group(0))

    intro = outside_disclosures(client.get("/config/http").text)
    assert "Leave a field empty to use the default." in intro
    assert 'Lists use square brackets, for example ["email"].' in intro
    notifications = client.get("/config/notifications").text
    assert "Scan-report notifications (legacy)." in notifications
    assert "watch alert channels" in notifications
    channels = client.get("/config/channels").text
    assert "Watch alert channels." in channels
    assert "scan-report notifications" in channels


def test_field_labels_are_passed_to_get_error_preview_and_rule_renders(accounts, monkeypatch):
    _, _, _, client = accounts
    real_render = config_module.render_template
    rendered = []

    def record_render(template, **context):
        if template == "config_section.html":
            rendered.append(context)
        return real_render(template, **context)

    monkeypatch.setattr(config_module, "render_template", record_render)

    page = client.get("/config/http")
    assert page.status_code == 200
    from test_dashboard_config import form

    request_data = form(page.text)
    bad = dict(request_data, g0_retries="not-a-number")
    assert client.post("/config/http", data=bad).status_code == 400
    good = dict(request_data, g0_retries="4")
    assert client.post("/config/http", data=good).status_code == 200

    _rule_text_page(client)

    assert len(rendered) >= 4
    assert all(context.get("field_labels") == FIELD_LABELS for context in rendered)
