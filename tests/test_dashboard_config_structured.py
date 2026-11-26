"""Structured watch-source and inventory-column editor controls."""

import html
import re
import tomllib

import pytest
from werkzeug.datastructures import MultiDict

from cvebeacon.config import CANONICAL_FIELDS, OPTIONAL_FIELDS, WATCH_SOURCES, load_config
from cvebeacon.errors import ConfigurationError
from test_dashboard import setup
from test_dashboard_accounts import accounts as account_fixture, login
from test_dashboard_config import form
from cvebeacon.dashboard_config import groups_for


@pytest.fixture
def accounts(account_fixture):
    account_fixture[0].config_path.chmod(0o644)
    return account_fixture


_BASE = '''[inventory]
path = "inventory.csv"

[state]
database = "state.db"

[output]
directory = "reports"

[sources]
nvd_enabled = false
cve_enabled = false
euvd_enabled = false
cisa_kev_enabled = false
eu_kev_enabled = false
epss_enabled = false
'''
_TAIL = _BASE[_BASE.index("[state]"):]


def _write_config(accounts, extra=""):
    path = accounts[0].config_path
    path.write_text(extra + _BASE, encoding="utf-8", newline="\n")
    return path


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
    for name, contents in re.findall(r'<select name="([^"]+)"[^>]*>(.*?)</select>', source, re.S):
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


def _confirm(client, section, response):
    assert response.status_code == 200, response.text
    return client.post("/config/" + section, data=form(response.text, "confirm"))


def _document(path):
    return tomllib.loads(path.read_text(encoding="utf-8"))


def test_watch_sources_render_catalog_checkboxes_and_explain_scan_toggle(accounts):
    _, _, _, client = accounts
    login(client, "admin")
    response = client.get("/config/watch")

    assert response.status_code == 200
    for source in WATCH_SOURCES:
        assert f'name="g0_sources_{source}"' in response.text
        assert re.search(rf'name="g0_sources_{source}"[^>]*checked', response.text)
    assert "NVD is required" in response.text
    assert "watch catalogs" in response.text.lower()
    assert "scan-source toggles" in response.text.lower()
    assert '<textarea name="g0_sources"' not in response.text


def test_inventory_columns_render_all_fields_and_required_asset_id(accounts):
    _, _, _, client = accounts
    login(client, "admin")
    response = client.get("/config/inventory")

    assert response.status_code == 200
    assert 'name="g0_column_key_0"' in response.text
    assert 'name="g0_column_heading_0"' in response.text
    assert "Add mapping" in response.text
    assert "asset_id" in response.text and "required" in response.text
    for key in (*CANONICAL_FIELDS, *OPTIONAL_FIELDS):
        assert f'<option value="{key}"' in response.text


@pytest.mark.parametrize(
    "section,extra,expected_path,expected_value",
    [
        ("watch", "[watch]\nenabled = true\n\n", "watch", None),
        ("watch", '[watch]\nenabled = true\nsources = ["euvd", "nvd"]\n\n', "watch.sources", ["euvd", "nvd"]),
        (
            "inventory",
            '[inventory.columns]\nasset_id = "asset key"\npurl = "package ref"\nvendor = "maker"\nproduct = "name"\nversion = "release"\n\n',
            "inventory.columns",
            {"asset_id": "asset key", "purl": "package ref", "vendor": "maker", "product": "name", "version": "release"},
        ),
    ],
)
def test_untouched_structured_control_preserves_presence_order_and_values(
    accounts, section, extra, expected_path, expected_value
):
    path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    before = _document(path)
    response = client.get("/config/" + section)
    preview = _post_rendered(client, section, response.text)

    assert preview.status_code == 200, preview.text
    assert "Nothing has changed" in preview.text
    assert path.read_bytes() == (extra + _BASE).encode("utf-8")
    saved = _confirm(client, section, preview)
    assert saved.status_code == 303, saved.text
    after = _document(path)
    if expected_value is None:
        assert "sources" not in after.get("watch", {})
    elif expected_path == "watch.sources":
        assert after["watch"]["sources"] == expected_value
    else:
        assert list(after["inventory"]["columns"]) == list(expected_value)
        assert after["inventory"]["columns"] == expected_value
    assert before == after


@pytest.mark.parametrize(
    "section,extra,path_key,original",
    [
        ("watch", '[watch]\nenabled = true\nsources = ["euvd", "nvd", "nvd"]\n\n', "sources", ["euvd", "nvd", "nvd"]),
        (
            "inventory",
            '[inventory.columns]\nasset_id = "asset"\nfuture_field = "future heading"\n\n',
            "columns",
            {"asset_id": "asset", "future_field": "future heading"},
        ),
        (
            "inventory",
            '[inventory.columns]\nasset_id = 7\n\n',
            "columns",
            {"asset_id": 7},
        ),
    ],
)
def test_unrepresentable_values_use_text_fallback_and_keep_noop(
    accounts, section, extra, path_key, original
):
    path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    response = client.get("/config/" + section)

    assert response.status_code == 200, response.text
    assert 'name="g0_' + path_key + '_mode" value="text"' in response.text
    assert "edit it as toml text" in response.text.lower()
    assert f'<textarea name="g0_{path_key}"' in response.text
    preview = _post_rendered(client, section, response.text)
    assert preview.status_code == 200, preview.text
    assert "Nothing has changed" in preview.text
    saved = _confirm(client, section, preview)
    assert saved.status_code == 303, saved.text
    saved_document = _document(path)
    actual = saved_document["watch"][path_key] if section == "watch" else saved_document["inventory"][path_key]
    assert actual == original


def test_unrepresentable_shapes_and_unknown_source_names_select_text_mode():
    inventory = groups_for("inventory", {"inventory": {"columns": []}})
    columns = next(control for group in inventory for control in group["controls"]
                   if control["key"] == "columns")["structured"]
    watch = groups_for("watch", {"watch": {"sources": ["nvd", "future_catalog"]}})
    sources = next(control for group in watch for control in group["controls"]
                   if control["key"] == "sources")["structured"]

    assert columns["mode"] == "text"
    assert "not a mapping table" in columns["reason"]
    assert sources["mode"] == "text"
    assert "unsupported catalog name" in sources["reason"]


def test_editing_one_column_changes_only_that_mapping_and_preview_is_separate(accounts):
    extra = ('[inventory.columns]\nasset_id = "asset"\nvendor = "vendor"\n'
             'product = "product"\nversion = "version"\npurl = "package"\n\n')
    path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    before = _document(path)
    page = client.get("/config/inventory")
    preview = _post_rendered(client, "inventory", page.text, changes={"g0_column_heading_1": "supplier"})

    assert preview.status_code == 200, preview.text
    assert '"vendor" = "supplier"' in html.unescape(preview.text)
    assert 'product = "product"' not in preview.text
    assert _document(path) == before
    saved = _confirm(client, "inventory", preview)
    assert saved.status_code == 303, saved.text
    after = _document(path)
    assert list(after["inventory"]["columns"]) == list(before["inventory"]["columns"])
    assert after["inventory"]["columns"] == {
        "asset_id": "asset", "vendor": "supplier", "product": "product",
        "version": "version", "purl": "package",
    }
    assert after["inventory"]["path"] == before["inventory"]["path"]


def test_inventory_mapping_add_and_remove_use_server_rendered_actions(accounts):
    extra = ('[inventory.columns]\nasset_id = "asset"\nvendor = "vendor"\n'
             'product = "product"\nversion = "version"\n\n')
    path = _write_config(accounts, extra)
    _, _, _, client = accounts
    login(client, "admin")
    before_bytes = path.read_bytes()
    page = client.get("/config/inventory")
    added = _post_rendered(
        client, "inventory", page.text, click=("g0_columns_add", "yes"),
        changes={"g0_column_add_key": "category", "g0_column_add_heading": "kind"},
    )
    assert added.status_code == 200, added.text
    assert 'value="category" selected' in added.text
    assert path.read_bytes() == before_bytes
    removed = _post_rendered(client, "inventory", added.text, click=("g0_columns_remove", "1"))
    assert removed.status_code == 200, removed.text
    preview = _post_rendered(client, "inventory", removed.text)
    assert preview.status_code == 200, preview.text
    saved = _confirm(client, "inventory", preview)
    assert saved.status_code == 303, saved.text
    assert _document(path)["inventory"]["columns"] == {
        "asset_id": "asset", "product": "product", "version": "version", "category": "kind",
    }


def test_changed_watch_sources_use_canonical_catalog_order_and_scoped_preview(accounts):
    path = _write_config(accounts, '[watch]\nenabled = true\nsources = ["euvd", "nvd"]\n\n')
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")
    data = _browser_form(page.text)
    data.pop("g0_sources_euvd")
    data.setlist("g0_sources_epss", ["epss"])
    preview = client.post("/config/watch", data=data)

    assert preview.status_code == 200, preview.text
    assert '"sources" = ["nvd", "epss"]' in html.unescape(preview.text)
    assert '"initial" =' not in html.unescape(preview.text) and 'inventory' not in preview.text
    assert "sources = [\"euvd\", \"nvd\"]" in path.read_text(encoding="utf-8")
    saved = _confirm(client, "watch", preview)
    assert saved.status_code == 303, saved.text
    assert _document(path)["watch"]["sources"] == ["nvd", "epss"]


@pytest.mark.parametrize(
    "document,needle",
    [
        ("[watch]\nenabled = true\nsources = [\"euvd\"]\n", "include nvd"),
        ("[inventory]\npath = \"inventory.csv\"\n[inventory.columns]\nvendor = \"maker\"\n", "asset_id"),
        ("[inventory]\npath = \"inventory.csv\"\ncolumns = []\n", "table"),
    ],
)
def test_loader_still_rejects_missing_nvd_asset_id_and_bad_columns_shape(tmp_path, document, needle):
    path = tmp_path / "config.toml"
    path.write_text(document + _TAIL, encoding="utf-8", newline="\n")

    with pytest.raises(ConfigurationError, match=needle):
        load_config(path)


def test_structured_and_text_fallback_cannot_be_posted_together(accounts):
    path = _write_config(accounts, '[watch]\nenabled = true\n\n')
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")
    pairs = _form_pairs(page.text)
    pairs.append(("g0_sources", '["nvd"]'))
    before = path.read_bytes()

    response = client.post("/config/watch", data=MultiDict(pairs))
    assert response.status_code == 400
    assert path.read_bytes() == before


def test_duplicate_structured_fields_are_rejected_without_writing(accounts):
    path = _write_config(accounts, '[watch]\nenabled = true\n\n')
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")
    pairs = _form_pairs(page.text)
    pairs.append(("g0_sources_nvd", "nvd"))
    before = path.read_bytes()

    response = client.post("/config/watch", data=MultiDict(pairs))
    assert response.status_code == 400
    assert path.read_bytes() == before


def test_missing_nvd_loader_error_links_to_the_control(accounts):
    path = _write_config(accounts, '[watch]\nenabled = true\nsources = ["nvd"]\n\n')
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")
    data = _browser_form(page.text)
    data.pop("g0_sources_nvd")
    response = client.post("/config/watch", data=data)

    assert response.status_code == 400
    assert 'aria-invalid="true"' in response.text
    assert 'aria-describedby="control-g0_sources-help control-g0_sources-error"' in response.text
    assert 'href="#control-g0_sources"' in response.text
    assert path.read_bytes() == ("[watch]\nenabled = true\nsources = [\"nvd\"]\n\n" + _BASE).encode("utf-8")
