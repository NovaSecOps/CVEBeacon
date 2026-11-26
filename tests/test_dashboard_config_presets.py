"""Scoped configuration presets apply to the current form and still preview."""

from copy import deepcopy
import os
import html
import re
import tomllib

import pytest

from cvebeacon.config import CANONICAL_FIELDS, OPTIONAL_FIELDS, WATCH_SOURCES
from test_dashboard import setup  # noqa: F401 - exposes the shared fixture dependency
from test_dashboard_accounts import accounts as account_fixture, csrf, PASSWORD, login
from test_dashboard_config_structured import (
    _browser_form,
    _confirm,
    _document,
)


_SEED = '''[watch]
enabled = true
sources = ["nvd", "eu_kev"]
initial = "backfill"
backfill_days = 4
overlap_minutes = 19
language = "en"

[inventory]
path = "inventory.csv"
format = "csv"
delimiter = ";"
encoding = "utf-8"
worksheet = "Assets"
header_row = 3

[inventory.columns]
asset_id = "asset key"
vendor = "maker"
product = "product name"
version = "release"
category = "kind"
purl = "package ref"

[state]
database = "state.db"

[output]
directory = "reports"

[sources]
osv_enabled = false
nvd_enabled = false
cve_enabled = false
euvd_enabled = false
cisa_kev_enabled = false
eu_kev_enabled = false
epss_enabled = false
nvd_api_key_env = "EXAMPLE_NVD_KEY"
minimum_request_interval = 4.5

[backup]
directory = "archives"
retention_days = 45
keep_min = 12
compress = false
'''

_REQUIRED_COLUMNS = {key: key for key in CANONICAL_FIELDS}
_GENERAL_COLUMNS = {key: key for key in (*CANONICAL_FIELDS, *OPTIONAL_FIELDS)}
_CASES = [
    ("watch", "watch-nvd-only", {"watch": {"sources": ["nvd"]}}),
    ("watch", "watch-all-catalogs", {"watch": {"sources": list(WATCH_SOURCES)}}),
    ("inventory", "inventory-required-columns", {"inventory": {"columns": _REQUIRED_COLUMNS}}),
    ("inventory", "inventory-general-inventory", {"inventory": {"columns": _GENERAL_COLUMNS}}),
    ("watch", "watch-quiet-baseline", {"watch": {"initial": "baseline"}}),
    ("watch", "watch-backfill-7-days", {
        "watch": {"initial": "backfill", "backfill_days": 7},
    }),
    ("watch", "watch-full-history", {"watch": {"initial": "full"}}),
    ("backup", "backup-7-days", {"backup": {"retention_days": 7}}),
    ("backup", "backup-30-days", {"backup": {"retention_days": 30}}),
    ("backup", "backup-90-days", {"backup": {"retention_days": 90}}),
]


def _write_seed(accounts, content=_SEED):
    path = accounts[0].config_path
    path.write_text(content, encoding="utf-8", newline="\n")
    return path


def _response_detail(response):
    plain = html.unescape(re.sub(r"<[^>]+>", " ", response.text))
    plain = " ".join(plain.split())
    details = re.findall(r".{0,80}(?:error|invalid|unsupported|must be|requires).{0,160}", plain, re.I)
    return " | ".join(details[:5]) or plain[:500]


def _click_preset(client, section, page, preset, *, changes=None):
    assert re.search(
        rf'<button\b[^>]*name="preset"[^>]*value="{re.escape(preset)}"',
        page,
    ), f"{preset} button is not rendered on /config/{section}"
    data = _browser_form(page, click=("preset", preset))
    assert data.get("preset") == preset
    for key, value in (changes or {}).items():
        data.setlist(key, [value])
    return client.post("/config/" + section, data=data)


def _patch_expected(document, patch):
    expected = deepcopy(document)
    for table, values in patch.items():
        if table == "inventory" and "columns" in values:
            expected.setdefault(table, {}).setdefault("columns", {}).update(values["columns"])
        else:
            expected.setdefault(table, {}).update(deepcopy(values))
    return expected


@pytest.fixture
def accounts(account_fixture):
    account_fixture[0].config_path.chmod(0o644)
    return account_fixture


@pytest.mark.parametrize("section,preset,patch", _CASES)
def test_each_preset_applies_its_exact_patch_only_after_confirmation(
    accounts, section, preset, patch
):
    path = _write_seed(accounts)
    before_bytes = path.read_bytes()
    before = _document(path)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/" + section)

    preview = _click_preset(client, section, page.text, preset)

    assert preview.status_code == 200, _response_detail(preview)
    assert "Review changes" in preview.text
    assert "Nothing has been saved yet" in preview.text
    assert path.read_bytes() == before_bytes
    diff = html.unescape(re.search(r"<pre>(.*?)</pre>", preview.text, re.S)[1])
    assert "--- current" in diff and "+++ proposed" in diff
    if section == "watch":
        assert "[sources]" not in diff and "nvd_api_key_env" not in diff
    elif section == "inventory":
        assert "[backup]" not in diff
    else:
        assert "[inventory]" not in diff and "[watch]" not in diff

    expected = _patch_expected(before, patch)
    saved = _confirm(client, section, preview)

    assert saved.status_code == 303, saved.text
    assert _document(path) == expected


@pytest.mark.parametrize(
    "preset,expected",
    [
        ("watch-nvd-only", ["nvd"]),
        ("watch-all-catalogs", list(WATCH_SOURCES)),
    ],
)
def test_source_preset_materializes_an_absent_key(accounts, preset, expected):
    seed = _SEED.replace('sources = ["nvd", "eu_kev"]\n', "")
    path = _write_seed(accounts, seed)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")

    preview = _click_preset(client, "watch", page.text, preset)

    assert preview.status_code == 200, _response_detail(preview)
    assert path.read_bytes() == seed.encode("utf-8")
    saved = _confirm(client, "watch", preview)
    assert saved.status_code == 303, saved.text
    actual = _document(path)
    assert "sources" in actual["watch"]
    assert actual["watch"]["sources"] == expected


def test_untouched_absent_source_key_stays_absent(accounts):
    seed = _SEED.replace('sources = ["nvd", "eu_kev"]\n', "")
    path = _write_seed(accounts, seed)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")

    preview = client.post("/config/watch", data=_browser_form(page.text))

    assert preview.status_code == 200, _response_detail(preview)
    assert "Nothing has changed" in preview.text
    saved = _confirm(client, "watch", preview)
    assert saved.status_code == 303, saved.text
    assert "sources" not in _document(path)["watch"]


def test_untouched_absent_column_key_stays_absent(accounts):
    start = _SEED.index("[inventory.columns]\n")
    end = _SEED.index("[state]\n")
    seed = _SEED[:start] + _SEED[end:]
    path = _write_seed(accounts, seed)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/inventory")

    preview = client.post("/config/inventory", data=_browser_form(page.text))

    assert preview.status_code == 200, _response_detail(preview)
    assert "Nothing has changed" in preview.text
    saved = _confirm(client, "inventory", preview)
    assert saved.status_code == 303, saved.text
    assert "columns" not in _document(path)["inventory"]


def test_required_columns_preset_materializes_an_absent_key(accounts):
    start = _SEED.index("[inventory.columns]\n")
    end = _SEED.index("[state]\n")
    seed = _SEED[:start] + _SEED[end:]
    path = _write_seed(accounts, seed)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/inventory")

    preview = _click_preset(
        client, "inventory", page.text, "inventory-required-columns",
    )

    assert preview.status_code == 200, _response_detail(preview)
    assert path.read_bytes() == seed.encode("utf-8")
    saved = _confirm(client, "inventory", preview)
    assert saved.status_code == 303, saved.text
    actual = _document(path)["inventory"]["columns"]
    assert actual == _REQUIRED_COLUMNS


@pytest.mark.parametrize(
    "seed,preset,field,submitted,error_text",
    [
        (
            _SEED.replace(
                'sources = ["nvd", "eu_kev"]',
                'sources = ["nvd", "eu_kev", "nvd"]',
            ),
            "watch-nvd-only", "g0_sources", "[",
            "watch.sources must be a valid TOML array or table",
        ),
        (
            _SEED.replace('purl = "package ref"', "purl = 7"),
            "inventory-required-columns", "g0_columns", "[]",
            "Inventory column mappings are invalid",
        ),
        (
            _SEED.replace('purl = "package ref"', "purl = 7"),
            "inventory-required-columns", "g0_columns", "{",
            "inventory.columns must be a valid TOML array or table",
        ),
    ],
)
def test_invalid_fallback_text_is_reported_before_a_preset(
    accounts, seed, preset, field, submitted, error_text
):
    path = _write_seed(accounts, seed)
    before = path.read_bytes()
    _, _, _, client = accounts
    login(client, "admin")
    section = "watch" if field == "g0_sources" else "inventory"
    page = client.get("/config/" + section)

    response = _click_preset(
        client, section, page.text, preset, changes={field: submitted},
    )

    assert response.status_code == 400, _response_detail(response)
    assert error_text in response.text
    assert 'href="#control-' + field + '"' in response.text
    assert 'aria-invalid="true"' in response.text
    assert "<pre>" not in response.text
    assert path.read_bytes() == before


_CUSTOM_COLUMN_ORDER = ["purl", "asset_id", "category", "vendor", "product", "version"]
_CUSTOM_COLUMNS = '''[inventory.columns]
purl = "package ref"
asset_id = "asset key"
category = "kind"
vendor = "maker"
product = "product name"
version = "release"
'''
_CUSTOM_COLUMNS_FALLBACK = _CUSTOM_COLUMNS.replace(
    'purl = "package ref"', "purl = 7",
)


@pytest.mark.parametrize(
    "preset,patch",
    [
        ("inventory-required-columns", _REQUIRED_COLUMNS),
        ("inventory-general-inventory", _GENERAL_COLUMNS),
    ],
)
@pytest.mark.parametrize("fallback", [False, True], ids=["rows", "fallback"])
def test_column_presets_keep_existing_key_order(
    accounts, preset, patch, fallback
):
    custom_columns = _CUSTOM_COLUMNS_FALLBACK if fallback else _CUSTOM_COLUMNS
    start = _SEED.index("[inventory.columns]\n")
    end = _SEED.index("[state]\n")
    seed = _SEED[:start] + custom_columns + "\n" + _SEED[end:]
    path = _write_seed(accounts, seed)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/inventory")
    if fallback:
        assert "Inventory column mapping table (TOML)" in page.text

    preview = _click_preset(client, "inventory", page.text, preset)

    assert preview.status_code == 200, _response_detail(preview)
    saved = _confirm(client, "inventory", preview)
    assert saved.status_code == 303, saved.text
    expected_order = list(_CUSTOM_COLUMN_ORDER)
    expected_order.extend(key for key in patch if key not in expected_order)
    assert list(_document(path)["inventory"]["columns"]) == expected_order


@pytest.mark.parametrize(
    "section,preset,changes,expected_path,expected_value",
    [
        ("watch", "watch-nvd-only", {"g0_overlap_minutes": "41"}, ("watch", "overlap_minutes"), 41),
        ("inventory", "inventory-required-columns", {
            "g0_column_heading_5": "package locator",
        }, ("inventory", "columns", "purl"), "package locator"),
        ("backup", "backup-30-days", {"g0_keep_min": "29"}, ("backup", "keep_min"), 29),
    ],
)
def test_preset_keeps_other_unsaved_edits_on_the_page(
    accounts, section, preset, changes, expected_path, expected_value
):
    path = _write_seed(accounts)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/" + section)
    preview = _click_preset(client, section, page.text, preset, changes=changes)

    assert preview.status_code == 200, _response_detail(preview)
    saved = _confirm(client, section, preview)
    assert saved.status_code == 303, saved.text
    actual = _document(path)
    value = actual
    for key in expected_path:
        value = value[key]
    assert value == expected_value


def test_source_and_column_presets_apply_from_text_fallbacks(accounts):
    source_text = _SEED.replace(
        'sources = ["nvd", "eu_kev"]',
        'sources = ["nvd", "eu_kev", "nvd"]',
    )
    source_path = _write_seed(accounts, source_text)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")
    assert "TOML" in page.text and "repeated catalog name" in page.text
    source_preview = _click_preset(client, "watch", page.text, "watch-nvd-only")

    assert source_preview.status_code == 200, _response_detail(source_preview)
    assert '"sources" = ["nvd"]' in html.unescape(source_preview.text)
    assert source_path.read_bytes() == source_text.encode("utf-8")
    source_saved = _confirm(client, "watch", source_preview)
    assert source_saved.status_code == 303, source_saved.text
    assert _document(source_path)["watch"]["sources"] == ["nvd"]

    columns_text = _SEED.replace('purl = "package ref"', "purl = 7")
    column_path = _write_seed(accounts, columns_text)
    page = client.get("/config/inventory")
    assert "Inventory column mapping table (TOML)" in page.text
    assert "non-text headings" in page.text
    column_preview = _click_preset(
        client, "inventory", page.text, "inventory-required-columns",
    )

    assert column_preview.status_code == 200, _response_detail(column_preview)
    column_diff = html.unescape(re.search(r"<pre>(.*?)</pre>", column_preview.text, re.S)[1])
    assert '"purl" = 7' in column_diff
    assert '"vendor" = "vendor"' in column_diff
    assert column_path.read_bytes() == columns_text.encode("utf-8")
    column_saved = _confirm(client, "inventory", column_preview)
    assert column_saved.status_code == 303, column_saved.text
    saved_columns = _document(column_path)["inventory"]["columns"]
    assert saved_columns["purl"] == 7
    assert {key: saved_columns[key] for key in _REQUIRED_COLUMNS} == _REQUIRED_COLUMNS


def test_matching_preset_shows_the_normal_no_change_preview(accounts):
    seed = _SEED.replace(
        'sources = ["nvd", "eu_kev"]',
        'sources = ["nvd"]',
    )
    path = _write_seed(accounts, seed)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")
    preview = _click_preset(client, "watch", page.text, "watch-nvd-only")

    assert preview.status_code == 200, _response_detail(preview)
    assert "Nothing has changed" in preview.text
    assert path.read_bytes() == seed.encode("utf-8")
    saved = _confirm(client, "watch", preview)
    assert saved.status_code == 303, saved.text
    assert _document(path) == tomllib.loads(seed)


def test_full_history_explains_the_larger_first_check_beside_its_preset(accounts):
    _write_seed(accounts)
    _, _, _, client = accounts
    login(client, "admin")
    page = client.get("/config/watch")

    assert re.search(
        r'<button\b[^>]*name="preset"[^>]*value="watch-full-history"', page.text,
    )
    assert "The first check downloads much more data and takes longer." in page.text


def test_preset_labels_and_first_load_order_match_the_scoped_choices(accounts):
    _, _, _, client = accounts
    login(client, "admin")

    watch = client.get("/config/watch").text
    assert "NVD only" in watch
    assert "All watch catalogs" in watch
    assert "all sources" not in watch.lower()
    assert watch.index("Quiet baseline") < watch.index("Backfill 7 days")
    assert watch.index("Backfill 7 days") < watch.index("Full history")

    inventory = client.get("/config/inventory").text
    assert "CVEBeacon required columns" in inventory
    assert "CVEBeacon general inventory" in inventory

    backup = client.get("/config/backup").text
    assert backup.index(">7 days<") < backup.index(">30 days<")
    assert backup.index(">30 days<") < backup.index(">90 days<")


def test_rejected_preset_posts_leave_the_file_byte_identical(accounts):
    path = _write_seed(accounts)
    before = path.read_bytes()
    _, users, app, admin_client = accounts
    login(admin_client, "admin")
    watch_page = admin_client.get("/config/watch")
    data = _browser_form(watch_page.text, click=("preset", "watch-nvd-only"))
    assert data.get("preset") == "watch-nvd-only"

    unknown = data.copy()
    unknown.setlist("preset", ["unknown-preset"])
    response = admin_client.post("/config/watch", data=unknown)
    assert response.status_code == 400
    assert path.read_bytes() == before

    preset_confirm = data.copy()
    preset_confirm.setlist("action", ["confirm"])
    preset_confirm.setlist("preview", ["unissued-preview"])
    response = admin_client.post("/config/watch", data=preset_confirm)
    assert response.status_code == 400
    assert path.read_bytes() == before

    inventory_page = admin_client.get("/config/inventory")
    wrong_section = _browser_form(
        inventory_page.text, click=("preset", "inventory-required-columns"),
    )
    assert wrong_section.get("preset") == "inventory-required-columns"
    wrong_section.setlist("preset", ["watch-nvd-only"])
    response = admin_client.post("/config/inventory", data=wrong_section)
    assert response.status_code == 400
    assert path.read_bytes() == before

    missing_csrf = data.copy()
    missing_csrf.pop("csrf", None)
    response = admin_client.post("/config/watch", data=missing_csrf)
    assert response.status_code == 400
    assert path.read_bytes() == before

    proof = users.authenticate("admin", PASSWORD)
    users.save_role("view-only", {"view"}, authorization=proof)
    users.edit_user("reader", role="view-only", disabled=False, authorization=proof)
    reader_client = app.test_client()
    login(reader_client, "reader")
    reader_page = reader_client.get("/config/watch")
    assert reader_page.status_code == 403
    assert 'name="preset"' not in reader_page.text
    reader_data = data.copy()
    reader_data.setlist("csrf", [csrf(reader_client)])
    response = reader_client.post("/config/watch", data=reader_data)
    assert response.status_code == 403
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes block writes")
def test_presets_are_hidden_when_the_configuration_is_read_only(accounts):
    config, _, _, client = accounts
    login(client, "admin")
    writable_page = client.get("/config/watch")
    assert re.search(r'<button\b[^>]*name="preset"', writable_page.text)

    directory = config.config_path.parent
    original_mode = directory.stat().st_mode & 0o777
    directory.chmod(0o500)
    try:
        read_only_page = client.get("/config/watch")
        assert read_only_page.status_code == 200, read_only_page.text
        assert "Read-only configuration" in read_only_page.text
        assert 'name="preset"' not in read_only_page.text
    finally:
        directory.chmod(original_mode)
