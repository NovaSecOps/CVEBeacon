"""Reject dangerous workbook structure before the workbook reader starts."""

from io import BytesIO
import json
from zipfile import ZipFile

from openpyxl import Workbook
import pytest

from cvebeacon import inventory, inventory_preview
from cvebeacon.config import InventoryConfig
from cvebeacon.errors import ConfigurationError, InventoryValidationError
from cvebeacon.inventory_preview import preview_upload


def workbook_with_part(name, transform):
    workbook = Workbook()
    workbook.active.append(["asset_id", "vendor", "product", "version"])
    workbook.active.append(["a", "Example", "Widget", "1"])
    source, output = BytesIO(), BytesIO()
    workbook.save(source)
    with ZipFile(source) as original, ZipFile(output, "w") as changed:
        for entry in original.namelist():
            data = original.read(entry)
            changed.writestr(entry, transform(data) if entry == name else data)
    return output.getvalue()


@pytest.mark.parametrize("part", ("xl/worksheets/sheet1.xml", "docProps/core.xml",
                                  "xl/_rels/workbook.xml.rels"))
@pytest.mark.parametrize("encoding", ("utf-8", "utf-16", "utf-32"))
def test_xml_declarations_are_refused_before_openpyxl(part, encoding, tmp_path, monkeypatch):
    def declaration(data):
        return ("<!DOCTYPE workbook>" + data.decode()).encode(encoding)

    payload = workbook_with_part(part, declaration)
    path = tmp_path / "inventory.xlsx"
    path.write_bytes(payload)

    def opened(*args, **kwargs):
        pytest.fail("worksheet parser ran before XML preflight")

    monkeypatch.setattr(inventory, "load_workbook", opened)
    with pytest.raises(ConfigurationError, match="XML declarations"):
        preview_upload(payload, ".xlsx", "Example")
    with pytest.raises(InventoryValidationError, match="XML declarations"):
        inventory.load_inventory(InventoryConfig(path))
    with pytest.raises(InventoryValidationError, match="XML declarations"):
        inventory.inspect_inventory(path)


def test_coordinates_are_checked_before_workbook_parser(monkeypatch):
    payload = workbook_with_part(
        "xl/worksheets/sheet1.xml", lambda data: data.replace(b'r="D2"', b'r="XFD2"')
    )
    monkeypatch.setattr(inventory, "load_workbook", lambda *a, **k: pytest.fail("opened unsafe coordinates"))
    with pytest.raises(ConfigurationError, match="column limit"):
        preview_upload(payload, ".xlsx", "Example")


def test_yaml_alias_and_expanded_text_budget(monkeypatch):
    data = b"- {asset_id: a, vendor: &vendor Example, product: *vendor, version: '1'}"
    with pytest.raises(ConfigurationError, match="YAML aliases"):
        preview_upload(data, ".yaml", "Example")
    monkeypatch.setattr(inventory_preview, "MAX_LOGICAL_TEXT", 10, raising=False)
    with pytest.raises(ConfigurationError, match="too much text"):
        preview_upload(b"asset_id,vendor,product,version\na,Example,Widget,1\n", ".csv", "Example")


def test_preview_reports_physical_lines_and_the_first_error_page():
    upload = b'asset_id,vendor,product,version,category\na,Example,Widget,1,"two\nlines"\n\nb,Example,Widget,,\n'
    preview = preview_upload(upload, ".csv", "Example")
    assert [row[0] for row in preview.validation] == [2, 5]
    rows = b"".join(f"{i},Example,Widget,1\n".encode() for i in range(50))
    preview = preview_upload(b"asset_id,vendor,product,version\n" + rows + b"bad,Example,Widget,\n", ".csv", "Example")
    assert preview.first_error == (52, 2)


def test_known_parse_errors_and_json_depth_are_sanitized():
    with pytest.raises(ConfigurationError, match="duplicate column names"):
        preview_upload(b"private-header,PRIVATE-HEADER\na,b\n", ".csv", "Example")
    document = json.dumps([{"asset_id": "private-marker"}]).encode()
    with pytest.raises(ConfigurationError) as caught:
        preview_upload(b"[" * 64 + document + b"]" * 64, ".json", "Example")
    assert "private-marker" not in str(caught.value)


def test_per_part_and_total_decompression_limits(monkeypatch):
    from cvebeacon import xlsx_safety

    payload = workbook_with_part("docProps/core.xml", lambda data: data)
    with ZipFile(BytesIO(payload)) as book:
        sizes = [entry.file_size for entry in book.infolist()]
    monkeypatch.setattr(xlsx_safety, "MAX_PART_BYTES", max(sizes))
    monkeypatch.setattr(xlsx_safety, "MAX_EXPANDED_BYTES", sum(sizes))
    assert preview_upload(payload, ".xlsx", "Example").assets
    monkeypatch.setattr(xlsx_safety, "MAX_PART_BYTES", max(sizes) - 1)
    with pytest.raises(ConfigurationError, match="part exceeds"):
        preview_upload(payload, ".xlsx", "Example")
    monkeypatch.setattr(xlsx_safety, "MAX_PART_BYTES", max(sizes))
    monkeypatch.setattr(xlsx_safety, "MAX_EXPANDED_BYTES", sum(sizes) - 1)
    with pytest.raises(ConfigurationError, match="total expanded size"):
        preview_upload(payload, ".xlsx", "Example")


def test_parser_limits_reject_a_standalone_entity_marker_and_a_far_row(monkeypatch):
    payload = workbook_with_part(
        "docProps/core.xml", lambda data: b'<!ENTITY marker "example">' + data
    )
    with pytest.raises(ConfigurationError, match="XML declarations"):
        preview_upload(payload, ".xlsx", "Example")
    payload = workbook_with_part(
        "xl/worksheets/sheet1.xml", lambda data: data.replace(b'<row r="2">', b'<row r="100002">')
    )
    monkeypatch.setattr(inventory, "load_workbook", lambda *a, **kw: pytest.fail("opened unsafe row position"))
    with pytest.raises(ConfigurationError, match="row limit"):
        preview_upload(payload, ".xlsx", "Example")


def test_exact_cell_budget_is_checked_before_row_validation(monkeypatch):
    payload = workbook_with_part("docProps/core.xml", lambda data: data)
    monkeypatch.setattr(inventory_preview, "MAX_CELLS", 4)
    assert preview_upload(payload, ".xlsx", "Example").assets
    monkeypatch.setattr(inventory_preview, "MAX_CELLS", 3)
    with pytest.raises(ConfigurationError, match="too many cells"):
        preview_upload(payload, ".xlsx", "Example")


def test_full_size_workbook_upload_reaches_the_row_limit():
    from openpyxl import Workbook

    workbook = Workbook(write_only=True)
    sheet = workbook.create_sheet()
    sheet.append(["asset_id", "vendor", "product", "version"])
    for index in range(100_000):
        sheet.append([f"asset-{index:06}", "Example", "Widget", "1"])
    payload = BytesIO()
    workbook.save(payload)
    result = preview_upload(payload.getvalue(), ".xlsx", "Example")
    assert len(result.assets) == 100_000 and result.errors == 0


@pytest.mark.parametrize("suffix", (".json", ".yaml"))
def test_upload_shape_error_asks_for_a_list_of_inventory_rows(suffix):
    data = b'{"title": "private-marker"}'
    with pytest.raises(ConfigurationError, match="list of inventory rows") as caught:
        preview_upload(data, suffix, "Example")
    assert "private-marker" not in str(caught.value)


def test_yaml_complexity_and_configured_aliases_have_safe_errors(tmp_path):
    data = b"[" * 35 + b'"private-marker"' + b"]" * 35
    with pytest.raises(ConfigurationError, match="YAML is too complex") as caught:
        preview_upload(data, ".yaml", "Example")
    assert "private-marker" not in str(caught.value)
    path = tmp_path / "inventory.yaml"
    path.write_bytes(b"- {asset_id: a, vendor: &vendor Example, product: *vendor, version: '1'}")
    with pytest.raises(InventoryValidationError, match="YAML aliases"):
        inventory.load_inventory(InventoryConfig(path))
    with pytest.raises(InventoryValidationError, match="YAML aliases"):
        inventory.inspect_inventory(path)
