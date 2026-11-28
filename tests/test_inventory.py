from __future__ import annotations

import csv
import json
from dataclasses import replace

import pytest
import yaml
from openpyxl import Workbook

from cvebeacon.config import InventoryConfig
from cvebeacon.errors import InventoryValidationError
from cvebeacon.inventory import inspect_inventory, load_inventory


ROWS = [{"Asset": "srv-1", "Maker": "Acme", "Name": "Widget", "Release": "1.2.3"}]
MAPPING = {"asset_id": "Asset", "vendor": "Maker", "product": "Name", "version": "Release"}


def _config(path, **values):
    return InventoryConfig(path=path, columns=MAPPING, **values)


@pytest.mark.parametrize("kind", ["csv", "json", "yaml", "xlsx"])
def test_all_formats_produce_same_model(tmp_path, kind):
    path = tmp_path / f"inventory.{kind}"
    if kind == "csv":
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=ROWS[0]); writer.writeheader(); writer.writerows(ROWS)
    elif kind == "json": path.write_text(json.dumps({"items": ROWS}), encoding="utf-8")
    elif kind == "yaml": path.write_text(yaml.safe_dump({"items": ROWS}), encoding="utf-8")
    else:
        wb = Workbook(); ws = wb.active; ws.title = "Assets"; ws.append(list(ROWS[0])); ws.append(list(ROWS[0].values())); wb.save(path)
    kwargs = {"records_path": "items"} if kind in {"json", "yaml"} else ({"worksheet": "Assets"} if kind == "xlsx" else {})
    asset = load_inventory(_config(path, **kwargs))[0]
    assert (asset.asset_id, asset.vendor, asset.product, asset.version) == ("srv-1", "Acme", "Widget", "1.2.3")


def test_validation_reports_duplicate_and_blank(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(ROWS + [{**ROWS[0], "Asset": "srv-2", "Name": ""}]), encoding="utf-8")
    with pytest.raises(InventoryValidationError) as error:
        load_inventory(_config(path))
    assert "blank required field: product" in str(error.value)


@pytest.mark.parametrize("kind", ["json", "csv"])
def test_control_only_versions_are_rejected_before_stripping(tmp_path, kind):
    path = tmp_path / f"inventory.{kind}"
    if kind == "json":
        path.write_text(json.dumps([{
            "asset_id": "a", "vendor": "v", "product": "p", "version": "\t"}]), encoding="utf-8")
    else:
        path.write_text('asset_id,vendor,product,version\na,v,p,"\t"\n',
                        encoding="utf-8", newline="\n")
    with pytest.raises(InventoryValidationError,
                       match="version cannot be normalized: contains a control character"):
        load_inventory(InventoryConfig(path=path))


@pytest.mark.parametrize("kind", ["json", "csv"])
def test_padded_versions_load_without_the_padding(tmp_path, kind):
    path = tmp_path / f"inventory.{kind}"
    if kind == "json":
        path.write_text(json.dumps([{
            "asset_id": "a", "vendor": "v", "product": "p", "version": "\t2.1\n"}]), encoding="utf-8")
    else:
        path.write_text('asset_id,vendor,product,version\na,v,p,"\t2.1\n"\n',
                        encoding="utf-8", newline="\n")
    asset = load_inventory(InventoryConfig(path=path))[0]
    assert asset.version == "2.1"


def test_managed_and_snapshot_contract_reads_accept_a_padded_version():
    from cvebeacon.managed_inventory import read_inventory
    from cvebeacon.web_inventory import read_contract

    data = json.dumps([{"asset_id": "a", "vendor": "v", "product": "p",
                        "version": "\t2.1\n", "client": "Acme"}]).encode("utf-8")
    for reader in (read_contract, read_inventory):
        assert [asset.version for asset in reader(data)] == ["2.1"]


def test_empty_and_space_only_versions_remain_valid(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps([
        {"asset_id": "a", "vendor": "v", "product": "p"},
        {"asset_id": "b", "vendor": "v", "product": "p", "version": "   "},
    ]), encoding="utf-8")
    assert [asset.version for asset in load_inventory(InventoryConfig(path=path))] == ["", ""]


def test_managed_and_snapshot_contract_reads_reject_a_control_only_version():
    from cvebeacon.managed_inventory import read_inventory
    from cvebeacon.web_inventory import read_contract

    data = json.dumps([{"asset_id": "a", "vendor": "v", "product": "p",
                        "version": "\t", "client": "Acme"}]).encode("utf-8")
    for reader in (read_contract, read_inventory):
        with pytest.raises(InventoryValidationError,
                           match="version cannot be normalized: contains a control character"):
            reader(data)


def test_duplicate_ids_are_case_insensitive(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(ROWS + [{**ROWS[0], "Asset": "SRV-1"}]), encoding="utf-8")
    with pytest.raises(InventoryValidationError, match="duplicate asset_id"):
        load_inventory(_config(path))


def test_case_insensitive_source_headers(tmp_path):
    path = tmp_path / "case.csv"
    path.write_text("asset,maker,name,release\nsrv-1,Acme,Widget,1.2.3\n", encoding="utf-8")
    mapping = {**MAPPING, "asset_id": "ASSET"}
    assert load_inventory(InventoryConfig(path=path, columns=mapping))[0].asset_id == "srv-1"


def test_inspect_xlsx_does_not_modify_source(tmp_path):
    path = tmp_path / "book.xlsx"; wb = Workbook(); wb.active.append(["Asset"]); wb.save(path)
    before = path.read_bytes(); result = inspect_inventory(path)
    assert result["sheets"][0]["headers"] == ["Asset"]
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "name,content",
    [
        ("bad.json", "{"),
        ("bad.yaml", "!!python/object:unsafe.Type {}"),
        ("bad.csv", 'asset_id,vendor,product,version\n"unterminated,Acme,Widget,1\n'),
        ("bad.xlsx", "not a zip archive"),
    ],
)
def test_malformed_inputs_fail_safely(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    with pytest.raises(InventoryValidationError):
        load_inventory(InventoryConfig(path=path))


@pytest.mark.parametrize("name,content", [
    ("inventory.yaml", 'asset_id: "SyntheticSecret\n'),
    ("inventory.json", '{"asset_id": "SyntheticSecret",'),
])
def test_structured_parser_errors_do_not_echo_source_content(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    with pytest.raises(InventoryValidationError) as raised:
        load_inventory(InventoryConfig(path=path))
    message = str(raised.value)
    assert "SyntheticSecret" not in message
    assert "line" in message.lower()


@pytest.mark.parametrize("kind", ["csv", "json", "yaml"])
def test_inspect_structured_formats(tmp_path, kind):
    path = tmp_path / f"inventory.{kind}"
    if kind == "csv": path.write_text("asset_id,vendor,product,version\na,v,p,1\n", encoding="utf-8")
    elif kind == "json": path.write_text('[{"asset_id":"a"}]', encoding="utf-8")
    else: path.write_text("- asset_id: a\n", encoding="utf-8")
    assert inspect_inventory(path)["format"] == kind
