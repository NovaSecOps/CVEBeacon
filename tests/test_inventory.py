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
    path.write_text(json.dumps(ROWS + [{**ROWS[0], "Release": ""}]), encoding="utf-8")
    with pytest.raises(InventoryValidationError) as error:
        load_inventory(_config(path))
    assert "blank required field: version" in str(error.value)


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


@pytest.mark.parametrize("kind", ["csv", "json", "yaml"])
def test_inspect_structured_formats(tmp_path, kind):
    path = tmp_path / f"inventory.{kind}"
    if kind == "csv": path.write_text("asset_id,vendor,product,version\na,v,p,1\n", encoding="utf-8")
    elif kind == "json": path.write_text('[{"asset_id":"a"}]', encoding="utf-8")
    else: path.write_text("- asset_id: a\n", encoding="utf-8")
    assert inspect_inventory(path)["format"] == kind
