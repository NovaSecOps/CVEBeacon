import json
from datetime import date

import pytest
import yaml
from openpyxl import Workbook

from cvebeacon.config import InventoryConfig
from cvebeacon.errors import InventoryValidationError
from cvebeacon.inventory import load_inventory


@pytest.mark.parametrize("kind,version", [(kind, version) for kind in ["json", "yaml", "xlsx"] for version in [7.0, 10.1, 700, True, ["7.0"]] if not (kind == "xlsx" and isinstance(version, list))])
def test_versions_must_be_text_without_type_coercion(tmp_path, kind, version):
    path = tmp_path / f"inventory.{kind}"
    row = {"asset_id": "a", "vendor": "Acme", "product": "Widget", "version": version}
    if kind == "xlsx":
        book = Workbook(); book.active.append(list(row)); book.active.append(list(row.values())); book.save(path)
    else:
        path.write_text(json.dumps([row]) if kind == "json" else yaml.safe_dump([row]), encoding="utf-8")
    with pytest.raises(InventoryValidationError, match="text"):
        load_inventory(InventoryConfig(path))


@pytest.mark.parametrize("version", ["10.1", "7.0", "7.0.0", "01.020", "1e3"])
def test_text_versions_preserved(tmp_path, version):
    path = tmp_path / "i.json"
    path.write_text(json.dumps([dict(asset_id="a", vendor="Acme", product="Widget", version=version)]))
    assert load_inventory(InventoryConfig(path))[0].version == version


def test_xlsx_date_version_rejected(tmp_path):
    path = tmp_path / "i.xlsx"; book = Workbook()
    book.active.append(["asset_id", "vendor", "product", "version"])
    book.active.append(["a", "Acme", "Widget", date(2026, 1, 1)]); book.save(path)
    with pytest.raises(InventoryValidationError): load_inventory(InventoryConfig(path))


def test_unmapped_record_cannot_disappear(tmp_path):
    path = tmp_path / "i.json"
    path.write_text(json.dumps([dict(asset_id="a", vendor="Acme", product="Widget", version="1"), {"typo": "lost asset"}]))
    with pytest.raises(InventoryValidationError): load_inventory(InventoryConfig(path))


def test_csv_extra_fields_rejected(tmp_path):
    path = tmp_path / "i.csv"
    path.write_text("asset_id,vendor,product,version\na,Acme,Widget,1,2\n")
    with pytest.raises(InventoryValidationError): load_inventory(InventoryConfig(path))
