from __future__ import annotations

import json

import pytest

from cvebeacon.config import InventoryConfig
from cvebeacon.errors import InventoryValidationError
from cvebeacon.inventory import load_inventory, validate_records

MAPPING = {
    "asset_id": "Asset",
    "vendor": "Maker",
    "product": "Name",
    "version": "Release",
    "client": "Client",
}


def config(path, **values):
    return InventoryConfig(path=path, columns=MAPPING, **values)


def test_client_column_is_mapped_and_normalized(tmp_path):
    path = tmp_path / "inventory.csv"
    path.write_text(
        "Asset,Maker,Name,Release,Client\n"
        "srv-1,Acme,Widget,1.2.3,  Acme  \n"
        "srv-2,Acme,Widget,1.2.4,\n",
        encoding="utf-8",
    )
    assets = load_inventory(config(path))
    assert [asset.client for asset in assets] == ["Acme", ""]


def test_client_name_is_nfkc_normalized(tmp_path):
    path = tmp_path / "inventory.csv"
    path.write_text(
        "Asset,Maker,Name,Release,Client\n"
        "srv-1,Acme,Widget,1.2.3,Ａcme\n",
        encoding="utf-8",
    )
    assert load_inventory(config(path))[0].client == "Acme"


@pytest.mark.parametrize(
    "value",
    (
        "Acme\x01Corp",
        "Acme\x7fCorp",
        "Acme\x85Corp",
        "Acme\u202eCorp",
        "Acme\u200bCorp",
        "Acme\ufeffCorp",
    ),
)
def test_client_name_rejects_control_and_format_characters(tmp_path, value):
    path = tmp_path / "inventory.csv"
    path.write_text(
        "Asset,Maker,Name,Release,Client\n"
        f"srv-1,Acme,Widget,1.2.3,{value}\n",
        encoding="utf-8",
    )
    with pytest.raises(
        InventoryValidationError,
        match="control or format characters|without control characters",
    ):
        load_inventory(config(path))


def test_client_name_length_is_bounded(tmp_path):
    path = tmp_path / "inventory.csv"
    path.write_text(
        "Asset,Maker,Name,Release,Client\n"
        f"srv-1,Acme,Widget,1.2.3,{'x' * 121}\n",
        encoding="utf-8",
    )
    with pytest.raises(InventoryValidationError, match="at most 120 characters"):
        load_inventory(config(path))


def test_client_does_not_change_asset_identity(tmp_path):
    path = tmp_path / "inventory.csv"
    path.write_text(
        "Asset,Maker,Name,Release,Client\n"
        "srv-1,Acme,Widget,1.2.3,Acme\n"
        "srv-2,Acme,Widget,1.2.3,Globex\n",
        encoding="utf-8",
    )
    first, second = load_inventory(config(path))
    assert first.target_key == second.target_key
    assert first.identity_path == second.identity_path == "product"


def test_public_record_validation_accepts_client():
    asset = validate_records(
        [
            {
                "asset_id": "srv-1",
                "vendor": "Acme",
                "product": "Widget",
                "version": "1.2.3",
                "client": "Acme",
            }
        ]
    )[0]
    assert asset.client == "Acme"


def test_json_inventory_client_mapping(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "Asset": "srv-1",
                        "Maker": "Acme",
                        "Name": "Widget",
                        "Release": "1.2.3",
                        "Client": "Acme",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    asset = load_inventory(config(path, records_path="records"))[0]
    assert asset.client == "Acme"
