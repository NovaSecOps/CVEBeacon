import csv
from dataclasses import replace
import json

from openpyxl import Workbook
import pytest
import yaml

from cvebeacon.config import InventoryConfig
from cvebeacon.engine import QueryEngine
from cvebeacon.errors import InventoryValidationError
from cvebeacon.identity import identity_conflict, normalize_asset, parse_purl, purl_string
from cvebeacon.inventory import load_inventory
from cvebeacon.models import Asset, Applicability
from test_dashboard import setup


@pytest.mark.parametrize("raw,expected,name", [
    ("pkg:PyPI/Django_Rest.Framework@1.2", "pkg:pypi/django-rest-framework@1.2", "django-rest-framework"),
    ("pkg:npm/%40Scope/OldPackage@1.2.3", "pkg:npm/%40Scope/OldPackage@1.2.3", "@Scope/OldPackage"),
    ("pkg:maven/org.Example/Library@1.0?type=jar&classifier=sources#src/main", "pkg:maven/org.Example/Library@1.0?classifier=sources&type=jar#src/main", "org.Example:Library"),
    ("pkg:golang/github.com/Owner/Module@v1.2.3", "pkg:golang/github.com/Owner/Module@v1.2.3", "github.com/Owner/Module"),
    ("pkg:nuget/Newtonsoft.Json@12.0.1", "pkg:nuget/Newtonsoft.Json@12.0.1", "Newtonsoft.Json"),
    ("pkg:cargo/serde@1.0.0", "pkg:cargo/serde@1.0.0", "serde"),
])
def test_purl_components_and_type_specific_case(raw, expected, name):
    asset = normalize_asset(Asset("a", purl=raw))
    assert asset.purl == expected and asset.product == name
    assert purl_string(parse_purl(asset.purl)) == expected
    assert asset.identity_path == "purl"


@pytest.mark.parametrize("raw", ["pkg:maven/name@1", "pkg:pypi/namespace/name@1", "pkg:nuget/namespace/name@1", "pkg:npm/name%GG@1", "https://example.invalid/foo", "pkg:npm/", "pkg:unknown-type/name"])
def test_invalid_purl_is_not_generic_fallback(raw):
    with pytest.raises(ValueError):
        normalize_asset(Asset("a", "Acme", "Widget", "1", purl=raw))


@pytest.mark.parametrize("fields", [
    {"purl": "pkg:pypi/django@1", "version": "2"},
    {"purl": "pkg:pypi/django@1", "ecosystem": "npm"},
    {"purl": "pkg:npm/Django@1", "product": "django"},
    {"purl": "pkg:maven/org.Example/Library@1", "product": "org.example:library"},
    {"cpe": "cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*", "version": "2"},
])
def test_direct_identity_contradictions_rejected(fields):
    with pytest.raises(ValueError, match="contradict"):
        normalize_asset(Asset("a", **fields))


def test_category_grouping_not_identity_and_ecosystems_never_conflated():
    asset = normalize_asset(Asset("a", ecosystem="npm", product="example", version="1.2.3"))
    assert asset.target_key == replace(asset, asset_id="b", system_id="host-1", category="firewall").target_key
    assert asset.target_key != replace(asset, ecosystem="PyPI").target_key
    assert asset.target_key != replace(asset, product="Example").target_key
    assert Asset("a", "Acme", "Widget", "1").target_key == ("acme", "widget", "1")


def test_cross_identity_uncertainty(setup):
    asset = normalize_asset(Asset("a", purl="pkg:pypi/widget@1", cpe="cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*"))
    assert identity_conflict(asset)
    with QueryEngine(setup[0]) as engine:
        result = engine.query_asset(asset)
    assert result.coverage == Applicability.NEEDS_REVIEW


def test_explicit_cpe_preserves_qualifiers_and_skips_fuzzy_discovery(setup, monkeypatch):
    cpe = "cpe:2.3:a:acme:widget:*:update:edition:en:sw:windows:x64:other"
    asset = normalize_asset(Asset("a", version="1.2", cpe=cpe))
    with QueryEngine(setup[0]) as engine:
        monkeypatch.setattr(engine.nvd, "resolve_cpes", lambda _: pytest.fail("explicit identity went through discovery"))
        resolved, _ = engine._resolve_cpe(asset)
    assert resolved == cpe.replace(":*:update", ":1.2:update")


@pytest.mark.parametrize("fields", [
    {"repository": "https://example.invalid/repo", "commit": "abc"},
    {"commit": "a" * 40},
    {"repository": "https://user:password@example.invalid/repo", "commit": "a" * 40},
    {"repository": "file:///local/repo", "commit": "a" * 40},
])
def test_commit_requires_exact_identity(fields):
    with pytest.raises(ValueError):
        normalize_asset(Asset("a", **fields))


@pytest.mark.parametrize("kind", ["csv", "json", "yaml", "xlsx"])
def test_all_formats_optional_identity_and_mapping(tmp_path, kind):
    row = {"ID": "component-1", "Package": "pkg:pypi/requests@2.25.0", "Group": "system-1", "category": "custom category"}
    path = tmp_path / f"inventory.{kind}"
    if kind == "csv":
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(row))
            writer.writeheader(); writer.writerow(row)
    elif kind == "json":
        path.write_text(json.dumps([row]), encoding="utf-8")
    elif kind == "yaml":
        path.write_text(yaml.safe_dump([row]), encoding="utf-8")
    else:
        book = Workbook(); book.active.append(list(row)); book.active.append(list(row.values())); book.save(path); book.close()
    asset = load_inventory(InventoryConfig(path, columns={"asset_id": "ID", "purl": "Package", "system_id": "Group"}))[0]
    assert asset.product == "requests" and asset.version == "2.25.0" and asset.vendor == ""
    assert asset.system_id == "system-1" and asset.category == "custom category"


def test_optional_xlsx_formulas_rejected(tmp_path):
    path = tmp_path / "inventory.xlsx"
    book = Workbook(); book.active.append(["asset_id", "purl", "system_id"])
    book.active.append(["a", "pkg:pypi/requests@1", '=CONCAT("private")']); book.save(path); book.close()
    with pytest.raises(InventoryValidationError, match="formulas"):
        load_inventory(InventoryConfig(path))


def test_exact_unicode_identity_preserved_and_nontext_rejected(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps([{"asset_id": "a", "ecosystem": "npm", "product": "Ｆoo", "version": "1", "category": "library"}]), encoding="utf-8")
    assert load_inventory(InventoryConfig(path))[0].product == "Ｆoo"
    path.write_text('[{"asset_id":"a","purl":"pkg:pypi/requests@1","system_id":123}]', encoding="utf-8")
    with pytest.raises(InventoryValidationError, match="must be text"):
        load_inventory(InventoryConfig(path))
