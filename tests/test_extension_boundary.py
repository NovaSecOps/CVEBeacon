"""Standalone core remains independent of optional inventory producers."""

import ast
from pathlib import Path
import tomllib

from cvebeacon.inventory import load_inventory, validate_records
from cvebeacon.config import InventoryConfig
import json
import pytest
from cvebeacon.errors import InventoryValidationError


def test_core_has_no_extension_import_or_dependency():
    root = Path(__file__).parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())
    assert not any("extension" in item or "kubernetes" in item or "cyclonedx" in item or "spdx" in item
                   for item in project["project"]["dependencies"])
    for path in (root / "src" / "cvebeacon").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            assert not any(name.startswith(("cvebeacon_extensions", "kubernetes", "cyclonedx", "spdx")) for name in modules)


@pytest.mark.parametrize("rows", [
    [dict(asset_id="a", vendor="Acme", product="Widget", version="01.0")],
    [dict(asset_id="a", purl="pkg:pypi/Requests@2.0")],
    [dict(asset_id="a", purl="pkg:pypi/example@1", version="2")],
    [dict(asset_id="a", vendor="Acme", product="Widget", version=1)],
    [dict(asset_id="a", purl="pkg:pypi/example@1"), dict(asset_id="A", purl="pkg:pypi/example@1")],
    [],
])
def test_public_validator_matches_file_path(tmp_path, rows):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    try:
        loaded = load_inventory(InventoryConfig(path))
    except InventoryValidationError:
        with pytest.raises(InventoryValidationError):
            validate_records(rows)
    else:
        assert loaded == validate_records(rows)
