"""Dashboard-managed inventory participates in the normal inventory loader."""

from dataclasses import asdict
import json

import pytest

from cvebeacon.config import load_config
from cvebeacon.inventory import load_inventory
from cvebeacon.models import Asset
from cvebeacon.managed_inventory import client_key


def test_watch_only_config_discovers_inventory_without_reloading(tmp_path):
    path = tmp_path / "cvebeacon.toml"
    path.write_text("[state]\ndatabase = 'state.db'\n[watch]\nenabled = true\n")
    config = load_config(path)
    assert config.effective_inventory is None
    directory = tmp_path / "inventories"
    directory.mkdir(mode=0o700)
    asset = Asset("asset", vendor="vendor", product="product", version="1", client="Example")
    source = directory / f"{client_key(asset.client)}.json"
    source.touch(mode=0o600)
    source.write_text(json.dumps([asdict(asset)]))
    assert load_inventory(config.effective_inventory) == [asset]
    assert load_inventory(load_config(path).effective_inventory) == [asset]
    source.unlink()
    assert config.effective_inventory is None


def write_managed(directory, client, asset_id):
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / f"{client_key(client)}.json"
    path.touch(mode=0o600)
    asset = Asset(asset_id, vendor="vendor", product="product", version="1", client=client)
    path.write_text(json.dumps([asdict(asset)]))
    return path


def test_merge_collisions_report_client_names_without_asset_ids(tmp_path):
    from cvebeacon.errors import InventoryValidationError

    source = tmp_path / "inventory.csv"
    source.write_text("asset_id,vendor,product,version,client\nprivate-id,v,p,1,Configured client\n")
    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[inventory]\npath='inventory.csv'\n")
    config = load_config(path)
    write_managed(config.inventory_directory, "Dashboard client", "PRIVATE-ID")
    with pytest.raises(InventoryValidationError) as result:
        load_inventory(config.effective_inventory)
    assert "Configured client" in str(result.value)
    assert "Dashboard client" in str(result.value)
    assert "private-id" not in str(result.value).casefold()


def test_validation_and_doctor_report_corrupt_inventory(tmp_path, capsys, caplog):
    from cvebeacon.cli import main

    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n")
    config = load_config(path)
    write_managed(config.inventory_directory, "One", "asset-1")
    corrupt = write_managed(config.inventory_directory, "Two", "asset-2")
    corrupt.write_text("FILE-CONTENTS-MARKER")
    assert [asset.asset_id for asset in load_inventory(config.effective_inventory)] == ["asset-1"]
    assert "Skipping invalid client inventory" in caplog.text
    assert main(["--config", str(path), "inventory", "validate"]) == 2
    assert "partial: 1 asset(s)" in capsys.readouterr().out
    assert main(["--config", str(path), "doctor", "--local-state"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert "Skipping invalid client inventory" in checks["managed_inventory"][0]
    assert "FILE-CONTENTS-MARKER" not in repr(checks) + caplog.text


def test_old_configs_ignore_profiles_and_history_and_can_disable_managed(tmp_path):
    path = tmp_path / "config.toml"
    old = "[state]\ndatabase='state.db'\n[watch]\nenabled=true\n"
    path.write_text(old)
    config = load_config(path)
    directory = config.inventory_directory
    directory.mkdir(mode=0o700)
    (directory / "unused.client").touch()
    (directory / f"{client_key('Example')}.20261110T120000000000Z.json").touch()
    assert config.effective_inventory is None
    write_managed(directory, "Example", "asset")
    path.write_text(old + "[inventory]\nmanaged=false\n")
    assert load_config(path).effective_inventory is None


def test_scan_with_a_corrupt_inventory_does_not_replace_successful_correlation(tmp_path, monkeypatch):
    from cvebeacon import cli
    from cvebeacon.clients import latest_successful_scan
    from cvebeacon.models import QueryResult

    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n")
    config = load_config(path)
    write_managed(config.inventory_directory, "One", "asset-1")
    monkeypatch.setattr(cli, "_run_query", lambda config, assets, **kwargs: [
        QueryResult(asset, (), ()) for asset in assets
    ])
    command = ["--config", str(path), "scan"]
    assert cli.main(command) == 0
    initial = latest_successful_scan(config.database_path)
    assert initial is not None
    corrupt = write_managed(config.inventory_directory, "Two", "asset-2")
    corrupt.write_text("INVALID INVENTORY")
    assert cli.main(command) == 4
    assert latest_successful_scan(config.database_path) == initial


def test_legacy_inventory_directory_and_configured_input_are_not_merged(tmp_path):
    directory = tmp_path / "inventories"
    directory.mkdir(mode=0o755)
    legacy = directory / "stock.json"
    legacy.write_text(json.dumps([asdict(Asset("legacy", "v", "p", "1", client="Example"))]))
    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[inventory]\npath='inventories/stock.json'\n")
    config = load_config(path)
    assert [asset.asset_id for asset in load_inventory(config.effective_inventory)] == ["legacy"]

    named = write_managed(directory, "Example", "legacy")
    path.write_text(f"[state]\ndatabase='state.db'\n[inventory]\npath='inventories/{named.name}'\n")
    config = load_config(path)
    assert [asset.asset_id for asset in load_inventory(config.effective_inventory)] == ["legacy"]


def test_discovery_requires_inventory_names_and_names_the_client_in_warnings(tmp_path, caplog):
    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n")
    config = load_config(path)
    directory = config.inventory_directory
    directory.mkdir(mode=0o700)
    inventory = write_managed(directory, "Example", "a")
    data = inventory.read_bytes()
    inventory.rename(directory / inventory.name.upper().replace(".JSON", ".json"))
    (directory / "stray.json").write_bytes(data)
    assert config.effective_inventory is None

    profile = directory / f"{client_key('Example')}.client"
    profile.touch(mode=0o600)
    profile.write_text(json.dumps({"name": "Example", "notes": "", "contact": ""}))
    inventory = write_managed(directory, "Example", "a")
    inventory.write_bytes(data.replace(b'"Example"', b'"PRIVATE-MARKER"'))
    from cvebeacon.errors import InventoryValidationError
    with pytest.raises(InventoryValidationError, match="no valid records"):
        load_inventory(config.effective_inventory)
    assert "Example" in caplog.text
    assert "PRIVATE-MARKER" not in caplog.text
    assert inventory.stem not in caplog.text


def test_managed_keys_normalize_unicode_and_are_safe_for_reserved_labels():
    import unicodedata

    from cvebeacon.managed_inventory import KEY, client_key as managed_key

    assert managed_key("Société") == managed_key(unicodedata.normalize("NFD", "SOCIÉTÉ"))
    assert KEY.fullmatch(managed_key("CON"))


def test_unsafe_inventory_directory_is_reported(tmp_path, caplog):
    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n")
    config = load_config(path)
    config.inventory_directory.write_text("ordinary file")
    assert config.effective_inventory is None
    assert "inventory storage is not a directory" in caplog.text


def test_scan_explains_missing_requested_report_when_inventory_is_partial(tmp_path, monkeypatch, capsys):
    from cvebeacon import cli
    from cvebeacon.models import QueryResult

    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n")
    config = load_config(path)
    write_managed(config.inventory_directory, "Good client", "asset-1")
    write_managed(config.inventory_directory, "Bad client", "asset-2").write_text("invalid")
    monkeypatch.setattr(cli, "_run_query", lambda config, assets, **kwargs: [
        QueryResult(asset, (), ()) for asset in assets
    ])
    assert cli.main(["--config", str(path), "scan", "--report", "json"]) == 4
    assert "Report not written because a client inventory is unreadable" in capsys.readouterr().err
    assert not list(config.output_dir.glob("*.json"))
