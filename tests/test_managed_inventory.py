"""Dashboard-managed inventory participates in the normal inventory loader."""

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from cvebeacon.config import load_config
from cvebeacon.inventory import load_inventory
from cvebeacon.models import Asset
from cvebeacon.private_storage import private_directory
from cvebeacon.web_assets import replace_bytes, save_allowlist
from cvebeacon.managed_inventory import client_key


def test_watch_only_config_discovers_inventory_without_reloading(tmp_path):
    path = tmp_path / "cvebeacon.toml"
    path.write_text("[state]\ndatabase = 'state.db'\n[watch]\nenabled = true\n", encoding="utf-8")
    config = load_config(path)
    assert config.effective_inventory is None
    asset = Asset("asset", vendor="vendor", product="product", version="1", client="Example")
    source = write_managed(config.inventory_directory, asset.client, asset.asset_id)
    assert load_inventory(config.effective_inventory) == [asset]
    assert load_inventory(load_config(path).effective_inventory) == [asset]
    source.unlink()
    assert config.effective_inventory is None


def write_managed(directory, client, asset_id):
    if not directory.exists():
        private_directory(directory, owner_only=True)
    path = directory / f"{client_key(client)}.json"
    asset = Asset(asset_id, vendor="vendor", product="product", version="1", client=client)
    replace_bytes(path, json.dumps([asdict(asset)]).encode("utf-8"))
    return path


def test_merge_collisions_report_client_names_without_asset_ids(tmp_path):
    from cvebeacon.errors import InventoryValidationError

    source = tmp_path / "inventory.csv"
    source.write_text("asset_id,vendor,product,version,client\nprivate-id,v,p,1,Configured client\n", encoding="utf-8")
    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[inventory]\npath='inventory.csv'\n", encoding="utf-8")
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
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n", encoding="utf-8")
    config = load_config(path)
    write_managed(config.inventory_directory, "One", "asset-1")
    corrupt = write_managed(config.inventory_directory, "Two", "asset-2")
    corrupt.write_text("FILE-CONTENTS-MARKER", encoding="utf-8")
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
    path.write_text(old, encoding="utf-8")
    config = load_config(path)
    directory = config.inventory_directory
    private_directory(directory, owner_only=True)
    (directory / "unused.client").touch()
    (directory / f"{client_key('Example')}.20261110T120000000000Z.json").touch()
    assert config.effective_inventory is None
    write_managed(directory, "Example", "asset")
    path.write_text(old + "[inventory]\nmanaged=false\n", encoding="utf-8")
    assert load_config(path).effective_inventory is None


def test_scan_with_a_corrupt_inventory_does_not_replace_successful_correlation(tmp_path, monkeypatch):
    from cvebeacon import cli
    from cvebeacon.clients import latest_successful_scan
    from cvebeacon.models import QueryResult

    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n", encoding="utf-8")
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
    corrupt.write_text("INVALID INVENTORY", encoding="utf-8")
    assert cli.main(command) == 4
    assert latest_successful_scan(config.database_path) == initial


def test_legacy_inventory_directory_and_configured_input_are_not_merged(tmp_path):
    directory = tmp_path / "inventories"
    directory.mkdir(mode=0o755)
    legacy = directory / "stock.json"
    legacy.write_text(json.dumps([asdict(Asset("legacy", "v", "p", "1", client="Example"))]), encoding="utf-8")
    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[inventory]\npath='inventories/stock.json'\n", encoding="utf-8")
    config = load_config(path)
    assert [asset.asset_id for asset in load_inventory(config.effective_inventory)] == ["legacy"]

    named = write_managed(directory, "Example", "legacy")
    path.write_text(f"[state]\ndatabase='state.db'\n[inventory]\npath='inventories/{named.name}'\n", encoding="utf-8")
    config = load_config(path)
    assert [asset.asset_id for asset in load_inventory(config.effective_inventory)] == ["legacy"]


def test_discovery_requires_inventory_names_and_names_the_client_in_warnings(tmp_path, caplog):
    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n", encoding="utf-8")
    config = load_config(path)
    directory = config.inventory_directory
    private_directory(directory, owner_only=True)
    inventory = write_managed(directory, "Example", "a")
    data = inventory.read_bytes()
    uppercase = directory / f"{inventory.stem.upper()}.json"
    inventory.unlink()
    replace_bytes(uppercase, data)
    (directory / "stray.json").write_bytes(data)
    assert {item.name for item in directory.iterdir()} == {uppercase.name, "stray.json"}
    assert config.effective_inventory is None

    profile = directory / f"{client_key('Example')}.client"
    replace_bytes(profile, b'{"name":"Example","notes":"","contact":""}')
    uppercase.unlink()
    inventory = write_managed(directory, "Example", "a")
    inventory.write_bytes(data.replace(b'"Example"', b'"PRIVATE-MARKER"'))
    inventory_config = config.effective_inventory
    assert inventory.name in {item.name for item in directory.iterdir()}
    assert inventory_config is not None
    from cvebeacon.errors import InventoryValidationError
    with pytest.raises(InventoryValidationError, match="no valid records"):
        load_inventory(inventory_config)
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
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n", encoding="utf-8")
    config = load_config(path)
    config.inventory_directory.write_text("ordinary file", encoding="utf-8")
    assert config.effective_inventory is None
    assert "inventory storage is not a directory" in caplog.text


def test_reserved_inventory_loads_with_configured_file_and_client_files(tmp_path):
    configured = tmp_path / "configured.json"
    configured.write_text(json.dumps([asdict(Asset("configured", "v", "p", "1"))]), encoding="utf-8", newline="\n")
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f"[state]\ndatabase='state.db'\n[inventory]\npath='{configured.name}'\n", encoding="utf-8", newline="\n",
    )
    config = load_config(config_path)
    clients = [write_managed(config.inventory_directory, "First client", "client-1"),
               write_managed(config.inventory_directory, "Second client", "client-2")]
    legacy_bytes = [path.read_bytes() for path in clients]
    no_client = Asset("personal", "v", "p", "1")
    replace_bytes(config.inventory_directory / "unassigned.json", json.dumps([asdict(no_client)]).encode("utf-8"))

    assert {asset.asset_id for asset in load_inventory(config.effective_inventory)} == {
        "configured", "client-1", "client-2", "personal",
    }
    assert [path.read_bytes() for path in clients] == legacy_bytes
    assert not list(config.inventory_directory.glob("*.client"))


def test_reserved_inventory_alone_activates_effective_inventory(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n", encoding="utf-8", newline="\n")
    config = load_config(path)
    private_directory(config.inventory_directory, owner_only=True)
    reserved = Asset("personal", "v", "p", "1")
    replace_bytes(config.inventory_directory / "unassigned.json", json.dumps([asdict(reserved)]).encode("utf-8"))

    assert config.effective_inventory.managed_directory == config.inventory_directory
    assert load_inventory(config.effective_inventory) == [reserved]


@pytest.mark.parametrize("labels", [("", ""), ("Example", "Example")])
def test_reserved_reader_accepts_blank_or_one_uniform_label(labels):
    from cvebeacon.managed_inventory import read_unassigned_inventory

    rows = [asdict(Asset(f"asset-{index}", "v", "p", "1", client=label))
            for index, label in enumerate(labels)]
    assert [asset.client for asset in read_unassigned_inventory(json.dumps(rows).encode("utf-8"))] == list(labels)


def test_reserved_reader_rejects_mixed_labels():
    from cvebeacon.managed_inventory import read_unassigned_inventory

    rows = [asdict(Asset("one", "v", "p", "1")), asdict(Asset("two", "v", "p", "1", client="Example"))]
    with pytest.raises(ValueError, match="same client"):
        read_unassigned_inventory(json.dumps(rows).encode("utf-8"))


@pytest.mark.parametrize("source", ["configured", "client", "web snapshot"])
def test_reserved_ids_are_unique_case_insensitively_across_sources(tmp_path, source):
    from cvebeacon.errors import InventoryValidationError

    configured = tmp_path / "configured.json"
    configured.write_text(json.dumps([asdict(Asset("configured", "v", "p", "1"))]), encoding="utf-8", newline="\n")
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f"[state]\ndatabase='state.db'\n[inventory]\npath='{configured.name}'\nweb_snapshots=true\n",
        encoding="utf-8", newline="\n",
    )
    config = load_config(config_path)
    private_directory(config.inventory_directory, owner_only=True)
    if source == "configured":
        configured.write_text(json.dumps([asdict(Asset("duplicate", "v", "p", "1"))]), encoding="utf-8", newline="\n")
    elif source == "client":
        write_managed(config.inventory_directory, "Example", "duplicate")
    else:
        web_directory = config.database_path.parent / "web-inventory"
        private_directory(web_directory, owner_only=True)
        snapshot = web_directory / "assets.json"
        rows = [dict(asset_id="duplicate", vendor="v", product="p", version="1", client="Web")]
        timestamp = datetime.now(timezone.utc).isoformat()
        save_allowlist(snapshot, rows)
        manifest = dict(
            contract="cvebeacon.inventory.v1", collector="web-detect", collector_version="0.1.0",
            source_id="web", generated_at=timestamp, observed_at=timestamp,
            sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(), record_count=1,
            status="success", omissions=[],
        )
        save_allowlist(Path(str(snapshot) + ".manifest.json"), manifest)
    duplicate = Asset("DUPLICATE", "v", "p", "1")
    replace_bytes(config.inventory_directory / "unassigned.json", json.dumps([asdict(duplicate)]).encode("utf-8"))

    with pytest.raises(InventoryValidationError, match="An asset ID is shared"):
        load_inventory(config.effective_inventory, snapshot_directory=config.database_path.parent / "web-inventory")


def test_client_named_unassigned_does_not_collide_with_reserved_stem(tmp_path):
    from cvebeacon.managed_inventory import archive_path, inventory_files, is_managed_file, profiles

    directory = tmp_path / "inventories"
    private_directory(directory, owner_only=True)
    client_path = write_managed(directory, "unassigned", "named-client")
    reserved_path = directory / "unassigned.json"
    replace_bytes(reserved_path, json.dumps([asdict(Asset("no-client", "v", "p", "1"))]).encode("utf-8"))

    assert client_path != reserved_path
    assert {path.name for path in inventory_files(directory)} == {client_path.name, "unassigned.json"}
    archived = archive_path(reserved_path)
    assert is_managed_file(reserved_path)
    assert is_managed_file(archived)
    assert not is_managed_file(directory / "unassigned.client")
    assert not is_managed_file(directory / "unassigned-extra.json")
    assert profiles(directory) == ()


def test_scan_explains_missing_requested_report_when_inventory_is_partial(tmp_path, monkeypatch, capsys):
    from cvebeacon import cli
    from cvebeacon.models import QueryResult

    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase='state.db'\n[watch]\nenabled=true\n", encoding="utf-8")
    config = load_config(path)
    write_managed(config.inventory_directory, "Good client", "asset-1")
    write_managed(config.inventory_directory, "Bad client", "asset-2").write_text("invalid", encoding="utf-8")
    monkeypatch.setattr(cli, "_run_query", lambda config, assets, **kwargs: [
        QueryResult(asset, (), ()) for asset in assets
    ])
    assert cli.main(["--config", str(path), "scan", "--report", "json"]) == 4
    assert "Report not written because an inventory is unreadable" in capsys.readouterr().err
    assert not list(config.output_dir.glob("*.json"))
