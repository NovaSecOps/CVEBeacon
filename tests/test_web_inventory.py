"""Saved web observations join inventory only with explicit configuration."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

import pytest

from cvebeacon import cli, dashboard
from cvebeacon.config import load_config
from cvebeacon.dashboard_config import groups_for, dumps
from cvebeacon.errors import ConfigurationError, InventoryValidationError
from cvebeacon.inventory import load_inventory
from cvebeacon.private_storage import private_directory
from cvebeacon.web_assets import save_allowlist
from cvebeacon.web_inventory import read_web_snapshot


def snapshot(directory, *, name="acme", asset_id="web-acme", partial=False):
    private_directory(directory, owner_only=True)
    output = directory / (name + ".json")
    rows = [dict(asset_id=asset_id, vendor="nginx", product="nginx", version="1.26.2", client="Acme")]
    timestamp = datetime.now(timezone.utc).isoformat()
    manifest = dict(contract="cvebeacon.inventory.v1", collector="web-detect", collector_version="0.1.0",
                    source_id="web-acme", generated_at=timestamp, observed_at=timestamp,
                    sha256="", record_count=1,
                    status="partial" if partial else "success", omissions=["blocked"] if partial else [])
    save_allowlist(output, rows)
    # save_allowlist uses a different JSON representation; bind the exact bytes.
    manifest["sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    save_allowlist(Path(str(output) + ".manifest.json"), manifest)
    save_allowlist(Path(str(output) + ".review.json"), {"client": "Acme", "reviews": [{"reason": "blocked"}]})
    return output


def config_file(tmp_path, *, enabled=False, path=True, watch=False):
    config = tmp_path / "config.toml"
    document = {"inventory": {"web_snapshots": enabled},
                "state": {"database": str(tmp_path / "data" / "state.db")},
                "sources": {key + "_enabled": False for key in
                            ("osv", "nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")}}
    if path:
        inventory = tmp_path / "inventory.json"
        inventory.write_text(json.dumps([dict(asset_id="supplied", vendor="Acme", product="Widget", version="1")]), encoding="utf-8")
        document["inventory"]["path"] = str(inventory)
    if watch:
        document["watch"] = {"enabled": True, "sources": ["nvd"]}
    config.write_text(dumps(document), encoding="utf-8")
    return load_config(config)


@pytest.mark.parametrize("enabled", [False, True])
def test_merge_opt_in_keeps_supplied_inventory(tmp_path, enabled):
    config = config_file(tmp_path, enabled=enabled)
    directory = config.database_path.parent / "web-inventory"
    snapshot(directory)
    rows = load_inventory(config.inventory, snapshot_directory=directory)
    assert [row.asset_id for row in rows] == (["supplied", "web-acme"] if enabled else ["supplied"])
    if enabled:
        assert rows[-1].client == "Acme"


def test_partial_snapshot_is_used_and_corrupt_snapshot_warns(tmp_path, caplog):
    config = config_file(tmp_path, enabled=True)
    directory = config.database_path.parent / "web-inventory"
    snapshot(directory, partial=True)
    save_allowlist(directory / "broken.json", {"bad": True})
    rows = load_inventory(config.inventory, snapshot_directory=directory)
    assert len(rows) == 2
    assert "Skipping invalid web snapshot broken.json" in caplog.text
    assert "Using partial web snapshot acme.json" in caplog.text
    assert json.loads((directory / "acme.json.review.json").read_text())["reviews"] == [{"reason": "blocked"}]


@pytest.mark.parametrize("collision", ["SUPPLIED", "web-acme"])
def test_collision_is_an_error_across_all_inputs(tmp_path, collision):
    config = config_file(tmp_path, enabled=True)
    directory = config.database_path.parent / "web-inventory"
    snapshot(directory)
    snapshot(directory, name="second", asset_id=collision)
    with pytest.raises(InventoryValidationError, match="asset_id collision"):
        load_inventory(config.inventory, snapshot_directory=directory)


@pytest.mark.parametrize("fault", ["hash", "count", "contract", "status", "future", "row", "duplicate-key", "unknown-field"])
def test_invalid_contract_is_skipped(tmp_path, caplog, fault):
    config = config_file(tmp_path, enabled=True)
    directory = config.database_path.parent / "web-inventory"
    output = snapshot(directory)
    manifest_path = Path(str(output) + ".manifest.json")
    manifest = json.loads(manifest_path.read_text())
    if fault in {"row", "unknown-field"}:
        rows = json.loads(output.read_text())
        rows[0]["version" if fault == "row" else "body"] = 1
        save_allowlist(output, rows)
        manifest["sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    elif fault == "duplicate-key":
        output.write_text('[{"asset_id":"a","asset_id":"b"}]', encoding="utf-8")
        manifest["sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    else:
        field, value = {"hash": ("sha256", "0" * 64), "count": ("record_count", 2),
                        "contract": ("contract", "unsupported"), "status": ("status", "failed"),
                        "future": ("observed_at", "2999-01-01T00:00:00Z")}[fault]
        manifest[field] = value
    save_allowlist(manifest_path, manifest)
    assert [row.asset_id for row in load_inventory(config.inventory, snapshot_directory=directory)] == ["supplied"]
    assert "Skipping invalid web snapshot" in caplog.text


def test_web_only_inventory_scan_and_dashboard(tmp_path, capsys):
    config = config_file(tmp_path, enabled=True, path=False)
    assert config.inventory.path is None
    directory = config.database_path.parent / "web-inventory"
    snapshot(directory, partial=True)
    assert cli.main(["--config", str(config.config_path), "inventory", "validate"]) == 0
    assert "valid: 1" in capsys.readouterr().out
    assert cli.main(["--config", str(config.config_path), "scan"]) == 4
    client = dashboard.create_app(config).test_client()
    response = client.get("/assets")
    assert response.status_code == 200 and "Acme" in response.text and "nginx" in response.text
    assert cli.main(["--config", str(config.config_path), "inventory", "inspect"]) == 2


def test_empty_web_only_inventory_is_not_clean(tmp_path):
    config = config_file(tmp_path, enabled=True, path=False)
    with pytest.raises(InventoryValidationError, match="no valid records"):
        load_inventory(config.inventory, snapshot_directory=config.database_path.parent / "web-inventory")
    assert cli.main(["--config", str(config.config_path), "scan"]) == 2


def test_watch_only_and_default_off_preserve_missing_inventory(tmp_path):
    config = config_file(tmp_path, path=False, watch=True)
    assert config.inventory is None
    assert dashboard.create_app(config).test_client().get("/assets").status_code == 200
    with pytest.raises(ConfigurationError, match="inventory.path"):
        config_file(tmp_path, path=False)


@pytest.mark.parametrize("value", ["true", 1, [], None])
def test_web_setting_requires_boolean(tmp_path, value):
    path = tmp_path / "config.toml"
    path.write_text('[watch]\nenabled=true\n[inventory]\nweb_snapshots=' +
                    ('"true"' if value == "true" else '1' if value == 1 else '[]' if value == [] else '""'), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="web_snapshots must be a boolean"):
        load_config(path)


def test_editor_boolean_has_no_administrator_path_restriction():
    group = groups_for("inventory", {"inventory": {"web_snapshots": True}}, can_admin=False)[0]
    field = next(item for item in group["controls"] if item["key"] == "web_snapshots")
    assert field["kind"] == "boolean" and not field["readonly"]


def test_snapshot_inputs_refuse_links(tmp_path):
    if os.name != "posix":
        pytest.skip("symbolic link creation requires privileges on Windows")
    output = snapshot(tmp_path / "web-inventory")
    other = output.with_name("linked.json")
    other.symlink_to(output)
    with pytest.raises(Exception, match="regular file"):
        read_web_snapshot(other)


def test_snapshot_json_depth_is_bounded_before_decoding():
    from cvebeacon.web_inventory import decode_json
    with pytest.raises(ValueError, match="nesting"):
        decode_json(b"[" * 65 + b"0" + b"]" * 65)
    assert decode_json(b'{"quoted":"[\\\"[]", "value":[]}')["value"] == []


def test_snapshot_rejects_normalization_expansion(tmp_path):
    output = snapshot(tmp_path / "web-inventory", asset_id="\ufdfa" * 8192)
    with pytest.raises(ValueError, match="normalized inventory value exceeds text limit"):
        read_web_snapshot(output)
