from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from cvebeacon_extensions.contract import manifest_path, read_snapshot, write_snapshot
from cvebeacon_automation.common import AutomationError, Secret, lock, read_json
from cvebeacon_automation.config import Config, Source, load_config
from cvebeacon_automation.health import status
from cvebeacon_automation.pipeline import run_pipeline
from cvebeacon_automation.staging import current_snapshot, publish


def setup(tmp_path):
    output = tmp_path / "merged.json"
    core = tmp_path / "core.toml"
    core.write_text('[inventory]\npath="merged.json"\nformat="json"\n[state]\ndatabase="core.db"\n[sources]\nosv_enabled=false\nnvd_enabled=false\ncve_enabled=false\neuvd_enabled=false\ncisa_kev_enabled=false\neu_kev_enabled=false\nepss_enabled=false\n')
    source = tmp_path / "source.json"
    write_snapshot(source, [dict(asset_id="a", purl="pkg:pypi/example@1.0")], source_id="host-a", collector="synthetic")
    config = Config(tmp_path / "auto.toml", tmp_path / "state", tmp_path / "staging", output, core,
                    (Source("host-a", snapshot=source),))
    return config, source


@pytest.mark.parametrize("code", [0, 2, 3, 4])
def test_preserves_core_exit_and_health(tmp_path, code):
    config, source = setup(tmp_path)
    assert run_pipeline(config, scanner=lambda c: code) == code
    assert status(config.state_dir)["core_exit"] == code
    assert read_snapshot(config.inventory_path).records[0]["product"] == "example"
    if code == 4:
        assert status(config.state_dir)["status"] == "coverage_warning"


def test_required_failure_preserves_previous_inventory(tmp_path):
    config, source = setup(tmp_path)
    assert run_pipeline(config, scanner=lambda c: 0) == 0
    before = config.inventory_path.read_bytes()
    source.write_text("corrupted")
    assert run_pipeline(config, scanner=lambda c: pytest.fail("must stop before scan")) == 2
    assert config.inventory_path.read_bytes() == before


def test_optional_failure_is_degraded_and_manifest_partial(tmp_path):
    config, source = setup(tmp_path)
    config = replace(config, sources=(*config.sources, Source("optional", required=False, snapshot=tmp_path / "missing.json")))
    assert run_pipeline(config, scanner=lambda c: 0) == 5
    assert read_snapshot(config.inventory_path, allow_partial=True).manifest["omissions"] == ["optional"]


def test_whole_pipeline_lock(tmp_path):
    config, source = setup(tmp_path)
    with lock(config.state_dir / "automation.lock"):
        with pytest.raises(AutomationError, match="locked"):
            run_pipeline(config, scanner=lambda c: pytest.fail("locked pipeline"))
    assert run_pipeline(config, scanner=lambda c: 0) == 0


def test_exact_byte_staging_and_idempotence(tmp_path):
    config, source = setup(tmp_path)
    raw, side = source.read_bytes(), manifest_path(source).read_bytes()
    assert publish(config.staging_dir, "host-a", raw, side)["status"] == "accepted"
    assert publish(config.staging_dir, "host-a", raw, side)["status"] == "idempotent"
    assert current_snapshot(config.staging_dir, "host-a").read_bytes() == raw
    with pytest.raises(AutomationError, match="source_identity_mismatch"):
        publish(config.staging_dir, "host-b", raw, side)


def test_rollback_cannot_replace_fresher_staging(tmp_path):
    config, source = setup(tmp_path)
    old_raw, old_side = source.read_bytes(), manifest_path(source).read_bytes()
    publish(config.staging_dir, "host-a", old_raw, old_side)
    metadata = json.loads(old_side)
    metadata["generated_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    metadata["observed_at"] = metadata["generated_at"]
    with pytest.raises(AutomationError, match="snapshot_replay_or_rollback"):
        publish(config.staging_dir, "host-a", old_raw, json.dumps(metadata).encode())


@pytest.mark.parametrize("name", ["../evil", "a/b", "x:y", "CON", "name.", "a\\b"])
def test_staging_source_path_traversal(tmp_path, name):
    with pytest.raises(AutomationError):
        current_snapshot(tmp_path, name)


def test_configuration_strict_and_no_secret_resolution(tmp_path, monkeypatch):
    text = '[automation]\nversion=1\ncore_config="core.toml"\n[[sources]]\nid="host-a"\nsnapshot="host.json"\n'
    filename = tmp_path / "auto.toml"
    filename.write_text(text)
    assert load_config(filename).sources[0].required
    filename.write_text(text + 'raw_password="canary"\n')
    with pytest.raises(AutomationError):
        load_config(filename)
    secret = Secret.parse({"env": "FAKE_CREDENTIAL"}, tmp_path)
    assert "FAKE_CREDENTIAL" not in repr(secret)
    with pytest.raises(AutomationError, match="secret_unavailable"):
        secret.resolve()


def test_core_child_environment_contains_no_automation_secrets(monkeypatch):
    from cvebeacon_automation.process import clean_environment
    monkeypatch.setenv("AUTOMATION_TOKEN", "credential-canary")
    monkeypatch.setenv("SSLKEYLOGFILE", "/secret/path")
    monkeypatch.setenv("HTTPS_PROXY", "https://secret.invalid")
    assert not {"AUTOMATION_TOKEN", "SSLKEYLOGFILE", "HTTPS_PROXY"} & clean_environment().keys()


def test_manifest_destination_preflight_preserves_good_inventory(tmp_path):
    config, source = setup(tmp_path)
    config.inventory_path.write_bytes(b"previous-good-inventory")
    manifest_path(config.inventory_path).mkdir()
    assert run_pipeline(config, scanner=lambda c: pytest.fail("bad pair must not scan")) == 2
    assert config.inventory_path.read_bytes() == b"previous-good-inventory"


def test_second_publication_failure_rolls_back_first_side(tmp_path, monkeypatch):
    from cvebeacon_automation import common
    config, source = setup(tmp_path)
    assert run_pipeline(config, scanner=lambda c: 0) == 0
    before = config.inventory_path.read_bytes()
    side_before = manifest_path(config.inventory_path).read_bytes()
    real_atomic = common.atomic
    def fail_manifest(destination, data):
        if destination == manifest_path(config.inventory_path):
            raise OSError("synthetic failure")
        return real_atomic(destination, data)
    monkeypatch.setattr(common, "atomic", fail_manifest)
    write_snapshot(source, [dict(asset_id="a", purl="pkg:pypi/example@2.0")], source_id="host-a", collector="synthetic")
    assert run_pipeline(config, scanner=lambda c: pytest.fail("failed publish must not scan")) == 2
    assert config.inventory_path.read_bytes() == before
    assert manifest_path(config.inventory_path).read_bytes() == side_before


def test_different_state_dirs_lock_shared_resources(tmp_path):
    config, source = setup(tmp_path)
    resource = config.inventory_path.with_name(config.inventory_path.name + ".automation.lock")
    with lock(resource):
        assert run_pipeline(replace(config, state_dir=tmp_path / "another-state"), scanner=lambda c: pytest.fail("shared inventory locked")) == 75


def test_sidecar_cannot_overwrite_input(tmp_path):
    config, source = setup(tmp_path)
    config = replace(config, inventory_path=tmp_path / "overlap.json", sources=(Source("host-a", snapshot=tmp_path / "overlap.json.manifest.json"),))
    # Set a valid matching Core path so collision, not config mismatch, is decisive.
    config.core_config.write_text(config.core_config.read_text().replace('"merged.json"', '"overlap.json"'))
    assert run_pipeline(config, scanner=lambda c: pytest.fail("collision")) == 2
    assert "pipeline_path_collision" in status(config.state_dir)["failures"]


@pytest.mark.parametrize("core_exit", [0, 4])
def test_operational_delivery_failure_is_persisted_without_erasing_core_coverage(tmp_path, monkeypatch, core_exit):
    from cvebeacon_automation.notifications import service
    config, source = setup(tmp_path)
    config = replace(config, notifications=({"id": "synthetic"},), operations={"enabled": True})
    monkeypatch.setattr(service, "dispatch", lambda *args: {"unhealthy": False})
    monkeypatch.setattr(service, "operational", lambda *args: {"version": 1, "unhealthy": True, "attempted": 1})
    assert run_pipeline(config, scanner=lambda c: core_exit) == (5 if core_exit == 0 else 4)
    health = status(config.state_dir)
    assert health["core_exit"] == core_exit and health["operations"]["unhealthy"]
    assert "operational_notification_failure" in health["failures"]
    assert health["consecutive_failures"] == 1


def test_disabled_discovery_does_not_degrade_pipeline(tmp_path, monkeypatch):
    from cvebeacon_automation.discovery import nmap
    config, source = setup(tmp_path)
    config = replace(config, discovery=({"id": "disabled", "enabled": False},))
    monkeypatch.setattr(nmap, "run_jobs", lambda config: {"disabled": {"status": "disabled"}})
    assert run_pipeline(config, scanner=lambda c: 0) == 0
    assert status(config.state_dir)["discovery"]["disabled"]["status"] == "disabled"


@pytest.mark.parametrize("value", [[], {"version": 99, "status": "operational"},
    {"version": 1, "status": "operational", "consecutive_failures": "1"},
    {"version": 1, "status": "operational", "sources": []}])
def test_corrupt_health_is_not_silently_reset(tmp_path, value):
    directory = tmp_path / "state"
    directory.mkdir()
    filename = directory / "health.json"
    raw = json.dumps(value).encode()
    filename.write_bytes(raw)
    with pytest.raises(AutomationError, match="invalid_automation_health"):
        status(directory)
    assert filename.read_bytes() == raw


def test_kubernetes_observation_collision_preserves_input(tmp_path):
    config, source = setup(tmp_path)
    raw = source.read_bytes()
    config = replace(config, sources=(Source("cluster", kind="kubernetes", options={"observations": str(config.inventory_path)}),))
    assert run_pipeline(config, scanner=lambda c: pytest.fail("observation collision must halt")) == 2
    assert source.read_bytes() == raw
    assert "pipeline_path_collision" in status(config.state_dir)["failures"]


def test_core_database_cannot_overwrite_static_source(tmp_path):
    config, source = setup(tmp_path)
    raw = source.read_bytes()
    config.core_config.write_text(config.core_config.read_text().replace('database="core.db"', 'database="source.json"'))
    assert run_pipeline(config, scanner=lambda c: pytest.fail("database collides with input")) == 2
    assert source.read_bytes() == raw
    assert "core_state_path_collision" in status(config.state_dir)["failures"]


def test_explicit_container_coverage_policy_preserves_health(tmp_path, monkeypatch, capsys):
    from cvebeacon_automation import cli, config as configuration, pipeline
    config, source = setup(tmp_path)
    monkeypatch.setattr(configuration, "load_config", lambda _: config)
    monkeypatch.setattr(pipeline, "core_scan", lambda _: 4)
    assert cli.main(["run", "--accept-coverage-warning"]) == 0
    assert status(config.state_dir)["core_exit"] == 4
    assert status(config.state_dir)["status"] == "coverage_warning"
    assert "coverage warning" in capsys.readouterr().err
