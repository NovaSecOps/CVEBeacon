from datetime import timedelta
import hashlib
import json
from pathlib import Path

import pytest

from cvebeacon.config import InventoryConfig
from cvebeacon.inventory import load_inventory, validate_records
from cvebeacon.errors import InventoryValidationError
from cvebeacon_extensions import contract
from cvebeacon_extensions.cli import main
from cvebeacon_extensions.contract import ExtensionError, read_snapshot, write_snapshot, utc_now, manifest_path
from cvebeacon_extensions.merge import merge_snapshots


def row(asset="a", version="1", system="host-a"):
    return dict(asset_id=asset, purl=f"pkg:pypi/example@{version}", system_id=system)


def snapshot(tmp_path, name="a", records=None, **kwargs):
    path = tmp_path / f"{name}.json"
    write_snapshot(path, records or [row(name)], source_id=name, collector="test", **kwargs)
    return path


def mutate_manifest(path, **changes):
    location = manifest_path(path)
    value = json.loads(location.read_bytes())
    value.update(changes)
    location.write_bytes(contract.json_bytes(value))


def test_roundtrip_matches_real_core(tmp_path):
    path = snapshot(tmp_path, records=[row(), dict(asset_id="legacy", vendor="Acme", product="Widget", version="01.020")])
    observed = read_snapshot(path)
    assert validate_records(observed.records) == load_inventory(InventoryConfig(path))
    assert observed.records[1]["version"] == "01.020"


@pytest.mark.parametrize("records", [[], [dict(asset_id="a", version=1)], [dict(asset_id="a", unknown="x")],
    [row(), row("A")], [dict(asset_id="a", purl="pkg:pypi/example@1", version="2")],
    [dict(asset_id="a", purl="pkg:pypi/example@1", cpe="cpe:2.3:a:acme:example:1:*:*:*:*:*:*:*")]])
def test_invalid_output_preserves_previous_pair(tmp_path, records):
    path = snapshot(tmp_path)
    before = (path.read_bytes(), manifest_path(path).read_bytes())
    with pytest.raises((ExtensionError, InventoryValidationError)):
        write_snapshot(path, records, source_id="a", collector="test")
    assert before == (path.read_bytes(), manifest_path(path).read_bytes())


@pytest.mark.parametrize("change", [dict(sha256="0"*64), dict(record_count=True), dict(record_count=2),
    dict(contract="future"), dict(status="failed"), dict(status="partial"), dict(source_id="../a"),
    dict(generated_at="2026-01-01"), dict(observed_at="2099-01-01T00:00:00Z")])
def test_manifest_rejections(tmp_path, change):
    path = snapshot(tmp_path)
    mutate_manifest(path, **change)
    with pytest.raises(ExtensionError):
        read_snapshot(path)


def test_stale_partial_missing_and_freshness_propagation(tmp_path):
    observed = utc_now() - timedelta(hours=1)
    a = snapshot(tmp_path, observed_at=observed.isoformat())
    out = tmp_path / "merged.json"
    with pytest.raises(ExtensionError, match="stale"):
        merge_snapshots([a], out, source_id="central", max_age_seconds=1)
    with pytest.raises(ExtensionError, match="missing required"):
        merge_snapshots([a], out, source_id="central", expected_sources=["b"])
    assert not out.exists()
    merge_snapshots([a, tmp_path / "absent.json"], out, source_id="central", expected_sources=["b"], allow_partial=True)
    with pytest.raises(ExtensionError, match="partial"):
        read_snapshot(out)
    result = read_snapshot(out, allow_partial=True)
    assert set(result.manifest["omissions"]) == {"b", "missing-input"}
    assert contract.timestamp(result.manifest["observed_at"]) == observed


def test_determinism_duplicate_coalescing_and_conflicts(tmp_path):
    a = snapshot(tmp_path, records=[row("a"), row("z", system="host-z")])
    b = snapshot(tmp_path, "b", records=[row("a"), row("b", system="host-b")])
    out1, out2 = tmp_path / "one.json", tmp_path / "two.json"
    merge_snapshots([a, b], out1, source_id="central")
    merge_snapshots([b, a], out2, source_id="central")
    assert out1.read_bytes() == out2.read_bytes()
    assert len(read_snapshot(out1).records) == 3
    write_snapshot(b, [row("a", "2")], source_id="b", collector="test")
    with pytest.raises(ExtensionError, match="conflicting asset_id"):
        merge_snapshots([a, b], out2, source_id="central")
    write_snapshot(b, [row("different-id", "2")], source_id="b", collector="test")
    with pytest.raises(ExtensionError, match="strong identity"):
        merge_snapshots([a, b], out2, source_id="central")


def test_duplicate_sources_input_overwrite_and_corrupt_partial(tmp_path):
    a = snapshot(tmp_path)
    b = snapshot(tmp_path, "b", records=[row("b", system="host-b")])
    mutate_manifest(b, source_id="a")
    with pytest.raises(ExtensionError, match="duplicate source"):
        merge_snapshots([a,b], tmp_path / "out.json", source_id="central")
    with pytest.raises(ExtensionError, match="overwrite"):
        merge_snapshots([a], a, source_id="central")
    with pytest.raises(ExtensionError, match="duplicate input"):
        merge_snapshots([a,a], tmp_path / "out.json", source_id="central")
    mutate_manifest(a, sha256="bad")
    with pytest.raises(ExtensionError, match="hash"):
        merge_snapshots([a], tmp_path / "out.json", source_id="central", allow_partial=True)


def test_interrupted_pair_cannot_look_fresh(tmp_path, monkeypatch):
    path = snapshot(tmp_path)
    original = contract._atomic
    def interrupt(destination, data):
        if destination == manifest_path(path):
            raise OSError("synthetic interruption")
        return original(destination, data)
    monkeypatch.setattr(contract, "_atomic", interrupt)
    with pytest.raises(OSError):
        write_snapshot(path, [row(version="2")], source_id="a", collector="test")
    with pytest.raises(ExtensionError, match="hash"):
        read_snapshot(path)


def test_lock_and_symlink_no_overwrite(tmp_path):
    path = snapshot(tmp_path)
    before = path.read_bytes()
    lock = Path(str(path) + ".lock")
    lock.touch()
    with pytest.raises(ExtensionError, match="locked"):
        write_snapshot(path, [row(version="2")], source_id="a", collector="test")
    assert path.read_bytes() == before
    link = tmp_path / "link.json"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("symlink creation unavailable for this account")
    with pytest.raises(ExtensionError, match="regular"):
        read_snapshot(link)
    with pytest.raises(ExtensionError, match="regular"):
        write_snapshot(link, [row()], source_id="a", collector="test")
    assert path.read_bytes() == before


@pytest.mark.parametrize("data", [b'{"a":1,"a":2}', b'[NaN]', b'\xff', b'['*2000+b']'*2000],
                         ids=["duplicate", "nonfinite", "utf8", "depth"])
def test_malicious_json(data):
    with pytest.raises(ExtensionError):
        contract.decode_json(data)


def test_bounded_read_and_cli(tmp_path):
    path = snapshot(tmp_path)
    with pytest.raises(ExtensionError):
        contract.read_bytes(path, 1)
    assert main(["validate", str(path)]) == 0
    assert main(["validate", str(path), "--max-age-seconds", "-1"]) == 2
    assert main(["merge", str(path), "--source-id", "central", "--output", str(tmp_path / "out.json")]) == 0


@pytest.mark.parametrize("first,second", [
    (row(), dict(asset_id="b", ecosystem="PyPI", product="example", version="2", system_id="host-a")),
    (dict(asset_id="a", cpe="cpe:2.3:a:acme:example:1:*:*:*:*:*:*:*", system_id="host-a"),
     dict(asset_id="b", cpe="cpe:2.3:a:acme:example:2:*:*:*:*:*:*:*", system_id="host-a")),
])
def test_equivalent_strong_identity_conflicts(tmp_path, first, second):
    a = snapshot(tmp_path, records=[first])
    b = snapshot(tmp_path, "b", records=[second])
    with pytest.raises(ExtensionError, match="strong identity"):
        merge_snapshots([a,b], tmp_path / "out.json", source_id="central")


def test_published_data_always_fits_reader_limits(tmp_path):
    path = snapshot(tmp_path)
    before = (path.read_bytes(), manifest_path(path).read_bytes())
    with pytest.raises(ExtensionError, match="manifest exceeds"):
        write_snapshot(path, [row()], source_id="a", collector="test", omissions=[str(i)+"a"*120 for i in range(600)])
    with pytest.raises(ExtensionError, match="normalized"):
        write_snapshot(path, [row("\ufdfa"*8192)], source_id="a", collector="test")
    assert before == (path.read_bytes(), manifest_path(path).read_bytes())


def test_unpaired_surrogate_rejected_before_snapshot_write(tmp_path):
    path = snapshot(tmp_path)
    before = path.read_bytes()
    with pytest.raises(ExtensionError):
        write_snapshot(path, [dict(asset_id="a", vendor="Example", product="\ud800", version="1")], source_id="a", collector="test")
    assert path.read_bytes() == before
