from datetime import timedelta
import hashlib
import json
import os
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


def test_inventory_v1_includes_the_optional_client_label():
    assert "client" in contract.FIELDS
    records = contract.canonical_records(
        [
            {
                "asset_id": "a",
                "vendor": "Acme",
                "product": "Widget",
                "version": "1",
                "client": "Acme",
            }
        ]
    )
    assert records[0]["client"] == "Acme"
    assert records[0].keys() == set(contract.FIELDS)


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


def test_repository_commit_conflict_requires_distinct_instances(tmp_path):
    first=dict(asset_id="one",system_id="instance",repository="https://example.invalid/project",commit="a"*40)
    second=dict(first,asset_id="two",commit="b"*40)
    a=snapshot(tmp_path,records=[first])
    b=snapshot(tmp_path,"b",records=[second])
    output=tmp_path/"merged.json"
    with pytest.raises(ExtensionError,match="strong identity"):
        merge_snapshots([a,b],output,source_id="central")
    assert not output.exists()
    write_snapshot(b,[dict(second,system_id="another-instance")],source_id="b",collector="test")
    assert merge_snapshots([a,b],output,source_id="central")["record_count"]==2


def test_merge_record_bound_stops_before_reading_remaining_inputs(tmp_path,monkeypatch):
    from cvebeacon_extensions import merge
    paths=[snapshot(tmp_path,str(i),records=[row(str(i),system="host-"+str(i))]) for i in range(3)]
    calls=[]
    original=merge.read_snapshot
    def read(path,**kwargs): calls.append(path); return original(path,**kwargs)
    monkeypatch.setattr(merge,"MAX_RECORDS",1)
    monkeypatch.setattr(merge,"read_snapshot",read)
    with pytest.raises(ExtensionError,match="record limit"):
        merge_snapshots(paths,tmp_path/"merged.json",source_id="central")
    assert calls==paths[:2]


def test_merge_byte_budget_stops_before_remaining_inputs(tmp_path,monkeypatch):
    from cvebeacon_extensions import merge
    paths=[snapshot(tmp_path,str(i),records=[row(str(i),system="host-"+str(i))]) for i in range(3)]
    calls=[]
    original=merge.read_snapshot
    def read(path,**kwargs): calls.append(path); return original(path,**kwargs)
    monkeypatch.setattr(merge,"MAX_BYTES",len(paths[0].read_bytes())+5)
    monkeypatch.setattr(merge,"read_snapshot",read)
    with pytest.raises(ExtensionError,match="size limit"):
        merge_snapshots(paths,tmp_path/"merged.json",source_id="central")
    assert calls==paths[:2]


@pytest.mark.parametrize("failure", [False, True])
def test_windows_atomic_creates_private_temporary_before_writing(tmp_path, monkeypatch, failure):
    import os
    from cvebeacon import private_storage
    calls = []
    create = private_storage.private_file
    def checked_create(path, **kwargs):
        calls.append((path, kwargs))
        return create(path, **kwargs)
    class WindowsOS:
        name = "nt"
        def __getattr__(self, name):
            return getattr(os, name)
    monkeypatch.setattr(contract, "os", WindowsOS())
    monkeypatch.setattr(private_storage, "private_file", checked_create)
    path = tmp_path / "snapshot.json"
    path.write_bytes(b'old')
    def publish(source, destination):
        assert calls and calls[0][0] == Path(source)
        assert calls[0][1] == {"create": True, "exclusive": True}
        assert Path(source).read_bytes() == b'new'
        if failure:
            raise PermissionError("held reader")
        os.replace(source, destination)
    monkeypatch.setattr(contract, "replace_file", publish)
    if failure:
        with pytest.raises(PermissionError, match="held reader"):
            contract._atomic(path, b'new')
    else:
        contract._atomic(path, b'new')
    assert path.read_bytes() == (b'old' if failure else b'new')
    assert not list(tmp_path.glob('.cvebeacon-*'))


def assert_private_publications(tmp_path):
    import os
    from cvebeacon.web_inventory import read_bytes, read_web_snapshot
    from cvebeacon_extensions.web import _publish_review
    path = tmp_path / "web.json"
    for version in ("1", "2"):
        write_snapshot(path, [row(version=version)], source_id="web-a", collector="web-detect")
        _publish_review(path, "Acme", "web-a", [], products=[], run={"status": "success"})
        for target in (path, manifest_path(path), Path(str(path) + '.review.json')):
            assert read_bytes(target)  # Core's strict owner/file ACL check.
            if os.name == 'posix':
                assert target.stat().st_mode & 0o777 == 0o600
        assert read_web_snapshot(path)[0][0].version == version
    assert not list(tmp_path.glob('.cvebeacon-*'))


@pytest.mark.skipif(os.name != 'nt', reason="native Windows owner-only ACLs")
def test_windows_publications_pass_core_strict_file_checks(tmp_path):
    # Use an ordinary parent to ensure files do not depend on private inheritance.
    assert_private_publications(tmp_path)
    # Core checks the owner and each ACE; also require inheritance protection.
    import ctypes as c
    from ctypes import wintypes as w
    import msvcrt
    from cvebeacon import windows_private
    from cvebeacon.private_storage import private_file
    control_of = windows_private._bind(windows_private._security,
        "GetSecurityDescriptorControl", [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)])
    for path in tmp_path.glob("*.json"):
        with os.fdopen(private_file(path, readonly=True), "rb") as handle:
            descriptor = c.c_void_p()
            result = windows_private._get_security(msvcrt.get_osfhandle(handle.fileno()),
                1, 4, None, None, None, None, c.byref(descriptor))
            assert result == 0
            try:
                control, revision = w.WORD(), w.DWORD()
                assert control_of(descriptor, c.byref(control), c.byref(revision))
                assert control.value & 0x1000  # SE_DACL_PROTECTED
            finally:
                windows_private._free(descriptor)


@pytest.mark.skipif(os.name != 'posix', reason="POSIX 0600 publication modes")
def test_posix_publications_keep_owner_only_modes(tmp_path):
    assert_private_publications(tmp_path)

