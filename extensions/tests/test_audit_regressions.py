"""Independent extension boundary and resource regressions."""

import pytest
import ast
import importlib.util
import json
import os
from pathlib import Path
import threading
import subprocess

from cvebeacon.config import InventoryConfig
from cvebeacon.errors import InventoryValidationError
from cvebeacon.inventory import load_inventory, validate_records
from cvebeacon_extensions.merge import merge_snapshots
from cvebeacon_extensions.sbom import extract_sbom, SPDX3_CONTEXT

from cvebeacon_extensions import contract, kubernetes as kube
from cvebeacon_extensions.contract import ExtensionError, canonical_records, json_bytes


def test_canonical_exchange_never_silently_discards_a_row():
    records = [dict(asset_id="good", purl="pkg:pypi/example@1"),
               dict(asset_id="", vendor="", product="", version="")]
    with pytest.raises(ExtensionError, match="record"):
        canonical_records(records)


def test_kubernetes_enrichment_bounds_expanded_bytes_before_final_validation(tmp_path, monkeypatch):
    image = "registry.example/app@sha256:" + "a" * 64
    sbom = tmp_path / "image.json"
    sbom.write_bytes(json_bytes(dict(bomFormat="CycloneDX", specVersion="1.7",
        components=[dict(name="example", purl="pkg:generic/example", version="v" * 1000)])))
    assert sbom.stat().st_size < 4096
    observations = [dict(running=True, image_id=image, namespace="demo", pod_uid=str(i),
                         pod="pod-" + str(i), container_kind="regular", container="app")
                    for i in range(20)]
    monkeypatch.setattr(kube, "MAX_BYTES", 4096)
    validated = []
    original = kube.canonical_records
    def validate(rows):
        validated.append(len(rows))
        return original(rows)
    monkeypatch.setattr(kube, "canonical_records", validate)
    with pytest.raises(ExtensionError, match="size limit"):
        kube.enrich(observations, {image: sbom}, source_id="cluster")
    assert not validated


@pytest.mark.parametrize("data", [b'{"x":1,"x":2}', b'[Infinity]', b'[-Infinity]',
    b'[NaN]', b'\xff', b'[{]', b'[' * 65 + b']' * 65,
    b'[' + b'9' * 5000 + b']'])
def test_parser_invalid_structure_is_controlled(data):
    with pytest.raises(ExtensionError):
        contract.decode_json(data)


def test_parser_boundaries_and_quoted_structure(monkeypatch):
    monkeypatch.setattr(contract, "MAX_BYTES", 64)
    assert contract.decode_json(b'\xef\xbb\xbf["\\\"[{]}\\\\"]') == ['"[{]}\\']
    assert contract.decode_json(b'[]' + b' ' * 62) == []
    with pytest.raises(ExtensionError, match="size"):
        contract.decode_json(b'[]' + b' ' * 63)


@pytest.mark.parametrize("value", [None, 1, {}, "2026-02-29T00:00:00Z",
    "2024-02-30T00:00:00Z", "2026-01-01", "2026-01-01T00:00:00+01:00"])
def test_timestamp_invalid_values_are_controlled(value):
    with pytest.raises(ExtensionError):
        contract.timestamp(value)


def test_timestamp_equivalent_utc_and_leap_boundary():
    assert contract.timestamp("2024-02-29T23:59:59Z") == contract.timestamp("2024-02-29T23:59:59+00:00")


@pytest.mark.parametrize("records", [
    [dict(asset_id="a", purl="pkg:pypi/example@1")],
    [dict(asset_id="a", purl="pkg:pypi/example@1", version="2")],
    [dict(asset_id="a", purl="pkg:pypi/example@1"), dict(asset_id="A", purl="pkg:pypi/example@1")],
    [dict(asset_id="a", vendor="Acme", product="Widget", version="01.20")],
    [dict(asset_id="a", vendor="Acme", product="Widget", version=1)],
])
def test_public_validator_matches_file_loader_for_adversarial_records(tmp_path, records):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    try:
        expected = validate_records(records)
    except InventoryValidationError:
        with pytest.raises(InventoryValidationError):
            load_inventory(InventoryConfig(path))
    else:
        assert load_inventory(InventoryConfig(path)) == expected


@pytest.mark.parametrize("which", ["old-inventory", "old-manifest", "missing-inventory", "missing-manifest", "truncated-inventory", "truncated-manifest"])
def test_pair_mismatches_never_pass(tmp_path, which):
    path = tmp_path / "inventory.json"
    contract.write_snapshot(path, [dict(asset_id="a", purl="pkg:pypi/example@1")], source_id="a", collector="test")
    old_data, old_metadata = path.read_bytes(), contract.manifest_path(path).read_bytes()
    contract.write_snapshot(path, [dict(asset_id="a", purl="pkg:pypi/example@2")], source_id="a", collector="test")
    if which == "old-inventory": path.write_bytes(old_data)
    if which == "old-manifest": contract.manifest_path(path).write_bytes(old_metadata)
    if which == "missing-inventory": path.unlink()
    if which == "missing-manifest": contract.manifest_path(path).unlink()
    if which == "truncated-inventory": path.write_bytes(path.read_bytes()[:10])
    if which == "truncated-manifest": contract.manifest_path(path).write_bytes(b'{"contract":')
    with pytest.raises((ExtensionError, OSError)):
        contract.read_snapshot(path)


def test_cooperating_writers_and_stale_lock_fail_without_replacing(tmp_path, monkeypatch):
    path = tmp_path / "inventory.json"
    row = dict(asset_id="a", purl="pkg:pypi/example@1")
    contract.write_snapshot(path, [row], source_id="a", collector="test")
    entered, release = threading.Event(), threading.Event()
    original = contract._atomic
    failures = []
    def atomic(destination, data):
        if destination == path:
            entered.set()
            assert release.wait(5)
        original(destination, data)
    def write():
        try: contract.write_snapshot(path, [row], source_id="a", collector="test")
        except Exception as error: failures.append(error)
    monkeypatch.setattr(contract, "_atomic", atomic)
    writer = threading.Thread(target=write)
    writer.start()
    try:
        assert entered.wait(5)
        with pytest.raises(ExtensionError, match="locked"):
            contract.write_snapshot(path, [dict(row, purl="pkg:pypi/example@2")], source_id="a", collector="test")
    finally:
        release.set()
        writer.join(5)
    assert not writer.is_alive() and not failures
    assert contract.read_snapshot(path).records[0]["version"] == "1"
    lock = Path(str(path) + ".lock")
    lock.write_text("investigate this interrupted writer")
    with pytest.raises(ExtensionError, match="investigate"):
        contract.write_snapshot(path, [row], source_id="a", collector="test")
    assert lock.read_text() == "investigate this interrupted writer"


def test_empty_partial_merge_is_controlled_and_preserves_output(tmp_path):
    output = tmp_path / "previous.json"
    contract.write_snapshot(output, [dict(asset_id="a", purl="pkg:pypi/example@1")], source_id="a", collector="test")
    before = output.read_bytes(), contract.manifest_path(output).read_bytes()
    with pytest.raises(ExtensionError, match="records"):
        merge_snapshots([tmp_path / "missing.json"], output, source_id="central", allow_partial=True)
    assert before == (output.read_bytes(), contract.manifest_path(output).read_bytes())


@pytest.mark.parametrize("first,second,conflicts", [
    ("pkg:pypi/example@1", "pkg:pypi/Example@2", True),
    ("pkg:npm/example@1", "pkg:npm/example@2", True),
    ("pkg:deb/debian/example@1?arch=amd64&distro=debian-12", "pkg:deb/debian/example@2?arch=amd64&distro=debian-12", True),
    ("pkg:deb/debian/example@1?arch=amd64", "pkg:deb/debian/example@1?arch=arm64", False),
    ("pkg:generic/example@1#one", "pkg:generic/example@1#two", False),
])
def test_merge_slots_preserve_qualifiers_and_reject_side_by_side_ambiguity(tmp_path, first, second, conflicts):
    paths = [tmp_path / (name + ".json") for name in ("one", "two")]
    for path, purl in zip(paths, (first, second)):
        contract.write_snapshot(path, [dict(asset_id=path.stem, purl=purl, system_id="host")], source_id=path.stem, collector="test")
    output = tmp_path / "out.json"
    if conflicts:
        with pytest.raises(ExtensionError, match="strong identity"):
            merge_snapshots(paths, output, source_id="central", allow_partial=True)
        assert not output.exists()
    else:
        assert merge_snapshots(paths, output, source_id="central")["record_count"] == 2


def test_merge_exact_size_budget_includes_unicode_escapes_and_array_indentation(tmp_path, monkeypatch):
    from cvebeacon_extensions import merge
    paths = [tmp_path / (str(i) + ".json") for i in range(3)]
    rows = []
    for i, path in enumerate(paths):
        row = dict(asset_id=str(i), vendor="Acme", product='snowman ☃ \\"', version="1", system_id=str(i))
        contract.write_snapshot(path, [row], source_id=str(i), collector="test")
        rows.extend(contract.read_snapshot(path).records)
    size = len(json_bytes(canonical_records(rows)))
    assert size == 3 + sum(len(json_bytes(row)) + 2 * (len(row) + 2) + 1 for row in rows)
    monkeypatch.setattr(merge, "MAX_BYTES", size)
    assert merge_snapshots(paths, tmp_path / "exact.json", source_id="central")["record_count"] == 3
    monkeypatch.setattr(merge, "MAX_BYTES", size - 1)
    with pytest.raises(ExtensionError, match="size limit"):
        merge_snapshots(paths, tmp_path / "over.json", source_id="central")


def test_spdx_reference_category_and_unknown_values_do_not_invent_identity():
    packages = [dict(SPDXID="SPDXRef-" + str(i), name="weak", versionInfo="1",
        externalRefs=[dict(referenceCategory=category, referenceType=kind, referenceLocator=locator)])
        for i, (category, kind, locator) in enumerate([
            ("OTHER", "purl", "pkg:pypi/example@1"),
            ("SECURITY", "purl", "pkg:pypi/example@1"),
            ("PACKAGE-MANAGER", "advisory", "pkg:pypi/example@1"),
            ("OTHER", "download", "NOASSERTION"), ("OTHER", "download", "NONE")])]
    rows, reviews = extract_sbom(dict(spdxVersion="SPDX-2.3", packages=packages), source_id="build")
    assert not rows and len(reviews) == len(packages)


def test_sbom_ordering_namespaces_and_ordinary_upgrade_identity():
    components = [dict(name="display", purl="pkg:npm/%40one/example@1"),
                  dict(name="display", purl="pkg:npm/%40two/example@1")]
    document = dict(bomFormat="CycloneDX", specVersion="1.7", components=components)
    old, reviews = extract_sbom(document, source_id="build")
    document["components"] = [dict(item, purl=item["purl"].replace("@1", "@2")) for item in reversed(components)]
    new, _ = extract_sbom(document, source_id="build")
    assert not reviews and len({row["asset_id"] for row in old}) == 2
    assert {row["asset_id"] for row in old} == {row["asset_id"] for row in new}


@pytest.mark.parametrize("context", ["https://untrusted.invalid/context", [SPDX3_CONTEXT],
    {"@import": SPDX3_CONTEXT}, None])
def test_jsonld_remote_contexts_are_rejected_without_resolution(context):
    with pytest.raises(ExtensionError, match="context"):
        extract_sbom({"@context": context, "@graph": []}, source_id="build")


def test_kubernetes_canary_projection_all_container_classes():
    canary = "operational-secret-canary"
    pod = dict(metadata=dict(name="app", uid="uid", namespace="demo", labels={"private": canary},
        annotations={"private": canary}), spec=dict(serviceAccountName=canary,
        imagePullSecrets=[dict(name=canary)], volumes=[dict(secret=dict(secretName=canary))]), status={})
    for field, statuses in [("containers", "containerStatuses"), ("initContainers", "initContainerStatuses"),
                            ("ephemeralContainers", "ephemeralContainerStatuses")]:
        pod["spec"][field] = [dict(name="app", image="app:tag", command=[canary], args=[canary],
            env=[dict(name="SECRET", value=canary)], envFrom=[dict(secretRef=dict(name=canary))])]
        pod["status"][statuses] = [dict(name="app", imageID="sha256:" + "a" * 64, state={"running": {}})]
    projected = kube.project_pods([pod], selected_namespace="demo")
    assert len(projected) == 3 and canary not in json.dumps(projected)
    assert all(kube.image_digest(row["image_id"]) is None for row in projected)


def test_kubernetes_instance_identity_changes_only_at_documented_boundaries(tmp_path):
    image = "registry.example/app@sha256:" + "a" * 64
    sbom = tmp_path / "image.json"
    sbom.write_bytes(json_bytes(dict(bomFormat="CycloneDX", specVersion="1.7", components=[dict(name="a", purl="pkg:pypi/example@1")])))
    first = dict(running=True, image_id=image, namespace="demo", pod_uid="uid", pod="one", container_kind="regular", container="app")
    observations = [first, dict(first, pod_uid="uid2", pod="two"), dict(first, namespace="other"), dict(first, container="sidecar")]
    rows, reviews = kube.enrich(observations, {image: sbom}, source_id="cluster")
    assert not reviews and len({row["asset_id"] for row in rows}) == 4
    repeated, _ = kube.enrich([first], {image: sbom}, source_id="cluster")
    assert repeated[0] in rows


def test_extensions_have_no_state_applicability_or_delivery_authority():
    root = Path(__file__).parents[1] / "src/cvebeacon_extensions"
    forbidden = {"cvebeacon.state", "cvebeacon.engine", "cvebeacon.notifications", "cvebeacon.notify", "sqlite3"}
    for path in root.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            imports = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            assert not any(name == bad or name.startswith(bad + ".") for name in imports for bad in forbidden), path.name


@pytest.mark.skipif(os.name != "posix", reason="Linux deployment flock wrapper")
def test_scan_lock_open_failure_is_controlled(monkeypatch, capsys):
    path = Path(__file__).parents[2] / "deploy/kubernetes/scan.py"
    spec = importlib.util.spec_from_file_location("audit_scan", path)
    scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scan)
    monkeypatch.setattr(scan.sys, "argv", [str(path)])
    monkeypatch.setattr(scan.signal, "signal", lambda *args: None)
    def denied(*args, **kwargs):
        raise PermissionError("filesystem-secret-canary")
    monkeypatch.setattr(scan.os, "open", denied)
    assert scan.main() == 2
    assert "canary" not in capsys.readouterr().err


@pytest.mark.parametrize("leaf", ["inventory", "manifest", "lock"])
def test_linked_publication_leaves_preserve_targets(tmp_path, leaf):
    output, target = tmp_path / "out.json", tmp_path / "target.json"
    row = dict(asset_id="a", purl="pkg:pypi/example@1")
    target.write_text("immutable canary target")
    path = {"inventory": output, "manifest": contract.manifest_path(output),
            "lock": Path(str(output) + ".lock")}[leaf]
    try: path.symlink_to(target)
    except OSError: pytest.skip("symlink creation unavailable for this account")
    with pytest.raises(ExtensionError):
        contract.write_snapshot(output, [row], source_id="source", collector="test")
    assert target.read_text() == "immutable canary target"
    assert path.is_symlink()
    assert not output.exists() if leaf != "inventory" else output.is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX special input files")
def test_fifo_socket_device_inputs_are_rejected_before_open(tmp_path):
    import socket
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    sock = socket.socket(socket.AF_UNIX)
    try:
        endpoint = tmp_path / "socket"
        sock.bind(str(endpoint))
        for path in (fifo, endpoint, Path("/dev/null")):
            with pytest.raises(ExtensionError, match="regular"):
                contract.read_bytes(path)
    finally:
        sock.close()


@pytest.mark.skipif(os.name != "nt", reason="native Windows junction/reparse point")
def test_windows_junction_input_and_destination_are_rejected(tmp_path):
    target, junction = tmp_path / "target", tmp_path / "junction.json"
    target.mkdir()
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(target)], capture_output=True, timeout=10)
    assert result.returncode == 0, "could not create synthetic junction"
    with pytest.raises(ExtensionError, match="regular"):
        contract.read_bytes(junction)
    with pytest.raises(ExtensionError, match="regular"):
        contract.write_snapshot(junction, [dict(asset_id="a", purl="pkg:pypi/example@1")], source_id="source", collector="test")
    assert not list(target.iterdir())


def test_hardlinked_output_replacement_preserves_original_inode(tmp_path):
    target, output = tmp_path / "target.json", tmp_path / "output.json"
    target.write_text("original hardlink bytes")
    os.link(target, output)
    contract.write_snapshot(output, [dict(asset_id="a", purl="pkg:pypi/example@1")], source_id="source", collector="test")
    assert target.read_text() == "original hardlink bytes"
    assert contract.read_snapshot(output).manifest["status"] == "success"


def test_host_multiarch_and_windows_cosmetic_normalization():
    from cvebeacon_extensions.hosts import linux_inventory, windows_inventory
    rows, reviews = linux_inventory('ID=debian\nVERSION_ID=12',
        'installed\tlibfoo+extra\t2:1.0~rc1-1+b2\tamd64\ninstalled\tlibfoo+extra\t2:1.0~rc1-1+b2\ti386\n',
        backend="dpkg", source_id="host", package_namespace="debian")
    packages = [row for row in rows if row["purl"]]
    assert not reviews and len(packages) == 2
    assert len({row["asset_id"] for row in packages}) == 2
    assert all(row["version"] == "2:1.0~rc1-1+b2" for row in packages)
    program = dict(name="Widget", vendor="Acme", version="1", scope="machine", view="64")
    old, _ = windows_inventory(dict(product="Windows", version="12345"), [program], source_id="host")
    new, _ = windows_inventory(dict(product="Windows", version="12345"), [dict(program, name=" Widget ", vendor="ACME", version="2")], source_id="host")
    assert {row["asset_id"] for row in old} == {row["asset_id"] for row in new}
