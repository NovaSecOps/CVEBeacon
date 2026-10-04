"""Offline OCI wire, attribution, bounds and prior-generation regressions."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from cvebeacon_extensions.contract import json_bytes, read_snapshot
from cvebeacon_automation.common import AutomationError, digest
from cvebeacon_automation.config import Config, Source
from cvebeacon_automation.http import Response
from cvebeacon_automation.registry import acquire, client
from cvebeacon_automation.staging import current_snapshot

URL = "https://registry.example"
REPO = "team/app"
CDX = "application/vnd.cyclonedx+json"


def descriptor(raw, media, **extra):
    return dict(mediaType=media, digest="sha256:" + digest(raw), size=len(raw), **extra)


class RegistryWire:
    """Recorded finite protocol fixture; no socket or response-selected request."""

    def __init__(self, *, sbom=None, sbom_media=CDX, artifact_change=None, layer_change=None, image_index=False):
        self.calls = []
        self.routes = {}
        self.empty = b"{}"
        self.sbom = json_bytes(sbom or dict(bomFormat="CycloneDX", specVersion="1.6", components=[
            dict(type="library", name="example", version="1.0", purl="pkg:pypi/example@1.0")]))
        image_config = json_bytes(dict(architecture="amd64", os="linux"))
        self.target = dict(schemaVersion=2, mediaType=client.IMAGE,
                           config=descriptor(image_config, "application/vnd.oci.image.config.v1+json"), layers=[])
        if image_index:
            image_manifest = json_bytes(self.target)
            self.target = dict(schemaVersion=2, mediaType=client.INDEX,
                               manifests=[descriptor(image_manifest, client.IMAGE)])
        self.target_raw = json_bytes(self.target)
        self.subject = descriptor(self.target_raw, self.target["mediaType"])
        self.reference = "registry.example/" + REPO + "@" + self.subject["digest"]
        layer = descriptor(self.sbom, sbom_media)
        if layer_change:
            layer.update(layer_change)
        self.artifact = dict(schemaVersion=2, mediaType=client.IMAGE, artifactType=sbom_media,
                             config=descriptor(self.empty, client.EMPTY), layers=[layer], subject=self.subject.copy())
        if artifact_change:
            self.artifact.update(artifact_change(self) if callable(artifact_change) else artifact_change)
        self.artifact_raw = json_bytes(self.artifact)
        self.referrer = descriptor(self.artifact_raw, client.IMAGE, artifactType=sbom_media)
        self.install_manifest(self.subject["digest"], self.target_raw, self.target["mediaType"])
        self.install_manifest(self.referrer["digest"], self.artifact_raw, client.IMAGE)
        self.routes[f"/v2/{REPO}/blobs/sha256:{digest(self.empty)}"] = Response(200, {"content-type": "application/octet-stream"}, self.empty)
        self.routes[f"/v2/{REPO}/blobs/sha256:{digest(self.sbom)}"] = Response(200, {"content-type": "application/octet-stream"}, self.sbom)
        self.referrers_path = f"/v2/{REPO}/referrers/{self.subject['digest']}"
        self.page([self.referrer])

    def install_manifest(self, expected, raw, media):
        self.routes[f"/v2/{REPO}/manifests/{expected}"] = Response(200, {"content-type": media, "docker-content-digest": expected}, raw)

    def page(self, items, *, query="", link=None):
        headers = {"content-type": client.INDEX}
        if link is not None:
            headers["link"] = link
        self.routes[self.referrers_path + query] = Response(200, headers, json_bytes(dict(schemaVersion=2, mediaType=client.INDEX, manifests=items)))

    def request(self, method, url, *, headers, body=b""):
        assert method == "GET" and body == b""
        parsed = urlsplit(url)
        assert parsed.scheme == "https" and parsed.netloc == "registry.example"
        self.calls.append((url, dict(headers)))
        key = parsed.path + ("?" + parsed.query if parsed.query else "")
        assert key in self.routes, "fixture never permits unplanned URL"
        return self.routes[key]


def definition(tmp_path=None, **options):
    return client.validate_registries([dict(id="lab", url=URL, repositories=[REPO], **options)], tmp_path or Path("."))[0]


def run_wire(wire, *, pin=None, running=False, registry=None):
    return client.RegistryClient(registry or definition(), transport=wire).acquire(wire.reference, artifact_digest=pin, running=running)


def test_verified_referrer_and_generic_blob_content_type():
    wire = RegistryWire()
    evidence = run_wire(wire)
    assert evidence.sbom_bytes == wire.sbom
    assert evidence.image_digest == wire.subject["digest"]
    assert evidence.artifact_digest == wire.referrer["digest"]
    assert len(wire.calls) == 5
    assert all("Authorization" not in headers for _, headers in wire.calls)
    assert all("sha256:" in url for url, _ in wire.calls)


@pytest.mark.parametrize("mutate,category", [
    (lambda w: w.routes.__setitem__(f"/v2/{REPO}/manifests/{w.subject['digest']}", Response(200, {"content-type": client.IMAGE}, w.target_raw + b" ")), "registry_digest_mismatch"),
    (lambda w: w.page([dict(w.referrer, size=w.referrer["size"] + 1)]), "registry_size_mismatch"),
    (lambda w: w.routes.__setitem__(f"/v2/{REPO}/blobs/sha256:{digest(w.sbom)}", Response(200, {}, b"wrong")), "registry_digest_mismatch"),
    (lambda w: w.page([dict(w.referrer, artifactType=[])]), "registry_descriptor_invalid"),
])
def test_tampered_bytes_and_descriptors_rejected(mutate, category):
    wire = RegistryWire()
    mutate(wire)
    with pytest.raises(AutomationError, match=category):
        run_wire(wire)


@pytest.mark.parametrize("change", [
    lambda w: dict(subject=dict(w.subject, digest="sha256:" + "0" * 64)),
    lambda w: dict(subject=dict(w.subject, size=w.subject["size"] + 1)),
    lambda w: dict(subject=dict(w.subject, mediaType=client.INDEX)),
])
def test_artifact_subject_must_match_complete_target_descriptor(change):
    with pytest.raises(AutomationError, match="registry_subject_mismatch"):
        run_wire(RegistryWire(artifact_change=change))


@pytest.mark.parametrize("change,category", [
    ({"layers": []}, "registry_artifact_layout_unsupported"),
    ({"artifactType": "application/spdx+json"}, "registry_media_invalid"),
    ({"config": descriptor(b"{}", "application/json")}, "registry_artifact_layout_unsupported"),
])
def test_unsupported_artifact_layout(change, category):
    with pytest.raises(AutomationError, match=category):
        run_wire(RegistryWire(artifact_change=change))


def test_sbom_layer_size_is_verified_independently():
    base = RegistryWire()
    wire = RegistryWire(layer_change={"size": len(base.sbom) + 1})
    with pytest.raises(AutomationError, match="registry_size_mismatch"):
        run_wire(wire)


def test_descriptor_external_urls_are_ignored():
    wire = RegistryWire(artifact_change=lambda w: dict(subject=dict(w.subject, urls=["https://metadata.invalid/admin"])))
    wire.referrer["urls"] = ["https://metadata.invalid/admin"]
    wire.page([wire.referrer])
    assert run_wire(wire).sbom_bytes == wire.sbom
    assert len(wire.calls) == 5


def test_referrer_ambiguity_requires_explicit_digest():
    wire = RegistryWire()
    other = RegistryWire(artifact_change={"annotations": {"test": "second-valid-artifact"}})
    wire.install_manifest(other.referrer["digest"], other.artifact_raw, client.IMAGE)
    wire.page([wire.referrer, other.referrer])
    with pytest.raises(AutomationError, match="registry_sbom_ambiguous"):
        run_wire(wire)
    assert run_wire(wire, pin=wire.referrer["digest"]).artifact_digest == wire.referrer["digest"]


def test_server_filter_claim_does_not_accept_unrelated_artifact():
    wire = RegistryWire()
    wire.page([dict(wire.referrer, artifactType="application/vnd.in-toto+json")])
    with pytest.raises(AutomationError, match="registry_sbom_missing"):
        run_wire(wire)
    assert len(wire.calls) == 2


def test_bounded_pagination_and_duplicate_deduplication():
    wire = RegistryWire()
    wire.page([wire.referrer], link='<?page=two>; rel="next"')
    wire.page([wire.referrer], query="?page=two")
    assert run_wire(wire).artifact_digest == wire.referrer["digest"]
    assert len(wire.calls) == 6


@pytest.mark.parametrize("link", [
    '<https://metadata.invalid/admin>; rel="next"',
    '</v2/team/other/referrers/sha256:' + "0" * 64 + '>; rel="next"',
    '<https://registry.example/admin>; rel="next"',
    '<https://user:password@registry.example/admin>; rel="next"',
    '<?page=two#fragment>; rel="next"',
    '<?page=two>; rel="next", <?page=three>; rel="next"',
])
def test_hostile_pagination_rejected_before_new_request(link):
    wire = RegistryWire()
    wire.page([wire.referrer], link=link)
    with pytest.raises(AutomationError):
        run_wire(wire)
    assert len(wire.calls) == 2


def test_pagination_loop_limit_and_conflict():
    wire = RegistryWire()
    wire.page([wire.referrer], link=f'<{wire.referrers_path}>; rel="next"')
    with pytest.raises(AutomationError, match="registry_pagination_loop"):
        run_wire(wire)
    wire.page([wire.referrer], link='<?page=two>; rel="next"')
    with pytest.raises(AutomationError, match="registry_pagination_limit"):
        run_wire(wire, registry=replace(definition(), max_pages=1))
    wire.page([dict(wire.referrer, size=wire.referrer["size"] + 1)], query="?page=two")
    with pytest.raises(AutomationError, match="registry_referrer_conflict"):
        run_wire(wire)


def test_auth_challenge_and_redirect_never_choose_destination(monkeypatch):
    monkeypatch.setenv("REGISTRY_TEST_TOKEN", "synthetic-token-canary")
    registry = definition(bearer={"env": "REGISTRY_TEST_TOKEN"})
    for status, headers, category in [(401, {"www-authenticate": 'Bearer realm="https://169.254.169.254/token",scope="registry:catalog:*"'}, "registry_authentication_required"),
                                      (307, {"location": "https://metadata.invalid/admin"}, "registry_redirect_rejected")]:
        wire = RegistryWire()
        wire.routes[f"/v2/{REPO}/manifests/{wire.subject['digest']}"] = Response(status, headers, b"synthetic-token-canary")
        with pytest.raises(AutomationError, match=category) as exc:
            run_wire(wire, registry=registry)
        assert "synthetic-token-canary" not in str(exc.value)
        assert len(wire.calls) == 1 and wire.calls[0][1]["Authorization"] == "Bearer synthetic-token-canary"


@pytest.mark.parametrize("status", [404, 405])
def test_unsupported_referrers_has_honest_category(status):
    wire = RegistryWire()
    wire.routes[wire.referrers_path] = Response(status, {}, b"")
    with pytest.raises(AutomationError, match="registry_referrers_unavailable"):
        run_wire(wire)
    assert len(wire.calls) == 2


def test_bounds_and_duplicate_json_keys():
    wire = RegistryWire()
    with pytest.raises(AutomationError, match="registry_descriptor_invalid"):
        run_wire(wire, registry=replace(definition(), max_sbom_bytes=1))
    wire.page([wire.referrer, wire.referrer])
    with pytest.raises(AutomationError, match="registry_referrers_limit"):
        run_wire(wire, registry=replace(definition(), max_referrers=1))
    wire.routes[wire.referrers_path] = Response(200, {"content-type": client.INDEX}, b'{"schemaVersion":2,"schemaVersion":2}')
    with pytest.raises(AutomationError, match="registry_json_invalid"):
        run_wire(wire)
    expired = client.RegistryClient(definition(), transport=wire, deadline=0)
    with pytest.raises(AutomationError, match="registry_budget_exhausted"):
        expired.acquire(wire.reference)


@pytest.mark.parametrize("reference", ["registry.example/team/app:latest", "registry.example/team/app@sha256:" + "0" * 63,
                                       "other.example/team/app@sha256:" + "0" * 64, "registry.example/private/app@sha256:" + "0" * 64,
                                       "registry.example/team/../app@sha256:" + "0" * 64])
def test_reference_allowlist_before_wire(reference):
    wire = RegistryWire()
    with pytest.raises(AutomationError):
        client.RegistryClient(definition(), transport=wire).acquire(reference)
    assert not wire.calls


def configuration(tmp_path, wire, monkeypatch, *, kind="registry", allow_partial=False):
    registries = (dict(id="lab", url=URL, repositories=[REPO]),)
    source = Source("registry-a", kind=kind, allow_partial=allow_partial,
                    options=dict(registry="lab", image=wire.reference) if kind == "registry" else dict(observations="observations.json", registries=["lab"]))
    config = Config(tmp_path / "auto.toml", tmp_path / "state", tmp_path / "staging", tmp_path / "merged.json", tmp_path / "core.toml",
                    (source,), registries=registries)
    constructor = client.RegistryClient
    monkeypatch.setattr(acquire, "RegistryClient", lambda registry, **kwargs: constructor(registry, transport=wire, **kwargs))
    return config, source


def test_publish_verified_inventory_and_immutable_evidence(tmp_path, monkeypatch):
    wire = RegistryWire()
    config, source = configuration(tmp_path, wire, monkeypatch)
    result = acquire.collect_source(config, source)
    snapshot = read_snapshot(current_snapshot(config.staging_dir, source.id))
    assert snapshot.records[0]["purl"] == "pkg:pypi/example@1.0"
    evidence = Path(result["evidence_path"])
    provenance = json.loads((evidence / "provenance.json").read_bytes())
    assert evidence.name == result["generation"] == provenance["generation"]
    assert provenance["origin"] == "registry" and not provenance["attestation_verified"]
    assert (evidence / "sbom-000.json").read_bytes() == wire.sbom
    assert provenance["sbom_map"]["images"][wire.reference] == "sbom-000.json"
    assert provenance["images"][0]["sbom_digest"] == "sha256:" + digest(wire.sbom)


def test_acquisition_failure_preserves_previous_source_and_artifact_bytes(tmp_path, monkeypatch):
    wire = RegistryWire()
    config, source = configuration(tmp_path, wire, monkeypatch)
    result = acquire.collect_source(config, source)
    pointer = config.staging_dir / source.id / "current.json"
    before = pointer.read_bytes()
    wire.routes[f"/v2/{REPO}/blobs/sha256:{digest(wire.sbom)}"] = Response(200, {}, b"malicious")
    with pytest.raises(AutomationError, match="registry_digest_mismatch"):
        acquire.collect_source(config, source)
    assert pointer.read_bytes() == before
    assert (Path(result["evidence_path"]) / "sbom-000.json").read_bytes() == wire.sbom


def observations(wire, *, generated_at=None, extra=None):
    row = dict(namespace="synthetic", pod="app", pod_uid="uid-a", owner_kind="Deployment", owner="app", container="main",
               container_kind="regular", image="registry.example/team/app:latest", image_id="containerd://" + wire.reference, running=True)
    return dict(contract="cvebeacon.kubernetes-observations.v1", source_id="registry-a",
                generated_at=generated_at or datetime.now(timezone.utc).isoformat(), observations=[row] + (extra or []))


def test_kubernetes_uses_running_digest_and_preserves_observation_time(tmp_path, monkeypatch):
    wire = RegistryWire()
    config, source = configuration(tmp_path, wire, monkeypatch, kind="kubernetes")
    observed = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    document = observations(wire, generated_at=observed)
    document["observations"][0]["image"] = "registry.example/team/app@sha256:" + "0" * 64
    (tmp_path / "observations.json").write_bytes(json_bytes(document))
    acquire.collect_source(config, source)
    snapshot = read_snapshot(current_snapshot(config.staging_dir, source.id))
    assert snapshot.manifest["observed_at"] == observed
    assert len(snapshot.records) == 1
    assert all("0" * 64 not in url for url, _ in wire.calls)


def test_stale_kubernetes_input_and_bare_config_id_cannot_trigger_requests(tmp_path, monkeypatch):
    wire = RegistryWire()
    config, source = configuration(tmp_path, wire, monkeypatch, kind="kubernetes")
    old = observations(wire, generated_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat())
    (tmp_path / "observations.json").write_bytes(json_bytes(old))
    with pytest.raises(AutomationError, match="registry_observations_stale"):
        acquire.collect_source(config, source)
    fresh = observations(wire)
    fresh["observations"][0]["image_id"] = "containerd://sha256:" + "0" * 64
    (tmp_path / "observations.json").write_bytes(json_bytes(fresh))
    with pytest.raises(AutomationError, match="registry_no_eligible_images"):
        acquire.collect_source(config, source)
    assert not wire.calls


def test_running_reference_cannot_use_index_sbom():
    wire = RegistryWire(image_index=True)
    with pytest.raises(AutomationError, match="registry_running_manifest_required"):
        run_wire(wire, running=True)
    assert len(wire.calls) == 1
    assert run_wire(wire).image_media == client.INDEX


def test_partial_sbom_requires_explicit_opt_in(tmp_path, monkeypatch):
    sbom = dict(bomFormat="CycloneDX", specVersion="1.6", components=[
        dict(type="library", name="example", version="1.0", purl="pkg:pypi/example@1.0"),
        dict(type="library", name="unresolved", version="2.0")])
    wire = RegistryWire(sbom=sbom)
    config, source = configuration(tmp_path, wire, monkeypatch)
    with pytest.raises(AutomationError, match="registry_sbom_review_required"):
        acquire.collect_source(config, source)
    acquire.collect_source(config, replace(source, allow_partial=True))
    snapshot = read_snapshot(current_snapshot(config.staging_dir, source.id), allow_partial=True)
    assert snapshot.manifest["omissions"] == ["review-required"]


def test_orphan_archive_same_generation_retry_retains_first_provenance(tmp_path, monkeypatch):
    from cvebeacon_extensions import contract
    frozen = datetime.now(timezone.utc)
    monkeypatch.setattr(contract, "utc_now", lambda: frozen)
    wire = RegistryWire()
    config, source = configuration(tmp_path, wire, monkeypatch)
    real_publish = acquire.publish
    monkeypatch.setattr(acquire, "publish", lambda *a, **k: (_ for _ in ()).throw(OSError("synthetic pointer failure")))
    with pytest.raises(OSError):
        acquire.collect_source(config, source)
    archives = list((config.staging_dir / source.id / "registry-evidence").iterdir())
    assert len(archives) == 1
    archive = archives[0]
    before = {p.name: p.read_bytes() for p in archive.iterdir()}
    assert not (config.staging_dir / source.id / "current.json").exists()
    monkeypatch.setattr(acquire, "publish", real_publish)
    result = acquire.collect_source(config, source)
    assert result["generation"] == archive.name
    assert {p.name: p.read_bytes() for p in archive.iterdir()} == before
    assert read_snapshot(current_snapshot(config.staging_dir, source.id)).records[0]["version"] == "1.0"


def test_orphan_archive_corruption_cannot_be_silently_overwritten(tmp_path, monkeypatch):
    from cvebeacon_extensions import contract
    monkeypatch.setattr(contract, "utc_now", lambda: frozen)
    frozen = datetime.now(timezone.utc)
    wire = RegistryWire()
    config, source = configuration(tmp_path, wire, monkeypatch)
    real_publish = acquire.publish
    monkeypatch.setattr(acquire, "publish", lambda *a, **k: (_ for _ in ()).throw(OSError("synthetic")))
    with pytest.raises(OSError):
        acquire.collect_source(config, source)
    archive = next((config.staging_dir / source.id / "registry-evidence").iterdir())
    (archive / "sbom-000.json").write_bytes(b"corrupt")
    monkeypatch.setattr(acquire, "publish", real_publish)
    with pytest.raises(AutomationError, match="registry_evidence_conflict"):
        acquire.collect_source(config, source)
    assert (archive / "sbom-000.json").read_bytes() == b"corrupt"
    assert not (config.staging_dir / source.id / "current.json").exists()


@pytest.mark.parametrize("url", ["http://registry.example", URL + "/prefix", URL + "?", URL + "#", "https://user:secret@registry.example"])
def test_registry_origin_configuration_is_strict(url):
    with pytest.raises(AutomationError):
        client.validate_registries([dict(id="lab", url=url, repositories=[REPO])], Path("."))


def test_spdx2_reuses_frozen_importer_and_media_gate(tmp_path, monkeypatch):
    sbom = dict(spdxVersion="SPDX-2.3", packages=[dict(SPDXID="SPDXRef-package", name="example", versionInfo="1.0",
        externalRefs=[dict(referenceCategory="PACKAGE-MANAGER", referenceType="purl", referenceLocator="pkg:pypi/example@1.0")])])
    wire = RegistryWire(sbom=sbom, sbom_media="application/spdx+json")
    config, source = configuration(tmp_path, wire, monkeypatch)
    acquire.collect_source(config, source)
    assert read_snapshot(current_snapshot(config.staging_dir, source.id)).records[0]["purl"] == "pkg:pypi/example@1.0"
    mismatch = RegistryWire(sbom=sbom, sbom_media=CDX)
    with pytest.raises(AutomationError, match="registry_sbom_media_mismatch"):
        run_wire(mismatch)


def test_unmapped_kubernetes_instance_stays_explicit_partial(tmp_path, monkeypatch):
    wire = RegistryWire()
    config, source = configuration(tmp_path, wire, monkeypatch, kind="kubernetes")
    document = observations(wire)
    unmapped = dict(document["observations"][0], pod="unmapped", pod_uid="uid-b", image_id="containerd://sha256:" + "0" * 64)
    document["observations"].append(unmapped)
    (tmp_path / "observations.json").write_bytes(json_bytes(document))
    with pytest.raises(AutomationError, match="registry_sbom_review_required"):
        acquire.collect_source(config, source)
    acquire.collect_source(config, replace(source, allow_partial=True))
    snapshot = read_snapshot(current_snapshot(config.staging_dir, source.id), allow_partial=True)
    assert len(snapshot.records) == 1 and snapshot.manifest["omissions"] == ["review-required"]


def test_conflicting_pod_identity_rejected_before_registry_requests(tmp_path, monkeypatch):
    wire = RegistryWire()
    config, source = configuration(tmp_path, wire, monkeypatch, kind="kubernetes")
    document = observations(wire)
    document["observations"].append(dict(document["observations"][0], pod_uid="different-uid", container="different-container"))
    (tmp_path / "observations.json").write_bytes(json_bytes(document))
    with pytest.raises(AutomationError, match="registry_observations_invalid"):
        acquire.collect_source(config, source)
    assert not wire.calls


def test_spdx3_exact_offline_context_and_creation_info(tmp_path, monkeypatch):
    from cvebeacon_extensions.sbom import SPDX3_CONTEXT
    sbom = {"@context": SPDX3_CONTEXT, "@graph": [
        dict(spdxId="creation", type="CreationInfo", specVersion="3.0.1"),
        dict(spdxId="package", type="software_Package", creationInfo="creation", name="example",
             software_packageVersion="1.0", software_packageUrl="pkg:pypi/example@1.0")]}
    wire = RegistryWire(sbom=sbom, sbom_media="application/spdx3+json")
    config, source = configuration(tmp_path, wire, monkeypatch)
    acquire.collect_source(config, source)
    assert read_snapshot(current_snapshot(config.staging_dir, source.id)).records[0]["purl"] == "pkg:pypi/example@1.0"
    assert len(wire.calls) == 5  # The context URI never becomes an HTTP request.


def test_retained_evidence_budget_includes_provenance_before_commit(tmp_path, monkeypatch):
    wire = RegistryWire()
    config, source = configuration(tmp_path, wire, monkeypatch)
    retained = len(wire.target_raw) + len(wire.artifact_raw) + len(wire.sbom) + len(wire.empty)
    monkeypatch.setattr(acquire, "MAX_BYTES", retained + 1)
    with pytest.raises(AutomationError, match="registry_evidence_set_limit"):
        acquire.collect_source(config, source)
    assert not (config.staging_dir / source.id / "current.json").exists()
