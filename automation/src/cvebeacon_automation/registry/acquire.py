"""Validated registry evidence to frozen SBOM/running-image enrichment contracts."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import time

from cvebeacon_extensions.contract import (ExtensionError, MAX_BYTES, MAX_RECORDS, decode_json, json_bytes,
                                           manifest_path, read_bytes, read_snapshot, timestamp, write_snapshot)
from cvebeacon_extensions.kubernetes import enrich, image_digest, namespace
from cvebeacon_extensions.sbom import extract_sbom, text

from ..common import AutomationError, atomic, digest, directory, now
from ..config import keys, path
from ..staging import publish, source_directory
from .client import RegistryClient, _CAPACITY, image_reference, sha256, validate_registries


def validate_source(source, registries):
    definitions = validate_registries(registries, Path("."))
    by_id = {value.id: value for value in definitions}
    options = source.options
    if source.kind == "registry":
        keys(options, {"registry", "image", "artifact_digest"})
        name = options.get("registry")
        if not isinstance(name, str) or name not in by_id:
            raise AutomationError("registry_source_invalid")
        image_reference(options.get("image"), by_id[name])
        if "artifact_digest" in options:
            sha256(options["artifact_digest"])
    elif source.kind == "kubernetes":
        keys(options, {"observations", "registries", "artifact_digests"})
        if not isinstance(options.get("observations"), str) or not options["observations"] or len(options["observations"]) > 4096 or "\x00" in options["observations"]:
            raise AutomationError("registry_observations_path_invalid")
        selected = options.get("registries")
        if (not isinstance(selected, list) or not 1 <= len(selected) <= 32
                or any(not isinstance(name, str) or name not in by_id for name in selected) or len(set(selected)) != len(selected)):
            raise AutomationError("registry_source_invalid")
        pins = options.get("artifact_digests", {})
        if not isinstance(pins, dict) or len(pins) > 64:
            raise AutomationError("registry_artifact_pins_invalid")
        for reference, expected in pins.items():
            _select(reference, [by_id[name] for name in selected], required=True)
            sha256(expected)
    else:
        raise AutomationError("registry_source_invalid")


def _select(reference, registries, *, required=False):
    matches = []
    for registry in registries:
        try:
            image_reference(reference, registry)
        except AutomationError:
            continue
        matches.append(registry)
    if len(matches) == 1:
        return matches[0]
    if required:
        raise AutomationError("registry_image_outside_allowlist")
    return None


def _observations(filename, source):
    raw = read_bytes(filename)
    data = decode_json(raw)
    if (not isinstance(data, dict) or set(data) != {"contract", "source_id", "generated_at", "observations"}
            or data["contract"] != "cvebeacon.kubernetes-observations.v1" or data["source_id"] != source.id):
        raise AutomationError("registry_observations_invalid")
    observed = timestamp(data["generated_at"])
    current = datetime.now(timezone.utc)
    if observed > current or (current - observed).total_seconds() > source.max_age_seconds:
        raise AutomationError("registry_observations_stale")
    rows = data["observations"]
    fields = {"namespace", "pod", "pod_uid", "owner_kind", "owner", "container", "container_kind", "image", "image_id", "running"}
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise AutomationError("registry_observations_invalid")
    seen, pod_names, pod_uids = set(), {}, {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields or type(row["running"]) is not bool:
            raise AutomationError("registry_observations_invalid")
        namespace(row["namespace"])
        for field in fields - {"running", "namespace"}:
            text(row[field], field, required=field in {"pod", "pod_uid", "container", "container_kind", "image"})
        if row["container_kind"] not in {"regular", "init", "ephemeral"}:
            raise AutomationError("registry_observations_invalid")
        key = row["namespace"], row["pod_uid"], row["container_kind"], row["container"]
        name = row["namespace"], row["pod"]
        if (key in seen or row["pod_uid"] in pod_uids and pod_uids[row["pod_uid"]] != name
                or name in pod_names and pod_names[name] != row["pod_uid"]):
            raise AutomationError("registry_observations_invalid")
        seen.add(key)
        pod_names[name], pod_uids[row["pod_uid"]] = row["pod_uid"], name
    return rows, data["generated_at"], raw


def _media_format(evidence):
    return "cyclonedx" if evidence.sbom_media == "application/vnd.cyclonedx+json" else "spdx"


def _save_evidence(folder, generation, evidences, provenance, observation_bytes=None):
    archive = directory(folder / "registry-evidence")
    final = archive / generation
    files = {}
    for index, evidence in enumerate(evidences):
        for prefix, raw in (("image", evidence.image_bytes), ("artifact", evidence.artifact_bytes),
                            ("sbom", evidence.sbom_bytes), ("config", evidence.config_bytes)):
            files[f"{prefix}-{index:03}.json"] = raw
    if observation_bytes is not None:
        files["observations.json"] = observation_bytes
    provenance_bytes = json_bytes(provenance)
    if sum(map(len, files.values())) + len(provenance_bytes) > MAX_BYTES:
        raise AutomationError("registry_evidence_set_limit")

    def existing():
        # A crash after archive rename but before pointer publication leaves a
        # complete unreferenced archive. Reuse only identical verified bytes and
        # metadata, retaining the first acquisition time rather than rewriting it.
        directory(final)
        if {child.name for child in final.iterdir()} != set(files) | {"provenance.json"}:
            raise AutomationError("registry_evidence_conflict")
        for name, raw in files.items():
            if read_bytes(final / name) != raw:
                raise AutomationError("registry_evidence_conflict")
        previous = decode_json(read_bytes(final / "provenance.json"))
        if not isinstance(previous, dict):
            raise AutomationError("registry_evidence_conflict")
        acquired = timestamp(previous.get("acquired_at"))
        if acquired > datetime.now(timezone.utc):
            raise AutomationError("registry_evidence_conflict")
        expected = dict(provenance, acquired_at=previous.get("acquired_at"))
        if previous != expected:
            raise AutomationError("registry_evidence_conflict")
        return final

    if final.exists() or final.is_symlink():
        return existing()
    with tempfile.TemporaryDirectory(prefix=".registry-evidence-", dir=archive) as temporary:
        pending = Path(temporary)
        for name, raw in files.items():
            atomic(pending / name, raw)
        atomic(pending / "provenance.json", provenance_bytes)
        try:
            os.rename(pending, final)
        except OSError:
            if final.exists():
                return existing()
            raise
        if os.name == "posix":
            descriptor = os.open(archive, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    return existing()


def collect_source(config, source):
    """Commit only fully verified evidence; any acquisition failure preserves pointer."""
    validate_source(source, config.registries)
    definitions = validate_registries(config.registries, config.config_path.parent)
    by_id = {value.id: value for value in definitions}
    if source.kind == "registry":
        selected = [by_id[source.options["registry"]]]
        requested = [(source.options["image"], source.options.get("artifact_digest"), selected[0])]
        observations = observation_bytes = None
        observed_at = None
    else:
        selected = [by_id[name] for name in source.options["registries"]]
        observations, observed_at, observation_bytes = _observations(path(config.config_path.parent, source.options["observations"]), source)
        references = {image_digest(row["image_id"]) for row in observations if row["running"]}
        references.discard(None)
        requested = []
        for reference in sorted(references):
            registry = _select(reference, selected)
            if registry is not None:
                requested.append((reference, source.options.get("artifact_digests", {}).get(reference), registry))
    if not requested:
        raise AutomationError("registry_no_eligible_images")
    if len(requested) > 64:
        raise AutomationError("registry_image_limit")
    if not _CAPACITY.acquire(blocking=False):
        raise AutomationError("registry_capacity_exhausted")
    try:
        deadline = time.monotonic() + max(registry.budget_seconds for registry in selected)
        clients, evidences, reviews = {}, [], []
        retained = len(observation_bytes or b"")
        folder = source_directory(config.staging_dir, source.id)
        with tempfile.TemporaryDirectory(prefix=".registry-collect-", dir=folder) as temporary:
            scratch = Path(temporary)
            mapping = {}
            image_map = {}
            for index, (reference, pin, registry) in enumerate(requested):
                if registry.id not in clients:
                    clients[registry.id] = RegistryClient(registry, deadline=deadline)
                evidence = clients[registry.id].acquire(reference, artifact_digest=pin, running=source.kind == "kubernetes")
                retained += sum(len(raw) for raw in (evidence.image_bytes, evidence.artifact_bytes, evidence.sbom_bytes, evidence.config_bytes))
                if retained > MAX_BYTES:
                    raise AutomationError("registry_evidence_set_limit")
                # Frozen importer validates identity, supported format/version,
                # component limits and conflicts before any source publication.
                components, skipped = extract_sbom(decode_json(evidence.sbom_bytes), source_id=source.id, format=_media_format(evidence))
                if not components:
                    raise AutomationError("registry_sbom_no_usable_components")
                if observations is None:
                    rows, reviews = components, skipped
                filename = f"sbom-{index:03}.json"
                atomic(scratch / filename, evidence.sbom_bytes)
                mapping[reference] = scratch / filename
                image_map[reference] = filename
                evidences.append(evidence)
            if observations is not None:
                rows, reviews = enrich(observations, mapping, source_id=source.id)
            if not rows:
                raise AutomationError("registry_sbom_no_usable_components")
            if reviews and not source.allow_partial:
                raise AutomationError("registry_sbom_review_required")
            if time.monotonic() > deadline:
                raise AutomationError("registry_budget_exhausted")
            candidate = scratch / "inventory.json"
            write_snapshot(candidate, rows, source_id=source.id, collector="registry" if observations is None else "kubernetes-registry",
                           observed_at=observed_at, omissions=["review-required"] if reviews else [])
            read_snapshot(candidate, max_age_seconds=source.max_age_seconds, allow_partial=source.allow_partial)
            raw, side = read_bytes(candidate), read_bytes(manifest_path(candidate), 65536)
            generation = digest(raw + b"\x00" + side)
            provenance = dict(contract="cvebeacon.registry-evidence.v1", source_id=source.id, generation=generation,
                              acquired_at=now(), origin="registry", integrity="sha256-and-subject", attestation_verified=False,
                              images=[dict(image=evidence.image, image_digest=evidence.image_digest, image_media=evidence.image_media,
                                           artifact_digest=evidence.artifact_digest, sbom_digest=evidence.sbom_digest,
                                           sbom_media=evidence.sbom_media, image_file=f"image-{index:03}.json",
                                           artifact_file=f"artifact-{index:03}.json", sbom_file=f"sbom-{index:03}.json",
                                           config_file=f"config-{index:03}.json") for index, evidence in enumerate(evidences)], reviews=reviews,
                              sbom_map=dict(contract="cvebeacon.image-sboms.v1", images=image_map))
            evidence_path = _save_evidence(folder, generation, evidences, provenance, observation_bytes)
            if time.monotonic() > deadline:
                raise AutomationError("registry_budget_exhausted")
            result = publish(config.staging_dir, source.id, raw, side, max_age_seconds=source.max_age_seconds)
            return dict(result, source_id=source.id, evidence_generation=generation, evidence_path=str(evidence_path), images=len(evidences))
    finally:
        _CAPACITY.release()
