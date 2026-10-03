"""Optional read-only Pod observation and local digest-bound SBOM enrichment."""

from __future__ import annotations

import http.client
import ipaddress
import os
from pathlib import Path
import re
import ssl
import socket
import threading
import time
from urllib.parse import urlencode

from .contract import (ExtensionError, MAX_BYTES, MAX_RECORDS, _atomic, canonical_records,
                       decode_json, json_bytes, label, read_bytes, utc_now, write_snapshot)
from .sbom import extract_sbom, objects, stable_id, text

SERVICE_ACCOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
MAX_PAGE_BYTES = 8 * 1024 * 1024


def namespace(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
        raise ExtensionError("invalid Kubernetes namespace")
    return value


def in_cluster_client():
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    try:
        address = ipaddress.ip_address(host)
        if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError()
    except ValueError as exc:
        raise ExtensionError("in-cluster API service address is unavailable or invalid") from exc
    # Kubernetes projected service-account volumes legitimately use symlinks.
    # These fixed credential paths are deployment-controlled, unlike SBOM paths.
    try:
        token = read_bytes((SERVICE_ACCOUNT / "token").resolve(), 32768).decode("ascii").strip()
    except UnicodeError as exc:
        raise ExtensionError("invalid service-account token encoding") from exc
    if not re.fullmatch(r"[A-Za-z0-9._~-]+", token):
        raise ExtensionError("invalid service-account token")
    # create_default_context honors SSLKEYLOGFILE. This credentialed collector
    # must not create TLS secret logs from inherited environment configuration.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(SERVICE_ACCOUNT / "ca.crt"))
    def get(path):
        # Direct connection to the fixed service IP: no proxy, redirect, DNS,
        # ambient auth or user URL handling. The timer interrupts slow-drip
        # headers/bodies, which a socket inactivity timeout alone cannot bound.
        connection = http.client.HTTPSConnection(str(address), int(port), timeout=15, context=context)
        timer = None
        try:
            connection.connect()
            transport = connection.sock
            def interrupt():
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(15, interrupt)
            timer.daemon = True
            timer.start()
            connection.request("GET", path, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
            response = connection.getresponse()
            if response.status != 200:
                raise ExtensionError(f"Kubernetes API request failed (HTTP {response.status})")
            data = response.read(MAX_PAGE_BYTES + 1)
            if len(data) > MAX_PAGE_BYTES:
                raise ExtensionError("Kubernetes API page exceeds size limit")
            return data
        except (OSError, http.client.HTTPException):
            raise ExtensionError("Kubernetes API connection failed") from None
        finally:
            if timer:
                timer.cancel()
            connection.close()
    return get


def list_pods(get, *, selected_namespace: str | None) -> list[dict]:
    prefix = "/api/v1/pods" if selected_namespace is None else f"/api/v1/namespaces/{namespace(selected_namespace)}/pods"
    continuation, version, total = "", None, 0
    seen_tokens = set()
    seen_uids, seen_names = set(), set()
    observations = []
    deadline = time.monotonic() + 60
    for page in range(200):
        if time.monotonic() > deadline:
            raise ExtensionError("Kubernetes collection deadline exceeded")
        query = {"limit": "500"}
        if continuation:
            query["continue"] = continuation
        raw = get(prefix + "?" + urlencode(query))
        if time.monotonic() > deadline:
            raise ExtensionError("Kubernetes collection deadline exceeded")
        total += len(raw)
        if total > MAX_BYTES:
            raise ExtensionError("Kubernetes response set exceeds size limit")
        document = decode_json(raw)
        if not isinstance(document, dict) or document.get("kind") != "PodList" or document.get("apiVersion") != "v1":
            raise ExtensionError("expected a v1 PodList")
        metadata = document.get("metadata")
        if not isinstance(metadata, dict):
            raise ExtensionError("missing PodList metadata")
        current = text(metadata.get("resourceVersion"), "resourceVersion", required=True)
        if version is not None and current != version:
            raise ExtensionError("Kubernetes pagination changed resource version")
        version = current
        # Project immediately. Full Pod responses may contain plaintext env
        # values; never retain, log or serialize unselected API fields.
        pods = objects(document.get("items"), "PodList items")
        projected = project_pods(pods, selected_namespace=selected_namespace)
        for pod in pods:
            meta = pod["metadata"]
            uid, name = meta["uid"], (meta["namespace"], meta["name"])
            if uid in seen_uids or name in seen_names:
                raise ExtensionError("duplicate Pod identity across API pages")
            seen_uids.add(uid)
            seen_names.add(name)
        observations.extend(projected)
        if len(observations) > MAX_RECORDS:
            raise ExtensionError("too many container observations")
        continuation = text(metadata.get("continue", ""), "continue")
        if not continuation:
            keys = [(row["namespace"], row["pod_uid"], row["container_kind"], row["container"]) for row in observations]
            if len(set(keys)) != len(keys):
                raise ExtensionError("duplicate container observations across API pages")
            return sorted(observations, key=lambda row: (row["namespace"], row["pod"], row["container_kind"], row["container"]))
        if continuation in seen_tokens:
            raise ExtensionError("Kubernetes pagination repeated continuation token")
        seen_tokens.add(continuation)
    raise ExtensionError("Kubernetes pagination exceeds page limit")


def project_pods(pods: list[dict], *, selected_namespace: str | None) -> list[dict]:
    result = []
    for pod in pods:
        metadata, spec, status = pod.get("metadata"), pod.get("spec"), pod.get("status", {})
        if not all(isinstance(value, dict) for value in (metadata, spec, status)):
            raise ExtensionError("malformed Pod structure")
        ns = namespace(metadata.get("namespace"))
        if selected_namespace is not None and ns != selected_namespace:
            raise ExtensionError("Pod outside selected namespace")
        name = text(metadata.get("name"), "Pod name", required=True)
        uid = text(metadata.get("uid"), "Pod UID", required=True)
        owners = objects(metadata.get("ownerReferences", []), "ownerReferences")
        owner = next((value for value in owners if value.get("controller") is True), None)
        owner_kind = text(owner.get("kind"), "owner kind") if owner else ""
        owner_name = text(owner.get("name"), "owner name") if owner else ""
        for field, statuses, kind in (("containers", "containerStatuses", "regular"),
                                      ("initContainers", "initContainerStatuses", "init"),
                                      ("ephemeralContainers", "ephemeralContainerStatuses", "ephemeral")):
            known = {}
            for state in objects(status.get(statuses, []), statuses):
                container_name = text(state.get("name"), "status container name", required=True)
                if container_name in known:
                    raise ExtensionError("duplicate container status")
                known[container_name] = state
            seen = set()
            for container in objects(spec.get(field, []), field):
                container_name = text(container.get("name"), "container name", required=True)
                if container_name in seen:
                    raise ExtensionError("duplicate container name")
                seen.add(container_name)
                state = known.get(container_name, {})
                details = state.get("state", {})
                if (not isinstance(details, dict) or len(details) > 1
                        or any(key not in {"running", "waiting", "terminated"} or not isinstance(value, dict)
                               for key, value in details.items())):
                    raise ExtensionError("ambiguous container state")
                running = "running" in details and isinstance(details["running"], dict)
                result.append(dict(namespace=ns, pod=name, pod_uid=uid, owner_kind=owner_kind, owner=owner_name,
                                   container=container_name, container_kind=kind,
                                   image=text(container.get("image"), "container image", required=True),
                                   image_id=text(state.get("imageID"), "imageID"), running=running))
    return result


def image_digest(value: str) -> str | None:
    for prefix in ("docker-pullable://", "docker://", "containerd://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", value):
        return value
    # A bare runtime sha256 may be an image config ID, not a manifest digest.
    return None


def load_sbom_map(path: Path) -> dict[str, Path]:
    document = decode_json(read_bytes(path))
    if not isinstance(document, dict) or set(document) != {"contract", "images"} or document["contract"] != "cvebeacon.image-sboms.v1":
        raise ExtensionError("invalid image/SBOM map contract")
    if not isinstance(document["images"], dict) or len(document["images"]) > MAX_RECORDS:
        raise ExtensionError("images must be a bounded object")
    result = {}
    for reference, filename in document["images"].items():
        if image_digest(reference) != reference:
            raise ExtensionError("SBOM map keys must be exact repository@sha256 digests")
        if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,190}\.json", filename):
            raise ExtensionError("SBOM map values must be plain JSON filenames in the map directory")
        result[reference] = path.parent / filename
    return result


def enrich(observations: list[dict], mapping: dict[str, Path], *, source_id: str):
    rows, reviews, cache = [], [], {}
    input_bytes = 0
    for observation in observations:
        if not observation["running"]:
            continue
        reference = image_digest(observation["image_id"])
        # Spec may name a multi-platform index while status names a platform
        # manifest, or spec may have changed before an old container stops.
        # Only the reported running image can select a supplied SBOM.
        if not reference or reference not in mapping:
            reviews.append(dict(pod=observation["pod"], namespace=observation["namespace"],
                                container=observation["container"], reason="no-exact-running-image-sbom"))
            continue
        if reference not in cache:
            raw = read_bytes(mapping[reference])
            input_bytes += len(raw)
            if input_bytes > MAX_BYTES:
                raise ExtensionError("supplied SBOM set exceeds size limit")
            cache[reference] = extract_sbom(decode_json(raw), source_id="image-template")
        instance = stable_id(source_id, json_bytes([observation["namespace"], observation["pod_uid"],
                                                   observation["container_kind"], observation["container"]]).decode())
        components, skipped = cache[reference]
        if len(rows) + len(components) > MAX_RECORDS:
            raise ExtensionError("enriched inventory exceeds record limit")
        rows.extend(dict(row, system_id=instance, asset_id=stable_id(instance, row["asset_id"])) for row in components)
        if skipped:
            reviews.append(dict(pod=observation["pod"], namespace=observation["namespace"],
                                container=observation["container"], reason="sbom-review-required", count=len(skipped)))
        if len(rows) > MAX_RECORDS:
            raise ExtensionError("enriched inventory exceeds record limit")
    return (canonical_records(rows) if rows else [], reviews)


def collect_kubernetes(output: Path, *, source_id: str, selected_namespace: str | None,
                       sbom_map: Path | None = None, observations_only: bool = False, get=None):
    label(source_id)
    if observations_only == bool(sbom_map):
        raise ExtensionError("choose either --observations-only or --sbom-map")
    mapping = load_sbom_map(sbom_map) if sbom_map else {}
    outputs = {output.resolve(), Path(str(output)+".manifest.json").resolve(), Path(str(output)+".observations.json").resolve()}
    if sbom_map and outputs & {sbom_map.resolve(), *(path.resolve() for path in mapping.values())}:
        raise ExtensionError("output must not overwrite supplied SBOM inputs")
    observations = list_pods(get or in_cluster_client(), selected_namespace=selected_namespace)
    document = dict(contract="cvebeacon.kubernetes-observations.v1", source_id=source_id,
                    generated_at=utc_now().isoformat(), observations=observations)
    if observations_only:
        projected = json_bytes(document)
        if len(projected) > MAX_BYTES:
            raise ExtensionError("observation output exceeds size limit")
        _atomic(output, projected)
        return dict(record_count=len(observations), status="observations-only")
    rows, reviews = enrich(observations, mapping, source_id=source_id)
    document["reviews"] = reviews
    projected = json_bytes(document)
    if len(projected) > MAX_BYTES:
        raise ExtensionError("observation output exceeds size limit")
    _atomic(Path(str(output)+".observations.json"), projected)
    if not rows:
        raise ExtensionError("no running containers with usable mapped SBOM identity; observations written")
    return write_snapshot(output, rows, source_id=source_id, collector="kubernetes",
                          omissions=["review-required"] if reviews else [])
