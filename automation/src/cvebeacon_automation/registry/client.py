"""A bounded, configured-origin OCI 1.1 Referrers API subset."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import threading
import time
from urllib.parse import urljoin, urlsplit

from cvebeacon_extensions.contract import ExtensionError, decode_json
from ..common import AutomationError, Secret, digest, identifier
from ..config import keys, number, path, tables
from ..http import HTTPS, endpoint

IMAGE = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_IMAGE = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
EMPTY = "application/vnd.oci.empty.v1+json"
SBOM_TYPES = {"application/vnd.cyclonedx+json", "application/spdx+json", "application/spdx3+json"}
MANIFEST_TYPES = {IMAGE, INDEX, DOCKER_IMAGE, DOCKER_INDEX}
MAX_METADATA = 4 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
_CAPACITY = threading.BoundedSemaphore(4)


def sha256(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise AutomationError("registry_digest_invalid")
    return value


def repository(value):
    # Conservative Distribution repository subset: no escapes, tags or dot paths.
    segment = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
    if not isinstance(value, str) or len(value) > 255 or not re.fullmatch(segment + r"(?:/" + segment + r")*", value):
        raise AutomationError("registry_repository_invalid")
    return value


@dataclass(frozen=True)
class Registry:
    id: str
    url: str
    repositories: tuple[str, ...]
    bearer: Secret | None = field(default=None, repr=False)
    ca_file: object = None
    timeout_seconds: int = 15
    budget_seconds: int = 60
    max_pages: int = 16
    max_referrers: int = 128
    max_sbom_bytes: int = 8 * 1024 * 1024


def validate_registries(registries, base):
    result, seen, origins = [], set(), set()
    for entry in tables(list(registries) if isinstance(registries, tuple) else registries, 32):
        keys(entry, {"id", "url", "repositories", "bearer", "ca_file", "timeout_seconds", "budget_seconds", "max_pages", "max_referrers", "max_sbom_bytes"})
        name = identifier(entry.get("id"), "registry_id")
        url = entry.get("url")
        target = endpoint(url)
        if target.path != "/" or "?" in url or "#" in url or name.casefold() in seen or target.origin in origins:
            raise AutomationError("registry_configuration_invalid")
        seen.add(name.casefold())
        origins.add(target.origin)
        allowed = entry.get("repositories")
        if not isinstance(allowed, list) or not 1 <= len(allowed) <= 128:
            raise AutomationError("registry_allowlist_invalid")
        allowed = tuple(repository(value) for value in allowed)
        if len(set(allowed)) != len(allowed):
            raise AutomationError("registry_allowlist_invalid")
        result.append(Registry(name, url.rstrip("/"), allowed,
            Secret.parse(entry["bearer"], base) if "bearer" in entry else None,
            path(base, entry["ca_file"]) if "ca_file" in entry else None,
            number(entry.get("timeout_seconds", 15), 1, 60), number(entry.get("budget_seconds", 60), 1, 300),
            number(entry.get("max_pages", 16), 1, 32), number(entry.get("max_referrers", 128), 1, 512),
            number(entry.get("max_sbom_bytes", 8 * 1024 * 1024), 1, 32 * 1024 * 1024)))
    return tuple(result)


def image_reference(value, registry: Registry):
    if not isinstance(value, str) or len(value) > 2048 or value.count("@") != 1:
        raise AutomationError("registry_image_reference_invalid")
    name, expected = value.split("@")
    sha256(expected)
    authority, separator, repo = name.partition("/")
    if not separator or not authority or "?" in name or "#" in name:
        raise AutomationError("registry_image_reference_invalid")
    requested = endpoint("https://" + authority)
    if requested.path != "/" or requested.origin != endpoint(registry.url).origin:
        raise AutomationError("registry_image_outside_allowlist")
    repository(repo)
    if repo not in registry.repositories:
        raise AutomationError("registry_image_outside_allowlist")
    return repo, expected


def descriptor(value, *, maximum=2**63 - 1):
    if not isinstance(value, dict) or not isinstance(value.get("mediaType"), str) or len(value["mediaType"]) > 256:
        raise AutomationError("registry_descriptor_invalid")
    if "artifactType" in value and (not isinstance(value["artifactType"], str) or len(value["artifactType"]) > 256):
        raise AutomationError("registry_descriptor_invalid")
    sha256(value.get("digest"))
    if type(value.get("size")) is not int or not 0 <= value["size"] <= maximum:
        raise AutomationError("registry_descriptor_invalid")
    return value


def document(raw):
    try:
        result = decode_json(raw)
    except ExtensionError:
        raise AutomationError("registry_json_invalid") from None
    if not isinstance(result, dict) or type(result.get("schemaVersion")) is not int or result["schemaVersion"] != 2:
        raise AutomationError("registry_manifest_invalid")
    return result


def verify(raw, expected, size=None):
    if "sha256:" + digest(raw) != expected:
        raise AutomationError("registry_digest_mismatch")
    if size is not None and len(raw) != size:
        raise AutomationError("registry_size_mismatch")


def next_link(value, current, expected_path, origin):
    """Conservative Link subset: one next link, fixed origin/path, opaque query."""
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise AutomationError("registry_pagination_invalid")
    # Distribution implementations use one relative/absolute next link. Reject
    # ambiguous links and quoted commas rather than partially parsing them.
    match = re.fullmatch(r'\s*<([^<>]+)>\s*;\s*rel\s*=\s*(?:"next"|next)\s*', value)
    if not match:
        raise AutomationError("registry_pagination_invalid")
    destination = urljoin(current, match[1])
    target = endpoint(destination)
    if target.origin != origin or urlsplit(destination).path != expected_path:
        raise AutomationError("registry_pagination_outside_allowlist")
    return destination


@dataclass(frozen=True)
class Evidence:
    image: str
    image_digest: str
    image_media: str
    image_bytes: bytes = field(repr=False)
    artifact_digest: str
    artifact_bytes: bytes = field(repr=False)
    sbom_digest: str
    sbom_media: str
    sbom_bytes: bytes = field(repr=False)
    config_bytes: bytes = field(repr=False)


class RegistryClient:
    """Sequential acquisition; URLs from descriptors/challenges are never used."""

    def __init__(self, registry: Registry, *, deadline=None, transport=None):
        self.registry = registry
        self.deadline = min(time.monotonic() + registry.budget_seconds, deadline) if deadline is not None else time.monotonic() + registry.budget_seconds
        self.requests = self.bytes = 0
        try:
            self.transport = transport if transport is not None else HTTPS(registry.url, ca_file=registry.ca_file,
                timeout=registry.timeout_seconds, max_response=MAX_METADATA)
        except OSError:
            raise AutomationError("registry_tls_unavailable") from None
        self.authorization = None
        if registry.bearer is not None:
            token = registry.bearer.resolve()
            if not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token):
                raise AutomationError("registry_bearer_invalid")
            self.authorization = "Bearer " + token

    def _get(self, url, *, limit=MAX_METADATA, accept=None):
        left = self.deadline - time.monotonic()
        if left <= 0 or self.requests >= 64:
            raise AutomationError("registry_budget_exhausted")
        self.requests += 1
        self.transport.timeout = min(self.registry.timeout_seconds, left)
        self.transport.max_response = min(limit, MAX_TOTAL - self.bytes)
        headers = {"Accept": accept or "application/octet-stream"}
        if self.authorization is not None:
            headers["Authorization"] = self.authorization
        try:
            response = self.transport.request("GET", url, headers=headers)
        except AutomationError:
            raise
        except (OSError, ValueError):
            raise AutomationError("registry_connection_failed") from None
        self.bytes += len(response.body)
        if time.monotonic() > self.deadline or self.bytes > MAX_TOTAL:
            raise AutomationError("registry_budget_exhausted")
        if len(response.body) > limit:
            raise AutomationError("registry_response_limit")
        if 300 <= response.status < 400:
            raise AutomationError("registry_redirect_rejected")
        if response.status == 401:
            # Never parse/follow a response-selected token realm or scope.
            raise AutomationError("registry_authentication_required")
        if response.status != 200:
            category = "registry_referrers_unavailable" if "/referrers/" in urlsplit(url).path and response.status in {404, 405} else "registry_request_failed"
            raise AutomationError(category)
        return response

    def _manifest(self, repo, expected, *, advertised=None):
        maximum = MAX_METADATA
        if advertised is not None:
            descriptor(advertised, maximum=maximum)
        response = self._get(f"{self.registry.url}/v2/{repo}/manifests/{expected}", accept=", ".join(sorted(MANIFEST_TYPES)))
        verify(response.body, expected, advertised["size"] if advertised is not None else None)
        data = document(response.body)
        media = data.get("mediaType")
        if not isinstance(media, str) or media not in MANIFEST_TYPES or response.headers.get("content-type", "").split(";", 1)[0].strip() != media:
            raise AutomationError("registry_media_invalid")
        if advertised is not None and advertised["mediaType"] != media:
            raise AutomationError("registry_media_invalid")
        header_digest = response.headers.get("docker-content-digest")
        if header_digest is not None and header_digest != expected:
            raise AutomationError("registry_digest_mismatch")
        return data, response.body

    def _referrers(self, repo, expected):
        fixed_path = f"/v2/{repo}/referrers/{expected}"
        url, seen, descriptors = self.registry.url + fixed_path, set(), {}
        total = 0
        for page in range(self.registry.max_pages):
            if url in seen:
                raise AutomationError("registry_pagination_loop")
            seen.add(url)
            response = self._get(url, accept=INDEX)
            data = document(response.body)
            if data.get("mediaType") != INDEX or response.headers.get("content-type", "").split(";", 1)[0].strip() != INDEX:
                raise AutomationError("registry_referrers_invalid")
            items = data.get("manifests")
            if not isinstance(items, list):
                raise AutomationError("registry_referrers_invalid")
            total += len(items)
            if total > self.registry.max_referrers:
                raise AutomationError("registry_referrers_limit")
            for item in items:
                descriptor(item, maximum=MAX_METADATA)
                value = (item["mediaType"], item["size"], item.get("artifactType"))
                if item["digest"] in descriptors and descriptors[item["digest"]][0] != value:
                    raise AutomationError("registry_referrer_conflict")
                descriptors[item["digest"]] = value, item
            url = next_link(response.headers.get("link"), url, fixed_path, endpoint(self.registry.url).origin)
            if url is None:
                return [value[1] for _, value in sorted(descriptors.items())]
        raise AutomationError("registry_pagination_limit")

    def _blob(self, repo, value, *, maximum):
        descriptor(value, maximum=maximum)
        response = self._get(f"{self.registry.url}/v2/{repo}/blobs/{value['digest']}", limit=maximum)
        verify(response.body, value["digest"], value["size"])
        if response.headers.get("docker-content-digest", value["digest"]) != value["digest"]:
            raise AutomationError("registry_digest_mismatch")
        return response.body

    def acquire(self, image, *, artifact_digest=None, running=False):
        repo, expected = image_reference(image, self.registry)
        if artifact_digest is not None:
            sha256(artifact_digest)
        target, image_bytes = self._manifest(repo, expected)
        media = target["mediaType"]
        if running and media not in {IMAGE, DOCKER_IMAGE}:
            raise AutomationError("registry_running_manifest_required")
        if media in {IMAGE, DOCKER_IMAGE}:
            config = descriptor(target.get("config"))
            if config["mediaType"] not in {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"} or "artifactType" in target:
                raise AutomationError("registry_image_manifest_invalid")
            layers = target.get("layers")
            if not isinstance(layers, list) or len(layers) > 4096:
                raise AutomationError("registry_image_manifest_invalid")
            for layer in layers:
                descriptor(layer)
        else:
            manifests = target.get("manifests")
            if not isinstance(manifests, list) or not 1 <= len(manifests) <= 4096:
                raise AutomationError("registry_image_manifest_invalid")
            for item in manifests:
                descriptor(item)
        candidates = [value for value in self._referrers(repo, expected)
                      if value["mediaType"] == IMAGE and value.get("artifactType") in SBOM_TYPES]
        if artifact_digest is not None:
            candidates = [value for value in candidates if value["digest"] == artifact_digest]
        if not candidates:
            raise AutomationError("registry_sbom_missing")
        if len(candidates) != 1:
            raise AutomationError("registry_sbom_ambiguous")
        selected = candidates[0]
        artifact, artifact_bytes = self._manifest(repo, selected["digest"], advertised=selected)
        subject = descriptor(artifact.get("subject"), maximum=MAX_METADATA)
        if (subject["digest"], subject["size"], subject["mediaType"]) != (expected, len(image_bytes), media):
            raise AutomationError("registry_subject_mismatch")
        sbom_media = artifact.get("artifactType")
        if sbom_media != selected.get("artifactType") or sbom_media not in SBOM_TYPES:
            raise AutomationError("registry_media_invalid")
        config = descriptor(artifact.get("config"), maximum=2)
        if (config["mediaType"], config["digest"], config["size"]) != (EMPTY, "sha256:" + digest(b"{}"), 2):
            raise AutomationError("registry_artifact_layout_unsupported")
        layers = artifact.get("layers")
        if not isinstance(layers, list) or len(layers) != 1:
            raise AutomationError("registry_artifact_layout_unsupported")
        layer = descriptor(layers[0], maximum=self.registry.max_sbom_bytes)
        if layer["mediaType"] != sbom_media:
            raise AutomationError("registry_media_invalid")
        config_bytes = self._blob(repo, config, maximum=2)
        sbom_bytes = self._blob(repo, layer, maximum=self.registry.max_sbom_bytes)
        try:
            sbom = decode_json(sbom_bytes)
        except ExtensionError:
            raise AutomationError("registry_sbom_invalid") from None
        if (not isinstance(sbom, dict)
                or sbom_media == "application/vnd.cyclonedx+json" and sbom.get("bomFormat") != "CycloneDX"
                or sbom_media == "application/spdx+json" and "spdxVersion" not in sbom
                or sbom_media == "application/spdx3+json" and ("@context" not in sbom or "spdxVersion" in sbom)):
            raise AutomationError("registry_sbom_media_mismatch")
        return Evidence(image, expected, media, image_bytes, selected["digest"], artifact_bytes,
                        layer["digest"], sbom_media, sbom_bytes, config_bytes)
