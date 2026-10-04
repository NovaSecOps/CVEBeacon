"""Pinned, ephemeral Distribution 3.1.2 with real TLS and OCI Referrers API.

Docker is used only to create this synthetic registry, never exposed to the
product or a generator. Client acquisition traffic is restricted to loopback.
"""

from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import time
from urllib.parse import urljoin, urlsplit
import uuid

from cvebeacon_extensions.contract import json_bytes, read_snapshot
from cvebeacon_automation.common import AutomationError, digest
from cvebeacon_automation.config import Config, Source
from cvebeacon_automation.http import HTTPS, endpoint
from cvebeacon_automation.registry.acquire import collect_source
from cvebeacon_automation.registry.client import RegistryClient, validate_registries
from cvebeacon_automation.staging import current_snapshot
from support import certificate, command, local_network_only


REGISTRY_IMAGE = "registry:3.1.2@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8"
IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
SBOM_MEDIA = "application/vnd.cyclonedx+json"
REPOSITORY = "synthetic/image"


def descriptor(media, raw):
    return {"mediaType": media, "digest": "sha256:" + digest(raw), "size": len(raw)}


class RegistryFixture:
    def __init__(self, url, cert):
        self.url, self.cert = url, cert
        self.transport = HTTPS(url, ca_file=cert, timeout=5, max_response=4 * 1024 * 1024)

    def blob(self, raw):
        reply = self.transport.request("POST", self.url + f"/v2/{REPOSITORY}/blobs/uploads/", body=b"")
        assert reply.status == 202
        destination = urljoin(self.url, reply.headers["location"])
        assert endpoint(destination).origin == endpoint(self.url).origin
        assert urlsplit(destination).path.startswith(f"/v2/{REPOSITORY}/blobs/uploads/")
        expected = "sha256:" + digest(raw)
        reply = self.transport.request("PUT", destination + ("&" if "?" in destination else "?") + "digest=" + expected,
                                       headers={"Content-Type": "application/octet-stream"}, body=raw)
        assert reply.status == 201 and reply.headers["docker-content-digest"] == expected

    def manifest(self, value):
        raw = json_bytes(value)
        expected = "sha256:" + digest(raw)
        reply = self.transport.request("PUT", self.url + f"/v2/{REPOSITORY}/manifests/{expected}",
                                       headers={"Content-Type": IMAGE_MEDIA}, body=raw)
        assert reply.status == 201 and reply.headers["docker-content-digest"] == expected
        return raw

    def image(self, label):
        config = json_bytes({"architecture": "amd64", "os": "linux", "config": {"Labels": {"synthetic": label}},
                             "rootfs": {"type": "layers", "diff_ids": []}})
        self.blob(config)
        raw = self.manifest({"schemaVersion": 2, "mediaType": IMAGE_MEDIA,
                             "config": descriptor("application/vnd.oci.image.config.v1+json", config), "layers": []})
        return raw, self.url.removeprefix("https://") + "/" + REPOSITORY + "@sha256:" + digest(raw)

    def sbom(self, target, version="1"):
        raw = json_bytes({"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
                          "components": [{"type": "library", "name": "example", "version": version,
                                          "purl": "pkg:pypi/example@" + version}]})
        self.blob(b"{}")
        self.blob(raw)
        artifact = self.manifest({"schemaVersion": 2, "mediaType": IMAGE_MEDIA, "artifactType": SBOM_MEDIA,
                                  "config": descriptor("application/vnd.oci.empty.v1+json", b"{}"),
                                  "layers": [descriptor(SBOM_MEDIA, raw)], "subject": descriptor(IMAGE_MEDIA, target)})
        return "sha256:" + digest(artifact)


@contextmanager
def distribution(root):
    cert, key = certificate(root)
    name = "cvebeacon-registry-" + uuid.uuid4().hex[:16]
    # Pull setup precedes the product network guard; this is an immutable fixture.
    command(["docker", "pull", REGISTRY_IMAGE], timeout=180)
    identifier = command(["docker", "run", "--detach", "--name", name, "--read-only", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges:true", "--publish", "127.0.0.1::5000",
                          "--mount", f"type=bind,source={root},target=/tls,readonly",
                          "--tmpfs", "/var/lib/registry:rw,nosuid,size=64m", "--tmpfs", "/tmp:rw,nosuid,size=16m",
                          "--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/tls/tls.crt", "--env", "REGISTRY_HTTP_TLS_KEY=/tls/tls.key",
                          "--env", "REGISTRY_HTTP_ADDR=0.0.0.0:5000", "--env", "REGISTRY_STORAGE_DELETE_ENABLED=false",
                          REGISTRY_IMAGE])
    assert len(identifier) == 64 and all(c in "0123456789abcdef" for c in identifier)
    try:
        port = command(["docker", "port", identifier, "5000/tcp"])
        assert port.startswith("127.0.0.1:") and port.count(":") == 1
        fixture = RegistryFixture("https://" + port, cert)
        deadline = time.monotonic() + 30
        with local_network_only():
            while True:
                try:
                    assert fixture.transport.request("GET", fixture.url + "/v2/").status == 200
                    break
                except AutomationError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
        yield fixture
    finally:
        # Exact ID returned by our create call, never a name/pattern inventory.
        command(["docker", "rm", "--force", identifier])


def main():
    if os.name != "posix" or os.environ.get("CVEBEACON_DISPOSABLE_CI") != "1":
        raise SystemExit("native registry acceptance requires explicitly isolated Linux CI")
    with tempfile.TemporaryDirectory(prefix="cvebeacon-native-registry-") as temporary:
        root = Path(temporary)
        with distribution(root) as fixture, local_network_only():
            image_raw, image = fixture.image("with-sbom")
            artifact = fixture.sbom(image_raw)
            registry = {"id": "local", "url": fixture.url, "repositories": [REPOSITORY], "ca_file": str(fixture.cert)}
            definition = validate_registries((registry,), root)[0]
            evidence = RegistryClient(definition).acquire(image)
            assert evidence.artifact_digest == artifact and evidence.image_bytes == image_raw
            source = Source("registry-image", kind="registry", options={"registry": "local", "image": image})
            config = Config(root / "auto.toml", root / "state", root / "staging", root / "merged.json", root / "core.toml", (source,),
                            registries=(registry,))
            collect_source(config, source)
            good = current_snapshot(config.staging_dir, source.id)
            snapshot = read_snapshot(good)
            assert len(snapshot.records) == 1 and snapshot.records[0]["purl"] == "pkg:pypi/example@1"
            before = good.read_bytes()
            missing_raw, missing_image = fixture.image("without-sbom")
            missing = replace(source, options={"registry": "local", "image": missing_image})
            try:
                collect_source(config, missing)
            except AutomationError as error:
                assert error.category == "registry_sbom_missing"
            else:
                raise AssertionError("missing SBOM produced inventory")
            assert current_snapshot(config.staging_dir, source.id) == good and good.read_bytes() == before
            second_artifact = fixture.sbom(image_raw, version="2")
            assert second_artifact != artifact
            try:
                RegistryClient(definition).acquire(image)
            except AutomationError as error:
                assert error.category == "registry_sbom_ambiguous"
            else:
                raise AssertionError("conflicting SBOM silently selected")
            assert RegistryClient(definition).acquire(image, artifact_digest=artifact).artifact_digest == artifact
            wrong = replace(definition, ca_file=None)
            try:
                RegistryClient(wrong).acquire(image)
            except AutomationError:
                pass
            else:
                raise AssertionError("untrusted registry TLS accepted")
    print("actual pinned Distribution3.1.2 TLS/referrers/digest/blob/importer, missing evidence preservation, ambiguity and explicit artifact pin passed")


if __name__ == "__main__":
    main()
