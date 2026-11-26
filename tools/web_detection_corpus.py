"""Download or locally check npm builds against the passive web detector.

Manifest entries contain ``package``, ``version``, ``kind`` and ``file``.
Online mode treats ``file`` as a member path in the package tarball. ``--offline``
reads ``file`` as a local path and copies the build into the caller's output
directory without opening a network connection.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath
from urllib.error import URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cvebeacon_extensions.webrules import Resource, detect, normalize_version, page_from

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_TARBALL_BYTES = 128 * 1024 * 1024
MAX_BUILD_BYTES = 16 * 1024 * 1024
REGISTRY_HOST = "registry.npmjs.org"
_PACKAGE = re.compile(r"(?:[a-z0-9][a-z0-9._~-]{0,213}|@[a-z0-9._~-]+/[a-z0-9][a-z0-9._~-]{0,213})\Z")
_PACKAGE_DETECTION_ALIASES = {"core-js-bundle": "core-js"}

# Reviewed artifacts whose shipped bundle contains another npm package.
# The filename key is exact so Bootstrap's non-bundle build does not inherit it.
_BUNDLED_INCLUSIONS = {
    ("bootstrap", "bootstrap.bundle.min.js"): frozenset({"@popperjs/core"}),
}


class _RegistryRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        parts = urlsplit(new_url)
        if parts.scheme != "https" or parts.hostname != REGISTRY_HOST or parts.username or parts.password:
            raise URLError("registry redirect left the official npm host")
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


_REGISTRY = build_opener(_RegistryRedirects())


def _bounded_read(response, limit: int) -> bytes:
    length = response.headers.get("Content-Length")
    if length is not None:
        try:
            if int(length) > limit:
                raise ValueError("download exceeds its size limit")
        except ValueError:
            raise ValueError("invalid or oversized download length") from None
    payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("download exceeds its size limit")
    return payload


def _request_bytes(url: str, limit: int) -> bytes:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != REGISTRY_HOST or parts.username or parts.password:
        raise ValueError("downloads must use the official npm registry")
    request = Request(url, headers={"User-Agent": "CVEBeacon-web-corpus/1", "Accept": "application/json, */*"})
    with _REGISTRY.open(request, timeout=30) as response:
        return _bounded_read(response, limit)


def _manifest(path: Path, *, offline: bool = False) -> list[dict]:
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds its size limit")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("manifest must be a list of at most 1,000 builds")
    checked = []
    for row in value:
        if not isinstance(row, dict):
            raise ValueError("manifest entries must be objects")
        package, version, kind, member = (row.get("package"), row.get("version"),
                                           row.get("kind"), row.get("file"))
        if not isinstance(package, str) or not _PACKAGE.fullmatch(package):
            raise ValueError("manifest contains an invalid npm package name")
        if not isinstance(version, str) or len(version) > 64 or normalize_version(version) != version:
            raise ValueError("manifest contains an invalid package version")
        if kind not in {"script", "style"}:
            raise ValueError("manifest kind must be script or style")
        if not isinstance(member, str) or not member or len(member) > 1024 or "\\" in member:
            raise ValueError("manifest contains an invalid artifact path")
        if not offline:
            relative = PurePosixPath(member.removeprefix("package/"))
            if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                raise ValueError("package artifact paths must be relative and contain no dot segments")
        checked.append({"package": package, "version": version, "kind": kind, "file": member})
    return checked


def _safe_output_name(index: int, row: dict, member_name: str) -> str:
    package = row["package"].replace("@", "scope_").replace("/", "_")
    version = re.sub(r"[^A-Za-z0-9._+-]", "_", row["version"])
    basename = re.sub(r"[^A-Za-z0-9._+-]", "_", PurePosixPath(member_name).name)
    return f"{index:04d}_{package}_{version}_{row['kind']}_{basename}"


def _local_build(row: dict, manifest_dir: Path) -> tuple[bytes, str]:
    source = Path(row["file"])
    if not source.is_absolute():
        source = manifest_dir / source
    size = source.stat().st_size
    if size > MAX_BUILD_BYTES:
        raise ValueError("local build exceeds its size limit")
    payload = source.read_bytes()
    if len(payload) > MAX_BUILD_BYTES:
        raise ValueError("local build exceeds its size limit")
    return payload, source.name


def _package_build(row: dict) -> tuple[bytes, str]:
    package_path = quote(row["package"], safe="@")
    version_path = quote(row["version"], safe="")
    metadata_url = f"https://{REGISTRY_HOST}/{package_path}/{version_path}"
    metadata = json.loads(_request_bytes(metadata_url, MAX_METADATA_BYTES).decode("utf-8"))
    if not isinstance(metadata, dict) or metadata.get("version") != row["version"]:
        raise ValueError("registry returned a different package version")
    dist = metadata.get("dist")
    archive_url = dist.get("tarball") if isinstance(dist, dict) else None
    if not isinstance(archive_url, str):
        raise ValueError("registry metadata did not include a package tarball")
    archive_bytes = _request_bytes(archive_url, MAX_TARBALL_BYTES)
    wanted = row["file"].removeprefix("package/")
    target = f"package/{wanted}"
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        member = None
        for count, item in enumerate(archive, 1):
            if count > 100_000:
                raise ValueError("package tarball contains too many entries")
            if item.name == target:
                member = item
                break
        if member is None or not member.isreg() or member.size > MAX_BUILD_BYTES:
            raise ValueError("package tarball does not contain the requested regular file")
        stream = archive.extractfile(member)
        if stream is None:
            raise ValueError("package artifact could not be read")
        payload = stream.read(MAX_BUILD_BYTES + 1)
    if len(payload) > MAX_BUILD_BYTES:
        raise ValueError("package build exceeds its size limit")
    return payload, PurePosixPath(wanted).name


def _direct_detections(detections):
    return tuple(item for item in detections
                 if not (item.implied_by and set(item.evidence_types) <= {"implied"}))


def _bundle_allowlist(row: dict) -> frozenset[str]:
    name = PurePosixPath(row["file"].removeprefix("package/")).name
    return _BUNDLED_INCLUSIONS.get((row["package"], name), frozenset())


def _check(row: dict, payload: bytes, path: Path) -> dict:
    text = payload.decode("utf-8", "replace")
    resource_url = f"https://corpus.invalid/{path.name}"
    found = _direct_detections(detect(page_from({}, "", (Resource(resource_url, row["kind"], text),))))
    expected_package = _PACKAGE_DETECTION_ALIASES.get(row["package"], row["package"])
    own = [item for item in found if item.ecosystem == "npm" and item.package == expected_package]
    expected_versions = {expected_package: row["version"]}
    expected_packages = {expected_package, *_bundle_allowlist(row)}
    unexpected = sorted({
        item.package if item.package else f"{item.vendor}/{item.product}"
        for item in found
        if (item.package if item.ecosystem == "npm" else f"{item.vendor}/{item.product}")
        not in expected_packages
    })
    wrong_versions = []
    if not own or not any(row["version"] in item.versions for item in own):
        wrong_versions.append(f"{expected_package}@{row['version']}")
    for item in found:
        if item.package in expected_versions and row["version"] not in item.versions:
            if item.package not in wrong_versions:
                wrong_versions.append(f"{item.package}@{','.join(item.versions) or 'no-version'}")
    status = "OK" if own and not wrong_versions and not unexpected else "FAIL"
    labels = sorted({f"{item.package or item.vendor + '/' + item.product}@{','.join(item.versions) or 'no-version'}"
                     for item in found})
    return {"package": row["package"], "version": row["version"], "found": labels,
            "unexpected": unexpected, "wrong_versions": wrong_versions, "status": status}


def run(manifest: Path, destination: Path, *, offline: bool = False) -> tuple[dict, ...]:
    rows = _manifest(manifest, offline=offline)
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    for index, row in enumerate(rows, 1):
        payload, member_name = (_local_build(row, manifest.parent) if offline else _package_build(row))
        target = destination / _safe_output_name(index, row, member_name)
        target.write_bytes(payload)
        results.append(_check(row, payload, target))
    return tuple(results)


def _print(results: tuple[dict, ...]) -> None:
    print(f"{'BUILD':46} {'DETECTED':54} {'EXTRA':24} STATUS")
    for item in results:
        build = f"{item['package']}@{item['version']}"
        detected = ", ".join(item["found"]) or "(none)"
        extra = ", ".join(item["unexpected"]) or "-"
        print(f"{build[:46]:46} {detected[:54]:54} {extra[:24]:24} {item['status']}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="JSON list of package builds")
    parser.add_argument("directory", type=Path, help="caller-selected directory for copied builds")
    parser.add_argument("--offline", action="store_true",
                        help="read local file paths from the manifest without network access")
    args = parser.parse_args(argv)
    try:
        results = run(args.manifest, args.directory, offline=args.offline)
    except (OSError, ValueError, URLError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"web corpus check failed: {exc}", file=sys.stderr)
        return 2
    _print(results)
    passed = sum(item["status"] == "OK" for item in results)
    print(f"\n{passed} correct, {len(results) - passed} failed of {len(results)} builds")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
