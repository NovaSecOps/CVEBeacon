"""Decide GHCR image tags for a release without overwriting a version tag.

The script reads the registry tag pages, refuses an existing version, and only
selects ``latest`` when the release is the highest stable numeric version. Every
tag page is read before the decision; a page error stops publishing.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

STABLE_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
NEXT_LINK = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
MAX_PAGES = 100
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


class RegistryError(RuntimeError):
    """A registry response that must stop publishing."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, Sequence[str]]
    body: bytes


def fetch(request: Request) -> Response:
    """Return an HTTP response, including error statuses, and fail on transport errors."""
    try:
        with urlopen(request, timeout=30) as response:
            return Response(response.status, response.headers, response.read())
    except HTTPError as error:
        return Response(error.code, error.headers, error.read())
    except URLError as error:
        raise RegistryError(f"registry request failed: {error.reason}") from error


def header_values(headers: Mapping[str, Sequence[str]], name: str) -> list[str]:
    get_all = getattr(headers, "get_all", None)
    if get_all is not None:
        return list(get_all(name) or [])
    values: list[str] = []
    for key, value in headers.items():
        if key.lower() == name.lower():
            values.extend(value if isinstance(value, (list, tuple)) else [value])
    return values


def registry_token(
    base: str,
    repository: str,
    actor: str,
    token: str,
    *,
    request: Callable[[Request], Response] | None = None,
) -> str:
    send = request or fetch
    encoded = base64.b64encode(f"{actor}:{token}".encode("utf-8")).decode("ascii")
    scope = quote(repository, safe="/")
    url = f"{base}/token?scope=repository:{scope}:pull&service=ghcr.io"
    response = send(Request(url, headers={"Authorization": f"Basic {encoded}"}))
    if response.status != 200:
        raise RegistryError(f"registry token request returned HTTP {response.status}")
    try:
        document = json.loads(response.body)
    except ValueError as error:
        raise RegistryError("registry token response was not JSON") from error
    value = document.get("token") if isinstance(document, dict) else None
    if not isinstance(value, str) or not value:
        raise RegistryError("registry token response did not include a token")
    return value


def ensure_version_absent(
    base: str,
    repository: str,
    version: str,
    token: str,
    *,
    request: Callable[[Request], Response] | None = None,
) -> None:
    send = request or fetch
    url = f"{base}/v2/{repository}/manifests/{quote(version, safe='')}"
    response = send(
        Request(url, headers={"Authorization": f"Bearer {token}", "Accept": MANIFEST_ACCEPT})
    )
    if response.status == 200:
        raise RegistryError(
            f"{base}/{repository}:{version} already exists; refusing to overwrite an immutable version tag"
        )
    if response.status != 404:
        raise RegistryError(
            f"manifest check returned HTTP {response.status}; refusing to publish"
        )


def next_page_url(
    headers: Mapping[str, Sequence[str]], base: str, repository: str
) -> str | None:
    page = f"{base}/v2/{repository}/tags/list"
    for value in header_values(headers, "Link"):
        match = NEXT_LINK.search(value)
        if match is None:
            continue
        url = match.group(1)
        if url.startswith("/"):
            url = base + url
        if url != page and not url.startswith(page + "?"):
            raise RegistryError(f"unexpected pagination link: {url}")
        return url
    return None


def list_tags(
    base: str,
    repository: str,
    token: str,
    *,
    request: Callable[[Request], Response] | None = None,
) -> list[str]:
    send = request or fetch
    url = f"{base}/v2/{repository}/tags/list"
    seen: set[str] = set()
    tags: list[str] = []
    for _ in range(MAX_PAGES):
        if url in seen:
            raise RegistryError("registry pagination repeated a page")
        seen.add(url)
        response = send(Request(url, headers={"Authorization": f"Bearer {token}"}))
        if response.status == 404:
            if len(seen) != 1:
                raise RegistryError("registry returned 404 after the first tag page")
            return []
        if response.status != 200:
            raise RegistryError(f"tag listing returned HTTP {response.status}")
        try:
            document = json.loads(response.body)
        except ValueError as error:
            raise RegistryError("tag listing response was not JSON") from error
        page = document.get("tags") if isinstance(document, dict) else None
        if page is None:
            page = []
        if not isinstance(page, list) or not all(isinstance(tag, str) for tag in page):
            raise RegistryError("tag listing response had malformed tags")
        tags.extend(page)
        following = next_page_url(response.headers, base, repository)
        if following is None:
            return tags
        url = following
    raise RegistryError(f"tag listing exceeded {MAX_PAGES} pages")


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def stable_tags(tags: Sequence[str]) -> list[str]:
    return [tag for tag in tags if STABLE_VERSION.fullmatch(tag) is not None]


def promote_latest(version: str, tags: Sequence[str]) -> bool:
    if STABLE_VERSION.fullmatch(version) is None:
        return False
    stable = stable_tags(tags)
    if not stable:
        return True
    return version_key(version) > max(version_key(tag) for tag in stable)


def tag_values(image: str, version: str, promote: bool) -> list[str]:
    values = [f"{image}:{version}"]
    if promote:
        values.append(f"{image}:latest")
    return values


def repository_from_image(image: str) -> str:
    prefix = "ghcr.io/"
    if not image.startswith(prefix):
        raise RegistryError("IMAGE_NAME must use the ghcr.io registry")
    repository = image[len(prefix):]
    parts = repository.split("/")
    if len(parts) != 2 or not all(parts):
        raise RegistryError("IMAGE_NAME must be ghcr.io/<owner>/<package>")
    return repository


def main() -> int:
    image = os.environ.get("IMAGE_NAME", "").strip()
    version = os.environ.get("VERSION", "").strip()
    actor = os.environ.get("GITHUB_ACTOR", "").strip()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    output = os.environ.get("GITHUB_OUTPUT", "").strip()
    base = os.environ.get("REGISTRY_BASE", "https://ghcr.io").rstrip("/")
    if not version or not actor or not token or not output:
        raise RegistryError(
            "IMAGE_NAME, VERSION, GITHUB_ACTOR, GITHUB_TOKEN and GITHUB_OUTPUT are required"
        )
    repository = repository_from_image(image)
    registry = registry_token(base, repository, actor, token)
    ensure_version_absent(base, repository, version, registry)
    tags = list_tags(base, repository, registry)
    promote = promote_latest(version, tags)
    stable = stable_tags(tags)
    highest = max(stable, key=version_key) if stable else "none"
    values = tag_values(image, version, promote)
    print(f"Highest stable tag: {highest}; promote latest: {str(promote).lower()}")
    with open(output, "a", encoding="utf-8") as handle:
        handle.write("tags<<RELEASE_TAGS\n")
        handle.write("\n".join(values))
        handle.write("\nRELEASE_TAGS\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RegistryError as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1) from error
