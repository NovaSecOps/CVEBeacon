"""Regression checks for the release image tag guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release_registry_check.py"


def load_guard():
    spec = importlib.util.spec_from_file_location("release_registry_guard", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def guard():
    return load_guard()


def reply(guard, status: int, body: bytes = b"", headers: dict | None = None):
    return guard.Response(status, headers or {}, body)


def fetch_from(guard, pages: dict):
    def request(request):
        try:
            return pages[request.full_url]
        except KeyError as error:
            raise AssertionError(f"unexpected URL {request.full_url}") from error

    return request


def test_highest_stable_tag_on_a_later_page_blocks_backward_latest(guard):
    base = "https://ghcr.io"
    first = f"{base}/v2/owner/image/tags/list"
    second = f"{base}/v2/owner/image/tags/list?last=1.1.0&n=2"
    pages = {
        first: reply(
            guard,
            200,
            b'{"tags": ["1.0.0", "1.1.0"]}',
            {"Link": ['</v2/owner/image/tags/list?last=1.1.0&n=2>; rel="next"']},
        ),
        second: reply(guard, 200, b'{"tags": ["1.2.0"]}'),
    }
    tags = guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages))
    assert tags == ["1.0.0", "1.1.0", "1.2.0"]
    assert guard.promote_latest("1.1.1", tags) is False
    assert guard.promote_latest("1.2.0", tags) is False
    assert guard.promote_latest("1.3.0", tags) is True


def test_absolute_next_link_is_followed(guard):
    base = "https://ghcr.io"
    first = f"{base}/v2/owner/image/tags/list"
    second = f"{base}/v2/owner/image/tags/list?last=2.0.0"
    pages = {
        first: reply(guard, 200, b'{"tags": ["2.0.0"]}', {"Link": [f'<{second}>; rel="next"']}),
        second: reply(guard, 200, b'{"tags": ["2.1.0"]}'),
    }
    assert guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages)) == [
        "2.0.0",
        "2.1.0",
    ]


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_later_page_error_stops_publishing(guard, status):
    base = "https://ghcr.io"
    first = f"{base}/v2/owner/image/tags/list"
    second = f"{base}/v2/owner/image/tags/list?last=1.0.0"
    pages = {
        first: reply(guard, 200, b'{"tags": ["1.0.0"]}', {"Link": [f'<{second}>; rel="next"']}),
        second: reply(guard, status),
    }
    with pytest.raises(guard.RegistryError, match=f"HTTP {status}"):
        guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages))


def test_later_page_404_stops_publishing(guard):
    base = "https://ghcr.io"
    first = f"{base}/v2/owner/image/tags/list"
    second = f"{base}/v2/owner/image/tags/list?last=1.0.0"
    pages = {
        first: reply(guard, 200, b'{"tags": ["1.0.0"]}', {"Link": [f'<{second}>; rel="next"']}),
        second: reply(guard, 404),
    }
    with pytest.raises(guard.RegistryError, match="404 after the first"):
        guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages))


def test_missing_package_has_no_tags(guard):
    base = "https://ghcr.io"
    pages = {f"{base}/v2/owner/image/tags/list": reply(guard, 404)}
    assert guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages)) == []


@pytest.mark.parametrize("body", [b"not json", b'{"tags": [1]}', b'{"tags": "1.0.0"}'])
def test_malformed_tag_page_stops_publishing(guard, body):
    base = "https://ghcr.io"
    pages = {f"{base}/v2/owner/image/tags/list": reply(guard, 200, body)}
    with pytest.raises(guard.RegistryError, match="malformed tags|not JSON"):
        guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages))


def test_repeated_pagination_page_stops_publishing(guard):
    base = "https://ghcr.io"
    url = f"{base}/v2/owner/image/tags/list"
    pages = {
        url: reply(guard, 200, b'{"tags": ["1.0.0"]}', {"Link": [f'<{url}>; rel="next"']}),
    }
    with pytest.raises(guard.RegistryError, match="repeated"):
        guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages))


def test_pagination_to_another_host_is_rejected(guard):
    base = "https://ghcr.io"
    url = f"{base}/v2/owner/image/tags/list"
    pages = {
        url: reply(
            guard,
            200,
            b'{"tags": ["1.0.0"]}',
            {"Link": ['<https://example.invalid/v2/owner/image/tags/list>; rel="next"']},
        ),
    }
    with pytest.raises(guard.RegistryError, match="unexpected pagination link"):
        guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages))


def test_existing_version_is_refused(guard):
    with pytest.raises(guard.RegistryError, match="already exists"):
        guard.ensure_version_absent(
            "https://ghcr.io",
            "owner/image",
            "1.0.0",
            "token",
            request=lambda request: reply(guard, 200),
        )


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_manifest_check_error_is_refused(guard, status):
    with pytest.raises(guard.RegistryError, match=f"HTTP {status}"):
        guard.ensure_version_absent(
            "https://ghcr.io",
            "owner/image",
            "1.0.0",
            "token",
            request=lambda request: reply(guard, status),
        )


def test_absent_version_is_accepted(guard):
    guard.ensure_version_absent(
        "https://ghcr.io",
        "owner/image",
        "1.0.0",
        "token",
        request=lambda request: reply(guard, 404),
    )


@pytest.mark.parametrize(
    ("version", "tags", "expected"),
    [
        ("1.0.0", [], True),
        ("1.0.0", ["1.0.0"], False),
        ("1.0.1", ["1.0.0"], True),
        ("1.10.0", ["1.9.9"], True),
        ("1", ["0.9.0"], True),
        ("1.2.0rc1", ["1.1.0"], False),
    ],
)
def test_latest_promotion_policy(guard, version, tags, expected):
    assert guard.promote_latest(version, tags) is expected


def test_tag_values_only_add_latest_when_promoted(guard):
    assert guard.tag_values("ghcr.io/owner/image", "1.0.0", False) == [
        "ghcr.io/owner/image:1.0.0"
    ]
    assert guard.tag_values("ghcr.io/owner/image", "1.0.0", True) == [
        "ghcr.io/owner/image:1.0.0",
        "ghcr.io/owner/image:latest",
    ]


@pytest.mark.parametrize("image", ["docker.io/owner/image", "ghcr.io/owner", "ghcr.io/a/b/c", "ghcr.io//image"])
def test_image_name_validation(guard, image):
    with pytest.raises(guard.RegistryError):
        guard.repository_from_image(image)


def test_main_reads_all_pages_and_writes_the_tags_output(guard, monkeypatch, tmp_path):
    base = "https://ghcr.io"
    owner = "owner"
    image = f"ghcr.io/{owner}/image"
    token_url = f"{base}/token?scope=repository:{owner}/image:pull&service=ghcr.io"
    first = f"{base}/v2/{owner}/image/tags/list"
    second = f"{first}?last=1.1.0&n=2"
    pages = {
        token_url: reply(guard, 200, b'{"token": "registry-token"}'),
        f"{base}/v2/{owner}/image/manifests/1.2.0": reply(guard, 404),
        first: reply(
            guard,
            200,
            b'{"tags": ["1.0.0", "1.1.0"]}',
            {"Link": [f'<{second}>; rel="next"']},
        ),
        second: reply(guard, 200, b'{"tags": ["1.3.0"]}'),
    }
    monkeypatch.setattr(guard, "fetch", fetch_from(guard, pages))
    output = tmp_path / "github-output"
    monkeypatch.setenv("IMAGE_NAME", image)
    monkeypatch.setenv("VERSION", "1.2.0")
    monkeypatch.setenv("GITHUB_ACTOR", "owner")
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert guard.main() == 0
    text = output.read_text()
    assert "tags<<RELEASE_TAGS" in text
    assert f"{image}:1.2.0" in text
    assert f"{image}:latest" not in text


def prepare_main(guard, monkeypatch, tmp_path, pages, version):
    base = "https://ghcr.io"
    owner = "owner"
    image = f"ghcr.io/{owner}/image"
    token_url = f"{base}/token?scope=repository:{owner}/image:pull&service=ghcr.io"
    pages.setdefault(token_url, reply(guard, 200, b'{"token": "registry-token"}'))
    pages.setdefault(f"{base}/v2/{owner}/image/manifests/{version}", reply(guard, 404))
    monkeypatch.setattr(guard, "fetch", fetch_from(guard, pages))
    output = tmp_path / "github-output"
    monkeypatch.setenv("IMAGE_NAME", image)
    monkeypatch.setenv("VERSION", version)
    monkeypatch.setenv("GITHUB_ACTOR", "owner")
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    return image, output


@pytest.mark.parametrize("body", [b"[]", b"null", b"{}", b'{"tag": []}', b'"1.0.0"'])
def test_non_object_or_missing_tags_page_stops_publishing(guard, body):
    base = "https://ghcr.io"
    pages = {f"{base}/v2/owner/image/tags/list": reply(guard, 200, body)}
    with pytest.raises(guard.RegistryError, match="object with a tags field"):
        guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages))


def test_null_tags_is_explicitly_an_empty_page(guard):
    base = "https://ghcr.io"
    pages = {f"{base}/v2/owner/image/tags/list": reply(guard, 200, b'{"tags": null}')}
    assert guard.list_tags(base, "owner/image", "token", request=fetch_from(guard, pages)) == []


def test_main_stops_on_a_malformed_later_page(guard, monkeypatch, tmp_path):
    base = "https://ghcr.io"
    first = f"{base}/v2/owner/image/tags/list"
    second = f"{first}?last=1.0.0&n=1"
    pages = {
        first: reply(
            guard,
            200,
            b'{"tags": ["1.0.0"]}',
            {"Link": [f'<{second}>; rel="next"']},
        ),
        second: reply(guard, 200, b"[]"),
    }
    _, output = prepare_main(guard, monkeypatch, tmp_path, pages, "1.1.0")
    with pytest.raises(guard.RegistryError, match="object with a tags field"):
        guard.main()
    assert not output.exists()


def test_main_refuses_a_candidate_seen_on_a_later_tag_page(guard, monkeypatch, tmp_path):
    base = "https://ghcr.io"
    first = f"{base}/v2/owner/image/tags/list"
    second = f"{first}?last=1.0.0&n=1"
    pages = {
        first: reply(
            guard,
            200,
            b'{"tags": ["1.0.0"]}',
            {"Link": [f'<{second}>; rel="next"']},
        ),
        second: reply(guard, 200, b'{"tags": ["1.1.0"]}'),
    }
    _, output = prepare_main(guard, monkeypatch, tmp_path, pages, "1.1.0")
    with pytest.raises(guard.RegistryError, match="already exists in the tag list"):
        guard.main()
    assert not output.exists()
