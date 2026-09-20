from dataclasses import replace
import json

import httpx
import pytest

from cvebeacon.config import HttpConfig
from cvebeacon.http import HttpClient
from cvebeacon.identity import normalize_asset
from cvebeacon.models import Asset, Applicability as A
from cvebeacon.osv_applicability import compare, evaluate_osv, range_state
from cvebeacon.sources.osv import OSVSource, query_identity


def record(ecosystem="PyPI", name="example", kind="ECOSYSTEM", events=None, **extra):
    return {"id": "TEST-2026-123", "modified": "2026-09-20T00:00:00Z", "aliases": ["CVE-2026-1234"],
            "affected": [{"package": {"ecosystem": ecosystem, "name": name}, "ranges": [
                {"type": kind, "events": events or [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}], **extra}


@pytest.mark.parametrize("ecosystem,kind,version,state", [
    ("PyPI", "ECOSYSTEM", "1.9.post1", A.AFFECTED),
    ("PyPI", "ECOSYSTEM", "2.0.0rc1", A.AFFECTED),
    ("PyPI", "ECOSYSTEM", "2.0.0", A.NOT_AFFECTED),
    ("npm", "SEMVER", "2.0.0-beta.1", A.AFFECTED),
    ("npm", "SEMVER", "2.0.0+build.2", A.NOT_AFFECTED),
    ("npm", "SEMVER", "2", A.NEEDS_REVIEW),
    ("Go", "SEMVER", "v1.9.0", A.AFFECTED),
    ("Go", "SEMVER", "v2.0.0", A.NOT_AFFECTED),
    ("crates.io", "SEMVER", "1.9.0", A.AFFECTED),
    ("crates.io", "SEMVER", "2.0.0", A.NOT_AFFECTED),
    ("Maven", "ECOSYSTEM", "2.0.0-SNAPSHOT", A.AFFECTED),
    ("Maven", "ECOSYSTEM", "2.0.0.Final", A.NOT_AFFECTED),
    ("NuGet", "ECOSYSTEM", "1.9.0.1", A.AFFECTED),
    ("NuGet", "ECOSYSTEM", "2.0.0.0", A.NOT_AFFECTED),
    ("Unsupported", "ECOSYSTEM", "2.1.0", A.NEEDS_REVIEW),
    ("PyPI", "ECOSYSTEM", "unknown", A.NEEDS_REVIEW),
])
def test_ecosystem_semantics(ecosystem, kind, version, state):
    asset = Asset("a", ecosystem=ecosystem, product="example", version=version)
    assert evaluate_osv(asset, record(ecosystem, kind=kind)).state == state


@pytest.mark.parametrize("ecosystem,lower,fixed", [("Debian:12", "1:1.0-1~deb12u1", "1:1.0-1"),
    ("AlmaLinux:9", "1:2.0-1.el9", "1:2.0-2.el9")])
def test_distro_epoch_and_revision(ecosystem, lower, fixed):
    value = record(ecosystem, events=[{"introduced": "0"}, {"fixed": fixed}])
    assert evaluate_osv(Asset("a", ecosystem=ecosystem, product="example", version=lower), value).state == A.AFFECTED
    assert evaluate_osv(Asset("a", ecosystem=ecosystem, product="example", version=fixed), value).state == A.NOT_AFFECTED


@pytest.mark.parametrize("events,version,expected", [
    ([{"introduced": "1.0.0"}, {"fixed": "2.0.0"}, {"introduced": "3.0.0"}], "2.5.0", False),
    ([{"introduced": "0"}, {"last_affected": "2.0.0"}], "2.0.0", True),
    ([{"introduced": "0"}, {"last_affected": "2.0.0"}], "2.0.1", False),
    ([{"introduced": "0"}, {"limit": "2.0.0"}], "2.0.0", False),
    ([{"introduced": "0"}, {"limit": "2.0.0"}, {"limit": "3.0.0"}], "2.5.0", True),
    ([{"fixed": "2.0.0"}, {"introduced": "0"}], "1.0.0", True),
    ([{"introduced": "0"}, {"limit": "*"}], "9.0.0", True),
    ([{"introduced": "1.0.0", "fixed": "2.0.0"}], "3.0.0", None),
    ([{"fixed": "2.0.0"}], "3.0.0", None),
    ([{"introduced": "0"}, {"fixed": "2.0.0"}, {"last_affected": "3.0.0"}], "4.0.0", None),
    ([{"introduced": "1.0.0"}, {"fixed": "1.0.0"}], "4.0.0", None),
    ([{"introduced": "1.0.0"}, {"fixed": "1.0.0"}, {"limit": "2.0.0"}], "4.0.0", None),
    ([{"introduced": "0"}, {"fixed": "bad-version"}], "4.0.0", None),
])
def test_osv_boundaries_and_malformed_events(events, version, expected):
    assert range_state(version, {"type": "SEMVER", "events": events}, "npm") is expected


def test_explicit_versions_and_unsupported_range_cannot_exclude():
    value = record("Custom")
    value["affected"][0]["versions"] = ["release-a"]
    asset = Asset("a", ecosystem="Custom", product="example", version="release-a")
    assert evaluate_osv(asset, value).state == A.AFFECTED
    assert evaluate_osv(replace(asset, version="release-b"), value).state == A.NEEDS_REVIEW
    value["affected"][0]["ranges"] = []
    assert evaluate_osv(replace(asset, version="release-b"), value).state == A.NEEDS_REVIEW


def test_identity_mismatch_and_withdrawal():
    asset = Asset("a", ecosystem="npm", product="Example", version="1.0.0")
    assert evaluate_osv(asset, record("npm", name="example", kind="SEMVER")).state == A.COVERAGE_UNKNOWN
    assert evaluate_osv(asset, record("PyPI", name="Example")).state == A.COVERAGE_UNKNOWN
    assert evaluate_osv(asset, record("npm", name="Example", withdrawn="2026-09-20T00:00:00Z")).state == A.NEEDS_REVIEW


def test_nuget_lookup_preserves_registry_case_but_comparison_is_insensitive():
    asset = Asset("a", ecosystem="NuGet", product="Newtonsoft.Json", version="1.0.0")
    assert query_identity(asset) == {"package": {"ecosystem": "NuGet", "name": "Newtonsoft.Json"}}
    assert evaluate_osv(asset, record("NuGet", name="newtonsoft.json")).state == A.AFFECTED


def test_exact_commit_requires_query_and_repository_evidence():
    asset = Asset("a", repository="https://example.invalid/repo", commit="a" * 40)
    value = record()
    value["affected"][0]["ranges"] = [{"type": "GIT", "repo": asset.repository, "events": [{"introduced": "b" * 40}]}]
    assert evaluate_osv(asset, value, commit_match=True).state == A.AFFECTED
    assert evaluate_osv(asset, value).state == A.COVERAGE_UNKNOWN
    assert evaluate_osv(replace(asset, repository="https://example.invalid/different"), value, commit_match=True).state == A.COVERAGE_UNKNOWN


def test_purl_qualifiers_preserved_locally_never_sent():
    asset = normalize_asset(Asset("private-asset", purl="pkg:pypi/example@1?repository_url=https://internal.invalid/repo#private/path"))
    assert query_identity(asset) is None
    assert evaluate_osv(asset, record()).state == A.COVERAGE_UNKNOWN
    assert "internal.invalid" in asset.purl


def transport(handler):
    return HttpClient(HttpConfig(retries=0), client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_batch_pagination_and_request_minimization():
    assets = [normalize_asset(Asset("internal-id", ecosystem="PyPI", product="Example", version="1.0", category="secret-team", system_id="internal-host")),
              normalize_asset(Asset("other-id", purl="pkg:npm/Other@2.0.0"))]
    requests = []
    def handler(request):
        requests.append(request)
        if request.method == "POST":
            body = json.loads(request.content)
            if "page_token" not in body["queries"][0]:
                assert body == {"queries": [{"package": {"ecosystem": "PyPI", "name": "example"}}, {"package": {"purl": "pkg:npm/Other"}}]}
                return httpx.Response(200, json={"results": [{"vulns": [{"id": "TEST-2026-123"}], "next_page_token": "next"}, {}]})
            assert body == {"queries": [{"package": {"ecosystem": "PyPI", "name": "example"}, "page_token": "next"}]}
            return httpx.Response(200, json={"results": [{}]})
        return httpx.Response(200, json=record())
    results = OSVSource(transport(handler)).query_many(assets)
    assert len(results[assets[0].target_key].records) == 1
    assert not results[assets[1].target_key].records
    assert all(result.error is None for result in results.values())
    outbound = " ".join(str(r.url) + r.content.decode() + str(dict(r.headers)) for r in requests)
    for private in ("internal-id", "other-id", "secret-team", "internal-host"):
        assert private not in outbound
    assert all("authorization" not in r.headers and "apikey" not in r.headers for r in requests)


@pytest.mark.parametrize("payload", [{}, {"results": []}, {"results": [None]}, {"results": [{"vulns": None}]},
    {"results": [{"error": "failed"}]}, {"results": [{"next_page_token": 1}]}])
def test_bad_batch_is_failure_not_empty(payload):
    asset = Asset("a", ecosystem="PyPI", product="example", version="1")
    result = OSVSource(transport(lambda _: httpx.Response(200, json=payload))).query_many([asset])[asset.target_key]
    assert result.error


def test_partial_record_failure_retains_success_and_flags_degradation():
    asset = Asset("a", ecosystem="PyPI", product="example", version="1")
    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "TEST-2026-123"}, {"id": "TEST-2026-124"}]}]})
        return httpx.Response(200, json=record()) if request.url.path.endswith("123") else httpx.Response(503)
    result = OSVSource(transport(handler)).query_many([asset])[asset.target_key]
    assert result.error and len(result.records) == 1


def test_repeated_page_token_is_bounded_failure():
    asset = Asset("a", ecosystem="PyPI", product="example", version="1")
    calls = []
    def handler(_):
        calls.append(1)
        return httpx.Response(200, json={"results": [{"next_page_token": "same"}]})
    result = OSVSource(transport(handler)).query_many([asset])[asset.target_key]
    assert result.error and len(calls) == 2
