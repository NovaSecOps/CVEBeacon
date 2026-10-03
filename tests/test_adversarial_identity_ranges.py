"""Specification boundaries and unsafe normalization must never imply exclusion."""

import pytest

from cvebeacon.identity import normalize_asset, parse_purl, purl_string
from cvebeacon.models import Asset, Applicability as A
from cvebeacon.osv_applicability import compare, evaluate_osv, range_state


@pytest.mark.parametrize("raw", [
    "pkg:pypi/example@1#..", "pkg:pypi/example@1#src/./main",
    "pkg:pypi/example@1#%2e%2e", "pkg:pypi/example@1#src%2Fmain",
    "pkg:npm/foo@1?arch=x86&arch=arm", "pkg:npm/foo@1?arch=x86&ARCH=arm",
    "pkg:maven/org%2Fother/name@1",
])
def test_invalid_purl_components_are_not_silently_removed(raw):
    with pytest.raises(ValueError):
        normalize_asset(Asset("a", purl=raw))


@pytest.mark.parametrize("raw", [
    "pkg:generic/name%2Fother@1", "pkg:generic/name%252Fother@1",
    "pkg:npm/OldPackage@1?repository_url=https%3A%2F%2Fexample.invalid%2Fa#src/main",
    "pkg:maven/org.Example/Name@1%2Bmeta?classifier=sources&type=jar",
    "pkg:generic/%E2%98%83@rev%2Fone", "pkg:generic/name%3Fother@v%40one",
])
def test_purl_roundtrip_preserves_decoded_identity(raw):
    first = parse_purl(raw)
    second = parse_purl(purl_string(first))
    assert (first.type, first.namespace, first.name, first.version, first.qualifiers, first.subpath) == (
        second.type, second.namespace, second.name, second.version, second.qualifiers, second.subpath)


def osv_record(ecosystem, name, events, *, versions=()):
    return {"id": "TEST-2026-1234", "modified": "2026-10-03T00:00:00Z", "affected": [
        {"package": {"ecosystem": ecosystem, "name": name}, "versions": list(versions),
         "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}


@pytest.mark.parametrize("ecosystem,version", [
    ("NuGet", "vv2.0.0"), ("NuGet", "2 .0.0"), ("Debian:12", "v2.0"),
    ("Debian:12", "2 .0"), ("Maven", "2 .0"),
])
def test_invalid_ecosystem_spelling_cannot_become_fixed(ecosystem, version):
    asset = Asset("a", ecosystem=ecosystem, product="example", version=version)
    value = osv_record(ecosystem, "example", [{"introduced": "0"}, {"fixed": "2.0"}])
    assert evaluate_osv(asset, value).state == A.NEEDS_REVIEW


def test_rpm_leading_v_is_significant():
    # rpm-version(7): alphabetic segments sort before numeric ones.
    assert compare("v2.0", "2.0", "ECOSYSTEM", "Red Hat:rhel:9") == -1


@pytest.mark.parametrize("left,right", [("1.0-release", "1.0"), ("1.0.RC1", "1.0-RC1")])
def test_maven_ordering_disagreements_require_review(left, right):
    # Current Maven considers these equivalent; do not use an incompatible
    # library ordering to produce an automatic exclusion.
    result = compare(left, right, "ECOSYSTEM", "Maven")
    assert result in (None, 0)
    value = osv_record("Maven", "g:p", [{"introduced": "0"}, {"fixed": left}])
    asset = Asset("a", ecosystem="Maven", product="g:p", version=right)
    assert evaluate_osv(asset, value).state != A.AFFECTED or result == 0


@pytest.mark.parametrize("ecosystem,left,right,expected", [
    ("PyPI", "1!1.0", "2.0", 1), ("PyPI", "1.0rc1", "1.0", -1),
    ("PyPI", "1.0.post1", "1.0", 1), ("PyPI", "1.0+local", "1.0", 1),
    ("npm", "1.0.0-beta.2", "1.0.0-beta.11", -1),
    ("npm", "1.0.0+one", "1.0.0+two", 0),
    ("Go", "v1.0.1-0.20250101000000-abcdefabcdef", "v1.0.1", -1),
    ("crates.io", "1.0.0-rc.1", "1.0.0", -1),
    ("NuGet", "1.0.0-Alpha", "1.0.0-alpha", 0),
    ("NuGet", "1.0.0.1", "1.0.0", 1),
    ("Debian:12", "1:1.0~rc1-1", "1:1.0-1", -1),
    ("Debian:12", "1.0", "1.0-0", 0),
    ("Red Hat:rhel:9", "1.0^git1", "1.0.1", -1),
    ("Red Hat:rhel:9", "1.0^git1", "1.0", 1),
])
def test_primary_ecosystem_ordering_vectors(ecosystem, left, right, expected):
    assert compare(left, right, "ECOSYSTEM", ecosystem) == expected


@pytest.mark.parametrize("version,expected", [
    ("0.9.0", False), ("1.0.0", True), ("1.9.9", True), ("2.0.0", False),
    ("2.9.9", False), ("3.0.0", True), ("3.9.9", True), ("4.0.0", False),
])
def test_osv_unsorted_reopened_intervals(version, expected):
    events = [{"fixed": "4.0.0"}, {"introduced": "3.0.0"},
              {"fixed": "2.0.0"}, {"introduced": "1.0.0"}]
    assert range_state(version, {"type": "SEMVER", "events": events}, "npm") is expected


def test_multiple_limit_union_and_version_list_union():
    value = {"type": "SEMVER", "events": [{"introduced": "0"}, {"limit": "2.0.0"}, {"limit": "3.0.0"}]}
    assert range_state("2.0.0", value, "npm") is True
    assert range_state("3.0.0", value, "npm") is False
    record = osv_record("npm", "example", [{"introduced": "0"}, {"fixed": "1.0.0"}], versions=("2.0.0",))
    assert evaluate_osv(Asset("a", ecosystem="npm", product="example", version="2.0.0"), record).state == A.AFFECTED
