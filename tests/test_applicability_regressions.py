from dataclasses import replace

import pytest

from cvebeacon.applicability import Decision, evaluate_cve_evidence, exact_cpe_version, same_identity
from cvebeacon.models import Applicability as A, Asset, Evidence, Vulnerability
from cvebeacon.reconcile import reconcile

@pytest.mark.parametrize("entry", [
    {"version": 1, "status": "unaffected"},
    {"version": "0.0.0", "lessThan": 2, "versionType": "python", "status": "unaffected"},
])
def test_malformed_numeric_source_versions_cannot_exclude(entry):
    evidence = Evidence("cve_list", "cna", "test", details={"affected": [{"vendor": "Acme", "product": "Widget", "defaultStatus": "unaffected", "versions": [entry]}]})
    assert evaluate_cve_evidence(Asset("a", "Acme", "Widget", "1"), evidence).state == A.NEEDS_REVIEW


ASSET = Asset("a", "Acme", "Widget", "1.0.0")


def evaluate(version, entries, **extra):
    product = {"vendor": "Acme", "product": "Widget", "versions": entries, **extra}
    return evaluate_cve_evidence(replace(ASSET, version=version), Evidence("cve_list", "cna", "test", details={"affected": [product]}))


@pytest.mark.parametrize("left,right", [("C++", "C"), ("foo-bar", "foobar"), ("a.b", "ab")])
def test_product_punctuation_is_not_deleted(left, right):
    assert not same_identity(left, right)


@pytest.mark.parametrize("version", ["", " ", "*", "-", "unknown", "N/A"])
def test_missing_version_cannot_use_unaffected_default(version):
    assert evaluate(version, [], defaultStatus="unaffected").state == A.NEEDS_REVIEW


def test_semver_build_metadata_does_not_change_precedence():
    entry = {"version": "0", "lessThanOrEqual": "1.0.0", "versionType": "semver", "status": "affected"}
    assert evaluate("1.0.0+build.9", [entry], defaultStatus="unaffected").state == A.AFFECTED


def test_semver_prerelease_order_is_ascii_not_pep440():
    entry = {"version": "1.0.0-alpha", "lessThan": "1.0.0-beta", "versionType": "semver", "status": "affected"}
    assert evaluate("1.0.0-alpha.10", [entry]).state == A.AFFECTED


@pytest.mark.parametrize("version", ["01.0.0", "1.0", "v1.0.0", "1.0.0rc1"])
def test_non_semver_spelling_is_not_guessed(version):
    entry = {"version": "0", "lessThan": "2.0.0", "versionType": "semver", "status": "affected"}
    assert evaluate(version, [entry], defaultStatus="unaffected").state == A.NEEDS_REVIEW


@pytest.mark.parametrize("endpoint,version,expected", [("lessThan", "2.0.0", A.NOT_AFFECTED), ("lessThanOrEqual", "2.0.0", A.AFFECTED), ("lessThan", "1.0.0", A.AFFECTED)])
def test_semver_range_boundaries(endpoint, version, expected):
    assert evaluate(version, [{"version": "1.0.0", endpoint: "2.0.0", "versionType": "semver", "status": "affected"}], defaultStatus="unaffected").state == expected


def test_unknown_overlap_blocks_explicit_exclusion():
    assert evaluate("1.0.0", [{"version": "1.0.0", "status": "unaffected"}, {"version": "1.0.0", "status": "unknown"}]).state == A.NEEDS_REVIEW


def test_platform_scoped_exclusion_cannot_exclude_unknown_platform():
    assert evaluate("1.0.0", [], defaultStatus="unaffected", platforms=["Windows"]).state == A.NEEDS_REVIEW


def test_malformed_entry_cannot_fall_through_to_unaffected():
    assert evaluate("1.0.0", [None], defaultStatus="unaffected").state == A.NEEDS_REVIEW


def test_review_evidence_blocks_clean_reconciliation():
    finding = reconcile(ASSET, Vulnerability("CVE-2026-1234"), [], [Decision(A.NOT_AFFECTED, "excluded"), Decision(A.NEEDS_REVIEW, "conflicting or unsupported evidence")])
    assert finding.applicability == A.NEEDS_REVIEW


def test_cpe_replacement_preserves_edition_and_platform():
    original = "cpe:2.3:a:acme:widget:*:sp1:pro:en:enterprise:windows:x64:-"
    assert exact_cpe_version(original, "1.0") == original.replace(":*:sp1", ":1.0:sp1")


@pytest.mark.parametrize("version", ["", "*", "-", "\n"])
def test_cpe_unknown_versions_are_rejected(version):
    with pytest.raises(ValueError):
        exact_cpe_version("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", version)
