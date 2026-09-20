from __future__ import annotations

from cvebeacon.applicability import evaluate_cve_evidence, exact_cpe_version
from cvebeacon.models import Applicability, Asset, Evidence, Vulnerability
from cvebeacon.reconcile import reconcile


ASSET = Asset("a1", "Acme Corp", "Widget-Pro", "1.5.0")


def evidence(versions, default=None):
    product = {"vendor": "Acme Corp", "product": "Widget Pro", "versions": versions}
    if default: product["defaultStatus"] = default
    return Evidence("cve_list", "cna", "affected evidence", details={"affected": [product]})


def test_supported_semver_range_can_prove_affected():
    decision = evaluate_cve_evidence(ASSET, evidence([{"version": "1.0.0", "lessThan": "2.0.0", "versionType": "semver", "status": "affected"}]))
    assert decision.state == Applicability.AFFECTED


def test_custom_range_is_never_blindly_compared():
    decision = evaluate_cve_evidence(ASSET, evidence([{"version": "1.0", "lessThan": "2.0", "versionType": "custom", "status": "affected"}]))
    assert decision.state == Applicability.NEEDS_REVIEW


def test_affirmative_unaffected_evidence_is_required():
    decision = evaluate_cve_evidence(ASSET, evidence([{"version": "1.5.0", "status": "unaffected"}]))
    assert decision.state == Applicability.NOT_AFFECTED
    unknown = evaluate_cve_evidence(ASSET, Evidence("cve_list", "cna", "none", details={"affected": []}))
    assert unknown.state == Applicability.COVERAGE_UNKNOWN


def test_authoritative_conflict_becomes_review():
    vuln = Vulnerability("CVE-2026-1234")
    finding = reconcile(ASSET, vuln, [], [
        type("D", (), {"state": Applicability.AFFECTED, "reason": "affected"})(),
        type("D", (), {"state": Applicability.NOT_AFFECTED, "reason": "not affected"})(),
    ])
    assert finding.applicability == Applicability.NEEDS_REVIEW
    assert finding.conflicts


def test_nvd_exact_conflicting_with_official_unaffected_needs_review():
    vuln = Vulnerability("CVE-2026-1234")
    finding = reconcile(ASSET, vuln, [], [
        type("D", (), {"state": Applicability.NOT_AFFECTED, "reason": "explicitly unaffected"})(),
    ], nvd_exact_match=True)
    assert finding.applicability == Applicability.NEEDS_REVIEW


def test_nvd_exact_is_not_downgraded_by_noncontradictory_uncertainty():
    vuln = Vulnerability("CVE-2026-1234")
    finding = reconcile(ASSET, vuln, [], [
        type("D", (), {"state": Applicability.NEEDS_REVIEW, "reason": "unsupported secondary range"})(),
    ], nvd_exact_match=True)
    assert finding.applicability == Applicability.AFFECTED


def test_supported_status_changes_are_applied():
    decision = evaluate_cve_evidence(ASSET, evidence([{
        "version": "1.0.0", "lessThan": "3.0.0", "versionType": "semver", "status": "affected",
        "changes": [{"at": "1.4.0", "status": "unaffected"}],
    }]))
    assert decision.state == Applicability.NOT_AFFECTED


def test_exact_cpe_replaces_version():
    value = exact_cpe_version("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "1.2:3")
    assert ":1.2\\:3:" in value
