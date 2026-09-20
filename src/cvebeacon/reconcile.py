"""Merge source claims without allowing source order to erase disagreement."""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from .applicability import Decision
from .models import Applicability, Asset, Evidence, Finding, Vulnerability


def merge_vulnerabilities(values: Iterable[Vulnerability]) -> Vulnerability:
    items = list(values)
    if not items:
        raise ValueError("at least one vulnerability is required")
    first = items[0]
    def preferred(field: str):
        return next((getattr(item, field) for item in items if getattr(item, field) is not None), None)
    return replace(
        first,
        summary=preferred("summary"), published=preferred("published"), modified=preferred("modified"),
        rejected=any(item.rejected for item in items), cvss_score=preferred("cvss_score"),
        cvss_vector=preferred("cvss_vector"), cvss_version=preferred("cvss_version"),
        epss_score=preferred("epss_score"), epss_percentile=preferred("epss_percentile"),
        epss_date=preferred("epss_date"), cisa_kev=any(item.cisa_kev for item in items),
        eu_kev=any(item.eu_kev for item in items),
        references=tuple(dict.fromkeys(url for item in items for url in item.references)),
    )


def reconcile(
    asset: Asset,
    vulnerability: Vulnerability,
    evidence: Iterable[Evidence],
    decisions: Iterable[Decision],
    *,
    nvd_exact_match: bool = False,
) -> Finding:
    evidence_tuple = tuple(evidence)
    decision_list = list(decisions)
    states = {item.state for item in decision_list if item.state != Applicability.COVERAGE_UNKNOWN}
    conflicts: list[str] = []
    if vulnerability.rejected:
        state = Applicability.NEEDS_REVIEW
        reason = "the CVE record is rejected or withdrawn and this material state requires review"
    elif (Applicability.AFFECTED in states and Applicability.NOT_AFFECTED in states) or (nvd_exact_match and Applicability.NOT_AFFECTED in states):
        state = Applicability.NEEDS_REVIEW
        reason = "authoritative sources disagree on applicability"
        conflicts = [item.reason for item in decision_list if item.state in {Applicability.AFFECTED, Applicability.NOT_AFFECTED}]
    elif Applicability.AFFECTED in states or nvd_exact_match:
        state = Applicability.AFFECTED
        reason = next((item.reason for item in decision_list if item.state == Applicability.AFFECTED), "NVD matched the exact product version as vulnerable")
    elif Applicability.NOT_AFFECTED in states:
        state = Applicability.NOT_AFFECTED
        reason = next(item.reason for item in decision_list if item.state == Applicability.NOT_AFFECTED)
    elif Applicability.NEEDS_REVIEW in states or evidence_tuple:
        state = Applicability.NEEDS_REVIEW
        reason = next((item.reason for item in decision_list if item.state == Applicability.NEEDS_REVIEW), "evidence exists but does not prove version applicability")
    else:
        state = Applicability.COVERAGE_UNKNOWN
        reason = "no authoritative applicability evidence was available"
    confidence = "high" if state in {Applicability.AFFECTED, Applicability.NOT_AFFECTED} else "limited"
    return Finding(asset, vulnerability, state, confidence, reason, evidence_tuple, tuple(conflicts))
