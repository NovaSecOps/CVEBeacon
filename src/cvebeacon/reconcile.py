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
    items.sort(key=lambda item: (-(item.cvss_score if item.cvss_score is not None else -1), item.cvss_version or "", item.cvss_vector or "", item.summary or "", item.modified or ""))
    first = items[0]
    def preferred(field: str):
        return next((getattr(item, field) for item in items if getattr(item, field) is not None), None)
    return replace(
        first,
        summary=preferred("summary"), published=preferred("published"), modified=preferred("modified"),
        rejected=any(item.rejected for item in items), cvss_score=first.cvss_score,
        cvss_vector=first.cvss_vector, cvss_version=first.cvss_version,
        epss_score=preferred("epss_score"), epss_percentile=preferred("epss_percentile"),
        epss_date=preferred("epss_date"), cisa_kev=True if any(item.cisa_kev for item in items) else (False if any(item.cisa_kev is False for item in items) else None),
        eu_kev=True if any(item.eu_kev for item in items) else (False if any(item.eu_kev is False for item in items) else None),
        references=tuple(sorted({url for item in items for url in item.references})),
        aliases=tuple(sorted({identifier for item in items for identifier in item.aliases})),
        source_ids=tuple(sorted({identifier for item in items for identifier in item.source_ids})),
        fixed_versions=tuple(sorted({version for item in items for version in item.fixed_versions})),
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
        reason = "the vulnerability record is rejected or withdrawn and this material state requires review"
    elif any(getattr(item, "conflict", False) for item in decision_list):
        state = Applicability.NEEDS_REVIEW
        reason = "authoritative evidence contains an unresolved applicability conflict"
        conflicts = [item.reason for item in decision_list]
    elif (Applicability.AFFECTED in states and Applicability.NOT_AFFECTED in states) or (nvd_exact_match and Applicability.NOT_AFFECTED in states):
        state = Applicability.NEEDS_REVIEW
        reason = "authoritative sources disagree on applicability"
        conflicts = [item.reason for item in decision_list if item.state in {Applicability.AFFECTED, Applicability.NOT_AFFECTED}]
    elif Applicability.AFFECTED in states or nvd_exact_match:
        state = Applicability.AFFECTED
        reason = next((item.reason for item in decision_list if item.state == Applicability.AFFECTED), "NVD matched the exact product version as vulnerable")
    elif Applicability.NOT_AFFECTED in states and Applicability.NEEDS_REVIEW in states:
        state = Applicability.NEEDS_REVIEW
        reason = "exclusion is not conclusive while other applicability evidence is unresolved"
        conflicts = [item.reason for item in decision_list]
    elif Applicability.NOT_AFFECTED in states:
        state = Applicability.NOT_AFFECTED
        reason = next(item.reason for item in decision_list if item.state == Applicability.NOT_AFFECTED)
    elif decision_list and all(item.state == Applicability.COVERAGE_UNKNOWN for item in decision_list):
        state = Applicability.COVERAGE_UNKNOWN
        reason = "sources do not establish this product identity"
    elif Applicability.NEEDS_REVIEW in states or evidence_tuple:
        state = Applicability.NEEDS_REVIEW
        reason = next((item.reason for item in decision_list if item.state == Applicability.NEEDS_REVIEW), "evidence exists but does not prove version applicability")
    else:
        state = Applicability.COVERAGE_UNKNOWN
        reason = "no authoritative applicability evidence was available"
    confidence = "high" if state in {Applicability.AFFECTED, Applicability.NOT_AFFECTED} else "limited"
    return Finding(asset, vulnerability, state, confidence, reason, evidence_tuple, tuple(conflicts))
