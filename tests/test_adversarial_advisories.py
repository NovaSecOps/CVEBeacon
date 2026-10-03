"""Authoritative alias lifecycles must preserve one monitored vulnerability."""

from contextlib import closing
from dataclasses import replace

from cvebeacon.models import Applicability as A, Evidence, QueryResult
from cvebeacon.package_query import alias_groups
from cvebeacon.state import StateStore
from test_package_engine import native_finding


def test_alias_cycles_transitive_bridge_and_unrelated_records():
    records = [{"id": "A-123", "aliases": ["B-123", "B-123"]},
               {"id": "C-123", "aliases": ["D-123"]},
               {"id": "B-123", "aliases": ["C-123", "A-123"]},
               {"id": "E-123", "related": ["A-123"], "upstream": ["D-123"]}]
    for ordered in (records, list(reversed(records))):
        groups = alias_groups(ordered)
        assert sorted(sorted(group[0]) for group in groups) == [["A-123", "B-123", "C-123", "D-123"], ["E-123"]]


def test_later_cve_metadata_cannot_change_package_material_evidence(tmp_path):
    store = StateStore(tmp_path / "s.db")
    original = native_finding()
    _, ids = store.record_scan([QueryResult(original.asset, (original,), ())], channels=("teams", "email"))
    store.mark_delivery("teams", ids, accepted=True)
    with closing(store._connect()) as db:
        first_seen = db.execute("SELECT first_seen FROM current_findings").fetchone()[0]
    assigned = replace(original, vulnerability=replace(original.vulnerability,
        cve_id="CVE-2026-1234", advisory_id="CVE-2026-1234", aliases=(original.vulnerability.primary_id,)),
        evidence=original.evidence + (Evidence("nvd", "cve_enrichment", "CVE alias metadata",
            details={"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": []}]}]}),
            Evidence("cve_list", "cve_enrichment", "CNA alias metadata", details={"state": "PUBLISHED", "affected": []})))
    assert store.record_scan([QueryResult(assigned.asset, (assigned,), ())], channels=("teams", "email"))[1] == []
    assert not store.pending_events("teams") and len(store.pending_events("email")) == 1
    reordered = replace(assigned, evidence=tuple(reversed(assigned.evidence)), vulnerability=replace(
        assigned.vulnerability, aliases=(*assigned.vulnerability.aliases, "ANOTHER-2026-123")))
    assert store.record_scan([QueryResult(reordered.asset, (reordered,), ())])[1] == []
    assert len(store.history(cve_id="ANOTHER-2026-123")) == 1
    changed = replace(reordered, vulnerability=replace(reordered.vulnerability, cvss_score=9.5))
    assert len(store.record_scan([QueryResult(changed.asset, (changed,), ())])[1]) == 1
    with closing(store._connect()) as db:
        assert db.execute("SELECT first_seen FROM current_findings").fetchone()[0] == first_seen


def test_existing_package_fingerprint_upgrades_without_an_alert(tmp_path):
    original = native_finding()
    observed = replace(original, evidence=original.evidence + (
        Evidence("nvd", "cve_enrichment", "metadata", details={"configurations": []}),))
    store = StateStore(tmp_path / "s.db")
    store.record_scan([QueryResult(observed.asset, (observed,), ())])
    # Computed by the exact original PR #2 material_fingerprint function.
    legacy = "76c26ac7747dc9e58d0e19c8f33c69246fd9cc9b3356cb121ff8185f7a7ea0d3"
    with store.transaction() as db:
        db.execute("UPDATE current_findings SET fingerprint=?", (legacy,))
    assert store.record_scan([QueryResult(observed.asset, (observed,), ())])[1] == []
    changed = replace(observed, applicability=A.NOT_AFFECTED)
    assert len(store.record_scan([QueryResult(changed.asset, (changed,), ())])[1]) == 1
