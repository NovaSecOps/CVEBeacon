from __future__ import annotations

from dataclasses import replace
from datetime import date

from cvebeacon.models import Applicability, Asset, Evidence, Finding, QueryResult, Vulnerability
from cvebeacon.state import StateStore, material_fingerprint


def finding(*, epss=0.1, score=8.0, applicability=Applicability.AFFECTED):
    asset = Asset("a1", "Acme", "Widget", "1")
    vuln = Vulnerability("CVE-2026-1234", cvss_score=score, epss_score=epss, epss_date=date(2026, 1, 1))
    return Finding(asset, vuln, applicability, "high", "exact", (Evidence("nvd", "applicability", "exact"),))


def result(item): return QueryResult(item.asset, (item,), ())


def test_epss_change_is_not_material():
    assert material_fingerprint(finding(epss=0.1)) == material_fingerprint(finding(epss=0.9))


def test_rejection_and_cvss_changes_are_material():
    original = finding()
    rejected = replace(original, vulnerability=replace(original.vulnerability, rejected=True))
    rescored = replace(original, vulnerability=replace(original.vulnerability, cvss_score=9.9))
    assert material_fingerprint(original) != material_fingerprint(rejected)
    assert material_fingerprint(original) != material_fingerprint(rescored)


def test_state_new_unchanged_changed_and_channel_isolation(tmp_path):
    store = StateStore(tmp_path / "state.db")
    _, first = store.record_scan([result(finding())], channels=("teams", "email"))
    _, unchanged = store.record_scan([result(finding(epss=0.8))], channels=("teams", "email"))
    _, changed = store.record_scan([result(finding(score=9.0))], channels=("teams", "email"))
    assert len(first) == 1 and unchanged == [] and len(changed) == 1
    store.mark_delivery("teams", first, accepted=True)
    store.mark_delivery("email", first, accepted=False, error="temporary")
    assert not any(row["event_id"] == first[0] for row in store.pending_events("teams"))
    assert any(row["event_id"] == first[0] for row in store.pending_events("email"))
    with store._connect() as db:
        current = db.execute("SELECT first_seen,last_seen FROM current_findings").fetchone()
        assert current["first_seen"] <= current["last_seen"]


def test_failed_transaction_does_not_commit_partial_run(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.db"); store.initialize()
    bad = finding()
    original = Finding.to_dict
    monkeypatch.setattr(Finding, "to_dict", lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
    try:
        try: store.record_scan([result(bad)])
        except RuntimeError: pass
    finally: monkeypatch.setattr(Finding, "to_dict", original)
    with store._connect() as db:
        assert db.execute("SELECT count(*) FROM runs").fetchone()[0] == 0
