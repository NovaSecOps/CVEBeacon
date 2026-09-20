from dataclasses import replace
from datetime import date
from contextlib import closing
import sqlite3

import pytest

from cvebeacon.models import Applicability as A, Asset, Evidence, Finding, HealthStatus, QueryResult, SourceHealth, Vulnerability, utc_now
from cvebeacon.state import StateStore, material_fingerprint
from cvebeacon.errors import StateError


def finding():
    product = {"vendor": "Acme", "product": "Widget", "versions": [{"version": "1", "status": "affected"}, {"version": "2", "status": "unaffected"}]}
    return Finding(Asset("a", "Acme", "Widget", "1"), Vulnerability("CVE-2026-1234", cisa_kev=True), A.AFFECTED, "high", "test", (Evidence("cve_list", "cna", "test", details={"affected": [product]}), Evidence("cisa_kev", "known_exploitation", "listed")))


def test_material_evidence_array_order_and_duplicates_do_not_alert():
    item = finding()
    product = item.evidence[0].details["affected"][0]
    changed = replace(item.evidence[0], details={"affected": [{**product, "versions": list(reversed(product["versions"]))}]})
    assert material_fingerprint(item) == material_fingerprint(replace(item, evidence=(changed, changed, item.evidence[1])))


def test_epss_appearing_does_not_create_material_event():
    item = finding()
    scored = replace(item, vulnerability=replace(item.vulnerability, epss_score=.8, epss_date=date(2026, 1, 1)), evidence=item.evidence + (Evidence("epss", "predictive_enrichment", "score", details={"score": .8}),))
    assert material_fingerprint(item) == material_fingerprint(scored)


def test_core_failure_preserves_known_finding_and_no_false_resolution(tmp_path):
    store = StateStore(tmp_path / "s.db"); item = finding()
    store.record_scan([QueryResult(item.asset, (item,), ())])
    degraded = replace(item, applicability=A.NOT_AFFECTED, evidence=())
    health = (SourceHealth("nvd", HealthStatus.FAILED, utc_now(), "offline"),)
    _, events = store.record_scan([QueryResult(item.asset, (degraded,), health, A.COVERAGE_UNKNOWN, "offline")])
    assert not events
    assert store.latest_findings()[0]["applicability"] == "affected"
    store.record_scan([QueryResult(item.asset, (), health, A.COVERAGE_UNKNOWN, "offline")])
    assert len(store.latest_findings()) == 1


def test_kev_failure_does_not_remove_known_membership_or_alert(tmp_path):
    store = StateStore(tmp_path / "s.db"); item = finding()
    store.record_scan([QueryResult(item.asset, (item,), ())])
    degraded = replace(item, vulnerability=replace(item.vulnerability, cisa_kev=False), evidence=item.evidence[:1])
    health = (SourceHealth("cisa_kev", HealthStatus.FAILED, utc_now(), "offline"),)
    _, events = store.record_scan([QueryResult(item.asset, (degraded,), health)])
    assert events == []
    assert store.latest_findings()[0]["vulnerability"]["cisa_kev"]


@pytest.mark.parametrize("accepted_teams,accepted_email", [(True, True), (True, False), (False, True), (False, False)])
def test_independent_delivery_outcomes_and_retry(tmp_path, accepted_teams, accepted_email):
    store = StateStore(tmp_path / "s.db"); item = finding()
    _, ids = store.record_scan([QueryResult(item.asset, (item,), ())], channels=("teams", "email"))
    for channel, accepted in (("teams", accepted_teams), ("email", accepted_email)):
        store.mark_delivery(channel, ids, accepted=accepted)
        assert bool(store.pending_events(channel)) is not accepted
    _, events = store.record_scan([QueryResult(item.asset, (item,), ())], channels=("teams", "email"))
    assert not events


def test_failed_run_is_recorded_and_latest_health_exposes_failure(tmp_path):
    from cvebeacon.cli import _source_status
    store = StateStore(tmp_path / "s.db"); item = finding()
    store.record_scan([QueryResult(item.asset, (item,), ())])
    health = (SourceHealth("euvd", HealthStatus.FAILED, utc_now(), "offline"),)
    run_id, _ = store.record_scan([QueryResult(item.asset, (), health, A.COVERAGE_UNKNOWN)])
    with closing(store._connect()) as db:
        assert db.execute("SELECT status FROM runs WHERE run_id=?", (run_id,)).fetchone()[0] == "failed"
    assert _source_status(store)[0]["status"] == "failed"


def test_busy_database_fails_without_committing_a_run(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "s.db"); store.initialize()
    original = store._connect
    def impatient():
        db = original(); db.execute("PRAGMA busy_timeout=1"); return db
    monkeypatch.setattr(store, "_connect", impatient)
    with closing(original()) as lock:
        lock.execute("BEGIN IMMEDIATE")
        with pytest.raises(StateError, match="locked"):
            store.record_scan([QueryResult(finding().asset, (), ())])
        lock.rollback()
    with closing(original()) as db:
        assert db.execute("SELECT count(*) FROM runs").fetchone()[0] == 0


def test_unsupported_schema_initialization_rolls_back_new_tables(tmp_path):
    path = tmp_path / "s.db"
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE schema_info(version INTEGER)")
        db.execute("INSERT INTO schema_info VALUES (999)"); db.commit()
    with pytest.raises(StateError, match="unsupported"):
        StateStore(path).initialize()
    with closing(sqlite3.connect(path)) as db:
        assert [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")] == ["schema_info"]
