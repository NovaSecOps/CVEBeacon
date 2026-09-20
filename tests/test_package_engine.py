from contextlib import closing
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from cvebeacon.config import AppConfig, InventoryConfig, SourceConfig
from cvebeacon.engine import QueryEngine
from cvebeacon.errors import SourceError, StateError
from cvebeacon.identity import normalize_asset
from cvebeacon.models import Asset, Applicability as A, Evidence, Finding, HealthStatus as H, QueryResult, SourceHealth, Vulnerability, utc_now
from cvebeacon.package_query import alias_groups
from cvebeacon.sources.osv import OSVResult
from cvebeacon.state import StateStore, material_fingerprint
from test_osv import record


def engine(tmp_path, records=(), error=None):
    sources = SourceConfig(nvd_enabled=False, cve_enabled=False, euvd_enabled=False,
        cisa_kev_enabled=False, eu_kev_enabled=False, epss_enabled=False)
    config = AppConfig(tmp_path / "c.toml", InventoryConfig(tmp_path / "i.csv"), tmp_path / "s.db", tmp_path, sources=sources)
    value = QueryEngine(config)
    value.osv.query_many = lambda assets: {asset.target_key: OSVResult(tuple(records), error, frozenset(r["id"] for r in records)) for asset in assets}
    return value


def package():
    return normalize_asset(Asset("a", purl="pkg:pypi/example@1.0.0", category="library", system_id="private-system"))


def test_non_cve_advisory_and_authoritative_alias_dedup(tmp_path):
    first = record(aliases=[])
    second = record(id="OTHER-2026-1", aliases=[first["id"]])
    with engine(tmp_path, [first, second]) as value:
        result = value.scan([package()])[0]
    assert result.coverage is None and len(result.findings) == 1
    vuln = result.findings[0].vulnerability
    assert vuln.cve_id is None and vuln.primary_id == "OTHER-2026-1"
    assert set(vuln.source_ids) == {first["id"], second["id"]}
    assert len(result.findings[0].evidence) == 2
    assert result.findings[0].applicability == A.AFFECTED
    assert result.to_dict()["findings"][0]["vulnerability"]["advisory_id"] == vuln.primary_id


def test_related_and_description_do_not_merge():
    first = record(aliases=[], related=["OTHER-2026-1"], summary="identical")
    second = record(id="OTHER-2026-1", aliases=[], summary="identical")
    assert len(alias_groups([first, second])) == 2


def test_alias_conflicting_assessments_require_review(tmp_path):
    first = record()
    second = record(id="OTHER-2026-1", events=[{"introduced": "0"}, {"fixed": "1.0.0"}])
    with engine(tmp_path, [first, second]) as value:
        result = value.scan([package()])[0]
    assert len(result.findings) == 1 and result.findings[0].applicability == A.NEEDS_REVIEW
    assert result.findings[0].conflicts


def test_package_source_failure_no_false_clean_and_generic_independence(tmp_path):
    with engine(tmp_path, error="OSV unavailable") as value:
        native, generic = value.scan([package(), Asset("b", "Acme", "Widget", "1")])
    assert native.coverage == A.COVERAGE_UNKNOWN and native.source_health[0].status == H.FAILED
    assert all(health.source != "osv" for health in generic.source_health)


def test_nvd_failure_preserves_package_applicability(tmp_path):
    with engine(tmp_path, [record()]) as value:
        value.config = replace(value.config, sources=replace(value.config.sources, nvd_enabled=True))
        def fail(_): raise SourceError("nvd", "unavailable")
        value.nvd.by_id = fail
        result = value.scan([package()])[0]
    assert result.findings[0].applicability == A.AFFECTED and result.coverage is None
    assert any(h.source == "nvd" and h.status == H.DEGRADED for h in result.source_health)


def test_withdrawal_refreshed_after_disappearance(tmp_path):
    with engine(tmp_path, [record()]) as value:
        first = value.scan([package()])[0]
        value.osv.query_many = lambda assets: {asset.target_key: OSVResult() for asset in assets}
        value.osv.record = lambda identifier: record(withdrawn="2026-09-20T01:00:00Z")
        after = value.scan([package()], known_findings=[first.findings[0].to_dict()])[0]
    assert after.findings[0].vulnerability.rejected
    assert after.findings[0].applicability == A.NEEDS_REVIEW


def test_disabled_required_source_is_unknown(tmp_path):
    with engine(tmp_path) as value:
        value.config = replace(value.config, sources=replace(value.config.sources, osv_enabled=False))
        value.osv.query_many = lambda _: pytest.fail("disabled source requested")
        result = value.scan([package()])[0]
    assert result.coverage == A.COVERAGE_UNKNOWN and result.source_health[0].status == H.DISABLED


def test_grouping_changes_share_lookup_but_keep_local_metadata(tmp_path):
    first = package()
    second = replace(first, asset_id="b", category="other", system_id="second-system")
    with engine(tmp_path, [record()]) as value:
        calls = []
        def query(assets):
            calls.extend(assets)
            return {a.target_key: OSVResult((record(),)) for a in assets}
        value.osv.query_many = query
        results = value.scan([first, second])
    assert len(calls) == 1
    assert results[1].asset == second and results[1].findings[0].asset == second


def native_finding():
    return Finding(package(), Vulnerability(advisory_id="TEST-2026-123", source_ids=("TEST-2026-123",)), A.AFFECTED, "high", "test",
                   (Evidence("osv", "package_applicability", "test", details={"state": "published", "affected": record()["affected"]}),))


def test_alias_addition_preserves_delivery_and_does_not_alert(tmp_path):
    store = StateStore(tmp_path / "s.db")
    finding = native_finding()
    _, events = store.record_scan([QueryResult(finding.asset, (finding,), ())], channels=("teams", "email"))
    store.mark_delivery("teams", events, accepted=True)
    changed = replace(finding, vulnerability=replace(finding.vulnerability, advisory_id="CVE-2026-1234", cve_id="CVE-2026-1234", aliases=("TEST-2026-123",)))
    _, new_events = store.record_scan([QueryResult(changed.asset, (changed,), ())], channels=("teams", "email"))
    assert not new_events
    assert not store.pending_events("teams") and len(store.pending_events("email")) == 1
    assert store.latest_findings()[0]["vulnerability"]["advisory_id"] == "TEST-2026-123"
    assert len(store.history(cve_id="CVE-2026-1234")) == 1


def test_state_required_source_failure_is_identity_aware(tmp_path):
    store = StateStore(tmp_path / "s.db")
    finding = native_finding()
    store.record_scan([QueryResult(finding.asset, (finding,), ())])
    excluded = replace(finding, applicability=A.NOT_AFFECTED)
    osv_failure = (SourceHealth("osv", H.FAILED, utc_now(), "failed"),)
    assert not store.record_scan([QueryResult(finding.asset, (excluded,), osv_failure, A.COVERAGE_UNKNOWN)])[1]
    assert store.latest_findings()[0]["applicability"] == "affected"
    nvd_failure = (SourceHealth("nvd", H.FAILED, utc_now(), "failed"),)
    assert len(store.record_scan([QueryResult(finding.asset, (excluded,), nvd_failure)])[1]) == 1
    assert store.latest_findings()[0]["applicability"] == "not_affected"


def test_schema2_upgrade_preserves_all_rows_and_no_alert_storm(tmp_path):
    store = StateStore(tmp_path / "s.db")
    legacy = Finding(Asset("a", "Acme", "Widget", "1"), Vulnerability("CVE-2026-1234"), A.AFFECTED, "high", "test")
    attempt = store.start_scan()
    _, ids = store.record_scan([QueryResult(legacy.asset, (legacy,), ())], channels=("teams", "email"), attempt_id=attempt)
    store.finish_scan(attempt, successful=True); store.mark_delivery("teams", ids, accepted=True)
    tables = ("runs", "current_findings", "events", "deliveries", "source_health", "scan_attempts", "scan_assets")
    with store.transaction() as db:
        db.execute("DROP TABLE advisory_aliases")
        db.execute("UPDATE schema_info SET version=2")
        before = {t: [tuple(r) for r in db.execute(f"SELECT * FROM {t}")] for t in tables}
    store.initialize(); store.initialize()
    with closing(store._connect()) as db:
        assert db.execute("SELECT version FROM schema_info").fetchone()[0] == 3
        assert before == {t: [tuple(r) for r in db.execute(f"SELECT * FROM {t}")] for t in tables}
    assert not store.record_scan([QueryResult(legacy.asset, (legacy,), ())], channels=("teams", "email"))[1]
    assert len(store.pending_events("email")) == 1 and not store.pending_events("teams")


def test_migration_failure_rolls_back_schema_and_alias_table(tmp_path):
    store = StateStore(tmp_path / "s.db")
    store.initialize()
    with store.transaction() as db:
        db.execute("DROP TABLE advisory_aliases")
        db.execute("UPDATE schema_info SET version=2")
        db.execute("CREATE TRIGGER fail_migration BEFORE UPDATE ON schema_info BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
    with pytest.raises(StateError, match="synthetic failure"):
        store.initialize()
    with closing(store._connect()) as db:
        assert db.execute("SELECT version FROM schema_info").fetchone()[0] == 2
        assert db.execute("SELECT name FROM sqlite_master WHERE name='advisory_aliases'").fetchone() is None


def test_alias_reconciliation_keeps_original_history_rows(tmp_path):
    store = StateStore(tmp_path / "s.db")
    first = native_finding()
    second = replace(first, vulnerability=Vulnerability(advisory_id="OTHER-2026-1", source_ids=("OTHER-2026-1",)))
    store.record_scan([QueryResult(first.asset, (first, second), ())], channels=("email",))
    with closing(store._connect()) as db:
        before = [tuple(row) for row in db.execute("SELECT * FROM events")]
        deliveries = [tuple(row) for row in db.execute("SELECT * FROM deliveries")]
    merged = replace(first, vulnerability=replace(first.vulnerability, aliases=(second.vulnerability.primary_id,)))
    assert not store.record_scan([QueryResult(first.asset, (merged,), ())], channels=("email",))[1]
    assert len(store.latest_findings()) == 1
    assert len(store.history(cve_id=first.vulnerability.primary_id)) == 2
    assert len(store.history(cve_id=second.vulnerability.primary_id)) == 2
    with closing(store._connect()) as db:
        assert before == [tuple(row) for row in db.execute("SELECT * FROM events")]
        assert deliveries == [tuple(row) for row in db.execute("SELECT * FROM deliveries")]
        assert db.execute("SELECT count(*) FROM current_findings").fetchone()[0] == 2
