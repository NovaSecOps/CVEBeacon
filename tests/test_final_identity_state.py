"""Conservative identity handling across incomplete source and alias updates."""

from dataclasses import replace
import os

import pytest

from cvebeacon.errors import StateError
from cvebeacon.models import Asset, Applicability as A, Evidence, QueryResult, Vulnerability
from cvebeacon.osv_applicability import evaluate_osv
from cvebeacon.sources.osv import OSVResult
from cvebeacon.state import StateStore
from test_osv import record
from test_package_engine import engine, native_finding, package


@pytest.mark.parametrize("ecosystem,name,purl", [
    ("PyPI", "example", "pkg:deb/debian/example"),
    ("PyPI", "example", "pkg:generic/example"),
    ("PyPI", "example", "pkg:apk/alpine/other"),
    ("Debian:12", "example", "pkg:deb/debian/other?arch=source"),
    ("Debian:12", "example", "pkg:rpm/redhat/example"),
    ("Debian:12", "example", "pkg:deb/ubuntu/example"),
    ("Red Hat:rhel:9", "example", "pkg:deb/debian/example"),
])
def test_unmapped_supplementary_purl_cannot_establish_exclusion(ecosystem, name, purl):
    value = record(events=[{"introduced": "0"}, {"fixed": "1.0"}])
    value["affected"][0]["package"] = {"ecosystem": ecosystem, "name": name, "purl": purl}
    assert evaluate_osv(Asset("a", ecosystem=ecosystem, product=name, version="2.0"), value).state == A.NEEDS_REVIEW


@pytest.mark.parametrize("reverse", [False, True])
def test_disappearing_alias_reconciles_before_persistence(tmp_path, reverse):
    first = record(id="TEST-A", aliases=["TEST-B"])
    second = record(id="TEST-B", aliases=[])
    store = StateStore(tmp_path / "state.db")
    with engine(tmp_path, [first, second]) as value:
        initial = value.scan([package()])
        store.record_scan(initial, channels=("email",))
        # The source now omits the old link and disagrees about the boundary.
        first = record(id="TEST-A", aliases=[])
        second = record(id="TEST-B", aliases=[], events=[{"introduced": "0"}, {"fixed": "1.0.0"}])
        records = (second, first) if reverse else (first, second)
        value.osv.query_many = lambda assets: {a.target_key: OSVResult(records) for a in assets}
        updated = value.scan([package()], known_findings=store.latest_findings())
        assert len(updated[0].findings) == 1
        assert updated[0].findings[0].applicability == A.NEEDS_REVIEW
        assert len(store.record_scan(updated, channels=("email",))[1]) == 1
        repeated = value.scan([package()], known_findings=store.latest_findings())
        assert store.record_scan(repeated, channels=("email",))[1] == []
    assert store.latest_findings()[0]["applicability"] == "needs_review"
    assert len(store.history(cve_id="TEST-B")) == 2
    assert len(store.pending_events("email")) == 2


def test_unreconciled_historical_alias_collision_rolls_back(tmp_path):
    store = StateStore(tmp_path / "state.db")
    original = native_finding()
    linked = replace(original, vulnerability=replace(original.vulnerability, aliases=("TEST-B",)))
    store.record_scan([QueryResult(linked.asset, (linked,), ())])
    before = store.latest_findings()
    conflicting = replace(original, applicability=A.NOT_AFFECTED,
        vulnerability=replace(original.vulnerability, advisory_id="TEST-B", source_ids=("TEST-B",)))
    with pytest.raises(StateError, match="alias"):
        store.record_scan([QueryResult(original.asset, (original, conflicting), ())])
    assert store.latest_findings() == before
    assert len(store.history()) == 1


def test_later_euvd_alias_metadata_does_not_create_material_event(tmp_path):
    store = StateStore(tmp_path / "state.db")
    initial_record = record(aliases=[])
    with engine(tmp_path, [initial_record]) as value:
        initial = value.scan([package()])
        store.record_scan(initial)
        value.config = replace(value.config, sources=replace(value.config.sources, euvd_enabled=True))
        value.euvd.search = lambda *args, **kwargs: [(Vulnerability("CVE-2026-7654"),
            Evidence("euvd", "independent_enrichment", "metadata", details={"products": [{"name": "example"}]}))]
        value.osv.query_many = lambda assets: {a.target_key: OSVResult((record(aliases=["CVE-2026-7654"]),)) for a in assets}
        enriched = value.scan([package()], known_findings=store.latest_findings())
        assert store.record_scan(enriched)[1] == []


def test_non_cve_osv_severity_change_is_material(tmp_path):
    store = StateStore(tmp_path / "state.db")
    before = native_finding()
    severity = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    after = replace(before, evidence=(replace(before.evidence[0], details={**before.evidence[0].details, "severity": severity}),))
    store.record_scan([QueryResult(before.asset, (before,), ())])
    assert len(store.record_scan([QueryResult(after.asset, (after,), ())])[1]) == 1
    assert store.record_scan([QueryResult(after.asset, (after,), ())])[1] == []


def test_existing_osv_fingerprint_policy_upgrade_preserves_events(tmp_path):
    store = StateStore(tmp_path / "state.db")
    original = native_finding()
    observed = replace(original, evidence=original.evidence + (
        Evidence("euvd", "independent_enrichment", "old package enrichment", details={"products": ["example"]}),))
    _, ids = store.record_scan([QueryResult(observed.asset, (observed,), ())], channels=("email",))
    with store.transaction() as db:
        db.execute("UPDATE current_findings SET fingerprint='previous-policy'")
    refreshed = replace(original, evidence=original.evidence + (
        Evidence("euvd", "cve_enrichment", "refreshed metadata", details={"products": ["example", "other"]}),))
    assert store.record_scan([QueryResult(refreshed.asset, (refreshed,), ())])[1] == []
    assert [item["event_id"] for item in store.pending_events("email")] == ids
    changed = replace(refreshed, vulnerability=replace(refreshed.vulnerability, cisa_kev=True))
    assert len(store.record_scan([QueryResult(changed.asset, (changed,), ())])[1]) == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows device names")
@pytest.mark.parametrize("path", ["NUL:", "CON::$DATA", "subdir/CON:"])
def test_static_path_join_rejects_device_ads_without_opening_devices(path):
    from werkzeug.security import safe_join
    assert safe_join("static", path) is None
