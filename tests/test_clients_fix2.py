from dataclasses import replace
import sqlite3

import pytest

from cvebeacon.clients import affected_clients, client_cves, client_summaries
from cvebeacon.errors import InventoryValidationError, StateError
from cvebeacon.inventory import validate_records
from cvebeacon.models import Applicability, Asset, Finding, QueryResult, Vulnerability
from cvebeacon.state import StateStore
import cvebeacon.clients as clients


@pytest.mark.parametrize("reverse", (False, True))
@pytest.mark.parametrize("winner,loser", (
    (Applicability.AFFECTED, Applicability.NOT_AFFECTED),
    (Applicability.AFFECTED, Applicability.NEEDS_REVIEW),
    (Applicability.NEEDS_REVIEW, Applicability.NOT_AFFECTED),
))
def test_normalized_snapshot_collision_keeps_strongest_identity(tmp_path, reverse, winner, loser):
    path = tmp_path / "state.db"
    asset = Asset("a1", "Acme", "Widget", "1", client="Acme")
    winning = Finding(asset, Vulnerability(advisory_id="GHSA-dddd-eeee-ffff",
        aliases=("CVE-2026-0001",)), winner, "high", "test")
    losing = Finding(asset, Vulnerability(advisory_id="GHSA-aaaa-bbbb-cccc",
        aliases=("cve-2026-0001",)), loser, "high", "test")
    items = (losing, winning) if reverse else (winning, losing)
    run, _ = StateStore(path).record_scan([QueryResult(asset, items, ())])
    with sqlite3.connect(path) as db:
        row = db.execute("SELECT advisory_id,applicability FROM scan_findings "
            "WHERE run_id=? AND identifier=?", (run, "CVE-2026-0001")).fetchone()
    assert row == ("GHSA-DDDD-EEEE-FFFF", winner.value)
    assert affected_clients(path, ("CVE-2026-0001",))["CVE-2026-0001"][0].status == winner.value


def test_snapshot_freezes_known_aliases_when_source_drops_them(tmp_path):
    path = tmp_path / "state.db"
    store = StateStore(path)
    asset = Asset("a1", "Acme", "Widget", "1", client="Acme")
    item = Finding(asset, Vulnerability(advisory_id="GHSA-aaaa-bbbb-cccc",
        aliases=("CVE-2026-0009",)), Applicability.AFFECTED, "high", "test")
    store.record_scan([QueryResult(asset, (item,), ())])
    without_alias = replace(item, vulnerability=replace(item.vulnerability, aliases=()))
    store.record_scan([QueryResult(asset, (without_alias,), ())])
    with store.transaction() as db:
        db.execute("DELETE FROM advisory_aliases")
        db.execute("INSERT INTO advisory_aliases VALUES (?,?,?)",
            (asset.asset_id, "CVE-2026-9999", item.vulnerability.primary_id))
    assert client_cves(path, "Acme") == ("CVE-2026-0009",)
    assert affected_clients(path, ("CVE-2026-0009",))["CVE-2026-0009"][0].name == "Acme"
    assert affected_clients(path, ("CVE-2026-9999",)) == {}
    assert client_summaries(path)[1][0].findings[0].cve_id == "CVE-2026-0009"


@pytest.mark.parametrize("character", ("\u2028", "\u2029", "\ud800"))
def test_inventory_rejects_non_display_client_characters(character):
    with pytest.raises(InventoryValidationError, match="client"):
        validate_records([dict(asset_id="a1", vendor="Acme", product="Widget",
            version="1", client="Acme" + character + "Corp")])


@pytest.mark.parametrize("value", ("Acme\u2028Corp", "Acme\u2029Corp", "Acme\ud800Corp",
    "Acme\x85Corp", "Acme\u202eCorp", "x" * 121))
def test_record_scan_revalidates_client_and_rolls_back(tmp_path, value):
    path = tmp_path / "state.db"
    asset = Asset("a1", "Acme", "Widget", "1", client=value)
    with pytest.raises(StateError, match="client"):
        StateStore(path).record_scan([QueryResult(asset, (), ())])
    with sqlite3.connect(path) as db:
        for table in ("runs", "scan_assets", "scan_asset_clients", "scan_findings"):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_reader_sees_commit_between_sidecar_check_and_open(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    store = StateStore(path)
    asset = Asset("a1", "Acme", "Widget", "1", client="Acme")
    def record(current):
        item = Finding(current, Vulnerability("CVE-2026-0001"),
            Applicability.AFFECTED, "high", "test")
        store.record_scan([QueryResult(current, (item,), ())])
    record(asset)
    assert not path.with_name("state.db-wal").exists()
    real_connect = sqlite3.connect
    writers = []
    def interleave(database, *args, **kwargs):
        if isinstance(database, str) and "mode=ro" in database and not writers:
            writers.append(real_connect(path))
            writers[0].execute("SELECT COUNT(*) FROM runs").fetchone()
            record(replace(asset, client="Globex"))
        return real_connect(database, *args, **kwargs)
    monkeypatch.setattr(sqlite3, "connect", interleave)
    try:
        assert affected_clients(path, ("CVE-2026-0001",))["CVE-2026-0001"][0].name == "Globex"
    finally:
        for writer in writers:
            writer.close()


def test_correlation_uses_one_read_transaction(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    StateStore(path).record_scan([])
    original = clients._latest_successful_scan
    def check(db):
        assert db.in_transaction
        assert db.execute("PRAGMA query_only").fetchone()[0] == 1
        return original(db)
    monkeypatch.setattr(clients, "_latest_successful_scan", check)
    assert affected_clients(path, ("CVE-2026-0001",)) == {}
