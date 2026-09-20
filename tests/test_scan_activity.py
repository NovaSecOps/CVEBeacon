from contextlib import closing

import pytest

from cvebeacon import cli
from cvebeacon.config import load_config
from cvebeacon.errors import CVEBeaconError
from cvebeacon.models import Applicability, Asset, QueryResult
from cvebeacon.state import StateStore


def test_v1_upgrade_preserves_existing_monitoring_data(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.record_scan([QueryResult(Asset("a", "Acme", "Widget", "1"), (), (), Applicability.COVERAGE_UNKNOWN, "unknown")])
    with store.transaction() as db:
        before = [tuple(row) for row in db.execute("SELECT * FROM runs")]
        db.execute("DROP TABLE scan_attempts")
        db.execute("DROP TABLE scan_assets")
        db.execute("UPDATE schema_info SET version=1")
    store.initialize()
    with closing(store._connect()) as db:
        assert [tuple(row) for row in db.execute("SELECT * FROM runs")] == before
        assert db.execute("SELECT version FROM schema_info").fetchone()[0] == 2
    assert store.dashboard_snapshot()["assets"] == []  # Legacy coverage is unknown, not invented.


@pytest.mark.parametrize("failure,expected", [(CVEBeaconError("invalid inventory"), 2), (KeyboardInterrupt(), 130)])
def test_scan_attempt_failure_before_result_is_visible(tmp_path, monkeypatch, failure, expected):
    config = tmp_path / "config.toml"
    config.write_text("[inventory]\npath='inventory.csv'\n[state]\ndatabase='state.db'\n", encoding="utf-8")
    def fail(*args): raise failure
    monkeypatch.setattr(cli, "load_inventory", fail)
    assert cli.main(["--config", str(config), "scan"]) == expected
    store = StateStore(tmp_path / "state.db")
    snapshot = store.dashboard_snapshot()
    assert snapshot["attempt"]["status"] == "failed"
    assert snapshot["latest"] is None
    assert "invalid inventory" not in snapshot["attempt"]["message"]


def test_completed_scan_links_attempt_and_preserves_manual_isolation(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text("[inventory]\npath='inventory.csv'\n[state]\ndatabase='state.db'\n", encoding="utf-8")
    (tmp_path / "inventory.csv").write_text("asset_id,vendor,product,version\na,Acme,Widget,1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "_run_query", lambda config, assets, **kwargs: [QueryResult(assets[0], (), ())])
    assert cli.main(["--config", str(path), "scan"]) == 0
    store = StateStore(load_config(path).database_path)
    data = store.dashboard_snapshot()
    assert data["attempt"]["status"] == "completed"
    assert data["attempt"]["run_id"] == data["latest"]["run_id"]
    assert data["assets"][0]["asset"]["version"] == "1"
    assert cli.main(["--config", str(path), "query", "--vendor", "Acme", "--product", "Widget", "--version", "1"]) == 0
    assert store.dashboard_snapshot()["attempt"] == data["attempt"]
