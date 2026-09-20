from __future__ import annotations

from cvebeacon import cli
from cvebeacon.models import Applicability, Asset, QueryResult


def test_manual_query_does_not_create_monitoring_state(tmp_path, monkeypatch, capsys):
    config = tmp_path / "config.toml"
    config.write_text(
        """[inventory]\npath='inventory.csv'\n[inventory.columns]\nasset_id='asset_id'\nvendor='vendor'\nproduct='product'\nversion='version'\n[state]\ndatabase='state.db'\n[output]\ndirectory='reports'\n""",
        encoding="utf-8",
    )
    def fake_query(app_config, assets):
        return [QueryResult(assets[0], (), (), Applicability.COVERAGE_UNKNOWN, "test")]
    monkeypatch.setattr(cli, "_run_query", fake_query)
    assert cli.main(["--config", str(config), "query", "--vendor", "Any Vendor", "--product", "Any Product", "--version", "v1"]) == 0
    assert not (tmp_path / "state.db").exists()
    assert '"coverage": "coverage_unknown"' in capsys.readouterr().out


def test_inventory_inspect_with_explicit_path_needs_no_configuration(tmp_path, capsys):
    inventory = tmp_path / "inventory.csv"
    inventory.write_text("asset_id,vendor,product,version\na,Any,Thing,1\n", encoding="utf-8")
    missing_config = tmp_path / "does-not-exist.toml"
    assert cli.main(["--config", str(missing_config), "inventory", "inspect", str(inventory)]) == 0
    assert '"format": "csv"' in capsys.readouterr().out


def test_schedule_interactive_default_is_four_hours(tmp_path, monkeypatch, capsys):
    inventory = tmp_path / "inventory.csv"
    inventory.write_text("asset_id,vendor,product,version\na,Any,Thing,1\n", encoding="utf-8")
    config = tmp_path / "config.toml"
    config.write_text(
        """[inventory]\npath='inventory.csv'\n[inventory.columns]\nasset_id='asset_id'\nvendor='vendor'\nproduct='product'\nversion='version'\n[state]\ndatabase='state.db'\n[output]\ndirectory='reports'\n""",
        encoding="utf-8",
    )
    answers = iter(["", "yes"])
    monkeypatch.setattr("builtins.input", lambda _message: next(answers))
    installed = []
    monkeypatch.setattr(cli, "install", lambda plan: installed.append(plan))
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    assert cli.main(["--config", str(config), "schedule", "install"]) == 0
    assert installed[0].every_hours == 4
    assert "Interval: every 4 hours" in capsys.readouterr().out
