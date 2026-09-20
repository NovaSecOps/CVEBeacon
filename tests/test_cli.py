from __future__ import annotations

from cvebeacon import cli
from cvebeacon.models import Applicability, Asset, QueryResult
import pytest


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


@pytest.fixture
def local_config(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("[inventory]\npath='inventory.csv'\n[state]\ndatabase='state.db'\n[output]\ndirectory='reports'\n", encoding="utf-8")
    (tmp_path / "inventory.csv").write_text("asset_id,vendor,product,version\na,Acme,Widget,1\n", encoding="utf-8")
    return config


@pytest.mark.parametrize("target", ["config.toml", "inventory.csv", "state.db"])
def test_export_cannot_overwrite_operational_files(local_config, monkeypatch, target):
    monkeypatch.setattr(cli, "_run_query", lambda config, assets: [])
    path = local_config.parent / target
    if not path.exists(): path.write_bytes(b"preserved")
    original = path.read_bytes()
    assert cli.main(["--config", str(local_config), "export", "--format", "json", "--output", str(path)]) == 2
    assert path.read_bytes() == original


def test_live_doctor_failure_exits_nonzero(local_config, monkeypatch):
    monkeypatch.setattr(cli, "_live_source_checks", lambda config: {"nvd": "failed: timeout"})
    assert cli.main(["--config", str(local_config), "doctor", "--live"]) == 2


@pytest.mark.parametrize("args,path", [(["--ecosystem", "PyPI", "--product", "requests", "--version", "2.31.0"], "ecosystem"),
    (["--purl", "pkg:npm/%40scope/MixedCase@1.2.3"], "purl"),
    (["--cpe", "cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*"], "cpe")])
def test_explicit_queries_are_normalized_without_state(local_config, monkeypatch, capsys, args, path):
    def query(config, assets):
        assert assets[0].identity_path == path
        return [QueryResult(assets[0], (), (), Applicability.COVERAGE_UNKNOWN)]
    monkeypatch.setattr(cli, "_run_query", query)
    assert cli.main(["--config", str(local_config), "query", *args]) == 0
    assert not (local_config.parent / "state.db").exists()


@pytest.mark.parametrize("args", [["--purl", "not-a-purl"], ["--purl", "pkg:pypi/requests@1", "--version", "2"],
    ["--ecosystem", "PyPI", "--product", "requests"], ["--vendor", " ", "--product", "a", "--version", "1"]])
def test_invalid_queries_fail_before_network(local_config, args):
    assert cli.main(["--config", str(local_config), "query", *args]) == 2


def test_validate_explains_identity(local_config, capsys):
    assert cli.main(["--config", str(local_config), "inventory", "validate", "--identities"]) == 0
    assert "a: product" in capsys.readouterr().out
