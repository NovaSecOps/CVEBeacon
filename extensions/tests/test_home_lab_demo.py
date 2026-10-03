"""Exercise the synthetic end-to-end orchestration without native host access."""

import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest

from cvebeacon.config import AppConfig
from cvebeacon_extensions import hosts


def _module():
    path = Path(__file__).resolve().parents[2] / "tools" / "home_lab_demo.py"
    spec = importlib.util.spec_from_file_location("home_lab_demo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_three_host_lifecycle_persists_unknown_coverage_without_host_or_network(tmp_path, monkeypatch):
    demo = _module()
    def forbidden(*args, **kwargs):
        raise AssertionError("demo must not inspect a real host or read credentials")
    for name in ("collect_linux", "collect_windows", "windows_observations", "run_packages"):
        monkeypatch.setattr(hosts, name, forbidden)
    monkeypatch.setattr(AppConfig, "secret", forbidden)
    output = tmp_path / "demo"
    summary = demo.run_demo(output)
    assert summary == json.loads((output / "summary.json").read_bytes())
    assert summary["sources"] == ["linux-a", "linux-b", "windows-a"]
    assert [run["assets"] for run in summary["runs"]] == [10, 10, 10]
    assert all(run["core_run_status"] == "failed" and run["coverage_unknown"] == 10 for run in summary["runs"])
    assert {key: len(values) for key, values in summary["changes"].items()} == {
        "upgraded": 1, "removed": 1, "added": 1, "unchanged": 8,
    }
    for phase in ("initial", "changed", "repeat"):
        report = json.loads((output / "reports" / f"{phase}.json").read_bytes())
        assert len(report) == 10
        assert all(not item["findings"] and item["coverage"] == "coverage_unknown" for item in report)
    assert (output / "reports" / "repeat.xlsx").is_file()
    with sqlite3.connect(output / "state" / "demo.db") as db:
        assert db.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 3
        assert db.execute("SELECT COUNT(*) FROM scan_assets").fetchone()[0] == 30
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM scan_attempts WHERE status='failed'").fetchone()[0] == 3
    # A second new destination produces the same scenario summary/asset IDs.
    assert demo.run_demo(tmp_path / "second") == summary


def test_existing_destination_is_never_reused_or_modified(tmp_path):
    demo = _module()
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_bytes(b"existing user data")
    with pytest.raises(FileExistsError):
        demo.run_demo(output)
    assert marker.read_bytes() == b"existing user data"
    assert list(output.iterdir()) == [marker]
