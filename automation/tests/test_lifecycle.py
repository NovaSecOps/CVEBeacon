"""End-to-end offline product lifecycle and fixture isolation checks."""

import importlib.util
import json
import os
from pathlib import Path
import socket

import pytest

from cvebeacon_automation.common import AutomationError

SPEC = importlib.util.spec_from_file_location("automation_lifecycle_demo", Path(__file__).parents[1] / "tools/lifecycle.py")
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


def test_three_source_real_core_state_lifecycle_is_deterministic(tmp_path, monkeypatch):
    original_network = socket.create_connection
    monkeypatch.setenv("LIFECYCLE_UPLOAD_TOKEN", "existing-environment-must-be-restored")
    first = demo.run_demo(tmp_path / "first")
    second = demo.run_demo(tmp_path / "second")
    assert first == second
    assert json.loads((tmp_path / "first/summary.json").read_bytes()) == first
    assert first["authority"] == "offline-synthetic-fixtures" and first["external_network_calls"] == 0
    assert first["core_events"] == 2 and first["event_provider_attempts"] == 8
    assert first["phases"]["unchanged"]["core_events"] == first["phases"]["unchanged"]["provider_attempts"] == 0
    assert first["phases"]["initial"]["core_exit"] == 4 and first["phases"]["initial"]["coverage_unknown"] == 3
    assert first["phases"]["notification_outage"]["retry_attempts"] == 1
    assert first["phases"]["stale_required"]["core_db_preserved"] and not first["phases"]["discovery"]["inventory_promoted"]
    assert socket.create_connection is original_network
    assert os.environ["LIFECYCLE_UPLOAD_TOKEN"] == "existing-environment-must-be-restored"


def test_lifecycle_refuses_to_overwrite_existing_evidence(tmp_path):
    sentinel = tmp_path / "existing-evidence.txt"
    sentinel.write_bytes(b"previous evidence must remain immutable")
    with pytest.raises(AutomationError, match="lifecycle_output_must_be_empty"):
        demo.run_demo(tmp_path)
    assert sentinel.read_bytes() == b"previous evidence must remain immutable"
    assert sorted(path.name for path in tmp_path.iterdir()) == [sentinel.name]


def test_unexpected_transport_networking_is_blocked_and_context_restored(tmp_path, monkeypatch):
    original_network = socket.create_connection
    def erroneous_fixture(self, *args, **kwargs):
        socket.create_connection(("127.0.0.1", 1))
        pytest.fail("network call escaped the offline boundary")
    monkeypatch.setattr(demo.RegistryFixture, "request", erroneous_fixture)
    with pytest.raises(AssertionError, match="prohibits every socket"):
        demo.run_demo(tmp_path)
    assert not (tmp_path / "core.db").exists(), "failed acquisition must stop before Core writes"
    assert not (tmp_path / "summary.json").exists(), "an interrupted fixture must not claim a passed demo"
    assert socket.create_connection is original_network
