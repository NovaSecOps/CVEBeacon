"""Regression coverage for install durability and completion finalization."""
from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import sqlite3
import sys

import pytest

from cvebeacon import updater as u, update_state
from cvebeacon.config import UpdateConfig, load_config
from cvebeacon.errors import CVEBeaconError
from cvebeacon.locking import RunLock
from cvebeacon.update_transaction import ensure_ready
from test_updater import transaction, signed, value
from watch_support import write_config
from test_dashboard_updates import updates
from test_dashboard_operations import login, submit

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Native update durability uses Linux filesystem and service semantics")


def test_readonly_config_check_uses_writable_advisory_state(tmp_path, signed):
    config_dir, state = tmp_path / "config", tmp_path / "state"
    config_dir.mkdir()
    state.mkdir()
    config = write_config(config_dir, inventory=False)
    config.config_path.write_text(config.config_path.read_text().replace('database = "state.db"', 'database = "' + str(state / "state.db") + '"').replace('database = "watch.db"', 'database = "' + str(state / "watch.db") + '"'))
    config = replace(load_config(config.config_path), update=UpdateConfig(enabled=True))
    config_dir.chmod(0o555)
    try:
        assert u.check(config, http=signed[0].http)["available"] == "0.1.1"
        assert u.read_status(config)["available"] == "0.1.1"
        assert (state / u.STATUS).is_file()
    finally:
        config_dir.chmod(0o700)

def test_check_returns_data_even_if_all_status_publication_fails(tmp_path, signed, monkeypatch):
    config = replace(write_config(tmp_path, inventory=False), update=UpdateConfig(enabled=True))
    monkeypatch.setattr(u, "atomic_json", lambda *a, **k: (_ for _ in ()).throw(PermissionError("synthetic readonly storage")))
    assert u.check(config, http=signed[0].http)["available"] == "0.1.1"

def test_check_returns_data_when_status_is_a_directory(tmp_path, signed):
    config = replace(write_config(tmp_path, inventory=False), update=UpdateConfig(enabled=True))
    (config.config_path.parent / u.STATUS).mkdir()
    assert u.check(config, http=signed[0].http)["available"] == "0.1.1"

def test_dashboard_check_handles_storage_oserrors(updates, monkeypatch):
    from cvebeacon import dashboard_update
    _, _, client = updates
    login(client)
    monkeypatch.setattr(dashboard_update, "check", lambda *args: (_ for _ in ()).throw(PermissionError("synthetic storage error")))
    assert submit(client, "/updates/check").status_code == 400
