"""Completion admission barriers and finalization feedback regressions."""
import ast
import errno
import json
import os
from pathlib import Path
import sqlite3
import sys

import pytest

from cvebeacon import updater as u
from cvebeacon.errors import CVEBeaconError
from cvebeacon.locking import RunLock
from cvebeacon.update_transaction import ensure_ready
from test_updater import transaction, signed, value
from test_dashboard_updates import updates
from test_dashboard_operations import login

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Native completion and permissions require Linux")


@pytest.mark.parametrize("restart", [False, True])
def test_failed_completion_barrier_blocks_writers_until_recovery(transaction, monkeypatch, restart):
    updater, native, config = transaction
    prefix = updater.policy.prefix
    journal = prefix / u.JOURNAL
    real = os.fsync
    durable = []
    def sync(fd):
        target = Path(os.readlink(f"/proc/self/fd/{fd}"))
        if target == prefix and journal.exists():
            record = journal.read_bytes()
            if json.loads(record)["phase"] == "complete":
                raise OSError(errno.EIO, "synthetic completion parent sync failure")
            real(fd)
            durable[:] = [record]
            return
        return real(fd)
    monkeypatch.setattr(os, "fsync", sync)
    with pytest.raises(u.UpdateError):
        updater.apply("0.1.1")
    assert json.loads(durable[0])["phase"] == "health"
    assert json.loads(journal.read_bytes())["phase"] == "complete"
    # Resource locks are released after the failure. The independent mutation
    # guard must still refuse both ordinary CLI and dashboard writes.
    with RunLock(config.watch.database.parent / u.LOCK_NAME):
        for command in ("run", "watch", "dashboard-write"):
            with pytest.raises(CVEBeaconError, match="recovery"):
                ensure_ready(command, prefix=prefix, running_version="0.1.1")
        assert value(config.watch.database) == "new"
    monkeypatch.setattr(os, "fsync", real)
    if restart:
        # A possible crash outcome is the last successfully synced health
        # record. No acknowledged writer was admitted against that old state.
        u.atomic_json(journal, json.loads(durable[0]))
    recovered = u.Updater(updater.policy, native, updater.releases)
    result = recovered.recover()
    assert result["result"] == ("rolled-back" if restart else "updated")
    ensure_ready("dashboard-write", prefix=prefix, running_version=result["version"])
    with sqlite3.connect(config.watch.database) as db:
        db.execute("UPDATE sentinel SET value='acknowledged after recovery'")
    assert recovered.recover()["result"] == "no-recovery-required"
    assert value(config.watch.database) == "acknowledged after recovery"

@pytest.mark.parametrize("barrier_fails", [True, False])
def test_writer_in_completion_rename_window_must_establish_durability(transaction, monkeypatch, barrier_fails):
    updater, native, config = transaction
    prefix, journal = updater.policy.prefix, updater.policy.prefix / u.JOURNAL
    real = os.fsync
    observed, durable = [], []
    checking = False
    def sync(fd):
        nonlocal checking
        if Path(os.readlink(f"/proc/self/fd/{fd}")) == prefix and journal.exists() and json.loads(journal.read_bytes())["phase"] == "complete":
            if checking:
                if barrier_fails:
                    raise OSError(errno.EIO, "synthetic guard completion sync failure")
                real(fd)
                durable.append(journal.read_bytes())
                return
            if not observed:
                checking = True
                try:
                    ensure_ready("dashboard-write", prefix=prefix, running_version="0.1.1")
                except CVEBeaconError:
                    observed.append("blocked")
                else:
                    observed.append("admitted")
                    with sqlite3.connect(config.watch.database) as db:
                        db.execute("UPDATE sentinel SET value='acknowledged in completion window'")
                finally:
                    checking = False
                # Only the guard's successful barrier can have persisted the
                # completed record before this simulated updater failure.
                raise OSError(errno.EIO, "synthetic updater completion sync failure")
        return real(fd)
    monkeypatch.setattr(os, "fsync", sync)
    assert updater.apply("0.1.1")["result"] == "updated"
    assert observed == (["blocked"] if barrier_fails else ["admitted"])
    if not barrier_fails:
        assert durable and json.loads(durable[0])["phase"] == "complete"
        monkeypatch.setattr(os, "fsync", real)
        # Restart with the completion persisted by the guard itself. Recovery
        # must preserve the later acknowledged write rather than old snapshots.
        u.atomic_json(journal, json.loads(durable[0]))
        assert u.Updater(updater.policy, native, updater.releases).recover()["result"] == "updated"
        assert value(config.watch.database) == "acknowledged in completion window"
        assert "restore" not in native.calls
