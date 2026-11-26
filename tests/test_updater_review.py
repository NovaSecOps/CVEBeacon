"""Regression cases for the updater's recovery and diagnostic boundaries."""
import errno
import sqlite3
import sys

import pytest

from cvebeacon import update_state


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Native updates are Linux-only")


@pytest.mark.parametrize("code", [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED,
                                 sqlite3.SQLITE_BUSY_SNAPSHOT, sqlite3.SQLITE_LOCKED_SHAREDCACHE])
@pytest.mark.parametrize("direct", [False, True])
def test_backup_worker_times_confirmed_primary_and_extended_contention(tmp_path, monkeypatch, code, direct):
    clock = [0.0]
    attempts = []

    class Source:
        def backup(self, destination, *, pages, progress, sleep):
            attempts.append(clock[0])
            assert pages > 0
            if direct:
                error = sqlite3.OperationalError("synthetic lock contention")
                error.sqlite_errorcode = code
                raise error
            for _ in range(5):
                progress(code, 1000, 1000)
                clock[0] += sleep

        def close(self):
            pass

    monkeypatch.setattr(update_state.sqlite3, "connect", lambda *args, **kwargs: Source())
    monkeypatch.setattr(update_state.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(update_state.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    with pytest.raises(update_state.BackupDatabaseBusy):
        update_state._backup_copy_worker(tmp_path / "source", tmp_path / "destination", wait_seconds=0.2)
    assert clock[0] >= 0.2 and attempts[0] == 0
    assert len(attempts) > 1 if direct else len(attempts) == 1


@pytest.mark.parametrize("terminal_failure", [False, True])
def test_backup_worker_allows_progress_near_expiry_and_preserves_terminal_errors(tmp_path, monkeypatch, terminal_failure):
    clock = [0.0]
    destination = tmp_path / "destination"
    destination.touch()

    class Connection:
        def backup(self, target, *, pages, progress, sleep):
            assert 0 < pages < 1000
            progress(sqlite3.SQLITE_BUSY, 1000, 1000)
            clock[0] = 0.29
            if terminal_failure:
                clock[0] = 0.3
                raise OSError(errno.EIO, "synthetic terminal write error")
            progress(sqlite3.SQLITE_OK, 1000 - pages, 1000)
            clock[0] = 1.0
            progress(sqlite3.SQLITE_BUSY, 1000 - pages, 1000)
            clock[0] = 1.29
            progress(sqlite3.SQLITE_DONE, 0, 1000)

        def execute(self, query):
            clock[0] = 9.0
            return self

        def fetchone(self):
            return ("ok",)

        def close(self):
            pass

    monkeypatch.setattr(update_state.sqlite3, "connect", lambda *args, **kwargs: Connection())
    monkeypatch.setattr(update_state.time, "monotonic", lambda: clock[0])
    if terminal_failure:
        with pytest.raises(OSError, match="terminal write error"):
            update_state._backup_copy_worker(tmp_path / "source", destination, wait_seconds=0.3)
    else:
        update_state._backup_copy_worker(tmp_path / "source", destination, wait_seconds=0.3)
        assert clock[0] == 9.0


def test_backup_parent_preserves_a_terminal_failure_when_a_busy_worker_exits(tmp_path, monkeypatch):
    import io

    class ExitingWorker:
        def __init__(self):
            self.args = ["snapshot worker"]
            self.stdout = io.BytesIO(b"busy\n")
            self.returncode = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stdout.close()

        def communicate(self, *args, **kwargs):
            self.returncode = 1
            return b"", b""

        def poll(self):
            status, self.returncode = self.returncode, 1
            return status

        def wait(self, *args, **kwargs):
            return 1

    worker = ExitingWorker()
    monkeypatch.setattr(update_state.subprocess, "Popen", lambda *args, **kwargs: worker)
    moments = iter((0.0, 0.3))
    monkeypatch.setattr(update_state.time, "monotonic", lambda: next(moments))
    with pytest.raises(update_state.SnapshotError, match="snapshot operation failed") as error:
        update_state._copy_sqlite_bounded(tmp_path / "source", tmp_path / "destination", wait_seconds=0.3)
    assert not isinstance(error.value, update_state.BackupDatabaseBusy)
