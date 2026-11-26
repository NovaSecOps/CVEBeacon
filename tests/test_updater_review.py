"""Regression cases for the updater's recovery and diagnostic boundaries."""
import errno
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from cvebeacon import update_state, updater as u


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


@pytest.mark.parametrize("exit_code,stdout,stderr", [
    (1, b"", b"permission denied: no crontab for service"),
    (1, b"permission denied", b"no crontab for service"),
    (1, b"", b"no crontab for another"),
    (2, b"", b"no crontab for service"),
])
def test_root_crontab_check_accepts_only_the_named_absence_diagnostic(tmp_path, monkeypatch, exit_code, stdout, stderr):
    import pwd

    account = SimpleNamespace(pw_name="service", pw_uid=1234, pw_gid=1234)
    monkeypatch.setattr(pwd, "getpwnam", lambda login: account)
    native = u.Native(u.Policy(tmp_path, tmp_path / "config", tmp_path, "service"))
    monkeypatch.setattr(u.shutil, "which", lambda *args, **kwargs: "/usr/bin/crontab")
    monkeypatch.setattr(native, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], exit_code, stdout, stderr))
    with pytest.raises(u.UpdateError) as error:
        native.managed_cron()
    assert error.value.reason_code == "preflight-crontab-unreadable"


def test_crontab_uses_the_policy_login_and_refuses_a_changed_lookup(tmp_path, monkeypatch):
    import pwd

    account = SimpleNamespace(pw_name="canonical", pw_uid=1234, pw_gid=1234)
    monkeypatch.setattr(pwd, "getpwnam", lambda login: account)
    native = u.Native(u.Policy(tmp_path, tmp_path / "config", tmp_path, "service"))
    monkeypatch.setattr(u.shutil, "which", lambda *args, **kwargs: "/usr/bin/crontab")
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 1, b"", b"no crontab for service\n")

    monkeypatch.setattr(native, "run", run)
    native.managed_cron()
    assert calls[0][0] == ["crontab", "-l", "-u", "service"]
    assert not calls[0][1].get("service", False)
    assert calls[0][1]["env"]["LC_ALL"] == "C"
    monkeypatch.setattr(pwd, "getpwnam", lambda login: SimpleNamespace(
        pw_name="canonical", pw_uid=1235, pw_gid=1234))
    with pytest.raises(u.UpdateError) as error:
        native.managed_cron()
    assert error.value.reason_code == "preflight-crontab-unreadable"
    assert len(calls) == 1


@pytest.mark.parametrize("failure", ["late", "timeouts", "restart", "relisten"])
def test_health_probe_shares_deadline_and_rechecks_process_and_listener(tmp_path, monkeypatch, failure):
    native = object.__new__(u.Native)
    native.policy = u.Policy(tmp_path, tmp_path / "config", tmp_path, "service")
    clock = [0.0]
    start_id = [111]
    listener = ["10"]
    clients = []
    requests = []
    timeouts = []

    def systemctl(*, timeout=600):
        timeouts.append((clock[0], timeout))
        if failure == "timeouts":
            clock[0] += timeout
            raise subprocess.TimeoutExpired("systemctl", timeout)
        return 42

    native.dashboard_pid = systemctl
    native.process_start = lambda pid: start_id[0]
    native.listener_sockets = lambda pid: {listener[0]}
    native.owns_listener = lambda pid: True

    class Client:
        def __init__(self, *args, **kwargs):
            clients.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Transport(Client):
        def request_once(self, *args, timeout, **kwargs):
            requests.append(timeout)
            assert 0 < timeout <= min(2, 120 - clock[0])
            if failure == "late":
                clock[0] = 121.0
            elif failure == "restart":
                start_id[0] += 1
            elif failure == "relisten":
                listener[0] = str(int(listener[0]) + 1)
            return SimpleNamespace(status_code=200, body=b'{"status":"ok","version":"0.1.1","pid":42}')

    monkeypatch.setattr(u.httpx, "Client", Client)
    monkeypatch.setattr(u, "HttpClient", Transport)
    monkeypatch.setattr(u.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(u.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    with pytest.raises(u.UpdateError, match="health probe failed"):
        native.probe("0.1.1")
    assert clock[0] == (121 if failure == "late" else 120)
    assert len([client for client in clients if type(client) is Client]) == len(requests)
    assert all(0 < timeout <= 120 - now for now, timeout in timeouts)
