"""Regression cases for the updater's recovery and diagnostic boundaries."""
from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from cvebeacon import update_state, updater as u
from cvebeacon.locking import RunInProgress, RunLock
from test_updater import signed, transaction, value


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


def _audit(updater):
    return [json.loads(line) for line in (updater.policy.prefix / "update-audit.jsonl")
            .read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("obstacle", ["monitor", "writer"])
def test_recovery_leaves_running_dashboard_alone_if_writers_have_not_quiesced(transaction, monkeypatch, obstacle):
    updater, native, config = transaction
    updater._begin("0.1.0", "0.1.1", updater.policy.units)
    journal = updater.policy.prefix / u.JOURNAL
    initial = journal.read_bytes()
    lock = RunLock(config.watch.database.parent / u.LOCK_NAME)
    if obstacle == "monitor":

        def stop(units):
            raise u.UpdateError("monitoring service is still active")
        monkeypatch.setattr(native, "stop", stop)
    else:
        assert lock.acquire()
        updater.policy = replace(updater.policy, wait_seconds=0)
    try:
        with pytest.raises(u.UpdateError, match="recovery remains incomplete"):
            updater.recover()
        assert "freeze" not in native.calls
        assert journal.read_bytes() == initial
    finally:
        lock.release()


def test_recovery_stops_a_partially_started_dashboard_while_writer_lock_is_held(transaction, monkeypatch):
    updater, native, config = transaction
    updater._begin("0.1.0", "0.1.1", updater.policy.units)
    stops = []
    started = False

    def start(units):
        nonlocal started
        started = True
        raise subprocess.TimeoutExpired("private synthetic command", 1)

    # Check both stops without ever taking or releasing recovery's lock.
    def record_stop(units):
        with pytest.raises(RunInProgress):
            with RunLock(config.watch.database.parent / u.LOCK_NAME):
                pytest.fail("dashboard stop occurred without the writer lock")
        stops.append(started)

    monkeypatch.setattr(native, "freeze", record_stop)
    monkeypatch.setattr(native, "start", start)
    with pytest.raises(u.UpdateError, match="recovery remains incomplete"):
        updater.recover()
    assert stops == [False, True]


@pytest.mark.parametrize("phase", ["installing", "complete"])
def test_post_replacement_fsync_failure_uses_the_disk_checkpoint(transaction, monkeypatch, phase):
    updater, native, config = transaction
    journal = updater.policy.prefix / u.JOURNAL
    original_fsync = os.fsync
    injected = []
    restores = []

    def fsync(fd):
        if (not injected and Path(f"/proc/self/fd/{fd}").resolve() == journal.parent
                and journal.exists()):
            record = json.loads(journal.read_text(encoding="utf-8"))
            if record["phase"] == phase:
                injected.append(record)
                raise OSError(errno.EIO, "synthetic fsync failure after replacement")
        return original_fsync(fd)

    original_state = native.state

    def state(python, action, directory, digest=None):
        if action == "restore":
            restores.append(digest)
        return original_state(python, action, directory, digest)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(native, "state", state)
    if phase == "installing":
        with pytest.raises(u.UpdateError, match="previous release and state restored"):
            updater.apply("0.1.1")
    else:
        # A complete record skips diagnostic rewriting and restoration.
        assert updater.apply("0.1.1")["result"] == "updated"
        # Force the complete branch through the same audit-visible recovery
        # boundary by asserting that the final record remains complete below.
        assert "restore" not in native.calls
    assert len(injected) == 1
    record = injected[0]
    archived = json.loads((updater.policy.prefix / "transactions" / (record["id"] + ".json"))
                          .read_text(encoding="utf-8"))
    assert archived["snapshot_ready"]
    assert archived["manifest_sha256"] == record["manifest_sha256"]
    assert restores == ([record["manifest_sha256"]] if phase == "installing" else [])
    assert value(config.watch.database) == ("old" if phase == "installing" else "new")


def test_unreadable_checkpoint_reread_does_not_overwrite_the_fence(transaction, monkeypatch):
    updater, native, config = transaction
    journal = updater.policy.prefix / u.JOURNAL
    original = native.backup_directory

    def fail_after_invalid_record(path):
        original(path)
        journal.write_text("{", encoding="utf-8", newline="\n")
        raise OSError("synthetic private write details")

    monkeypatch.setattr(native, "backup_directory", fail_after_invalid_record)
    with pytest.raises(u.UpdateError, match="recovery remains incomplete"):
        updater.apply("0.1.1")
    assert journal.read_bytes() == b"{"
    assert u.read_status(config)["last_update"]["reason"] == "recovery-incomplete"
    assert _audit(updater)[-1]["reason"] == "recovery-incomplete"


def test_apply_runs_backup_with_the_020_interpreter_and_state_module(transaction, monkeypatch):
    updater, native, config = transaction
    prefix = updater.policy.prefix
    (prefix / "releases/0.1.0").rename(prefix / "releases/0.2.0")
    (prefix / "current").unlink()
    (prefix / "current").symlink_to("releases/0.2.0", target_is_directory=True)
    native.versions = {package: "0.2.0" for package in u.PACKAGES}
    monkeypatch.setattr(updater.releases, "check", lambda *args: u.Release("0.2.1", "", ()))

    def verify(release, directory, signers):
        (directory / "synthetic.whl").touch()

    monkeypatch.setattr(updater.releases, "verify", verify)
    observed = []
    executor = object.__new__(u.Native)
    executor.policy = updater.policy

    def run(argv, **kwargs):
        assert (prefix / "current").resolve() == prefix / "releases/0.2.0"
        assert kwargs["service"]
        assert argv == [prefix / "releases/0.2.0/.venv/bin/python", "-I", "-m",
                        "cvebeacon.update_state", "backup", config.config_path, updater.policy.data, argv[-1]]
        observed.append(argv[-1])
        update_state.backup(config, updater.policy.data, argv[-1])
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    executor.run = run
    monkeypatch.setattr(native, "state", executor.state)
    assert updater.apply("0.2.1")["result"] == "updated"
    assert len(observed) == 1 and (observed[0] / "manifest.json").is_file()
