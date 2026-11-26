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
        assert u.read_status(config)["last_update"]["recovery_reason"] == (
            "quiesce-failed" if obstacle == "monitor" else "lock-failed")
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

        def stream(self, *args, timeout, **kwargs):
            requests.append(timeout)
            assert 0 < timeout <= min(2, 120 - clock[0])
            if failure == "late":
                clock[0] = 121.0
            elif failure == "restart":
                start_id[0] += 1
            elif failure == "relisten":
                listener[0] = str(int(listener[0]) + 1)

            from contextlib import nullcontext
            return nullcontext(SimpleNamespace(
                status_code=200, headers={}, iter_raw=lambda: [b'{"status":"ok","version":"0.1.1","pid":42}']))

    monkeypatch.setattr(u.httpx, "Client", Client)
    monkeypatch.setattr(u.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(u.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    with pytest.raises(u.UpdateError, match="health probe failed"):
        native.probe("0.1.1")
    assert clock[0] == (121 if failure == "late" else 120)
    assert len(clients) == len(requests)
    assert all(0 < timeout <= 120 - now for now, timeout in timeouts)


@pytest.mark.parametrize("failure", ["malformed", "unclaimable", "timeout"])
def test_request_service_classifies_failures_and_keeps_details_private(transaction, monkeypatch, failure):
    updater, native, config = transaction
    request = updater.policy.data / u.REQUEST
    private = "synthetic private request text"
    if failure == "malformed":
        request.write_text(private, encoding="utf-8", newline="\n")
    else:
        u.atomic_json(request, {"version": "0.1.1", "user": "admin", "time": u.stamp()})
    if failure == "unclaimable":
        original_rename = os.rename

        def rename(source, destination, **kwargs):
            if source == request:
                raise PermissionError(private)
            return original_rename(source, destination, **kwargs)

        monkeypatch.setattr(os, "rename", rename)
    if failure == "timeout":
        def preflight(venv):
            raise subprocess.TimeoutExpired(private, 1)
        monkeypatch.setattr(native, "preflight", preflight)
    args = SimpleNamespace(update_command="apply", from_request=True, version=None,
                           config=str(config.config_path), policy="unused")
    monkeypatch.setattr(u, "unsupported_reason", lambda: None)
    monkeypatch.setattr(u.Policy, "read", lambda path: updater.policy)
    monkeypatch.setattr(u, "Updater", lambda policy: updater)
    monkeypatch.setattr(u.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0))
    assert u.cli(args) == 0
    expected = {"malformed": "request-invalid", "unclaimable": "request-claim-failed", "timeout": "preflight-failed"}[failure]
    status = u.read_status(config)
    assert status["last_request"]["reason"] == expected
    assert _audit(updater)[-1]["reason"] == expected
    assert private not in json.dumps(status) + json.dumps(_audit(updater))


@pytest.mark.parametrize("operation", ["apply", "recover"])
def test_update_lock_open_errors_are_classified_as_advisory_attempts(transaction, monkeypatch, operation):
    updater, _, config = transaction

    def cannot_open(lock):
        raise PermissionError("synthetic private lock path")

    monkeypatch.setattr(u.RunLock, "acquire", cannot_open)
    with pytest.raises(PermissionError):
        getattr(updater, operation)()
    assert u.read_status(config)["last_attempt"]["reason"] == "lock-failed"
    assert _audit(updater)[-1]["reason"] == "lock-failed"
    assert not (updater.policy.prefix / "update-result.json").exists()


@pytest.mark.parametrize("operation", ["apply", "recover"])
def test_contender_cannot_replace_the_newly_written_transaction_result(transaction, monkeypatch, operation):
    updater, native, config = transaction
    contender = type(updater)(updater.policy, native, updater.releases)
    original = contender.event
    lock = RunLock(updater.policy.prefix / "update.lock")
    assert lock.acquire()

    def finish_original(*args, **kwargs):
        lock.release()
        assert updater.apply("0.1.1")["result"] == "updated"
        return original(*args, **kwargs)

    monkeypatch.setattr(contender, "event", finish_original)
    try:
        with pytest.raises(RunInProgress):
            getattr(contender, operation)()
    finally:
        lock.release()
    mirror = json.loads((updater.policy.prefix / "update-result.json").read_text(encoding="utf-8"))
    status = u.read_status(config)
    assert mirror["result"] == status["last_update"]["result"] == "updated"
    assert status["last_attempt"]["reason"] == "lock-failed"


@pytest.mark.parametrize("obstacle", ["lock", "preflight"])
def test_invalid_manual_version_never_enters_status_or_audit(transaction, monkeypatch, obstacle):
    updater, native, config = transaction
    private = "synthetic private version text"
    lock = RunLock(updater.policy.prefix / "update.lock")

    def preflight(venv):
        raise u.UpdateError("synthetic private exception details")

    monkeypatch.setattr(native, "preflight", preflight)
    if obstacle == "lock":
        assert lock.acquire()
    try:
        with pytest.raises(u.UpdateError, match="release version"):
            updater.apply(private)
    finally:
        lock.release()
    updater.target = private
    updater.event("check")
    status, audit = u.read_status(config), _audit(updater)
    assert status["last_attempt"]["reason"] == "version-invalid"
    assert status["last_attempt"]["version"] is audit[-1]["version"] is None
    assert private not in json.dumps(status) + json.dumps(audit)
    assert "synthetic private exception details" not in json.dumps(status) + json.dumps(audit)


@pytest.mark.parametrize("failure", ["timer", "archive"])
def test_finalization_failure_keeps_completed_outcome_and_records_phase(transaction, monkeypatch, failure):
    updater, _, config = transaction
    attr = "_resume_timers" if failure == "timer" else "_archive"

    def fail(*args):
        raise OSError("synthetic private finalization details")

    with monkeypatch.context() as patch:
        patch.setattr(updater, attr, fail)
        assert updater.apply("0.1.1")["result"] == "updated"
    expected = "finalize-timers-failed" if failure == "timer" else "finalize-archive-failed"
    entry = u.read_status(config)["last_update"]
    assert entry["result"] == "updated" and entry["finalization_reason"] == expected
    assert _audit(updater)[-1]["reason"] == expected
    assert updater.recover()["result"] == "updated"
    assert "finalization_reason" not in u.read_status(config)["last_update"]


def test_pending_adoption_failure_is_classified(transaction, monkeypatch):
    updater, native, config = transaction
    updater._begin("0.1.0", "0.1.0", (), kind="adopt")
    (updater.policy.prefix / ".venv").mkdir()

    def preflight(venv):
        raise subprocess.TimeoutExpired("synthetic private adoption command", 1)

    monkeypatch.setattr(native, "preflight", preflight)
    with pytest.raises(u.UpdateError, match="recovery remains incomplete"):
        updater.recover()
    assert u.read_status(config)["last_update"]["recovery_reason"] == "adopt-failed"
    assert any(event.get("reason") == "adopt-failed" for event in _audit(updater))
    assert (updater.policy.prefix / u.JOURNAL).exists()


def test_verified_recovery_clears_incomplete_without_losing_original_update_reason(transaction, monkeypatch):
    updater, native, config = transaction
    native.failure = "migrate"

    def cannot_start(units):
        raise u.UpdateError("synthetic partial start")

    with monkeypatch.context() as patch:
        patch.setattr(native, "start", cannot_start)
        with pytest.raises(u.UpdateError, match="recovery remains incomplete"):
            updater.apply("0.1.1")
    failed = u.read_status(config)["last_update"]
    assert failed["reason"] == "migrate-failed" and failed["recovery_reason"] == "start-failed"
    assert type(updater)(updater.policy, native, updater.releases).recover()["result"] == "rolled-back"
    recovered = u.read_status(config)["last_update"]
    assert recovered["reason"] == "migrate-failed" and "recovery_reason" not in recovered
    assert value(config.watch.database) == "old"


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


@pytest.mark.parametrize("config_form", ["relative", "absolute"])
@pytest.mark.parametrize("reason", ["policy-invalid", "recovery-incomplete"])
def test_invalid_policy_reports_only_to_the_system_journal(transaction, monkeypatch, caplog, config_form, reason):
    updater, _, config = transaction
    request = updater.policy.data / u.REQUEST
    u.atomic_json(request, {"version": "0.1.1", "user": "admin", "time": u.stamp()})
    original = request.stat().st_ino, request.read_bytes()
    (updater.policy.data).chmod(0o700)
    args = SimpleNamespace(update_command="apply", from_request=True,
                           config=str(config.config_path) if config_form == "absolute" else config.config_path.name,
                           policy="unused")
    monkeypatch.setattr(u, "unsupported_reason", lambda: None)
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    def policy(path):
        raise u.UpdateError("synthetic private policy error", reason_code=reason)

    monkeypatch.setattr(u.Policy, "read", policy)
    stopped = []

    def stop(argv, **kwargs):
        stopped.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(u.subprocess, "run", stop)
    assert u.cli(args) == 0
    assert reason in caplog.text and "synthetic private policy error" not in caplog.text
    status = u.read_status(config)
    assert "last_request" not in status
    assert (request.stat().st_ino, request.read_bytes()) == original
    assert stopped == [["systemctl", "stop", "cvebeacon-update.path"]]


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


def test_long_multilingual_notes_cannot_hide_diagnostic_status(transaction, monkeypatch):
    updater, _, config = transaction
    release = u.Release("0.1.1", "🚀漢" * 32768, ())
    monkeypatch.setattr(updater.releases, "check", lambda *args: release)

    def fail(*args):
        raise u.UpdateError("synthetic private verification details", reason_code="verify-signature")

    monkeypatch.setattr(updater.releases, "verify", fail)
    with pytest.raises(u.UpdateError):
        updater.apply("0.1.1")
    status = u.read_status(config)
    assert status["last_update"]["reason"] == "verify-signature"
    assert status["notes"] and release.notes.startswith(status["notes"])
    assert (config.config_path.parent / u.UPDATE_STATUS_DIR / u.STATUS).stat().st_size <= 131072


def test_every_consumed_request_gets_a_terminal_result(transaction):
    updater, _, config = transaction
    u.atomic_json(updater.policy.data / u.REQUEST, {"version": "0.1.1", "user": "admin", "time": u.stamp()})
    assert updater.apply(from_request=True)["result"] == "updated"
    entry = u.read_status(config)["last_request"]
    assert entry["version"] == "0.1.1" and entry["result"] == "updated" and "reason" not in entry
