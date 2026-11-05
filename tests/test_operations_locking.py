"""Run-lock privacy, contention and cooperative interrupt regressions."""

from dataclasses import replace
import errno
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

import pytest

from cvebeacon import cli
from cvebeacon.errors import CVEBeaconError
from cvebeacon.locking import RunLock, run_lock_path
from test_dashboard_operations import make_config


def test_shared_watch_database_has_one_lock(tmp_path):
    config = make_config(tmp_path)
    other = replace(config, database_path=tmp_path / "other" / "state.db")
    assert run_lock_path(config) == run_lock_path(other)
    with RunLock(run_lock_path(config)):
        contender = RunLock(run_lock_path(other))
        assert not contender.acquire()


@pytest.mark.parametrize("unsafe", ["hardlink", "symlink", "directory"])
def test_lock_refuses_unsafe_files_without_changing_target(tmp_path, unsafe):
    target = tmp_path / "target"
    target.write_bytes(b"keep this content")
    target.chmod(0o600)
    path = tmp_path / "run.lock"
    if unsafe == "hardlink":
        os.link(target, path)
    elif unsafe == "symlink":
        path.symlink_to(target)
    else:
        path.mkdir()
    with pytest.raises(CVEBeaconError):
        with RunLock(path):
            pass
    assert target.read_bytes() == b"keep this content"


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and modes")
def test_lock_accepts_permissive_existing_file(tmp_path):
    path = tmp_path / "run.lock"
    path.write_bytes(b"holder metadata")
    path.chmod(0o666)
    with RunLock(path, command="scan"):
        pass


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
@pytest.mark.parametrize("umask", [0o022, 0o002])
def test_new_lock_file_uses_process_umask(tmp_path, umask):
    path = tmp_path / "run.lock"
    previous = os.umask(umask)
    try:
        with RunLock(path):
            pass
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o666 & ~umask


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_relaxed_file_validation_accepts_a_private_mode(tmp_path):
    from cvebeacon.private_storage import private_file, validate_file
    path = tmp_path / "run.lock"
    path.write_bytes(b"")
    path.chmod(0o600)
    descriptor = private_file(path, owner_only=False)
    try:
        details = validate_file(descriptor, path, owner_only=False)
    finally:
        os.close(descriptor)
    assert stat.S_IMODE(details.st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_job_history_still_requires_a_private_file(tmp_path):
    from cvebeacon.dashboard_jobs import JobStore
    directory = tmp_path / "dashboard-jobs"
    # A private directory, so the file check itself is what refuses.
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "dashboard-jobs.db"
    path.write_bytes(b"")
    path.chmod(0o666)
    with pytest.raises(CVEBeaconError):
        JobStore(directory).initialize()


def test_lock_rejects_symlinked_directory_before_creating_targets(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "link").symlink_to(target, target_is_directory=True)
    with pytest.raises(CVEBeaconError):
        with RunLock(tmp_path / "link" / "new" / "run.lock"):
            pass
    assert list(target.iterdir()) == []


def test_windows_lock_keeps_byte_zero_separate_and_clears_before_unlock(tmp_path, monkeypatch):
    lock = RunLock(tmp_path / "run.lock")
    events = []
    def take(fd):
        assert os.fstat(fd).st_size == 0
        events.append("locked")
    def release(fd):
        os.lseek(fd, 1, os.SEEK_SET)
        assert os.read(fd, 4096) == b""
        events.append("unlocked")
    monkeypatch.setattr(lock, "_lock", take)
    monkeypatch.setattr(lock, "_unlock", release)
    assert lock.acquire()
    assert lock.path.read_bytes().startswith(b"\0{")
    lock.release()
    assert events == ["locked", "unlocked"]


def test_contention_without_readable_metadata_is_still_busy(tmp_path, monkeypatch):
    lock = RunLock(tmp_path / "run.lock")
    def busy(fd):
        raise BlockingIOError()
    monkeypatch.setattr(lock, "_lock", busy)
    monkeypatch.setattr(os, "read", lambda *a: (_ for _ in ()).throw(PermissionError()))
    assert not lock.acquire()
    assert lock.probe() is not None


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes")
def test_lock_accepts_preexisting_world_writable_directory(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with RunLock(shared / "run.lock"):
        assert (shared / "run.lock").exists()
    assert stat.S_IMODE(shared.stat().st_mode) == 0o777


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes")
@pytest.mark.parametrize("mode", [0o770, 0o775, 0o777, 0o1777])
def test_job_storage_accepts_a_shared_parent_directory(tmp_path, mode):
    from cvebeacon.dashboard_jobs import JobStore, _JobLog
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(mode)
    directory = shared / "dashboard-jobs"
    with RunLock(shared / "run.lock"):
        store = JobStore(directory)
        job = store.create("scan", "admin", ["scan"])
        with_log = _JobLog(job.log_path)
        with_log.write(b"shared parent works")
        with_log.close()
        assert store.log_tail(job) == "shared parent works"
    assert stat.S_IMODE(shared.stat().st_mode) == mode
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory ownership")
def test_lock_accepts_foreign_owned_world_writable_mount(tmp_path, monkeypatch):
    real_lstat = Path.lstat
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    def mounted_owner(path, *args, **kwargs):
        details = real_lstat(path, *args, **kwargs)
        if path == shared or (path in shared.parents and path != Path("/")):
            values = list(details)
            values[4] = os.geteuid() + 1
            return os.stat_result(values)
        return details
    monkeypatch.setattr(Path, "lstat", mounted_owner)
    with RunLock(shared / "run.lock"):
        assert (shared / "run.lock").stat().st_uid == os.geteuid()


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes")
@pytest.mark.parametrize("mask", [0o002, 0o022])
def test_doctor_then_scan_creates_private_state_directory(tmp_path, monkeypatch, mask):
    config = make_config(tmp_path)
    config = replace(config, database_path=tmp_path / "state" / "state.db")
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    state_directory = Path(config.database_path).resolve().parent
    assert not state_directory.exists()
    tmp_path.chmod(0o700)
    monkeypatch.setattr(cli, "_run_scan", lambda *a, **k: 17)
    previous = os.umask(mask)
    try:
        assert cli.main(["--config", str(config.config_path), "doctor"]) == 0
        assert cli.main(["--config", str(config.config_path), "scan"]) == 17
        assert stat.S_IMODE(state_directory.stat().st_mode) == 0o700
    finally:
        os.umask(previous)


def test_lock_metadata_write_failure_is_a_controlled_cli_error(tmp_path, monkeypatch, capsys):
    config = make_config(tmp_path)
    called = []
    monkeypatch.setattr(cli, "_run_scan", lambda *a, **k: called.append(True) or 17)
    real_write = os.write
    def full_disk(fd, data):
        if b'"account"' in data:
            raise OSError(errno.ENOSPC, "synthetic full disk")
        return real_write(fd, data)
    monkeypatch.setattr(os, "write", full_disk)
    assert cli.main(["--config", str(config.config_path), "scan"]) == 2
    error = capsys.readouterr().err
    assert error.startswith("error: cannot write the operation lock metadata")
    assert "Traceback" not in error
    assert len(error.strip().splitlines()) == 1
    assert called == []


@pytest.mark.parametrize("operation", ["report", "unreport"])
def test_report_commands_take_shared_lock(tmp_path, capsys, operation):
    config = make_config(tmp_path)
    with RunLock(run_lock_path(config)):
        assert cli.main(["--config", str(config.config_path), "watch", operation, "CVE-2026-1234"]) == 2
    assert "another run is in progress" in capsys.readouterr().err


def test_windows_break_handler_uses_keyboard_interrupt_cleanup(monkeypatch):
    handlers = {}
    monkeypatch.setattr(signal, "SIGBREAK", 21, raising=False)
    monkeypatch.setattr(signal, "signal", lambda signum, handler: handlers.setdefault(signum, handler))
    monkeypatch.setattr(signal, "getsignal", lambda signum: signal.SIG_DFL)
    def run(args):
        handlers[21](21, None)
    monkeypatch.setattr(cli, "run", run)
    assert cli.main(["schedule", "status"]) == 130


def test_cli_progress_is_line_buffered_for_frozen_interpreters(tmp_path, monkeypatch):
    from io import BytesIO, TextIOWrapper
    output = BytesIO()
    stream = TextIOWrapper(output, encoding="utf-8", newline="\n")
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli, "run", lambda args: print("progress") or 0)
    assert cli.main(["schedule", "status"]) == 0
    assert output.getvalue() == b"progress\n"


def test_real_process_lock_conflict_and_probe_are_controlled(tmp_path):
    path = tmp_path / "run.lock"
    with RunLock(path, command="scan"):
        result = subprocess.run([
            sys.executable, "-c",
            "import sys; from cvebeacon.locking import RunLock; "
            "lock=RunLock(sys.argv[1]); print(lock.acquire()); print(lock.probe())",
            str(path),
        ], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("False\n")
    assert "running scan" in result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX SQLite record locks")
def test_rejected_run_lock_hardlink_preserves_live_database_transaction(tmp_path):
    from cvebeacon.watch.users import UserStore
    database = tmp_path / "users.db"
    users = UserStore(database)
    users.initialize()
    def writer():
        result = subprocess.run([
            sys.executable, "-c",
            "import sqlite3, sys\n"
            "db=sqlite3.connect(sys.argv[1], timeout=0)\n"
            "try:\n"
            "    db.execute('BEGIN IMMEDIATE')\n"
            "except sqlite3.OperationalError as exc:\n"
            "    assert exc.sqlite_errorcode == sqlite3.SQLITE_BUSY\n"
            "    print('blocked')\n"
            "else:\n"
            "    db.rollback(); print('acquired')\n",
            str(database),
        ], capture_output=True, text=True, check=True, timeout=10)
        return result.stdout.strip()
    with users.transaction():
        assert writer() == "blocked"
        path = tmp_path / "run.lock"
        os.link(database, path)
        with pytest.raises(CVEBeaconError):
            RunLock(path).acquire()
        assert writer() == "blocked"
    assert writer() == "acquired"
