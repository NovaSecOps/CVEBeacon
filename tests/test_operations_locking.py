"""Run-lock privacy, contention and cooperative interrupt regressions."""

from dataclasses import replace
import os
import signal
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


@pytest.mark.parametrize("unsafe", ["hardlink", "symlink", "mode", "directory"])
def test_lock_refuses_unsafe_files_without_changing_target(tmp_path, unsafe):
    target = tmp_path / "target"
    target.write_bytes(b"keep this content")
    target.chmod(0o600)
    path = tmp_path / "run.lock"
    if unsafe == "hardlink":
        os.link(target, path)
    elif unsafe == "symlink":
        path.symlink_to(target)
    elif unsafe == "mode":
        path.write_bytes(b"unsafe")
        path.chmod(0o666)
    else:
        path.mkdir()
    with pytest.raises(CVEBeaconError):
        with RunLock(path):
            pass
    assert target.read_bytes() == b"keep this content"


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
    stream = TextIOWrapper(output, encoding="utf-8")
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
