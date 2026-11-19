"""Publication rollback must preserve failures and attempt every owned name."""

import errno
import os
from pathlib import Path

import pytest

from cvebeacon import cli, locking
from cvebeacon.errors import CVEBeaconError
from cvebeacon.locking import RunLock
from test_dashboard_operations import make_config


@pytest.fixture(autouse=True)
def synthetic_holder_identity(monkeypatch):
    monkeypatch.setattr(locking, "_account_name", lambda: "cvebeacon")
    monkeypatch.setattr(locking, "_host_name", lambda: "example.com")


@pytest.mark.parametrize("stage,error", [
    ("temporary-write", errno.ENOSPC), ("temporary-write", errno.EIO),
    ("link", errno.EOPNOTSUPP), ("reference-write", errno.ENOSPC),
])
@pytest.mark.parametrize("persistent", [False, True])
def test_publication_failure_and_cleanup_refusal_preserve_original_error(tmp_path, monkeypatch, stage, error, persistent):
    original_write, original_unlink = os.write, Path.unlink
    publication_error = OSError(error, "synthetic original publication failure")
    cleanup_attempts, failed = [], []
    def write(fd, data):
        if ((stage == "temporary-write" and b'"account"' in data)
                or (stage == "reference-write" and b'"owner_token"' in data and b'"account"' not in data)):
            failed.append(True)
            raise publication_error
        return original_write(fd, data)
    def link(source, target):
        failed.append(True)
        raise publication_error
    def unlink(path, *args, **kwargs):
        if failed and ".owner." in path.name:
            cleanup_attempts.append(path.name)
            if persistent or len(cleanup_attempts) == 1:
                raise PermissionError(errno.EACCES, "synthetic cleanup refusal")
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(locking.os, "write", write)
    if stage == "link":
        monkeypatch.setattr(locking.os, "link", link)
    monkeypatch.setattr(Path, "unlink", unlink)
    lock = RunLock(tmp_path / "run.lock")
    try:
        if stage == "link" and not persistent:
            assert lock.acquire()
            assert RunLock(lock.path).snapshot()["description"] == "holder unavailable"
        else:
            with pytest.raises(CVEBeaconError) as caught:
                lock.acquire()
            assert caught.value.__cause__ is publication_error
            assert RunLock(lock.path).probe() is None
        assert len(cleanup_attempts) >= 2
        assert lock._owner_descriptor is None
        assert lock._temporary_descriptor is None
        if not persistent:
            assert list(tmp_path.glob("run.lock.owner.*")) == []
    finally:
        lock.release()


def test_reference_write_failure_rolls_back_the_published_record(tmp_path, monkeypatch):
    original = os.write
    error = OSError(errno.ENOSPC, "synthetic reference write failure")
    def write(fd, data):
        if b'"owner_token"' in data and b'"account"' not in data:
            raise error
        return original(fd, data)
    monkeypatch.setattr(locking.os, "write", write)
    lock = RunLock(tmp_path / "run.lock")
    with pytest.raises(CVEBeaconError) as caught:
        lock.acquire()
    assert caught.value.__cause__ is error
    assert lock._owner_descriptor is None and lock._descriptor is None
    assert list(tmp_path.glob("run.lock.owner.*")) == []
    assert RunLock(lock.path).probe() is None


@pytest.mark.parametrize("cleanup_error", [OSError(errno.EIO, "synthetic completed close with error"),
                                          RuntimeError("synthetic unexpected cleanup failure")],
                         ids=["io-error", "unexpected-error"])
def test_close_failure_does_not_mask_write_error_or_skip_rollback(tmp_path, monkeypatch, cleanup_error):
    original_open, original_close, original_write = locking.private_file, os.close, os.write
    temporary_fds, cleanup_errors = set(), []
    error = OSError(errno.ENOSPC, "synthetic private write failure")
    def open_file(path, **kwargs):
        fd = original_open(path, **kwargs)
        if path.name.endswith(".tmp"):
            temporary_fds.add(fd)
        return fd
    def close(fd):
        original_close(fd)
        if fd in temporary_fds and not cleanup_errors:
            cleanup_errors.append(True)
            raise cleanup_error
    def write(fd, data):
        if b'"account"' in data:
            raise error
        return original_write(fd, data)
    monkeypatch.setattr(locking, "private_file", open_file)
    monkeypatch.setattr(locking.os, "close", close)
    monkeypatch.setattr(locking.os, "write", write)
    lock = RunLock(tmp_path / "run.lock")
    with pytest.raises(CVEBeaconError) as caught:
        lock.acquire()
    assert caught.value.__cause__ is error
    assert cleanup_errors and list(tmp_path.glob("run.lock.owner.*")) == []
    assert lock._owner_descriptor is None and RunLock(lock.path).probe() is None


def test_temporary_rollback_preserves_a_replacement_inode(tmp_path, monkeypatch):
    lock = RunLock(tmp_path / "run.lock")
    original_open, original_write = locking.private_file, os.write
    temporary_paths = []
    replacement = tmp_path / "protected"
    replacement.write_bytes(b"preserve replacement")
    error = OSError(errno.ENOSPC, "synthetic private write failure")
    def open_file(path, **kwargs):
        descriptor = original_open(path, **kwargs)
        if path.name.endswith(".tmp"):
            temporary_paths.append(path)
        return descriptor
    def write(fd, data):
        if b'"account"' in data:
            os.replace(replacement, temporary_paths[0])
            raise error
        return original_write(fd, data)
    monkeypatch.setattr(locking, "private_file", open_file)
    monkeypatch.setattr(locking.os, "write", write)
    with pytest.raises(CVEBeaconError) as caught:
        lock.acquire()
    assert caught.value.__cause__ is error
    assert temporary_paths[0].read_bytes() == b"preserve replacement"
    assert lock._owner_descriptor is None and RunLock(lock.path).probe() is None


def test_owner_close_failure_still_rolls_back_and_releases_shared_lock(tmp_path, monkeypatch):
    lock = RunLock(tmp_path / "run.lock")
    original_open, original_close, original_write = locking.private_file, lock._close_owner, os.write
    shared_fds, close_errors = [], []
    error = OSError(errno.ENOSPC, "synthetic reference write failure")
    def open_file(path, **kwargs):
        fd = original_open(path, **kwargs)
        if path == lock.path:
            shared_fds.append(fd)
        return fd
    def close_owner():
        original_close()
        if not close_errors:
            close_errors.append(True)
            raise OSError(errno.EIO, "synthetic owner close failure")
    def write(fd, data):
        if b'"owner_token"' in data and b'"account"' not in data:
            raise error
        return original_write(fd, data)
    monkeypatch.setattr(locking, "private_file", open_file)
    monkeypatch.setattr(lock, "_close_owner", close_owner)
    monkeypatch.setattr(locking.os, "write", write)
    try:
        with pytest.raises(CVEBeaconError) as caught:
            lock.acquire()
        assert caught.value.__cause__ is error
        assert close_errors and list(tmp_path.glob("run.lock.owner.*")) == []
        assert RunLock(lock.path).probe() is None
    finally:
        # The pre-fix failure skips closing the shared descriptor.
        for fd in set(shared_fds):
            try:
                details = os.fstat(fd)
            except OSError:
                continue
            expected = lock.path.stat()
            if (details.st_dev, details.st_ino) == (expected.st_dev, expected.st_ino):
                os.close(fd)


def test_shared_close_failure_cannot_replace_the_original_write_error(tmp_path, monkeypatch):
    lock = RunLock(tmp_path / "run.lock")
    original_open, original_close, original_write = locking.private_file, os.close, os.write
    shared_fds, close_errors = set(), []
    error = OSError(errno.ENOSPC, "synthetic private write failure")
    def open_file(path, **kwargs):
        fd = original_open(path, **kwargs)
        if path == lock.path:
            shared_fds.add(fd)
        return fd
    def close(fd):
        original_close(fd)
        if fd in shared_fds and not close_errors:
            close_errors.append(True)
            raise RuntimeError("synthetic shared-descriptor cleanup failure")
    def write(fd, data):
        if b'"account"' in data:
            raise error
        return original_write(fd, data)
    monkeypatch.setattr(locking, "private_file", open_file)
    monkeypatch.setattr(locking.os, "close", close)
    monkeypatch.setattr(locking.os, "write", write)
    with pytest.raises(CVEBeaconError) as caught:
        lock.acquire()
    assert caught.value.__cause__ is error
    assert close_errors and list(tmp_path.glob("run.lock.owner.*")) == []
    assert RunLock(lock.path).probe() is None


def test_rollback_attempts_both_names_when_first_unlink_fails(tmp_path, monkeypatch):
    original = Path.unlink
    attempts = []
    def unlink(path, *args, **kwargs):
        if ".owner." in path.name:
            kind = "temporary" if path.name.endswith(".tmp") else "final"
            attempts.append(kind)
            if attempts.count(kind) == 1:
                raise PermissionError(errno.EACCES, "synthetic first unlink refusal")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", unlink)
    with RunLock(tmp_path / "run.lock") as lock:
        assert attempts[:4] == ["temporary", "final", "temporary", "final"]
        assert RunLock(lock.path).snapshot()["description"] == "holder unavailable"
        assert list(tmp_path.glob("run.lock.owner.*")) == []


def test_cli_never_runs_after_write_error_and_cleanup_refusal(tmp_path, monkeypatch, capsys):
    config = make_config(tmp_path)
    original_write, original_unlink = os.write, Path.unlink
    called, refusals = [], []
    def write(fd, data):
        if b'"account"' in data:
            raise OSError(errno.ENOSPC, "synthetic full disk")
        return original_write(fd, data)
    def unlink(path, *args, **kwargs):
        if path.name.endswith(".tmp") and not refusals:
            refusals.append(True)
            raise PermissionError(errno.EACCES, "synthetic cleanup refusal")
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(cli, "_run_scan", lambda *a, **k: called.append(True) or 17)
    monkeypatch.setattr(locking.os, "write", write)
    monkeypatch.setattr(Path, "unlink", unlink)
    assert cli.main(["--config", str(config.config_path), "scan"]) == 2
    assert called == [] and list(tmp_path.glob("*.owner.*")) == []
    assert capsys.readouterr().err.startswith("error: cannot write the operation lock metadata")


@pytest.mark.parametrize("windows", [False, True])
def test_link_limit_failure_keeps_the_shared_run_usable(tmp_path, monkeypatch, windows):
    attempts = []
    def link(source, target):
        attempts.append(True)
        error = OSError(errno.EINVAL if windows else errno.EMLINK, "synthetic hard-link limit")
        if windows:
            error.winerror = 1142
        raise error
    monkeypatch.setattr(locking.os, "link", link)
    with RunLock(tmp_path / "run.lock") as lock:
        assert RunLock(lock.path).snapshot()["description"] == "holder unavailable"
        assert lock._owner_descriptor is None and list(tmp_path.glob("run.lock.owner.*")) == []
    assert attempts == [True] and RunLock(lock.path).probe() is None
