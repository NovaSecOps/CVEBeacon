"""Windows record cleanup and unverified legacy handoff regressions."""

import errno
import json
import os
from pathlib import Path

import pytest

from cvebeacon import dashboard, locking
from cvebeacon.errors import CVEBeaconError
from cvebeacon.locking import RunInProgress, RunLock, run_lock_path
from test_dashboard_operations import fake_scheduler, login, make_config, new_accounts


@pytest.mark.parametrize("emulate_sharing", [False, True])
def test_holder_record_publication_and_cleanup_respect_windows_sharing(tmp_path, monkeypatch, emulate_sharing):
    handles = {}
    denied = []
    original_open = locking.private_file
    original_close = os.close
    original_unlink = Path.unlink
    def open_file(path, **kwargs):
        fd = original_open(path, **kwargs)
        details = os.fstat(fd)
        handles[fd] = ((details.st_dev, details.st_ino), kwargs.get("readonly", False)
                       or kwargs.get("share_delete", False))
        return fd
    def close(fd):
        handles.pop(fd, None)
        return original_close(fd)
    def unlink(path, *args, **kwargs):
        if path.exists():
            details = path.stat()
            identity = (details.st_dev, details.st_ino)
            if any(inode == identity and not share_delete for inode, share_delete in handles.values()):
                denied.append(path.name)
                raise PermissionError(errno.EACCES, "synthetic Windows delete-sharing refusal")
        return original_unlink(path, *args, **kwargs)
    if emulate_sharing:
        monkeypatch.setattr(locking, "private_file", open_file)
        monkeypatch.setattr(locking.os, "close", close)
        monkeypatch.setattr(Path, "unlink", unlink)
    monkeypatch.setattr(locking, "_account_name", lambda: "cvebeacon")
    monkeypatch.setattr(locking, "_host_name", lambda: "example.com")
    monkeypatch.setenv("CVEBEACON_DASHBOARD_JOB", "7")
    path = tmp_path / "run.lock"
    for _ in range(2):
        with RunLock(path, command="scan") as lock:
            record_path = lock.owner_path
            assert record_path.stat().st_nlink == 1
            assert not record_path.with_name(record_path.name + ".tmp").exists()
            snapshot = RunLock(path).snapshot()
            assert snapshot["state"] == "active" and snapshot["command"] == "scan"
            assert snapshot["account"] == "cvebeacon" and snapshot["dashboard"] is True
            assert "running scan" in RunLock(path).probe()
            if emulate_sharing:
                # Delete sharing is confined to private metadata, never the run lock.
                assert handles[lock._descriptor][1] is False
        assert not record_path.exists()
        assert list(tmp_path.glob("run.lock.owner.*")) == []
    assert denied == [] and handles == {}


@pytest.mark.parametrize("persistent", [False, True])
def test_permission_fallback_does_not_retain_partial_publication(tmp_path, monkeypatch, persistent):
    original = Path.unlink
    failures = []
    def fail_temporary_unlink(path, *args, **kwargs):
        if path.name.endswith(".tmp") and (persistent or not failures):
            failures.append(True)
            raise PermissionError(errno.EACCES, "synthetic publication cleanup refusal")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", fail_temporary_unlink)
    lock = RunLock(tmp_path / "run.lock")
    try:
        if persistent:
            with pytest.raises(CVEBeaconError, match="metadata"):
                lock.acquire()
            assert RunLock(lock.path).probe() is None
        else:
            assert lock.acquire()
            assert RunLock(lock.path).snapshot()["description"] == "holder unavailable"
            assert list(tmp_path.glob("run.lock.owner.*")) == []
        assert lock._owner_descriptor is None
    finally:
        lock.release()


@pytest.mark.parametrize("error", sorted({errno.ENOSYS, errno.EOPNOTSUPP}))
def test_unsupported_hard_links_leave_normal_runs_usable(tmp_path, monkeypatch, error):
    attempts = []
    def unsupported(source, target):
        attempts.append((source, target))
        raise OSError(error, "synthetic filesystem without hard-link support")
    monkeypatch.setattr(locking.os, "link", unsupported)
    with RunLock(tmp_path / "run.lock", command="scan") as lock:
        snapshot = RunLock(lock.path).snapshot()
        assert snapshot["state"] == "active" and snapshot["description"] == "holder unavailable"
        assert lock._owner_descriptor is None
        assert list(tmp_path.glob("run.lock.owner.*")) == []
    assert len(attempts) == 1
    assert RunLock(lock.path).probe() is None


@pytest.mark.parametrize("winerror", [1, 50, 120])
def test_unsupported_windows_link_errors_leave_normal_runs_usable(tmp_path, monkeypatch, winerror):
    def unsupported(source, target):
        error = OSError(errno.EINVAL, "synthetic unsupported Windows link operation")
        error.winerror = winerror
        raise error
    monkeypatch.setattr(locking.os, "link", unsupported)
    with RunLock(tmp_path / "run.lock") as lock:
        assert RunLock(lock.path).snapshot()["description"] == "holder unavailable"
        assert list(tmp_path.glob("run.lock.owner.*")) == []


def test_free_lock_reads_a_legacy_sidecar_only_dead_pid_record(tmp_path, monkeypatch):
    path = tmp_path / "run.lock"
    path.write_bytes(b"\0")
    legacy = path.with_name(path.name + ".owner.json")
    payload = json.dumps({"account": "previous-account", "host": "example.com", "pid": 123,
                          "command": "watch run", "started_at": "2026-01-01T00:00:00+00:00"}).encode()
    descriptor = locking.private_file(legacy, create=True, exclusive=True)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    monkeypatch.setattr(locking, "_dead_local_pid", lambda record: record.get("pid") == 123)
    snapshot = RunLock(path).snapshot()
    assert snapshot["state"] == "stale" and snapshot["account"] == "previous-account"
    assert snapshot["command"] == "watch run" and not snapshot["dashboard"]
    assert path.read_bytes() == b"\0" and legacy.read_bytes() == payload


@pytest.mark.parametrize("dashboard_marker", [False, True])
def test_legacy_live_pid_cannot_identify_a_new_acquisition(tmp_path, monkeypatch, dashboard_marker):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler({})[0]
    client = app.test_client()
    login(client, "viewer")
    path = run_lock_path(config)
    previous = {"account": "previous-account", "host": "example.com", "pid": os.getpid(),
                "command": "watch run", "started_at": "2026-01-01T00:00:00+00:00"}
    if dashboard_marker:
        previous["dashboard_job"] = 99
    path.write_bytes(b"\0" + json.dumps(previous).encode())
    monkeypatch.setattr(locking, "_host_name", lambda: "example.com")
    current = RunLock(path, command="scan")
    original_lock = current._lock
    observed = []
    def take(fd):
        original_lock(fd)
        snapshot = RunLock(path).snapshot()
        holder = RunLock(path).probe()
        page = client.get("/operations/")
        observed.append((snapshot, holder, page))
    monkeypatch.setattr(current, "_lock", take)
    try:
        with current:
            pass
        snapshot, holder, page = observed[0]
        assert snapshot["state"] == "active" and snapshot["dashboard"] is False
        assert "account" not in snapshot and "command" not in snapshot
        assert "previous-account" not in str(holder)
        assert "cancel" not in str(RunInProgress(holder))
        assert page.status_code == 200 and "Active run" in page.text
        assert "previous-account" not in page.text and "watch run" not in page.text
        assert "Cancel job" not in page.text
    finally:
        app.extensions["dashboard_jobs"].shutdown()
