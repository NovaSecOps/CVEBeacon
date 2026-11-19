"""Acquisition identity, protected paths and queued admission regressions."""

from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import sqlite3
import threading
import uuid

import httpx
import pytest

from cvebeacon import cli, dashboard, dashboard_config as dc, dashboard_jobs as jobs, locking, scheduling
from cvebeacon.errors import CVEBeaconError, ConfigurationError
from cvebeacon.locking import LOCK_NAME, OperationLock, RunLock, run_lock_path
from test_dashboard_operations import (
    _Result, fake_job, fake_scheduler, login, make_config, new_accounts, wait_for,
)
from watch_support import mock_client


@pytest.mark.parametrize("store", ["state", "watch"])
@pytest.mark.parametrize("suffix", [".owner.json", ".owner." + "a" * 32 + ".json"])
def test_holder_namespace_is_protected_in_current_and_candidate_roots(tmp_path, store, suffix):
    config = make_config(tmp_path)
    for directory in (tmp_path, tmp_path / "candidate"):
        path = directory / (LOCK_NAME + suffix)
        updated = replace(config, database_path=path) if store == "state" else replace(
            config, watch=replace(config.watch, database=path))
        with pytest.raises(ConfigurationError):
            dc.check_protected_paths(updated, config.config_path, tmp_path / "backups", [config])


def test_cli_refuses_database_in_holder_namespace_without_writing(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    path = tmp_path / (LOCK_NAME + ".owner.json")
    path.write_bytes(b"protected database")
    config = replace(config, database_path=path)
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "_run_scan", lambda *a, **k: 0)
    assert cli.main(["scan"]) == 2
    assert path.read_bytes() == b"protected database"


def test_acquisition_never_replaces_existing_holder_path(tmp_path, monkeypatch):
    token = "a" * 32
    monkeypatch.setattr(locking.uuid, "uuid4", lambda: uuid.UUID(hex=token))
    lock = RunLock(tmp_path / "run.lock")
    path = tmp_path / ("run.lock.owner." + token + ".json")
    path.write_bytes(b"protected file")
    path.chmod(0o600)
    with pytest.raises(CVEBeaconError):
        lock.acquire()
    assert path.read_bytes() == b"protected file"


def test_release_does_not_remove_a_replacement_file(tmp_path):
    lock = RunLock(tmp_path / "run.lock")
    assert lock.acquire()
    target = lock.owner_path
    replacement = tmp_path / "protected"
    replacement.write_bytes(b"preserve replacement")
    os.replace(replacement, target)
    lock.release()
    assert target.read_bytes() == b"preserve replacement"


@pytest.mark.parametrize("dead", [True, False])
def test_publication_window_never_attributes_an_old_record(tmp_path, monkeypatch, dead):
    path = tmp_path / "run.lock"
    orphan = path.with_name(path.name + ".owner.json")
    orphan.write_text(json.dumps({"account": "old-account", "host": "example.com", "pid": 123,
                                  "command": "watch run", "dashboard_job": 99}))
    orphan.chmod(0o600)
    monkeypatch.setattr(locking, "_dead_local_pid", lambda _: dead)
    original = locking.os.write
    observed = []
    def write(fd, payload):
        if b'"account"' in payload:
            observed.append(RunLock(path).snapshot())
        return original(fd, payload)
    monkeypatch.setattr(locking.os, "write", write)
    with RunLock(path, command="scan"):
        pass
    assert observed and observed[0]["state"] == "active"
    assert not observed[0]["dashboard"]
    assert "old-account" not in observed[0]["description"]


def test_legacy_inline_holder_wins_over_unrelated_sidecar(tmp_path):
    path = tmp_path / "run.lock"
    orphan = path.with_name(path.name + ".owner.json")
    orphan.write_text(json.dumps({"account": "orphan", "dashboard_job": 99, "command": "watch run"}))
    orphan.chmod(0o600)
    lock = RunLock(path)
    fd = lock._open()
    try:
        lock._lock(fd)
        os.lseek(fd, 1, os.SEEK_SET)
        os.write(fd, json.dumps({"account": "legacy", "command": "scan", "pid": os.getpid()}).encode())
        snapshot = RunLock(path).snapshot()
        assert snapshot["state"] == "active" and snapshot["command"] == "scan"
        assert not snapshot["dashboard"]
    finally:
        lock._unlock(fd)
        os.close(fd)


@pytest.mark.parametrize("error", [errno.EACCES, errno.EPERM, errno.EROFS])
def test_private_metadata_permission_failure_does_not_block_shared_lock(tmp_path, monkeypatch, error):
    path = tmp_path / "run.lock"
    path.touch()
    original = locking.private_file
    def open_file(target, **kwargs):
        if target != path:
            raise PermissionError(error, "synthetic metadata permission refusal")
        return original(target, **kwargs)
    monkeypatch.setattr(locking, "private_file", open_file)
    with RunLock(path):
        snapshot = RunLock(path).snapshot()
        assert snapshot["state"] == "active" and not snapshot["dashboard"]
        assert "account" not in path.read_text(errors="replace")


def test_foreign_orphan_in_sticky_parent_does_not_block_successor(tmp_path, monkeypatch):
    if os.name == "posix":
        tmp_path.chmod(0o1777)
    path = tmp_path / "run.lock"
    orphan = path.with_name(path.name + ".owner.json")
    orphan.write_bytes(b"foreign private orphan")
    orphan.chmod(0o600)
    original = locking.os.replace
    def sticky_replace(source, target):
        if Path(target) == orphan:
            raise PermissionError(errno.EPERM, "synthetic foreign owner in sticky directory")
        return original(source, target)
    monkeypatch.setattr(locking.os, "replace", sticky_replace)
    with RunLock(path) as lock:
        assert lock.owner_path != orphan
        assert json.loads(lock.owner_path.read_bytes())["pid"] == os.getpid()
    assert orphan.read_bytes() == b"foreign private orphan"


def test_snapshot_does_not_create_missing_storage(tmp_path):
    root = tmp_path / "missing"
    assert RunLock(root / "run.lock").snapshot() is None
    assert not root.exists()


def test_bad_lock_does_not_hide_operations(tmp_path):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler({})[0]
    target = tmp_path / "protected"
    target.write_text("preserve")
    run_lock_path(config).symlink_to(target)
    client = app.test_client()
    login(client, "viewer")
    try:
        page = client.get("/operations/")
        assert page.status_code == 200 and "unavailable" in page.text.lower()
        assert target.read_text() == "preserve"
    finally:
        app.extensions["dashboard_jobs"].shutdown()


@pytest.mark.parametrize("xml", [
    '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal>'
    '<UserId>synthetic-private-account</UserId></Principal></Principals><Actions><Exec>'
    '<Command>/opt/private/cvebeacon</Command><Arguments>SYNTHETIC_SCHEDULE_SECRET</Arguments>'
    '</Exec></Actions></Task>',
    '<Task broken SYNTHETIC_SCHEDULE_SECRET /opt/private/cvebeacon synthetic-private-account',
])
def test_windows_operations_schedule_is_restricted_and_cached(tmp_path, monkeypatch, xml):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    calls = []
    def scheduler(*args, **kwargs):
        calls.append(args)
        return _Result(stdout=xml)
    app.extensions["dashboard_schedule_runner"] = scheduler
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Windows")
    client = app.test_client()
    login(client, "viewer")
    try:
        assert client.get("/operations/schedule").status_code == 403
        for _ in range(2):
            text = client.get("/operations/").text
            assert "Scheduled by Windows Task Scheduler" in text
            assert "SYNTHETIC_SCHEDULE_SECRET" not in text
            assert "/opt/private" not in text and "synthetic-private-account" not in text
        assert len(calls) == 1
    finally:
        app.extensions["dashboard_jobs"].shutdown()


def test_real_channel_test_is_lock_free_and_does_not_change_watch_storage(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    with sqlite3.connect(config.watch.database) as db:
        db.execute("CREATE TABLE sentinel(value TEXT)")
        db.execute("INSERT INTO sentinel VALUES ('preserve')")
    before = config.watch.database.read_bytes()
    requests = []
    def sink(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200)
    monkeypatch.setattr(cli, "HttpClient", lambda _: mock_client(sink))
    with RunLock(run_lock_path(config)) as lock:
        inline, owner = lock.path.read_bytes(), lock.owner_path.read_bytes()
        assert cli.main(["--config", str(config.config_path), "watch", "notify", "test", "sink"]) == 0
        assert lock.path.read_bytes() == inline and lock.owner_path.read_bytes() == owner
    assert config.watch.database.read_bytes() == before
    assert len(requests) == 1 and requests[0]["test"] is True


def test_previous_acquisition_with_reused_pid_cannot_describe_current_holder(tmp_path, monkeypatch):
    path = tmp_path / "run.lock"
    monkeypatch.setenv("CVEBEACON_DASHBOARD_JOB", "99")
    with RunLock(path, command="watch run") as old:
        payload = old.owner_path.read_bytes()
    monkeypatch.delenv("CVEBEACON_DASHBOARD_JOB")
    with RunLock(path, command="scan") as current:
        current.owner_path.write_bytes(payload)
        snapshot = RunLock(path).snapshot()
        assert snapshot["state"] == "active" and not snapshot["dashboard"]
        assert "watch run" not in snapshot["description"]


def test_old_token_cannot_identify_holder_before_new_reference_is_written(tmp_path, monkeypatch):
    path = tmp_path / "run.lock"
    monkeypatch.setenv("CVEBEACON_DASHBOARD_JOB", "99")
    with RunLock(path, command="watch run") as old:
        reference, payload, owner = path.read_bytes(), old.owner_path.read_bytes(), old.owner_path
    path.write_bytes(reference)
    owner.write_bytes(payload)
    owner.chmod(0o600)
    monkeypatch.delenv("CVEBEACON_DASHBOARD_JOB")
    current = RunLock(path, command="scan")
    original = current._lock
    observed = []
    def take(fd):
        original(fd)
        observed.append(RunLock(path).snapshot())
    monkeypatch.setattr(current, "_lock", take)
    with current:
        pass
    assert observed[0]["state"] == "active" and not observed[0]["dashboard"]
    assert "watch run" not in observed[0]["description"]


@pytest.mark.parametrize("outcome", ["release", "cancel", "timeout"])
def test_cron_winning_child_admission_returns_job_to_waiting(tmp_path, monkeypatch, outcome):
    config = make_config(tmp_path)
    manager = jobs.JobManager(config, new_accounts(config))
    first = RunLock(run_lock_path(config), command="watch run")
    competitor = RunLock(run_lock_path(config), command="watch sync")
    spawned = threading.Event()
    children = []
    original = jobs.subprocess.Popen
    def spawn(*args, **kwargs):
        if not spawned.is_set():
            assert competitor.acquire()
            spawned.set()
        process = original(*args, **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(jobs.subprocess, "Popen", spawn)
    monkeypatch.setattr(jobs, "LOCK_WAIT_TIMEOUT_SECONDS", 2 if outcome == "timeout" else 10)
    try:
        assert first.acquire()
        job = manager.submit("watch-evaluate", started_by="admin", argv=jobs.build_command(config, "watch-evaluate"))
        wait_for(lambda: manager.store.get(job.id).message)
        first.release()
        assert spawned.wait(3)
        wait_for(lambda: children and children[0].poll() is not None and
                 manager.store.get(job.id).status in {"queued", "failed"})
        assert manager.store.get(job.id).status == "queued"
        assert manager.store.get(job.id).started_at is None
        if outcome == "release":
            competitor.release()
            assert manager.wait(job.id).status == "succeeded"
            assert len(children) == 2
        elif outcome == "cancel":
            assert manager.cancel(job.id, actor="runner")
            assert manager.wait(job.id).status == "cancelled" and len(children) == 1
        else:
            result = manager.wait(job.id, timeout=3)
            assert result.status == "failed" and "wait for it to finish" in result.message
            assert result.exit_code is None and len(children) == 1
        wait_for(lambda: manager.store.get(job.id).audit_pending is None)
        actions = [entry.action for entry in manager.users.audit_entries()]
        assert actions.count(f"job_started:{job.id}:watch-evaluate") == 1
        if outcome != "timeout":
            assert f"job_failed:{job.id}:watch-evaluate" not in actions
    finally:
        first.release()
        competitor.release()
        manager.shutdown()


def test_validation_exit_is_never_retried(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    manager = jobs.JobManager(config, new_accounts(config))
    launches = []
    original = jobs.subprocess.Popen
    def spawn(*args, **kwargs):
        launches.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(jobs.subprocess, "Popen", spawn)
    try:
        job = manager.submit("watch-evaluate", started_by="admin", argv=fake_job("raise SystemExit(2)"))
        result = manager.wait(job.id)
        assert result.status == "failed" and result.exit_code == 2
        assert len(launches) == 1
    finally:
        manager.shutdown()
