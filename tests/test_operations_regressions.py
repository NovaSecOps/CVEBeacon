"""Storage, supervision and accountability regressions for operations."""

from dataclasses import replace
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from cvebeacon import dashboard, dashboard_jobs as jobs, dashboard_ops, scheduling
from cvebeacon.errors import CVEBeaconError, StateError
from cvebeacon.locking import RunLock, run_lock_path
from test_dashboard_operations import (
    _Result, fake_job, fake_scheduler, login, make_config, new_accounts,
    submit, wait_for,
)


def manager_for(tmp_path):
    config = make_config(tmp_path)
    return jobs.JobManager(config, new_accounts(config))


def test_full_history_inspection_never_migrates_or_writes(tmp_path):
    config = make_config(tmp_path, initial="full")
    path = config.watch.database
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE watch_meta(key TEXT PRIMARY KEY,value TEXT)")
        db.execute("INSERT INTO watch_meta VALUES ('schema_version','1')")
    before = path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode
    users = new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client, "viewer")
    with RunLock(run_lock_path(config)):
        assert client.get("/operations/").status_code == 200
        assert jobs.full_history_confirmation_required(config)
    assert (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode) == before


def test_inventory_only_run_and_frozen_commands(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    config = replace(config, watch=replace(config.watch, enabled=False))
    assert jobs.build_command(config, "run")[-1] == "run"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "cvebeacon.exe"))
    assert jobs.build_command(config, "run")[:2] == [sys.executable, "--config"]
    assert " -m " not in dashboard_ops._fallback_install_command(config)


def test_child_cannot_import_from_config_directory_or_inherit_unrelated_secrets(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    (tmp_path / "cvebeacon.py").write_text("print('SHADOWED')")
    (tmp_path / "sitecustomize.py").write_text("print('CUSTOMIZED')")
    monkeypatch.setenv("UNRELATED_SECRET", "synthetic-private-value")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    job = manager.submit("notify-test", started_by="admin", argv=jobs.build_command(manager.config, "notify-test", channel="sink"))
    job = manager.wait(job.id)
    assert job.status == "failed"  # loopback port is closed
    assert "SHADOWED" not in manager.store.log_tail(job)
    assert "CUSTOMIZED" not in manager.store.log_tail(job)
    probe = manager.submit("notify-test", started_by="admin", argv=fake_job("import os; print(os.getenv('UNRELATED_SECRET', 'absent'))"))
    assert "absent" in manager.store.log_tail(manager.wait(probe.id))


def test_live_output_is_visible_before_child_exits(tmp_path):
    manager = manager_for(tmp_path)
    job = manager.submit("notify-test", started_by="admin", argv=fake_job("import time; print('live output'); time.sleep(15)"))
    try:
        wait_for(lambda: "live output" in manager.store.log_tail(manager.store.get(job.id)), timeout=3)
        assert manager.store.get(job.id).status == "running"
    finally:
        manager.cancel(job.id)
        manager.wait(job.id)


def test_retention_preserves_all_active_jobs_and_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "MAX_JOBS", 3)
    store = jobs.JobStore(tmp_path / "jobs.db")
    active = [store.create("scan", "admin", ["scan"]) for _ in range(2)]
    store.mark_running(active[0].id)
    for job in active:
        Path(job.log_path).write_bytes(b"active")
    for _ in range(6):
        job = store.create("scan", "admin", ["scan"])
        store.finish(job.id, "succeeded", exit_code=0)
    for job in active:
        assert store.get(job.id).active
        assert Path(job.log_path).read_bytes() == b"active"


def test_queue_is_bounded_before_audit_and_creation(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    monkeypatch.setattr(manager, "start_thread", lambda: None)
    monkeypatch.setattr(jobs, "MAX_PENDING_JOBS", 2, raising=False)
    for _ in range(2):
        manager.submit("notify-test", started_by="admin", argv=fake_job("pass"))
    before = len(manager.users.audit_entries())
    with pytest.raises(CVEBeaconError, match="queue"):
        manager.submit("notify-test", started_by="admin", argv=fake_job("pass"))
    assert len(manager.store.active()) == 2
    assert len(manager.users.audit_entries()) == before


@pytest.mark.parametrize("target_exists", [False, True])
def test_job_database_symlink_is_never_followed(tmp_path, target_exists):
    target = tmp_path / "target"
    if target_exists:
        target.write_bytes(b"keep")
    (tmp_path / "jobs.db").symlink_to(target)
    with pytest.raises(StateError):
        jobs.JobStore(tmp_path / "jobs.db").initialize()
    assert target.read_bytes() == b"keep" if target_exists else not target.exists()


def test_log_symlinks_and_paths_outside_log_directory_are_refused(tmp_path):
    store = jobs.JobStore(tmp_path / "jobs.db")
    job = store.create("scan", "admin", ["scan"])
    target = tmp_path / "target"
    target.write_bytes(b"private")
    Path(job.log_path).symlink_to(target)
    with pytest.raises((StateError, OSError)):
        jobs._JobLog(job.log_path)
    assert store.log_tail(job) == ""
    assert store.log_tail(replace(job, log_path=str(target))) == ""
    assert target.read_bytes() == b"private"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX path replacement while open")
def test_log_rotation_keeps_checked_descriptor_after_path_swap(tmp_path):
    store = jobs.JobStore(tmp_path / "jobs.db")
    job = store.create("scan", "admin", ["scan"])
    log = jobs._JobLog(job.log_path)
    target = tmp_path / "target"
    target.write_bytes(b"private target")
    try:
        Path(job.log_path).unlink()
        Path(job.log_path).symlink_to(target)
        log.write(b"x" * (jobs.MAX_LOG_BYTES + 1))
    finally:
        log.close()
    assert target.read_bytes() == b"private target"


def test_log_rotation_stays_in_place_and_bounded(tmp_path):
    store = jobs.JobStore(tmp_path / "jobs.db")
    job = store.create("scan", "admin", ["scan"])
    log = jobs._JobLog(job.log_path)
    try:
        log.write(b"a" * (jobs.MAX_LOG_BYTES + 100))
        log.write(b"b" * (jobs.MAX_LOG_BYTES + 100))
    finally:
        log.close()
    path = Path(job.log_path)
    assert path.stat().st_size == jobs.MAX_LOG_BYTES
    assert path.read_bytes() == b"b" * jobs.MAX_LOG_BYTES
    assert [item.name for item in path.parent.iterdir()] == [path.name]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory modes")
def test_existing_world_writable_log_directory_is_accepted(tmp_path):
    from cvebeacon.dashboard_jobs import JobStore, _JobLog
    directory = tmp_path / "dashboard-jobs"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    store = JobStore(tmp_path / "jobs.db")
    job = store.create("scan", "admin", ["scan"])
    log = _JobLog(job.log_path)
    log.write(b"shared log storage")
    log.close()
    assert store.log_tail(job) == "shared log storage"


def test_capture_failure_reaps_child_before_marking_failed(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    marker = tmp_path / "cleanup"
    processes = []
    popen = subprocess.Popen
    def spawn(*args, **kwargs):
        child = popen(*args, **kwargs)
        processes.append(child)
        return child
    monkeypatch.setattr(jobs.subprocess, "Popen", spawn)
    monkeypatch.setattr(jobs._JobLog, "write", lambda *a: (_ for _ in ()).throw(OSError("capture failed")))
    job = manager.submit("notify-test", started_by="admin", argv=fake_job("""
        import signal, pathlib, sys, time
        def stop(*args):
            pathlib.Path(sys.argv[1]).write_text('cleaned')
            raise SystemExit(130)
        signal.signal(signal.SIGINT, stop)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, stop)
        print('ready', flush=True)
        [time.sleep(0.01) for _ in range(3000)]  # short slices let a Windows break handler run
    """, marker))
    try:
        assert manager.wait(job.id).status == "failed"
        assert processes[0].poll() is not None
        assert marker.read_text() == "cleaned"
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait()


def test_cancel_audits_requester_and_removes_queued_id(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    monkeypatch.setattr(manager, "start_thread", lambda: None)
    job = manager.submit("notify-test", started_by="admin", argv=fake_job("pass"))
    assert manager.cancel(job.id, actor="runner")
    entry = next(e for e in manager.users.audit_entries() if e.action.startswith("job_cancel_requested"))
    assert entry.actor == "runner"
    assert str(job.id) in entry.action and job.operation in entry.action
    assert job.id not in manager._queue
    outcome = next(e for e in manager.users.audit_entries() if e.action.startswith("job_cancelled:"))
    assert outcome.actor == "runner" and outcome.username == "admin"


@pytest.mark.parametrize("action", ["install", "remove"])
def test_schedule_audit_failure_prevents_mutation(tmp_path, monkeypatch, action):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    runner, calls = fake_scheduler({})
    app.extensions["dashboard_schedule_runner"] = runner
    monkeypatch.setattr(dashboard_ops, "_running_as_root", lambda: False)
    monkeypatch.setattr(app.extensions["dashboard_users"], "record_action", lambda *a, **kw: (_ for _ in ()).throw(StateError("audit unavailable")))
    response = submit(client, f"/operations/schedule/{action}", mode="interval", every="4", command="watch", confirm="remove")
    assert response.status_code >= 400
    assert not any(args == ["crontab", "-"] for args, _ in calls)


def test_schedule_ignores_account_when_logged_out_is_off(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler({})[0]
    monkeypatch.setattr(dashboard_ops, "_running_as_root", lambda: False)
    response = submit(client, "/operations/schedule/install", mode="interval", every="4", command="watch", account="unused-account")
    assert response.status_code == 303


@pytest.mark.parametrize("secret", ["two  spaces", "line\nbreak", "secret" * 150])
def test_password_diagnostics_never_normalize_or_truncate_secrets(tmp_path, monkeypatch, secret):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Windows")
    def runner(args, **kwargs):
        if "register.ps1" in " ".join(args):
            return _Result(returncode=1, stderr="rejected " + secret)
        return _Result()
    app.extensions["dashboard_schedule_runner"] = runner
    response = submit(client, "/operations/schedule/install", mode="interval", every="4", command="watch", run_logged_out="yes", account="svc", password=secret)
    assert response.status_code == 400
    assert " ".join(secret.split())[:40] not in response.text


def test_windows_break_exit_is_reported_as_a_forced_cancellation():
    assert jobs.normalize_exit_code(0xC000013A) == (130, True)
    assert jobs.normalize_exit_code(130) == (130, False)
    assert jobs.exit_meaning(0xC000013A) == "Cancelled by an interrupt"


def test_cancel_escalates_and_reaps_an_uncooperative_child(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    monkeypatch.setattr(jobs, "CANCEL_GRACE_SECONDS", 0.15, raising=False)
    monkeypatch.setattr(jobs, "TERMINATE_GRACE_SECONDS", 0.15, raising=False)
    job = manager.submit("notify-test", started_by="admin", argv=fake_job("""
        import signal, time
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, signal.SIG_IGN)
        print('ready', flush=True)
        [time.sleep(0.01) for _ in range(3000)]  # short slices let a Windows break handler run
    """))
    process = None
    try:
        wait_for(lambda: "ready" in manager.store.log_tail(manager.store.get(job.id)))
        process = manager._process
        manager.cancel(job.id)
        result = manager.wait(job.id, timeout=2)
        assert result.status == "cancelled"
        assert "forced" in result.message
        assert process.poll() is not None
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()


def test_shutdown_runs_cleanup_and_reaps_child(tmp_path):
    manager = manager_for(tmp_path)
    marker = tmp_path / "cleanup"
    job = manager.submit("notify-test", started_by="admin", argv=fake_job("""
        import signal, pathlib, sys, time
        def stop(*args):
            pathlib.Path(sys.argv[1]).write_text('cleaned')
            raise SystemExit(130)
        signal.signal(signal.SIGINT, stop)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, stop)
        print('ready', flush=True)
        [time.sleep(0.01) for _ in range(3000)]  # short slices let a Windows break handler run
    """, marker))
    wait_for(lambda: "ready" in manager.store.log_tail(manager.store.get(job.id)))
    process = manager._process
    try:
        manager.shutdown()
        assert process.poll() is not None
        assert marker.read_text() == "cleaned"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_job_outcome_audit_is_retained_and_retried(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    monkeypatch.setattr(manager, "start_thread", lambda: None)
    job = manager.submit("notify-test", started_by="admin", argv=fake_job("print('done')"))
    record = manager.users.record_action
    monkeypatch.setattr(manager.users, "record_action", lambda *a, **kw: (_ for _ in ()).throw(StateError("audit unavailable")))
    manager._run_job(job)
    current = manager.store.get(job.id)
    assert current.status == "succeeded"
    assert current.audit_pending == "job_succeeded"
    monkeypatch.setattr(manager.users, "record_action", record)
    manager.retry_audits()
    assert manager.store.get(job.id).audit_pending is None
    assert any(e.action == f"job_succeeded:{job.id}:notify-test" for e in manager.users.audit_entries())


@pytest.mark.parametrize("action", ["install", "remove"])
def test_schedule_outcome_audit_failure_is_visible_and_retried(tmp_path, monkeypatch, action):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    runner, calls = fake_scheduler({"text": "# unrelated\n"})
    app.extensions["dashboard_schedule_runner"] = runner
    monkeypatch.setattr(dashboard_ops, "_running_as_root", lambda: False)
    users = app.extensions["dashboard_users"]
    record = users.record_action
    def fail_outcome(name, **kwargs):
        if not name.endswith("_requested"):
            raise StateError("outcome audit unavailable")
        return record(name, **kwargs)
    monkeypatch.setattr(users, "record_action", fail_outcome)
    response = submit(client, f"/operations/schedule/{action}", mode="interval", every="4", command="watch", confirm="remove")
    assert response.status_code == 400
    assert "audit unavailable" in response.text
    manager = app.extensions["dashboard_jobs"]
    assert manager.store.pending_actions()
    monkeypatch.setattr(users, "record_action", record)
    manager.retry_audits()
    assert not manager.store.pending_actions()
    assert any(e.action.startswith("schedule_installed:" if action == "install" else "schedule_remove_skipped") for e in users.audit_entries())


def test_child_keeps_only_configured_secret_references(tmp_path, monkeypatch):
    from cvebeacon.launching import child_environment
    config = make_config(tmp_path, channels='''
        [watch.channels.teams]
        type = "teams"
        webhook_url_env = "SYNTHETIC_CHANNEL_SECRET"
    ''')
    monkeypatch.setenv("SYNTHETIC_CHANNEL_SECRET", "needed")
    monkeypatch.setenv(config.dashboard.password_hash_env, "unneeded")
    environment = child_environment(config)
    assert environment["SYNTHETIC_CHANNEL_SECRET"] == "needed"
    assert config.dashboard.password_hash_env not in environment


def test_schedule_account_controls_start_disabled(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler({})[0]
    monkeypatch.setattr(dashboard_ops, "_running_as_root", lambda: False)
    page = client.get("/operations/schedule")
    assert 'name="account" maxlength="256" autocomplete="off" disabled' in page.text
    assert "/static/schedule.js" in page.text
    assert client.get("/static/schedule.js").status_code == 200


@pytest.mark.parametrize("output", ["two  spaces", "partial-password-prefix", "x" * 1000])
def test_installer_discards_password_bearing_diagnostics_before_rendering(tmp_path, monkeypatch, output):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Windows")
    plan = scheduling.make_plan(tmp_path / "config.toml", 4, command="watch", run_logged_out=True, account="svc")
    with pytest.raises(CVEBeaconError) as error:
        scheduling.install(plan, password="two  spaces", run=lambda *a, **kw: _Result(returncode=1, stderr=output))
    assert output[:40] not in str(error.value)
    assert "[redacted]" in str(error.value)
