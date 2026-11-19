"""External run visibility and independent channel-test execution."""

import json
import os
import stat
from datetime import datetime

import pytest

from cvebeacon import cli, dashboard, dashboard_jobs as jobs, locking, scheduling
from cvebeacon.dashboard_jobs import JobManager
from cvebeacon.locking import RunInProgress, RunLock, run_lock_path
from test_dashboard_operations import (
    fake_job, fake_scheduler, job_id, login, make_config, new_accounts, submit, wait_for,
)


def test_external_run_is_visible_to_viewer(tmp_path):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler({})[0]
    client = app.test_client()
    login(client, "viewer")
    try:
        with RunLock(run_lock_path(config), command="watch run"):
            page = client.get("/operations/")
            assert page.status_code == 200
            assert "Active run" in page.text
            assert "watch run" in page.text
            assert "Elapsed" in page.text
            assert "Cancel job" not in page.text
    finally:
        app.extensions["dashboard_jobs"].shutdown()


def test_channel_test_finishes_during_a_long_main_job(tmp_path):
    config = make_config(tmp_path)
    manager = JobManager(config, new_accounts(config))
    marker = tmp_path / "release"
    try:
        slow = manager.submit("watch-run", started_by="admin", argv=fake_job(
            "import pathlib, sys, time\n"
            "print('ready', flush=True)\n"
            "while not pathlib.Path(sys.argv[1]).exists(): time.sleep(0.01)", marker))
        wait_for(lambda: "ready" in manager.store.log_tail(manager.store.get(slow.id)))
        quick = manager.submit("notify-test", started_by="admin", argv=fake_job("print('test complete')"))
        assert manager.wait(quick.id, timeout=2).status == "succeeded"
        assert manager.store.get(slow.id).status == "running"
        wait_for(lambda: manager.store.get(quick.id).audit_pending is None)
        assert any(entry.action == f"job_succeeded:{quick.id}:notify-test"
                   for entry in manager.users.audit_entries())
        assert manager.users.verify_audit() is None
    finally:
        marker.touch()
        manager.shutdown()


def test_manual_job_waits_for_external_run_then_starts(tmp_path):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler({})[0]
    manager = app.extensions["dashboard_jobs"]
    manager.command_builder = lambda *a, **k: fake_job("print('ran after release')")
    client = app.test_client()
    login(client)
    try:
        with RunLock(run_lock_path(config), command="watch run"):
            response = submit(client, "/operations/run", operation="watch-evaluate")
            assert response.status_code == 303
            identifier = job_id(response)
            wait_for(lambda: manager.store.get(identifier).message)
            assert manager.store.get(identifier).status == "queued"
            assert manager.store.get(identifier).started_at is None
            for path in ("/operations/", "/operations/jobs", f"/operations/jobs/{identifier}"):
                page = client.get(path).text
                assert "Queue position 1" in page
                assert "waiting for" in page and "watch run" in page
        result = manager.wait(identifier)
        assert result.status == "succeeded" and result.message is None
        assert "ran after release" in manager.store.log_tail(result)
    finally:
        manager.shutdown()


@pytest.mark.parametrize("cancel", [False, True])
def test_wait_is_bounded_and_cancellable(tmp_path, monkeypatch, cancel):
    config = make_config(tmp_path)
    manager = JobManager(config, new_accounts(config))
    monkeypatch.setattr(jobs, "LOCK_WAIT_TIMEOUT_SECONDS", 10 if cancel else 0.05)
    try:
        with RunLock(run_lock_path(config), command="watch run"):
            job = manager.submit("watch-run", started_by="admin", argv=fake_job("print('must not run')"))
            if cancel:
                wait_for(lambda: manager.store.get(job.id).message)
                assert manager.cancel(job.id, actor="runner")
            result = manager.wait(job.id, timeout=2)
            assert result.status == ("cancelled" if cancel else "failed")
            assert result.started_at is None
            assert manager.store.log_tail(result) == ""
            if not cancel:
                assert "watch run" in result.message and "wait for it to finish" in result.message
                assert "cancel it" not in result.message
            else:
                assert result.cancelled_by == "runner"
            wait_for(lambda: manager.store.get(job.id).audit_pending is None)
    finally:
        manager.shutdown()


@pytest.mark.parametrize("operation", ["watch-run", "notify-test"])
def test_each_lane_is_serial_and_explains_its_queue(tmp_path, operation):
    config = make_config(tmp_path)
    manager = JobManager(config, new_accounts(config))
    marker = tmp_path / "release"
    try:
        first = manager.submit(operation, started_by="admin", argv=fake_job(
            "import pathlib, sys, time\nprint('ready', flush=True)\n"
            "while not pathlib.Path(sys.argv[1]).exists(): time.sleep(0.01)", marker))
        wait_for(lambda: "ready" in manager.store.log_tail(manager.store.get(first.id)))
        second = manager.submit(operation, started_by="admin", argv=fake_job(
            "import pathlib, sys; assert pathlib.Path(sys.argv[1]).exists()", marker))
        third = manager.submit(operation, started_by="admin", argv=fake_job("pass"))
        assert manager.store.get(second.id).status == "queued"
        details = manager.queue_details()
        assert f"Queue position 1: behind job {first.id}" in details[second.id]
        assert f"Queue position 2: behind job {second.id}" in details[third.id]
        marker.touch()
        assert manager.wait(second.id).status == "succeeded"
        assert manager.wait(third.id).status == "succeeded"
    finally:
        marker.touch()
        manager.shutdown()


def test_cli_holder_is_private_and_removed(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    lock = RunLock(run_lock_path(config))
    seen = []
    def run(*a, **k):
        record = json.loads(lock.owner_path.read_text(encoding="utf-8"))
        assert record["command"] == "watch run"
        assert record["pid"] == os.getpid()
        assert record["account"] and record["host"]
        assert datetime.fromisoformat(record["started_at"]).utcoffset().total_seconds() == 0
        if os.name == "posix":
            assert stat.S_IMODE(lock.owner_path.stat().st_mode) == 0o600
        seen.append(record)
        return 17
    monkeypatch.setattr(cli, "_run_watch", run)
    assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 17
    assert len(seen) == 1 and not lock.owner_path.exists()


def test_lock_record_never_contains_full_arguments(tmp_path):
    with RunLock(tmp_path / "run.lock", command="scan --token synthetic-secret") as lock:
        record = json.loads(lock.owner_path.read_bytes())
        assert record["command"] == "run"
        assert "synthetic-secret" not in lock.owner_path.read_text(encoding="utf-8")


def test_dashboard_child_records_its_job_and_conflict_wording(tmp_path, capsys):
    config = make_config(tmp_path)
    manager = JobManager(config, new_accounts(config))
    marker = tmp_path / "release"
    lock = RunLock(run_lock_path(config))
    try:
        job = manager.submit("watch-run", started_by="admin", argv=fake_job(
            "import pathlib, sys, time\nfrom cvebeacon import cli\n"
            "def run(*args, **kwargs):\n"
            "    print('ready', flush=True)\n"
            "    while not pathlib.Path(sys.argv[2]).exists(): time.sleep(0.01)\n"
            "    return 0\n"
            "cli._run_watch = run\n"
            "raise SystemExit(cli.main(['--config', sys.argv[1], 'watch', 'run']))",
            config.config_path, marker))
        wait_for(lambda: "ready" in manager.store.log_tail(manager.store.get(job.id)))
        record = json.loads(lock.owner_path.read_text(encoding="utf-8"))
        assert record["dashboard_job"] == job.id
        assert record["command"] == "watch run" and record["pid"] != os.getpid()
        if os.name == "posix":
            assert stat.S_IMODE(lock.owner_path.stat().st_mode) == 0o600
        assert "Operations page" in str(RunInProgress(lock.probe()))
        assert cli.main(["--config", str(config.config_path), "watch", "evaluate", "--all", "--yes"]) == 2
        assert "or cancel it from the Operations page" in capsys.readouterr().err
        marker.touch()
        assert manager.wait(job.id).status == "succeeded"
        assert not lock.owner_path.exists()
        wait_for(lambda: manager.store.get(job.id).audit_pending is None)
    finally:
        marker.touch()
        manager.shutdown()


def test_external_conflict_never_offers_dashboard_cancel(tmp_path, capsys):
    config = make_config(tmp_path)
    with RunLock(run_lock_path(config), command="watch run") as lock:
        text = str(RunInProgress(RunLock(lock.path).probe()))
        assert "watch run" in text and "wait for it to finish" in text
        assert "cancel" not in text
        assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 2
        assert "cancel" not in capsys.readouterr().err


@pytest.mark.skipif(os.name == "nt", reason="Windows PID liveness is unknown")
def test_dead_local_holder_is_stale_on_operations(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler({})[0]
    client = app.test_client()
    login(client, "viewer")
    lock = RunLock(run_lock_path(config), command="watch run")
    try:
        assert lock.acquire()
        reference = lock.path.read_bytes()
        record = lock.owner_path.read_bytes()
        lock.release()
        # Restore both crash artifacts; a sidecar alone cannot identify a run.
        lock.path.write_bytes(reference)
        lock.owner_path.write_bytes(record)
        lock.owner_path.chmod(0o600)
        def dead(*args):
            raise ProcessLookupError()
        monkeypatch.setattr(locking.os, "kill", dead)
        assert lock.snapshot()["state"] == "stale"
        page = client.get("/operations/").text
        assert "Run record · stale" in page
        assert "Active run" not in page
    finally:
        app.extensions["dashboard_jobs"].shutdown()


@pytest.mark.skipif(os.name == "nt", reason="Windows PID liveness is unknown")
def test_unconfirmed_local_holder_is_not_reported_as_stopped(tmp_path):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler({})[0]
    client = app.test_client()
    login(client, "viewer")
    lock = RunLock(run_lock_path(config), command="watch run")
    try:
        assert lock.acquire()
        reference = lock.path.read_bytes()
        record = lock.owner_path.read_bytes()
        lock.release()
        # Restore the artifacts while the recorded process is still alive, so
        # the snapshot can confirm neither death nor a live lock holder.
        lock.path.write_bytes(reference)
        lock.owner_path.write_bytes(record)
        lock.owner_path.chmod(0o600)
        assert lock.snapshot()["state"] == "unknown"
        page = client.get("/operations/").text
        assert "Status unclear" in page
        assert "Run record · unknown" not in page
        assert "No command from this record is running now" not in page
        assert "Do not assume the storage is free" in page
        assert "callout-warning" in page
    finally:
        app.extensions["dashboard_jobs"].shutdown()


def test_operations_shows_installed_cron_to_viewer(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    state = {"text": scheduling.CRON_BEGIN + "\n0 */4 * * * cvebeacon watch run\n" + scheduling.CRON_END}
    app.extensions["dashboard_schedule_runner"] = fake_scheduler(state)[0]
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    client = app.test_client()
    login(client, "viewer")
    try:
        assert "Scheduled by cron" in client.get("/operations/").text
    finally:
        app.extensions["dashboard_jobs"].shutdown()
