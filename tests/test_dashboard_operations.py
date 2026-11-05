"""Dashboard operations: permissions, jobs, locking and schedules."""

from __future__ import annotations

from dataclasses import replace
import os
import re
import stat
import sys
import textwrap
import time
from pathlib import Path

import pytest

from cvebeacon import cli, dashboard, scheduling
from cvebeacon.config import load_config
from cvebeacon.dashboard_jobs import (
    MAX_LOG_BYTES,
    MAX_LOG_TAIL,
    JobStore,
    build_command,
    full_history_confirmation_required,
)
from cvebeacon.errors import ConfigurationError, StateError
from cvebeacon.locking import RunLock, run_lock_path
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from watch_support import write_config

PASSWORD = "Synthetic operations password 123"
CHANNELS = """
[watch.channels.sink]
type = "webhook"
url = "http://127.0.0.1:9/sink"
allow_insecure = true
"""


def csrf(client, path="/account"):
    page = client.get(path)
    assert page.status_code == 200
    return re.search(r'name="csrf" value="([^"]+)"', page.text)[1]


def login(client, username="admin"):
    token = csrf(client, "/login")
    response = client.post(
        "/login",
        data={"csrf": token, "username": username, "password": PASSWORD},
    )
    assert response.status_code == 303


def submit(client, path, **values):
    response = client.post(
        path, data={"csrf": csrf(client), **values}
    )
    return response


def make_config(tmp_path, *, initial="baseline", channels=CHANNELS):
    config = write_config(
        tmp_path,
        sources=("nvd",),
        initial=initial,
        channels=channels,
        extra="",
    )
    (tmp_path / "missing-inventory.csv").write_text(
        "asset_id,vendor,product,version\na,Acme,Widget,1\n", encoding="utf-8"
    )
    return config


def new_accounts(config):
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    for name in ("viewer", "runner", "retrier", "tester", "scheduler", "empty"):
        users.add(name, password=PASSWORD)
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("viewer-only", {"view"}, authorization=admin)
    users.save_role("runner-only", {"view", "run"}, authorization=admin)
    users.save_role("retrier-only", {"view", "retry"}, authorization=admin)
    users.save_role("tester-only", {"view", "test_channel"}, authorization=admin)
    users.save_role(
        "scheduler-only", {"view", "manage_schedule"}, authorization=admin
    )
    users.save_role("empty", set(), authorization=admin)
    for name, role in (
        ("viewer", "viewer-only"),
        ("runner", "runner-only"),
        ("retrier", "retrier-only"),
        ("tester", "tester-only"),
        ("scheduler", "scheduler-only"),
        ("empty", "empty"),
    ):
        users.edit_user(name, role=role, disabled=False, authorization=admin)
    return users


@pytest.fixture
def ops(tmp_path):
    config = make_config(tmp_path)
    users = new_accounts(config)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler({})[0]
    return config, users, app, app.test_client()


class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def fake_scheduler(state):
    """A crontab-like fake that also records every invocation."""
    calls = []

    def run(args, **kwargs):
        calls.append((list(args), kwargs))
        if args == ["crontab", "-l"]:
            return _Result(stdout=state.get("text", ""))
        if args == ["crontab", "-"]:
            state["text"] = kwargs.get("input", b"").decode("utf-8")
            return _Result()
        if args[:2] == ["schtasks", "/Query"]:
            return _Result(stdout=state.get("windows", ""))
        return _Result()

    return run, calls


def fake_job(script, *arguments):
    return [sys.executable, "-c", textwrap.dedent(script), *map(str, arguments)]


def set_builder(app, builder):
    app.extensions["dashboard_jobs"].command_builder = builder


def job_id(response):
    location = response.headers["Location"]
    return int(location.rstrip("/").rsplit("/", 1)[1])


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("condition was not reached in time")


def test_operations_page_and_job_history_are_visible_with_view(ops):
    _, _, app, client = ops
    login(client, "viewer")
    response = client.get("/operations/")
    assert response.status_code == 200
    assert "Operations" in response.text
    assert client.get("/operations/jobs").status_code == 200


def test_each_operation_uses_its_declared_permission(ops):
    _, _, app, client = ops

    login(client, "runner")
    set_builder(app, lambda *args, **kwargs: fake_job("print('ok')"))
    response = submit(client, "/operations/run", operation="watch-notify")
    assert response.status_code == 303
    app.extensions["dashboard_jobs"].wait(job_id(response))
    assert submit(client, "/operations/retry", operation="watch-retry-failed").status_code == 403
    assert submit(client, "/operations/test", channel="sink").status_code == 403
    client.get("/logout")

    login(client, "retrier")
    response = submit(client, "/operations/retry", operation="watch-retry-failed")
    assert response.status_code == 303
    app.extensions["dashboard_jobs"].wait(job_id(response))
    assert submit(client, "/operations/run", operation="watch-notify").status_code == 403
    client.get("/logout")

    login(client, "tester")
    response = submit(client, "/operations/test", channel="sink")
    assert response.status_code == 303
    app.extensions["dashboard_jobs"].wait(job_id(response))
    assert submit(client, "/operations/run", operation="watch-notify").status_code == 403
    client.get("/logout")

    login(client, "scheduler")
    assert client.get("/operations/schedule").status_code == 200
    assert submit(client, "/operations/run", operation="watch-notify").status_code == 403
    assert submit(client, "/operations/retry", operation="watch-retry-failed").status_code == 403
    client.get("/logout")

    login(client, "empty")
    assert client.get("/operations/").status_code == 403
    assert submit(client, "/operations/run", operation="watch-notify").status_code == 403


def test_job_succeeds_records_log_and_audit(ops):
    _, users, app, client = ops
    login(client)
    set_builder(app, lambda *args, **kwargs: fake_job("print('job succeeded')"))
    response = submit(client, "/operations/run", operation="watch-notify")
    assert response.status_code == 303
    manager = app.extensions["dashboard_jobs"]
    job = manager.wait(job_id(response))
    assert job.status == "succeeded"
    assert job.exit_code == 0
    assert "job succeeded" in manager.store.log_tail(job)
    assert "job succeeded" in client.get(f"/operations/jobs/{job.id}").text
    history = client.get("/operations/jobs")
    assert history.status_code == 200
    assert "Deliver pending alerts" in history.text
    assert "succeeded" in history.text
    actions = [entry.action for entry in users.audit_entries()]
    assert f"job_started:{job.id}:{job.operation}" in actions
    wait_for(lambda: f"job_succeeded:{job.id}:{job.operation}" in [entry.action for entry in users.audit_entries()])
    assert users.verify_audit() is None


def test_job_failure_shows_exit_meaning(ops):
    _, _, app, client = ops
    login(client)
    set_builder(app, lambda *args, **kwargs: fake_job("import sys; print('bad'); sys.exit(2)"))
    response = submit(client, "/operations/run", operation="watch-notify")
    manager = app.extensions["dashboard_jobs"]
    job = manager.wait(job_id(response))
    assert job.status == "failed"
    assert job.exit_code == 2
    page = client.get(f"/operations/jobs/{job.id}")
    assert page.status_code == 200
    assert "Validation or operational failure" in page.text
    assert "bad" in page.text


def test_cancel_sends_interrupt_and_cleanup_runs(ops, tmp_path):
    _, _, app, client = ops
    login(client)
    marker = tmp_path / "cleanup.txt"

    def builder(config, operation, *, confirmed=False, channel=None):
        return fake_job(
            """
            import pathlib
            import signal
            import sys
            import time

            def stop(signum, frame):
                pathlib.Path(sys.argv[1]).write_text("cleaned")
                raise SystemExit(130)

            signal.signal(signal.SIGINT, stop)
            if hasattr(signal, "SIGBREAK"):
                signal.signal(signal.SIGBREAK, stop)
            print("ready", flush=True)
            time.sleep(30)
            """,
            marker,
        )

    set_builder(app, builder)
    response = submit(client, "/operations/run", operation="watch-notify")
    manager = app.extensions["dashboard_jobs"]
    job = manager.wait(job_id(response), statuses=frozenset({"running"}))
    wait_for(lambda: "ready" in manager.store.log_tail(manager.store.get(job.id)))
    assert client.post(
        f"/operations/jobs/{job.id}/cancel",
        data={"csrf": csrf(client)},
    ).status_code == 303
    job = manager.wait(job.id, timeout=10)
    assert job.status == "cancelled"
    assert job.exit_code == 130
    assert marker.read_text() == "cleaned"
    assert "cleanup" in client.get(f"/operations/jobs/{job.id}").text.lower()


def test_queued_job_can_be_cancelled_before_it_starts(tmp_path):
    config = make_config(tmp_path)
    users = new_accounts(config)
    app = dashboard.create_app(config)
    manager = app.extensions["dashboard_jobs"]
    first = manager.submit(
        "watch-notify",
        started_by="admin",
        argv=fake_job("import time; time.sleep(5)"),
    )
    assert manager.wait(first.id, statuses=frozenset({"running"}))
    second = manager.submit(
        "watch-notify",
        started_by="admin",
        argv=fake_job("print('must not run')"),
    )
    assert manager.store.get(second.id).status == "queued"
    assert manager.cancel(second.id)
    assert manager.store.get(second.id).status == "cancelled"
    assert manager.cancel(first.id)
    assert manager.wait(first.id).status == "cancelled"
    assert not Path(second.log_path).exists()


def test_log_storage_and_tail_are_bounded(ops):
    _, _, app, client = ops
    login(client)
    set_builder(
        app,
        lambda *args, **kwargs: fake_job("print('x' * 400000, flush=True)"),
    )
    response = submit(client, "/operations/run", operation="watch-notify")
    manager = app.extensions["dashboard_jobs"]
    job = manager.wait(job_id(response), timeout=15)
    assert job.status == "succeeded"
    assert Path(job.log_path).stat().st_size <= MAX_LOG_BYTES
    tail = manager.store.log_tail(job)
    assert 0 < len(tail) <= MAX_LOG_TAIL
    page = client.get(f"/operations/jobs/{job.id}")
    assert page.status_code == 200


def test_single_flight_blocks_a_cli_style_lock_holder(ops):
    config, _, app, client = ops
    login(client)
    with RunLock(run_lock_path(config), command="watch sync"):
        response = submit(client, "/operations/run", operation="watch-sync")
    assert response.status_code == 409
    assert b"another run is in progress" in response.data.lower()
    assert app.extensions["dashboard_jobs"].store.recent() == ()


def test_cli_refuses_when_the_shared_lock_is_held(tmp_path, capsys):
    config = make_config(tmp_path)
    with RunLock(run_lock_path(config), command="watch sync"):
        assert cli.main(
            ["--config", str(config.config_path), "watch", "sync"]
        ) == 2
    assert "another run is in progress" in capsys.readouterr().err


def test_cli_releases_the_lock_after_a_command(tmp_path):
    config = make_config(tmp_path)
    arguments = [
        "--config",
        str(config.config_path),
        "watch",
        "evaluate",
        "--all",
        "--yes",
    ]
    assert cli.main(arguments) == 0
    assert cli.main(arguments) == 0


def test_full_history_requires_confirmation_before_the_yes_flag(tmp_path):
    config = make_config(tmp_path, initial="full")
    assert full_history_confirmation_required(config)
    with pytest.raises(ConfigurationError, match="full-history"):
        build_command(config, "watch-sync")
    command = build_command(config, "watch-sync", confirmed=True)
    assert command[-1] == "--yes"
    assert full_history_confirmation_required(replace(config, watch=replace(config.watch, initial="baseline"))) is False


def test_full_history_route_has_a_confirmation_step(tmp_path):
    config = make_config(tmp_path, initial="full")
    users = new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    captured = {}

    def builder(config, operation, *, confirmed=False, channel=None):
        captured["value"] = confirmed
        return fake_job("print('started')")

    set_builder(app, builder)
    response = submit(client, "/operations/run", operation="watch-sync")
    assert response.status_code == 409
    assert "confirmation" in response.text.lower()
    assert app.extensions["dashboard_jobs"].store.recent() == ()
    response = submit(
        client, "/operations/run", operation="watch-sync", confirm="full-history"
    )
    assert response.status_code == 303
    assert captured["value"] is True


def test_schedule_page_installs_and_removes_with_fake_runners(ops, monkeypatch):
    config, _, app, client = ops
    state = {}
    runner, calls = fake_scheduler(state)
    app.extensions["dashboard_schedule_runner"] = runner
    # Keep launcher paths independent of the checkout's name.
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scheduling.sys, "executable", "/opt/monitor/python")
    monkeypatch.setattr(scheduling.sys, "argv", ["/opt/monitor/pytest"])
    login(client)
    page = client.get("/operations/schedule")
    assert page.status_code == 200
    assert "not installed" in page.text
    response = submit(
        client,
        "/operations/schedule/install",
        mode="times",
        times="07:00,19:00",
        command="watch",
    )
    assert response.status_code == 303
    assert any(args == ["crontab", "-"] for args, _ in calls)
    assert scheduling.CRON_BEGIN in state["text"]
    assert scheduling.CRON_END in state["text"]
    assert "0 7,19 * * *" in state["text"]
    page = client.get("/operations/schedule")
    assert "CVEBeacon" in page.text
    assert submit(
        client,
        "/operations/schedule/remove",
        confirm="remove",
    ).status_code == 303
    assert state["text"] == ""
    actions = [entry.action for entry in app.extensions["dashboard_users"].audit_entries()]
    assert any(action.startswith('schedule_installed:{"command":"watch","times":"07:00,19:00"') for action in actions)
    assert "schedule_removed" in actions


def test_schedule_interval_install(ops, monkeypatch):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    _, _, app, client = ops
    state = {}
    runner, _ = fake_scheduler(state)
    app.extensions["dashboard_schedule_runner"] = runner
    login(client)
    response = submit(
        client,
        "/operations/schedule/install",
        mode="interval",
        every="6",
        command="watch",
    )
    assert response.status_code == 303
    assert "*/6" in state["text"]


def test_windows_logged_out_password_is_memory_only(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    users = new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    secret = "Synthetic service password 456"
    calls = []

    def runner(args, **kwargs):
        calls.append((list(args), kwargs))
        return _Result()

    app.extensions["dashboard_schedule_runner"] = runner
    response = submit(
        client,
        "/operations/schedule/install",
        mode="interval",
        every="4",
        command="watch",
        run_logged_out="yes",
        account="svc-cvebeacon",
        password=secret,
    )
    assert response.status_code == 303
    assert any(
        "register.ps1" in " ".join(args) for args, _ in calls
    )
    assert any(
        secret in kwargs.get("input", b"").decode("utf-8", "replace")
        for _, kwargs in calls
    )
    page = client.get("/operations/schedule")
    assert secret not in page.text
    assert all(secret not in entry.action for entry in users.audit_entries())
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes()


def test_windows_logged_out_password_is_redacted_from_errors(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    secret = "Synthetic rejection password 987"

    def runner(args, **kwargs):
        if "register.ps1" in " ".join(args):
            return _Result(returncode=1, stderr=f"registration rejected {secret}")
        return _Result()

    app.extensions["dashboard_schedule_runner"] = runner
    response = submit(
        client,
        "/operations/schedule/install",
        mode="interval",
        every="4",
        command="watch",
        run_logged_out="yes",
        account="svc-cvebeacon",
        password=secret,
    )
    assert response.status_code == 400
    assert secret not in response.text
    assert "[redacted]" in response.text


def test_schedule_install_is_blocked_when_it_would_use_root(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    users = new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    runner, _ = fake_scheduler({})
    app.extensions["dashboard_schedule_runner"] = runner
    monkeypatch.setattr("cvebeacon.dashboard_ops._running_as_root", lambda: True)
    page = client.get("/operations/schedule")
    assert page.status_code == 200
    assert "running as root" in page.text
    assert "Command-line fallback" in page.text
    response = submit(
        client,
        "/operations/schedule/install",
        mode="interval",
        every="4",
        command="watch",
    )
    assert response.status_code == 400
    assert "command-line fallback" in response.text.lower()


def test_job_history_store_retains_only_the_latest_jobs(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    first = store.create("scan", "admin", ["scan"])
    store.finish(first.id, "succeeded", exit_code=0)
    store.clear_audit(first.id)
    for _ in range(205):
        job = store.create("scan", "admin", ["scan"])
        store.finish(job.id, "succeeded", exit_code=0)
        store.clear_audit(job.id)
    jobs = store.recent(50)
    assert len(jobs) == 50
    assert store.get(first.id) is None


def test_job_history_file_is_owner_only(tmp_path):
    from cvebeacon.dashboard_jobs import _JobLog
    store = JobStore(tmp_path / "jobs.db")
    job = store.create("scan", "admin", ["scan"])
    log = _JobLog(job.log_path)
    log.write(b"private log")
    log.close()
    paths = (tmp_path / "jobs.db", Path(job.log_path))
    if os.name == "nt":
        import msvcrt
        from cvebeacon.windows_private import validate_handle
        for path in paths:
            with open(path, "rb") as handle:
                validate_handle(msvcrt.get_osfhandle(handle.fileno()))
    else:
        for path in paths:
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert Path(job.log_path).parent.stat().st_mode & 0o077 == 0


def test_abandoned_jobs_are_failed_after_a_restart(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    job = store.create("scan", "admin", ["scan"])
    assert store.mark_running(job.id)
    assert store.fail_interrupted() == 1
    current = store.get(job.id)
    assert current.status == "failed"
    assert "stopped" in current.message


def test_audit_action_does_not_create_a_missing_user_store(tmp_path):
    users = UserStore(tmp_path / "users.db")
    with pytest.raises(StateError, match="not found"):
        users.record_action("job_started", username="admin")
    assert not (tmp_path / "users.db").exists()


def test_channel_tests_disabled_in_builder_and_routes(tmp_path):
    config = make_config(tmp_path)
    config = replace(config, watch=replace(config.watch, enabled=False))
    new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    login(client)
    assert 'Test a channel' not in client.get('/operations/').text
    assert submit(client, '/operations/test', channel='sink').status_code == 400
    assert app.extensions['dashboard_jobs'].store.recent() == ()
    with pytest.raises(ConfigurationError, match='disabled'):
        build_command(config, 'notify-test', channel='sink')
