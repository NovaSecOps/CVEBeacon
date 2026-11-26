"""Dashboard operations: permissions, jobs, locking and schedules."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import html
import os
import re
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from cvebeacon import cli, dashboard, dashboard_ops, scheduling
from cvebeacon.config import UpdateConfig, load_config
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
from systemd_support import EXECUTABLE, SERVICE, TICK, TIMER, FakeSystemd
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


def _systemd_runner(config_path, **kwargs):
    runner = FakeSystemd(config_path, **kwargs)
    return runner, runner.calls


def _policy_file(tmp_path, *, units=("cvebeacon.timer", "cvebeacon.service",
                                    "cvebeacon-dashboard.service"), enabled=True):
    path = tmp_path / "update.toml"
    encoded_units = ", ".join(f'"{unit}"' for unit in units)
    path.write_text(
        f"enabled = {str(enabled).lower()}\n"
        'prefix = "/opt/cvebeacon"\n'
        'config = "/var/lib/cvebeacon/cvebeacon.toml"\n'
        'data = "/var/lib/cvebeacon"\n'
        'user = "cvebeacon"\n'
        f"units = [{encoded_units}]\n"
        'dashboard_unit = "cvebeacon-dashboard.service"\n',
        encoding="utf-8",
    )
    return path


def test_systemd_timer_probe_maps_active_enabled_status_and_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path)
    runner, calls = _systemd_runner(config.config_path, command=("run",))

    result = scheduling.systemd_timer_status(
        "cvebeacon.timer", "cvebeacon.service", config.config_path, run=runner
    )

    assert result == {
        "state": "On",
        "boot": "Yes",
        "next_run": "2026-11-26 07:00",
        "last_run": "2026-11-25 07:04",
        "last_result": "Succeeded",
        "scan_state": "scan",
    }
    assert len(calls) == 3
    assert all(call[1]["timeout"] == 2 for call in calls)
    assert all(call[1]["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"} for call in calls)
    assert calls[0][0] == [
        "systemctl", "show",
        "--property=ActiveState,UnitFileState,NextElapseUSecRealtime,LastTriggerUSec",
        "--", "cvebeacon.timer",
    ]
    assert calls[1][0] == [
        "systemctl", "show",
        "--property=Result,ExecMainStatus,ExecMainExitTimestamp",
        "--", "cvebeacon.service",
    ]
    assert calls[2][0][:4] == ["busctl", "--system", "--json=short", "get-property"]
    assert calls[2][0][-1] == "ExecStartEx"
    assert not any("/opt/cvebeacon" in str(call) for call in result.values())


def test_systemd_timer_probe_maps_inactive_disabled_and_watch(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path)
    runner, _ = _systemd_runner(
        config.config_path, command=("watch", "run"), timer_state="inactive",
        unit_file_state="disabled",
    )

    result = scheduling.systemd_timer_status(
        "cvebeacon.timer", "cvebeacon.service", config.config_path, run=runner
    )

    assert result["state"] == "Off"
    assert result["boot"] == "No"
    assert result["scan_state"] == "watch"


@pytest.mark.parametrize("mode", ["missing", "malformed", "another_config"])
def test_systemd_timer_probe_shows_unknown_for_unmatched_service(mode, tmp_path, monkeypatch):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path)
    manager = FakeSystemd(
        tmp_path / "another.toml" if mode == "another_config" else config.config_path,
        command=("watch", "run"),
    )

    def runner(args, **kwargs):
        if args[-1] == "ExecStartEx":
            if mode == "missing":
                return _Result(returncode=1)
            if mode == "malformed":
                return _Result(stdout='{"type":"a(sasasttttuii)","data":["bad"]}')
        return manager(args, **kwargs)

    result = scheduling.systemd_timer_status(
        "cvebeacon.timer", "cvebeacon.service", config.config_path, run=runner
    )

    assert result == {
        "state": "Unknown", "boot": "Unknown", "next_run": "Unknown",
        "last_run": "Unknown", "last_result": "Unknown", "scan_state": "unknown",
    }


def test_systemd_timer_probe_maps_failed_result_and_never_run(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path)
    failed, _ = _systemd_runner(
        config.config_path, result="exit-code", exit_status=2,
    )
    failed_result = scheduling.systemd_timer_status(
        "cvebeacon.timer", "cvebeacon.service", config.config_path, run=failed
    )
    assert failed_result["last_result"] == "Failed"

    never, _ = _systemd_runner(
        config.config_path, next_run="n/a", last_trigger="n/a", last_exit="n/a",
    )
    never_result = scheduling.systemd_timer_status(
        "cvebeacon.timer", "cvebeacon.service", config.config_path, run=never
    )
    assert never_result["last_run"] == "Never"
    assert never_result["last_result"] == "Never run"
    assert never_result["next_run"] == "Not scheduled"


@pytest.mark.parametrize("mode", ["timeout", "garbage"])
def test_systemd_timer_probe_fails_closed(mode, tmp_path, monkeypatch):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path)

    def run(args, **kwargs):
        if mode == "timeout":
            raise subprocess.TimeoutExpired(args, 2)
        return _Result(stdout="not systemctl output")

    result = scheduling.systemd_timer_status(
        "cvebeacon.timer", "cvebeacon.service", config.config_path, run=run
    )

    assert result == {
        "state": "Unknown", "boot": "Unknown", "next_run": "Unknown",
        "last_run": "Unknown", "last_result": "Unknown",
        "scan_state": "unknown",
    }


def test_nonmatching_standalone_timer_keeps_cron(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path)
    app = dashboard.create_app(config)
    runner, calls = _systemd_runner(tmp_path / "another.toml")
    app.extensions["dashboard_schedule_runner"] = runner
    monkeypatch.setattr(dashboard_ops, "UPDATE_POLICY_PATH", tmp_path / "missing-update.toml")

    with app.app_context():
        assert dashboard_ops.schedule_scan_state(config) == "none"
    assert any(call[0][-1] == TIMER for call in calls)
    assert any(call[0][0] == "crontab" for call in calls)


def test_policy_presence_ignores_contents_and_blocks_cron_for_custom_units(
    tmp_path, monkeypatch
):
    # Timer detection is Linux-only; read the fakes as Linux on every runner.
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = replace(
        make_config(tmp_path), update=UpdateConfig(enabled=False)
    )
    new_accounts(config)
    app = dashboard.create_app(config)
    policy = _policy_file(
        tmp_path,
        units=("custom.timer", "custom.service", "cvebeacon-dashboard.service"),
        enabled=False,
    )
    monkeypatch.setattr(dashboard_ops, "UPDATE_POLICY_PATH", policy)
    monkeypatch.setattr(dashboard_ops, "_policy_is_administrator_owned", lambda path: True)
    monkeypatch.setattr(dashboard_ops, "_policy_file_is_administrator_owned", lambda details: True)
    calls = []

    def runner(args, **kwargs):
        calls.append((list(args), kwargs))
        return _Result(returncode=1)

    app.extensions["dashboard_schedule_runner"] = runner

    def unexpected_open(*args, **kwargs):
        raise AssertionError("the dashboard must not read the updater policy")

    with monkeypatch.context() as scoped:
        scoped.setattr(dashboard_ops.os, "open", unexpected_open)
        with app.app_context():
            snapshot = dashboard_ops._schedule_snapshot(config)

    assert snapshot["timer_managed"] is True
    assert snapshot["summary"] == "Unknown"
    assert snapshot["scan_state"] == "unknown"
    assert snapshot["timer_status"] == {
        "state": "Unknown", "boot": "Unknown", "next_run": "Unknown",
        "last_run": "Unknown", "last_result": "Unknown", "scan_state": "unknown",
    }
    assert [call[0][-1] for call in calls] == [
        "cvebeacon.timer", "cvebeacon.timer", "cvebeacon.service",
    ]

    client = app.test_client()
    login(client)
    page = client.get("/operations/schedule")
    assert page.status_code == 200
    assert "Monitoring timer" in page.text
    assert "Unknown" in page.text
    denied = submit(
        client, "/operations/schedule/install", mode="interval", every="4",
        command="watch",
    )
    assert denied.status_code == 409
    assert "Enable dashboard schedule control" in denied.text
    assert not any(call[0][0] == "crontab" for call in calls)


def test_schedule_page_shows_systemd_timer_and_enable_instructions(tmp_path, monkeypatch):
    # Timer detection is Linux-only; read the fakes as Linux on every runner.
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    runner, calls = _systemd_runner(config.config_path, command=("run",))
    app.extensions["dashboard_schedule_runner"] = runner
    policy = _policy_file(tmp_path)
    monkeypatch.setattr(dashboard_ops, "UPDATE_POLICY_PATH", policy)
    monkeypatch.setattr(dashboard_ops, "_policy_is_administrator_owned", lambda path: True)
    monkeypatch.setattr(dashboard_ops, "_policy_file_is_administrator_owned", lambda details: True)
    monkeypatch.setattr(dashboard_ops, "_running_as_root", lambda: False)
    monkeypatch.setattr(scheduling, "_trusted_executable", lambda path, *args: path == EXECUTABLE, raising=False)
    client = app.test_client()
    login(client)

    page = client.get("/operations/schedule")
    assert page.status_code == 200
    assert "Monitoring timer" in page.text
    assert "On" in page.text and "Starts at boot" in page.text
    assert "2026-11-26 07:00" in page.text
    assert "2026-11-25 07:04" in page.text
    assert "Succeeded" in page.text
    assert "Current timer schedule: Every day at 07:00 and 19:00." in page.text
    assert "sudo /opt/cvebeacon/current/.venv/bin/cvebeacon" in page.text
    assert "schedule timer-control enable" in page.text
    assert "15-minute check" in page.text
    assert "Install schedule" not in page.text
    assert "permission denied" not in page.text.casefold()
    assert "sudo /opt/cvebeacon/current/.venv/bin/cvebeacon" in page.text
    assert "ExecStart=" not in page.text
    assert not any(call[0][0] == "crontab" for call in calls)

    denied = submit(
        client, "/operations/schedule/install", mode="interval", every="4",
        command="watch",
    )
    assert denied.status_code == 409
    assert "Enable dashboard schedule control" in denied.text
    assert not any(call[0][0] == "crontab" for call in calls)


def test_standalone_timer_editor_requires_permission_csrf_and_confirmation(
    ops, monkeypatch,
):
    config, users, app, client = ops
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    monkeypatch.setattr(dashboard_ops, "UPDATE_POLICY_PATH", config.config_path.with_name("missing-update.toml"))
    runner, calls = _systemd_runner(config.config_path, command=("run", "--if-due"), calendar=TICK)
    app.extensions["dashboard_schedule_runner"] = runner
    now = datetime(2026, 11, 26, 7, tzinfo=timezone.utc)
    monkeypatch.setattr(scheduling, "local_now", lambda: now)

    login(client, "runner")
    assert client.get("/operations/schedule").status_code == 403
    login(client, "scheduler")
    page = client.get("/operations/schedule")
    assert page.status_code == 200
    assert "Change schedule" in page.text
    assert "Next scheduled run:" in page.text
    assert "Timer tick: Every 15 minutes" in page.text
    assert "Last scheduled monitoring start: Never" in page.text
    assert "Last timer check: 2026-11-25 07:00" in page.text
    assert "Last result: Succeeded" not in page.text
    assert not any(call[0][0] == "crontab" for call in calls)
    assert "This schedule is managed on the server" not in page.text

    denied = client.post(
        "/operations/schedule/install", data={"mode": "interval", "every": "5"}
    )
    assert denied.status_code == 400
    assert not (config.database_path.parent / "schedule.json").exists()

    review = submit(
        client, "/operations/schedule/install", mode="interval", every="5"
    )
    assert review.status_code == 200
    assert "Confirm schedule change" in review.text
    assert "Every 5 hours" in review.text
    assert not (config.database_path.parent / "schedule.json").exists()
    token = re.search(r'name="confirm" value="([^"]+)"', review.text)[1]

    missing_csrf = client.post(
        "/operations/schedule/install", data={"confirm": token}
    )
    assert missing_csrf.status_code == 400
    saved = client.post(
        "/operations/schedule/install",
        data={"csrf": csrf(client), "confirm": token},
    )
    assert saved.status_code == 303
    schedule = scheduling.load_timer_schedule(config.database_path.parent)
    assert schedule.every_hours == 5
    actions = [entry.action for entry in users.audit_entries()]
    assert "timer_schedule_update_requested:{\"mode\":\"interval\",\"every\":5,\"times\":null}" in actions
    assert "timer_schedule_updated:{\"mode\":\"interval\",\"every\":5,\"times\":null}" in actions


def test_dashboard_timer_schedule_validation_uses_shared_messages(ops, monkeypatch):
    config, _, app, client = ops
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        dashboard_ops,
        "_schedule_snapshot",
        lambda _config: {
            "summary": "Scheduled automatically",
            "scan_state": "scan",
            "timer_managed": True,
            "timer_status": dict(dashboard_ops.TIMER_STATUS_LABELS),
            "timer_control": {"enabled": True, "calendar_words": "", "timer_tick": "Every 15 minutes"},
        },
    )
    login(client, "scheduler")

    response = submit(
        client, "/operations/schedule/install", mode="times", times="25:00"
    )

    assert response.status_code == 400
    assert "invalid schedule time '25:00'; use HH:MM from 00:00 to 23:59" in html.unescape(response.text)
    assert not (config.database_path.parent / "schedule.json").exists()


def test_home_and_operations_use_the_same_active_timer_state(tmp_path, monkeypatch):
    # Timer detection is Linux-only; read the fakes as Linux on every runner.
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    runner, calls = _systemd_runner(config.config_path, command=("run",))
    app.extensions["dashboard_schedule_runner"] = runner
    policy = _policy_file(tmp_path)
    monkeypatch.setattr(dashboard_ops, "UPDATE_POLICY_PATH", policy)
    monkeypatch.setattr(dashboard_ops, "_policy_is_administrator_owned", lambda path: True)
    monkeypatch.setattr(dashboard_ops, "_policy_file_is_administrator_owned", lambda details: True)
    client = app.test_client()
    login(client)

    operations = client.get("/operations/")
    count_after_operations = len(calls)
    home = client.get("/")

    assert "Scheduled automatically" in operations.text
    assert "A schedule is installed for this configuration" in home.text
    assert len(calls) == count_after_operations == 5
    cached = app.extensions["operations_schedule_summary"][3]
    assert cached["summary"] == "Scheduled automatically"
    assert "/opt/cvebeacon" not in repr(cached)
    assert "argv" not in repr(cached)


def test_timer_remove_control_remains_available_for_managed_cron(tmp_path, monkeypatch):
    # Timer detection is Linux-only; read the fakes as Linux on every runner.
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    config = make_config(tmp_path)
    new_accounts(config)
    app = dashboard.create_app(config)
    systemd, _ = _systemd_runner(config.config_path)
    cron_state = {
        "text": (
            scheduling.CRON_BEGIN
            + f"\n0 */4 * * * cvebeacon --config {config.config_path} scan\n"
            + scheduling.CRON_END + "\n"
        )
    }

    def runner(args, **kwargs):
        if args[:2] == ["systemctl", "show"]:
            return systemd(args, **kwargs)
        if args == ["crontab", "-l"]:
            return _Result(stdout=cron_state["text"])
        if args == ["crontab", "-"]:
            cron_state["text"] = kwargs["input"].decode("utf-8")
            return _Result()
        return _Result(returncode=1)

    app.extensions["dashboard_schedule_runner"] = runner
    policy = _policy_file(tmp_path)
    monkeypatch.setattr(dashboard_ops, "UPDATE_POLICY_PATH", policy)
    monkeypatch.setattr(dashboard_ops, "_policy_is_administrator_owned", lambda path: True)
    monkeypatch.setattr(dashboard_ops, "_policy_file_is_administrator_owned", lambda details: True)
    client = app.test_client()
    login(client)

    page = client.get("/operations/schedule")

    assert "Remove a managed cron schedule" in page.text
    assert "The systemd timer will continue to run." in page.text
    removed = submit(client, "/operations/schedule/remove", confirm="remove")
    assert removed.status_code == 303
    assert scheduling.CRON_BEGIN not in cron_state["text"]




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
    assert "Succeeded" in history.text
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
            for _ in range(3000):
                time.sleep(0.01)  # short slices let a Windows break handler run
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
    assert marker.read_text(encoding="utf-8") == "cleaned"
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


def test_single_flight_queues_behind_a_cli_style_lock_holder(ops):
    config, _, app, client = ops
    login(client)
    set_builder(app, lambda *a, **k: fake_job("print('after release')"))
    manager = app.extensions["dashboard_jobs"]
    try:
        with RunLock(run_lock_path(config), command="watch sync"):
            response = submit(client, "/operations/run", operation="watch-sync")
            assert response.status_code == 303
            identifier = job_id(response)
            wait_for(lambda: manager.store.get(identifier).message)
            assert manager.store.get(identifier).status == "queued"
            assert "waiting for" in manager.store.get(identifier).message
        assert manager.wait(identifier).status == "succeeded"
    finally:
        manager.shutdown()


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


def test_schedule_failure_does_not_claim_an_unchanged_schedule(ops, monkeypatch):
    _, _, app, client = ops
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")

    def runner(args, **kwargs):
        if list(args) == ["crontab", "-l"]:
            return _Result(returncode=0, stdout="")
        return _Result(returncode=1, stderr="synthetic install failure")

    app.extensions["dashboard_schedule_runner"] = runner
    login(client)
    response = submit(
        client,
        "/operations/schedule/install",
        mode="interval",
        every="4",
        command="watch",
    )
    assert response.status_code == 400
    assert "synthetic install failure" in response.text
    assert "The schedule action failed" in response.text
    assert "Nothing else was changed" not in response.text
    assert "Check the value and try again" not in response.text


def test_job_history_store_retains_only_the_latest_jobs(tmp_path):
    store = JobStore(tmp_path / "dashboard-jobs")
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
    store = JobStore(tmp_path / "dashboard-jobs")
    job = store.create("scan", "admin", ["scan"])
    log = _JobLog(job.log_path)
    log.write(b"private log")
    log.close()
    paths = (tmp_path / "dashboard-jobs" / "dashboard-jobs.db", Path(job.log_path))
    if os.name == "nt":
        import msvcrt
        from cvebeacon.windows_private import validate_handle
        for path in paths:
            with open(path, "rb") as handle:
                validate_handle(msvcrt.get_osfhandle(handle.fileno()))
        assert Path(job.log_path).parent == tmp_path / "dashboard-jobs"
    else:
        for path in paths:
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert Path(job.log_path).parent.stat().st_mode & 0o077 == 0


def test_abandoned_jobs_are_failed_after_a_restart(tmp_path):
    store = JobStore(tmp_path / "dashboard-jobs")
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


def test_timer_confirmation_keeps_a_start_admitted_after_review(ops, monkeypatch):
    config, _, _, client = ops
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    monkeypatch.setattr(dashboard_ops, "_schedule_snapshot", lambda config: {
        "timer_managed": True,
        "timer_status": dict(dashboard_ops.TIMER_STATUS_LABELS),
        "timer_control": {"enabled": True},
    })
    login(client, "scheduler")
    review = submit(client, "/operations/schedule/install", mode="interval", every="5")
    token = re.search(r'name="confirm" value="([^"]+)"', review.text)[1]
    now = datetime(2026, 11, 26, 7, tzinfo=timezone.utc)
    original_record = dashboard_ops._record

    def admit_during_confirmation(action, detail=None):
        if action == "timer_schedule_update_requested":
            assert scheduling.should_run_scheduled(config.database_path.parent, now)
        original_record(action, detail)

    monkeypatch.setattr(dashboard_ops, "_record", admit_during_confirmation)
    assert submit(client, "/operations/schedule/install", confirm=token).status_code == 303
    schedule = scheduling.load_timer_schedule(config.database_path.parent)
    assert schedule.every_hours == 5
    assert schedule.last_start == now
