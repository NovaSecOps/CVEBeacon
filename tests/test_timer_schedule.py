"""Dashboard-controlled systemd timer scheduling."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import os
from pathlib import Path, PureWindowsPath
import struct
from threading import Event
from zoneinfo import ZoneInfo

import pytest

from cvebeacon import cli, scheduling
from cvebeacon.errors import SchedulingError
from systemd_support import DROPIN, EXECUTABLE, SERVICE, TICK, TIMER, FakeSystemd, posix_path
from watch_support import write_config


posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor and ownership semantics")


def _test_zone():
    # A synthetic TZif zone keeps the fold and gap tests independent of host tzdata.
    change = [int(datetime(2026, month, day, 1, tzinfo=timezone.utc).timestamp())
              for month, day in ((3, 29), (10, 25))]
    header = struct.pack(">4sc15x6I", b"TZif", b"\0", 0, 0, 0, 2, 2, 8)
    body = struct.pack(">2i2B i2B i2B", *change, 1, 0, 0, 0, 0, 3600, 1, 4)
    return ZoneInfo.from_file(BytesIO(header + body + b"STD\0DST\0"))



@pytest.fixture(autouse=True)
def linux_scheduler(monkeypatch):
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")


def test_interval_due_uses_elapsed_time_and_records_start(tmp_path):
    start = datetime(2026, 11, 26, 7, tzinfo=timezone.utc)
    schedule = scheduling.build_timer_schedule(every_hours=4, last_start=start)

    assert not scheduling.schedule_due(schedule, start + timedelta(hours=3, minutes=59))
    assert scheduling.schedule_due(schedule, start + timedelta(hours=4))
    assert scheduling.should_run_scheduled(
        tmp_path, now=start + timedelta(hours=4)
    )
    assert not scheduling.should_run_scheduled(
        tmp_path, now=start + timedelta(hours=4, minutes=15)
    )
    saved = scheduling.load_timer_schedule(tmp_path)
    assert saved.last_start == start + timedelta(hours=4)


def test_fixed_times_catch_up_only_once_after_missed_times(tmp_path):
    now = datetime(2026, 11, 26, 21, 30, tzinfo=timezone.utc)
    schedule = scheduling.build_timer_schedule(
        times="07:00,12:00,19:00",
        last_start=datetime(2026, 11, 25, 20, tzinfo=timezone.utc),
    )

    assert scheduling.schedule_due(schedule, now)
    assert scheduling.should_run_scheduled(tmp_path, now=now)
    assert not scheduling.should_run_scheduled(
        tmp_path, now=now + timedelta(minutes=15)
    )


def test_first_run_without_history_uses_interval_and_fixed_time_rules(tmp_path):
    morning = datetime(2026, 11, 26, 6, 45, tzinfo=timezone.utc)
    evening = datetime(2026, 11, 26, 7, 1, tzinfo=timezone.utc)

    assert scheduling.schedule_due(
        scheduling.build_timer_schedule(every_hours=4), morning
    )
    fixed = scheduling.build_timer_schedule(times="07:00,19:00")
    assert not scheduling.schedule_due(fixed, morning)
    assert scheduling.schedule_due(fixed, evening)


def test_fallback_schedule_file_defaults_to_shipped_times_and_never_runs_each_tick(
    tmp_path,
):
    before = datetime(2026, 11, 26, 6, 45, tzinfo=timezone.utc)
    due = datetime(2026, 11, 26, 7, 1, tzinfo=timezone.utc)

    assert scheduling.load_timer_schedule(tmp_path).times == ("07:00", "19:00")
    assert not scheduling.should_run_scheduled(tmp_path, now=before)
    assert scheduling.should_run_scheduled(tmp_path, now=due)
    assert not scheduling.should_run_scheduled(
        tmp_path, now=due + timedelta(minutes=15)
    )


def test_fixed_time_does_not_run_twice_when_clock_repeats_an_hour(tmp_path):
    zone = _test_zone()
    first_0135 = datetime(2026, 10, 25, 1, 35, tzinfo=zone, fold=0)
    repeated_0145 = datetime(2026, 10, 25, 1, 45, tzinfo=zone, fold=1)
    schedule = scheduling.build_timer_schedule(times="01:30")
    scheduling.save_timer_schedule(tmp_path, schedule)

    assert scheduling.should_run_scheduled(tmp_path, now=first_0135)
    assert not scheduling.should_run_scheduled(tmp_path, now=repeated_0145)


@pytest.fixture
def fake_switch(tmp_path, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("the unprivileged service-account fixture requires a non-root caller")
    root = tmp_path / "system"
    (root / "etc/systemd/system").mkdir(parents=True)
    release = root / "opt/cvebeacon/releases/1.2.3"
    executable = release / ".venv/bin/cvebeacon"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/false\n", encoding="utf-8", newline="\n")
    executable.chmod(0o755)
    release.parent.parent.joinpath("current").symlink_to("releases/1.2.3", target_is_directory=True)
    root.chmod(0o755)
    for directory in (*root.glob("etc/**"), *root.glob("opt/**")):
        directory.chmod(0o755)
    data = tmp_path / "data"
    data.mkdir()
    config = write_config(data, inventory=False)
    runner = FakeSystemd(config.config_path, root=root)
    runner.service["User"] = str(os.geteuid())

    # This fixture exercises the real service-side parser and descriptor
    # writer as its own unprivileged account. The root-only UID change is
    # replaced at the boundary so the test never needs elevated privileges.
    def initialize(data, config_path, account, initial):
        assert data == config.database_path.parent
        assert account.pw_uid == os.geteuid()
        with scheduling._schedule_directory(data) as directory:
            scheduling._initialize_schedule_as_service(directory, config_path, initial)

    monkeypatch.setattr(scheduling, "_initialize_timer_data", initialize, raising=False)
    return root, config, runner


def _switch(action, root, config, runner, **kwargs):
    return scheduling.timer_control(
        action, run=runner, root_directory=root, geteuid=lambda: 0,
        **({"config_path": config.config_path, "data_directory": config.database_path.parent}
           if action == "enable" else {}),
        **kwargs,
    )


def _dropins(root):
    return tuple(root / "etc/systemd/system" / (unit + ".d") / DROPIN for unit in (TIMER, SERVICE))


@posix_only
def test_timer_control_enable_preserves_command_and_writes_private_dropins(fake_switch):
    root, config, runner = fake_switch
    runner.argv += ["--yes"]

    assert _switch("enable", root, config, runner) == "dashboard schedule control enabled"
    timer, service = _dropins(root)
    assert timer.read_text(encoding="utf-8") == (
        "[Timer]\nOnCalendar=\nOnCalendar=*:0/15\nPersistent=true\n"
    )
    service_text = service.read_text(encoding="utf-8")
    assert "ExecStart=\n" in service_text
    assert f'ExecStart=:"{EXECUTABLE}"' in service_text
    assert f'"{config.config_path}"' in service_text
    assert '"run" "--yes" "--if-due"' in service_text
    assert timer.stat().st_mode & 0o777 == 0o600
    assert service.stat().st_mode & 0o777 == 0o600
    assert scheduling.load_timer_schedule(config.database_path.parent).times == ("07:00", "19:00")
    assert runner.actions[-2:] == [["daemon-reload"], ["restart", TIMER]]
    assert runner.loaded_dropins == (True, True)


@posix_only
def test_timer_control_publishes_only_fixed_dropin_files(fake_switch, monkeypatch):
    root, config, runner = fake_switch
    published = []
    publish = scheduling._publish_file

    def record_publish(directory_fd, name, temporary):
        systemd_root = root / "etc/systemd/system"
        details = os.fstat(directory_fd)
        directories = (systemd_root, *(
            path for path in systemd_root.rglob("*") if path.is_dir()
        ))
        if any(
            (details.st_dev, details.st_ino) == (path.stat().st_dev, path.stat().st_ino)
            for path in directories
        ):
            published.append(name)
        return publish(directory_fd, name, temporary)

    monkeypatch.setattr(scheduling, "_publish_file", record_publish)
    _switch("enable", root, config, runner)

    assert published
    assert set(published) == {DROPIN}
    files = {
        path.relative_to(root / "etc/systemd/system")
        for path in (root / "etc/systemd/system").rglob("*")
        if path.is_file()
    }
    assert files == {Path(TIMER + ".d") / DROPIN, Path(SERVICE + ".d") / DROPIN}


@posix_only
def test_timer_control_parses_initial_interval_and_is_idempotent(fake_switch):
    root, config, runner = fake_switch
    runner.calendar = ("*-*-* 00/6:00:00",)
    _switch("enable", root, config, runner)
    saved = scheduling.load_timer_schedule(config.database_path.parent)
    assert saved.every_hours == 6
    assert saved.times == ()

    timer = _dropins(root)[0]
    timer_before = timer.read_bytes()
    calls_before = len(runner.calls)
    actions_before = runner.actions
    assert _switch("enable", root, config, runner) == "dashboard schedule control is already enabled"
    assert timer.read_bytes() == timer_before
    assert runner.actions == actions_before
    assert {args[0] for args, _ in runner.calls[calls_before:]} == {"systemctl", "busctl"}


@posix_only
def test_timer_control_uses_default_for_a_custom_calendar(fake_switch):
    root, config, runner = fake_switch
    runner.calendar = ("Mon *-*-* 07:00:00",)
    _switch("enable", root, config, runner)

    saved = scheduling.load_timer_schedule(config.database_path.parent)
    assert saved.times == ("07:00", "19:00")
    assert (config.database_path.parent / "schedule.json").stat().st_mode & 0o777 == 0o600


@posix_only
def test_timer_control_refuses_unexpected_execstart_without_writing(fake_switch):
    root, config, runner = fake_switch
    runner.argv[3:] = ["watch", "run"]
    with pytest.raises(SchedulingError, match="expected CVEBeacon run command"):
        _switch("enable", root, config, runner)

    assert not any(path.parent.exists() for path in _dropins(root))


@posix_only
def test_timer_control_disable_removes_only_its_dropins(fake_switch):
    root, config, runner = fake_switch
    _switch("enable", root, config, runner)
    timer, service = _dropins(root)
    for path in (timer, service):
        path.with_name("local.conf").write_text("keep\n", encoding="utf-8", newline="\n")
    config.config_path.unlink()
    policy = root / "etc/cvebeacon/update.toml"
    policy.parent.mkdir(mode=0o755)
    policy.write_text("broken policy [", encoding="utf-8", newline="\n")

    assert _switch("disable", root, config, runner) == "dashboard schedule control disabled"
    assert not timer.exists() and not service.exists()
    assert timer.with_name("local.conf").read_text(encoding="utf-8") == "keep\n"
    assert service.with_name("local.conf").read_text(encoding="utf-8") == "keep\n"
    assert runner.actions[-2:] == [["daemon-reload"], ["restart", TIMER]]
    actions = runner.actions
    assert _switch("disable", root, config, runner) == "dashboard schedule control drop-ins are already absent"
    assert runner.actions == actions


def test_timer_control_requires_root_for_every_action(tmp_path):
    for action in ("enable", "disable", "status"):
        with pytest.raises(SchedulingError, match="must run as root"):
            scheduling.timer_control(
                action, data_directory=tmp_path, config_path=tmp_path / "cvebeacon.toml",
                run=lambda *args, **kwargs: pytest.fail("unprivileged call must not reach systemd"),
                root_directory=tmp_path, geteuid=lambda: 1000,
            )


def test_dashboard_detects_control_from_loaded_systemd_properties(tmp_path, monkeypatch):
    config_path = tmp_path / "cvebeacon.toml"
    # The standalone install being modeled uses an administrator-owned entry point.
    monkeypatch.setattr(scheduling, "_trusted_executable", lambda path, *args: path == EXECUTABLE, raising=False)
    baseline = FakeSystemd(config_path)
    disabled = scheduling.systemd_timer_control_status(TIMER, SERVICE, config_path, run=baseline)
    assert disabled["enabled"] is False
    assert disabled["calendar_words"] == "Every day at 07:00 and 19:00"
    assert "schedule timer-control enable" in disabled["enable_command"]

    active = FakeSystemd(config_path, calendar=TICK, command=("run", "--if-due"))
    enabled = scheduling.systemd_timer_control_status(TIMER, SERVICE, config_path, run=active)
    assert enabled["enabled"] is True
    assert enabled["timer_tick"] == "Every 15 minutes"

    unexpected = FakeSystemd(config_path, command=("watch", "run"))
    refused = scheduling.systemd_timer_control_status(TIMER, SERVICE, config_path, run=unexpected)
    assert refused["enabled"] is False
    assert refused["enable_command"] is None


def test_schedule_validation_uses_existing_bounds_and_messages():
    with pytest.raises(SchedulingError, match="schedule interval must be a whole number from 2 through 24 hours"):
        scheduling.build_timer_schedule(every_hours=1)
    with pytest.raises(SchedulingError, match="invalid schedule time"):
        scheduling.build_timer_schedule(times="25:00")


def test_run_if_due_skips_without_scanning_when_not_due(tmp_path, monkeypatch, caplog):
    caplog.set_level("INFO")
    config = write_config(tmp_path, inventory=False)
    future = datetime.now(timezone.utc) + timedelta(minutes=1)
    scheduling.save_timer_schedule(
        config.database_path.parent,
        scheduling.build_timer_schedule(every_hours=4, last_start=future),
    )
    monkeypatch.setattr(
        cli, "_run_all",
        lambda *args, **kwargs: pytest.fail("not-due run must not scan"),
    )

    assert cli.main([
        "--config", str(config.config_path), "run", "--if-due",
    ]) == 0
    assert "scheduled run not due" in caplog.text
    assert scheduling.load_timer_schedule(config.database_path.parent).last_start == future


def test_run_if_due_records_start_before_starting_monitoring(tmp_path, monkeypatch):
    config = write_config(tmp_path, inventory=False)
    scheduling.save_timer_schedule(
        config.database_path.parent,
        scheduling.build_timer_schedule(every_hours=4),
    )
    starts = []

    def run_all(app_config, *, yes=False):
        starts.append(scheduling.load_timer_schedule(app_config.database_path.parent).last_start)
        return 0

    monkeypatch.setattr(cli, "_run_all", run_all)

    assert cli.main([
        "--config", str(config.config_path), "run", "--if-due",
    ]) == 0
    assert len(starts) == 1
    assert starts[0] is not None
    assert starts[0].tzinfo is not None


def test_first_late_appointment_catches_up_across_midnight(tmp_path):
    first = datetime(2026, 11, 26, 23, 45, tzinfo=timezone.utc)
    scheduling.save_timer_schedule(tmp_path, scheduling.build_timer_schedule(times="23:59"))

    assert not scheduling.should_run_scheduled(tmp_path, first)
    assert scheduling.should_run_scheduled(tmp_path, first + timedelta(minutes=15))
    assert not scheduling.should_run_scheduled(tmp_path, first + timedelta(minutes=30))


def test_saved_late_appointment_catches_up_on_its_first_tick(tmp_path, monkeypatch):
    saved_at = datetime(2026, 11, 26, 23, 55, tzinfo=timezone.utc)
    monkeypatch.setattr(scheduling, "local_now", lambda: saved_at, raising=False)
    scheduling.change_timer_schedule(tmp_path, scheduling.build_timer_schedule(times="23:59"))
    assert scheduling.should_run_scheduled(tmp_path, saved_at + timedelta(minutes=5))


def test_future_history_rejects_large_skew_and_blocks_small_skew(tmp_path):
    now = datetime(2026, 11, 26, 7, 15, tzinfo=timezone.utc)
    schedule = scheduling.build_timer_schedule(
        times="07:00", last_start=now + timedelta(minutes=1),
    )
    assert not scheduling.schedule_due(schedule, now)

    scheduling.save_timer_schedule(tmp_path, scheduling.build_timer_schedule(
        2, last_start=now + timedelta(days=1),
    ))
    with pytest.raises(SchedulingError, match="future"):
        scheduling.should_run_scheduled(tmp_path, now)


@pytest.mark.parametrize("payload", [
    pytest.param(b'{"version":' + b"1" * 5000 + b"}", id="integer"),
    pytest.param(b"[" * 8000 + b"]" * 8000, id="nesting"),
    pytest.param(
        b'{"version":1,"every_hours":null,"times":["07:00"],'
        b'"last_start":"0001-01-01T00:00:00+23:59"}', id="timestamp",
    ),
])
def test_corrupt_schedule_is_a_handled_error(tmp_path, payload, monkeypatch):
    path = tmp_path / "schedule.json"
    path.write_bytes(payload)
    path.chmod(0o600)

    if payload.startswith(b"["):
        # Some Python versions decode nested arrays without recursion. Run
        # their stdlib Python scanner too, which has a recursive parse path.
        monkeypatch.setattr(json.scanner, "make_scanner", json.scanner.py_make_scanner)
        monkeypatch.setattr(json, "_default_decoder", json.JSONDecoder())
    with pytest.raises(SchedulingError):
        scheduling.load_timer_schedule(tmp_path)


def test_time_validator_canonicalizes_decimal_minutes():
    assert scheduling.parse_times("07:0٣") == ("07:03",)
    with pytest.raises(SchedulingError, match="duplicate"):
        scheduling.parse_times("07:03,07:0٣")


def test_prediction_uses_gap_fold_and_quarter_hour_windows():
    zone = _test_zone()
    gap = scheduling.build_timer_schedule(times="01:30")
    before_gap = datetime(2026, 3, 29, 0, 45, tzinfo=zone)
    after_gap = datetime(2026, 3, 29, 2, tzinfo=zone)
    assert scheduling.schedule_next_run(gap, before_gap) == after_gap
    assert scheduling.schedule_due(gap, after_gap)

    start = datetime(2026, 10, 25, 1, 30, tzinfo=zone)
    fold = scheduling.build_timer_schedule(times="01:30", last_start=start)
    second = datetime(2026, 10, 25, 1, 15, tzinfo=zone, fold=1)
    assert not scheduling.schedule_due(fold, second)
    assert scheduling.schedule_next_run(fold, second).isoformat() == "2026-10-26T01:30:00+00:00"

    off_tick = scheduling.build_timer_schedule(times="07:02")
    assert scheduling.schedule_next_run(
        off_tick, datetime(2026, 11, 26, 7, tzinfo=zone)
    ).minute == 15


@pytest.mark.parametrize(("spec", "times"), [
    ("*-*-* 07:30:00", ("07:30",)),
    ("*-*-* 00/5:00:00", ("00:00", "05:00", "10:00", "15:00", "20:00")),
])
def test_calendar_migration_preserves_daily_minutes_and_irregular_steps(spec, times):
    assert scheduling._calendar_schedule(spec).times == times


def test_control_combines_real_calendar_entries_and_checks_extra_triggers(tmp_path):
    config = tmp_path / "site settings.toml"
    runner = FakeSystemd(config, calendar=("*-*-* 07:30:00", "*-*-* 19:45:00"))
    args = (TIMER, SERVICE, config)
    assert scheduling.systemd_timer_control_status(*args, run=runner)["calendar_words"] == (
        "Every day at 07:30 and 19:45"
    )

    runner.calendar = (TICK,)
    runner.argv.append("--if-due")
    assert scheduling.systemd_timer_control_status(*args, run=runner)["enabled"] is True
    runner.monotonic = ("{ OnBootUSec=5min ; next_elapse=0 }",)
    assert scheduling.systemd_timer_control_status(*args, run=runner)["enabled"] is False
    runner.monotonic = ()
    for field, invalid in (("OnClockChange", "yes"), ("OnTimezoneChange", "yes"), ("Unit", "other.service"),
                           ("Triggers", "other.service")):
        original = runner.fields[field]
        runner.fields[field] = invalid
        assert scheduling.systemd_timer_control_status(*args, run=runner)["enabled"] is False
        runner.fields[field] = original


@posix_only
def test_typed_execstart_round_trips_literal_special_paths(fake_switch, monkeypatch):
    root, config, runner = fake_switch
    renamed = config.config_path.with_name('site "settings" \\ ${literal} %.toml')
    config.config_path.rename(renamed)
    config = replace(config, config_path=renamed)
    original_dir = root / "opt/cvebeacon"
    original_dir.rename(original_dir.with_name("cve$beacon"))
    runner.path = runner.argv[0] = EXECUTABLE.replace("cvebeacon/current", "cve$beacon/current")
    runner.argv[2] = posix_path(renamed).replace("$", "$$")
    runner.argv.extend(("--yes",))
    monkeypatch.setenv("PATH", "/example/untrusted")
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/example/untrusted")
    # The fake's loaded override exposes the decoded config path as typed argv.
    original = runner.argv
    def run(args, **kwargs):
        if runner.loaded_dropins[1]:
            runner.argv = [*original[:2], posix_path(renamed), *original[3:]]
        return runner(args, **kwargs)
    _switch("enable", root, config, run)
    service = _dropins(root)[1].read_text(encoding="utf-8")
    assert (
        'ExecStart=:"/opt/cve$beacon/current/.venv/bin/cvebeacon" "--config" "'
        + posix_path(renamed.parent) + '/site \\"settings\\" \\\\ ${literal} %%.toml" "run" "--yes" "--if-due"\n'
    ) in service
    assert all(kwargs["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"} for _, kwargs in runner.calls)
    assert all(kwargs["cwd"] == "/" for _, kwargs in runner.calls)


@posix_only
@pytest.mark.parametrize("problem", ["path", "flags", "multiple", "environment", "newline", "untrusted"])
def test_root_enable_rejects_ambiguous_or_untrusted_command(fake_switch, problem):
    root, config, runner = fake_switch
    if problem == "path":
        runner.path = "/usr/bin/other"
    elif problem == "flags":
        runner.flags = ["privileged"]
    elif problem == "multiple":
        runner.commands = 2
    elif problem == "environment":
        runner.argv[2] = "/var/lib/${NAME}/config.toml"
    elif problem == "newline":
        runner.argv[2] = "/var/lib/config\n.toml"
    else:
        (root / "opt/cvebeacon/releases").chmod(0o775)
    with pytest.raises(SchedulingError, match="expected CVEBeacon run command"):
        _switch("enable", root, config, runner)
    assert not runner.actions
    assert not any(path.exists() for path in _dropins(root))


def _existing_dropins(root):
    files = _dropins(root)
    for path in files:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.write_text("[Unit]\n", encoding="utf-8", newline="\n")
        path.chmod(0o600)
    return files


@posix_only
@pytest.mark.parametrize("unsafe", ["symlink", "writable"])
def test_disable_checks_every_directory_before_unlinking(fake_switch, unsafe):
    root, config, runner = fake_switch
    timer, service = _existing_dropins(root)
    ancestor = root / "etc/systemd"
    if unsafe == "symlink":
        redirected = ancestor.with_name("redirected")
        ancestor.rename(redirected)
        ancestor.symlink_to(redirected, target_is_directory=True)
    else:
        ancestor.chmod(0o775)

    with pytest.raises(SchedulingError):
        _switch("disable", root, config, runner)
    assert timer.exists() and service.exists()
    assert not runner.actions


@posix_only
def test_matching_override_with_wrong_mode_is_replaced(fake_switch):
    root, config, runner = fake_switch
    _switch("enable", root, config, runner)
    timer = _dropins(root)[0]
    timer.chmod(0o644)

    assert _switch("enable", root, config, runner) == "dashboard schedule control enabled"
    assert timer.stat().st_mode & 0o777 == 0o600
    assert runner.loaded_dropins == (True, True)


@posix_only
def test_disable_rolls_back_a_second_file_failure(fake_switch, monkeypatch):
    root, config, runner = fake_switch
    files = _existing_dropins(root)
    runner.loaded_dropins = (True, True)
    original = os.unlink
    mutations = 0

    def unlink(name, *args, **kwargs):
        nonlocal mutations
        if Path(name).name == DROPIN:
            mutations += 1
            if mutations == 2:
                raise OSError("simulated unlink refusal")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)
    with pytest.raises(SchedulingError):
        _switch("disable", root, config, runner)
    assert [path.read_bytes() for path in files] == [b"[Unit]\n", b"[Unit]\n"]
    assert runner.loaded_dropins == (True, True)
    assert runner.fields["ActiveState"] == "active"


@posix_only
def test_enable_rolls_back_restart_failure_and_retry_restarts(fake_switch):
    root, config, runner = fake_switch
    runner.fail_action = "restart"
    with pytest.raises(SchedulingError, match="systemd timer action failed"):
        _switch("enable", root, config, runner)
    assert not any(path.exists() for path in _dropins(root))
    assert runner.loaded_dropins == (False, False)
    assert runner.fields["ActiveState"] == "active"

    assert _switch("enable", root, config, runner) == "dashboard schedule control enabled"
    assert runner.loaded_dropins == (True, True)
    assert runner.fields["ActiveState"] == "active"


@posix_only
@pytest.mark.parametrize("action", ("enable", "disable"))
def test_retry_recovers_after_reload_and_rollback_fail(fake_switch, action):
    root, config, runner = fake_switch
    if action == "disable":
        _existing_dropins(root)
        runner.loaded_dropins = (True, True)
    runner.fail_action = "daemon-reload"
    runner.fail_once = False
    with pytest.raises(SchedulingError, match="rollback is pending"):
        _switch(action, root, config, runner)
    timer = _dropins(root)[0]
    assert b"# CVEBEACON-SCHEDULE-RECOVERY-1 " in timer.read_bytes()
    systemd_files = {
        path.relative_to(root / "etc/systemd/system")
        for path in (root / "etc/systemd/system").rglob("*")
        if path.is_file()
    }
    assert systemd_files <= {
        Path(TIMER + ".d") / DROPIN,
        Path(SERVICE + ".d") / DROPIN,
    }

    runner.fail_action = None
    assert _switch(action, root, config, runner) == f"dashboard schedule control {action}d"
    assert runner.loaded_dropins == ((True, True) if action == "enable" else (False, False))
    if action == "enable":
        assert b"# CVEBEACON-SCHEDULE-RECOVERY-1 " not in timer.read_bytes()
        assert _dropins(root)[1].exists()
    else:
        assert not timer.exists()
        assert not _dropins(root)[1].exists()
    final_files = {
        path.relative_to(root / "etc/systemd/system")
        for path in (root / "etc/systemd/system").rglob("*")
        if path.is_file()
    }
    expected_files = (
        {Path(TIMER + ".d") / DROPIN, Path(SERVICE + ".d") / DROPIN}
        if action == "enable" else set()
    )
    assert final_files == expected_files
    assert runner.fields["ActiveState"] == "active"


@posix_only
def test_updater_exclusion_locks_existing_inode_without_writing(tmp_path):
    import fcntl

    lock_path = tmp_path / "update.lock"
    lock_path.write_bytes(b"existing updater metadata\n")
    lock_path.chmod(0o600)
    original_stat = lock_path.stat()
    original_bytes = lock_path.read_bytes()

    with scheduling.ExitStack() as stack:
        scheduling._open_existing_update_lock(
            stack, lock_path, expected_owner=os.geteuid()
        )
        locked_stat = lock_path.stat()
        assert (locked_stat.st_dev, locked_stat.st_ino) == (
            original_stat.st_dev,
            original_stat.st_ino,
        )
        assert lock_path.read_bytes() == original_bytes
        contender = os.open(lock_path, os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)

    assert lock_path.read_bytes() == original_bytes
    final_stat = lock_path.stat()
    assert (final_stat.st_dev, final_stat.st_ino) == (
        original_stat.st_dev,
        original_stat.st_ino,
    )


@posix_only
def test_updater_exclusion_fails_closed_when_lock_is_missing(tmp_path):
    with scheduling.ExitStack() as stack:
        with pytest.raises(SchedulingError, match="updater lock file is missing"):
            scheduling._open_existing_update_lock(
                stack, tmp_path / "missing-update.lock", expected_owner=os.geteuid()
            )


@posix_only
def test_updater_exclusion_fails_closed_for_a_linked_lock(tmp_path):
    target = tmp_path / "target.lock"
    target.write_bytes(b"unchanged\n")
    lock_path = tmp_path / "update.lock"
    lock_path.symlink_to(target)

    with scheduling.ExitStack() as stack:
        with pytest.raises(SchedulingError, match="updater lock file cannot be verified"):
            scheduling._open_existing_update_lock(
                stack, lock_path, expected_owner=os.geteuid()
            )


@posix_only
def test_enable_refuses_runtime_database_outside_approved_data(fake_switch):
    root, config, runner = fake_switch
    text = config.config_path.read_text(encoding="utf-8").replace('"state.db"', '"../state.db"')
    config.config_path.write_text(text, encoding="utf-8", newline="\n")
    with pytest.raises(SchedulingError, match="administrator-approved data directory"):
        _switch("enable", root, config, runner)
    assert not (config.database_path.parent.parent / "schedule.json").exists()
    assert not any(path.exists() for path in _dropins(root))


@posix_only
def test_enable_takes_the_recognized_update_policy_as_data_authority(fake_switch, monkeypatch):
    import pwd

    from cvebeacon.updater import Policy

    root, config, runner = fake_switch
    allowed = config.database_path.parent
    account = pwd.getpwuid(os.geteuid())
    monkeypatch.setattr(Policy, "read", lambda path: Policy(root, config.config_path, allowed, account.pw_name))
    policy_path = root / "etc/cvebeacon/update.toml"
    data, identity = scheduling._timer_data_authority(runner, policy_path, True, None, config.config_path)
    assert data == allowed
    assert identity.pw_uid == account.pw_uid
    with pytest.raises(SchedulingError, match="must match"):
        scheduling._timer_data_authority(runner, policy_path, True, allowed.parent, config.config_path)


def test_run_if_due_logs_corrupt_data_and_does_not_monitor(tmp_path, monkeypatch, caplog):
    config = write_config(tmp_path, inventory=False)
    path = config.database_path.parent / "schedule.json"
    path.write_bytes(b'{"version":' + b"1" * 5000 + b"}")
    path.chmod(0o600)
    monkeypatch.setattr(cli, "_run_all", lambda *args, **kwargs: pytest.fail("corrupt schedule admitted a run"))

    assert cli.main(["--config", str(config.config_path), "run", "--if-due"]) == 2
    assert "scheduled run skipped: schedule data file is invalid" in caplog.text


def test_loaded_systemd_path_comparison_uses_posix_on_every_host():
    config = PureWindowsPath("C:/var/lib/cvebeacon/site settings.toml")
    argv = [EXECUTABLE, "--config", "/var/lib/cvebeacon/site settings.toml", "run", "--if-due"]
    assert scheduling._timer_run_command((argv, False), config) == argv


@posix_only
def test_timer_read_and_dashboard_write_hold_the_same_directory_lock(tmp_path, monkeypatch):
    current = datetime(2026, 11, 26, 7, tzinfo=timezone.utc)
    scheduling.save_timer_schedule(tmp_path, scheduling.build_timer_schedule(2))
    timer_read = Event()
    finish_tick = Event()
    write_requested = Event()
    original_read = scheduling._read_timer_schedule

    def pause_first_read(directory):
        value = original_read(directory)
        if not timer_read.is_set():
            timer_read.set()
            assert finish_tick.wait(5)
        return value

    def change_cadence():
        write_requested.set()
        scheduling.change_timer_schedule(tmp_path, scheduling.build_timer_schedule(5))

    monkeypatch.setattr(scheduling, "_read_timer_schedule", pause_first_read)
    with ThreadPoolExecutor(max_workers=2) as executor:
        tick = executor.submit(scheduling.should_run_scheduled, tmp_path, current)
        try:
            assert timer_read.wait(5)
            edit = executor.submit(change_cadence)
            assert write_requested.wait(5)
            assert not edit.done()
        finally:
            finish_tick.set()
        assert tick.result(timeout=5)
        edit.result(timeout=5)

    saved = scheduling.load_timer_schedule(tmp_path)
    assert saved.every_hours == 5
    assert saved.last_start == current
