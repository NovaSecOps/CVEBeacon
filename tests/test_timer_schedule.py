"""Dashboard-controlled systemd timer scheduling."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import shlex
from zoneinfo import ZoneInfo

import pytest

from cvebeacon import cli, scheduling
from cvebeacon.errors import SchedulingError
from watch_support import write_config


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
    now = datetime(2026, 11, 26, 21, 30, tzinfo=ZoneInfo("Europe/Lisbon"))
    schedule = scheduling.build_timer_schedule(
        times="07:00,12:00,19:00",
        last_start=datetime(2026, 11, 25, 20, tzinfo=ZoneInfo("Europe/Lisbon")),
    )

    assert scheduling.schedule_due(schedule, now)
    assert scheduling.should_run_scheduled(tmp_path, now=now)
    assert not scheduling.should_run_scheduled(
        tmp_path, now=now + timedelta(minutes=15)
    )


def test_first_run_without_history_uses_interval_and_fixed_time_rules(tmp_path):
    morning = datetime(2026, 11, 26, 6, 45, tzinfo=ZoneInfo("Europe/Lisbon"))
    evening = datetime(2026, 11, 26, 7, 1, tzinfo=ZoneInfo("Europe/Lisbon"))

    assert scheduling.schedule_due(
        scheduling.build_timer_schedule(every_hours=4), morning
    )
    fixed = scheduling.build_timer_schedule(times="07:00,19:00")
    assert not scheduling.schedule_due(fixed, morning)
    assert scheduling.schedule_due(fixed, evening)


def test_fallback_schedule_file_defaults_to_shipped_times_and_never_runs_each_tick(
    tmp_path,
):
    before = datetime(2026, 11, 26, 6, 45, tzinfo=ZoneInfo("Europe/Lisbon"))
    due = datetime(2026, 11, 26, 7, 1, tzinfo=ZoneInfo("Europe/Lisbon"))

    assert scheduling.load_timer_schedule(tmp_path).times == ("07:00", "19:00")
    assert not scheduling.should_run_scheduled(tmp_path, now=before)
    assert scheduling.should_run_scheduled(tmp_path, now=due)
    assert not scheduling.should_run_scheduled(
        tmp_path, now=due + timedelta(minutes=15)
    )


def test_fixed_time_does_not_run_twice_when_clock_repeats_an_hour(tmp_path):
    zone = ZoneInfo("Europe/Lisbon")
    first_0135 = datetime(2026, 10, 25, 1, 35, tzinfo=zone, fold=0)
    repeated_0145 = datetime(2026, 10, 25, 1, 45, tzinfo=zone, fold=1)
    schedule = scheduling.build_timer_schedule(times="01:30")
    scheduling.save_timer_schedule(tmp_path, schedule)

    assert scheduling.should_run_scheduled(tmp_path, now=first_0135)
    assert not scheduling.should_run_scheduled(tmp_path, now=repeated_0145)


def _exec_start(executable, config_path, *tail):
    argv = [str(executable), "--config", str(config_path), *tail]
    return (
        "ExecStart={ path=" + str(executable) + " ; argv[]="
        + shlex.join(argv)
        + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
        "pid=0 ; code=exited ; status=0/0 }\n"
    )


class FakeSystemctl:
    def __init__(self, config_path, *, calendar="*-*-* 07,19:00:00", tail=("run",)):
        self.config_path = Path(config_path)
        self.executable = Path("/opt/cvebeacon/current/.venv/bin/cvebeacon")
        self.calendar = calendar
        self.tail = tuple(tail)
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        if args[:2] == ["systemctl", "show"]:
            requested = args[2].partition("=")[2].split(",")
            props = {
                "OnCalendar": self.calendar,
                "Persistent": "yes",
                "ExecStart": _exec_start(
                    self.executable, self.config_path, *self.tail
                ).split("=", 1)[1].rstrip("\n"),
            }
            return _Result(
                stdout="".join(f"{name}={props[name]}\n" for name in requested)
            )
        return _Result()


class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_timer_control_enable_preserves_command_and_writes_private_dropins(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_path = data_dir / "cvebeacon.toml"
    config_path.write_text("", encoding="utf-8", newline="\n")
    systemctl = FakeSystemctl(config_path)
    root = tmp_path / "root"
    root.mkdir()

    result = scheduling.timer_control(
        "enable", data_directory=data_dir, config_path=config_path,
        run=systemctl, root_directory=root, geteuid=lambda: 0,
    )

    timer = root / "etc/systemd/system/cvebeacon.timer.d/dashboard-schedule.conf"
    service = root / "etc/systemd/system/cvebeacon.service.d/dashboard-schedule.conf"
    assert result == "dashboard schedule control enabled"
    assert timer.read_text(encoding="utf-8") == (
        "[Timer]\nOnCalendar=\nOnCalendar=*:0/15\nPersistent=true\n"
    )
    service_text = service.read_text(encoding="utf-8")
    assert "ExecStart=\n" in service_text
    assert '"/opt/cvebeacon/current/.venv/bin/cvebeacon"' in service_text
    assert f'"{config_path}"' in service_text
    assert '"run" "--if-due"' in service_text
    assert timer.stat().st_mode & 0o777 == 0o600
    assert service.stat().st_mode & 0o777 == 0o600
    assert scheduling.load_timer_schedule(data_dir).times == ("07:00", "19:00")
    assert [call[0][1:] for call in systemctl.calls[-2:]] == [
        ["daemon-reload"], ["restart", "cvebeacon.timer"],
    ]


def test_timer_control_parses_initial_interval_and_is_idempotent(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_path = data_dir / "cvebeacon.toml"
    config_path.write_text("", encoding="utf-8", newline="\n")
    systemctl = FakeSystemctl(config_path, calendar="*-*-* 00/6:00:00")
    root = tmp_path / "root"
    root.mkdir()

    scheduling.timer_control(
        "enable", data_directory=data_dir, config_path=config_path,
        run=systemctl, root_directory=root, geteuid=lambda: 0,
    )
    saved = scheduling.load_timer_schedule(data_dir)
    assert saved.every_hours == 6
    assert saved.times == ()

    timer = root / "etc/systemd/system/cvebeacon.timer.d/dashboard-schedule.conf"
    timer_before = timer.read_bytes()
    systemctl.calendar = "*:0/15"
    systemctl.tail = ("run", "--if-due")
    result = scheduling.timer_control(
        "enable", data_directory=data_dir, config_path=config_path,
        run=systemctl, root_directory=root, geteuid=lambda: 0,
    )

    assert result == "dashboard schedule control is already enabled"
    assert timer.read_bytes() == timer_before
    assert [call[0][1:] for call in systemctl.calls[-2:]] == [
        ["show", "--property=OnCalendar,Persistent", "--", "cvebeacon.timer"],
        ["show", "--property=ExecStart", "--", "cvebeacon.service"],
    ]


def test_timer_control_uses_default_for_a_custom_calendar(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_path = data_dir / "cvebeacon.toml"
    systemctl = FakeSystemctl(config_path, calendar="Mon *-*-* 07:00:00")
    root = tmp_path / "root"
    root.mkdir()

    scheduling.timer_control(
        "enable", data_directory=data_dir, config_path=config_path,
        run=systemctl, root_directory=root, geteuid=lambda: 0,
    )

    saved = scheduling.load_timer_schedule(data_dir)
    assert saved.times == ("07:00", "19:00")
    assert (data_dir / "schedule.json").stat().st_mode & 0o777 == 0o600


def test_timer_control_refuses_unexpected_execstart_without_writing(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_path = data_dir / "cvebeacon.toml"
    systemctl = FakeSystemctl(config_path, tail=("watch", "run"))
    root = tmp_path / "root"
    root.mkdir()

    with pytest.raises(SchedulingError, match="expected CVEBeacon run command"):
        scheduling.timer_control(
            "enable", data_directory=data_dir, config_path=config_path,
            run=systemctl, root_directory=root, geteuid=lambda: 0,
        )

    assert not (root / "etc/systemd/system/cvebeacon.timer.d").exists()
    assert not (root / "etc/systemd/system/cvebeacon.service.d").exists()


def test_timer_control_disable_removes_only_its_dropins(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_path = data_dir / "cvebeacon.toml"
    root = tmp_path / "root"
    timer_dir = root / "etc/systemd/system/cvebeacon.timer.d"
    service_dir = root / "etc/systemd/system/cvebeacon.service.d"
    timer_dir.mkdir(parents=True)
    service_dir.mkdir(parents=True)
    for directory in (timer_dir, service_dir):
        (directory / "dashboard-schedule.conf").write_text("managed\n", encoding="utf-8")
        (directory / "local.conf").write_text("keep\n", encoding="utf-8")
    systemctl = FakeSystemctl(config_path, calendar="*:0/15", tail=("run", "--if-due"))

    result = scheduling.timer_control(
        "disable", data_directory=data_dir, config_path=config_path,
        run=systemctl, root_directory=root, geteuid=lambda: 0,
    )

    assert result == "dashboard schedule control disabled"
    assert not (timer_dir / "dashboard-schedule.conf").exists()
    assert not (service_dir / "dashboard-schedule.conf").exists()
    assert (timer_dir / "local.conf").read_text(encoding="utf-8") == "keep\n"
    assert (service_dir / "local.conf").read_text(encoding="utf-8") == "keep\n"
    assert [call[0][1:] for call in systemctl.calls[-2:]] == [
        ["daemon-reload"], ["restart", "cvebeacon.timer"],
    ]
    call_count = len(systemctl.calls)
    assert scheduling.timer_control(
        "disable", data_directory=data_dir, config_path=config_path,
        run=systemctl, root_directory=root, geteuid=lambda: 0,
    ) == "dashboard schedule control drop-ins are already absent"
    assert len(systemctl.calls) == call_count


def test_timer_control_requires_root_for_every_action(tmp_path):
    for action in ("enable", "disable", "status"):
        with pytest.raises(SchedulingError, match="must run as root"):
            scheduling.timer_control(
                action, data_directory=tmp_path, config_path=tmp_path / "cvebeacon.toml",
                run=lambda *args, **kwargs: _Result(), root_directory=tmp_path,
                geteuid=lambda: 1000,
            )


def test_dashboard_detects_control_from_loaded_systemd_properties(tmp_path):
    config_path = tmp_path / "cvebeacon.toml"
    baseline = FakeSystemctl(config_path)
    disabled = scheduling.systemd_timer_control_status(
        "cvebeacon.timer", "cvebeacon.service", config_path, run=baseline,
    )
    assert disabled["enabled"] is False
    assert disabled["calendar_words"] == "Every day at 07:00 and 19:00"
    assert "schedule timer-control enable" in disabled["enable_command"]

    active = FakeSystemctl(
        config_path, calendar="*:0/15", tail=("run", "--if-due")
    )
    enabled = scheduling.systemd_timer_control_status(
        "cvebeacon.timer", "cvebeacon.service", config_path, run=active,
    )
    assert enabled["enabled"] is True
    assert enabled["timer_tick"] == "Every 15 minutes"

    unexpected = FakeSystemctl(config_path, tail=("watch", "run"))
    refused = scheduling.systemd_timer_control_status(
        "cvebeacon.timer", "cvebeacon.service", config_path, run=unexpected,
    )
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
    future = datetime.now(timezone.utc) + timedelta(days=1)
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

