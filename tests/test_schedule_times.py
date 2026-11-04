from __future__ import annotations

import shlex
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from cvebeacon import cli
from cvebeacon.errors import SchedulingError
from cvebeacon.scheduling import (
    CRON_BEGIN,
    CRON_END,
    WINDOWS_TASK,
    _cron_lines,
    _describe_windows_xml,
    _windows_xml,
    default_command,
    describe,
    install,
    make_plan,
    parse_times,
    status,
)

NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def linux_plan(tmp_path, **kwargs):
    return make_plan(
        tmp_path / "config.toml",
        times=kwargs.pop("times", "07:00,19:00"),
        system="linux",
        executable="/opt/cvebeacon",
        allow_incompatible=True,
        **kwargs,
    )


def test_cron_groups_times_by_minute(tmp_path):
    plan = linux_plan(tmp_path, times="19:00,07:00,07:30")
    lines = _cron_lines(plan)
    prefix = shlex.join(["/opt/cvebeacon", "--config", str(plan.config_path), "scan"])
    assert lines == [f"0 7,19 * * * {prefix}", f"30 7 * * * {prefix}"]


def test_cron_both_runs_scan_then_watch_in_one_block(tmp_path):
    plan = linux_plan(tmp_path, times="07:00", command="both")
    lines = _cron_lines(plan)
    assert len(lines) == 2
    assert lines[0].endswith(" scan")
    assert lines[1].endswith(" watch run")
    assert lines[0].startswith("0 7 * * * ")


def test_interval_both_uses_two_cron_lines(tmp_path):
    plan = make_plan(
        tmp_path / "config.toml",
        every_hours=4,
        command="both",
        system="linux",
        executable="/opt/cvebeacon",
        allow_incompatible=True,
    )
    lines = _cron_lines(plan)
    assert len(lines) == 2
    assert all(line.startswith("0 */4 * * * ") for line in lines)
    assert lines[0].endswith(" scan")
    assert lines[1].endswith(" watch run")


def test_linux_install_keeps_unrelated_entries_and_one_owned_block(tmp_path):
    writes = []

    class Result:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    def fake_run(args, **kwargs):
        if args == ["crontab", "-l"]:
            return Result(stdout="15 2 * * * backup\n")
        writes.append(kwargs["input"])
        return Result()

    plan = linux_plan(tmp_path, command="both")
    install(plan, run=fake_run)
    value = writes[0]
    assert value.startswith("15 2 * * * backup\n")
    assert value.count(CRON_BEGIN) == 1
    assert value.count(CRON_END) == 1
    assert "0 7,19 * * * " in value
    assert value.count(" watch run") == 1
    assert value.count(" scan") == 1


def test_cron_read_failure_never_writes_with_times(tmp_path):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=1, stdout="", stderr="permission denied")

    with pytest.raises(SchedulingError):
        install(linux_plan(tmp_path), run=fake_run)
    assert calls == [["crontab", "-l"]]


def test_times_and_interval_are_mutually_exclusive(tmp_path):
    with pytest.raises(SchedulingError, match="mutually exclusive"):
        make_plan(
            tmp_path / "config.toml",
            4,
            times="07:00",
            system="linux",
            executable="/opt/cvebeacon",
            allow_incompatible=True,
        )


@pytest.mark.parametrize(
    "value",
    ["24:00", "7:5", "07:60", "07:00,07:00", "not-a-time"],
)
def test_invalid_times_are_rejected(tmp_path, value):
    with pytest.raises(SchedulingError):
        parse_times(value)


def test_more_than_twelve_times_are_rejected():
    values = ",".join(f"{hour:02d}:00" for hour in range(13))
    with pytest.raises(SchedulingError, match="at most 12"):
        parse_times(values)


def test_times_accepts_twelve_distinct_values():
    values = tuple(f"{hour:02d}:00" for hour in range(12))
    assert parse_times(values) == values


def test_percent_and_newline_are_rejected_in_times_mode(tmp_path):
    with pytest.raises(SchedulingError, match="percent"):
        make_plan(
            tmp_path / "config%name.toml",
            times="07:00",
            system="linux",
            executable="/opt/cvebeacon",
            allow_incompatible=True,
        )
    with pytest.raises(SchedulingError, match="line breaks"):
        make_plan(
            tmp_path / ("config\nname.toml"),
            times="07:00",
            system="linux",
            executable="/opt/cvebeacon",
            allow_incompatible=True,
        )


@pytest.mark.parametrize(
    "inventory,watch,expected",
    [
        (True, False, "scan"),
        (False, True, "watch"),
        (True, True, "both"),
    ],
)
def test_default_command_follows_config_shape(inventory, watch, expected):
    assert default_command(inventory=inventory, watch=watch) == expected


def test_describe_shows_times_and_commands(tmp_path):
    plan = linux_plan(tmp_path, command="both")
    text = describe(plan)
    assert "Schedule: daily at 07:00, 19:00" in text
    assert "Commands:" in text
    assert text.count("--config") == 2
    assert " scan" in text and " watch run" in text


def test_status_shows_times_and_commands(tmp_path, monkeypatch):
    block = (
        f"{CRON_BEGIN}\n"
        "0 7,19 * * * /opt/cvebeacon --config /srv/cvebeacon.toml scan\n"
        f"{CRON_END}"
    )

    def fake_run(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=block + "\n", stderr="")

    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    text = status(run=fake_run)
    assert "daily at 07:00, 19:00" in text
    assert "Commands:" in text
    assert "/opt/cvebeacon --config /srv/cvebeacon.toml scan" in text


def test_windows_fixed_times_generate_one_task_with_two_actions(tmp_path, monkeypatch):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    executable = tmp_path / "cvebeacon.exe"
    plan = make_plan(
        tmp_path / "config.toml",
        times="07:00,19:00",
        command="both",
        executable=executable,
    )
    calls = []
    xml_path = None

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(args, **kwargs):
        nonlocal xml_path
        calls.append(args)
        assert args[:3] == ["schtasks", "/Create", "/XML"]
        assert args[4:6] == ["/TN", WINDOWS_TASK]
        assert args[6] == "/F"
        xml_path = args[3]
        root = ET.parse(xml_path).getroot()
        triggers = root.findall(f".//{NS}CalendarTrigger")
        assert len(triggers) == 2
        boundaries = {item.findtext(f"{NS}StartBoundary")[11:16] for item in triggers}
        assert boundaries == {"07:00", "19:00"}
        actions = root.findall(f".//{NS}Exec")
        assert len(actions) == 2
        arguments = [item.findtext(f"{NS}Arguments") or "" for item in actions]
        assert arguments[0].endswith(" scan")
        assert arguments[1].endswith(" watch run")
        principal = root.find(f".//{NS}Principal")
        assert principal.findtext(f"{NS}LogonType") == "InteractiveToken"
        assert principal.findtext(f"{NS}RunLevel") == "LeastPrivilege"
        with open(xml_path, "rb") as handle:
            assert handle.read(2) in {b"\xff\xfe", b"\xfe\xff"}
        return Result()

    install(plan, run=fake_run)
    assert calls
    assert xml_path is not None
    assert not Path(xml_path).exists()


def test_windows_interval_both_uses_xml_with_two_actions(tmp_path, monkeypatch):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    plan = make_plan(
        tmp_path / "config.toml",
        4,
        command="both",
        executable=tmp_path / "cvebeacon.exe",
    )
    xml = _windows_xml(plan)
    root = ET.fromstring(xml.decode("utf-16"))
    assert len(root.findall(f".//{NS}TimeTrigger")) == 1
    repetition = root.find(f".//{NS}Repetition")
    assert repetition.findtext(f"{NS}Interval") == "PT4H"
    assert len(root.findall(f".//{NS}Exec")) == 2


def write_schedule_config(tmp_path, *, inventory: bool = False, watch: bool = False):
    blocks = []
    if inventory:
        blocks.append('[inventory]\npath = "inventory.csv"\n')
    if watch:
        blocks.append(
            """
[watch]
enabled = true
database = "watch.db"
sources = ["nvd"]

[[watch.rules]]
name = "critical"
condition = { cvss_min = 9.0 }
channels = ["alerts"]

[watch.channels.alerts]
type = "webhook"
enabled = false
url = "https://example.invalid/hook"
"""
        )
    path = tmp_path / "config.toml"
    path.write_text("\n".join(blocks), encoding="utf-8")
    return path


def test_cli_schedule_times_uses_the_config_default_command(tmp_path, monkeypatch, capsys):
    config = write_schedule_config(tmp_path, watch=True)
    installed = []
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    monkeypatch.setattr(cli, "install", lambda plan: installed.append(plan))
    assert (
        cli.main(
            [
                "--config",
                str(config),
                "schedule",
                "install",
                "--times",
                "07:00,19:00",
                "--yes",
            ]
        )
        == 0
    )
    assert installed[0].schedule_command == "watch"
    assert installed[0].times == ("07:00", "19:00")
    assert "Schedule: daily at 07:00, 19:00" in capsys.readouterr().out


def test_cli_schedule_both_config_defaults_to_both(tmp_path, monkeypatch):
    config = write_schedule_config(tmp_path, inventory=True, watch=True)
    installed = []
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    monkeypatch.setattr(cli, "install", lambda plan: installed.append(plan))
    assert (
        cli.main(
            [
                "--config",
                str(config),
                "schedule",
                "install",
                "--times",
                "07:00",
                "--yes",
            ]
        )
        == 0
    )
    assert installed[0].schedule_command == "both"
    assert len(installed[0].commands) == 2


def test_cli_schedule_rejects_times_with_interval(tmp_path, capsys):
    config = write_schedule_config(tmp_path, inventory=True)
    assert (
        cli.main(
            [
                "--config",
                str(config),
                "schedule",
                "install",
                "--every",
                "4",
                "--times",
                "07:00",
                "--yes",
            ]
        )
        == 2
    )
    assert "mutually exclusive" in capsys.readouterr().err


def test_cli_schedule_rejects_watch_without_watch_mode(tmp_path, capsys):
    config = write_schedule_config(tmp_path, inventory=True)
    assert (
        cli.main(
            [
                "--config",
                str(config),
                "schedule",
                "install",
                "--times",
                "07:00",
                "--command",
                "watch",
                "--yes",
            ]
        )
        == 2
    )
    assert "watch mode is disabled" in capsys.readouterr().err


def test_windows_interval_status_shows_the_repetition(tmp_path):
    plan = make_plan(
        tmp_path / "config.toml",
        4,
        command="both",
        system="windows",
        executable=tmp_path / "cvebeacon.exe",
        allow_incompatible=True,
    )
    text = _describe_windows_xml(_windows_xml(plan).decode("utf-16"))
    assert "Interval: every 4 hours" in text
    assert text.count("--config") == 2
