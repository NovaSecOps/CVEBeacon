from __future__ import annotations

import os
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
    _without_managed_block,
    default_command,
    describe,
    install,
    make_plan,
    parse_times,
    remove,
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


def test_cron_both_runs_one_ordered_command(tmp_path):
    plan = linux_plan(tmp_path, times="07:00", command="both")
    lines = _cron_lines(plan)
    assert len(lines) == 1
    assert lines[0].startswith("0 7 * * * ")
    assert lines[0].endswith(" run")


def test_interval_both_uses_one_cron_line(tmp_path):
    plan = make_plan(
        tmp_path / "config.toml",
        every_hours=4,
        command="both",
        system="linux",
        executable="/opt/cvebeacon",
        allow_incompatible=True,
    )
    lines = _cron_lines(plan)
    assert len(lines) == 1
    assert lines[0].startswith("0 */4 * * * ")
    assert lines[0].endswith(" run")


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
    value = writes[0].decode("utf-8")
    assert value.startswith("15 2 * * * backup\n")
    assert value.count(CRON_BEGIN) == 1
    assert value.count(CRON_END) == 1
    assert "0 7,19 * * * " in value
    assert value.count(" run") == 1
    assert " scan" not in value
    assert " watch run" not in value


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


def test_describe_shows_times_and_one_command(tmp_path):
    plan = linux_plan(tmp_path, command="both")
    text = describe(plan)
    assert "Schedule: daily at 07:00, 19:00" in text
    assert "Commands:" in text
    assert text.count("--config") == 1
    assert text.rstrip().endswith(" run")


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


def test_windows_fixed_times_generate_one_task_with_one_action(tmp_path, monkeypatch):
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
        assert root.find(f".//{NS}Repetition") is None
        actions = root.findall(f".//{NS}Exec")
        assert len(actions) == 1
        arguments = actions[0].findtext(f"{NS}Arguments") or ""
        assert arguments.endswith(" run")
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


def test_windows_interval_both_uses_plain_schtasks(tmp_path, monkeypatch):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    plan = make_plan(
        tmp_path / "config.toml",
        4,
        command="both",
        executable=tmp_path / "cvebeacon.exe",
    )
    calls = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(args, **kwargs):
        calls.append(args)
        return Result()

    install(plan, run=fake_run)
    assert len(calls) == 1
    args = calls[0]
    assert "/XML" not in args
    assert args[5:9] == ["/SC", "HOURLY", "/MO", "4"]
    assert args[-1].endswith(" run")
    assert args[-1].count("--config") == 1


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
    assert len(installed[0].commands) == 1
    assert installed[0].command[-1] == "run"


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


@pytest.mark.parametrize(
    "scan_code,watch_code,expected",
    [(0, 0, 0), (4, 0, 4), (0, 3, 3), (2, 0, 2), (3, 2, 2), (3, 4, 3)],
)
def test_cli_run_combines_exit_codes(
    tmp_path, monkeypatch, scan_code, watch_code, expected
):
    config = write_schedule_config(tmp_path, inventory=True, watch=True)
    calls = []
    monkeypatch.setattr(
        cli, "_run_scan", lambda config: calls.append("scan") or scan_code
    )
    monkeypatch.setattr(
        cli,
        "_run_watch",
        lambda args, config: calls.append("watch") or watch_code,
    )
    assert cli.main(["--config", str(config), "run"]) == expected
    assert calls == ["scan", "watch"]


def test_cli_run_skips_unconfigured_parts(tmp_path, monkeypatch):
    config = write_schedule_config(tmp_path, watch=True)
    calls = []
    monkeypatch.setattr(
        cli, "_run_scan", lambda config: calls.append("scan") or 0
    )
    monkeypatch.setattr(
        cli, "_run_watch", lambda args, config: calls.append("watch") or 0
    )
    assert cli.main(["--config", str(config), "run"]) == 0
    assert calls == ["watch"]


def test_windows_fixed_time_status_shows_the_times(tmp_path):
    plan = make_plan(
        tmp_path / "config.toml",
        times="07:00,19:00",
        command="both",
        system="windows",
        executable=tmp_path / "cvebeacon.exe",
        allow_incompatible=True,
    )
    text = _describe_windows_xml(_windows_xml(plan).decode("utf-16"))
    assert "Schedule: daily at 07:00, 19:00" in text
    assert text.count("--config") == 1


def test_cron_status_lists_each_command_once(tmp_path, monkeypatch):
    scan = "/opt/cvebeacon --config /srv/cvebeacon.toml scan"
    watch = "/opt/cvebeacon --config /srv/cvebeacon.toml watch run"
    block = (
        f"{CRON_BEGIN}\n"
        f"0 7,19 * * * {scan}\n"
        f"0 7,19 * * * {watch}\n"
        f"30 7 * * * {scan}\n"
        f"30 7 * * * {watch}\n"
        f"{CRON_END}"
    )

    def fake_run(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=block + "\n", stderr="")

    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    text = status(run=fake_run)
    commands = [line.strip() for line in text.splitlines() if line.startswith("  /opt")]
    assert commands == [scan, watch]


def test_module_mode_keeps_the_virtualenv_interpreter(tmp_path, monkeypatch):
    real = tmp_path / "python-real"
    real.write_text("", encoding="utf-8")
    venv_python = tmp_path / "venv-python"
    venv_python.symlink_to(real)
    monkeypatch.setattr("cvebeacon.scheduling.sys.executable", str(venv_python))
    monkeypatch.setattr("cvebeacon.scheduling.sys.argv", ["/tmp/pytest"])
    plan = make_plan(
        tmp_path / "config.toml",
        times="07:00",
        system="linux",
        allow_incompatible=True,
    )
    assert plan.module_mode is True
    assert plan.executable == venv_python


def test_without_managed_block_preserves_unrelated_bytes():
    text = "0 5 * * * /bin/foo   \n15 2 * * * backup\r\nMAILTO=\"x\"\r\n"
    assert _without_managed_block(text) == text
    assert _without_managed_block("0 5 * * * /bin/foo   ") == "0 5 * * * /bin/foo   "
    mixed = f"0 5 * * * /bin/foo   \n{CRON_BEGIN}\n0 7 * * * scan\n{CRON_END}\n15 2 * * * backup\r"
    assert _without_managed_block(mixed) == "0 5 * * * /bin/foo   \n15 2 * * * backup\r"


def test_install_keeps_an_entry_without_a_final_newline(tmp_path):
    writes = []

    class Result:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    def fake_run(args, **kwargs):
        if args == ["crontab", "-l"]:
            return Result(stdout="15 2 * * * backup   ")
        writes.append(kwargs["input"])
        return Result()

    install(linux_plan(tmp_path), run=fake_run)
    assert writes[0].decode("utf-8").startswith("15 2 * * * backup   \n" + CRON_BEGIN)


@pytest.mark.skipif(os.name != "posix", reason="POSIX cron")
def test_real_crontab_round_trip_preserves_bytes(tmp_path, monkeypatch):
    store = tmp_path / "crontab"
    original = b"MAILTO=me  \r\n0 1 * * * a\rb  \n# caf\xe9  \r\nlast"
    store.write_bytes(original)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    script = binaries / "crontab"
    script.write_text(
        "#!/bin/sh\n"
        f"store={shlex.quote(str(store))}\n"
        'if [ "$1" = "-l" ]; then\n'
        '  if [ -f "$store" ]; then\n'
        '    cat "$store"\n'
        "  else\n"
        '    echo "no crontab for test" >&2\n'
        "    exit 1\n"
        "  fi\n"
        'elif [ "$1" = "-" ]; then\n'
        '  cat > "$store"\n'
        "else\n"
        "  exit 2\n"
        "fi\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    monkeypatch.setenv(
        "PATH", f"{binaries}{os.pathsep}{os.environ.get('PATH', '')}"
    )
    plan = linux_plan(tmp_path)
    install(plan)
    installed = store.read_bytes()
    assert CRON_BEGIN.encode() in installed
    assert b"0 1 * * * a\rb  " in installed
    assert b"# caf\xe9  \r\n" in installed
    assert remove(system="linux") is True
    assert store.read_bytes() == original
