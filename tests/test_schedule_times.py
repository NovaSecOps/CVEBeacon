from __future__ import annotations

import os
import shlex
import subprocess
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
    _current_windows_account,
    _describe_windows_xml,
    _windows_access_denied,
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
    prefix = shlex.join([str(plan.executable), "--config", str(plan.config_path), "scan"])
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
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert args[:3] == ["schtasks", "/Create", "/XML"]
        assert args[4:6] == ["/TN", WINDOWS_TASK]
        assert args[6] == "/F"
        assert "/HRESULT" in args
        assert "/RU" not in args and "/NP" not in args
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
        assert principal.findtext(f"{NS}UserId") is None
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
    assert args[-1] == "/HRESULT"
    command_line = args[args.index("/TR") + 1]
    assert command_line.endswith(" run")
    assert command_line.count("--config") == 1


def windows_plan(tmp_path, **kwargs):
    from cvebeacon import scheduling

    original = scheduling._current_windows_account
    scheduling._current_windows_account = lambda: (r"CORP\svc-cvebeacon", "")
    try:
        return make_plan(
            tmp_path / "config.toml",
            times=kwargs.pop("times", "07:00,19:00"),
            system="windows",
            executable=tmp_path / "cvebeacon.exe",
            allow_incompatible=True,
            **kwargs,
        )
    finally:
        scheduling._current_windows_account = original


def windows_root(plan):
    text = _windows_xml(plan).decode("utf-16")
    return ET.fromstring(text.split("?>", 1)[1].lstrip())


def test_windows_logged_out_task_uses_s4u_with_the_current_account(tmp_path):
    plan = windows_plan(tmp_path, run_logged_out=True)
    principal = windows_root(plan).find(f".//{NS}Principal")
    assert principal.findtext(f"{NS}UserId") == r"CORP\svc-cvebeacon"
    assert principal.findtext(f"{NS}LogonType") == "S4U"
    assert principal.findtext(f"{NS}RunLevel") == "LeastPrivilege"
    assert "Runs as: CORP\\svc-cvebeacon (S4U, while logged off)" in describe(plan)


def test_windows_account_prefers_the_native_extended_name():
    account, note = _current_windows_account(
        resolve_extended=lambda: r"CORP\svc-cvebeacon",
        resolve_user=lambda: "fallback",
    )
    assert account == r"CORP\svc-cvebeacon"
    assert note == ""


def test_windows_account_falls_back_and_says_so():
    def fail():
        raise OSError("NameSamCompatible unavailable")

    account, note = _current_windows_account(
        resolve_extended=fail, resolve_user=lambda: "svc-cvebeacon"
    )
    assert account == "svc-cvebeacon"
    assert "NameSamCompatible" in note


def test_windows_account_notes_entra_id_accounts():
    account, note = _current_windows_account(
        resolve_extended=lambda: r"AzureAD\user@example.com",
        resolve_user=lambda: "fallback",
    )
    assert account == r"AzureAD\user@example.com"
    assert "Entra" in note


def test_windows_account_fails_closed_when_both_lookups_fail():
    def fail():
        raise OSError("unavailable")

    with pytest.raises(SchedulingError, match="account's shell"):
        _current_windows_account(resolve_extended=fail, resolve_user=fail)


@pytest.mark.skipif(os.name == "nt", reason="needs a non-Windows host")
def test_windows_account_is_not_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("USERDOMAIN", "CORP")
    monkeypatch.setenv("USERNAME", "svc-cvebeacon")
    with pytest.raises(SchedulingError, match="account's shell"):
        _current_windows_account()


def test_windows_plan_shows_an_account_note(tmp_path, monkeypatch):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "cvebeacon.scheduling._current_windows_account",
        lambda: (r"AzureAD\user@example.com", "verify the Entra ID account"),
    )
    plan = make_plan(
        tmp_path / "config.toml",
        times="07:00",
        executable=tmp_path / "cvebeacon.exe",
        run_logged_out=True,
    )
    text = describe(plan)
    assert "Runs as: AzureAD\\user@example.com (S4U, while logged off)" in text
    assert "Account note: verify the Entra ID account" in text


def test_windows_logged_out_fixed_times_uses_passwordless_schtasks(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    plan = windows_plan(tmp_path, run_logged_out=True)
    calls = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        root = ET.parse(args[3]).getroot()
        principal = root.find(f".//{NS}Principal")
        assert principal.findtext(f"{NS}LogonType") == "S4U"
        assert principal.findtext(f"{NS}UserId") == r"CORP\svc-cvebeacon"
        return Result()

    install(plan, run=fake_run)
    args, kwargs = calls[0]
    assert args[:3] == ["schtasks", "/Create", "/XML"]
    assert args[4:6] == ["/TN", WINDOWS_TASK]
    assert args[6:10] == ["/RU", r"CORP\svc-cvebeacon", "/NP", "/F"]
    assert args[-1] == "/HRESULT"
    assert kwargs["stdin"] is subprocess.DEVNULL


def test_windows_logged_out_interval_installs_xml(tmp_path, monkeypatch):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "cvebeacon.scheduling._current_windows_account",
        lambda: (r"CORP\svc-cvebeacon", ""),
    )
    plan = make_plan(
        tmp_path / "config.toml",
        4,
        command="watch",
        executable=tmp_path / "cvebeacon.exe",
        run_logged_out=True,
    )
    calls = []
    roots = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(args, **kwargs):
        calls.append(args)
        roots.append(ET.parse(args[3]).getroot())
        assert kwargs["stdin"] is subprocess.DEVNULL
        return Result()

    install(plan, run=fake_run)
    args = calls[0]
    assert args[:3] == ["schtasks", "/Create", "/XML"]
    assert args[6:10] == ["/RU", r"CORP\svc-cvebeacon", "/NP", "/F"]
    root = roots[0]
    repetition = root.find(f".//{NS}TimeTrigger/{NS}Repetition")
    assert repetition is not None
    assert repetition.findtext(f"{NS}Interval") == "PT4H"
    assert root.find(f".//{NS}CalendarTrigger") is None
    principal = root.find(f".//{NS}Principal")
    assert principal.findtext(f"{NS}LogonType") == "S4U"
    assert principal.findtext(f"{NS}UserId") == r"CORP\svc-cvebeacon"


def test_logged_out_schedule_is_rejected_on_linux(tmp_path, monkeypatch):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    with pytest.raises(SchedulingError, match="only on Windows"):
        make_plan(tmp_path / "config.toml", times="07:00", run_logged_out=True)
    with pytest.raises(SchedulingError, match="only on Windows"):
        make_plan(
            tmp_path / "config.toml",
            4,
            system="linux",
            allow_incompatible=True,
            run_logged_out=True,
        )


def test_windows_access_denied_asks_for_the_service_account_shell(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    plan = windows_plan(tmp_path, run_logged_out=True)

    def fake_run(args, **kwargs):
        return SimpleNamespace(
            returncode=1, stdout="", stderr="ERROR: Access is denied."
        )

    with pytest.raises(SchedulingError) as error:
        install(plan, run=fake_run)
    message = str(error.value)
    assert "Access is denied" in message
    assert "account that will run it" in message
    assert "\n" not in message


@pytest.mark.parametrize(
    "code,expected",
    [
        ("0x80070569", "Log on as a batch job"),
        ("0x80070534", "account or logon error"),
        ("0x8007052e", "account or logon error"),
    ],
)
def test_windows_registration_errors_map_to_one_line_hints(
    tmp_path, monkeypatch, code, expected
):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    plan = windows_plan(tmp_path, run_logged_out=True)

    def fake_run(args, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=f"schtasks: {code}",
        )

    with pytest.raises(SchedulingError) as error:
        install(plan, run=fake_run)
    message = str(error.value)
    assert expected in message
    assert "\n" not in message


@pytest.mark.parametrize("code", [0x80070005, -2147024891, 2147942405])
def test_windows_access_denied_uses_numeric_code_with_localized_text(
    tmp_path, monkeypatch, code
):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    plan = windows_plan(tmp_path, run_logged_out=True)

    def fake_run(args, **kwargs):
        return SimpleNamespace(returncode=code, stdout="", stderr="ERRO: Acesso negado.")

    with pytest.raises(SchedulingError) as error:
        install(plan, run=fake_run)
    assert "account that will run it" in str(error.value)


def test_windows_access_denied_accepts_the_hresult_without_english_text(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    plan = windows_plan(tmp_path, run_logged_out=True)

    def fake_run(args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="ERROR: 0x80070005")

    with pytest.raises(SchedulingError, match="account that will run it"):
        install(plan, run=fake_run)


def test_windows_access_denied_stays_one_line_with_extra_diagnostics(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    plan = windows_plan(tmp_path, run_logged_out=True)

    def fake_run(args, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="ERROR: Access is denied.\nAnother diagnostic line.",
        )

    with pytest.raises(SchedulingError) as error:
        install(plan, run=fake_run)
    assert "\n" not in str(error.value)
    assert "Another diagnostic line" in str(error.value)


def test_linux_failure_never_gets_the_windows_access_hint(tmp_path, monkeypatch):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    plan = make_plan(
        tmp_path / "config.toml",
        times="07:00",
        system="linux",
        executable="/opt/cvebeacon",
        allow_incompatible=True,
    )

    def fake_run(args, **kwargs):
        if args == ["crontab", "-l"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="access denied")

    with pytest.raises(SchedulingError) as error:
        install(plan, run=fake_run)
    assert "elevated prompt" not in str(error.value)


def test_windows_status_reports_logged_off_execution(tmp_path):
    logged_out = _describe_windows_xml(
        _windows_xml(windows_plan(tmp_path, run_logged_out=True)).decode(
            "utf-16"
        )
    )
    assert "Account: CORP\\svc" in logged_out
    assert "Runs while logged off: yes" in logged_out
    interactive = _describe_windows_xml(
        _windows_xml(windows_plan(tmp_path)).decode("utf-16")
    )
    assert "Runs while logged off: no" in interactive
    assert "Account:" not in interactive


@pytest.mark.parametrize(
    "code", [5, 0x80070005, -2147024891, 2147942405]
)
def test_windows_access_denied_normalises_signed_and_unsigned_codes(code):
    assert _windows_access_denied("ERRO: Acesso negado.", code)


def test_windows_access_denied_detects_signed_and_unsigned_text():
    assert _windows_access_denied("-2147024891", 1)
    assert _windows_access_denied("2147942405", 1)
    assert _windows_access_denied("0X80070005", 1)


def test_windows_status_treats_interactive_token_or_password_as_logged_off():
    text = (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<Principals><Principal><LogonType>InteractiveTokenOrPassword</LogonType>"
        "</Principal></Principals>"
        "<Actions><Exec><Command>cvebeacon</Command><Arguments>scan</Arguments>"
        "</Exec></Actions></Task>"
    )
    assert "Runs while logged off: yes" in _describe_windows_xml(text)


def test_cli_schedule_run_logged_out_is_forwarded(tmp_path, monkeypatch, capsys):
    config = write_schedule_config(tmp_path, watch=True)
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "cvebeacon.scheduling._current_windows_account",
        lambda: (r"CORP\svc-cvebeacon", ""),
    )
    installed = []
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
                "--command",
                "watch",
                "--run-logged-out",
                "--yes",
            ]
        )
        == 0
    )
    assert installed[0].run_logged_out is True
    assert installed[0].user_id == r"CORP\svc-cvebeacon"
    assert "Runs as: CORP\\svc-cvebeacon (S4U, while logged off)" in (
        capsys.readouterr().out
    )


def test_cli_schedule_run_logged_out_is_rejected_on_linux(tmp_path, monkeypatch, capsys):
    config = write_schedule_config(tmp_path, watch=True)
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
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
                "--run-logged-out",
                "--yes",
            ]
        )
        == 2
    )
    error = capsys.readouterr().err
    assert "only on Windows" in error
    assert "Traceback" not in error


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
    [
        (0, 0, 0),
        (4, 0, 4),
        (0, 3, 3),
        (2, 0, 2),
        (3, 2, 2),
        (3, 4, 3),
        (0, 1, 1),
        (1, 0, 1),
        (1, 2, 2),
        (1, 3, 3),
        (1, 4, 4),
        (0, 9, 2),
    ],
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
