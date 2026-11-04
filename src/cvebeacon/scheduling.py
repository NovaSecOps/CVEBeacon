"""Native, narrowly owned schedule planning and management."""

from __future__ import annotations

import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .errors import SchedulingError

WINDOWS_TASK = "CVEBeacon Monitor"
CRON_BEGIN = "# BEGIN CVEBEACON MANAGED"
CRON_END = "# END CVEBEACON MANAGED"
CRON_SEPARATOR = "# CVEBEACON SEPARATOR ADDED"
SCHEDULE_COMMANDS = ("scan", "watch", "both")
TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
TIME_PATTERN = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")
MAX_TIMES = 12

WINDOWS_REGISTRATION_SCRIPT = """param(
    [Parameter(Mandatory = $true)][string]$TaskName,
    [Parameter(Mandatory = $true)][string]$XmlPath,
    [Parameter(Mandatory = $true)][string]$Account,
    [switch]$UseXmlPrincipal
)
$ErrorActionPreference = 'Stop'
$xml = [System.IO.File]::ReadAllText($XmlPath)
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$folder = $service.GetFolder('\\')
$userId = if ($UseXmlPrincipal) { $null } else { $Account }
$null = $folder.RegisterTask($TaskName, $xml, 6, $userId, $null, 2, $null)
"""

ET.register_namespace("", TASK_NAMESPACE)


@dataclass(frozen=True, slots=True)
class SchedulePlan:
    system: str
    every_hours: int | None
    config_path: Path
    executable: Path
    module_mode: bool = False
    times: tuple[str, ...] = ()
    schedule_command: str = "scan"
    run_logged_out: bool = False
    user_id: str = ""
    account_note: str = ""
    account_explicit: bool = False

    def _command(self, action: str) -> list[str]:
        prefix = (
            [str(self.executable), "-m", "cvebeacon"]
            if self.module_mode
            else [str(self.executable)]
        )
        tails = {
            "scan": ["scan"],
            "watch": ["watch", "run"],
            "both": ["run"],
        }
        return [*prefix, "--config", str(self.config_path), *tails[action]]

    @property
    def commands(self) -> tuple[list[str], ...]:
        return (self._command(self.schedule_command),)

    @property
    def command(self) -> list[str]:
        """The first scheduled command, kept for callers that expect one."""
        return self.commands[0]


def default_command(*, inventory: bool, watch: bool) -> str:
    if watch and inventory:
        return "both"
    if watch:
        return "watch"
    return "scan"


def parse_times(value: str | tuple[str, ...] | list[str]) -> tuple[str, ...]:
    raw = value.split(",") if isinstance(value, str) else list(value)
    if not raw:
        raise SchedulingError("schedule times cannot be empty")
    if len(raw) > MAX_TIMES:
        raise SchedulingError(f"schedule accepts at most {MAX_TIMES} times")
    times: list[str] = []
    seen: set[str] = set()
    for item in raw:
        text = str(item).strip()
        match = TIME_PATTERN.fullmatch(text)
        if match is None:
            raise SchedulingError(
                f"invalid schedule time {text!r}; use HH:MM from 00:00 to 23:59"
            )
        canonical = f"{match.group(1)}:{match.group(2)}"
        if canonical in seen:
            raise SchedulingError(f"duplicate schedule time {canonical}")
        seen.add(canonical)
        times.append(canonical)
    return tuple(sorted(times, key=lambda item: (int(item[:2]), int(item[3:]))))


def _windows_extended_name() -> str:
    """Return the current account as DOMAIN\\user through GetUserNameExW."""
    import ctypes
    from ctypes import wintypes

    secur32 = ctypes.WinDLL("secur32", use_last_error=True)
    secur32.GetUserNameExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.ULONG),
    ]
    secur32.GetUserNameExW.restype = wintypes.BOOLEAN
    size = wintypes.ULONG(256)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not secur32.GetUserNameExW(2, buffer, ctypes.byref(size)):
        error = ctypes.get_last_error()
        if error == 234 and size.value > 0:
            buffer = ctypes.create_unicode_buffer(size.value)
            if secur32.GetUserNameExW(2, buffer, ctypes.byref(size)):
                return buffer.value
        raise OSError(error, "GetUserNameExW failed")
    return buffer.value


def _windows_user_name() -> str:
    """Return the current user name through GetUserNameW."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.GetUserNameW.argtypes = [
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetUserNameW.restype = wintypes.BOOL
    size = wintypes.DWORD(256)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not advapi32.GetUserNameW(buffer, ctypes.byref(size)):
        error = ctypes.get_last_error()
        if error == 122 and size.value > 0:
            buffer = ctypes.create_unicode_buffer(size.value)
            if advapi32.GetUserNameW(buffer, ctypes.byref(size)):
                return buffer.value
        raise OSError(error, "GetUserNameW failed")
    return buffer.value


def _current_windows_account(resolve_extended=None, resolve_user=None) -> tuple[str, str]:
    """Return the effective account and an optional warning.

    The account comes from the operating system, never from USERNAME or
    USERDOMAIN. An injected resolver is used by the offline tests.
    """
    if resolve_extended is None and resolve_user is None and os.name != "nt":
        raise SchedulingError(
            "cannot determine the current Windows account on this host; "
            "pass --account DOMAIN\\user"
        )
    extended = resolve_extended or _windows_extended_name
    fallback = resolve_user or _windows_user_name
    try:
        account = extended().strip()
    except (AttributeError, OSError):
        account = ""
    if account:
        note = ""
        folded = account.casefold()
        if "@" in account or folded.startswith(("azuread\\", "microsoftaccount\\")):
            note = (
                "this looks like an Entra ID or Microsoft account; Task Scheduler "
                "may not accept it, so verify it or pass a local or domain account"
            )
        return account, note
    try:
        account = fallback().strip()
    except (AttributeError, OSError):
        account = ""
    if account:
        return account, (
            "the NameSamCompatible lookup failed; the fallback returns an "
            "unqualified name, so verify the task account"
        )
    raise SchedulingError(
        "cannot determine the current Windows account; pass --account DOMAIN\\user"
    )


def make_plan(
    config_path: str | Path,
    every_hours: int | None = None,
    *,
    times: str | tuple[str, ...] | list[str] | None = None,
    command: str = "scan",
    system: str = "auto",
    executable: str | Path | None = None,
    allow_incompatible: bool = False,
    run_logged_out: bool = False,
    account: str | None = None,
) -> SchedulePlan:
    if times is not None and every_hours is not None:
        raise SchedulingError("--times and --every are mutually exclusive")
    if times is None and every_hours is None:
        raise SchedulingError("choose an interval with --every or fixed times with --times")
    if command not in SCHEDULE_COMMANDS:
        raise SchedulingError("command must be scan, watch, or both")
    fixed_times: tuple[str, ...] = ()
    interval: int | None = None
    if times is not None:
        fixed_times = parse_times(times)
    else:
        if isinstance(every_hours, bool) or not isinstance(every_hours, int) or not 2 <= every_hours <= 24:
            raise SchedulingError("schedule interval must be a whole number from 2 through 24 hours")
        interval = every_hours
    actual = platform.system().casefold()
    detected = "windows" if actual == "windows" else "linux" if actual == "linux" else "unsupported"
    requested = detected if system == "auto" else system.casefold()
    if detected == "unsupported":
        raise SchedulingError(f"scheduling is unsupported on {platform.system()}")
    if requested not in {"windows", "linux"}:
        raise SchedulingError("platform must be auto, windows, or linux")
    if requested != detected and not allow_incompatible:
        raise SchedulingError(f"cannot manage a {requested} schedule on a {detected} host")
    if account is not None and not run_logged_out:
        raise SchedulingError("--account requires --run-logged-out")
    if run_logged_out and requested != "windows":
        raise SchedulingError("--run-logged-out is supported only on Windows")
    if account is not None and requested != "windows":
        raise SchedulingError("--account is supported only on Windows")
    if requested == "linux" and interval is not None and 24 % interval:
        raise SchedulingError("Linux cron intervals must divide 24: choose 2, 3, 4, 6, 8, 12, or 24 hours")
    if executable:
        target, module_mode = Path(executable).resolve(), False
    elif getattr(sys, "frozen", False):
        target, module_mode = Path(sys.executable).resolve(), False
    else:
        launcher = Path(sys.argv[0]).resolve()
        if requested == "windows" and not launcher.exists() and launcher.with_suffix(".exe").exists():
            launcher = launcher.with_suffix(".exe")
        if launcher.suffix.casefold() in {".exe", ""} and launcher.stem.casefold() == "cvebeacon":
            target, module_mode = launcher, False
        else:
            target, module_mode = Path(sys.executable), True
    config_target = Path(config_path).expanduser().resolve()
    if any(character in str(value) for value in (config_target, target) for character in "\r\n"):
        raise SchedulingError("schedule paths cannot contain line breaks")
    if requested == "linux" and any("%" in str(value) for value in (config_target, target)):
        raise SchedulingError("Linux cron paths cannot contain percent characters")
    account_name = ""
    account_note = ""
    if run_logged_out:
        if account is None:
            account_name, account_note = _current_windows_account()
        else:
            account_name = account.strip()
        if not account_name:
            raise SchedulingError(
                "--run-logged-out needs the Windows account that runs the task"
            )
        if any(character in account_name for character in "\r\n"):
            raise SchedulingError("schedule account cannot contain line breaks")
    return SchedulePlan(
        requested,
        interval,
        config_target,
        target,
        module_mode,
        fixed_times,
        command,
        run_logged_out=run_logged_out,
        user_id=account_name,
        account_note=account_note,
        account_explicit=account is not None,
    )


def _display_command(command: list[str], system: str) -> str:
    return subprocess.list2cmdline(command) if system == "windows" else shlex.join(command)


def describe(plan: SchedulePlan) -> str:
    if plan.times:
        schedule = "Schedule: daily at " + ", ".join(plan.times)
    else:
        schedule = f"Interval: every {plan.every_hours} hours"
    lines = [f"Platform: {plan.system}", schedule, "Commands:"]
    lines.extend(
        "  " + _display_command(command, plan.system) for command in plan.commands
    )
    if plan.run_logged_out:
        lines.append(f"Runs as: {plan.user_id} (S4U, while logged off)")
        if plan.account_note:
            lines.append(f"Account note: {plan.account_note}")
    return "\n".join(lines)


def _cron_lines(plan: SchedulePlan) -> list[str]:
    commands = plan.commands
    if plan.times:
        by_minute: dict[int, list[int]] = {}
        for value in plan.times:
            hour, minute = (int(part) for part in value.split(":"))
            by_minute.setdefault(minute, []).append(hour)
        lines: list[str] = []
        for minute in sorted(by_minute):
            hours = ",".join(str(hour) for hour in sorted(set(by_minute[minute])))
            for command in commands:
                lines.append(f"{minute} {hours} * * * {shlex.join(command)}")
        return lines
    hours = "0" if plan.every_hours == 24 else f"*/{plan.every_hours}"
    return [f"0 {hours} * * * {shlex.join(command)}" for command in commands]


def _windows_args(plan: SchedulePlan) -> list[str]:
    schedule = ["/SC", "DAILY", "/MO", "1"] if plan.every_hours == 24 else ["/SC", "HOURLY", "/MO", str(plan.every_hours)]
    return ["schtasks", "/Create", "/F", "/TN", WINDOWS_TASK, *schedule, "/RL", "LIMITED", "/TR", subprocess.list2cmdline(plan.command), "/HRESULT"]


def _tag(name: str) -> str:
    return f"{{{TASK_NAMESPACE}}}{name}"


def _add(parent: ET.Element, name: str, text: str | None = None) -> ET.Element:
    child = ET.SubElement(parent, _tag(name))
    if text is not None:
        child.text = text
    return child


def _windows_xml(plan: SchedulePlan, *, now: datetime | None = None) -> bytes:
    current = now or datetime.now()
    stamp = current.strftime("%Y-%m-%d")
    root = ET.Element(_tag("Task"), {"version": "1.2"})
    registration = _add(root, "RegistrationInfo")
    _add(registration, "Description", "CVEBeacon scan and watch schedule")
    triggers = _add(root, "Triggers")
    if plan.times:
        for value in plan.times:
            trigger = _add(triggers, "CalendarTrigger")
            _add(trigger, "StartBoundary", f"{stamp}T{value}:00")
            _add(trigger, "Enabled", "true")
            daily = _add(trigger, "ScheduleByDay")
            _add(daily, "DaysInterval", "1")
    else:
        trigger = _add(triggers, "TimeTrigger")
        repetition = _add(trigger, "Repetition")
        _add(repetition, "Interval", f"PT{plan.every_hours}H")
        _add(trigger, "StartBoundary", current.strftime("%Y-%m-%dT%H:%M:%S"))
        _add(trigger, "Enabled", "true")
    principals = _add(root, "Principals")
    principal = _add(principals, "Principal", None)
    principal.set("id", "Author")
    if plan.run_logged_out:
        _add(principal, "UserId", plan.user_id)
    _add(principal, "LogonType", "S4U" if plan.run_logged_out else "InteractiveToken")
    _add(principal, "RunLevel", "LeastPrivilege")
    settings = _add(root, "Settings")
    _add(settings, "MultipleInstancesPolicy", "IgnoreNew")
    _add(settings, "DisallowStartIfOnBatteries", "false")
    _add(settings, "StopIfGoingOnBatteries", "false")
    _add(settings, "StartWhenAvailable", "true")
    _add(settings, "Enabled", "true")
    actions = _add(root, "Actions", None)
    actions.set("Context", "Author")
    for command in plan.commands:
        action = _add(actions, "Exec")
        _add(action, "Command", command[0])
        _add(action, "Arguments", subprocess.list2cmdline(command[1:]))
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-16", xml_declaration=True)


def _describe_windows_xml(text: str) -> str | None:
    clean = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    try:
        root = ET.fromstring(clean)
    except (ET.ParseError, ValueError):
        return None
    times: list[str] = []
    interval: int | None = None
    for trigger in root.iter(_tag("CalendarTrigger")):
        repetition = trigger.find(_tag("Repetition"))
        value = repetition.findtext(_tag("Interval")) if repetition is not None else None
        match = re.fullmatch(r"PT(\d+)H", value or "")
        if match:
            interval = int(match.group(1))
            continue
        boundary = trigger.findtext(_tag("StartBoundary")) or ""
        if len(boundary) >= 16:
            times.append(boundary[11:16])
    for trigger in root.iter(_tag("TimeTrigger")):
        repetition = trigger.find(_tag("Repetition"))
        value = repetition.findtext(_tag("Interval")) if repetition is not None else None
        match = re.fullmatch(r"PT(\d+)H", value or "")
        if match:
            interval = int(match.group(1))
    commands: list[str] = []
    for action in root.iter(_tag("Exec")):
        command = action.findtext(_tag("Command")) or ""
        arguments = action.findtext(_tag("Arguments")) or ""
        line = (command + " " + arguments).strip()
        if line not in commands:
            commands.append(line)
    if not commands:
        return None
    if times:
        schedule = "Schedule: daily at " + ", ".join(sorted(set(times)))
    elif interval is not None:
        schedule = f"Interval: every {interval} hours"
    else:
        schedule = None
    lines = ["Task: " + WINDOWS_TASK]
    principal = root.find(f".//{_tag('Principal')}")
    if principal is not None:
        account = principal.findtext(_tag("UserId"))
        logon_type = principal.findtext(_tag("LogonType")) or "InteractiveToken"
        if account:
            lines.append("Account: " + account)
        logged_out = logon_type.casefold() in {
            "s4u",
            "password",
            "serviceaccount",
            "interactivetokenorpassword",
        }
        lines.append("Runs while logged off: " + ("yes" if logged_out else "no"))
    if schedule:
        lines.append(schedule)
    lines.append("Commands:")
    lines.extend("  " + command for command in commands)
    return "\n".join(lines)


def _describe_cron_block(block: str) -> str | None:
    times: set[str] = set()
    commands: list[str] = []
    interval: int | None = None
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 6:
            return None
        minute, hour = fields[0], fields[1]
        command = " ".join(fields[5:])
        if not minute.isdigit():
            return None
        if hour.startswith("*/") and hour[2:].isdigit():
            interval = int(hour[2:])
        else:
            try:
                hours = [int(value) for value in hour.split(",")]
            except ValueError:
                return None
            for value in hours:
                times.add(f"{value:02d}:{int(minute):02d}")
        if command not in commands:
            commands.append(command)
    if not commands:
        return None
    if interval is not None:
        schedule = f"Interval: every {interval} hours"
    else:
        schedule = "Schedule: daily at " + ", ".join(sorted(times))
    lines = [schedule, "Commands:"]
    lines.extend("  " + command for command in commands)
    return "\n".join(lines)


def _crontab_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="surrogateescape")
    return value or ""


def _read_crontab(run=subprocess.run) -> str:
    result = run(["crontab", "-l"], capture_output=True, check=False)
    stdout = _crontab_text(getattr(result, "stdout", ""))
    stderr = _crontab_text(getattr(result, "stderr", ""))
    if result.returncode == 1 and not stdout and stderr.strip().casefold().startswith("no crontab for "):
        return ""
    if result.returncode != 0:
        raise SchedulingError(f"cannot read user crontab: {stderr.strip()}")
    return stdout


def _without_managed_block(text: str) -> str:
    lines = text.split("\n")
    output: list[str] = []
    in_block, found = False, False
    separator_added = False
    block_end = -1
    for index, line in enumerate(lines):
        marker = line[:-1] if line.endswith("\r") else line
        if marker == CRON_BEGIN:
            if in_block or found:
                raise SchedulingError("malformed duplicate managed cron marker")
            in_block, found = True, True
            continue
        if marker == CRON_END:
            if not in_block:
                raise SchedulingError("managed cron end marker has no beginning")
            in_block = False
            block_end = index
            continue
        if in_block:
            if marker == CRON_SEPARATOR:
                separator_added = True
            continue
        output.append(line)
    if in_block:
        raise SchedulingError("managed cron block is missing its end marker")
    result = "\n".join(output)
    if (
        separator_added
        and block_end >= 0
        and all(item == "" for item in lines[block_end + 1 :])
        and result.endswith("\n")
    ):
        result = result[:-1]
    return result


def _windows_access_denied(detail: str, returncode: int) -> bool:
    folded = detail.casefold()
    code = returncode & 0xFFFFFFFF if isinstance(returncode, int) else returncode
    return (
        code in {5, 0x80070005}
        or "0x80070005" in folded
        or "2147942405" in folded
        or "-2147024891" in folded
        or "access is denied" in folded
        or "access denied" in folded
    )


def _windows_registration_hint(
    detail: str, returncode: int, plan: SchedulePlan
) -> str:
    folded = detail.casefold()
    if _windows_access_denied(detail, returncode):
        if plan.run_logged_out and plan.account_explicit:
            return (
                "access denied: use an elevated administrator shell with --account, "
                "or the service account's own shell"
            )
        if plan.run_logged_out:
            return (
                "access denied: use the service account's own shell, or name it "
                "with --account from an elevated administrator shell"
            )
        return "access denied: run from an elevated prompt"
    if "0x80070569" in folded:
        return (
            "the account needs the 'Log on as a batch job' right: grant it in "
            "secpol.msc; a domain GPO can override it"
        )
    if any(
        code in folded
        for code in ("0x80070534", "0x8007052e", "0x80070533", "0x800704ec")
    ):
        return (
            "account or logon error: verify the account and grant it the "
            "'Log on as a batch job' right in secpol.msc"
        )
    return ""


def install(plan: SchedulePlan, *, run=subprocess.run) -> None:
    if plan.system == "windows":
        if plan.run_logged_out:
            with tempfile.TemporaryDirectory(
                prefix="cvebeacon-schedule-", ignore_cleanup_errors=True
            ) as directory:
                xml_path = Path(directory) / "task.xml"
                script_path = Path(directory) / "register.ps1"
                xml_path.write_bytes(_windows_xml(plan))
                script_path.write_text(
                    WINDOWS_REGISTRATION_SCRIPT, encoding="utf-8"
                )

                def run_com(use_xml_principal: bool):
                    arguments = [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(script_path),
                        "-TaskName",
                        WINDOWS_TASK,
                        "-XmlPath",
                        str(xml_path),
                        "-Account",
                        plan.user_id,
                    ]
                    if use_xml_principal:
                        arguments.append("-UseXmlPrincipal")
                    return run(
                        arguments,
                        capture_output=True,
                        text=True,
                        errors="replace",
                        check=False,
                        stdin=subprocess.DEVNULL,
                        timeout=120,
                    )

                result = None
                last_error: Exception | None = None
                for use_xml_principal in (False, True):
                    try:
                        result = run_com(use_xml_principal)
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        last_error = exc
                        continue
                    if result.returncode == 0:
                        break
                if result is None or result.returncode != 0:
                    try:
                        result = run(
                            [
                                "schtasks",
                                "/Create",
                                "/XML",
                                str(xml_path),
                                "/TN",
                                WINDOWS_TASK,
                                "/RU",
                                plan.user_id,
                                "/NP",
                                "/F",
                                "/HRESULT",
                            ],
                            capture_output=True,
                            text=True,
                            check=False,
                            stdin=subprocess.DEVNULL,
                        )
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        if result is None:
                            detail = " ".join(str(exc).split())[:600]
                            raise SchedulingError(
                                f"schedule installation failed: {detail}"
                            ) from exc
                        last_error = exc
                if result is None:
                    detail = " ".join(str(last_error).split())[:600]
                    raise SchedulingError(
                        f"schedule installation failed: {detail}"
                    ) from last_error
        elif plan.times:
            descriptor, name = tempfile.mkstemp(prefix="cvebeacon-schedule-", suffix=".xml")
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(_windows_xml(plan))
                    handle.flush()
                    os.fsync(handle.fileno())
                result = run(
                    ["schtasks", "/Create", "/XML", name, "/TN", WINDOWS_TASK, "/F", "/HRESULT"],
                    capture_output=True,
                    text=True,
                    check=False,
                    stdin=subprocess.DEVNULL,
                )
            finally:
                try:
                    os.unlink(name)
                except OSError:
                    pass
        else:
            result = run(
                _windows_args(plan),
                capture_output=True,
                text=True,
                check=False,
                stdin=subprocess.DEVNULL,
            )
    else:
        existing = _read_crontab(run)
        clean = _without_managed_block(existing)
        separator = "\n" if clean and not clean.endswith("\n") else ""
        marker = f"{CRON_SEPARATOR}\n" if separator else ""
        lines = "\n".join(_cron_lines(plan))
        value = f"{clean}{separator}{CRON_BEGIN}\n{marker}{lines}\n{CRON_END}\n"
        payload = value.encode("utf-8", errors="surrogateescape")
        result = run(
            ["crontab", "-"], input=payload, capture_output=True, check=False
        )
    if result.returncode != 0:
        detail = " ".join(
            (
                _crontab_text(getattr(result, "stderr", ""))
                or _crontab_text(getattr(result, "stdout", ""))
            ).split()
        )
        hint = ""
        if plan.system == "windows":
            hint = _windows_registration_hint(detail, result.returncode, plan)
        if hint:
            detail = detail.rstrip(".; ")
        detail = detail[:600]
        message = (
            f"schedule installation failed: {detail}"
            if detail
            else "schedule installation failed"
        )
        if hint:
            message = f"{message}; {hint}"
        raise SchedulingError(message)


def _host_system(system: str) -> str:
    actual = platform.system().casefold()
    detected = "windows" if actual == "windows" else "linux" if actual == "linux" else "unsupported"
    resolved = detected if system == "auto" else system.casefold()
    if resolved not in {"windows", "linux"} or detected == "unsupported":
        raise SchedulingError("scheduling is supported only on Windows and Linux")
    if resolved != detected:
        raise SchedulingError(f"cannot manage a {resolved} schedule on a {detected} host")
    return resolved


def _command_text(value) -> str:
    if isinstance(value, bytes):
        if value.startswith((b"\xff\xfe", b"\xfe\xff")):
            return value.decode("utf-16", errors="replace")
        return value.decode("utf-8", errors="replace")
    return value or ""


def status(*, system: str = "auto", run=subprocess.run) -> str:
    resolved = _host_system(system)
    if resolved == "windows":
        result = run(
            ["schtasks", "/Query", "/TN", WINDOWS_TASK, "/XML"],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        stdout = _command_text(getattr(result, "stdout", ""))
        stderr = _command_text(getattr(result, "stderr", ""))
        if result.returncode == 0:
            summary = _describe_windows_xml(stdout)
            return summary or stdout.strip()
        message = f"{stdout}\n{stderr}".casefold()
        if any(value in message for value in ("cannot find", "not found", "does not exist")):
            return "not installed"
        raise SchedulingError(f"schedule status failed: {stderr.strip() or stdout.strip()}")
    text = _read_crontab(run)
    _without_managed_block(text)
    if CRON_BEGIN not in text: return "not installed"
    start, end = text.find(CRON_BEGIN), text.find(CRON_END)
    if end < start: raise SchedulingError("managed cron block is malformed")
    block = text[start:end + len(CRON_END)]
    summary = _describe_cron_block(block)
    return f"{summary}\n\nManaged cron block:\n{block}" if summary else block


def remove(*, system: str = "auto", run=subprocess.run) -> bool:
    resolved = _host_system(system)
    if resolved == "windows":
        result = run(
            ["schtasks", "/Delete", "/F", "/TN", WINDOWS_TASK],
            capture_output=True,
            text=True,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0: return True
        message = f"{result.stdout}\n{result.stderr}".casefold()
        if any(value in message for value in ("cannot find", "not found", "does not exist")): return False
        raise SchedulingError(f"schedule removal failed: {result.stderr.strip()}")
    existing = _read_crontab(run)
    if CRON_BEGIN not in existing: return False
    clean = _without_managed_block(existing)
    payload = clean.encode("utf-8", errors="surrogateescape")
    result = run(["crontab", "-"], input=payload, capture_output=True, check=False)
    if result.returncode != 0:
        raise SchedulingError(
            f"schedule removal failed: {_crontab_text(result.stderr).strip()}"
        )
    return True
