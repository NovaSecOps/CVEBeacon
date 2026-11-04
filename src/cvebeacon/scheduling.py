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
SCHEDULE_COMMANDS = ("scan", "watch", "both")
TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
TIME_PATTERN = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")
MAX_TIMES = 12

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


def make_plan(
    config_path: str | Path,
    every_hours: int | None = None,
    *,
    times: str | tuple[str, ...] | list[str] | None = None,
    command: str = "scan",
    system: str = "auto",
    executable: str | Path | None = None,
    allow_incompatible: bool = False,
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
    return SchedulePlan(
        requested,
        interval,
        config_target,
        target,
        module_mode,
        fixed_times,
        command,
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
    return ["schtasks", "/Create", "/F", "/TN", WINDOWS_TASK, *schedule, "/RL", "LIMITED", "/TR", subprocess.list2cmdline(plan.command)]


def _tag(name: str) -> str:
    return f"{{{TASK_NAMESPACE}}}{name}"


def _add(parent: ET.Element, name: str, text: str | None = None) -> ET.Element:
    child = ET.SubElement(parent, _tag(name))
    if text is not None:
        child.text = text
    return child


def _windows_xml(plan: SchedulePlan, *, now: datetime | None = None) -> bytes:
    if not plan.times:
        raise SchedulingError("the Windows task XML is used only for fixed times")
    stamp = (now or datetime.now()).strftime("%Y-%m-%d")
    root = ET.Element(_tag("Task"), {"version": "1.2"})
    registration = _add(root, "RegistrationInfo")
    _add(registration, "Description", "CVEBeacon scan and watch schedule")
    triggers = _add(root, "Triggers")
    for value in plan.times:
        trigger = _add(triggers, "CalendarTrigger")
        _add(trigger, "StartBoundary", f"{stamp}T{value}:00")
        _add(trigger, "Enabled", "true")
        daily = _add(trigger, "ScheduleByDay")
        _add(daily, "DaysInterval", "1")
    principals = _add(root, "Principals")
    principal = _add(principals, "Principal", None)
    principal.set("id", "Author")
    _add(principal, "LogonType", "InteractiveToken")
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


def _read_crontab(run=subprocess.run) -> str:
    result = run(["crontab", "-l"], capture_output=True, text=True, check=False)
    if result.returncode == 1 and not result.stdout and result.stderr.strip().casefold().startswith("no crontab for "):
        return ""
    if result.returncode != 0:
        raise SchedulingError(f"cannot read user crontab: {result.stderr.strip()}")
    return result.stdout


def _without_managed_block(text: str) -> str:
    lines = text.split("\n")
    output: list[str] = []
    in_block, found = False, False
    for line in lines:
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
            continue
        if not in_block:
            output.append(line)
    if in_block:
        raise SchedulingError("managed cron block is missing its end marker")
    return "\n".join(output)


def install(plan: SchedulePlan, *, run=subprocess.run) -> None:
    if plan.system == "windows":
        if plan.times:
            descriptor, name = tempfile.mkstemp(prefix="cvebeacon-schedule-", suffix=".xml")
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(_windows_xml(plan))
                    handle.flush()
                    os.fsync(handle.fileno())
                result = run(
                    ["schtasks", "/Create", "/XML", name, "/TN", WINDOWS_TASK, "/F"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            finally:
                try:
                    os.unlink(name)
                except OSError:
                    pass
        else:
            result = run(_windows_args(plan), capture_output=True, text=True, check=False)
    else:
        existing = _read_crontab(run)
        clean = _without_managed_block(existing)
        separator = "\n" if clean and not clean.endswith("\n") else ""
        lines = "\n".join(_cron_lines(plan))
        value = f"{clean}{separator}{CRON_BEGIN}\n{lines}\n{CRON_END}\n"
        result = run(["crontab", "-"], input=value, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SchedulingError(f"schedule installation failed: {result.stderr.strip()}")


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
        result = run(["schtasks", "/Query", "/TN", WINDOWS_TASK, "/XML"], capture_output=True, check=False)
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
        result = run(["schtasks", "/Delete", "/F", "/TN", WINDOWS_TASK], capture_output=True, text=True, check=False)
        if result.returncode == 0: return True
        message = f"{result.stdout}\n{result.stderr}".casefold()
        if any(value in message for value in ("cannot find", "not found", "does not exist")): return False
        raise SchedulingError(f"schedule removal failed: {result.stderr.strip()}")
    existing = _read_crontab(run)
    if CRON_BEGIN not in existing: return False
    clean = _without_managed_block(existing)
    result = run(["crontab", "-"], input=clean, capture_output=True, text=True, check=False)
    if result.returncode != 0: raise SchedulingError(f"schedule removal failed: {result.stderr.strip()}")
    return True
