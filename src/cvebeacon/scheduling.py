"""Native, narrowly owned schedule planning and management."""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import SchedulingError

LOG = logging.getLogger("cvebeacon")

WINDOWS_TASK = "CVEBeacon Monitor"
CRON_BEGIN = "# BEGIN CVEBEACON MANAGED"
CRON_END = "# END CVEBEACON MANAGED"
CRON_SEPARATOR = "# CVEBEACON SEPARATOR ADDED"
SCHEDULE_COMMANDS = ("scan", "watch", "both")
TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
TIME_PATTERN = re.compile(r"(\d{2}):(\d{2})")
MAX_TIMES = 12
DEFAULT_TIMER_TIMES = ("07:00", "19:00")
TIMER_SCHEDULE_FILENAME = "schedule.json"
TIMER_CONTROL_DROPIN = "dashboard-schedule.conf"
TIMER_CONTROL_TICK = "*:0/15"

WINDOWS_REGISTRATION_SCRIPT = """param(
    [Parameter(Mandatory = $true)][string]$TaskName,
    [Parameter(Mandatory = $true)][string]$XmlPath,
    [Parameter(Mandatory = $true)][string]$Account
)
$ErrorActionPreference = 'Stop'
$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), [System.Text.UTF8Encoding]::new($false), $false)
$password = $reader.ReadLine()
$reader.Dispose()
if (-not $password) { throw "no password on stdin" }
$xml = [System.IO.File]::ReadAllText($XmlPath)
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$folder = $service.GetFolder('\\')
$null = $folder.RegisterTask($TaskName, $xml, 6, $Account, $password, 1, $null)
"""

SID_PATTERN = re.compile(r"S-\d+(?:-\d+)+", re.IGNORECASE)
SYSTEMD_UNIT_PATTERN = re.compile(r"cvebeacon[\w@.-]*\.(service|timer)")
SYSTEMD_TIME_PATTERN = re.compile(
    r"(?:[A-Za-z]{3} )?(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)"
    r"(?: [A-Za-z0-9_+:/-]{1,32})?"
)

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
        if match is None or int(match[1]) > 23 or int(match[2]) > 59:
            raise SchedulingError(
                f"invalid schedule time {text!r}; use HH:MM from 00:00 to 23:59"
            )
        canonical = f"{int(match[1]):02d}:{int(match[2]):02d}"
        if canonical in seen:
            raise SchedulingError(f"duplicate schedule time {canonical}")
        seen.add(canonical)
        times.append(canonical)
    return tuple(sorted(times, key=lambda item: (int(item[:2]), int(item[3:]))))


@dataclass(frozen=True, slots=True)
class TimerSchedule:
    """The dashboard-owned schedule and the last scheduled run start."""

    every_hours: int | None = None
    times: tuple[str, ...] = ()
    last_start: datetime | None = None

    @property
    def mode(self) -> str:
        return "interval" if self.every_hours is not None else "times"


def parse_interval(value: int | str) -> int:
    """Validate an interval using the same bounds as ``make_plan``."""
    if isinstance(value, str):
        if not re.fullmatch(r"\d+", value):
            raise SchedulingError(
                "schedule interval must be a whole number from 2 through 24 hours"
            )
        try:
            value = int(value)
        except ValueError as exc:
            raise SchedulingError(
                "schedule interval must be a whole number from 2 through 24 hours"
            ) from exc
    if isinstance(value, bool) or not isinstance(value, int) or not 2 <= value <= 24:
        raise SchedulingError(
            "schedule interval must be a whole number from 2 through 24 hours"
        )
    return value


def _schedule_parts(
    every_hours: int | None,
    times: str | tuple[str, ...] | list[str] | None,
) -> tuple[int | None, tuple[str, ...]]:
    if times is not None and every_hours is not None:
        raise SchedulingError("--times and --every are mutually exclusive")
    if times is None and every_hours is None:
        raise SchedulingError("choose an interval with --every or fixed times with --times")
    if times is not None:
        return None, parse_times(times)
    return parse_interval(every_hours), ()


def build_timer_schedule(
    every_hours: int | None = None,
    *,
    times: str | tuple[str, ...] | list[str] | None = None,
    last_start: datetime | None = None,
) -> TimerSchedule:
    """Build timer schedule data through the shared scheduler validators."""
    interval, fixed_times = _schedule_parts(every_hours, times)
    if last_start is not None:
        _history_instant(last_start)
    return TimerSchedule(interval, fixed_times, last_start)


def _history_instant(value: datetime) -> datetime:
    try:
        if not isinstance(value, datetime) or value.utcoffset() is None:
            raise SchedulingError("schedule history must include a local time-zone offset")
        instant = value.astimezone(timezone.utc)
        # Keep room for UTC/local conversion and day or interval arithmetic.
        if not 2 <= value.year <= 9998 or not 2 <= instant.year <= 9998:
            raise SchedulingError("schedule history is outside the supported time range")
        return instant
    except (OverflowError, ValueError) as exc:
        raise SchedulingError("schedule history is outside the supported time range") from exc


def _schedule_directory(data_directory: str | Path) -> tuple[Path, os.stat_result]:
    directory = Path(data_directory).absolute()
    try:
        details = directory.lstat()
    except OSError as exc:
        raise SchedulingError("schedule data directory is unavailable") from exc
    if not stat.S_ISDIR(details.st_mode):
        raise SchedulingError("schedule data directory must be a real directory")
    return directory, details


def _schedule_path(data_directory: str | Path) -> tuple[Path, os.stat_result]:
    directory, details = _schedule_directory(data_directory)
    return directory / TIMER_SCHEDULE_FILENAME, details


def _schedule_payload(schedule: TimerSchedule) -> dict[str, object]:
    interval, fixed_times = _schedule_parts(
        schedule.every_hours,
        schedule.times if schedule.every_hours is None else (
            schedule.times if schedule.times else None
        ),
    )
    validated = build_timer_schedule(
        interval,
        times=fixed_times if interval is None else None,
        last_start=schedule.last_start,
    )
    return {
        "version": 1,
        "every_hours": validated.every_hours,
        "times": list(validated.times),
        "last_start": (
            validated.last_start.isoformat(timespec="microseconds")
            if validated.last_start is not None
            else None
        ),
    }


def load_timer_schedule(data_directory: str | Path) -> TimerSchedule:
    """Read private schedule data, or return the shipped timer defaults."""
    path, directory_details = _schedule_path(data_directory)
    try:
        entry = path.lstat()
    except FileNotFoundError:
        return build_timer_schedule(times=DEFAULT_TIMER_TIMES)
    except OSError as exc:
        raise SchedulingError("schedule data could not be read") from exc
    if (
        not stat.S_ISREG(entry.st_mode)
        or entry.st_nlink != 1
        or entry.st_uid != directory_details.st_uid
        or (os.name == "posix" and stat.S_IMODE(entry.st_mode) != 0o600)
    ):
        raise SchedulingError("schedule data file must be a private regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SchedulingError("schedule data could not be read") from exc
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_uid != directory_details.st_uid
            or (os.name == "posix" and stat.S_IMODE(opened.st_mode) != 0o600)
        ):
            raise SchedulingError("schedule data file must be a private regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            encoded = handle.read(16385)
    except OSError as exc:
        raise SchedulingError("schedule data could not be read") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(encoded) > 16384:
        raise SchedulingError("schedule data file is too large")
    try:
        payload = json.loads(encoded.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise SchedulingError("schedule data file is invalid") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "every_hours", "times", "last_start"}
        or type(payload.get("version")) is not int
        or payload.get("version") != 1
    ):
        raise SchedulingError("schedule data file is invalid")
    raw_times = payload.get("times")
    raw_interval = payload.get("every_hours")
    raw_start = payload.get("last_start")
    if not isinstance(raw_times, list) or any(not isinstance(item, str) for item in raw_times):
        raise SchedulingError("schedule data file is invalid")
    if raw_interval is not None and raw_times:
        raise SchedulingError("schedule data file is invalid")
    if raw_start is not None and not isinstance(raw_start, str):
        raise SchedulingError("schedule data file is invalid")
    try:
        last_start = datetime.fromisoformat(raw_start) if raw_start is not None else None
        if last_start is not None and (last_start.tzinfo is None or last_start.utcoffset() is None):
            raise SchedulingError("scheduled run start must include a local time-zone offset")
        return build_timer_schedule(
            raw_interval,
            times=raw_times if raw_interval is None else None,
            last_start=last_start,
        )
    except (TypeError, ValueError) as exc:
        raise SchedulingError("schedule data file is invalid") from exc


def save_timer_schedule(
    data_directory: str | Path,
    schedule: TimerSchedule,
    *,
    root_owner: bool = False,
) -> Path:
    """Atomically write owner-only schedule data beside monitoring state."""
    path, directory_details = _schedule_path(data_directory)
    if root_owner:
        if (
            os.name == "posix"
            and os.geteuid() != 0
            and directory_details.st_uid != os.geteuid()
        ):
            raise SchedulingError("root is required to initialize schedule data")
    elif os.name == "posix" and directory_details.st_uid != os.geteuid():
        raise SchedulingError("schedule data directory must be owned by the CVEBeacon account")
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    except OSError as exc:
        raise SchedulingError("schedule data file could not be written") from exc
    if current is not None and (
        not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or current.st_uid != directory_details.st_uid
        or (os.name == "posix" and stat.S_IMODE(current.st_mode) != 0o600)
    ):
        raise SchedulingError("schedule data file must be a private regular file")

    payload = json.dumps(
        _schedule_payload(schedule), ensure_ascii=False, sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".schedule.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
            if root_owner and (
                directory_details.st_uid != os.geteuid()
                or directory_details.st_gid != os.getegid()
            ):
                os.fchown(descriptor, directory_details.st_uid, directory_details.st_gid)
            check = os.fstat(descriptor)
            if (
                stat.S_IMODE(check.st_mode) != 0o600
                or check.st_uid != directory_details.st_uid
                or check.st_nlink != 1
            ):
                raise SchedulingError("schedule data permissions could not be secured")
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        raise SchedulingError("schedule data file could not be written") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return path


def _aware_now(now: datetime | None = None) -> datetime:
    if now is None:
        now = datetime.now(_system_local_timezone())
    if now.tzinfo is None or now.utcoffset() is None:
        raise SchedulingError("schedule time must include a local time-zone offset")
    return now


def local_now() -> datetime:
    """Return the current aware server-local time used by the timer schedule."""
    return _aware_now()


def _system_local_timezone():
    if os.name == "posix":
        try:
            target = os.readlink("/etc/localtime")
            marker = "/zoneinfo/"
            if marker in target:
                return ZoneInfo(target.split(marker, 1)[1])
        except (OSError, ZoneInfoNotFoundError):
            pass
        try:
            with open("/etc/localtime", "rb") as handle:
                return ZoneInfo.from_file(handle)
        except (OSError, ValueError):
            pass
    return datetime.now().astimezone().tzinfo or timezone.utc


def schedule_due(schedule: TimerSchedule, now: datetime) -> bool:
    """Return whether one scheduled window has elapsed since the last start."""
    now = _aware_now(now)
    if schedule.every_hours is not None:
        if schedule.last_start is None:
            return True
        elapsed = now.astimezone(timezone.utc) - schedule.last_start.astimezone(timezone.utc)
        return elapsed >= timedelta(hours=schedule.every_hours)
    local_now = now.replace(tzinfo=None)
    last_local = (
        schedule.last_start.astimezone(now.tzinfo).replace(tzinfo=None)
        if schedule.last_start is not None
        else None
    )
    days = (local_now.date(), local_now.date() - timedelta(days=1))
    if last_local is None:
        days = days[:1]
    for day in days:
        for text in schedule.times:
            scheduled = datetime.combine(day, datetime_time.fromisoformat(text))
            if scheduled <= local_now and (last_local is None or scheduled > last_local):
                return True
    return False


def schedule_next_run(schedule: TimerSchedule, now: datetime | None = None) -> datetime:
    """Compute the next schedule time in the server's local time zone."""
    current = _aware_now(now)
    if schedule.every_hours is not None:
        if schedule.last_start is None:
            return current
        return (schedule.last_start.astimezone(timezone.utc)
                + timedelta(hours=schedule.every_hours)).astimezone(current.tzinfo)
    local_wall = current.replace(tzinfo=None)
    zone = current.tzinfo
    for offset in range(0, 370):
        day = local_wall.date() + timedelta(days=offset)
        for text in schedule.times:
            wall = datetime.combine(day, datetime_time.fromisoformat(text))
            if wall <= local_wall:
                continue
            candidates = []
            for fold in (0, 1):
                candidate = wall.replace(tzinfo=zone, fold=fold)
                round_trip = candidate.astimezone(timezone.utc).astimezone(zone)
                if round_trip.replace(tzinfo=None) == wall and round_trip.astimezone(timezone.utc) > current.astimezone(timezone.utc):
                    candidates.append(round_trip)
            if candidates:
                return min(candidates, key=lambda item: item.astimezone(timezone.utc))
    raise SchedulingError("could not compute the next scheduled run")


def should_run_scheduled(data_directory: str | Path, now: datetime | None = None) -> bool:
    """Read the saved schedule and persist the start before a due run begins."""
    current = _aware_now(now)
    path, _ = _schedule_path(data_directory)
    try:
        path.lstat()
        missing = False
    except FileNotFoundError:
        missing = True
    except OSError as exc:
        raise SchedulingError("schedule data could not be checked") from exc
    schedule = load_timer_schedule(data_directory)
    due = schedule_due(schedule, current)
    if due or missing:
        save_timer_schedule(
            data_directory,
            TimerSchedule(
                schedule.every_hours,
                schedule.times,
                current if due else schedule.last_start,
            ),
        )
    return due


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
            "run the command from that account's shell"
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
        "cannot determine the current Windows account; "
        "run the command from that account's shell"
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
    if command not in SCHEDULE_COMMANDS:
        raise SchedulingError("command must be scan, watch, or both")
    interval, fixed_times = _schedule_parts(every_hours, times)
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
        lines.append(f"Runs as: {plan.user_id} (stored password, while logged off)")
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
    _add(principal, "LogonType", "Password" if plan.run_logged_out else "InteractiveToken")
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


def _lookup_account_sid(sid: str) -> str | None:
    """Resolve a SID string to DOMAIN\\name through LookupAccountSidW."""
    if os.name != "nt" or SID_PATTERN.fullmatch(sid) is None:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32.ConvertStringSidToSidW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.LPVOID),
        ]
        advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
        advapi32.LookupAccountSidW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPVOID,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.LookupAccountSidW.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [wintypes.LPVOID]
        kernel32.LocalFree.restype = wintypes.LPVOID

        sid_pointer = wintypes.LPVOID()
        if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(sid_pointer)):
            return None
        try:
            name_size = wintypes.DWORD()
            domain_size = wintypes.DWORD()
            use = wintypes.DWORD()
            advapi32.LookupAccountSidW(
                None,
                sid_pointer,
                None,
                ctypes.byref(name_size),
                None,
                ctypes.byref(domain_size),
                ctypes.byref(use),
            )
            if ctypes.get_last_error() != 122:  # ERROR_INSUFFICIENT_BUFFER
                return None
            name = ctypes.create_unicode_buffer(name_size.value)
            domain = ctypes.create_unicode_buffer(domain_size.value)
            if not advapi32.LookupAccountSidW(
                None,
                sid_pointer,
                name,
                ctypes.byref(name_size),
                domain,
                ctypes.byref(domain_size),
                ctypes.byref(use),
            ):
                return None
            return f"{domain.value}\\{name.value}" if domain.value else name.value
        finally:
            kernel32.LocalFree(sid_pointer)
    except (AttributeError, OSError, ValueError):
        return None


def _describe_windows_xml(
    text: str, *, sid_resolver=_lookup_account_sid
) -> str | None:
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
            if SID_PATTERN.fullmatch(account) is not None:
                try:
                    resolved = sid_resolver(account)
                except Exception:
                    resolved = None
                lines.append(
                    f"Account: {resolved} ({account})"
                    if resolved
                    else "Account: " + account
                )
            else:
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
        fields = stripped.split(maxsplit=5)
        if len(fields) < 6:
            return None
        minute, hour = fields[0], fields[1]
        command = fields[5]
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
        if plan.run_logged_out:
            return (
                "access denied: use an elevated administrator shell and verify "
                "the account name"
            )
        return "access denied: run from an elevated prompt"
    if "0x8007052e" in folded:
        return (
            "the account password was rejected: verify it and run the command again"
        )
    if "0x80070569" in folded:
        return (
            "the account needs the 'Log on as a batch job' right: grant it in "
            "secpol.msc; a domain GPO can override it"
        )
    if "0x80070534" in folded:
        return "the account was not found: verify the --account name"
    if any(code in folded for code in ("0x80070533", "0x800704ec")):
        return (
            "account or logon error: verify the account and grant it the "
            "'Log on as a batch job' right in secpol.msc"
        )
    return ""


def windows_powershell_environment() -> dict[str, str]:
    """Return the environment for Windows PowerShell 5.1 child processes.

    PowerShell 7 exports its own PSModulePath. Windows PowerShell inherits it
    and then cannot load its built-in modules, so drop it and let Windows
    PowerShell use its default module path.
    """
    return {
        name: value
        for name, value in os.environ.items()
        if name.upper() != "PSMODULEPATH"
    }


def install(
    plan: SchedulePlan, *, password: str | None = None, run=subprocess.run
) -> None:
    if plan.system == "windows":
        if plan.run_logged_out:
            if password and any(ord(ch) < 32 for ch in password):
                raise SchedulingError("account password cannot contain control characters")
            if not password:
                raise SchedulingError(
                    "--run-logged-out requires the account password"
                )
            directory = None
            try:
                directory = tempfile.mkdtemp(prefix="cvebeacon-schedule-")
                xml_path = Path(directory) / "task.xml"
                script_path = Path(directory) / "register.ps1"
                xml_path.write_bytes(_windows_xml(plan))
                script_path.write_text(
                    WINDOWS_REGISTRATION_SCRIPT, encoding="utf-8"
                )
                result = run(
                    [
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
                    ],
                    input=(password + "\n").encode("utf-8"),
                    capture_output=True,
                    check=False,
                    timeout=120,
                    env=windows_powershell_environment(),
                )
                if result.returncode != 0:
                    raw = _crontab_text(getattr(result, "stderr", "")) or _crontab_text(getattr(result, "stdout", ""))
                    # Scrub before category matching, case folding or truncation.
                    raw = raw.replace(password, "[redacted]")
                    hint = _windows_registration_hint(raw, result.returncode, plan)
                    message = "schedule installation failed; password-bearing diagnostics [redacted]"
                    raise SchedulingError(message + ("; " + hint if hint else ""))
            except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
                raise SchedulingError(
                    "schedule installation failed; password-bearing diagnostics [redacted]"
                ) from None
            finally:
                password = None
                if directory is not None:
                    try:
                        shutil.rmtree(directory)
                    except OSError as exc:
                        LOG.warning(
                            "could not remove temporary schedule directory %s: %s",
                            directory,
                            exc,
                        )
        elif plan.times:
            name = None
            try:
                descriptor, name = tempfile.mkstemp(
                    prefix="cvebeacon-schedule-", suffix=".xml"
                )
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
            except OSError as exc:
                detail = " ".join(str(exc).split())[:600]
                raise SchedulingError(
                    f"schedule installation failed: {detail}"
                ) from exc
            finally:
                if name is not None:
                    try:
                        os.unlink(name)
                    except OSError as exc:
                        LOG.warning(
                            "could not remove temporary schedule file %s: %s",
                            name,
                            exc,
                        )
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



def installed_scan_state(summary: str, config_path: Path, *, windows: bool = False) -> str:
    """Classify the recognized native actions for this configuration only."""
    if summary == "not installed":
        return "none"
    _, marker, commands = summary.partition("Commands:\n")
    if not marker:
        return "unknown"
    known = set()
    for line in commands.splitlines():
        if not line.startswith("  "):
            break
        try:
            parts = shlex.split(line, posix=not windows)
        except ValueError:
            continue
        action = _argv_scan_action(parts, config_path)
        if action in {"scan", "watch"}:
            known.add(action)
    return "scan" if "scan" in known else "watch" if "watch" in known else "unknown"


def _argv_scan_action(parts: list[str], config_path: Path) -> str:
    """Classify a command using the same config and action rules as schedule status."""
    try:
        option = parts.index("--config")
        path = Path(parts[option + 1].strip('"'))
        if not path.is_absolute() or path.resolve() != config_path.resolve():
            return "unknown"
        tail = tuple(parts[option + 2:])
    except (ValueError, IndexError, OSError):
        return "unknown"
    if tail in {
        ("scan",), ("run",), ("run", "--yes"),
        ("run", "--if-due"), ("run", "--yes", "--if-due"),
    }:
        return "scan"
    if tail in {("watch", "run"), ("watch", "run", "--yes")}:
        return "watch"
    return "unknown"


def _systemd_properties(run, unit: str, properties: tuple[str, ...]) -> dict[str, str] | None:
    """Read a fixed systemd property list without exposing command output."""
    try:
        result = run(
            ["systemctl", "show", "--property=" + ",".join(properties), "--", unit],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return None
    if getattr(result, "returncode", 1) != 0:
        return None
    output = _command_text(getattr(result, "stdout", ""))
    if len(output) > 32768:
        return None
    values: dict[str, str] = {}
    for line in output.splitlines():
        if len(line) > 8192 or "=" not in line:
            return None
        key, value = line.split("=", 1)
        if key not in properties or key in values or any(ord(char) < 32 for char in key):
            return None
        values[key] = value
    return values if set(values) == set(properties) else None


def _timestamp(value: str):
    """Parse systemd's display timestamp; return None for its explicit empty values."""
    text = value.strip()
    if text.casefold() in {"", "n/a", "never", "-", "0"}:
        return None
    match = SYSTEMD_TIME_PATTERN.fullmatch(text)
    if match is None:
        return False
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False


def _time_label(value, *, empty: str) -> str:
    parsed = _timestamp(value)
    if parsed is None:
        return empty
    if parsed is False:
        return "Unknown"
    return parsed.strftime("%Y-%m-%d %H:%M")


def _systemd_exec_argv(value: str) -> list[str] | None:
    """Extract one argv vector from systemd's fixed ExecStart display property."""
    if len(value) > 16384 or value.count("argv[]=") != 1:
        return None
    encoded = value.partition("argv[]=")[2]
    marker = " ; ignore_errors="
    if marker not in encoded:
        return None
    encoded = encoded.partition(marker)[0].strip()
    try:
        parts = shlex.split(encoded, posix=True)
    except ValueError:
        return None
    if not parts or len(parts) > 128 or any(len(part) > 4096 for part in parts):
        return None
    return parts


def _timer_run_command(value: str, config_path: str | Path | None = None):
    """Return the executable/config prefix and tail for an expected CVEBeacon run."""
    argv = _systemd_exec_argv(value)
    if (
        argv is None
        or len(argv) not in {4, 5, 6}
        or not Path(argv[0]).is_absolute()
        or Path(argv[0]).name.casefold() != "cvebeacon"
        or argv[1] != "--config"
        or not Path(argv[2]).is_absolute()
    ):
        return None
    configured = Path(argv[2])
    try:
        if config_path is not None and configured.resolve() != Path(config_path).resolve():
            return None
    except OSError:
        return None
    tail = argv[3:]
    if tail not in (
        ["run"], ["run", "--yes"],
        ["run", "--if-due"], ["run", "--yes", "--if-due"],
    ):
        return None
    return argv[0], argv[2], tail


def _timer_control_properties(run):
    timer = _systemd_properties(
        run, "cvebeacon.timer", ("OnCalendar", "Persistent")
    )
    service = _systemd_properties(run, "cvebeacon.service", ("ExecStart",))
    if timer is None or service is None:
        return None
    return timer, service


def _calendar_schedule(value: str) -> TimerSchedule | None:
    text = value.strip()
    daily = re.fullmatch(
        r"\*-\*-\*\s+((?:[01]\d|2[0-3])(?:,(?:[01]\d|2[0-3]))*):00:00",
        text,
    )
    if daily is not None:
        try:
            return build_timer_schedule(times=tuple(
                f"{hour}:00" for hour in daily.group(1).split(",")
            ))
        except SchedulingError:
            return None
    interval = re.fullmatch(
        r"\*-\*-\*\s+00/(\d{1,2}):00:00", text
    )
    if interval is not None:
        try:
            return build_timer_schedule(every_hours=parse_interval(int(interval.group(1))))
        except (ValueError, SchedulingError):
            return None
    return None


def _calendar_words(schedule: TimerSchedule | None) -> str:
    if schedule is None:
        return "A custom systemd calendar schedule"
    if schedule.every_hours is not None:
        return f"Every {schedule.every_hours} hours"
    return "Every day at " + " and ".join(schedule.times)


def _timer_control_state(
    timer: dict[str, str],
    service: dict[str, str],
    config_path: str | Path | None,
) -> dict[str, object]:
    schedule = _calendar_schedule(timer["OnCalendar"])
    argv = _timer_run_command(service["ExecStart"], config_path)
    persistent = timer["Persistent"].strip().casefold() in {"yes", "true", "1"}
    calendar = timer["OnCalendar"].strip()
    tick_active = calendar in {TIMER_CONTROL_TICK, "*-*-* *:0/15"}
    enabled = bool(
        persistent and tick_active and argv is not None
        and argv[2] in (["run", "--if-due"], ["run", "--yes", "--if-due"])
    )
    command = None
    base = _timer_run_command(service["ExecStart"], config_path)
    if base is not None and base[2] in (["run"], ["run", "--yes"]):
        command = shlex.join([
            "sudo", base[0], "--config", base[1],
            "schedule", "timer-control", "enable",
        ])
    return {
        "enabled": enabled,
        "calendar_words": _calendar_words(schedule),
        "timer_tick": "Every 15 minutes" if enabled else "15-minute tick when enabled",
        "schedule": schedule,
        "enable_command": command,
    }


def systemd_timer_control_status(
    timer_unit: str,
    service_unit: str,
    config_path: str | Path | None,
    *,
    run=subprocess.run,
) -> dict[str, object]:
    """Detect dashboard control from loaded systemd properties only."""
    unknown: dict[str, object] = {
        "enabled": None,
        "calendar_words": "The current timer schedule is unavailable",
        "timer_tick": "Unknown",
        "schedule": None,
        "enable_command": None,
    }
    if (
        timer_unit != "cvebeacon.timer"
        or service_unit != "cvebeacon.service"
    ):
        return unknown
    timer = _systemd_properties(run, timer_unit, ("OnCalendar", "Persistent"))
    service = _systemd_properties(run, service_unit, ("ExecStart",))
    if timer is None or service is None:
        return unknown
    return _timer_control_state(timer, service, config_path)


def _systemd_quote(value: str) -> str:
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SchedulingError("systemd command contains an unsupported path")
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("%", "%%")
        .replace("$", "$$")
    )
    return '"' + escaped + '"'


def _dropin_paths(root_directory: str | Path) -> tuple[Path, Path]:
    root = Path(root_directory).absolute()
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise SchedulingError("systemd root must be a real directory")
    except OSError as exc:
        raise SchedulingError("systemd root is unavailable") from exc
    base = root / "etc" / "systemd" / "system"
    return (
        base / "cvebeacon.timer.d" / TIMER_CONTROL_DROPIN,
        base / "cvebeacon.service.d" / TIMER_CONTROL_DROPIN,
    )


def _ensure_dropin_directory(directory: Path, root: Path) -> None:
    current = directory
    missing: list[Path] = []
    while current != root:
        try:
            details = current.lstat()
        except FileNotFoundError:
            missing.append(current)
            current = current.parent
            continue
        except OSError as exc:
            raise SchedulingError("systemd drop-in directory is unavailable") from exc
        if not stat.S_ISDIR(details.st_mode):
            raise SchedulingError("systemd drop-in path must contain only real directories")
        current = current.parent
    for item in reversed(missing):
        try:
            item.mkdir(mode=0o755)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SchedulingError("systemd drop-in directory could not be created") from exc
        if not stat.S_ISDIR(item.lstat().st_mode):
            raise SchedulingError("systemd drop-in path must contain only real directories")


def _atomic_root_dropin(path: Path, content: str) -> bool:
    directory = path.parent
    try:
        directory_details = directory.lstat()
    except OSError as exc:
        raise SchedulingError("systemd drop-in directory is unavailable") from exc
    if not stat.S_ISDIR(directory_details.st_mode):
        raise SchedulingError("systemd drop-in directory must be a real directory")
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    except OSError as exc:
        raise SchedulingError("systemd drop-in could not be inspected") from exc
    if current is not None:
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_uid != directory_details.st_uid
        ):
            raise SchedulingError("systemd drop-in must be a regular root-owned file")
        try:
            if path.read_text(encoding="utf-8") == content:
                return False
        except (OSError, UnicodeError) as exc:
            raise SchedulingError("systemd drop-in could not be read") from exc
    descriptor, name = tempfile.mkstemp(prefix=".dashboard-schedule.", dir=directory)
    temporary = Path(name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
            info = os.fstat(descriptor)
            if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise SchedulingError("systemd drop-in permissions could not be secured")
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        raise SchedulingError("systemd drop-in could not be written") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return True


def _remove_root_dropin(path: Path) -> bool:
    try:
        directory = path.parent
        directory_details = directory.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SchedulingError("systemd drop-in directory is unavailable") from exc
    if not stat.S_ISDIR(directory_details.st_mode):
        raise SchedulingError("systemd drop-in directory must be a real directory")
    try:
        current = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SchedulingError("systemd drop-in could not be inspected") from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or current.st_uid != directory_details.st_uid
    ):
        raise SchedulingError("systemd drop-in must be a regular root-owned file")
    try:
        path.unlink()
        if os.name == "posix":
            directory_fd = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        raise SchedulingError("systemd drop-in could not be removed") from exc
    return True


def _systemd_action(run, arguments: list[str]) -> None:
    try:
        result = run(
            ["systemctl", *arguments],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        raise SchedulingError("systemd timer action could not be completed") from exc
    if getattr(result, "returncode", 1) != 0:
        raise SchedulingError("systemd timer action failed; check systemd status")


def timer_control(
    action: str,
    *,
    data_directory: str | Path | None = None,
    config_path: str | Path | None = None,
    run=subprocess.run,
    root_directory: str | Path = "/",
    geteuid=None,
) -> str:
    """Manage the two fixed systemd drop-ins from a root-only CLI command."""
    if action not in {"enable", "disable", "status"}:
        raise SchedulingError("timer-control action must be enable, disable, or status")
    if platform.system().casefold() != "linux":
        raise SchedulingError("systemd timer control is supported only on Linux")
    resolve_uid = geteuid or getattr(os, "geteuid", lambda: -1)
    if resolve_uid() != 0:
        raise SchedulingError("schedule timer-control must run as root")

    root = Path(root_directory).absolute()
    timer_dropin, service_dropin = _dropin_paths(root)
    if action == "disable":
        timer_removed = _remove_root_dropin(timer_dropin)
        service_removed = _remove_root_dropin(service_dropin)
        if timer_removed or service_removed:
            _systemd_action(run, ["daemon-reload"])
            _systemd_action(run, ["restart", "cvebeacon.timer"])
            return "dashboard schedule control disabled"
        return "dashboard schedule control drop-ins are already absent"

    properties = _timer_control_properties(run)
    if properties is None:
        if action == "status":
            return "dashboard schedule control status unavailable"
        raise SchedulingError("could not read the CVEBeacon systemd timer and service")
    timer, service = properties
    detected = _timer_control_state(timer, service, config_path)
    if action == "status":
        if detected["enabled"] is True:
            return "dashboard schedule control enabled (15-minute timer tick)"
        if detected["enabled"] is None:
            return "dashboard schedule control status unavailable"
        return (
            "dashboard schedule control not enabled; current timer: "
            + str(detected["calendar_words"])
        )

    if data_directory is None or config_path is None:
        raise SchedulingError("timer-control enable requires the CVEBeacon config and data directory")
    base = _timer_run_command(service["ExecStart"], config_path)
    if base is None:
        raise SchedulingError(
            "refusing to change the timer: ExecStart is not the expected CVEBeacon run command"
        )
    tail = base[2]
    if tail in (["run", "--if-due"], ["run", "--yes", "--if-due"]):
        if detected["enabled"] is True:
            return "dashboard schedule control is already enabled"
    if detected["enabled"] is True:
        return "dashboard schedule control is already enabled"

    schedule_path, _ = _schedule_path(data_directory)
    try:
        schedule_path.lstat()
    except FileNotFoundError:
        initial = _calendar_schedule(timer["OnCalendar"])
        if initial is None:
            initial = build_timer_schedule(times=DEFAULT_TIMER_TIMES)
        save_timer_schedule(data_directory, initial, root_owner=True)
    else:
        # Validate existing data before installing a privileged unit override.
        load_timer_schedule(data_directory)

    _ensure_dropin_directory(timer_dropin.parent, root)
    _ensure_dropin_directory(service_dropin.parent, root)
    timer_content = (
        "[Timer]\n"
        "OnCalendar=\n"
        f"OnCalendar={TIMER_CONTROL_TICK}\n"
        "Persistent=true\n"
    )
    service_argv = [base[0], "--config", base[1], "run", "--if-due"]
    service_line = " ".join(_systemd_quote(part) for part in service_argv)
    service_content = f"[Service]\nExecStart=\nExecStart={service_line}\n"
    _atomic_root_dropin(timer_dropin, timer_content)
    _atomic_root_dropin(service_dropin, service_content)
    _systemd_action(run, ["daemon-reload"])
    _systemd_action(run, ["restart", "cvebeacon.timer"])
    return "dashboard schedule control enabled"


def _service_result(result: str, status: str) -> str:
    code_text = status.strip()
    if not re.fullmatch(r"\d{1,3}", code_text):
        return "Unknown"
    code = int(code_text)
    if code > 255:
        return "Unknown"
    state = result.strip().casefold()
    if state == "success":
        return "Succeeded" if code == 0 else "Unknown"
    if state == "exit-code":
        return "Failed" if code != 0 else "Unknown"
    return {
        "timeout": "Timed out",
        "watchdog": "Timed out",
        "signal": "Stopped",
        "core-dump": "Stopped",
        "oom-kill": "Stopped after running out of memory",
        "start-limit-hit": "Could not start",
        "resources": "Could not start",
        "protocol": "Could not start",
        "exec-condition": "Could not start",
        "exec-format": "Could not start",
    }.get(state, "Unknown")


def systemd_timer_status(
    timer_unit: str,
    service_unit: str,
    config_path: Path,
    *,
    run=subprocess.run,
) -> dict[str, str]:
    """Return plain labels for one updater-managed systemd timer and service.

    The caller supplies the units from a validated administrator policy. The
    names are checked again here before they reach the argument vector.
    """
    unknown = {
        "state": "Unknown", "boot": "Unknown", "next_run": "Unknown",
        "last_run": "Unknown", "last_result": "Unknown", "scan_state": "unknown",
    }
    if (
        not isinstance(timer_unit, str)
        or not SYSTEMD_UNIT_PATTERN.fullmatch(timer_unit)
        or not timer_unit.endswith(".timer")
        or timer_unit.startswith("cvebeacon-update")
        or not isinstance(service_unit, str)
        or not SYSTEMD_UNIT_PATTERN.fullmatch(service_unit)
        or not service_unit.endswith(".service")
        or service_unit.startswith("cvebeacon-update")
    ):
        return unknown

    timer = _systemd_properties(
        run,
        timer_unit,
        ("ActiveState", "UnitFileState", "NextElapseUSecRealtime", "LastTriggerUSec"),
    )
    service = _systemd_properties(
        run,
        service_unit,
        ("Result", "ExecMainStatus", "ExecMainExitTimestamp", "ExecStart"),
    )
    if timer is None:
        timer_labels = {"state": "Unknown", "boot": "Unknown", "next_run": "Unknown"}
        last_trigger = ""
    else:
        active = timer["ActiveState"].strip().casefold()
        timer_labels = {
            "state": "On" if active == "active" else "Off" if active in {"inactive", "failed"} else "Unknown",
            "boot": {
                "enabled": "Yes",
                "enabled-runtime": "This boot only",
                "disabled": "No",
                "masked": "No",
                "masked-runtime": "No",
                "static": "No",
                "indirect": "No",
                "generated": "No",
                "transient": "No",
                "linked": "No",
                "linked-runtime": "No",
                "alias": "No",
            }.get(timer["UnitFileState"].strip().casefold(), "Unknown"),
            "next_run": _time_label(timer["NextElapseUSecRealtime"], empty="Not scheduled"),
        }
        last_trigger = timer["LastTriggerUSec"]

    if service is None:
        return unknown
    argv = _systemd_exec_argv(service["ExecStart"])
    scan_state = _argv_scan_action(argv, config_path) if argv is not None else "unknown"
    if scan_state not in {"scan", "watch"}:
        return unknown

    service_last_run = _time_label(service["ExecMainExitTimestamp"], empty="Never")
    service_result = _service_result(service["Result"], service["ExecMainStatus"])

    if service_last_run == "Never":
        trigger_parsed = _timestamp(last_trigger)
        if trigger_parsed is None:
            last_run, last_result = "Never", "Never run"
        elif trigger_parsed is False:
            last_run, last_result = "Unknown", "Unknown"
        else:
            last_run, last_result = trigger_parsed.strftime("%Y-%m-%d %H:%M"), "Unknown"
    else:
        last_run, last_result = service_last_run, service_result
    return {
        **timer_labels,
        "last_run": last_run,
        "last_result": last_result,
        "scan_state": scan_state if scan_state in {"scan", "watch"} else "unknown",
    }

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
