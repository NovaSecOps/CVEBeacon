"""Native, narrowly owned schedule planning and management."""

from __future__ import annotations

import base64
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
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, time as datetime_time, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from uuid import uuid4
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
    """The dashboard-owned cadence and its admission history."""

    every_hours: int | None = None
    times: tuple[str, ...] = ()
    last_start: datetime | None = None
    eligible_since: datetime | None = None

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


@contextmanager
def _schedule_directory(data_directory):
    path = Path(data_directory).absolute()
    descriptor = None
    try:
        details = path.lstat()
        if not stat.S_ISDIR(details.st_mode):
            raise SchedulingError("schedule data directory must be a real directory")
        if os.name == "posix":
            descriptor = os.open(path, _DIRECTORY_FLAGS)
            details = os.fstat(descriptor)
        yield path, descriptor, details
    except OSError as exc:
        raise SchedulingError("schedule data directory or file is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_LEAF_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
_SCHEDULE_LIMIT = 16384
_HISTORY_SKEW = timedelta(minutes=5)


def _leaf_metadata(directory_fd, name, owner):
    details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_uid != owner:
        raise SchedulingError("schedule or systemd file must be a regular, singly linked, owner-controlled file")
    return details


def _read_leaf(directory_fd, name, owner, limit, *, private=False):
    try:
        original = _leaf_metadata(directory_fd, name, owner)
    except FileNotFoundError:
        return None
    with os.fdopen(os.open(name, _LEAF_FLAGS, dir_fd=directory_fd), "rb") as stream:
        details = os.fstat(stream.fileno())
        if (
            (details.st_dev, details.st_ino) != (original.st_dev, original.st_ino)
            or not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_uid != owner
            or (private and os.name == "posix" and stat.S_IMODE(details.st_mode) != 0o600)
        ):
            raise SchedulingError("schedule or systemd file has unsafe metadata")
        contents = stream.read(limit + 1)
    if len(contents) > limit:
        raise SchedulingError("schedule or systemd file is too large")
    return contents, stat.S_IMODE(details.st_mode)


def _stage_file(directory_fd, contents, mode):
    name = ".cvebeacon-schedule-" + uuid4().hex
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(name, flags, 0o600, dir_fd=directory_fd), "wb") as stream:
        try:
            stream.write(contents)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        except BaseException:
            os.unlink(name, dir_fd=directory_fd)
            raise
    return name


def _publish_file(directory_fd, name, temporary):
    if temporary is None:
        os.unlink(name, dir_fd=directory_fd)
    else:
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)


def _schedule_payload(schedule: TimerSchedule) -> bytes:
    validated = build_timer_schedule(
        schedule.every_hours, times=schedule.times or None, last_start=schedule.last_start,
    )
    if schedule.eligible_since is not None:
        _history_instant(schedule.eligible_since)
    payload = {
        "version": 1,
        "every_hours": validated.every_hours,
        "times": list(validated.times),
        "last_start": validated.last_start.isoformat() if validated.last_start is not None else None,
        "eligible_since": schedule.eligible_since.isoformat() if schedule.eligible_since is not None else None,
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _read_timer_schedule(directory) -> tuple[TimerSchedule, bool]:
    path, descriptor, details = directory
    entry = _read_leaf(
        descriptor, TIMER_SCHEDULE_FILENAME if descriptor is not None else path / TIMER_SCHEDULE_FILENAME,
        details.st_uid, _SCHEDULE_LIMIT, private=True,
    )
    if entry is None:
        return build_timer_schedule(times=DEFAULT_TIMER_TIMES), False
    try:
        payload = json.loads(entry[0].decode("utf-8"))
        required = {"version", "every_hours", "times", "last_start"}
        if (
            not isinstance(payload, dict)
            or set(payload) not in (required, required | {"eligible_since"})
            or type(payload["version"]) is not int
            or payload["version"] != 1
        ):
            raise ValueError
        times = payload["times"]
        interval = payload["every_hours"]
        if (not isinstance(times, list) or any(not isinstance(item, str) for item in times)
                or (interval is not None and times)):
            raise ValueError
        start = payload["last_start"]
        baseline = payload.get("eligible_since")
        schedule = build_timer_schedule(
            interval, times=times if interval is None else None,
            last_start=datetime.fromisoformat(start) if start is not None else None,
        )
        if baseline is not None:
            baseline = datetime.fromisoformat(baseline)
            _history_instant(baseline)
        return replace(schedule, eligible_since=baseline), True
    except (TypeError, ValueError, RecursionError) as exc:
        raise SchedulingError("schedule data file is invalid") from exc


def load_timer_schedule(data_directory: str | Path) -> TimerSchedule:
    """Read private schedule data, or return the shipped timer defaults."""
    with _schedule_directory(data_directory) as directory:
        schedule, _ = _read_timer_schedule(directory)
    return schedule


def _write_timer_schedule(directory, schedule):
    path, descriptor, details = directory
    contents = _schedule_payload(schedule)
    if descriptor is not None:
        if details.st_uid != os.geteuid():
            raise SchedulingError("schedule data directory must be owned by the CVEBeacon account")
        temporary = _stage_file(descriptor, contents, 0o600)
        try:
            _publish_file(descriptor, TIMER_SCHEDULE_FILENAME, temporary)
        finally:
            try:
                os.unlink(temporary, dir_fd=descriptor)
            except FileNotFoundError:
                pass
    else:
        with tempfile.NamedTemporaryFile(prefix=".schedule.", dir=path, delete=False) as stream:
            temporary = Path(stream.name)
            try:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
                os.replace(temporary, path / TIMER_SCHEDULE_FILENAME)
            finally:
                stream.close()
                temporary.unlink(missing_ok=True)


@contextmanager
def _schedule_lock(directory):
    path, descriptor, _ = directory
    if descriptor is not None:
        import fcntl

        # The directory inode remains stable when schedule.json is replaced.
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    else:
        from .locking import RunLock

        with RunLock(path / "schedule.lock"):
            yield


def save_timer_schedule(data_directory: str | Path, schedule: TimerSchedule) -> Path:
    """Atomically write owner-only schedule data beside monitoring state."""
    with _schedule_directory(data_directory) as directory, _schedule_lock(directory):
        _read_timer_schedule(directory)
        _write_timer_schedule(directory, schedule)
    return directory[0] / TIMER_SCHEDULE_FILENAME


def change_timer_schedule(data_directory: str | Path, schedule: TimerSchedule) -> None:
    """Update the cadence without overwriting a concurrently admitted start."""
    with _schedule_directory(data_directory) as directory, _schedule_lock(directory):
        previous, _ = _read_timer_schedule(directory)
        baseline = previous.eligible_since if previous.times == schedule.times else None
        if schedule.every_hours is None and baseline is None:
            baseline = _start_of_local_day(local_now())
        _write_timer_schedule(directory, replace(
            schedule, last_start=previous.last_start, eligible_since=baseline,
        ))


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


def _slot_instant(wall: datetime, zone) -> datetime:
    """Choose the first occurrence of a wall time, or the first instant after a gap."""
    guesses = sorted(
        wall.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc) for fold in (0, 1)
    )
    for instant in guesses:
        if instant.astimezone(zone).replace(tzinfo=None) == wall:
            return instant

    # The two UTC interpretations straddle the offset change in a gap.
    lower, upper = guesses
    second = timedelta(seconds=1)
    while upper - lower > second:
        midpoint = lower + ((upper - lower) // second // 2) * second
        if midpoint.astimezone(zone).replace(tzinfo=None) < wall:
            lower = midpoint
        else:
            upper = midpoint
    return upper


def _start_of_local_day(now):
    return _slot_instant(datetime.combine(now.date(), datetime_time.min), now.tzinfo)


def _schedule_window(schedule: TimerSchedule, now: datetime) -> datetime:
    current = _history_instant(now)
    start = _history_instant(schedule.last_start) if schedule.last_start is not None else None
    baseline = _history_instant(schedule.eligible_since) if schedule.eligible_since is not None else None
    if any(value is not None and value - current > _HISTORY_SKEW for value in (start, baseline)):
        raise SchedulingError("schedule history is too far in the future")
    if schedule.every_hours is not None:
        return current if start is None else start + timedelta(hours=schedule.every_hours)
    day = now.date()
    if baseline is None and start is None:
        baseline = _start_of_local_day(now)
    candidates = (
        _slot_instant(datetime.combine(day + timedelta(days=offset), datetime_time.fromisoformat(text)), now.tzinfo)
        # A slightly future start may already fall after tomorrow's first slot.
        for offset in range(-1, 3)
        for text in schedule.times
    )
    available = [
        slot for slot in candidates
        if (start is None or slot > start) and (baseline is None or slot >= baseline)
    ]
    if not available:
        raise SchedulingError("could not compute the next scheduled run")
    return min(available)


def schedule_due(schedule: TimerSchedule, now: datetime) -> bool:
    """Return whether one scheduled window has elapsed since the last start."""
    now = _aware_now(now)
    return _schedule_window(schedule, now) <= _history_instant(now)


def schedule_next_run(schedule: TimerSchedule, now: datetime | None = None) -> datetime:
    """Estimate the first future quarter-hour check that can admit a run."""
    now = _aware_now(now)
    current = _history_instant(now)
    earliest = _schedule_window(schedule, now)
    # Walk the actual UTC timeline, including both occurrences of a repeated
    # local quarter hour. An eligible fixed slot itself can occur only once.
    instant = max(current + timedelta(microseconds=1), earliest)
    if instant.microsecond:
        instant = instant.replace(microsecond=0) + timedelta(seconds=1)
    while True:
        local = instant.astimezone(now.tzinfo)
        if local.second == 0 and local.minute % 15 == 0:
            return local
        instant += timedelta(seconds=60 - local.second)


def should_run_scheduled(data_directory: str | Path, now: datetime | None = None) -> bool:
    """Read the saved schedule and persist the start before a due run begins."""
    current = _aware_now(now)
    with _schedule_directory(data_directory) as directory, _schedule_lock(directory):
        schedule, exists = _read_timer_schedule(directory)
        baseline = schedule.eligible_since
        if schedule.every_hours is None and schedule.last_start is None and baseline is None:
            baseline = _start_of_local_day(current)
        due = schedule_due(schedule, current)
        if due or not exists or baseline != schedule.eligible_since:
            _write_timer_schedule(directory, replace(
                schedule, eligible_since=baseline, last_start=current if due else schedule.last_start,
            ))
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


_SYSTEMD_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
_TIMER_UNIT = "cvebeacon.timer"
_SERVICE_UNIT = "cvebeacon.service"
_TIMER_PROPERTIES = (
    "LoadState", "Unit", "Triggers", "TimersCalendar", "TimersMonotonic",
    "Persistent", "OnClockChange", "OnTimezoneChange",
)
_CALENDAR_ENTRY = re.compile(r"\{ OnCalendar=([^{}]+?) ; next_elapse=[^{}]* \}")
_TICK_NORMALIZED = "*-*-* *:00/15:00"


def _systemd_call(run, args, *, timeout=2):
    try:
        result = run(
            args, env=_SYSTEMD_ENV.copy(), cwd="/", capture_output=True,
            check=False, stdin=subprocess.DEVNULL, encoding="utf-8", timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return None
    if getattr(result, "returncode", 1) != 0:
        return None
    output = _command_text(getattr(result, "stdout", ""))
    return output if len(output) <= 32768 else None


def _systemd_properties(run, unit: str, properties: tuple[str, ...]) -> dict[str, str] | None:
    """Read systemctl's display properties. Array entries can repeat the key."""
    output = _systemd_call(run, ["systemctl", "show", "--property=" + ",".join(properties), "--", unit])
    if output is None:
        return None
    arrays = {"TimersCalendar", "TimersMonotonic"} & set(properties)
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if len(line) > 8192 or not separator or key not in properties:
            return None
        if key in values:
            if key not in arrays:
                return None
            values[key] += " " + value
        else:
            values[key] = value
    for key in arrays:
        # systemctl emits no line for an empty array.
        values.setdefault(key, "")
    return values if set(values) == set(properties) else None


def _systemd_exec_start(run, unit):
    """Read the typed system manager property without lossy argv display formatting."""
    manager = "org.freedesktop.systemd1"
    label = "".join(chr(byte) if chr(byte).isascii() and chr(byte).isalnum() else f"_{byte:02x}"
                    for byte in unit.encode("utf-8"))
    output = _systemd_call(run, [
        "busctl", "--system", "--json=short", "get-property", manager,
        f"/org/freedesktop/systemd1/unit/{label}", f"{manager}.Service", "ExecStartEx",
    ])
    if output is None:
        return None
    try:
        payload = json.loads(output)
        if payload["type"] != "a(sasasttttuii)" or len(payload["data"]) != 1:
            return None
        path, argv, flags, *status = payload["data"][0]
        if (
            not _systemd_token(path) or not isinstance(argv, list) or not 4 <= len(argv) <= 6
            or not all(_systemd_token(token) for token in argv) or argv[0] != path
            or flags not in ([], ["no-env-expand"])
            or len(status) != 7 or any(type(field) is not int for field in status)
        ):
            return None
        return argv, bool(flags)
    except (KeyError, TypeError, ValueError, RecursionError):
        return None


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


def _systemd_token(value):
    return (
        isinstance(value, str) and 0 < len(value) <= 4096
        and not any(
            code < 32 or 0x7f <= code <= 0x9f or 0xd800 <= code <= 0xdfff
            for code in map(ord, value)
        )
    )


def _systemd_path(path):
    if not _systemd_token(path):
        return None
    candidate = PurePosixPath(path)
    if candidate.anchor != "/" or str(candidate) != path or ".." in candidate.parts:
        return None
    return candidate


def _native_posix_path(path):
    # Interpret systemd paths in the manager's POSIX namespace, including when
    # local tests supply a native Windows temporary directory.
    native = path if isinstance(path, PureWindowsPath) else Path(path).absolute()
    return PurePosixPath("/", *native.parts[1:])


def _timer_command(command, config_path=None):
    if command is None:
        return None
    argv, no_expansion = command
    executable = _systemd_path(argv[0])
    config_arg = argv[2]
    if not no_expansion:
        if "${" in config_arg.replace("$$", ""):
            return None
        config_arg = config_arg.replace("$$", "$")
    config = _systemd_path(config_arg)
    if (
        executable is None or executable.name != "cvebeacon" or argv[1] != "--config"
        or config is None
        or (config_path is not None and config != _native_posix_path(config_path))
    ):
        return None
    return [argv[0], argv[1], config_arg, *argv[3:]]


def _timer_run_command(command, config_path=None):
    argv = _timer_command(command, config_path)
    if not argv or argv[3] != "run":
        return None
    options = argv[4:]
    if len(set(options)) != len(options) or set(options) - {"--yes", "--if-due"}:
        return None
    return argv


def _trusted_executable(executable, root=Path("/")):
    """Allow the updater's root-owned current link and preserve its lexical path."""
    path = root.joinpath(*PurePosixPath(executable).parts[1:])
    owner = 0 if root == Path("/") else os.geteuid()

    def protected(directory):
        for parent in (directory, *directory.parents):
            details = parent.lstat()
            if not stat.S_ISDIR(details.st_mode) or details.st_uid != owner or details.st_mode & 0o022:
                return False
            if parent == root:
                return True
        return False

    try:
        # The installed entry point may traverse the versioned layout's
        # administrator-controlled current link. No other symlink is needed.
        for link in reversed(path.parents):
            if link == root or root not in link.parents:
                continue
            if link.name == "current" and link.is_symlink():
                if not protected(link.parent) or link.lstat().st_uid != owner:
                    return False
                target = link.readlink()
                if not target.is_absolute():
                    target = link.parent / target
                if target.parent != link.parent / "releases" or not protected(target):
                    return False
                path = target / path.relative_to(link)
                break
        details = path.lstat()
        return (
            protected(path.parent) and stat.S_ISREG(details.st_mode) and details.st_uid == owner
            and bool(details.st_mode & 0o111) and not details.st_mode & 0o022
        )
    except (OSError, RuntimeError):
        return False


def _calendar_entries(value: str) -> tuple[str, ...] | None:
    entries = []
    cursor = 0
    for match in _CALENDAR_ENTRY.finditer(value):
        if value[cursor:match.start()].strip():
            return None
        entries.append(match[1])
        cursor = match.end()
    if value[cursor:].strip():
        return None
    return tuple(entries)


def _calendar_schedule(specs: tuple[str, ...] | str) -> TimerSchedule | None:
    if isinstance(specs, str):
        specs = (specs,)
    times = []
    for spec in specs:
        # The manager normalizes midnight-based hour stepping to 00/N.
        step = re.fullmatch(r"\*-\*-\* 00/([0-9]{1,2}):00:00", spec)
        if step:
            hours = int(step[1])
            if not 2 <= hours <= 24:
                return None
            if len(specs) == 1 and 24 % hours == 0:
                return build_timer_schedule(every_hours=hours)
            times.extend(f"{hour:02d}:00" for hour in range(0, 24, hours))
            continue
        daily = re.fullmatch(r"\*-\*-\* ([0-9,]+):([0-9,]+):00", spec)
        if not daily:
            return None
        times.extend(f"{hour}:{minute}" for hour in daily[1].split(",") for minute in daily[2].split(","))
    try:
        return build_timer_schedule(times=list(dict.fromkeys(times)))
    except SchedulingError:
        return None


def _calendar_words(schedule: TimerSchedule | None) -> str:
    if schedule is None:
        return "A custom systemd timer schedule"
    if schedule.every_hours is not None:
        return f"Every {schedule.every_hours} hours"
    return "Every day at " + " and ".join(schedule.times)


def _timer_has_extra_triggers(timer):
    return bool(
        timer["TimersMonotonic"] or timer["OnClockChange"] != "no" or timer["OnTimezoneChange"] != "no"
    )


def _timer_control_state(timer, command, config_path=None, *, data_directory=None, root=Path("/")):
    calendar = _calendar_entries(timer["TimersCalendar"])
    argv = _timer_run_command(command, config_path)
    matches = bool(
        timer["LoadState"] == "loaded" and timer["Unit"] == _SERVICE_UNIT
        and timer["Triggers"] == _SERVICE_UNIT and argv
    )
    schedule = _calendar_schedule(calendar) if calendar and not _timer_has_extra_triggers(timer) else None
    enabled = bool(
        matches and not _timer_has_extra_triggers(timer)
        and calendar == (_TICK_NORMALIZED,) and timer["Persistent"] == "yes"
        and "--if-due" in argv
    )
    enable_command = None
    if (
        matches and calendar is not None and not enabled
        and timer["OnClockChange"] == timer["OnTimezoneChange"] == "no"
        and _trusted_executable(argv[0], root)
    ):
        options = ["--data-dir", str(_native_posix_path(data_directory))] if data_directory is not None else []
        enable_command = shlex.join([
            "sudo", argv[0], "--config", argv[2], "schedule", "timer-control", "enable", *options,
        ])
    return {
        "enabled": enabled,
        "matches": matches,
        "calendar_words": _calendar_words(schedule),
        "timer_tick": "Every 15 minutes" if enabled else "15-minute tick when enabled",
        "enable_command": enable_command,
    }


def systemd_timer_control_status(
    timer_unit: str,
    service_unit: str,
    config_path: str | Path | None,
    *,
    run=subprocess.run,
    data_directory: str | Path | None = None,
) -> dict[str, object]:
    """Detect dashboard control from the loaded reference timer and service."""
    if (timer_unit, service_unit) == (_TIMER_UNIT, _SERVICE_UNIT):
        timer = _systemd_properties(run, timer_unit, _TIMER_PROPERTIES)
        if timer is not None:
            return _timer_control_state(
                timer, _systemd_exec_start(run, service_unit), config_path, data_directory=data_directory,
            )
    return {
        "enabled": None, "matches": False,
        "calendar_words": "The current timer schedule is unavailable",
        "timer_tick": "Unknown", "enable_command": None,
    }


def _systemd_quote(value: str) -> str:
    if not _systemd_token(value):
        raise SchedulingError("systemd command contains an unsupported path")
    # The generated command uses the ':' prefix to disable dollar expansion.
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


_UPDATE_POLICY = Path("/etc/cvebeacon/update.toml")
_SWITCH_RECOVERY_MARKER = b"# CVEBEACON-SCHEDULE-RECOVERY-1 "
_SWITCH_RECOVERY_LIMIT = 4 * _SCHEDULE_LIMIT
_DROPIN_DIRECTORIES = (_TIMER_UNIT + ".d", _SERVICE_UNIT + ".d")
_MANAGER_STATE = ("LoadState", "NeedDaemonReload", "DropInPaths")


def _open_admin_directory(stack, path, *, boundary=Path("/"), owner=0):
    descriptor = os.open(boundary, _DIRECTORY_FLAGS)
    stack.callback(os.close, descriptor)
    _check_admin_directory(descriptor, owner)
    for component in path.relative_to(boundary).parts:
        if component == "..":
            raise SchedulingError("administrator directory paths must be normalized")
        descriptor = _open_admin_child(stack, descriptor, component, owner)
    return descriptor


def _check_admin_directory(descriptor, owner):
    details = os.fstat(descriptor)
    if details.st_uid != owner or details.st_mode & 0o022:
        raise SchedulingError("systemd paths must use administrator-owned, non-writable directories")


def _open_admin_child(stack, parent, name, owner, *, create=False):
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(name, 0o755, dir_fd=parent)
        os.fsync(parent)
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    stack.callback(os.close, descriptor)
    _check_admin_directory(descriptor, owner)
    return descriptor


def _systemd_action(run, *arguments):
    if _systemd_call(run, ["systemctl", *arguments], timeout=30) is None:
        raise SchedulingError("systemd timer action failed; check systemd status")


def _switch_manager_state(run):
    timer = _systemd_properties(run, _TIMER_UNIT, (*_TIMER_PROPERTIES, *_MANAGER_STATE[1:], "ActiveState"))
    service = _systemd_properties(run, _SERVICE_UNIT, _MANAGER_STATE)
    if timer is None or service is None:
        raise SchedulingError("could not read the CVEBeacon systemd timer and service")
    if timer["LoadState"] != "loaded" or service["LoadState"] != "loaded":
        raise SchedulingError("the CVEBeacon systemd timer and service must be loaded")
    if timer["ActiveState"] not in {"active", "inactive", "failed"}:
        raise SchedulingError("wait for the CVEBeacon timer state to settle and retry")
    return timer, service


def _manager_dropins(properties):
    return tuple(
        str(Path("/etc/systemd/system") / directory / TIMER_CONTROL_DROPIN) in unit["DropInPaths"].split()
        for directory, unit in zip(_DROPIN_DIRECTORIES, properties, strict=True)
    )


def _verify_manager(run, *, dropins, active, argv=None):
    timer, service = _switch_manager_state(run)
    if (
        _manager_dropins((timer, service)) != dropins
        or (timer["ActiveState"] == "active") != active
        or any(unit["NeedDaemonReload"] != "no" for unit in (timer, service))
    ):
        raise SchedulingError("the loaded timer, service or timer activity did not match the requested state")
    if argv is not None:
        command = _systemd_exec_start(run, _SERVICE_UNIT)
        if command != (argv, True) or not _timer_control_state(timer, command)["enabled"]:
            raise SchedulingError("systemd did not load the expected timer and monitoring command")


def _apply_dropin_files(descriptors, entries, owner):
    existing = [_read_leaf(fd, TIMER_CONTROL_DROPIN, owner, _SWITCH_RECOVERY_LIMIT) for fd in descriptors]
    staged = []
    try:
        for descriptor, entry in zip(descriptors, entries, strict=True):
            staged.append(_stage_file(descriptor, *entry) if entry is not None else None)
        for descriptor, previous, temporary in zip(descriptors, existing, staged, strict=True):
            if temporary is not None or previous is not None:
                _publish_file(descriptor, TIMER_CONTROL_DROPIN, temporary)
    finally:
        for descriptor, temporary in zip(descriptors, staged):
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=descriptor)
                except FileNotFoundError:
                    pass


def _switch_recovery_marker(files, active):
    record = {
        "version": 1,
        "active": active,
        "files": [
            None if entry is None else (base64.b64encode(entry[0]).decode("ascii"), entry[1])
            for entry in files
        ],
    }
    return _SWITCH_RECOVERY_MARKER + json.dumps(
        record, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"


def _read_switch_recovery(timer_directory, owner):
    saved = _read_leaf(
        timer_directory, TIMER_CONTROL_DROPIN, owner, _SWITCH_RECOVERY_LIMIT
    )
    if saved is None:
        return None
    lines = saved[0].splitlines(keepends=True)
    marked = [line for line in lines if line.startswith(_SWITCH_RECOVERY_MARKER)]
    if not marked:
        return None
    if len(marked) != 1 or lines[-1] != marked[0] or not marked[0].endswith(b"\n"):
        raise SchedulingError("the timer switch recovery record is invalid")
    try:
        record = json.loads(marked[0][len(_SWITCH_RECOVERY_MARKER):-1])
        if record["version"] != 1 or type(record["active"]) is not bool or len(record["files"]) != 2:
            raise ValueError
        files = []
        for entry in record["files"]:
            if entry is None:
                files.append(None)
                continue
            encoded, mode = entry
            content = base64.b64decode(encoded, validate=True)
            if type(mode) is not int or not 0 <= mode <= 0o7777 or len(content) > _SCHEDULE_LIMIT:
                raise ValueError
            files.append((content, mode))
        return files, record["active"]
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise SchedulingError("the timer switch recovery record is invalid") from exc


def _with_switch_recovery(contents, marker):
    current = contents or b""
    if current and not current.endswith(b"\n"):
        current += b"\n"
    return current + marker


def _publish_timer_dropin(directory, contents, mode=0o600):
    temporary = _stage_file(directory, contents, mode)
    try:
        _publish_file(directory, TIMER_CONTROL_DROPIN, temporary)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def _clear_switch_recovery(descriptor, timer_file):
    if timer_file is None:
        _publish_file(descriptor, TIMER_CONTROL_DROPIN, None)
    else:
        _publish_timer_dropin(descriptor, timer_file[0], timer_file[1])


def _restore_timer_switch(run, descriptors, owner, recovery, marker):
    files, active = recovery
    _systemd_action(run, "stop", _TIMER_UNIT)
    timer_file = files[0]
    timer_content = timer_file[0] if timer_file is not None else b""
    timer_with_marker = (_with_switch_recovery(timer_content, marker), 0o600)
    _apply_dropin_files(descriptors, [timer_with_marker, files[1]], owner)
    _systemd_action(run, "daemon-reload")
    if active:
        _systemd_action(run, "restart", _TIMER_UNIT)
    _verify_manager(run, dropins=(True, files[1] is not None), active=active)
    _clear_switch_recovery(descriptors[0], timer_file)
    _systemd_action(run, "daemon-reload")
    if active:
        _systemd_action(run, "restart", _TIMER_UNIT)
    _verify_manager(run, dropins=tuple(entry is not None for entry in files), active=active)


def _open_existing_update_lock(stack, path, *, expected_owner=0):
    """Lock a verified updater inode without creating or changing its contents."""
    import errno

    path = Path(path)
    try:
        original = path.lstat()
    except FileNotFoundError as exc:
        raise SchedulingError("the updater lock file is missing; refusing to change the timer") from exc
    except OSError as exc:
        raise SchedulingError("the updater lock file cannot be verified; refusing to change the timer") from exc
    if (
        not stat.S_ISREG(original.st_mode)
        or original.st_nlink != 1
        or original.st_uid != expected_owner
        or original.st_mode & 0o022
        or getattr(original, "st_file_attributes", 0) & 0x400
    ):
        raise SchedulingError("the updater lock file cannot be verified; refusing to change the timer")
    descriptor = None
    try:
        descriptor = os.open(path, _LEAF_FLAGS)
        current = os.fstat(descriptor)
        if (
            (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_uid != expected_owner
            or current.st_mode & 0o022
        ):
            raise SchedulingError("the updater lock file changed during verification; refusing to change the timer")
        import fcntl

        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if isinstance(exc, BlockingIOError) or exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                raise SchedulingError("an updater is running; wait for it to finish before changing the timer") from exc
            raise SchedulingError("the updater lock file could not be locked safely") from exc
        stack.callback(os.close, descriptor)
    except SchedulingError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(exc, FileNotFoundError):
            raise SchedulingError("the updater lock file is missing; refusing to change the timer") from exc
        raise SchedulingError("the updater lock file could not be verified or locked safely") from exc


def _switch_update_lock(stack, policy_path, root, run):
    """Take the same installation lock as the updater before touching systemd."""
    import tomllib

    from .update_transaction import installation_prefix, read_record
    from .updater import protected, read_bounded

    policy_present = policy_path is not None and os.path.lexists(policy_path)
    prefixes = set()
    if policy_present:
        protected(policy_path)
        raw_prefix = tomllib.loads(read_bounded(policy_path, _SCHEDULE_LIMIT).decode("utf-8")).get("prefix")
        if _systemd_path(raw_prefix) is None:
            raise SchedulingError("the administrator update policy has an invalid installation prefix")
        prefixes.add(Path(raw_prefix))
    elif root == Path("/"):
        # Disable needs no policy or runtime config. Match the updater lock
        # from the running installation and the loaded service installation.
        candidates = {installation_prefix()}
        command = _systemd_exec_start(run, _SERVICE_UNIT)
        if command and _systemd_path(command[0][0]) and _trusted_executable(command[0][0]):
            candidates.add(installation_prefix(Path(command[0][0]).parent.parent))
        prefixes.update(
            prefix for prefix in candidates if prefix is not None
            and ((prefix / "current").is_symlink() or (prefix / "update.lock").exists())
        )
    for prefix in sorted(prefixes):
        protected(prefix, directory=True)
        _open_existing_update_lock(stack, prefix / "update.lock", expected_owner=0)
        record = read_record(prefix)
        if record is not None and record["phase"] != "complete":
            raise SchedulingError("finish updater recovery before changing the timer")
    return policy_present


def _service_account(user):
    import pwd

    try:
        account = pwd.getpwuid(int(user)) if user.isascii() and user.isdecimal() else pwd.getpwnam(user)
    except (KeyError, ValueError, OverflowError) as exc:
        raise SchedulingError("the loaded CVEBeacon service must use an existing unprivileged account") from exc
    if account.pw_uid == 0:
        raise SchedulingError("the loaded CVEBeacon service must run as an unprivileged account")
    return account


def _initialize_schedule_as_service(directory, config_path, initial):
    from .config import load_config

    expected = directory[0]
    config = load_config(config_path)
    if config.database_path.parent != expected or not os.path.samestat(expected.stat(), directory[2]):
        raise SchedulingError("the configured state database must be directly in the administrator-approved data directory")
    with _schedule_lock(directory):
        saved, exists = _read_timer_schedule(directory)
        if exists:
            _schedule_window(saved, local_now())
        else:
            if initial.every_hours is None:
                initial = replace(initial, eligible_since=_start_of_local_day(local_now()))
            _write_timer_schedule(directory, initial)


def _initialize_timer_data(data, config_path, account, initial):
    """Keep the approved directory open and parse the runtime file after dropping privileges."""
    import signal

    with ExitStack() as stack:
        parent = _open_admin_directory(stack, data.parent)
        descriptor = os.open(data.name, _DIRECTORY_FLAGS, dir_fd=parent)
        stack.callback(os.close, descriptor)
        details = os.fstat(descriptor)
        if details.st_uid != account.pw_uid or details.st_mode & 0o022 or details.st_mode & 0o700 != 0o700:
            raise SchedulingError("the approved data directory must be writable only by the CVEBeacon account")
        pid = os.fork()
        if pid == 0:
            exit_code = 1
            try:
                signal.signal(signal.SIGALRM, signal.SIG_DFL)
                signal.alarm(10)
                os.setgroups([])
                os.setgid(account.pw_gid)
                os.setuid(account.pw_uid)
                _initialize_schedule_as_service((data, descriptor, details), config_path, initial)
                exit_code = 0
            finally:
                os._exit(exit_code)
        _, status = os.waitpid(pid, 0)
        if status != 0:
            raise SchedulingError(
                "could not initialize schedule as the service account; check the runtime config, "
                "state database parent and schedule data"
            )


def _timer_data_authority(run, policy_path, policy_present, requested_data, config_path):
    from .updater import Policy

    service = _systemd_properties(run, _SERVICE_UNIT, ("User", "DynamicUser"))
    if service is None or service["DynamicUser"] != "no":
        raise SchedulingError("the CVEBeacon service requires a fixed unprivileged account")
    account = _service_account(service["User"])
    if policy_present:
        try:
            policy = Policy.read(policy_path)
        except KeyError as exc:
            raise SchedulingError("the administrator update policy requires an existing service account") from exc
        if config_path != policy.config or account.pw_uid != _service_account(policy.user).pw_uid:
            raise SchedulingError("the loaded service account and config must match the administrator update policy")
        if requested_data is not None and Path(requested_data) != policy.data:
            raise SchedulingError("--data-dir must match the administrator update policy")
        requested_data = policy.data
    if requested_data is None or _systemd_path(str(requested_data)) is None or str(requested_data) == "/":
        raise SchedulingError("enable requires an administrator update policy or an explicit absolute --data-dir")
    return Path(requested_data), account


def _timer_switch_action(action, run, root, config_path, data_directory, policy_path):
    import fcntl

    base_path = root / "etc/systemd/system"
    owner = 0 if root == Path("/") else os.geteuid()
    with ExitStack() as stack:
        base = _open_admin_directory(stack, base_path, boundary=root, owner=owner)
        fcntl.flock(base, fcntl.LOCK_EX)
        policy_present = _switch_update_lock(stack, policy_path if action == "enable" else None, root, run)
        descriptors = []
        for name in _DROPIN_DIRECTORIES:
            try:
                descriptor = _open_admin_child(stack, base, name, owner)
            except FileNotFoundError:
                descriptor = None
            descriptors.append(descriptor)
        recovery = (
            _read_switch_recovery(descriptors[0], owner)
            if descriptors[0] is not None else None
        )
        if recovery is not None:
            if None in descriptors:
                raise SchedulingError("timer switch recovery requires both verified drop-in directories")
            marker = _switch_recovery_marker(*recovery)
            _restore_timer_switch(run, descriptors, owner, recovery, marker)
        before = [
            _read_leaf(fd, TIMER_CONTROL_DROPIN, owner, _SCHEDULE_LIMIT) if fd is not None else None
            for fd in descriptors
        ]
        properties = _switch_manager_state(run)
        timer, service = properties
        active = timer["ActiveState"] == "active"
        desired = [None, None]
        argv = None
        if action == "disable":
            if not any(before) and not any(_manager_dropins(properties)) and all(
                unit["NeedDaemonReload"] == "no" for unit in properties
            ):
                return "dashboard schedule control drop-ins are already absent"
        else:
            command = _systemd_exec_start(run, _SERVICE_UNIT)
            argv = _timer_run_command(command, config_path)
            if not argv or not _trusted_executable(argv[0], root):
                raise SchedulingError(
                    "refusing to change the timer: ExecStart is not the expected CVEBeacon run command in a trusted installation"
                )
            calendar = _calendar_entries(timer["TimersCalendar"])
            if (
                timer["Unit"] != _SERVICE_UNIT or timer["Triggers"] != _SERVICE_UNIT or calendar is None
                or timer["OnClockChange"] != "no" or timer["OnTimezoneChange"] != "no"
            ):
                raise SchedulingError("refusing to change a timer with unexpected targets or clock triggers")
            if "--if-due" not in argv:
                argv = [*argv, "--if-due"]
            timer_content = f"[Timer]\nOnCalendar=\nOnCalendar={TIMER_CONTROL_TICK}\nPersistent=true\n"
            service_line = ":" + " ".join(_systemd_quote(token) for token in argv)
            service_content = f"[Service]\nExecStart=\nExecStart={service_line}\n"
            desired = [(content.encode("utf-8"), 0o600) for content in (timer_content, service_content)]
            configured = _timer_control_state(timer, command)["enabled"]
            clean = all(unit["NeedDaemonReload"] == "no" for unit in properties)
            if configured and clean and active and (before == desired or not any(before)):
                if _manager_dropins(properties) == tuple(entry is not None for entry in before):
                    return "dashboard schedule control is already enabled"
            data, account = _timer_data_authority(run, policy_path, policy_present, data_directory, Path(argv[2]))
            initial = _calendar_schedule(calendar) if not _timer_has_extra_triggers(timer) else None
            _initialize_timer_data(data, Path(argv[2]), account, initial or build_timer_schedule(times=DEFAULT_TIMER_TIMES))

        # Create both destinations before writing recovery metadata into the
        # timer drop-in.
        for index, (name, descriptor) in enumerate(zip(_DROPIN_DIRECTORIES, descriptors, strict=True)):
            if descriptor is None:
                descriptors[index] = _open_admin_child(stack, base, name, owner, create=True)
        recovery = (before, active)
        marker = _switch_recovery_marker(before, active)
        try:
            old_timer = before[0][0] if before[0] is not None else None
            _publish_timer_dropin(
                descriptors[0], _with_switch_recovery(old_timer, marker)
            )
            if active:
                _systemd_action(run, "stop", _TIMER_UNIT)
            timer_content = desired[0][0] if desired[0] is not None else None
            timer_pending = (
                _with_switch_recovery(timer_content, marker), 0o600
            )
            _apply_dropin_files(descriptors, [timer_pending, desired[1]], owner)
            _systemd_action(run, "daemon-reload")
            if active or action == "enable":
                _systemd_action(run, "restart", _TIMER_UNIT)
            _verify_manager(
                run, dropins=(True, action == "enable"),
                active=active or action == "enable", argv=argv,
            )
            _clear_switch_recovery(descriptors[0], desired[0])
            _systemd_action(run, "daemon-reload")
            if active or action == "enable":
                _systemd_action(run, "restart", _TIMER_UNIT)
            _verify_manager(
                run, dropins=(action == "enable",) * 2,
                active=active or action == "enable", argv=argv,
            )
        except BaseException:
            try:
                _restore_timer_switch(run, descriptors, owner, recovery, marker)
            except (OSError, SchedulingError) as exc:
                raise SchedulingError("timer switch rollback is pending; retry timer-control to recover") from exc
            raise
        return f"dashboard schedule control {action}d"


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
    if action == "status":
        detected = systemd_timer_control_status(_TIMER_UNIT, _SERVICE_UNIT, None, run=run)
        if detected["enabled"]:
            return "dashboard schedule control enabled (15-minute timer tick)"
        if not detected["matches"]:
            return "dashboard schedule control status unavailable"
        return "dashboard schedule control not enabled; current timer: " + str(detected["calendar_words"])
    root = Path(root_directory).absolute()
    policy_path = root.joinpath(*_UPDATE_POLICY.parts[1:])
    try:
        return _timer_switch_action(action, run, root, config_path, data_directory, policy_path)
    except (OSError, ValueError) as exc:
        raise SchedulingError("the systemd timer switch could not access or verify its files") from exc


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
        ("Result", "ExecMainStatus", "ExecMainExitTimestamp"),
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
    command = _systemd_exec_start(run, service_unit)
    argv = _timer_command(command, config_path)
    if not argv:
        return unknown
    tail = argv[3:]
    if _timer_run_command(command, config_path) or tail == ["scan"]:
        scan_state = "scan"
    elif tail in (["watch", "run"], ["watch", "run", "--yes"]):
        scan_state = "watch"
    else:
        scan_state = "unknown"
    if scan_state not in {"scan", "watch"}:
        return unknown

    service_last_run = _time_label(service["ExecMainExitTimestamp"], empty="Never")
    service_result = _service_result(service["Result"], service["ExecMainStatus"])

    if "--if-due" in argv[4:]:
        # systemd records service completion for idle checks too.
        last_run = _time_label(last_trigger, empty="Never")
        last_result = service_result if last_run not in {"Unknown", "Never"} else last_run
    elif service_last_run == "Never":
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
