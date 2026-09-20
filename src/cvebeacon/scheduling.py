"""Native, narrowly owned schedule planning and management."""

from __future__ import annotations

import platform
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .errors import SchedulingError

WINDOWS_TASK = "CVEBeacon Monitor"
CRON_BEGIN = "# BEGIN CVEBEACON MANAGED"
CRON_END = "# END CVEBEACON MANAGED"


@dataclass(frozen=True, slots=True)
class SchedulePlan:
    system: str
    every_hours: int
    config_path: Path
    executable: Path
    module_mode: bool = False

    @property
    def command(self) -> list[str]:
        prefix = [str(self.executable), "-m", "cvebeacon"] if self.module_mode else [str(self.executable)]
        return [*prefix, "--config", str(self.config_path), "scan"]


def make_plan(config_path: str | Path, every_hours: int, *, system: str = "auto", executable: str | Path | None = None, allow_incompatible: bool = False) -> SchedulePlan:
    if isinstance(every_hours, bool) or not isinstance(every_hours, int) or not 2 <= every_hours <= 24:
        raise SchedulingError("schedule interval must be a whole number from 2 through 24 hours")
    actual = platform.system().casefold()
    detected = "windows" if actual == "windows" else "linux" if actual == "linux" else "unsupported"
    requested = detected if system == "auto" else system.casefold()
    if detected == "unsupported":
        raise SchedulingError(f"scheduling is unsupported on {platform.system()}")
    if requested not in {"windows", "linux"}:
        raise SchedulingError("platform must be auto, windows, or linux")
    if requested != detected and not allow_incompatible:
        raise SchedulingError(f"cannot manage a {requested} schedule on a {detected} host")
    if requested == "linux" and 24 % every_hours:
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
            target, module_mode = Path(sys.executable).resolve(), True
    config_target = Path(config_path).expanduser().resolve()
    if any(character in str(value) for value in (config_target, target) for character in "\r\n"):
        raise SchedulingError("schedule paths cannot contain line breaks")
    if requested == "linux" and any("%" in str(value) for value in (config_target, target)):
        raise SchedulingError("Linux cron paths cannot contain percent characters")
    return SchedulePlan(requested, every_hours, config_target, target, module_mode)


def describe(plan: SchedulePlan) -> str:
    command = subprocess.list2cmdline(plan.command) if plan.system == "windows" else shlex.join(plan.command)
    return f"Platform: {plan.system}\nInterval: every {plan.every_hours} hours\nCommand: {command}"


def _windows_args(plan: SchedulePlan) -> list[str]:
    schedule = ["/SC", "DAILY", "/MO", "1"] if plan.every_hours == 24 else ["/SC", "HOURLY", "/MO", str(plan.every_hours)]
    return ["schtasks", "/Create", "/F", "/TN", WINDOWS_TASK, *schedule, "/RL", "LIMITED", "/TR", subprocess.list2cmdline(plan.command)]


def _cron_line(plan: SchedulePlan) -> str:
    hours = "0" if plan.every_hours == 24 else f"*/{plan.every_hours}"
    return f"0 {hours} * * * {shlex.join(plan.command)}"


def _read_crontab(run=subprocess.run) -> str:
    result = run(["crontab", "-l"], capture_output=True, text=True, check=False)
    if result.returncode == 1 and not result.stdout and result.stderr.strip().casefold().startswith("no crontab for "):
        return ""
    if result.returncode != 0:
        raise SchedulingError(f"cannot read user crontab: {result.stderr.strip()}")
    return result.stdout


def _without_managed_block(text: str) -> str:
    lines = text.splitlines()
    output, in_block, found = [], False, False
    for line in lines:
        if line == CRON_BEGIN:
            if in_block or found: raise SchedulingError("malformed duplicate managed cron marker")
            in_block, found = True, True
            continue
        if line == CRON_END:
            if not in_block: raise SchedulingError("managed cron end marker has no beginning")
            in_block = False
            continue
        if not in_block: output.append(line)
    if in_block: raise SchedulingError("managed cron block is missing its end marker")
    return "\n".join(output).rstrip() + ("\n" if output else "")


def install(plan: SchedulePlan, *, run=subprocess.run) -> None:
    if plan.system == "windows":
        result = run(_windows_args(plan), capture_output=True, text=True, check=False)
    else:
        existing = _read_crontab(run)
        clean = _without_managed_block(existing)
        value = f"{clean}{CRON_BEGIN}\n{_cron_line(plan)}\n{CRON_END}\n"
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


def status(*, system: str = "auto", run=subprocess.run) -> str:
    resolved = _host_system(system)
    if resolved == "windows":
        result = run(["schtasks", "/Query", "/TN", WINDOWS_TASK, "/FO", "LIST", "/V"], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            return result.stdout.strip()
        message = f"{result.stdout}\n{result.stderr}".casefold()
        if any(value in message for value in ("cannot find", "not found", "does not exist")):
            return "not installed"
        raise SchedulingError(f"schedule status failed: {result.stderr.strip() or result.stdout.strip()}")
    text = _read_crontab(run)
    _without_managed_block(text)
    if CRON_BEGIN not in text: return "not installed"
    start, end = text.find(CRON_BEGIN), text.find(CRON_END)
    if end < start: raise SchedulingError("managed cron block is malformed")
    return text[start:end + len(CRON_END)]


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
