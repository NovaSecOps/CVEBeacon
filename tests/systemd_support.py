"""Local systemd manager replies used by timer and dashboard tests."""

import json
from pathlib import Path, PurePosixPath
from subprocess import CompletedProcess


EXECUTABLE = "/opt/cvebeacon/current/.venv/bin/cvebeacon"
TICK = "*-*-* *:00/15:00"
TIMER = "cvebeacon.timer"
SERVICE = "cvebeacon.service"
DROPIN = "dashboard-schedule.conf"


def posix_path(path):
    return str(PurePosixPath("/", *Path(path).parts[1:]))


class FakeSystemd:
    def __init__(
        self, config_path, *, command=("run",), calendar=("*-*-* 07,19:00:00",),
        executable=EXECUTABLE, root=None, timer_state="active", unit_file_state="enabled",
        result="success", exit_status=0, next_run="Thu 2026-11-26 07:00:00 UTC",
        last_trigger="Wed 2026-11-25 07:00:00 UTC", last_exit="Wed 2026-11-25 07:04:00 UTC",
        persistent="yes",
    ):
        self.executable = executable
        self.path = executable
        self.config = posix_path(config_path)
        self.argv = [executable, "--config", self.config, *command]
        self.flags = []
        self.calendar = (calendar,) if isinstance(calendar, str) else calendar
        self.fields = {
            "ActiveState": timer_state,
            "UnitFileState": unit_file_state,
            "NextElapseUSecRealtime": next_run,
            "LastTriggerUSec": last_trigger,
            "Persistent": persistent,
            "OnClockChange": "no", "OnTimezoneChange": "no",
            "Unit": SERVICE, "Triggers": SERVICE,
        }
        self.service = {
            "Result": result, "ExecMainStatus": str(exit_status), "ExecMainExitTimestamp": last_exit,
            "DynamicUser": "no", "User": "cvebeacon",
        }
        self.root = root
        self.loaded_dropins = (False, False)
        self.calls = []
        self.fail_action = None
        self.fail_once = True
        self.monotonic = ()
        self.commands = 1

    @property
    def actions(self):
        return [args[1:] for args, _ in self.calls if args[0] == "systemctl" and args[1] != "show"]

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        if args[0] == "busctl" and args[-1] == "ExecStartEx":
            argv = self.argv + (["--if-due"] if self.loaded_dropins[1] and "--if-due" not in self.argv else [])
            flags = ["no-env-expand"] if self.loaded_dropins[1] else self.flags
            data = [[self.path, argv, flags, 0, 0, 0, 0, 0, 0, 0]] * self.commands
            return CompletedProcess(args, 0, json.dumps({"type": "a(sasasttttuii)", "data": data}))
        if args[:2] == ["crontab", "-l"]:
            return CompletedProcess(args, 0, "")
        if args[:2] == ["systemctl", "show"]:
            unit = args[-1]
            index = (TIMER, SERVICE).index(unit)
            values = dict(self.fields if unit == TIMER else self.service)
            values.update({
                "LoadState": "loaded",
                "NeedDaemonReload": "no",
                "DropInPaths": f"/etc/systemd/system/{unit}.d/{DROPIN}" if self.loaded_dropins[index] else "",
            })
            if unit == TIMER:
                entries = (TICK,) if self.loaded_dropins[0] else self.calendar
                if self.loaded_dropins[0]:
                    values["Persistent"] = "yes"
                values["TimersCalendar"] = tuple(
                    f"{{ OnCalendar={spec} ; next_elapse={self.fields['NextElapseUSecRealtime']} }}"
                    for spec in entries
                )
                values["TimersMonotonic"] = self.monotonic if not self.loaded_dropins[0] else ()
            else:
                values["ExecStart"] = (
                    f"{{ path={self.path} ; argv[]={' '.join(self.argv)} ; ignore_errors=no ; "
                    "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0 }"
                )
            lines = []
            for name in args[2].partition("=")[2].split(","):
                if name in values:
                    value = values[name]
                    lines.extend(f"{name}={item}\n" for item in (value if isinstance(value, tuple) else (value,)))
            return CompletedProcess(args, 0, "".join(lines))
        if args[0] != "systemctl":
            return CompletedProcess(args, 1, "")
        action = args[1]
        if action == self.fail_action:
            if self.fail_once:
                self.fail_action = None
            return CompletedProcess(args, 1, "")
        if action == "daemon-reload" and self.root is not None:
            self.loaded_dropins = tuple(
                (self.root / "etc/systemd/system" / (unit + ".d") / DROPIN).exists()
                for unit in (TIMER, SERVICE)
            )
        elif action in {"stop", "restart"}:
            self.fields["ActiveState"] = "active" if action == "restart" else "inactive"
        return CompletedProcess(args, 0, "")
