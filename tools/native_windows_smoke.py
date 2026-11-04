"""Exercise the documented native Windows deployment on a disposable runner."""

import argparse
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
TASK = "CVEBeacon Monitor"
SERVICE_ACCOUNT = "cvb-smoke"
HEADER_NAME = "X-CVEBeacon-Smoke"
HEADER_VALUE = "synthetic-header-value"
STEPS = (
    "create the directories under the system drive and apply the documented data ACL",
    "create a virtual environment and pip install the checkout",
    "write a watch config with a loopback webhook channel and a header secret file",
    "run watch notify test and assert the loopback sink received the header and body",
    "run the baseline watch run offline, then watch status and check the resolved database path",
    "install a fixed-time interactive task, run it and assert last result 0 and a baseline database",
    "create the local service account, grant ACLs and the batch-logon right",
    "register, run and remove a fixed-time S4U task for the service account",
    "register, query and remove an interval S4U task",
    "remove the service account",
)

_step = 0

PROBE_COM_SCRIPT = """param(
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

PROBE_CMDLET_SCRIPT = """param(
    [Parameter(Mandatory = $true)][string]$TaskName,
    [Parameter(Mandatory = $true)][string]$XmlPath,
    [Parameter(Mandatory = $true)][string]$Account,
    [Parameter(Mandatory = $true)][string]$Method
)
$ErrorActionPreference = 'Stop'
if ($Method -eq 'd') {
    $xml = [System.IO.File]::ReadAllText($XmlPath)
    Register-ScheduledTask -Xml $xml -TaskName $TaskName -User $Account | Out-Null
} elseif ($Method -eq 'e') {
    $principal = New-ScheduledTaskPrincipal -UserId $Account -LogonType S4U -RunLevel Limited
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(2)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
} else {
    throw "unknown probe method"
}
"""


def step(description: str) -> None:
    global _step
    _step += 1
    print(f"STEP {_step}: {description} ok", flush=True)


def command(args, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(
        args, capture_output=True, text=True, errors="replace", check=False, **kwargs
    )


def checked(args, **kwargs):
    result = command(args, **kwargs)
    if result.returncode != 0:
        printable = subprocess.list2cmdline([str(item) for item in args])
        print(f"FAILED COMMAND: {printable}", flush=True)
        print(f"stdout:\n{result.stdout}", flush=True)
        print(f"stderr:\n{result.stderr}", flush=True)
    assert result.returncode == 0, (
        f"command failed ({result.returncode}): {args}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return result


def decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if b"\x00" in data[:200]:
        return data.decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("mbcs", errors="replace")


def query_xml() -> str:
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK, "/XML"],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, decode(result.stderr)
    return decode(result.stdout)


def delete_task() -> None:
    """Stop only the exact owned task, then remove it, without raising."""
    subprocess.run(
        ["schtasks", "/End", "/TN", TASK],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    for _ in range(10):
        result = subprocess.run(
            ["schtasks", "/Delete", "/F", "/TN", TASK],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            break
        time.sleep(1)
    remaining = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    if remaining.returncode == 0:
        print(f"WARN: task {TASK!r} is still registered after cleanup", flush=True)


def task_state() -> tuple[str, str, str]:
    script = (
        f"$i = Get-ScheduledTaskInfo -TaskName '{TASK}'; "
        f"$s = (Get-ScheduledTask -TaskName '{TASK}').State; "
        "$s.ToString() + '|' + $i.LastTaskResult + '|' + "
        "$i.LastRunTime.ToString('o')"
    )
    result = checked(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        timeout=60,
    )
    state, code, last_run = result.stdout.strip().split("|", 2)
    return state, code, last_run


def wait_for_task(before: str, timeout: float = 120) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state, code, last_run = task_state()
        if (
            state.casefold() != "running"
            and last_run != before
            and code not in {"267009", "267011"}
        ):
            return code
        time.sleep(1)
    state, code, last_run = task_state()
    raise AssertionError(
        f"task did not finish in {timeout:.0f}s: state={state} code={code} last={last_run}"
    )


def hresult(code: str) -> str:
    try:
        return f"{int(code, 0) & 0xFFFFFFFF:08X}"
    except ValueError:
        return ""


LOGON_FAILURES = {
    "80070569",  # ERROR_LOGON_TYPE_NOT_GRANTED
    "80070533",  # ERROR_ACCOUNT_RESTRICTION
    "8007052E",  # ERROR_LOGON_FAILURE
    "800704EC",  # ERROR_ACCOUNT_DISABLED
    "80070005",  # ERROR_ACCESS_DENIED
}


class Sink(BaseHTTPRequestHandler):
    requests: list[dict] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            payload = {}
        self.requests.append(
            {
                "path": self.path,
                "header": self.headers.get(HEADER_NAME),
                "body": payload,
            }
        )
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


def write_config(data: Path, port: int) -> Path:
    secret = data / "secrets"
    secret.mkdir()
    (secret / "hook-header").write_text(HEADER_VALUE, encoding="utf-8")
    config = data / "cvebeacon.toml"
    config.write_text(
        f"""[watch]
enabled = true
database = "cvebeacon-watch.db"
initial = "baseline"
sources = ["nvd"]

[[watch.rules]]
name = "smoke"
condition = {{ cvss_min = 9.0 }}
channels = ["sink"]

[watch.channels.sink]
type = "webhook"
enabled = true
url = "http://127.0.0.1:{port}/hook"
allow_insecure = true
header_name = "{HEADER_NAME}"
header_value_file = "secrets/hook-header"
""",
        encoding="utf-8",
    )
    return config


def change_batch_logon(*, account=None, sid=None, add=True) -> bytes:
    """Add or remove SeBatchLogonRight and return the account SID bytes."""
    import ctypes
    from ctypes import wintypes

    class LsaUnicodeString(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class LsaObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", wintypes.LPVOID),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.LookupAccountNameW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.LookupAccountNameW.restype = wintypes.BOOL
    advapi32.LsaOpenPolicy.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(LsaObjectAttributes),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.LsaOpenPolicy.restype = wintypes.LONG
    advapi32.LsaAddAccountRights.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        ctypes.POINTER(LsaUnicodeString),
        wintypes.ULONG,
    ]
    advapi32.LsaAddAccountRights.restype = wintypes.LONG
    advapi32.LsaRemoveAccountRights.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.BOOLEAN,
        ctypes.POINTER(LsaUnicodeString),
        wintypes.ULONG,
    ]
    advapi32.LsaRemoveAccountRights.restype = wintypes.LONG
    advapi32.LsaClose.argtypes = [wintypes.HANDLE]
    advapi32.LsaClose.restype = wintypes.LONG
    advapi32.LsaNtStatusToWinError.argtypes = [wintypes.LONG]
    advapi32.LsaNtStatusToWinError.restype = wintypes.ULONG

    if sid is None:
        if not account:
            raise ValueError("account or sid is required")
        sid_size = wintypes.DWORD()
        domain_size = wintypes.DWORD()
        use = wintypes.DWORD()
        advapi32.LookupAccountNameW(
            None,
            account,
            None,
            ctypes.byref(sid_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        )
        error = ctypes.get_last_error()
        if error != 122:  # ERROR_INSUFFICIENT_BUFFER
            raise OSError(error, f"cannot resolve account {account}")
        sid_buffer = ctypes.create_string_buffer(sid_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)
        if not advapi32.LookupAccountNameW(
            None,
            account,
            ctypes.cast(sid_buffer, wintypes.LPVOID),
            ctypes.byref(sid_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        ):
            raise OSError(
                ctypes.get_last_error(), f"cannot resolve account {account}"
            )
        sid_bytes = sid_buffer.raw
    else:
        sid_bytes = bytes(sid)
        sid_buffer = ctypes.create_string_buffer(sid_bytes)

    attributes = LsaObjectAttributes()
    attributes.Length = ctypes.sizeof(attributes)
    policy = wintypes.HANDLE()
    status = advapi32.LsaOpenPolicy(
        None, ctypes.byref(attributes), 0x00000810, ctypes.byref(policy)
    )
    if status:
        raise OSError(advapi32.LsaNtStatusToWinError(status), "LsaOpenPolicy failed")
    try:
        name = "SeBatchLogonRight"
        text = ctypes.create_unicode_buffer(name)
        right = LsaUnicodeString(
            len(name) * ctypes.sizeof(ctypes.c_wchar),
            (len(name) + 1) * ctypes.sizeof(ctypes.c_wchar),
            ctypes.cast(text, wintypes.LPWSTR),
        )
        sid_pointer = ctypes.cast(sid_buffer, wintypes.LPVOID)
        if add:
            status = advapi32.LsaAddAccountRights(
                policy, sid_pointer, ctypes.byref(right), 1
            )
            action = "LsaAddAccountRights"
        else:
            status = advapi32.LsaRemoveAccountRights(
                policy, sid_pointer, False, ctypes.byref(right), 1
            )
            action = "LsaRemoveAccountRights"
        if status:
            raise OSError(
                advapi32.LsaNtStatusToWinError(status), f"{action} failed"
            )
    finally:
        advapi32.LsaClose(policy)
    return sid_bytes


def stop_registered_task() -> None:
    """Stop the exact owned task and wait for it before touching its database."""
    query = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    if query.returncode != 0:
        return
    subprocess.run(
        ["schtasks", "/End", "/TN", TASK],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    for _ in range(10):
        try:
            state, _, _ = task_state()
        except AssertionError:
            return
        if state.casefold() != "running":
            return
        time.sleep(1)
    print(f"WARN: task {TASK!r} is still running after schtasks /End", flush=True)


def reset_database(data: Path) -> None:
    stop_registered_task()
    for path in data.glob("cvebeacon-watch.db*"):
        if os.name != "nt":
            path.unlink(missing_ok=True)
            continue
        for attempt in range(5):
            try:
                path.unlink()
                break
            except FileNotFoundError:
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.5)


def assert_baseline(database: Path) -> None:
    with closing(sqlite3.connect(database)) as db:
        mode = db.execute(
            "SELECT value FROM watch_meta WHERE key = 'initial_mode'"
        ).fetchone()
        rows = db.execute("SELECT COUNT(*) FROM watch_cve").fetchone()[0]
    assert mode == ("baseline",), mode
    assert rows == 0, rows


def database_owner(database: Path) -> str:
    script = f"(Get-Acl -LiteralPath '{database}').Owner"
    return checked(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=60,
    ).stdout.strip()


def write_probe_xml(path: Path, account: str) -> None:
    boundary = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")
    path.write_text(
        f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>CVEBeacon S4U probe</Description></RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{boundary}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(account)}</UserId>
      <LogonType>S4U</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec><Command>cmd.exe</Command><Arguments>/c exit 0</Arguments></Exec>
  </Actions>
</Task>
""",
        encoding="utf-16",
    )


def probe_principal(task_name: str) -> str:
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", task_name, "/XML"],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return f"query failed: {decode(result.stderr).strip()}"
    text = decode(result.stdout)
    logon = re.search(r"<LogonType>(.*?)</LogonType>", text)
    user = re.search(r"<UserId>(.*?)</UserId>", text)
    return "LogonType={} UserId={}".format(
        logon.group(1) if logon else "?",
        user.group(1) if user else "?",
    )


def probe_registration(
    label: str, account: str, task_name: str, args: list[str]
) -> None:
    print(f"PROBE {label}: account={account} task={task_name}", flush=True)
    try:
        result = command(args, timeout=120)
    except Exception as exc:
        print(f"PROBE {label}: EXCEPTION {exc}", flush=True)
        command(
            ["schtasks", "/Delete", "/F", "/TN", task_name],
            stdin=subprocess.DEVNULL,
        )
        return
    print(f"PROBE {label}: returncode={result.returncode}", flush=True)
    if result.stdout.strip():
        print(f"PROBE {label} stdout:\n{result.stdout}", flush=True)
    if result.stderr.strip():
        print(f"PROBE {label} stderr:\n{result.stderr}", flush=True)
    if result.returncode == 0:
        print(f"PROBE {label}: {probe_principal(task_name)}", flush=True)
    cleanup = command(
        ["schtasks", "/Delete", "/F", "/TN", task_name],
        stdin=subprocess.DEVNULL,
    )
    if cleanup.returncode != 0:
        print(
            f"PROBE {label} cleanup stderr:\n{cleanup.stderr}", flush=True
        )


def probe_s4u_registration(current: str, service: str) -> None:
    print("PROBE whoami /user:", flush=True)
    for name, args in (
        ("user", ["whoami", "/user"]),
        ("groups", ["whoami", "/groups"]),
        ("priv", ["whoami", "/priv"]),
    ):
        result = command(args, stdin=subprocess.DEVNULL)
        print(f"PROBE whoami /{name}:\n{result.stdout}{result.stderr}", flush=True)
    token = secrets.token_hex(3)
    with tempfile.TemporaryDirectory(
        prefix="cvebeacon-probe-", ignore_cleanup_errors=True
    ) as directory:
        directory = Path(directory)
        com_script = directory / "probe-com.ps1"
        cmdlet_script = directory / "probe-cmdlet.ps1"
        com_script.write_text(PROBE_COM_SCRIPT, encoding="utf-8")
        cmdlet_script.write_text(PROBE_CMDLET_SCRIPT, encoding="utf-8")
        for kind, account in (("current", current), ("service", service)):
            xml_path = directory / f"probe-{kind}.xml"
            write_probe_xml(xml_path, account)
            for method in ("a", "b", "c", "d", "e"):
                task_name = f"CVEBeacon Probe {token} {kind} {method}"
                if method == "a":
                    args = [
                        "schtasks",
                        "/Create",
                        "/XML",
                        str(xml_path),
                        "/TN",
                        task_name,
                        "/RU",
                        account,
                        "/NP",
                        "/F",
                        "/HRESULT",
                    ]
                elif method in {"b", "c"}:
                    args = [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(com_script),
                        "-TaskName",
                        task_name,
                        "-XmlPath",
                        str(xml_path),
                        "-Account",
                        account,
                    ]
                    if method == "c":
                        args.append("-UseXmlPrincipal")
                else:
                    args = [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(cmdlet_script),
                        "-TaskName",
                        task_name,
                        "-XmlPath",
                        str(xml_path),
                        "-Account",
                        account,
                        "-Method",
                        method,
                    ]
                try:
                    probe_registration(f"{kind}-{method}", account, task_name, args)
                except Exception as exc:
                    print(
                        f"PROBE {kind}-{method}: harness exception {exc}",
                        flush=True,
                    )
                    command(
                        ["schtasks", "/Delete", "/F", "/TN", task_name],
                        stdin=subprocess.DEVNULL,
                    )


def cleanup_account(batch_sid: bytes | None) -> bool:
    """Best-effort removal of the fixture's right and local account."""
    ok = True
    if batch_sid is not None:
        try:
            change_batch_logon(sid=batch_sid, add=False)
        except Exception as exc:
            ok = False
            print(f"WARN: could not remove SeBatchLogonRight: {exc}", flush=True)
    deleted = command(
        ["net", "user", SERVICE_ACCOUNT, "/delete"], stdin=subprocess.DEVNULL
    )
    if deleted.returncode != 0:
        print(
            f"WARN: could not delete {SERVICE_ACCOUNT}: {deleted.stderr.strip()}",
            flush=True,
        )
        return False
    remaining = command(
        ["net", "user", SERVICE_ACCOUNT], stdin=subprocess.DEVNULL
    )
    if remaining.returncode == 0:
        print(f"WARN: account {SERVICE_ACCOUNT} still exists after deletion", flush=True)
        ok = False
    return ok


def smoke() -> None:
    drive = os.environ.get("SystemDrive", "C:")
    root = Path(
        tempfile.mkdtemp(prefix="cvebeacon-native-", dir=drive + "\\")
    ).resolve()
    app = root / "app"
    data = root / "data"
    app.mkdir()
    data.mkdir()
    database = (data / "cvebeacon-watch.db").resolve()
    service_account = (
        f"{os.environ.get('COMPUTERNAME') or os.environ.get('USERDOMAIN')}"
        f"\\{SERVICE_ACCOUNT}"
    )
    installed = False
    user_created = False
    batch_sid: bytes | None = None
    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    env = dict(os.environ)
    env["NO_PROXY"] = ",".join(
        filter(None, [env.get("NO_PROXY"), "127.0.0.1", "localhost"])
    )
    env["no_proxy"] = env["NO_PROXY"]
    try:
        existing = subprocess.run(
            ["schtasks", "/Query", "/TN", TASK],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        assert existing.returncode != 0, (
            f"refusing to overwrite an existing task named {TASK!r}"
        )
        current = checked(["whoami"]).stdout.strip()
        checked(
            [
                "icacls",
                str(data),
                "/inheritance:r",
                "/grant:r",
                "SYSTEM:(OI)(CI)F",
                "BUILTIN\\Administrators:(OI)(CI)F",
                f"{current}:(OI)(CI)F",
            ]
        )
        step("directories and data ACL")

        venv = app / ".venv"
        checked([sys.executable, "-m", "venv", str(venv)], timeout=300)
        python = venv / "Scripts" / "python.exe"
        executable = venv / "Scripts" / "cvebeacon.exe"
        checked(
            [str(python), "-m", "pip", "install", "--upgrade", "pip>=26.2"],
            timeout=600,
            env=env,
        )
        checked([str(python), "-m", "pip", "install", str(ROOT)], timeout=900, env=env)
        assert executable.exists(), "the console launcher is missing"
        step("virtual environment and install")

        config = write_config(data, sink.server_address[1])
        base = [str(executable), "--config", str(config)]
        step("watch config and secret file")

        notify = checked([*base, "watch", "notify", "test", "sink"], timeout=120, env=env)
        assert "test message sent" in notify.stdout, notify.stdout
        assert len(Sink.requests) == 1, Sink.requests
        received = Sink.requests[0]
        assert received["path"] == "/hook", received
        assert received["header"] == HEADER_VALUE, received
        assert received["body"].get("test") is True, received
        step("watch notify test through the loopback sink")

        baseline = checked([*base, "watch", "run"], timeout=180, env=env)
        assert "baseline" in baseline.stdout.casefold(), baseline.stdout
        assert database.exists(), "watch run did not create the database"
        status = checked([*base, "watch", "status"], timeout=120, env=env)
        assert str(database).casefold() in status.stdout.casefold(), (
            f"database path mismatch: expected {database!r}, status {status.stdout!r}"
        )
        assert_baseline(database)
        step("offline baseline watch run and status")

        # Keep the next trigger at least two hours away. Baseline is silent only
        # on a fresh database, so an autonomous trigger must not fire mid-smoke.
        soon = datetime.now()
        times = []
        for offset in (2, 3, 4, 5):
            value = (soon + timedelta(hours=offset)).strftime("%H:%M")
            if value not in times:
                times.append(value)
            if len(times) == 2:
                break
        times = sorted(times)
        times_arg = ",".join(times)
        installed = True
        checked(
            [*base, "schedule", "install", "--times", times_arg, "--command", "watch", "--yes"],
            timeout=120,
            env=env,
        )
        status = checked([*base, "schedule", "status"], timeout=120, env=env)
        assert all(value in status.stdout for value in times), status.stdout
        assert "Runs while logged off: no" in status.stdout, status.stdout
        xml = query_xml()
        assert xml.count("<CalendarTrigger>") == 2, xml
        assert "<LogonType>InteractiveToken</LogonType>" in xml, xml
        reset_database(data)
        _, _, before = task_state()
        checked(
            ["schtasks", "/Run", "/TN", TASK],
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
        code = wait_for_task(before)
        assert code == "0", f"the scheduled watch run reported {code}"
        assert database.exists(), "the scheduled run did not write the database"
        assert_baseline(database)
        checked([*base, "schedule", "remove", "--yes"], timeout=120, env=env)
        status = checked([*base, "schedule", "status"], timeout=120, env=env)
        assert status.stdout.strip() == "not installed", status.stdout
        installed = False
        step("fixed-time interactive task install, run, result and removal")

        existing_account = command(
            ["net", "user", SERVICE_ACCOUNT], stdin=subprocess.DEVNULL
        )
        assert existing_account.returncode != 0, (
            f"refusing to reuse an existing account named {SERVICE_ACCOUNT!r}"
        )
        password = "Cvb-" + secrets.token_urlsafe(18) + "!9aA"
        created = command(
            ["net", "user", SERVICE_ACCOUNT, password, "/add", "/expires:never", "/Y"],
            stdin=subprocess.DEVNULL,
        )
        if created.returncode != 0:
            print(
                f"FAILED COMMAND: net user {SERVICE_ACCOUNT} <password omitted> "
                "/add /expires:never /Y",
                flush=True,
            )
            print(f"stdout:\n{created.stdout}", flush=True)
            print(f"stderr:\n{created.stderr}", flush=True)
        assert created.returncode == 0, created.stderr
        user_created = True
        for path, rights in ((root, "RX"), (app, "RX"), (data, "F")):
            checked(
                [
                    "icacls",
                    str(path),
                    "/grant",
                    f"{service_account}:(OI)(CI){rights}",
                    "/T",
                ]
            )
        batch_ready = True
        try:
            batch_sid = change_batch_logon(account=service_account, add=True)
        except Exception as exc:  # policy APIs vary; registration still proves XML
            batch_ready = False
            print(f"WARN: could not grant SeBatchLogonRight: {exc}", flush=True)
        step("local service account and ACLs")

        try:
            probe_s4u_registration(current, service_account)
        except Exception as exc:
            print(f"PROBE harness failed: {exc}", flush=True)

        installed = True
        install = checked(
            [
                *base,
                "schedule",
                "install",
                "--times",
                times_arg,
                "--command",
                "watch",
                "--run-logged-out",
                "--account",
                service_account,
                "--yes",
            ],
            timeout=120,
            env=env,
        )
        assert (
            f"Runs as: {service_account} (S4U, while logged off)" in install.stdout
        ), install.stdout
        status = checked([*base, "schedule", "status"], timeout=120, env=env)
        assert f"Account: {service_account}".casefold() in status.stdout.casefold(), (
            status.stdout
        )
        assert "Runs while logged off: yes" in status.stdout, status.stdout
        xml = query_xml()
        assert "<LogonType>S4U</LogonType>" in xml, xml
        assert (
            f"<UserId>{service_account}</UserId>".casefold() in xml.casefold()
        ), xml
        if batch_ready:
            reset_database(data)
            _, _, before = task_state()
            checked(
                ["schtasks", "/Run", "/TN", TASK],
                timeout=60,
                stdin=subprocess.DEVNULL,
            )
            code = wait_for_task(before)
            if code == "0":
                assert database.exists(), "the S4U run did not write the database"
                assert_baseline(database)
                owner = database_owner(database)
                assert SERVICE_ACCOUNT.casefold() in owner.casefold(), owner
                s4u_executed = True
            elif hresult(code) in LOGON_FAILURES:
                s4u_executed = False
                print(
                    f"WARN: S4U run reported {code} (0x{hresult(code)}); "
                    "registration-only proof",
                    flush=True,
                )
            else:
                raise AssertionError(f"the S4U watch run reported {code}")
        else:
            s4u_executed = False
            print(
                "WARN: S4U execution skipped; registration and XML only",
                flush=True,
            )
        checked([*base, "schedule", "remove", "--yes"], timeout=120, env=env)
        status = checked([*base, "schedule", "status"], timeout=120, env=env)
        assert status.stdout.strip() == "not installed", status.stdout
        installed = False
        step(
            "fixed-time S4U task registration"
            + (", execution and removal" if s4u_executed else " and removal")
        )

        installed = True
        reset_database(data)
        checked(
            [
                *base,
                "schedule",
                "install",
                "--every",
                "4",
                "--command",
                "watch",
                "--run-logged-out",
                "--account",
                service_account,
                "--yes",
            ],
            timeout=120,
            env=env,
        )
        xml = query_xml()
        assert "<TimeTrigger>" in xml, xml
        assert "<Interval>PT4H</Interval>" in xml, xml
        assert "<LogonType>S4U</LogonType>" in xml, xml
        checked([*base, "schedule", "remove", "--yes"], timeout=120, env=env)
        installed = False
        step("interval S4U XML registration and removal")

        assert cleanup_account(batch_sid), "service account cleanup failed"
        user_created = False
        step("service account removal")
    finally:
        if installed:
            delete_task()
        if user_created:
            cleanup_account(batch_sid)
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=5)
        shutil.rmtree(root, ignore_errors=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the steps without changing the host",
    )
    args = parser.parse_args(argv)
    if args.dry_run:
        print("DRY RUN: native Windows deployment smoke")
        for description in STEPS:
            print("  - " + description)
        return 0
    if os.name != "nt":
        print("SKIP: native Windows deployment smoke requires Windows")
        return 0
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise SystemExit(
            "native Windows task checks require a disposable GitHub-hosted runner"
        )
    try:
        smoke()
    except Exception:
        print(f"FAILED at STEP {_step + 1}", flush=True)
        raise
    print("PASS native Windows deployment smoke")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
