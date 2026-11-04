"""Exercise the documented native Windows deployment on a disposable runner."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TASK = "CVEBeacon Monitor"
HEADER_NAME = "X-CVEBeacon-Smoke"
HEADER_VALUE = "synthetic-header-value"
STEPS = (
    "create the app and data directories and apply the documented icacls data ACL",
    "create a virtual environment and pip install the checkout",
    "write a watch config with a loopback webhook channel and a header secret file",
    "run watch notify test and assert the loopback sink received the header and body",
    "run the baseline watch run offline, then watch status and check the database path",
    "install the 07:00,19:00 task, query its XML, run it and check the last result",
    "remove it, install with --run-logged-out, assert S4U, then remove it",
)


def command(args, **kwargs):
    return subprocess.run(
        args, capture_output=True, text=True, errors="replace", check=False, **kwargs
    )


def checked(args, **kwargs):
    result = command(args, **kwargs)
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
    )
    assert result.returncode == 0, decode(result.stderr)
    return decode(result.stdout)


def delete_task() -> None:
    subprocess.run(
        ["schtasks", "/Delete", "/F", "/TN", TASK],
        capture_output=True,
        check=False,
    )


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
        if state.casefold() != "running" and last_run != before:
            return code
        time.sleep(1)
    state, code, last_run = task_state()
    raise AssertionError(
        f"task did not finish in {timeout:.0f}s: state={state} code={code} last={last_run}"
    )


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
    secrets = data / "secrets"
    secrets.mkdir()
    (secrets / "hook-header").write_text(HEADER_VALUE, encoding="utf-8")
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


def smoke() -> None:
    root = Path(tempfile.mkdtemp(prefix="cvebeacon-native-"))
    app = root / "app"
    data = root / "data"
    app.mkdir()
    data.mkdir()
    installed = False
    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    env = dict(os.environ)
    env["NO_PROXY"] = ",".join(
        filter(None, [env.get("NO_PROXY"), "127.0.0.1", "localhost"])
    )
    env["no_proxy"] = env["NO_PROXY"]
    try:
        account = os.environ.get("COMPUTERNAME") or os.environ.get("USERDOMAIN")
        account = (
            f"{account}\\{os.environ['USERNAME']}"
            if account
            else os.environ["USERNAME"]
        )
        checked(
            [
                "icacls",
                str(data),
                "/inheritance:r",
                "/grant:r",
                "SYSTEM:(OI)(CI)F",
                "BUILTIN\\Administrators:(OI)(CI)F",
                f"{account}:(OI)(CI)F",
            ]
        )
        print("PASS data directory ACL")

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
        print("PASS virtual environment and install")

        config = write_config(data, sink.server_address[1])
        base = [str(executable), "--config", str(config)]
        notify = checked([*base, "watch", "notify", "test", "sink"], timeout=120, env=env)
        assert "test message sent" in notify.stdout, notify.stdout
        assert len(Sink.requests) == 1, Sink.requests
        received = Sink.requests[0]
        assert received["path"] == "/hook", received
        assert received["header"] == HEADER_VALUE, received
        assert received["body"].get("test") is True, received
        print("PASS watch notify test through the loopback sink")

        database = data / "cvebeacon-watch.db"
        baseline = checked([*base, "watch", "run"], timeout=180, env=env)
        assert "baseline" in baseline.stdout.casefold(), baseline.stdout
        assert database.exists(), "watch run did not create the database"
        status = checked([*base, "watch", "status"], timeout=120, env=env)
        assert str(database).casefold() in status.stdout.casefold(), status.stdout
        print("PASS offline baseline watch run and status")

        installed = True
        checked(
            [
                *base,
                "schedule",
                "install",
                "--times",
                "07:00,19:00",
                "--command",
                "watch",
                "--yes",
            ],
            timeout=120,
            env=env,
        )
        status = checked([*base, "schedule", "status"], timeout=120, env=env)
        assert "Schedule: daily at 07:00, 19:00" in status.stdout, status.stdout
        assert "Runs while logged off: no" in status.stdout, status.stdout
        xml = query_xml()
        assert "<LogonType>InteractiveToken</LogonType>" in xml, xml
        print("PASS interactive task install, status and XML")

        for path in data.glob("cvebeacon-watch.db*"):
            path.unlink()
        _, _, before = task_state()
        checked(["schtasks", "/Run", "/TN", TASK], timeout=60)
        code = wait_for_task(before)
        assert code == "0", f"the scheduled watch run reported {code}"
        print("PASS immediate scheduled task run with last result 0")

        checked([*base, "schedule", "remove", "--yes"], timeout=120, env=env)
        status = checked([*base, "schedule", "status"], timeout=120, env=env)
        assert status.stdout.strip() == "not installed", status.stdout
        installed = False
        print("PASS schedule removal")

        installed = True
        checked(
            [
                *base,
                "schedule",
                "install",
                "--times",
                "07:00,19:00",
                "--command",
                "watch",
                "--run-logged-out",
                "--yes",
            ],
            timeout=120,
            env=env,
        )
        status = checked([*base, "schedule", "status"], timeout=120, env=env)
        assert "Runs while logged off: yes" in status.stdout, status.stdout
        assert "Account:" in status.stdout, status.stdout
        xml = query_xml()
        assert "<LogonType>S4U</LogonType>" in xml, xml
        assert "<UserId>" in xml, xml
        print("PASS logged-out task install, status and S4U XML")

        checked([*base, "schedule", "remove", "--yes"], timeout=120, env=env)
        installed = False
    finally:
        if installed:
            delete_task()
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
        for step in STEPS:
            print("  - " + step)
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
    smoke()
    print("PASS native Windows deployment smoke")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
