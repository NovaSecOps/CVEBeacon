"""Offline native containment and bounded cleanup regressions."""

import io
import json
import os
from pathlib import Path
import sys
import threading
import time

import pytest

from cvebeacon_automation import process
from cvebeacon_automation.common import AutomationError


def python(program, *arguments):
    return [sys.executable, "-I", "-S", "-c", program, *map(str, arguments)]


def test_binary_stdin_and_exit_code():
    payload = bytes(range(256)) * 2048
    code, output = process.run(python("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.exit(17)"),
                               input=payload, limit=len(payload), timeout=10)
    assert (code, output) == (17, payload)


def test_default_environment_and_finite_path_overrides(tmp_path, monkeypatch):
    for name in ("AUTOMATION_TOKEN", "HTTPS_PROXY", "SSLKEYLOGFILE", "PYTHONPATH", "HOME"):
        monkeypatch.setenv(name, "synthetic-credential-canary")
    paths = {name: str(tmp_path / name) for name in ("HOME", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA")}
    code, output = process.run(python("import json, os; print(json.dumps(dict(os.environ)))"),
                               environment=paths, cwd=tmp_path, timeout=10)
    assert code == 0
    child = json.loads(output)
    assert all(child[name] == value for name, value in paths.items())
    assert not {"AUTOMATION_TOKEN", "HTTPS_PROXY", "SSLKEYLOGFILE", "PYTHONPATH"} & child.keys()
    assert b"synthetic-credential-canary" not in output


@pytest.mark.parametrize("environment", [{"PATH": "other"}, {"HOME": "bad\x00path"}, {"HOME": ""}])
def test_untrusted_environment_overrides_rejected(environment):
    with pytest.raises(AutomationError, match="invalid_process_environment"):
        process.run(python("pass"), environment=environment)


@pytest.mark.parametrize("kwargs", [{"timeout": float("nan")}, {"timeout": True}, {"limit": 1.5}, {"input": "text"}])
def test_invalid_bounds_before_process_creation(kwargs, monkeypatch):
    monkeypatch.setattr(process, "_spawn", lambda *a, **k: pytest.fail("must not launch"))
    with pytest.raises(AutomationError, match="invalid_process_bound"):
        process.run(python("pass"), **kwargs)


@pytest.mark.parametrize("stream,bound", [("stdout", 1024), ("stderr", 65536)])
def test_output_overflow_stops_live_process(stream, bound):
    started = time.monotonic()
    program = f"import sys,time; sys.{stream}.buffer.write(b'x'*{bound + 1}); sys.{stream}.flush(); time.sleep(20)"
    with pytest.raises(AutomationError, match="process_output_limit"):
        process.run(python(program), limit=1024, timeout=5)
    assert time.monotonic() - started < 4


def test_timeout_is_bounded():
    started = time.monotonic()
    with pytest.raises(AutomationError, match="process_timeout"):
        process.run(python("import time; time.sleep(20)"), timeout=1)
    assert time.monotonic() - started < 4


def spawn_pipe_holder(tmp_path, *, hold_leader):
    started = tmp_path / "descendant-started"
    survived = tmp_path / "descendant-survived"
    descendant = "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('started'); time.sleep(2); pathlib.Path(sys.argv[2]).write_text('survived'); time.sleep(20)"
    program = "\n".join([
        "import pathlib,subprocess,sys,time",
        f"subprocess.Popen([sys.executable,'-I','-S','-c',{descendant!r},sys.argv[1],sys.argv[2]])",
        "deadline=time.monotonic()+5",
        "while not pathlib.Path(sys.argv[1]).exists() and time.monotonic()<deadline: time.sleep(.01)",
        "assert pathlib.Path(sys.argv[1]).exists()",
        "print('leader-finished',flush=True)",
        "time.sleep(20)" if hold_leader else "pass",
    ])
    return python(program, started, survived), started, survived


def test_finished_leader_pipe_holder_is_killed(tmp_path):
    # On Windows sys.executable is the venv launcher, whose interpreter then
    # launches another venv interpreter. Containment must cover that chain.
    argv, marker, survived = spawn_pipe_holder(tmp_path, hold_leader=False)
    started = time.monotonic()
    code, output = process.run(argv, timeout=5)
    assert marker.exists()
    assert (code, output.strip()) == (0, b"leader-finished")
    assert time.monotonic() - started < 3
    time.sleep(2.2)
    assert not survived.exists()


def test_timeout_kills_pipe_holding_descendant(tmp_path):
    argv, marker, survived = spawn_pipe_holder(tmp_path, hold_leader=True)
    with pytest.raises(AutomationError, match="process_timeout"):
        process.run(argv, timeout=1)
    assert marker.exists()
    time.sleep(1.2)
    assert not survived.exists()


@pytest.mark.skipif(os.name != "nt", reason="native Windows Job assignment")
def test_job_assignment_failure_never_launches_target(tmp_path, monkeypatch):
    marker = tmp_path / "target-must-not-run"
    gate = process._WINDOWS_GATE.replace("assigned = kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess())", "assigned = False")
    monkeypatch.setattr(process, "_WINDOWS_GATE", gate)
    with pytest.raises(AutomationError, match="process_containment_unavailable"):
        process.run(python("import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('bad')", marker), timeout=5)
    assert not marker.exists()


def test_unresolved_readers_bound_capacity_without_synchronous_close(monkeypatch):
    released = threading.Event()
    capacity = threading.BoundedSemaphore(1)

    class RetainedPipe:
        def __init__(self, data):
            self.data = data
            self.closed = False
        def read(self, size):
            released.wait()
            data, self.data = self.data, b""
            return data
        def close(self):
            assert released.is_set(), "closing a pipe while its reader is blocked"
            self.closed = True

    class FinishedProcess:
        stdin = io.BytesIO()
        stdout = RetainedPipe((process._JOB_READY if os.name == "nt" else b"") + b"ok")
        stderr = RetainedPipe(b"")
        def wait(self, timeout=None):
            return 0
        def poll(self):
            return 0

    fake = FinishedProcess()
    monkeypatch.setattr(process, "_CAPACITY", capacity)
    monkeypatch.setattr(process, "_spawn", lambda *a, **k: (fake, None))
    monkeypatch.setattr(process, "terminate", lambda *a, **k: None)
    started = time.monotonic()
    try:
        with pytest.raises(AutomationError, match="process_orphaned_output"):
            process.run(["synthetic"], timeout=1)
        assert time.monotonic() - started < 4
        assert not fake.stdout.closed and not fake.stderr.closed
        with pytest.raises(AutomationError, match="process_capacity_exhausted"):
            process.run(["synthetic"], timeout=1)
    finally:
        released.set()
    assert capacity.acquire(timeout=2)
    capacity.release()
    assert fake.stdout.closed and fake.stderr.closed
