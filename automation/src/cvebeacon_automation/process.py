"""Fixed argv, bounded raw pipes, sanitized environment and descendant cleanup."""

from __future__ import annotations

import math
import os
import re
import signal
import subprocess
import sys
import threading
import time

from .common import AutomationError


_CAPACITY = threading.BoundedSemaphore(4)
_ENVIRONMENT_PATHS = {"HOME", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA"}
_JOB_READY = b"\x00CVEBeacon-Job-Ready\n"

# An isolated stdlib-only gate joins the Job before launching the requested argv.
# Starting suspended is insufficient for a Windows venv executable: its launcher
# creates another Python process. The actual interpreter joins before any target
# code can run. No caller text is interpolated into this program.
_WINDOWS_GATE = r'''
import ctypes
from ctypes import wintypes
import os
import subprocess
import sys
try:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    job = wintypes.HANDLE(int(sys.argv[1]))
    assigned = kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess())
    closed = kernel.CloseHandle(job)
    if not assigned or not closed:
        sys.exit(127)
    os.write(1, b"\x00CVEBeacon-Job-Ready\n")
    if os.read(0, 1) != b"1":
        sys.exit(127)
    target = subprocess.Popen(sys.argv[3:], shell=False, close_fds=True,
        stdin=sys.stdin.buffer if sys.argv[2] == "1" else subprocess.DEVNULL,
        stdout=sys.stdout.buffer, stderr=sys.stderr.buffer)
    sys.exit(target.wait())
except SystemExit:
    raise
except BaseException:
    sys.exit(127)
'''


def clean_environment(extra=(), *, environment=None):
    """Ambient credentials are absent unless an administrator selected a name."""
    if (not isinstance(extra, (tuple, list)) or len(extra) > 32
            or any(not isinstance(key, str) or not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", key) for key in extra)):
        raise AutomationError("invalid_process_environment")
    overrides = {} if environment is None else environment
    if (not isinstance(overrides, dict) or not set(overrides) <= _ENVIRONMENT_PATHS
            or any(not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value
                   for value in overrides.values())):
        raise AutomationError("invalid_process_environment")
    result = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP") if key in os.environ}
    result.update(PATH=os.defpath, LANG="C.UTF-8", LC_ALL="C.UTF-8", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
    for key in extra:
        if key in os.environ:
            result[key] = os.environ[key]
    result.update(overrides)
    return result


class _WindowsJob:
    """Unnamed Job with only its duplicate inherited by the trusted gate."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                        ("flags", wintypes.DWORD), ("minimum_working_set", ctypes.c_size_t),
                        ("maximum_working_set", ctypes.c_size_t), ("active_processes", wintypes.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]

        class IOCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("basic", BasicLimits), ("io", IOCounters), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

        self._mutex = threading.Lock()
        self._kernel = kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.DuplicateHandle.argtypes = (wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                          ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.DuplicateHandle.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL
        self._handle = kernel.CreateJobObjectW(None, None)
        if not self._handle:
            raise AutomationError("process_containment_unavailable")
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        if not kernel.SetInformationJobObject(self._handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise AutomationError("process_containment_unavailable")

    def duplicate(self):
        import ctypes
        from ctypes import wintypes

        duplicate = wintypes.HANDLE()
        current = self._kernel.GetCurrentProcess()
        if not self._kernel.DuplicateHandle(current, self._handle, current, ctypes.byref(duplicate), 0, True, 2):
            raise AutomationError("process_containment_unavailable")
        return duplicate.value

    def close_duplicate(self, handle):
        self._kernel.CloseHandle(handle)

    def close(self):
        with self._mutex:
            if self._handle:
                self._kernel.TerminateJobObject(self._handle, 1)
                self._kernel.CloseHandle(self._handle)
                self._handle = None


def terminate(process, job=None):
    """Never find a Windows process tree using a possibly finished leader PID."""
    if job is not None:
        job.close()
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _spawn(argv, *, input, environment, cwd):
    options = dict(stdin=subprocess.PIPE if input is not None or os.name == "nt" else subprocess.DEVNULL,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, shell=False, close_fds=True,
                   env=environment, cwd=cwd, start_new_session=os.name == "posix")
    job = None
    duplicate = None
    try:
        if os.name == "nt":
            job = _WindowsJob()
            duplicate = job.duplicate()
            startup = subprocess.STARTUPINFO()
            startup.lpAttributeList = {"handle_list": [duplicate]}
            options.update(startupinfo=startup, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            argv = [sys.executable, "-I", "-S", "-c", _WINDOWS_GATE, str(duplicate), "1" if input is not None else "0", *argv]
        return subprocess.Popen(argv, **options), job
    except OSError:
        if job is not None:
            job.close()
        raise AutomationError("process_unavailable") from None
    except BaseException:
        if job is not None:
            job.close()
        raise
    finally:
        if duplicate is not None:
            job.close_duplicate(duplicate)


def run(argv, *, timeout=60, limit=32 * 1024 * 1024, input=None, extra_env=(), environment=None, cwd=None):
    """No shell; only validated, explicit adapter argv and finite path overrides."""
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
            or not 1 <= timeout <= 3600 or type(limit) is not int or not 1 <= limit <= 48 * 1024 * 1024
            or input is not None and (not isinstance(input, bytes) or len(input) > 1024 * 1024)):
        raise AutomationError("invalid_process_bound")
    if not isinstance(argv, (tuple, list)) or not 1 <= len(argv) <= 64:
        raise AutomationError("invalid_process_argv")
    try:
        argv = [os.fspath(value) for value in argv]
    except TypeError:
        raise AutomationError("invalid_process_argv") from None
    if any(not isinstance(value, str) or not value or "\x00" in value for value in argv) or sum(map(len, argv)) > 32768:
        raise AutomationError("invalid_process_argv")
    child_environment = clean_environment(extra_env, environment=environment)
    capacity = _CAPACITY
    if not capacity.acquire(blocking=False):
        raise AutomationError("process_capacity_exhausted")
    process = None
    job = None
    threads = []
    outputs = [b"", b""]
    failures = []
    ready = threading.Event()
    deadline = time.monotonic() + timeout
    stopped = False
    stop_mutex = threading.Lock()

    def stop():
        nonlocal stopped
        with stop_mutex:
            if process is not None and not stopped:
                stopped = True
                terminate(process, job)

    def failed(category):
        failures.append(category)
        stop()

    def reader(stream, index, bound):
        chunks = []
        count = 0
        prefix = b""
        try:
            while True:
                chunk = stream.read(min(65536, bound + 1 - count))
                if not chunk:
                    break
                if os.name == "nt" and index == 0 and not ready.is_set():
                    prefix += chunk
                    if not _JOB_READY.startswith(prefix[:len(_JOB_READY)]):
                        failed("process_containment_unavailable")
                        return
                    if len(prefix) < len(_JOB_READY):
                        continue
                    ready.set()
                    chunk = prefix[len(_JOB_READY):]
                    prefix = b""
                chunks.append(chunk)
                count += len(chunk)
                if count > bound:
                    failed("process_output_limit")
                    return
            outputs[index] = b"".join(chunks)
        except (OSError, ValueError):
            failed("process_io_failure")

    def writer():
        try:
            payload = (b"1" if os.name == "nt" else b"") + (input or b"")
            remaining = memoryview(payload)
            while remaining:
                written = process.stdin.write(remaining)
                if not written:
                    raise OSError
                remaining = remaining[written:]
            process.stdin.close()
        except (OSError, ValueError):
            failed("process_io_failure")

    def close_streams():
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass

    try:
        process, job = _spawn(argv, input=input, environment=child_environment, cwd=cwd)
        threads = [threading.Thread(target=reader, args=(process.stdout, 0, limit), daemon=True),
                   threading.Thread(target=reader, args=(process.stderr, 1, 65536), daemon=True)]
        if input is not None or os.name == "nt":
            threads.append(threading.Thread(target=writer, daemon=True))
        for thread in threads:
            thread.start()
        try:
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise AutomationError("process_timeout") from None
        # Descendants may retain both pipes after the requested leader exits.
        stop()
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            raise AutomationError("process_orphaned_output")
        if os.name == "nt" and not ready.is_set():
            raise AutomationError("process_containment_unavailable")
        if failures:
            raise AutomationError(failures[0])
        return code, outputs[0]
    finally:
        if process is None:
            capacity.release()
        else:
            stop()
            cleanup_deadline = time.monotonic() + 2
            try:
                process.wait(timeout=max(0, cleanup_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
            for thread in threads:
                if thread.ident is not None:
                    thread.join(max(0, cleanup_deadline - time.monotonic()))
            if all(not thread.is_alive() for thread in threads) and process.poll() is not None:
                close_streams()
                capacity.release()
            else:
                # Never close an IO object from this thread while another thread
                # is inside read/write. Unresolved readers retain one of four
                # slots; a daemon reaper releases it only after real completion.
                def reap():
                    for thread in threads:
                        if thread.ident is not None:
                            thread.join()
                    process.wait()
                    close_streams()
                    capacity.release()
                threading.Thread(target=reap, daemon=True).start()
