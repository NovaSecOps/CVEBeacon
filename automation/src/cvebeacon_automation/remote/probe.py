"""Bundled transient Linux observation probe; never installs or writes a file."""

REMOTE_COMMAND = "exec /usr/bin/python3 -I -S -B -"

_BODY = r'''
import json
import os
import shlex
import signal
import subprocess
import sys
import threading

LIMIT = 16 * 1024 * 1024
DPKG = ["/usr/bin/dpkg-query", "--no-pager", "--show", "--showformat=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n"]
RPM = ["/usr/bin/rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{EPOCHNUM}\n"]

def fail():
    sys.stderr.write("remote_probe_failed\n")
    raise SystemExit(2)

def kill(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

def query(args):
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                   "HOME": "/nonexistent", "XDG_CONFIG_HOME": "/nonexistent"}
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, shell=False, env=environment, start_new_session=True)
    result, errors = [], []
    def drain():
        try:
            data = process.stdout.read(LIMIT + 1)
            result.append(data)
            if len(data) > LIMIT:
                kill(process)
        except OSError:
            errors.append(True)
    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        code = process.wait(timeout=30)
        reader.join(2)
        if reader.is_alive() or errors or code or not result or len(result[0]) > LIMIT:
            fail()
        return result[0].decode("utf-8", errors="strict")
    finally:
        kill(process)
        process.wait(timeout=5)
        reader.join(2)
        if not reader.is_alive():
            process.stdout.close()

try:
    if not sys.platform.startswith("linux"):
        fail()
    release_path = "/etc/os-release" if os.path.exists("/etc/os-release") else "/usr/lib/os-release"
    with open(release_path, "rb") as handle:
        raw_release = handle.read(65537)
    if len(raw_release) > 65536:
        fail()
    release = raw_release.decode("utf-8", errors="strict")
    backend = REQUESTED_BACKEND
    if backend == "auto":
        fields = {}
        for line in release.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"ID", "ID_LIKE"}:
                parsed = shlex.split(value, comments=False, posix=True)
                if len(parsed) == 1:
                    fields[key] = parsed[0]
        family = {fields.get("ID", ""), *fields.get("ID_LIKE", "").split()}
        backend = "dpkg" if family & {"debian", "ubuntu"} else "rpm" if family & {"rhel", "fedora", "centos", "suse", "opensuse", "rocky", "almalinux"} else "unknown"
    if backend not in {"dpkg", "rpm"}:
        fail()
    result = json.dumps(dict(version=1, backend=backend, os_release=release,
        packages=query(DPKG if backend == "dpkg" else RPM)), ensure_ascii=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(result) > 32 * 1024 * 1024:
        fail()
    sys.stdout.buffer.write(result + b"\n")
    sys.stdout.buffer.flush()
except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
    fail()
'''


def script(backend: str) -> bytes:
    if backend not in {"auto", "dpkg", "rpm"}:
        raise ValueError("unsupported_probe_backend")
    return ("REQUESTED_BACKEND = " + repr(backend) + "\n" + _BODY).encode("ascii")
