"""One shared, crash-safe lock for data-changing CVEBeacon operations.

The lock coordinates the dashboard's background jobs with scheduled and
interactive command-line runs. It is a persistent, owner-only file in the
state directory; the operating system releases the lock when a process exits,
so a crashed run cannot block later work permanently.
"""

from __future__ import annotations

import getpass
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import socket

from .errors import CVEBeaconError

LOCK_NAME = "cvebeacon-run.lock"
_METADATA_LIMIT = 4096


class RunInProgress(CVEBeaconError):
    """Another process or dashboard job holds the shared run lock."""

    def __init__(self, holder: str | None = None):
        self.holder = holder
        detail = f" ({holder})" if holder else ""
        super().__init__(
            f"another run is in progress{detail}; wait for it to finish or "
            "cancel it from the dashboard"
        )


def run_lock_path(config) -> Path:
    """Return the single lock path shared by CLI and dashboard in a config."""
    return Path(config.database_path).parent / LOCK_NAME


def _account_name() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError, RuntimeError):
        return "unknown"


def _host_name() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def describe_holder(value: bytes | str | None) -> str | None:
    if not value:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    try:
        record = json.loads(value)
    except (TypeError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    parts = []
    if isinstance(record.get("account"), str) and record["account"]:
        parts.append(record["account"])
    if isinstance(record.get("host"), str) and record["host"]:
        parts.append(f"on {record['host']}")
    if isinstance(record.get("pid"), int):
        parts.append(f"pid {record['pid']}")
    if isinstance(record.get("started_at"), str) and record["started_at"]:
        parts.append(f"since {record['started_at']}")
    if isinstance(record.get("command"), str) and record["command"]:
        parts.append(f"running {record['command']}")
    return ", ".join(parts) or None


class RunLock:
    """A non-blocking exclusive file lock held for a data-changing run.

    The file is never removed, so a waiter cannot accidentally lock a
    different inode. Metadata is written only while the lock is held.
    """

    def __init__(self, path: str | Path, *, command: str | None = None):
        self.path = Path(path)
        self.command = command
        self.holder: str | None = None
        self._descriptor: int | None = None

    def _lock(self, descriptor: int) -> None:
        if os.name == "nt":  # pragma: no cover - exercised on Windows
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(self, descriptor: int) -> None:
        if os.name == "nt":  # pragma: no cover - exercised on Windows
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            return
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)

    def acquire(self) -> bool:
        if self._descriptor is not None:
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(
                self.path,
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_BINARY", 0),
                0o600,
            )
        except OSError as exc:
            raise CVEBeaconError(
                f"cannot open the run lock {self.path}: {exc}"
            ) from exc
        try:
            if os.name == "nt":  # pragma: no cover - exercised on Windows
                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\n")
            try:
                self._lock(descriptor)
            except OSError:
                os.lseek(descriptor, 0, os.SEEK_SET)
                self.holder = describe_holder(
                    os.read(descriptor, _METADATA_LIMIT)
                )
                os.close(descriptor)
                return False
            metadata = {
                "account": _account_name(),
                "host": _host_name(),
                "pid": os.getpid(),
                "started_at": datetime.now(timezone.utc)
                .isoformat(timespec="seconds"),
            }
            if self.command:
                metadata["command"] = self.command
            payload = json.dumps(metadata, ensure_ascii=False).encode("utf-8")
            os.lseek(descriptor, 0, os.SEEK_SET)
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.ftruncate(descriptor, len(payload))
            if os.name == "posix":
                try:
                    os.fchmod(descriptor, 0o600)
                except OSError:
                    pass
            self._descriptor = descriptor
            return True
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        try:
            if os.name == "nt":  # pragma: no cover - exercised on Windows
                os.lseek(descriptor, 0, os.SEEK_SET)
                self._unlock(descriptor)
                os.ftruncate(descriptor, 0)
            else:
                os.ftruncate(descriptor, 0)
                self._unlock(descriptor)
        except OSError:
            pass
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def probe(self) -> str | None:
        """Return the current holder without disturbing the lock.

        ``None`` means the lock is free. The check is advisory; the real
        command still takes the lock before changing data.
        """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(
                self.path,
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_BINARY", 0),
                0o600,
            )
        except OSError as exc:
            raise CVEBeaconError(
                f"cannot inspect the run lock {self.path}: {exc}"
            ) from exc
        try:
            if os.name == "nt" and os.fstat(descriptor).st_size == 0:
                # msvcrt locks a byte range, so the file must contain one.
                os.write(descriptor, b"\n")
            try:
                self._lock(descriptor)
            except OSError:
                os.lseek(descriptor, 0, os.SEEK_SET)
                return describe_holder(os.read(descriptor, _METADATA_LIMIT))
            self._unlock(descriptor)
            return None
        finally:
            os.close(descriptor)

    def __enter__(self) -> "RunLock":
        if not self.acquire():
            raise RunInProgress(self.holder)
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.release()
