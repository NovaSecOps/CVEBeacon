"""Crash-safe resource locks for data-changing CVEBeacon operations.

The locks coordinate the dashboard's background jobs with scheduled and
interactive command-line runs. Persistent lock files live in the storage
directories and carry no state, so they may be shared with another service
account; the operating system releases locks when a process exits, so a
crashed run cannot block later work permanently.
"""

from __future__ import annotations

import errno
import getpass
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import socket

from .errors import CVEBeaconError
from .private_storage import private_directory, private_file

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
    """Return the watch storage lock shared by CLI and dashboard."""
    return Path(config.watch.database).resolve().parent / LOCK_NAME


def operation_lock_paths(config, operation: str) -> tuple[Path, ...]:
    """Select the stores written by an operation in canonical path order."""
    paths = set()
    if operation in {"scan", "web-detect", "web-plan", "web-assets"} or (operation == "run" and config.inventory is not None):
        paths.add(Path(config.database_path).resolve().parent / LOCK_NAME)
    if (operation == "run" and config.watch.enabled) or operation.startswith("watch-"):
        paths.add(run_lock_path(config))
    return tuple(sorted(paths))


class OperationLock:
    """Take each required resource once, releasing partial acquisitions."""

    def __init__(self, config, operation: str):
        self.locks = [
            RunLock(path, command=operation)
            for path in operation_lock_paths(config, operation)
        ]
        self.holder: str | None = None

    def acquire(self) -> bool:
        try:
            for lock in self.locks:
                if not lock.acquire():
                    self.holder = lock.holder
                    self.release()
                    return False
            return True
        except BaseException:
            self.release()
            raise

    def release(self) -> None:
        for lock in reversed(self.locks):
            lock.release()

    def probe(self) -> str | None:
        for lock in self.locks:
            holder = lock.probe()
            if holder is not None:
                return holder
        return None


def _contention(exc: OSError) -> bool:
    if isinstance(exc, BlockingIOError):
        return True
    if os.name == "nt":  # ERROR_LOCK_VIOLATION; CRT may expose only EACCES.
        code = getattr(exc, "winerror", None)
        return code == 33 if code is not None else exc.errno == errno.EACCES
    return exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}


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

        kind = fcntl.LOCK_SH if getattr(self, "_probing", False) else fcntl.LOCK_EX
        fcntl.flock(descriptor, kind | fcntl.LOCK_NB)

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
        descriptor = self._open()
        try:
            try:
                self._lock(descriptor)
            except OSError as exc:
                if not _contention(exc):
                    raise CVEBeaconError("cannot acquire the operation lock") from exc
                self.holder = self._holder(descriptor)
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
            try:
                os.lseek(descriptor, 1, os.SEEK_SET)
                written = 0
                while written < len(payload):
                    written += os.write(descriptor, payload[written:])
                os.ftruncate(descriptor, len(payload) + 1)
            except OSError as exc:
                raise CVEBeaconError(
                    "cannot write the operation lock metadata"
                ) from exc
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
            # Byte zero is reserved for Windows locking. Never write it, and
            # clear metadata while still locked so a successor cannot be erased.
            os.ftruncate(descriptor, 1)
            self._unlock(descriptor)
        except OSError:
            pass
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def _open(self) -> int:
        try:
            private_directory(self.path.parent)
            # The lock file carries no state. It may pre-exist from another
            # service account, so do not require its owner or permissions.
            return private_file(self.path, create=True, owner_only=False)
        except OSError as exc:
            raise CVEBeaconError("cannot open the run lock safely") from exc

    @staticmethod
    def _holder(descriptor: int) -> str:
        try:
            os.lseek(descriptor, 1, os.SEEK_SET)
            return describe_holder(os.read(descriptor, _METADATA_LIMIT)) or "holder unavailable"
        except OSError:
            return "holder unavailable"

    def probe(self) -> str | None:
        """Advisory contention check; the child always takes the real lock.

        POSIX readers share a probe lock. Windows requires a brief nonblocking
        byte-range attempt. Contention is busy even without readable metadata.
        """
        descriptor = self._open()
        self._probing = True
        try:
            try:
                self._lock(descriptor)
            except OSError as exc:
                if not _contention(exc):
                    raise CVEBeaconError("cannot probe the operation lock") from exc
                return self._holder(descriptor)
            self._unlock(descriptor)
            return None
        finally:
            self._probing = False
            os.close(descriptor)

    def __enter__(self) -> "RunLock":
        if not self.acquire():
            raise RunInProgress(self.holder)
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.release()
