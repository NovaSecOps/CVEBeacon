"""Crash-safe resource locks for data-changing CVEBeacon operations.

The locks coordinate the dashboard's background jobs with scheduled and
interactive command-line runs. Persistent lock files live in the storage
directories; private sidecar records describe their holders. Locks may be
shared with another service account; the operating system releases locks when
a process exits, so a crashed run cannot block later work permanently.
"""

from __future__ import annotations

import errno
from dataclasses import fields, is_dataclass
import getpass
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import socket
import stat
import uuid

from .errors import CVEBeaconError, ConfigurationError
from .private_storage import private_directory, private_file

LOCK_NAME = "cvebeacon-run.lock"
_METADATA_LIMIT = 4096
DASHBOARD_LOCK_CONFLICT_EXIT = 75


def owner_record_path(lock_path: Path, token: str | None = None) -> Path:
    """Derive a sibling name; never accept a filename from stored metadata."""
    suffix = ".owner.json" if token is None else f".owner.{token}.json"
    return lock_path.with_name(lock_path.name + suffix)


def is_owner_record_path(path: Path) -> bool:
    # Reserve temporary and future acquisition records as well as legacy names.
    return any(part.startswith(LOCK_NAME + ".owner.") for part in path.parts)


def owner_storage_paths(lock_path: Path) -> set[Path]:
    result = {owner_record_path(lock_path)}
    try:
        result.update(lock_path.parent.glob(lock_path.name + ".owner.*"))
    except OSError:
        pass
    return result


def validate_lock_storage(config) -> None:
    """Keep configured data and secrets outside the reserved owner namespace."""
    def paths(value):
        if isinstance(value, Path):
            yield value
        elif is_dataclass(value):
            for field in fields(value):
                yield from paths(getattr(value, field.name))
        elif isinstance(value, dict):
            for item in value.values():
                yield from paths(item)
        elif isinstance(value, (tuple, list)):
            for item in value:
                yield from paths(item)
    for path in (*paths(config), config.watch.users_database):
        if is_owner_record_path(path.absolute()) or is_owner_record_path(path.resolve()):
            raise ConfigurationError("configured paths must not alias operation holder storage")


def dashboard_job_id() -> int | None:
    value = os.environ.get("CVEBEACON_DASHBOARD_JOB", "")
    return int(value) if value.isascii() and value.isdecimal() and 0 < len(value) <= 18 and int(value) > 0 else None


class RunInProgress(CVEBeaconError):
    """Another process or dashboard job holds the shared run lock."""

    def __init__(self, holder: str | None = None):
        self.holder = holder
        detail = f" ({holder})" if holder else ""
        cancel = " or cancel it from the Operations page" if getattr(holder, "dashboard", False) else ""
        super().__init__(f"another run is in progress{detail}; wait for it to finish{cancel}")


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
        validate_lock_storage(config)
        label = operation.replace("watch-", "watch ", 1)
        if operation in {"watch-retry-failed", "watch-retry-ambiguous"}:
            label = "watch notify"
        elif operation == "web-plan":
            label = "web-detect --plan"
        self.locks = [
            RunLock(path, command=label)
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

    def snapshots(self) -> list[dict]:
        records = []
        for lock in self.locks:
            try:
                record = lock.snapshot()
            except CVEBeaconError:
                record = {"state": "unavailable", "dashboard": False, "elapsed": None}
            if record is not None:
                records.append(record)
        return records


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
    except (ImportError, KeyError, OSError, RuntimeError):
        return "unknown"


def _host_name() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


class Holder(str):
    """A printable holder that retains its bounded, parsed metadata."""

    def __new__(cls, description: str, record: dict):
        holder = super().__new__(cls, description)
        holder.record = record
        holder.dashboard = isinstance(record.get("dashboard_job"), int) and record["dashboard_job"] > 0
        return holder


def describe_holder(value: bytes | str | None) -> Holder | None:
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
    if isinstance(record.get("dashboard_job"), int) and record["dashboard_job"] > 0:
        parts.append(f"dashboard job {record['dashboard_job']}")
    return Holder(", ".join(parts), record) if parts else None


def _dead_local_pid(record: dict) -> bool:
    if os.name == "nt" or record.get("host") != _host_name():
        return False
    pid = record.get("pid")
    if not isinstance(pid, int) or not 0 < pid <= 2**31 - 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        pass
    return False


class RunLock:
    """A non-blocking exclusive file lock held for a data-changing run.

    The file is never removed, so a waiter cannot accidentally lock a
    different inode. Metadata is written only while the lock is held.
    """

    def __init__(self, path: str | Path, *, command: str | None = None):
        self.path = Path(path)
        self._owner_path: Path | None = None
        self._owner_identity: tuple[int, int] | None = None
        self._owner_descriptor: int | None = None
        # Only fixed labels may enter the record, never user arguments.
        labels = {"scan", "run", "web-detect", "web-detect --plan", "web-assets"}
        labels.update(f"watch {name}" for name in ("sync", "run", "evaluate", "notify", "report", "unreport"))
        self.command = command if command in labels else "run"
        self.holder: str | None = None
        self._descriptor: int | None = None

    @property
    def owner_path(self) -> Path:
        if self._owner_path is not None:
            return self._owner_path
        try:
            descriptor = self._open(create=False)
            try:
                token = self._token(self._inline(descriptor))
                if token is not None:
                    self._owner_path = owner_record_path(self.path, token)
            finally:
                os.close(descriptor)
        except (OSError, CVEBeaconError):
            pass
        return self._owner_path or owner_record_path(self.path)

    @staticmethod
    def _inline(descriptor: int) -> bytes:
        os.lseek(descriptor, 1, os.SEEK_SET)
        return os.read(descriptor, _METADATA_LIMIT)

    @staticmethod
    def _token(payload: bytes) -> str | None:
        try:
            token = json.loads(payload).get("owner_token")
        except (ValueError, AttributeError):
            return None
        if isinstance(token, str) and len(token) == 32 and all(char in "0123456789abcdef" for char in token):
            return token
        return None

    @staticmethod
    def _write(descriptor: int, payload: bytes) -> None:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if not count:
                raise OSError(errno.EIO, "short metadata write")
            written += count

    def _publish(self, metadata: dict) -> None:
        target = self.owner_path
        temporary = target.with_name(target.name + ".tmp")
        created = False
        descriptor = None
        try:
            descriptor = private_file(temporary, create=True, exclusive=True, share_delete=True)
            created = True
            self._owner_lock(descriptor)
            self._write(descriptor, json.dumps(metadata, ensure_ascii=False).encode("utf-8"))
            details = os.fstat(descriptor)
            identity = (details.st_dev, details.st_ino)
            # Unlike replace/rename, link refuses any pre-existing destination.
            # Only this acquisition's files are ever created or removed.
            os.link(temporary, target)
            self._owner_identity = identity
            self._owner_descriptor = descriptor
            descriptor = None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if created:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def _owner_lock(descriptor: int, *, probe=False, unlock=False) -> None:
        if os.name == "nt":  # pragma: no cover - exercised on Windows
            import msvcrt
            # Keep the lease outside the bounded JSON read range.
            os.lseek(descriptor, _METADATA_LIMIT, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK if unlock else msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            kind = fcntl.LOCK_UN if unlock else fcntl.LOCK_SH if probe else fcntl.LOCK_EX
            fcntl.flock(descriptor, kind | fcntl.LOCK_NB)
        os.lseek(descriptor, 0, os.SEEK_SET)

    def _owner_is_live(self, descriptor: int) -> bool:
        try:
            self._owner_lock(descriptor, probe=True)
        except OSError as exc:
            return _contention(exc)
        self._owner_lock(descriptor, unlock=True)
        return False

    def _close_owner(self) -> None:
        if self._owner_descriptor is not None:
            descriptor = self._owner_descriptor
            self._owner_descriptor = None
            os.close(descriptor)

    def _discard_partial_publication(self) -> None:
        """Rollback only this acquisition's linked files before a fallback."""
        self._close_owner()
        if self._owner_identity is not None:
            for path in (self.owner_path, self.owner_path.with_name(self.owner_path.name + ".tmp")):
                try:
                    details = path.lstat()
                except FileNotFoundError:
                    continue
                if (details.st_dev, details.st_ino) == self._owner_identity:
                    path.unlink()
            self._owner_identity = None

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
        self._owner_identity = None
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
            metadata["command"] = self.command
            job = dashboard_job_id()
            if job is not None:
                metadata["dashboard_job"] = job
            try:
                token = uuid.uuid4().hex
                self._owner_path = owner_record_path(self.path, token)
                details = os.fstat(descriptor)
                metadata.update(owner_token=token, lock_device=details.st_dev, lock_inode=details.st_ino)
                # Invalidate a predecessor before publishing this acquisition.
                # The shared inode contains only an opaque reference, no identity.
                reference = json.dumps({"owner_token": token}).encode("ascii")
                os.lseek(descriptor, 1, os.SEEK_SET)
                self._write(descriptor, reference)
                os.ftruncate(descriptor, len(reference) + 1)
                try:
                    self._publish(metadata)
                except OSError as exc:
                    optional = {errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOSYS,
                                getattr(errno, "ENOTSUP", errno.ENOSYS),
                                getattr(errno, "EOPNOTSUPP", errno.ENOSYS)}
                    if exc.errno not in optional and getattr(exc, "winerror", None) not in {1, 50, 120}:
                        raise
                    try:
                        self._discard_partial_publication()
                    except OSError as cleanup:
                        raise CVEBeaconError("cannot clean up the operation lock metadata") from cleanup
                    # Permissions or unsupported hard links must not block a
                    # normal run. No partial linked record may retain a lease.
            except OSError as exc:
                raise CVEBeaconError("cannot write the operation lock metadata") from exc
            self._descriptor = descriptor
            return True
        except BaseException:
            self._close_owner()
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
            if self._owner_identity is not None:
                details = self.owner_path.lstat()
                if (details.st_dev, details.st_ino) == self._owner_identity:
                    self.owner_path.unlink()
            self._close_owner()
            self._unlock(descriptor)
        except OSError:
            pass
        finally:
            # Drop the identity lease before the shared lock, including on
            # cleanup errors. A dead/released owner can never verify a successor.
            try:
                self._close_owner()
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _open(self, *, create: bool = True) -> int:
        try:
            if create:
                private_directory(self.path.parent)
            else:
                for parent in (self.path.parent, *self.path.parent.parents):
                    details = parent.lstat()
                    if not stat.S_ISDIR(details.st_mode) or getattr(details, "st_file_attributes", 0) & 0x400:
                        raise CVEBeaconError("operation storage directory must not be a link")
            # Windows byte-range probes require a writable descriptor, but
            # never create or write files while observing dashboard state.
            return private_file(self.path, create=create, readonly=not create and os.name != "nt", owner_only=False)
        except FileNotFoundError:
            if not create:
                raise
            raise CVEBeaconError("cannot open the run lock safely") from None
        except OSError as exc:
            raise CVEBeaconError("cannot open the run lock safely") from exc

    def _holder(self, descriptor: int, *, live=True) -> str:
        try:
            inline = self._inline(descriptor)
            token = self._token(inline)
            if token is None:
                # Legacy records have no acquisition lease. Even a live local
                # PID may have been reused since that record was written.
                if live:
                    return "holder unavailable"
                return describe_holder(inline) or "holder unavailable"
            path = owner_record_path(self.path, token)
            owner_fd = private_file(path, readonly=os.name != "nt", share_delete=True)
            try:
                if live and not self._owner_is_live(owner_fd):
                    return "holder unavailable"
                os.lseek(owner_fd, 0, os.SEEK_SET)
                holder = describe_holder(os.read(owner_fd, _METADATA_LIMIT))
            finally:
                os.close(owner_fd)
            details = os.fstat(descriptor)
            if (holder is not None and holder.record.get("owner_token") == token
                    and holder.record.get("lock_device") == details.st_dev
                    and holder.record.get("lock_inode") == details.st_ino
                    and self._inline(descriptor) == inline):
                return holder
        except (OSError, CVEBeaconError):
            pass
        return "holder unavailable"

    def snapshot(self) -> dict | None:
        """Observe existing storage without creating files or trusting orphans."""
        try:
            descriptor = self._open(create=False)
        except FileNotFoundError:
            return None
        self._probing = True
        acquired = False
        try:
            try:
                self._lock(descriptor)
                acquired = True
            except OSError as exc:
                if not _contention(exc):
                    raise CVEBeaconError("cannot probe the operation lock") from exc
            holder = self._holder(descriptor, live=not acquired)
            if acquired and not isinstance(holder, Holder):
                # A legacy private orphan may be shown only while the kernel
                # lock is free. It can never identify a live acquisition.
                try:
                    owner_fd = private_file(owner_record_path(self.path), readonly=True)
                    try:
                        holder = describe_holder(os.read(owner_fd, _METADATA_LIMIT))
                    finally:
                        os.close(owner_fd)
                except (OSError, CVEBeaconError):
                    return None
            if acquired and not isinstance(holder, Holder):
                return None
            record = dict(getattr(holder, "record", {}))
            state = ("stale" if _dead_local_pid(record) else "unknown") if acquired else "active"
            elapsed = None
            try:
                elapsed = max(0, int((datetime.now(timezone.utc) - datetime.fromisoformat(record["started_at"])).total_seconds()))
            except (KeyError, TypeError, ValueError):
                pass
            return {**record, "state": state, "description": str(holder), "elapsed": elapsed,
                    "dashboard": getattr(holder, "dashboard", False)}
        finally:
            if acquired:
                self._unlock(descriptor)
            self._probing = False
            os.close(descriptor)

    def probe(self) -> str | None:
        """Advisory nonblocking contention check; children take the real lock."""
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
