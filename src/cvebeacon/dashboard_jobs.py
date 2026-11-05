"""Background jobs, persistent job history and the shared single-flight lock.

Dashboard operations run as short-lived children of the same ``cvebeacon``
command line, using the same configuration and exit codes. The child takes the
shared run lock itself; the dashboard only probes it first to refuse a job
quickly when a scheduled or interactive run is already active.
"""

from __future__ import annotations

import os
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from typing import Callable, Iterable

from .config import AppConfig
from .errors import CVEBeaconError, ConfigurationError, StateError
from .locking import RunInProgress, RunLock, run_lock_path
from .watch.directories import ensure_private_directory
from .watch.store import WatchStore

JOB_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")
ACTIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})
MAX_JOBS = 200
MAX_HISTORY = MAX_JOBS
MAX_LOG_BYTES = 128 * 1024
MAX_LOG_TAIL = 16 * 1024

RUN_OPERATIONS = (
    "scan",
    "watch-sync",
    "watch-evaluate",
    "watch-notify",
    "watch-run",
    "run",
)
RETRY_OPERATIONS = ("watch-retry-failed", "watch-retry-ambiguous")
FULL_HISTORY_OPERATIONS = frozenset({"watch-sync", "watch-run", "run"})
WATCH_OPERATIONS = frozenset(RUN_OPERATIONS[1:]) | frozenset(RETRY_OPERATIONS)

OPERATION_LABELS = {
    "scan": "Scan inventory",
    "watch-sync": "Synchronise watch data",
    "watch-evaluate": "Evaluate every stored CVE",
    "watch-notify": "Deliver pending alerts",
    "watch-retry-failed": "Retry failed deliveries",
    "watch-retry-ambiguous": "Retry ambiguous deliveries",
    "watch-run": "Watch run",
    "run": "Run scan and watch together",
    "notify-test": "Send channel test",
}

DATA_CHANGING = frozenset(
    operation for operation in OPERATION_LABELS if operation != "notify-test"
)

EXIT_MEANINGS = {
    0: "Completed",
    1: "Cancelled or a required confirmation was refused",
    2: "Validation or operational failure",
    3: "Notification delivery failure",
    4: "Completed with uncertain coverage or degraded sources",
    5: "Completed with degraded optional operations",
    75: "Another run was in progress",
    130: "Cancelled by an interrupt",
    143: "Terminated after cleanup",
}


def exit_meaning(code: int | None) -> str:
    if code is None:
        return "Not finished"
    if code < 0:
        return f"Terminated by signal {-code}"
    return EXIT_MEANINGS.get(code, "Unrecognised exit code")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True, slots=True)
class Job:
    id: int
    operation: str
    status: str
    started_by: str
    created_at: str
    started_at: str | None
    ended_at: str | None
    exit_code: int | None
    cancel_requested: bool
    log_path: str
    message: str | None
    argv: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return OPERATION_LABELS.get(self.operation, self.operation)

    @property
    def active(self) -> bool:
        return self.status in ACTIVE_STATUSES

    @property
    def exit_meaning(self) -> str:
        return exit_meaning(self.exit_code)


class JobStore:
    """A small owner-only SQLite file for the last ``MAX_JOBS`` jobs."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.log_directory = self.path.parent / "dashboard-jobs"

    def _connect(self) -> sqlite3.Connection:
        try:
            ensure_private_directory(self.path.parent)
            if not self.path.exists():
                try:
                    descriptor = os.open(
                        self.path,
                        os.O_CREAT
                        | os.O_EXCL
                        | os.O_RDWR
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_BINARY", 0),
                        0o600,
                    )
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
            elif os.name == "posix":
                details = os.stat(self.path, follow_symlinks=False)
                if not stat.S_ISREG(details.st_mode):
                    raise StateError("dashboard job history must be a regular file")
                if details.st_uid != os.geteuid():
                    raise StateError(
                        "dashboard job history must be owned by this account"
                    )
                if stat.S_IMODE(details.st_mode) & 0o077:
                    os.chmod(self.path, 0o600)
            connection = sqlite3.connect(self.path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA temp_store = MEMORY")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS dashboard_job ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "operation TEXT NOT NULL,"
                "status TEXT NOT NULL,"
                "started_by TEXT NOT NULL,"
                "created_at TEXT NOT NULL,"
                "started_at TEXT,"
                "ended_at TEXT,"
                "exit_code INTEGER,"
                "cancel_requested INTEGER NOT NULL DEFAULT 0,"
                "log_path TEXT NOT NULL,"
                "argv TEXT NOT NULL,"
                "message TEXT)"
            )
            connection.commit()
            return connection
        except (OSError, sqlite3.Error) as exc:
            raise StateError(
                f"cannot open dashboard job history {self.path}: {exc}"
            ) from exc

    @staticmethod
    def _job(row: sqlite3.Row) -> Job:
        try:
            argv = tuple(json.loads(row["argv"] or "[]"))
        except (TypeError, ValueError):
            argv = ()
        return Job(
            int(row["id"]),
            str(row["operation"]),
            str(row["status"]),
            str(row["started_by"]),
            str(row["created_at"]),
            row["started_at"],
            row["ended_at"],
            None if row["exit_code"] is None else int(row["exit_code"]),
            bool(row["cancel_requested"]),
            str(row["log_path"]),
            row["message"],
            argv,
        )

    def initialize(self) -> None:
        with closing(self._connect()):
            pass

    def create(self, operation: str, started_by: str, argv: list[str]) -> Job:
        ensure_private_directory(self.log_directory)
        with closing(self._connect()) as db, db:
            cursor = db.execute(
                "INSERT INTO dashboard_job("
                "operation,status,started_by,created_at,started_at,"
                "cancel_requested,log_path,argv) VALUES (?,?,?,?,?,0,'',?)",
                (
                    operation,
                    "queued",
                    started_by,
                    _utc_now(),
                    None,
                    json.dumps(list(argv), ensure_ascii=False),
                ),
            )
            job_id = int(cursor.lastrowid)
            log_path = self.log_directory / f"job-{job_id}.log"
            db.execute(
                "UPDATE dashboard_job SET log_path=? WHERE id=?",
                (str(log_path), job_id),
            )
            db.execute(
                "DELETE FROM dashboard_job WHERE id NOT IN "
                "(SELECT id FROM dashboard_job ORDER BY id DESC LIMIT ?)",
                (MAX_JOBS,),
            )
            row = db.execute(
                "SELECT * FROM dashboard_job WHERE id=?", (job_id,)
            ).fetchone()
        self._remove_orphans()
        return self._job(row)

    def _remove_orphans(self) -> None:
        try:
            known = {
                Path(row[0]).name
                for row in self._rows("SELECT log_path FROM dashboard_job")
                if row[0]
            }
            for path in self.log_directory.glob("job-*.log"):
                if path.name not in known:
                    try:
                        path.unlink()
                    except OSError:
                        pass
        except (OSError, StateError):
            pass

    def _rows(self, sql: str, values: Iterable = ()) -> list[sqlite3.Row]:
        with closing(self._connect()) as db:
            return list(db.execute(sql, tuple(values)).fetchall())

    def get(self, job_id: int) -> Job | None:
        rows = self._rows("SELECT * FROM dashboard_job WHERE id=?", (job_id,))
        return self._job(rows[0]) if rows else None

    def recent(self, limit: int = MAX_HISTORY) -> tuple[Job, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_JOBS:
            raise ValueError("invalid job history limit")
        return tuple(
            self._job(row)
            for row in self._rows(
                "SELECT * FROM dashboard_job ORDER BY id DESC LIMIT ?", (limit,)
            )
        )

    def active(self) -> tuple[Job, ...]:
        return tuple(
            self._job(row)
            for row in self._rows(
                "SELECT * FROM dashboard_job WHERE status IN ('queued','running') "
                "ORDER BY id"
            )
        )

    def fail_interrupted(self) -> int:
        """Mark jobs abandoned by a previous dashboard process as failed."""
        with closing(self._connect()) as db, db:
            cursor = db.execute(
                "UPDATE dashboard_job SET status='failed',ended_at=?,"
                "message=? WHERE status IN ('queued','running')",
                (
                    _utc_now(),
                    "The dashboard stopped before this job finished.",
                ),
            )
            return cursor.rowcount

    def mark_running(self, job_id: int) -> bool:
        with closing(self._connect()) as db, db:
            cursor = db.execute(
                "UPDATE dashboard_job SET status='running',started_at=? "
                "WHERE id=? AND status='queued'",
                (_utc_now(), job_id),
            )
            return cursor.rowcount == 1

    def cancel_queued(self, job_id: int) -> bool:
        with closing(self._connect()) as db, db:
            cursor = db.execute(
                "UPDATE dashboard_job SET cancel_requested=1,status='cancelled',"
                "ended_at=?,message=? WHERE id=? AND status='queued'",
                (
                    _utc_now(),
                    "Cancelled before the command started.",
                    job_id,
                ),
            )
            return cursor.rowcount == 1

    def request_cancel(self, job_id: int) -> None:
        with closing(self._connect()) as db, db:
            db.execute(
                "UPDATE dashboard_job SET cancel_requested=1 WHERE id=?",
                (job_id,),
            )

    def finish(
        self,
        job_id: int,
        status: str,
        *,
        exit_code: int | None,
        message: str | None = None,
    ) -> None:
        if status not in TERMINAL_STATUSES:
            raise ValueError("invalid terminal job status")
        with closing(self._connect()) as db, db:
            db.execute(
                "UPDATE dashboard_job SET status=?,ended_at=?,exit_code=?,"
                "message=? WHERE id=?",
                (status, _utc_now(), exit_code, message, job_id),
            )

    def log_tail(self, job: Job, limit: int = MAX_LOG_TAIL) -> str:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LOG_TAIL:
            raise ValueError("invalid log tail limit")
        try:
            path = Path(job.log_path)
            size = path.stat().st_size
            with path.open("rb") as handle:
                if size > limit:
                    handle.seek(size - limit)
                return handle.read(limit).decode("utf-8", "replace")
        except OSError:
            return ""


class _JobLog:
    """Append output while keeping one job's log within a fixed bound."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        ensure_private_directory(self.path.parent)
        self._handle = self.path.open("ab", buffering=0)
        if os.name == "posix":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        self._size = self.path.stat().st_size

    def write(self, chunk: bytes) -> None:
        if not chunk:
            return
        self._handle.write(chunk)
        self._size += len(chunk)
        if self._size > MAX_LOG_BYTES:
            self._handle.close()
            data = self.path.read_bytes()
            self.path.write_bytes(data[-MAX_LOG_BYTES:])
            self._size = min(len(data), MAX_LOG_BYTES)
            self._handle = self.path.open("ab", buffering=0)

    def close(self) -> None:
        try:
            self._handle.close()
        except OSError:
            pass


def channel_names(config: AppConfig) -> tuple[str, ...]:
    return tuple(channel.name for channel in config.watch.channels)


def full_history_confirmation_required(config: AppConfig) -> bool:
    """Whether the next sync would start the CLI's full-history path."""
    if not config.watch.enabled:
        return False
    database = Path(config.watch.database)
    metadata: dict[str, str] = {}
    if database.is_file():
        try:
            metadata = WatchStore(database).metadata()
        except CVEBeaconError:
            # A corrupt or unreadable store cannot be inspected safely; make
            # the operator confirm rather than silently passing --yes.
            return True
    first_run = "initialized_at" not in metadata
    if not first_run:
        return False
    mode = metadata.get("initial_mode") or config.watch.initial
    return mode == "full" and metadata.get("nvd_cursor") is None


def build_command(
    config: AppConfig,
    operation: str,
    *,
    confirmed: bool = False,
    channel: str | None = None,
) -> list[str]:
    """Build the CLI child command without a shell or any secret value."""
    if operation not in OPERATION_LABELS:
        raise ConfigurationError("unknown operation")
    if operation in WATCH_OPERATIONS and not config.watch.enabled:
        raise ConfigurationError("watch mode is disabled; set [watch] enabled = true")
    if operation == "scan" and config.inventory is None:
        raise ConfigurationError(
            "this configuration has no inventory; scans cannot run"
        )
    if operation == "run" and config.inventory is None and not config.watch.enabled:
        raise ConfigurationError(
            "nothing to run; add an [inventory] path or set [watch] enabled = true"
        )
    base = [
        sys.executable,
        "-m",
        "cvebeacon",
        "--config",
        str(config.config_path),
    ]
    if operation == "scan":
        return [*base, "scan"]
    if operation == "watch-sync":
        args = [*base, "watch", "sync"]
    elif operation == "watch-evaluate":
        args = [*base, "watch", "evaluate", "--all", "--yes"]
    elif operation == "watch-notify":
        args = [*base, "watch", "notify"]
    elif operation == "watch-retry-failed":
        args = [*base, "watch", "notify", "--retry-failed"]
    elif operation == "watch-retry-ambiguous":
        args = [*base, "watch", "notify", "--retry-ambiguous"]
    elif operation == "watch-run":
        args = [*base, "watch", "run"]
    elif operation == "run":
        args = [*base, "run"]
    elif operation == "notify-test":
        if channel not in channel_names(config):
            raise ConfigurationError("unknown watch channel")
        return [*base, "watch", "notify", "test", channel]
    else:  # pragma: no cover - guarded by the operation check above
        raise ConfigurationError("unknown operation")
    if operation in FULL_HISTORY_OPERATIONS and full_history_confirmation_required(config):
        if not confirmed:
            raise ConfigurationError(
                "full-history confirmation is required before this operation"
            )
        args.append("--yes")
    return args


class JobManager:
    """Serialize dashboard jobs and keep their persistent state current."""

    def __init__(
        self,
        config: AppConfig,
        users,
        *,
        store: JobStore | None = None,
        command_builder: Callable[..., list[str]] = build_command,
    ):
        self.config = config
        self.users = users
        self.store = store or JobStore(
            Path(config.database_path).parent / "dashboard-jobs.db"
        )
        self.command_builder = command_builder
        try:
            self.store.fail_interrupted()
        except CVEBeaconError:
            # A missing or read-only state directory is reported when an
            # operations page or job is requested.
            pass
        self._condition = threading.Condition()
        self._queue: list[int] = []
        self._thread: threading.Thread | None = None
        self._process: subprocess.Popen | None = None
        self._running: int | None = None

    def start_thread(self) -> None:
        with self._condition:
            if self._thread is not None:
                return
            self._thread = threading.Thread(
                target=self._loop,
                name="cvebeacon-dashboard-jobs",
                daemon=True,
            )
            self._thread.start()

    def submit(
        self,
        operation: str,
        *,
        started_by: str,
        argv: list[str],
        audit: bool = True,
    ) -> Job:
        if operation not in OPERATION_LABELS:
            raise ConfigurationError("unknown operation")
        if operation in DATA_CHANGING:
            holder = RunLock(
                run_lock_path(self.config), command=operation
            ).probe()
            if holder is not None:
                raise RunInProgress(holder)
        job = self.store.create(operation, started_by, argv)
        try:
            if audit:
                self.users.record_action(
                    "job_started", username=started_by, actor=started_by
                )
        except Exception:
            self.store.finish(
                job.id,
                "failed",
                exit_code=None,
                message="The job audit entry could not be recorded.",
            )
            raise
        with self._condition:
            self._queue.append(job.id)
            self._condition.notify_all()
        self.start_thread()
        return job

    def cancel(self, job_id: int) -> bool:
        job = self.store.get(job_id)
        if job is None:
            return False
        if job.status == "queued":
            if self.store.cancel_queued(job_id):
                self._audit_finished(self.store.get(job_id), "job_cancelled")
                with self._condition:
                    self._condition.notify_all()
                return True
            job = self.store.get(job_id)
            if job is None:
                return False
        if job.status != "running":
            return False
        self.store.request_cancel(job_id)
        with self._condition:
            process = self._process
            running = self._running == job_id
        if running and process is not None and process.poll() is None:
            try:
                self._interrupt(process)
            except OSError:
                # The process may have exited between the check and the send.
                pass
        return True

    @staticmethod
    def _interrupt(process: subprocess.Popen) -> None:
        if os.name == "nt":  # pragma: no cover - exercised on Windows
            process.send_signal(signal.CTRL_BREAK_EVENT)
            return
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            process.send_signal(signal.SIGINT)

    def wait(
        self,
        job_id: int,
        *,
        timeout: float = 10.0,
        statuses: frozenset[str] = TERMINAL_STATUSES,
    ) -> Job | None:
        deadline = time.monotonic() + timeout
        while True:
            job = self.store.get(job_id)
            if job is not None and job.status in statuses:
                return job
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return job
            with self._condition:
                self._condition.wait(min(0.05, remaining))

    def _loop(self) -> None:
        while True:
            with self._condition:
                while not self._queue:
                    self._condition.wait()
                job_id = self._queue.pop(0)
            try:
                job = self.store.get(job_id)
                if job is None or job.status != "queued":
                    continue
                if job.cancel_requested:
                    self.store.finish(
                        job_id,
                        "cancelled",
                        exit_code=None,
                        message="Cancelled before the command started.",
                    )
                    self._audit_finished(self.store.get(job_id), "job_cancelled")
                    continue
                self._run_job(job)
            except Exception:
                try:
                    job = self.store.get(job_id)
                    if job is not None and job.status in ACTIVE_STATUSES:
                        self.store.finish(
                            job_id,
                            "failed",
                            exit_code=None,
                            message="The dashboard could not run this job.",
                        )
                        self._audit_finished(self.store.get(job_id), "job_failed")
                except Exception:
                    pass
            finally:
                with self._condition:
                    self._running = None
                    self._process = None
                    self._condition.notify_all()

    def _run_job(self, job: Job) -> None:
        argv = list(job.argv)
        if not argv:
            self.store.finish(
                job.id,
                "failed",
                exit_code=None,
                message="The job has no command.",
            )
            self._audit_finished(self.store.get(job.id), "job_failed")
            return
        if job.operation in DATA_CHANGING:
            holder = RunLock(
                run_lock_path(self.config), command=job.operation
            ).probe()
            if holder is not None:
                self.store.finish(
                    job.id,
                    "failed",
                    exit_code=None,
                    message=f"Another run is in progress ({holder}).",
                )
                self._audit_finished(self.store.get(job.id), "job_failed")
                return
        if not self.store.mark_running(job.id):
            # A queued cancel won the race before the worker started it.
            return
        with self._condition:
            self._running = job.id
        log = _JobLog(job.log_path)
        process = None
        code: int | None = None
        try:
            process = subprocess.Popen(
                argv,
                cwd=str(Path(self.config.config_path).parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                start_new_session=os.name != "nt",
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP
                    if os.name == "nt"
                    else 0
                ),
            )
            with self._condition:
                self._process = process
            current = self.store.get(job.id)
            if current is not None and current.cancel_requested:
                self._interrupt(process)
            assert process.stdout is not None
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                log.write(chunk)
            code = process.wait()
        finally:
            log.close()
            if process is not None and process.stdout is not None:
                try:
                    process.stdout.close()
                except OSError:
                    pass
        current = self.store.get(job.id)
        requested = bool(current and current.cancel_requested)
        if requested or code == 130:
            status = "cancelled"
            message = "Cancelled by request; the command ran its own cleanup."
        elif code == 0:
            status = "succeeded"
            message = None
        else:
            status = "failed"
            message = exit_meaning(code)
        self.store.finish(job.id, status, exit_code=code, message=message)
        self._audit_finished(
            self.store.get(job.id),
            {
                "succeeded": "job_succeeded",
                "cancelled": "job_cancelled",
                "failed": "job_failed",
            }[status],
        )

    def _audit_finished(self, job: Job | None, action: str) -> None:
        if job is None:
            return
        try:
            self.users.record_action(
                action, username=job.started_by, actor=job.started_by
            )
        except Exception:
            # Job state is already durable; a vanished account store must not
            # turn a completed job into a failed one.
            pass
