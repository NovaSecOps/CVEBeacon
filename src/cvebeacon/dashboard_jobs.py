"""Background jobs, persistent job history and the shared single-flight lock.

Dashboard operations run as short-lived children of the same ``cvebeacon``
command line, using the same configuration and exit codes. The child takes the
required storage locks itself; the dashboard probes them first to refuse a job
quickly when a scheduled or interactive run is already active.
"""

from __future__ import annotations

import os
import atexit
import queue
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import logging
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Callable, Iterable

from .config import AppConfig
from .errors import CVEBeaconError, ConfigurationError, StateError
from .locking import OperationLock, RunInProgress
from .private_storage import private_directory, private_file, validate_file
from .launching import command_prefix, child_environment
from .watch.users import _pin_database

LOG = logging.getLogger(__name__)
WORKER_RETRY_MAX_SECONDS = 5.0

JOB_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")
ACTIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})
MAX_JOBS = 200
MAX_PENDING_JOBS = 20
CANCEL_GRACE_SECONDS = 3.0
TERMINATE_GRACE_SECONDS = 2.0
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
WATCH_OPERATIONS = frozenset(RUN_OPERATIONS[1:-1]) | frozenset(RETRY_OPERATIONS) | {"notify-test"}

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
    audit_pending: str | None = None
    cancelled_by: str | None = None

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
        self.path = Path(path).absolute()
        self.log_directory = self.path.parent / "dashboard-jobs"

    def _connect(self) -> sqlite3.Connection:
        try:
            private_directory(self.path.parent)
            if os.name == "posix":
                # Process-lifetime pins avoid closing raw descriptors while
                # another SQLite connection holds POSIX record locks.
                descriptor, created = _pin_database(self.path, create=True)
                if created:
                    os.fchmod(descriptor, 0o600)
                validate_file(descriptor, self.path)
            else:
                descriptor = private_file(self.path, create=True)
            expected = os.fstat(descriptor)
            try:
                connection = sqlite3.connect(self.path, timeout=30)
                actual = self.path.lstat()
                if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                    connection.close()
                    raise StateError("dashboard job history was replaced while opening")
                validate_file(descriptor, self.path)
            finally:
                if os.name == "nt":
                    os.close(descriptor)
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
                "message TEXT, audit_pending TEXT, cancelled_by TEXT)"
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(dashboard_job)")}
            for column in ("audit_pending", "cancelled_by"):
                if column not in columns:
                    connection.execute(f"ALTER TABLE dashboard_job ADD COLUMN {column} TEXT")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS dashboard_action ("
                "id INTEGER PRIMARY KEY, action TEXT NOT NULL, actor TEXT NOT NULL, detail TEXT)"
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
            row["audit_pending"],
            row["cancelled_by"],
        )

    def initialize(self) -> None:
        with closing(self._connect()):
            pass

    def create(self, operation: str, started_by: str, argv: list[str]) -> Job:
        private_directory(self.log_directory)
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
                "DELETE FROM dashboard_job WHERE status IN ('succeeded','failed','cancelled') "
                "AND audit_pending IS NULL AND id NOT IN "
                "(SELECT id FROM dashboard_job WHERE status IN ('succeeded','failed','cancelled') "
                "ORDER BY id DESC LIMIT ?)",
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
        try:
            with closing(self._connect()) as db:
                return list(db.execute(sql, tuple(values)).fetchall())
        except (OSError, sqlite3.Error) as exc:
            raise StateError("cannot read dashboard job history") from exc

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
                "message=?,audit_pending='job_failed' WHERE status IN ('queued','running')",
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

    def cancel_queued(self, job_id: int, actor: str | None = None) -> bool:
        with closing(self._connect()) as db, db:
            cursor = db.execute(
                "UPDATE dashboard_job SET cancel_requested=1,status='cancelled',cancelled_by=?,"
                "ended_at=?,message=?,audit_pending='job_cancelled' WHERE id=? AND status='queued'",
                (
                    actor,
                    _utc_now(),
                    "Cancelled before the command started.",
                    job_id,
                ),
            )
            return cursor.rowcount == 1

    def request_cancel(self, job_id: int, actor: str | None = None) -> None:
        with closing(self._connect()) as db, db:
            db.execute(
                "UPDATE dashboard_job SET cancel_requested=1,cancelled_by=? WHERE id=?",
                (actor, job_id),
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
                "message=?,audit_pending=? WHERE id=?",
                (status, _utc_now(), exit_code, message, "job_" + status, job_id),
            )

    def log_tail(self, job: Job, limit: int = MAX_LOG_TAIL) -> str:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LOG_TAIL:
            raise ValueError("invalid log tail limit")
        try:
            path = Path(job.log_path)
            if path != self.log_directory / f"job-{job.id}.log":
                return ""
            private_directory(self.log_directory)
            descriptor = private_file(path, readonly=True)
            with os.fdopen(descriptor, "rb") as handle:
                size = os.fstat(handle.fileno()).st_size
                if size > limit:
                    handle.seek(size - limit)
                return handle.read(limit).decode("utf-8", "replace")
        except (OSError, StateError):
            return ""

    def pending_audits(self) -> list[tuple[Job, str]]:
        return [(self._job(row), row["audit_pending"]) for row in self._rows(
            "SELECT * FROM dashboard_job WHERE audit_pending IS NOT NULL")]

    def clear_audit(self, job_id: int) -> None:
        with closing(self._connect()) as db, db:
            db.execute("UPDATE dashboard_job SET audit_pending=NULL WHERE id=?", (job_id,))

    def queue_action(self, action: str, actor: str, detail: str | None) -> int:
        with closing(self._connect()) as db, db:
            return int(db.execute(
                "INSERT INTO dashboard_action(action,actor,detail) VALUES (?,?,?)",
                (action, actor, detail),
            ).lastrowid)

    def pending_actions(self):
        return self._rows("SELECT * FROM dashboard_action ORDER BY id")

    def clear_action(self, action_id: int) -> None:
        with closing(self._connect()) as db, db:
            db.execute("DELETE FROM dashboard_action WHERE id=?", (action_id,))


class _JobLog:
    """Capture through one checked descriptor, with bounded tail rotation."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        private_directory(self.path.parent)
        descriptor = private_file(self.path, create=True, exclusive=True)
        self._handle = os.fdopen(descriptor, "w+b", buffering=0)
        self._size = 0

    def write(self, chunk: bytes) -> None:
        if not chunk:
            return
        chunk = chunk[-MAX_LOG_BYTES:]
        if self._size + len(chunk) > MAX_LOG_BYTES:
            keep = MAX_LOG_BYTES - len(chunk)
            self._handle.seek(max(0, self._size - keep))
            tail = self._handle.read(keep)
            self._handle.seek(0)
            self._handle.write(tail)
            self._handle.truncate(len(tail))
            self._size = len(tail)
        self._handle.seek(self._size)
        self._handle.write(chunk)
        self._size += len(chunk)

    def close(self) -> None:
        self._handle.close()


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
            if any(Path(str(database) + suffix).exists() for suffix in ("-wal", "-journal")):
                return True
            with closing(sqlite3.connect(
                f"{database.resolve().as_uri()}?mode=ro&immutable=1", uri=True, timeout=0.1
            )) as db:
                metadata = dict(db.execute("SELECT key,value FROM watch_meta"))
        except (sqlite3.Error, OSError, ValueError):
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
        *command_prefix(),
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


def _windows_console_available() -> bool:
    import ctypes
    return bool(ctypes.windll.kernel32.GetConsoleCP())


class JobQueueFull(CVEBeaconError):
    """The bounded set of pending jobs is full."""


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
        self._audit_lock = threading.RLock()
        self._stopping = False
        self._cancel_deadline: float | None = None
        try:
            if self.store.pending_audits() or self.store.pending_actions():
                self.start_thread()
        except CVEBeaconError:
            pass

    def start_thread(self) -> None:
        with self._condition:
            if self._stopping or (self._thread is not None and self._thread.is_alive()):
                return
            self._thread = threading.Thread(
                target=self._loop,
                name="cvebeacon-dashboard-jobs",
                daemon=True,
            )
            self._thread.start()
            atexit.register(self.shutdown)

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
            holder = OperationLock(self.config, operation).probe()
            if holder is not None:
                raise RunInProgress(holder)
        with self._condition:
            if self._stopping:
                raise ConfigurationError("the dashboard is stopping")
            if len(self.store.active()) >= MAX_PENDING_JOBS:
                raise JobQueueFull("the job queue is full; wait for a job to finish")
            job = self.store.create(operation, started_by, argv)
            try:
                if audit:
                    self.users.record_action(
                        "job_started", username=started_by, actor=started_by,
                        detail=f"{job.id}:{job.operation}",
                    )
            except Exception:
                self.store.finish(
                    job.id, "failed", exit_code=None,
                    message="The job audit entry could not be recorded.",
                )
                raise
            self._queue.append(job.id)
            self._condition.notify_all()
        self.start_thread()
        return job

    def cancel(self, job_id: int, *, actor: str | None = None) -> bool:
        try:
            with self._condition:
                job = self.store.get(job_id)
                if job is None or not job.active:
                    return False
                self.users.record_action(
                    "job_cancel_requested", username=job.started_by,
                    actor=actor or job.started_by, detail=f"{job.id}:{job.operation}",
                )
                if self.store.cancel_queued(job_id, actor or job.started_by):
                    if job_id in self._queue:
                        self._queue.remove(job_id)
                    self._audit_finished(self.store.get(job_id), "job_cancelled")
                    self._condition.notify_all()
                    return True
                self.store.request_cancel(job_id, actor or job.started_by)
                process = self._process
                if self._running == job_id and process is not None and process.poll() is None:
                    if self._cancel_deadline is None:
                        self._cancel_deadline = time.monotonic() + CANCEL_GRACE_SECONDS
                        try:
                            self._interrupt(process)
                        except OSError:
                            pass
                self._condition.notify_all()
                return True
        except Exception:
            # An unavailable cancellation row must not prevent supervision of
            # an already running child. Preserve the error for the requester.
            with self._condition:
                process = self._process if self._running == job_id else None
            if process is not None:
                self._stop_process(process)
            raise

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
        try:
            self._work_loop()
        finally:
            with self._condition:
                if self._thread is threading.current_thread():
                    self._thread = None
                    atexit.unregister(self.shutdown)
                    self._condition.notify_all()

    def _work_loop(self) -> None:
        backoff = 0.5
        while True:
            with self._condition:
                if not self._queue and not self._stopping:
                    self._condition.wait(backoff)
                if self._stopping:
                    return
            try:
                audited = self.retry_audits()
                with self._condition:
                    if not self._queue:
                        if not self.store.pending_audits() and not self.store.pending_actions():
                            self._thread = None
                            atexit.unregister(self.shutdown)
                            return
                        backoff = 0.5 if audited else min(backoff * 2, WORKER_RETRY_MAX_SECONDS)
                        continue
                    if self._stopping:
                        return
                    # Keep the identifier queued until its initial read succeeds.
                    job_id = self._queue[0]
                    job = self.store.get(job_id)
                    self._queue.pop(0)
                backoff = 0.5
            except Exception:
                LOG.warning("Dashboard job storage is unavailable; retrying.")
                with self._condition:
                    if not self._stopping:
                        self._condition.wait(backoff)
                backoff = min(backoff * 2, WORKER_RETRY_MAX_SECONDS)
                continue
            try:
                if job is None or job.status != "queued":
                    continue
                if job.cancel_requested:
                    self.store.finish(
                        job_id, "cancelled", exit_code=None,
                        message="Cancelled before the command started.",
                    )
                    self._audit_finished(self.store.get(job_id), "job_cancelled")
                    continue
                self._run_job(job)
            except Exception:
                LOG.warning("The dashboard could not complete a job; retaining its stored outcome.")
                try:
                    job = self.store.get(job_id)
                    if job is not None and job.status in ACTIVE_STATUSES:
                        self.store.finish(
                            job_id, "failed", exit_code=None,
                            message="The dashboard could not run this job.",
                        )
                        self._audit_finished(self.store.get(job_id), "job_failed")
                except Exception:
                    LOG.warning("Job outcome storage is unavailable; restart recovery is required.")
            finally:
                with self._condition:
                    self._running = None
                    self._process = None
                    self._cancel_deadline = None
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
            holder = OperationLock(self.config, job.operation).probe()
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
        reader = None
        forced = False
        code: int | None = None
        chunks = queue.Queue(maxsize=16)
        reader_stop = threading.Event()

        def capture():
            try:
                while not reader_stop.is_set():
                    chunk = process.stdout.read(4096)
                    while not reader_stop.is_set():
                        try:
                            chunks.put(chunk, timeout=0.1)
                            break
                        except queue.Full:
                            pass
                    if not chunk:
                        return
            except Exception as exc:
                while not reader_stop.is_set():
                    try:
                        chunks.put(exc, timeout=0.1)
                        break
                    except queue.Full:
                        pass

        try:
            if os.name == "nt" and not _windows_console_available():
                raise ConfigurationError("background jobs require a Windows console for cooperative cancellation")
            with self._condition:
                if self._stopping:
                    return  # The queued row is retained for restart recovery.
                process = subprocess.Popen(
                    argv,
                    cwd=sys.prefix,
                    env=child_environment(self.config),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                    start_new_session=os.name != "nt",
                    creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
                )
                self._process = process
            reader = threading.Thread(target=capture, daemon=True)
            reader.start()
            output_done = False
            while True:
                current = self.store.get(job.id)
                with self._condition:
                    if (self._stopping or (current and current.cancel_requested)) and self._cancel_deadline is None:
                        self._cancel_deadline = time.monotonic() + CANCEL_GRACE_SECONDS
                        try:
                            self._interrupt(process)
                        except OSError:
                            pass
                    deadline = self._cancel_deadline
                if deadline is not None and time.monotonic() >= deadline and process.poll() is None:
                    forced = self._stop_process(process, interrupt=False)
                if output_done:
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                    continue
                try:
                    chunk = chunks.get(timeout=0.05)
                except queue.Empty:
                    continue
                if isinstance(chunk, Exception):
                    raise chunk
                if not chunk:
                    output_done = True
                    continue
                log.write(chunk)
            code = process.wait()
        finally:
            # Capture/store failures must not detach a child that still owns
            # monitoring state. Stop and reap before the worker clears it.
            if process is not None and process.poll() is None:
                forced = self._stop_process(process) or forced
            reader_stop.set()
            if process is not None and process.stdout is not None:
                process.stdout.close()
            if reader is not None:
                reader.join(timeout=1)
            log.close()
        current = self.store.get(job.id)
        requested = bool(current and current.cancel_requested)
        if requested or code == 130:
            status = "cancelled"
            message = (
                "Cancellation required forced termination; cleanup is not confirmed."
                if forced else "Cancelled by interrupt; the command had an opportunity to run cleanup."
            )
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

    @classmethod
    def _stop_process(cls, process, *, interrupt=True) -> bool:
        if process.poll() is not None:
            process.wait()
            return False
        if interrupt:
            try:
                cls._interrupt(process)
            except OSError:
                pass
            try:
                process.wait(timeout=CANCEL_GRACE_SECONDS)
                return False
            except subprocess.TimeoutExpired:
                pass
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return True

    def shutdown(self) -> None:
        """Reap children even when queued cancellation cannot be persisted.

        Rows whose cancellation fails remain durable; the next dashboard
        startup marks them interrupted rather than executing them again.
        """
        with self._condition:
            self._stopping = True
            queued = self._queue[:]
            self._queue.clear()
            self._condition.notify_all()
            thread = self._thread
        try:
            for job_id in queued:
                try:
                    self.store.cancel_queued(job_id)
                except Exception:
                    LOG.warning("Queued cancellation could not be stored; restart recovery is required.")
        finally:
            # No bookkeeping or worker read is allowed to bypass supervision.
            with self._condition:
                process = self._process
                if process is not None and process.poll() is None:
                    if self._cancel_deadline is None:
                        self._cancel_deadline = time.monotonic() + CANCEL_GRACE_SECONDS
                        try:
                            self._interrupt(process)
                        except OSError:
                            pass
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=CANCEL_GRACE_SECONDS + TERMINATE_GRACE_SECONDS + 2)
            if process is not None and process.poll() is None:
                self._stop_process(process, interrupt=False)
            self.retry_audits()

    def _audit_finished(self, job: Job | None, action: str) -> bool:
        if job is None:
            return True
        with self._audit_lock:
            try:
                current = self.store.get(job.id)
                if current is None or current.audit_pending != action:
                    return True
                self.users.record_action(
                    action, username=job.started_by,
                    actor=(current.cancelled_by or job.started_by) if action == "job_cancelled" else job.started_by,
                    detail=f"{job.id}:{job.operation}",
                )
                self.store.clear_audit(job.id)
                return True
            except Exception:
                # State and pending action are durable; retain the row/log.
                LOG.warning("A job outcome audit could not be recorded; retrying.")
                return False

    def audit_action(self, action: str, actor: str, detail: str | None = None) -> None:
        try:
            with self._audit_lock:
                action_id = self.store.queue_action(action, actor, detail)
                self.users.record_action(action, username=actor, actor=actor, detail=detail)
                self.store.clear_action(action_id)
        finally:
            self.start_thread()

    def retry_audits(self) -> bool:
        complete = True
        with self._audit_lock:
            try:
                actions = self.store.pending_actions()
                audits = self.store.pending_audits()
            except Exception:
                LOG.warning("Pending operation audits could not be read; retrying.")
                return False
            for row in actions:
                try:
                    self.users.record_action(
                        row["action"], username=row["actor"], actor=row["actor"], detail=row["detail"]
                    )
                    self.store.clear_action(row["id"])
                except Exception:
                    LOG.warning("An operation audit could not be recorded; retrying.")
                    complete = False
            for job, action in audits:
                if not self._audit_finished(job, action):
                    complete = False
        return complete
