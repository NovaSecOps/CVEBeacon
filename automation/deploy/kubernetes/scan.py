"""Run the scanner and atomically publish a consistent notifier-only SQLite copy."""

import os
from pathlib import Path
import signal
import sqlite3
import sys
import tempfile
import time

from cvebeacon_automation.cli import main as automation
from cvebeacon_automation.common import AutomationError, lock, regular


MAX_DATABASE = 256 * 1024 * 1024


def snapshot(source: Path, destination: Path):
    if source.absolute() == destination.absolute() or source.parent.absolute() != destination.parent.absolute():
        raise AutomationError("notification_snapshot_path_invalid")
    regular(source)
    if source.stat().st_size > MAX_DATABASE:
        raise AutomationError("notification_snapshot_capacity")
    if destination.exists() or destination.is_symlink():
        regular(destination)
    deadline = time.monotonic() + 30
    page_size = 65536
    def progress(status, remaining, total):
        if time.monotonic() > deadline or total * page_size > MAX_DATABASE:
            raise AutomationError("notification_snapshot_budget")
    descriptor, temporary = tempfile.mkstemp(prefix=".notification-copy-", suffix=".sqlite3", dir=source.parent)
    os.close(descriptor)
    pending = Path(temporary)
    try:
        with lock(source.with_name(source.name + ".automation.lock")):
            reader = sqlite3.connect(source.absolute().as_uri() + "?mode=ro", uri=True, timeout=2)
            writer = sqlite3.connect(pending, timeout=2)
            try:
                reader.execute("PRAGMA query_only=ON")
                reader.execute("PRAGMA trusted_schema=OFF")
                page_size = reader.execute("PRAGMA page_size").fetchone()[0]
                writer.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                reader.execute("BEGIN")
                version = reader.execute("SELECT version FROM schema_info LIMIT 2").fetchall()
                if version != [(3,)]:
                    raise AutomationError("unsupported_core_schema")
                reader.backup(writer, pages=256, progress=progress, sleep=0.05)
                # This changes only the independent copy, never the live Core database.
                assert writer.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
                assert writer.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                writer.commit()
            finally:
                writer.close()
                reader.close()
        regular(pending)
        if pending.stat().st_size > MAX_DATABASE:
            raise AutomationError("notification_snapshot_capacity")
        with pending.open("r+b") as handle:
            os.fsync(handle.fileno())
        os.replace(pending, destination)
        if os.name == "posix":
            descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        # Remove only this call's unpublished temporary copy, never prior state.
        pending.unlink(missing_ok=True)


def main():
    code = automation(["--config", "/config/scan.toml", "run", *sys.argv[1:]])
    if code:
        return code
    try:
        snapshot(Path("/core-state/core.db"), Path("/core-state/notification-core.db"))
    except (AutomationError, OSError, sqlite3.Error, ValueError):
        print("automation error: notification_snapshot_unavailable", file=sys.stderr)
        return 2
    print("consistent notification database copy published", flush=True)
    return 0


if __name__ == "__main__":
    def terminated(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminated)
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(143)
