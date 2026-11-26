"""Unprivileged, durable SQLite snapshots and independently verified restore."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import time

from .config import load_config
from .errors import CVEBeaconError
from .inventory_journal import recover, remove_file
from .managed_inventory import is_managed_file
from .private_storage import private_directory, private_file
from .publication import replace_file
from .snapshot import (
    SnapshotError,
    copy_sqlite as _copy_sqlite,
    digest,
    logical_digest,
    sync_directory,
    sync_file,
)
from .state import StateStore
from .watch.store import WatchStore
from .watch.users import UserStore
from .web_assets import replace_bytes
from .web_inventory import read_bytes


MAX_MANAGED_FILES = 20_000
BACKUP_BUSY_WAIT_SECONDS = 30.0


class BackupDatabaseBusy(SnapshotError):
    """A database remained locked for the bounded update-backup wait."""


BACKUP_RETRY_SECONDS = 0.05
BACKUP_BATCH_PAGES = 128


def _sqlite_busy(code):
    return isinstance(code, int) and (code & 0xFF) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


class _BusyWait:
    def __init__(self, wait_seconds):
        self.wait_seconds = wait_seconds
        self.since = None

    def retry(self):
        now = time.monotonic()
        if self.since is None:
            self.since = now
        if now - self.since >= self.wait_seconds:
            raise BackupDatabaseBusy("database remained busy during backup")

    def run(self, operation):
        while True:
            try:
                return operation()
            except sqlite3.OperationalError as exc:
                if not _sqlite_busy(getattr(exc, "sqlite_errorcode", None)):
                    raise
                self.retry()
                time.sleep(BACKUP_RETRY_SECONDS)

    def progress(self, code, remaining, total):
        if _sqlite_busy(code):
            self.retry()
        elif code in {sqlite3.SQLITE_OK, sqlite3.SQLITE_DONE}:
            self.since = None


def _backup_copy_worker(source, destination, *, wait_seconds):
    """Bound continuous SQLite contention at the point of retry."""
    source, destination = Path(source), Path(destination)
    src = _BusyWait(wait_seconds).run(
        lambda: sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=BACKUP_RETRY_SECONDS)
    )
    with closing(src):
        dst = _BusyWait(wait_seconds).run(
            lambda: sqlite3.connect(destination, timeout=BACKUP_RETRY_SECONDS)
        )
        with closing(dst):
            wait = _BusyWait(wait_seconds)
            # A surfaced BUSY/LOCKED ends this backup handle. Retrying against
            # the private destination is safe and shares the callback's clock.
            wait.run(lambda: src.backup(dst, pages=BACKUP_BATCH_PAGES,
                                        progress=wait.progress, sleep=BACKUP_RETRY_SECONDS))
            integrity = _BusyWait(wait_seconds).run(lambda: dst.execute("PRAGMA integrity_check").fetchone())
            if integrity[0] != "ok":
                raise SnapshotError("SQLite snapshot integrity check failed")
    destination.chmod(0o600)
    sync_file(destination)


def _copy_sqlite_bounded(source, destination, *, wait_seconds=BACKUP_BUSY_WAIT_SECONDS):
    """Use a separate process so SQLite file closes cannot release caller locks."""
    process = subprocess.run(
        [sys.executable, "-I", "-m", "cvebeacon.update_state", "--backup-copy",
         str(source), str(destination), str(wait_seconds)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C.UTF-8"},
        cwd=Path.cwd(),
    )
    if process.returncode == 75:
        raise BackupDatabaseBusy("database remained busy during backup")
    if process.returncode:
        raise SnapshotError("SQLite snapshot operation failed")


def databases(config, data, *, validate_known=True):
    data = Path(data).resolve(strict=True)
    paths = {config.database_path, config.watch.database, config.watch.users_database}
    for path in paths:
        if not path.resolve().is_relative_to(data):
            raise SnapshotError("all state databases must be inside the configured data directory")
    count = 0
    for parent, directories, files in os.walk(data, followlinks=False):
        for name in directories + files:
            count += 1
            if count > 20000:
                raise SnapshotError("data directory exceeds the update snapshot entry limit")
            if (Path(parent) / name).is_symlink():
                raise SnapshotError("data directory must not contain symbolic links")
        for name in files:
            path = Path(parent) / name
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SnapshotError("data directory contains a non-regular or linked file")
            if path in paths and not validate_known:
                continue
            try:
                with path.open("rb") as stream:
                    header = stream.read(16)
            except PermissionError:
                if path in paths:
                    raise SnapshotError("a configured state database is unreadable") from None
                continue  # Environment/secret files need not be readable to discover state.
            if header == b"SQLite format 3\x00":
                paths.add(path)
            elif path in paths and info.st_size:
                raise SnapshotError("a configured state database is not SQLite")
    return tuple(sorted(paths))


def _manifest(source, data):
    with (source / "manifest.json").open("rb") as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise SnapshotError("snapshot manifest exceeds the size limit")
    manifest = json.loads(raw)
    if manifest.get("format") != 1 or not isinstance(manifest.get("databases"), list):
        raise SnapshotError("invalid snapshot manifest")
    seen = set()
    for row in manifest["databases"]:
        relative = Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or row["path"] in seen:
            raise SnapshotError("invalid restore path")
        if not (data / relative).resolve().is_relative_to(data):
            raise SnapshotError("restore path is outside data")
        if Path(row["backup"]).name != row["backup"]:
            raise SnapshotError("invalid snapshot filename")
        seen.add(row["path"])
    return manifest



def _managed_files(config):
    directory = config.inventory_directory
    try:
        files = sorted(path for path in directory.iterdir() if is_managed_file(path)
                       and (config.inventory is None or config.inventory.path != path))
    except (FileNotFoundError, NotADirectoryError):
        return []
    if files:
        private_directory(directory, owner_only=True)
    return files


def _managed_snapshot(config, destination):
    recover(config.inventory_directory, config.watch.users_database)
    files = _managed_files(config)
    if len(files) > MAX_MANAGED_FILES:
        raise SnapshotError("managed inventory snapshot exceeds the file count limit")
    items = []
    for index, path in enumerate(files):
        saved = f"inventory-{index}.copy"
        payload = read_bytes(path)
        replace_bytes(destination / saved, payload)
        items.append({"name": path.name, "backup": saved, "sha256": hashlib.sha256(payload).hexdigest()})
    return items


def _managed_entries(config, source, manifest):
    if "managed_inventories" not in manifest:
        return None  # Snapshots written by earlier releases.
    items = manifest["managed_inventories"]
    if not isinstance(items, list) or len(items) > MAX_MANAGED_FILES:
        raise SnapshotError("invalid managed inventory snapshot")
    files = {}
    blobs = set()
    for item in items:
        if not isinstance(item, dict) or item.keys() != {"name", "backup", "sha256"}:
            raise SnapshotError("invalid managed inventory snapshot entry")
        name, saved, checksum = item["name"], item["backup"], item["sha256"]
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise SnapshotError("invalid managed inventory snapshot checksum")
        if (not isinstance(name, str) or Path(name).name != name or not is_managed_file(Path(name))
                or name in files or not isinstance(saved, str) or not re.fullmatch(r"inventory-[0-9]+\.copy", saved)
                or saved in blobs):
            raise SnapshotError("invalid managed inventory snapshot filename")
        target = config.inventory_directory / name
        if config.inventory is not None and target == config.inventory.path:
            raise SnapshotError("managed inventory snapshot overlaps the configured inventory")
        _verified_managed_bytes(source, saved, checksum)
        files[name] = (saved, checksum)
        blobs.add(saved)
    return files


def _verified_managed_bytes(source, saved, expected):
    payload = read_bytes(source / saved)
    if hashlib.sha256(payload).hexdigest() != expected:
        raise SnapshotError("managed inventory snapshot checksum mismatch")
    return payload


def _restore_managed(config, source, files):
    if files is None:
        return
    directory = config.inventory_directory
    existing = _managed_files(config)
    if files:
        private_directory(directory, owner_only=True)
    for name, (saved, expected) in files.items():
        replace_bytes(directory / name, _verified_managed_bytes(source, saved, expected))
    for path in existing:
        if path.name not in files:
            remove_file(path)


def _temporary_file(directory, prefix):
    path = directory / (prefix + secrets.token_hex(16))
    return path, private_file(path, create=True, exclusive=True)


def _copy_config(source, descriptor):
    with os.fdopen(descriptor, "wb") as destination:
        with source.open("rb") as original:
            shutil.copyfileobj(original, destination)
        destination.flush()
        os.fsync(destination.fileno())


def backup(config, data, destination):
    destination = Path(destination)
    paths = databases(config, data)
    manifest = {"format": 1, "databases": [], "config": config.config_path.name,
                "managed_inventories": _managed_snapshot(config, destination)}
    for index, path in enumerate(paths):
        exists = path.is_file()
        entry = {"path": path.relative_to(data).as_posix(), "backup": str(index) + ".db", "exists": exists}
        if exists:
            entry["mode"] = stat.S_IMODE(path.stat().st_mode)
            target = destination / entry["backup"]
            os.close(private_file(target, create=True, exclusive=True))
            _copy_sqlite_bounded(path, target)
            entry.update(sha256=digest(target), logical_sha256=logical_digest(target))
        manifest["databases"].append(entry)
    config_backup = destination / "config.toml"
    _copy_config(config.config_path, private_file(config_backup, create=True, exclusive=True))
    manifest["config_sha256"] = digest(config_backup)
    temporary = destination / ".manifest-completing"
    fd = private_file(temporary, create=True, exclusive=True)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream)
        stream.flush()
        os.fsync(stream.fileno())
    replace_file(temporary, destination / "manifest.json")
    sync_directory(destination)


def restore_config(path, data, source):
    path = Path(path)
    if path.parent != data:
        raise SnapshotError("runtime config must be directly inside the data directory")
    expected = _manifest(Path(source), data)["config_sha256"]
    if digest(Path(source) / "config.toml") != expected:
        raise SnapshotError("config snapshot checksum mismatch")
    temporary, fd = _temporary_file(data, ".update-config-")
    try:
        _copy_config(Path(source) / "config.toml", fd)
        if digest(temporary) != expected:
            raise SnapshotError("config snapshot checksum mismatch")
        replace_file(temporary, path)
        sync_directory(data)
    finally:
        temporary.unlink(missing_ok=True)


def restore(config, data, source):
    source = Path(source)
    manifest = _manifest(source, data)
    if digest(source / "config.toml") != manifest["config_sha256"]:
        raise SnapshotError("config snapshot checksum mismatch")
    managed = _managed_entries(config, source, manifest)
    if managed is not None:
        # Resolve the live decision before replacing its account audit database.
        recover(config.inventory_directory, config.watch.users_database)
    original = {row["path"] for row in manifest["databases"]}
    for path in databases(config, data, validate_known=False):
        if path.relative_to(data).as_posix() not in original:
            for candidate in (path, *[Path(str(path) + s) for s in ("-wal", "-shm", "-journal")]):
                candidate.unlink(missing_ok=True)
            sync_directory(path.parent)
    for row in manifest["databases"]:
        path = data / row["path"]
        if path.is_symlink():
            raise SnapshotError("invalid restore path")
        path.parent.mkdir(parents=True, exist_ok=True)
        for suffix in ("-wal", "-shm", "-journal"):
            Path(str(path) + suffix).unlink(missing_ok=True)
        if not row["exists"]:
            path.unlink(missing_ok=True)
            sync_directory(path.parent)
            continue
        saved = source / row["backup"]
        if digest(saved) != row["sha256"]:
            raise SnapshotError("snapshot database checksum mismatch")
        temporary, fd = _temporary_file(path.parent, ".update-restore-")
        os.close(fd)
        try:
            _copy_sqlite(saved, temporary)
            if os.name == "posix":
                temporary.chmod(row.get("mode", 0o600) & 0o600)
            replace_file(temporary, path)
            sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)
    _restore_managed(config, source, managed)
    restore_config(config.config_path, data, source)


def verify_restore(config, data, source):
    manifest = _manifest(Path(source), data)
    if digest(config.config_path) != manifest["config_sha256"]:
        raise SnapshotError("restored config does not match its snapshot")
    expected = set()
    for row in manifest["databases"]:
        path = data / row["path"]
        expected.add(path)
        if row["exists"]:
            if digest(Path(source) / row["backup"]) != row["sha256"] or logical_digest(path) != row["logical_sha256"]:
                raise SnapshotError("restored database does not match its snapshot")
        elif path.exists():
            raise SnapshotError("a newly created database was not removed")
    if any(path.exists() and path not in expected for path in databases(config, data)):
        raise SnapshotError("unexpected database remains after restore")
    managed = _managed_entries(config, Path(source), manifest)
    if managed is not None:
        actual = {path.name: path for path in _managed_files(config)}
        if actual.keys() != managed.keys() or any(
            hashlib.sha256(read_bytes(actual[name])).hexdigest() != checksum
            for name, (_, checksum) in managed.items()
        ):
            raise SnapshotError("restored managed inventories do not match their snapshot")


def migrate(config):
    StateStore(config.database_path).initialize()
    if config.watch.enabled or config.watch.database.exists():
        WatchStore(config.watch.database).initialize()
    if config.watch.users_database.exists():
        UserStore(config.watch.users_database).initialize(create=False)
    for path in {config.database_path, config.watch.database, config.watch.users_database}:
        if path.exists():
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise SnapshotError("local database integrity check failed")


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--backup-copy":
        _backup_copy_worker(sys.argv[2], sys.argv[3], wait_seconds=float(sys.argv[4]))
        return
    action, config_path, data, directory, *expected = sys.argv[1:]
    data, source = Path(data).resolve(strict=True), Path(directory)
    if expected and digest(source / "manifest.json") != expected[0]:
        raise SnapshotError("snapshot manifest checksum mismatch")
    if action == "recovery-paths":
        from .locking import LOCK_NAME
        rows = _manifest(source, data)["databases"]
        print(json.dumps(sorted({str((data / row["path"]).parent / LOCK_NAME) for row in rows})))
        return
    if action == "restore":
        restore_config(config_path, data, source)
    config = load_config(config_path)
    if action == "paths":
        from .locking import LOCK_NAME
        print(json.dumps([str(path) for path in sorted({path.parent / LOCK_NAME for path in databases(config, data)})]))
    elif action in {"backup", "restore", "verify_restore"}:
        globals()[action](config, data, source)
    else:
        raise SnapshotError("invalid snapshot operation")


if __name__ == "__main__":
    try:
        main()
    except BackupDatabaseBusy:
        raise SystemExit(75) from None
    except (CVEBeaconError, OSError, ValueError, KeyError, sqlite3.Error):
        raise SystemExit("state snapshot operation failed") from None
