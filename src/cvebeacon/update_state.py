"""Unprivileged SQLite snapshot, restore and migration helpers for updates."""
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile

from .config import load_config
from .errors import CVEBeaconError
from .state import StateStore
from .watch.store import WatchStore
from .watch.users import UserStore


class SnapshotError(CVEBeaconError):
    pass


def databases(config, data):
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
            path = Path(parent) / name
            if path.is_symlink():
                # State inputs must not redirect snapshots outside the data tree.
                raise SnapshotError("data directory must not contain symbolic links")
        for name in files:
            path = Path(parent) / name
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SnapshotError("data directory contains a non-regular or linked file")
            with path.open("rb") as stream:
                sqlite = stream.read(16) == b"SQLite format 3\x00"
            if sqlite or path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
                paths.add(path)
    return tuple(sorted(paths))


def _copy_sqlite(source, destination):
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=30)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
            if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise SnapshotError("SQLite snapshot integrity check failed")
    destination.chmod(0o600)


def backup(config, data, destination):
    destination = Path(destination)
    if config.config_path.is_symlink():
        raise SnapshotError("runtime config must be a regular file")
    manifest = {"databases": [], "config": config.config_path.name}
    for index, path in enumerate(databases(config, data)):
        exists = path.is_file()
        entry = {"path": path.relative_to(data).as_posix(), "backup": str(index) + ".db", "exists": exists}
        if exists:
            info = path.stat()
            entry.update(mode=stat.S_IMODE(info.st_mode))
            _copy_sqlite(path, destination / entry["backup"])
        manifest["databases"].append(entry)
    config_backup = destination / "config.toml"
    shutil.copyfile(config.config_path, config_backup)
    config_backup.chmod(0o600)
    # The completion marker is published only after every snapshot succeeds.
    (destination / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (destination / "manifest.json").chmod(0o600)


def restore(config, data, source):
    source = Path(source)
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    original = {row["path"] for row in manifest["databases"]}
    # Drop newly created state too; a failed migration may have introduced it.
    for path in databases(config, data):
        if path.relative_to(data).as_posix() not in original:
            for candidate in (path, *[Path(str(path) + s) for s in ("-wal", "-shm", "-journal")]):
                candidate.unlink(missing_ok=True)
    for row in manifest["databases"]:
        path = data / row["path"]
        if not path.resolve().is_relative_to(data) or path.is_symlink():
            raise SnapshotError("invalid restore path")
        for suffix in ("-wal", "-shm", "-journal"):
            Path(str(path) + suffix).unlink(missing_ok=True)
        if not row["exists"]:
            path.unlink(missing_ok=True)
            continue
        fd, temporary = tempfile.mkstemp(prefix=".update-restore-", dir=path.parent)
        os.close(fd)
        try:
            _copy_sqlite(source / row["backup"], Path(temporary))
            Path(temporary).chmod(row.get("mode", 0o600) & 0o600)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".update-config-", dir=data)
    os.close(fd)
    try:
        shutil.copyfile(source / "config.toml", temporary)
        Path(temporary).chmod(0o600)
        os.replace(temporary, config.config_path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def restore_config(path, data, source):
    path = Path(path)
    if path.parent != data:
        raise SnapshotError("runtime config must be directly inside the data directory")
    fd, temporary = tempfile.mkstemp(prefix=".update-config-", dir=data)
    os.close(fd)
    try:
        shutil.copyfile(Path(source) / "config.toml", temporary)
        Path(temporary).chmod(0o600)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


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
    action, config_path, data, directory = sys.argv[1:]
    data = Path(data).resolve(strict=True)
    if action == "restore":
        # Parse the restored config, never the possibly broken migration output.
        restore_config(config_path, data, directory)
    config = load_config(config_path)
    if action == "paths":
        from .locking import LOCK_NAME
        paths = {path.parent / LOCK_NAME for path in databases(config, data)}
        print(json.dumps([str(path) for path in sorted(paths)]))
    elif action == "backup":
        backup(config, data, Path(directory))
    elif action == "restore":
        restore(config, data, Path(directory))
    else:
        raise SnapshotError("invalid snapshot operation")


if __name__ == "__main__":
    try:
        main()
    except (CVEBeaconError, OSError, ValueError, sqlite3.Error):
        raise SystemExit("state snapshot operation failed") from None
