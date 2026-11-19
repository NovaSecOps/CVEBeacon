"""Unprivileged, durable SQLite snapshots and independently verified restore."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import tempfile

from .config import load_config
from .errors import CVEBeaconError
from .inventory_journal import recover, remove_file
from .managed_inventory import is_managed_file
from .private_storage import private_directory
from .web_assets import replace_bytes
from .web_inventory import read_bytes
from .state import StateStore
from .watch.store import WatchStore
from .watch.users import UserStore


class SnapshotError(CVEBeaconError):
    pass


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_file(path):
    with Path(path).open("rb") as stream:
        os.fsync(stream.fileno())


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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


def logical_digest(path):
    result = hashlib.sha256()
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SnapshotError("SQLite integrity check failed")
        for line in db.iterdump():
            result.update(line.encode("utf-8"))
            result.update(b"\n")
    return result.hexdigest()


def _copy_sqlite(source, destination):
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=30)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
            if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise SnapshotError("SQLite snapshot integrity check failed")
    destination.chmod(0o600)
    sync_file(destination)


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
    items = []
    for index, path in enumerate(_managed_files(config)):
        saved = f"inventory-{index}.copy"
        payload = read_bytes(path)
        replace_bytes(destination / saved, payload)
        items.append({"name": path.name, "backup": saved, "sha256": hashlib.sha256(payload).hexdigest()})
    return items


def _managed_entries(config, source, manifest):
    items = manifest.get("managed_inventories")
    if items is None:
        return None  # Snapshots written by earlier releases.
    if not isinstance(items, list) or len(items) > 20000:
        raise SnapshotError("invalid managed inventory snapshot")
    files = {}
    for item in items:
        name, saved = item["name"], item["backup"]
        if (not isinstance(name, str) or Path(name).name != name or not is_managed_file(Path(name))
                or name in files or not isinstance(saved, str) or not re.fullmatch(r"inventory-[0-9]+\.copy", saved)):
            raise SnapshotError("invalid managed inventory snapshot filename")
        target = config.inventory_directory / name
        if config.inventory is not None and target == config.inventory.path:
            raise SnapshotError("managed inventory snapshot overlaps the configured inventory")
        expected = item["sha256"]
        _verified_managed_bytes(source, saved, expected)
        files[name] = (saved, expected)
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
            _copy_sqlite(path, target)
            entry.update(sha256=digest(target), logical_sha256=logical_digest(target))
        manifest["databases"].append(entry)
    config_backup = destination / "config.toml"
    shutil.copyfile(config.config_path, config_backup)
    config_backup.chmod(0o600)
    sync_file(config_backup)
    manifest["config_sha256"] = digest(config_backup)
    temporary = destination / ".manifest-completing"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    os.replace(temporary, destination / "manifest.json")
    sync_directory(destination)


def restore_config(path, data, source):
    path = Path(path)
    if path.parent != data:
        raise SnapshotError("runtime config must be directly inside the data directory")
    expected = _manifest(Path(source), data)["config_sha256"]
    if digest(Path(source) / "config.toml") != expected:
        raise SnapshotError("config snapshot checksum mismatch")
    fd, temporary = tempfile.mkstemp(prefix=".update-config-", dir=data)
    os.close(fd)
    try:
        shutil.copyfile(Path(source) / "config.toml", temporary)
        if digest(Path(temporary)) != expected:
            raise SnapshotError("config snapshot checksum mismatch")
        Path(temporary).chmod(0o600)
        sync_file(temporary)
        os.replace(temporary, path)
        sync_directory(data)
    finally:
        Path(temporary).unlink(missing_ok=True)


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
        fd, temporary = tempfile.mkstemp(prefix=".update-restore-", dir=path.parent)
        os.close(fd)
        try:
            _copy_sqlite(saved, Path(temporary))
            Path(temporary).chmod(row.get("mode", 0o600) & 0o600)
            os.replace(temporary, path)
            sync_directory(path.parent)
        finally:
            Path(temporary).unlink(missing_ok=True)
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
            hashlib.sha256(read_bytes(actual[name])).hexdigest() != expected
            for name, (_, expected) in managed.items()
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
    except (CVEBeaconError, OSError, ValueError, KeyError, sqlite3.Error):
        raise SystemExit("state snapshot operation failed") from None
