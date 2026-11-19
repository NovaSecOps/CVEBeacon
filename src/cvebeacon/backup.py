"""Administrator backups, verification, retention and atomic restore.

A backup is one private directory holding online SQLite copies of every state
database, the configuration file and an optional set of referenced secret
files. The manifest records sizes and hashes so a restore can prove what it is
about to write. Downloads are built on demand from the verified directory.
"""

from __future__ import annotations

import json
import os
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile

from .config import AppConfig
from .errors import CVEBeaconError
from .locking import OperationLock, RunInProgress, dashboard_job_id
from .private_storage import private_directory, private_file
from .snapshot import (
    SnapshotError,
    copy_sqlite,
    digest,
    logical_digest,
    sync_directory,
    sync_file,
)
from .watch.channels import SecretRef

BACKUP_MANIFEST = "manifest.json"
BACKUP_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z(?:-[0-9]{1,4})?")
MAX_MANIFEST = 8 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_DATABASES = 1000
HASH = re.compile(r"[0-9a-f]{64}")
DATABASE_FILE = re.compile(r"[0-9]{1,4}\.db")


class BackupError(CVEBeaconError):
    pass


@dataclass(frozen=True)
class Backup:
    id: str
    path: Path
    created_at: str | None = None
    created_by: str | None = None
    total_size: int = 0
    databases: int = 0
    include_secrets: bool = False
    schema_versions: dict = field(default_factory=dict)
    valid: bool = True
    error: str | None = None

    @property
    def size_label(self) -> str:
        value = float(self.total_size)
        for unit in ("B", "KiB", "MiB", "GiB"):
            if value < 1024 or unit == "GiB":
                return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            value /= 1024
        return f"{self.total_size} B"


def backup_root(config: AppConfig) -> Path:
    if config.backup.directory is not None:
        return Path(config.backup.directory)
    return Path(config.database_path).parent / "backups"


def jobs_database(config: AppConfig) -> Path:
    return Path(config.database_path).parent / "dashboard-jobs" / "dashboard-jobs.db"


def _current_schemas() -> dict[str, int]:
    from .state import SCHEMA_VERSION as state_schema
    from .watch.store import SCHEMA_VERSION as watch_schema

    return {"state": state_schema, "watch": watch_schema}


def _schema_version(path: Path, role: str | None) -> int | None:
    try:
        with closing(sqlite3.connect(str(path.as_uri()) + "?mode=ro", uri=True, timeout=30)) as db:
            tables = {
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            value = None
            if role == "state" and "schema_info" in tables:
                row = db.execute("SELECT version FROM schema_info").fetchone()
                value = row[0] if row else None
            elif role == "watch" and "watch_meta" in tables:
                row = db.execute(
                    "SELECT value FROM watch_meta WHERE key='schema_version'"
                ).fetchone()
                value = row[0] if row else None
            elif "schema_info" in tables:
                row = db.execute("SELECT version FROM schema_info").fetchone()
                value = row[0] if row else None
            elif "watch_meta" in tables:
                row = db.execute(
                    "SELECT value FROM watch_meta WHERE key='schema_version'"
                ).fetchone()
                value = row[0] if row else None
            if value is None:
                value = db.execute("PRAGMA user_version").fetchone()[0] or None
    except (sqlite3.Error, OSError, ValueError):
        raise BackupError("cannot read a state database schema version") from None
    if value is None:
        return None
    try:
        version = int(value)
    except (TypeError, ValueError):
        raise BackupError("invalid state database schema version") from None
    return version if version > 0 else None


def _configured_databases(config: AppConfig) -> list[tuple[Path, str | None, bool]]:
    return [
        (Path(config.database_path), "state", True),
        (Path(config.watch.database), "watch", True),
        (Path(config.watch.users_database), "users", True),
        (jobs_database(config), "jobs", True),
    ]


def _sqlite_files(root: Path, excluded: Path) -> set[Path]:
    result: set[Path] = set()
    try:
        root = root.resolve(strict=True)
    except OSError:
        return result
    count = 0
    for parent, directories, files in os.walk(root, followlinks=False):
        here = Path(parent)
        directories[:] = [
            name for name in directories
            if not (here / name).is_symlink()
            and not _inside((here / name).resolve(), excluded)
        ]
        for name in directories + files:
            count += 1
            if count > MAX_ENTRIES:
                raise BackupError("data directory exceeds the backup entry limit")
        for name in files:
            path = here / name
            if path.is_symlink() or _inside(path.resolve(), excluded):
                continue
            try:
                if path.stat().st_size == 0:
                    continue
                with path.open("rb") as stream:
                    header = stream.read(16)
            except OSError:
                continue
            if header == b"SQLite format 3\x00":
                result.add(path.resolve())
    return result


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _secret_files(config: AppConfig) -> dict[str, Path]:
    result: dict[str, Path] = {}
    if config.sources.nvd_api_key_file is not None:
        result["sources.nvd_api_key_file"] = Path(config.sources.nvd_api_key_file)
    for channel in config.watch.channels:
        for key, value in channel.options.items():
            if isinstance(value, SecretRef) and value.file is not None:
                result[f"watch.channels.{channel.name}.{key}"] = Path(value.file)
    return result


def _file_size(path: Path) -> int:
    try:
        details = path.lstat()
    except OSError:
        raise BackupError("a backup file disappeared during creation") from None
    if not stat.S_ISREG(details.st_mode):
        raise BackupError("backup files must be regular files")
    return details.st_size


def _create(config: AppConfig, *, include_secrets: bool, created_by: str) -> Backup:
    root = backup_root(config)
    private_directory(root, owner_only=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    identifier = stamp
    suffix = 0
    while (root / identifier).exists() or (root / identifier).is_symlink():
        suffix += 1
        identifier = f"{stamp}-{suffix}"
    destination = root / identifier
    private_directory(destination, owner_only=True)
    root = root.resolve()
    excluded = root
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    entries: list[dict] = []
    files: list[dict] = []
    schema_versions: dict[str, int | None] = {}
    configured = _configured_databases(config)
    seen: set[Path] = set()
    try:
        targets: list[tuple[Path, str | None, bool]] = []
        for path, role, required in configured:
            path = path.expanduser().resolve()
            if path in seen:
                continue
            seen.add(path)
            targets.append((path, role, required))
        data = Path(config.database_path).parent
        for path in sorted(_sqlite_files(data, excluded)):
            if path in seen:
                continue
            seen.add(path)
            targets.append((path, None, False))
        targets.sort(key=lambda item: str(item[0]))
        if len(targets) > MAX_DATABASES:
            raise BackupError("data directory has too many databases for one backup")
        for index, (path, role, _required) in enumerate(targets):
            exists = path.is_file() and not path.is_symlink()
            entry = {
                "path": str(path),
                "role": role,
                "exists": exists,
                "schema": None,
            }
            if exists:
                name = f"{index}.db"
                target = destination / name
                copy_sqlite(path, target)
                _normalize_sqlite_copy(target)
                schema = _schema_version(target, role)
                entry.update(
                    backup=name,
                    size=_file_size(target),
                    sha256=digest(target),
                    logical_sha256=logical_digest(target),
                    mode=stat.S_IMODE(path.stat().st_mode),
                    schema=schema,
                )
                if role is not None:
                    schema_versions[role] = schema
                files.append(_file_row(name, target))
            elif path.exists():
                raise BackupError("a configured state database is not a regular file")
            entries.append(entry)
        config_target = destination / "config.toml"
        shutil.copyfile(config.config_path, config_target)
        config_target.chmod(0o600)
        sync_file(config_target)
        config_entry = {
            "source": str(Path(config.config_path)),
            "name": "config.toml",
            "size": _file_size(config_target),
            "sha256": digest(config_target),
            "mode": stat.S_IMODE(Path(config.config_path).stat().st_mode),
        }
        files.append(_file_row("config.toml", config_target))
        secret_entries: list[dict] = []
        skipped_secrets: list[str] = []
        if include_secrets:
            for index, (label, path) in enumerate(sorted(_secret_files(config).items())):
                path = path.expanduser()
                if path.is_symlink() or not path.is_file():
                    skipped_secrets.append(label)
                    continue
                name = f"secrets/{index}"
                target = destination / name
                target.parent.mkdir(mode=0o700, exist_ok=True)
                shutil.copyfile(path, target)
                target.chmod(0o600)
                sync_file(target)
                secret_entries.append({
                    "reference": label,
                    "path": str(path.resolve()),
                    "file": name,
                    "size": _file_size(target),
                    "sha256": digest(target),
                    "mode": stat.S_IMODE(path.stat().st_mode),
                })
                files.append(_file_row(name, target))
        manifest = {
            "version": 1,
            "id": identifier,
            "created_at": created_at,
            "created_by": created_by,
            "include_secrets": include_secrets,
            "schema_versions": schema_versions,
            "databases": entries,
            "config": config_entry,
            "secrets": secret_entries,
            "skipped_secrets": skipped_secrets,
            "files": files,
            "total_size": sum(item["size"] for item in files),
        }
        _write_manifest(destination, manifest)
        sync_directory(destination)
        sync_directory(root)
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return _backup(identifier, destination, manifest)


def _file_row(name: str, path: Path) -> dict:
    return {"name": name, "size": _file_size(path), "sha256": digest(path)}


def _normalize_sqlite_copy(path: Path) -> None:
    """Checkpoint a copy so the backup is one self-contained file."""
    try:
        with closing(sqlite3.connect(path)) as db:
            mode = db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
    except sqlite3.Error:
        raise BackupError("cannot finalize a SQLite snapshot") from None
    if str(mode).casefold() != "delete":
        raise BackupError("cannot finalize a SQLite snapshot")
    for suffix in ("-wal", "-shm", "-journal"):
        Path(str(path) + suffix).unlink(missing_ok=True)
    sync_file(path)


def _write_manifest(destination: Path, manifest: dict) -> None:
    temporary = destination / ".manifest-completing"
    descriptor = private_file(temporary, create=True, exclusive=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, ensure_ascii=True, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination / BACKUP_MANIFEST)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def _backup(identifier: str, path: Path, manifest: dict) -> Backup:
    return Backup(
        id=identifier,
        path=path,
        created_at=manifest.get("created_at"),
        created_by=manifest.get("created_by"),
        total_size=int(manifest.get("total_size") or 0),
        databases=len(manifest.get("databases") or ()),
        include_secrets=bool(manifest.get("include_secrets")),
        schema_versions={key: value for key, value in (manifest.get("schema_versions") or {}).items()
                         if isinstance(value, int)},
    )


def backup_path(config: AppConfig, backup_id: str) -> Path:
    if not isinstance(backup_id, str) or not BACKUP_ID.fullmatch(backup_id):
        raise BackupError("invalid backup identifier")
    root = backup_root(config)
    path = root / backup_id
    if path.is_symlink() or not path.is_dir():
        raise BackupError("backup not found")
    if path.resolve().parent != root.resolve():
        raise BackupError("invalid backup location")
    return path


def list_backups(config: AppConfig) -> list[Backup]:
    root = backup_root(config)
    if not root.is_dir() or root.is_symlink():
        return []
    result = []
    try:
        names = sorted((path.name for path in root.iterdir() if path.is_dir() and not path.is_symlink()), reverse=True)
    except OSError:
        raise BackupError("cannot read the backup directory") from None
    for name in names:
        if not BACKUP_ID.fullmatch(name):
            continue
        try:
            manifest = _load_manifest(root / name)
        except BackupError as exc:
            result.append(Backup(name, root / name, valid=False, error=str(exc)))
            continue
        result.append(_backup(name, root / name, manifest))
    return result


def _read_manifest(path: Path) -> dict:
    try:
        descriptor = private_file(path, readonly=True, owner_only=False)
    except (OSError, CVEBeaconError):
        raise BackupError("backup manifest is unreadable") from None
    try:
        with os.fdopen(descriptor, "rb") as stream:
            raw = stream.read(MAX_MANIFEST + 1)
    except OSError:
        raise BackupError("backup manifest is unreadable") from None
    if len(raw) > MAX_MANIFEST:
        raise BackupError("backup manifest exceeds the size limit")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError):
        raise BackupError("backup manifest is not valid JSON") from None
    if not isinstance(value, dict):
        raise BackupError("invalid backup manifest")
    return value


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _load_manifest(source: Path) -> dict:
    manifest = _read_manifest(source / BACKUP_MANIFEST)
    if manifest.get("version") != 1 or manifest.get("id") != source.name:
        raise BackupError("invalid backup manifest version or identity")
    created_at = manifest.get("created_at")
    try:
        datetime.fromisoformat(created_at)
    except (TypeError, ValueError):
        raise BackupError("invalid backup creation time") from None
    if not isinstance(manifest.get("created_by"), str) or not manifest["created_by"] or len(manifest["created_by"]) > 128:
        raise BackupError("invalid backup creator")
    if type(manifest.get("include_secrets")) is not bool:
        raise BackupError("invalid backup secret marker")
    databases = manifest.get("databases")
    if not isinstance(databases, list) or len(databases) > MAX_DATABASES:
        raise BackupError("invalid backup database list")
    seen_paths: set[str] = set()
    seen_files: set[str] = set()
    schema_versions = {}
    expected = {"config.toml"}
    for row in databases:
        if not isinstance(row, dict):
            raise BackupError("invalid backup database entry")
        path = row.get("path")
        if not isinstance(path, str) or not Path(path).is_absolute() or path in seen_paths:
            raise BackupError("invalid backup database path")
        seen_paths.add(path)
        if type(row.get("exists")) is not bool:
            raise BackupError("invalid backup database existence marker")
        schema = row.get("schema")
        if schema is not None and (type(schema) is not int or schema < 0):
            raise BackupError("invalid backup database schema")
        if row["exists"]:
            name = row.get("backup")
            if not isinstance(name, str) or not DATABASE_FILE.fullmatch(name) or name in seen_files:
                raise BackupError("invalid backup database filename")
            seen_files.add(name)
            expected.add(name)
            if not _valid_size(row.get("size")) or not _valid_hash(row.get("sha256")) or not _valid_hash(row.get("logical_sha256")):
                raise BackupError("invalid backup database checksum")
            if type(row.get("mode")) is not int:
                raise BackupError("invalid backup database mode")
        role = row.get("role")
        if role in {"state", "watch"} and row["exists"]:
            schema_versions[role] = schema
        elif role in {"users", "jobs"} and row["exists"]:
            schema_versions[role] = schema
    config_row = manifest.get("config")
    if not isinstance(config_row, dict) or config_row.get("name") != "config.toml":
        raise BackupError("invalid backup configuration entry")
    if not _valid_size(config_row.get("size")) or not _valid_hash(config_row.get("sha256")):
        raise BackupError("invalid backup configuration checksum")
    if type(config_row.get("mode")) is not int:
        raise BackupError("invalid backup configuration mode")
    if not isinstance(config_row.get("source"), str) or not Path(config_row["source"]).is_absolute():
        raise BackupError("invalid backup configuration path")
    secrets = manifest.get("secrets")
    if not isinstance(secrets, list):
        raise BackupError("invalid backup secret list")
    for row in secrets:
        if not isinstance(row, dict):
            raise BackupError("invalid backup secret entry")
        name = row.get("file")
        if not isinstance(name, str) or not re.fullmatch(r"secrets/[0-9]{1,4}", name) or name in seen_files:
            raise BackupError("invalid backup secret filename")
        seen_files.add(name)
        expected.add(name)
        if not isinstance(row.get("reference"), str) or not isinstance(row.get("path"), str) or not Path(row["path"]).is_absolute():
            raise BackupError("invalid backup secret reference")
        if not _valid_size(row.get("size")) or not _valid_hash(row.get("sha256")) or type(row.get("mode")) is not int:
            raise BackupError("invalid backup secret checksum")
    if manifest.get("schema_versions") != schema_versions:
        raise BackupError("backup schema versions do not match its databases")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise BackupError("invalid backup file list")
    listed = set()
    total = 0
    for row in files:
        if not isinstance(row, dict):
            raise BackupError("invalid backup file entry")
        name = row.get("name")
        if not isinstance(name, str) or name in listed:
            raise BackupError("invalid backup file name")
        listed.add(name)
        if not _valid_size(row.get("size")) or not _valid_hash(row.get("sha256")):
            raise BackupError("invalid backup file checksum")
        total += row["size"]
    if listed != expected or total != manifest.get("total_size"):
        raise BackupError("backup file list does not match its content")
    return manifest


def _valid_size(value) -> bool:
    return type(value) is int and value >= 0


def _valid_hash(value) -> bool:
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def _verify(config: AppConfig, backup_id: str) -> tuple[Backup, dict]:
    source = backup_path(config, backup_id)
    manifest = _load_manifest(source)
    for row in manifest["files"]:
        path = source / row["name"]
        try:
            details = path.lstat()
        except OSError:
            raise BackupError(f"backup file is missing: {row['name']}") from None
        if not stat.S_ISREG(details.st_mode) or details.st_size != row["size"]:
            raise BackupError(f"backup file size differs: {row['name']}")
        if digest(path) != row["sha256"]:
            raise BackupError(f"backup file checksum differs: {row['name']}")
    for row in manifest["databases"]:
        if not row["exists"]:
            continue
        path = source / row["backup"]
        try:
            logical = logical_digest(path)
        except (SnapshotError, sqlite3.Error, OSError):
            raise BackupError(f"backup database is not a valid SQLite snapshot: {row['backup']}") from None
        if logical != row["logical_sha256"]:
            raise BackupError(f"backup database content differs: {row['backup']}")
        detected = _schema_version(path, row["role"])
        if detected != row["schema"]:
            raise BackupError(f"backup database schema differs: {row['backup']}")
    return _backup(backup_id, source, manifest), manifest


def _refuse_newer(manifest: dict) -> None:
    current = _current_schemas()
    for role, value in manifest.get("schema_versions", {}).items():
        if role not in current or type(value) is not int:
            continue
        if value > current[role]:
            raise BackupError(
                f"backup {manifest['id']} uses a newer {role} schema "
                f"({value} > {current[role]}); upgrade CVEBeacon before restoring"
            )


@contextmanager
def _locked(config: AppConfig, operation: str):
    lock = OperationLock(config, operation)
    if not lock.acquire():
        raise BackupError(f"{operation.replace('-', ' ')} refused: {RunInProgress(lock.holder)}")
    try:
        yield
    finally:
        lock.release()


def create(config: AppConfig, *, include_secrets: bool = False, created_by: str = "cli") -> Backup:
    with _locked(config, "backup-create"):
        return _create(config, include_secrets=include_secrets, created_by=created_by)


def verify(config: AppConfig, backup_id: str) -> Backup:
    with _locked(config, "backup-verify"):
        backup, _ = _verify(config, backup_id)
    return backup


def _active_jobs(config: AppConfig) -> list[dict]:
    path = jobs_database(config)
    if not path.is_file():
        return []
    try:
        with closing(sqlite3.connect(str(path.as_uri()) + "?mode=ro", uri=True, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute(
                "SELECT id, operation, status FROM dashboard_job "
                "WHERE status IN ('queued','running') ORDER BY id"
            ).fetchall()
    except (sqlite3.Error, OSError, ValueError):
        raise BackupError(
            "cannot confirm that dashboard jobs are idle; stop the dashboard "
            "service before restoring"
        ) from None
    return [dict(row) for row in rows]


def _restore_database(config: AppConfig, source: Path, row: dict) -> None:
    data = Path(config.database_path).parent.resolve()
    configured = {path.resolve() for path, _, _ in _configured_databases(config)}
    raw = Path(row["path"])
    if raw.is_symlink():
        raise BackupError("restore target must not be a symbolic link")
    target = raw.resolve()
    if not (_inside(target, data) or target in configured):
        raise BackupError("restore target is outside the configured state")
    if target.parent.is_symlink() or (target.exists() and target.is_symlink()):
        raise BackupError("restore target must not be a symbolic link")
    target.parent.mkdir(parents=True, exist_ok=True)
    if row["exists"]:
        saved = source / row["backup"]
        if digest(saved) != row["sha256"]:
            raise BackupError("backup database changed during restore")
        for suffix in ("-wal", "-shm", "-journal"):
            Path(str(target) + suffix).unlink(missing_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".backup-restore-", dir=target.parent)
        os.close(descriptor)
        temporary_path = Path(temporary)
        try:
            copy_sqlite(saved, temporary_path)
            _normalize_sqlite_copy(temporary_path)
            temporary_path.chmod(0o600)
            if logical_digest(temporary_path) != row["logical_sha256"]:
                raise BackupError("restored database verification failed")
            os.replace(temporary, target)
            sync_directory(target.parent)
        finally:
            for candidate in (temporary_path, *(Path(str(temporary_path) + suffix)
                                                for suffix in ("-wal", "-shm", "-journal"))):
                candidate.unlink(missing_ok=True)
    else:
        target.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm", "-journal"):
            Path(str(target) + suffix).unlink(missing_ok=True)
        sync_directory(target.parent)


def _restore_config(config: AppConfig, source: Path, manifest: dict) -> None:
    entry = manifest["config"]
    saved = source / entry["name"]
    if digest(saved) != entry["sha256"]:
        raise BackupError("backup configuration changed during restore")
    target = Path(config.config_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".backup-config-", dir=target.parent)
    os.close(descriptor)
    try:
        shutil.copyfile(saved, temporary)
        if digest(temporary) != entry["sha256"]:
            raise BackupError("backup configuration verification failed")
        Path(temporary).chmod(entry.get("mode", 0o600) & 0o777)
        sync_file(temporary)
        os.replace(temporary, target)
        sync_directory(target.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _restore_secrets(config: AppConfig, source: Path, manifest: dict) -> list[str]:
    data = Path(config.database_path).parent.resolve()
    allowed = {path.expanduser().resolve() for path in _secret_files(config).values()}
    restored = []
    for row in manifest["secrets"]:
        raw = Path(row["path"])
        if raw.is_symlink():
            raise BackupError("restore target must not be a symbolic link")
        target = raw.resolve()
        if not (_inside(target, data) or target in allowed):
            raise BackupError("restore target is outside the configured secret files")
        saved = source / row["file"]
        if digest(saved) != row["sha256"]:
            raise BackupError("backup secret changed during restore")
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".backup-secret-", dir=target.parent)
        os.close(descriptor)
        try:
            shutil.copyfile(saved, temporary)
            if digest(temporary) != row["sha256"]:
                raise BackupError("backup secret verification failed")
            Path(temporary).chmod(0o600)
            sync_file(temporary)
            os.replace(temporary, target)
            sync_directory(target.parent)
            restored.append(row["reference"])
        finally:
            Path(temporary).unlink(missing_ok=True)
    return restored


def _validate_restore(config: AppConfig, manifest: dict) -> None:
    """Refuse every unsafe target before the first write."""
    data = Path(config.database_path).parent.resolve()
    configured = {path.resolve() for path, _, _ in _configured_databases(config)}
    seen: set[Path] = {Path(config.config_path).resolve()}
    for row in manifest["databases"]:
        raw = Path(row["path"])
        if raw.is_symlink():
            raise BackupError("restore target must not be a symbolic link")
        target = raw.resolve()
        if target in seen:
            raise BackupError("backup contains duplicate restore targets")
        seen.add(target)
        if not (_inside(target, data) or target in configured):
            raise BackupError("restore target is outside the configured state")
    allowed = {path.expanduser().resolve() for path in _secret_files(config).values()}
    for row in manifest["secrets"]:
        raw = Path(row["path"])
        if raw.is_symlink():
            raise BackupError("restore target must not be a symbolic link")
        target = raw.resolve()
        if target in seen:
            raise BackupError("backup contains duplicate restore targets")
        seen.add(target)
        if not (_inside(target, data) or target in allowed):
            raise BackupError("restore target is outside the configured secret files")


def restore(config: AppConfig, backup_id: str) -> dict:
    """Verify, snapshot, then replace state with a complete backup."""
    backup, manifest = _verify(config, backup_id)
    _refuse_newer(manifest)
    _validate_restore(config, manifest)
    with _locked(config, "backup-restore"):
        own_job = dashboard_job_id()
        active = [job for job in _active_jobs(config) if job["id"] != own_job]
        if active:
            labels = ", ".join(
                f"job {job['id']} ({job['operation']}, {job['status']})" for job in active
            )
            raise BackupError(
                "restore refused while dashboard jobs are active: " + labels
                + "; wait for them to finish or cancel them from the Operations page"
            )
        safety = _create(config, include_secrets=False, created_by="pre-restore")
        skipped: list[str] = []
        for row in manifest["databases"]:
            if own_job is not None and row.get("role") in {"users", "jobs"}:
                # The dashboard owns its live account audit and job history
                # while this job runs. The backup still contains both for a
                # stopped-service restore from the command line.
                skipped.append(row["role"])
                continue
            _restore_database(config, backup.path, row)
        _restore_config(config, backup.path, manifest)
        restored_secrets = _restore_secrets(config, backup.path, manifest)
        from .config import load_config
        from .update_state import migrate

        migrate(load_config(config.config_path))
    return {
        "restored": backup_id,
        "safety": safety.id,
        "databases": len(manifest["databases"]) - len(skipped),
        "secrets": restored_secrets,
        **({"skipped": skipped} if skipped else {}),
    }


def prune(config: AppConfig) -> dict:
    """Delete expired backups while retaining the newest ``keep_min``."""
    root = backup_root(config)
    if root.is_symlink():
        raise BackupError("backup directory must not be a symbolic link")
    if not root.is_dir():
        return {"removed": [], "kept": 0}
    policy = config.backup
    cutoff = datetime.now(timezone.utc) - timedelta(days=policy.retention_days)
    backups = list_backups(config)
    keep = {backup.id for backup in backups[:policy.keep_min]}
    removed = []
    for backup in backups:
        if backup.id in keep:
            continue
        try:
            created = datetime.fromisoformat(backup.created_at or "")
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
        if created >= cutoff:
            continue
        shutil.rmtree(backup.path)
        removed.append(backup.id)
    if removed:
        sync_directory(root)
    return {"removed": removed, "kept": len(backups) - len(removed)}


def build_archive(config: AppConfig, backup_id: str, *, compress: bool | None = None) -> object:
    """Stream one verified backup through a temporary, unnamed file."""
    backup, manifest = _verify(config, backup_id)
    gzip = config.backup.compress if compress is None else compress
    buffer = tempfile.TemporaryFile()
    try:
        with tarfile.open(fileobj=buffer, mode="w:gz" if gzip else "w") as archive:
            for row in manifest["files"]:
                path = backup.path / row["name"]
                archive.add(path, arcname=f"{backup.id}/{row['name']}")
            archive.add(backup.path / BACKUP_MANIFEST, arcname=f"{backup.id}/{BACKUP_MANIFEST}")
        buffer.seek(0)
    except BaseException:
        buffer.close()
        raise
    return buffer


def summary(config: AppConfig) -> dict:
    backups = list_backups(config)
    valid = [backup for backup in backups if backup.valid]
    return {
        "count": len(backups),
        "last": valid[0].created_at if valid else None,
        "last_id": valid[0].id if valid else None,
        "total_size": sum(backup.total_size for backup in valid),
    }


def cli(args, config: AppConfig) -> int:
    command = args.backup_command
    if command == "list":
        backups = list_backups(config)
        if not backups:
            print("no backups")
            return 0
        for backup in backups:
            state = "ok" if backup.valid else "invalid: " + (backup.error or "unknown")
            created = backup.created_at or "unknown"
            schema = ", ".join(
                f"{name} {value}" for name, value in sorted(backup.schema_versions.items())
            ) or ("unknown" if backup.databases else "no databases")
            print(f"{backup.id}  {created}  {backup.size_label}  "
                  f"{backup.databases} database(s)  {backup.created_by or 'unknown'}  "
                  f"{schema}  {state}")
        return 0
    if command == "create":
        created_by = getattr(args, "created_by", None) or "cli"
        if not isinstance(created_by, str) or not re.fullmatch(r"[\w.@-]{1,64}", created_by, re.ASCII):
            raise BackupError("invalid backup creator")
        backup = create(config, include_secrets=getattr(args, "include_secrets", False),
                        created_by=created_by)
        print(f"created {backup.id}: {backup.databases} database(s), {backup.size_label}")
        return 0
    if command == "verify":
        backup = verify(config, args.backup_id)
        print(f"verified {backup.id}: {backup.databases} database(s), {backup.size_label}")
        return 0
    if command == "restore":
        if not getattr(args, "yes", False):
            try:
                answer = input(f"Restore backup {args.backup_id}? [y/N] ").strip().casefold()
            except EOFError:
                answer = ""
            if answer not in {"y", "yes"}:
                print("cancelled")
                return 1
        result = restore(config, args.backup_id)
        print(f"restored {result['restored']}; safety backup {result['safety']}")
        if result.get("skipped"):
            print("preserved live dashboard job history: " + ", ".join(result["skipped"]))
        return 0
    if command == "prune":
        result = prune(config)
        print(f"removed {len(result['removed'])} backup(s); {result['kept']} retained")
        return 0
    raise BackupError("unsupported backup command")
