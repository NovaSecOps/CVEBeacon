"""Administrator backups, verification, retention and atomic restore.

A backup is one private directory holding online SQLite copies of every state
database, the configuration file and an optional set of referenced secret
files. The manifest records sizes and hashes so a restore can prove what it is
about to write. Downloads are built on demand from the verified directory.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
import tomllib
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO

from .config import AppConfig, load_config
from .errors import CVEBeaconError
from .locking import (
    DASHBOARD_LOCK_CONFLICT_EXIT,
    OperationLock,
    RunInProgress,
    dashboard_job_id,
)
from .private_storage import private_directory, private_file
from .publication import replace_file
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


class BackupBusy(BackupError):
    """A backup operation could not take the shared run lock."""


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return  # The updater keeps its original POSIX directory-sync contract.
    sync_directory(path)


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
    # User and job stores have no schema-version constant; their manifest
    # values remain informational until one exists.
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
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise BackupError(f"cannot read a state database schema version ({type(exc).__name__})") from None
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
            and not _backup_store(here / name)
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


def _secret_files(config: AppConfig, extra=()) -> dict[Path, list[str]]:
    """Resolve referenced secret files once per target path."""
    result: dict[Path, list[str]] = {}

    def add(path, reference):
        target = Path(path).expanduser()
        result.setdefault(target, []).append(reference)

    if config.sources.nvd_api_key_file is not None:
        add(config.sources.nvd_api_key_file, "sources.nvd_api_key_file")
    if config.sources.vulncheck_api_key_file is not None:
        add(config.sources.vulncheck_api_key_file, "sources.vulncheck_api_key_file")
    for channel in config.watch.channels:
        for key, value in channel.options.items():
            if isinstance(value, SecretRef) and value.file is not None:
                add(value.file, f"watch.channels.{channel.name}.{key}")
    for path in extra:
        add(path, "restore-target")
    return {path: list(dict.fromkeys(references)) for path, references in result.items()}


def _backup_store(path: Path) -> bool:
    """Identify a backup directory by name, layout or manifest identity."""
    if BACKUP_ID.fullmatch(path.name):
        return True
    folded = path.name.casefold()
    if folded in {"backup", "backups"} or folded.startswith(("backup-", "backups-")):
        return True
    try:
        names = {entry.name for entry in path.iterdir()}
    except OSError:
        return False
    if "manifest.json" in names:
        return True
    if "config.toml" in names and any(DATABASE_FILE.fullmatch(name) for name in names):
        return True
    manifest_path = path / BACKUP_MANIFEST
    if not manifest_path.exists():
        return False
    try:
        with manifest_path.open("rb") as stream:
            raw = stream.read(65536)
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (OSError, ValueError, UnicodeError):
        return False
    return (isinstance(value, dict) and value.get("version") == 1
            and value.get("id") == path.name
            and isinstance(value.get("databases"), list))


def _file_size(path: Path) -> int:
    try:
        details = path.lstat()
    except OSError:
        raise BackupError("a backup file disappeared during creation") from None
    if not stat.S_ISREG(details.st_mode):
        raise BackupError("backup files must be regular files")
    return details.st_size


def _create(config: AppConfig, *, include_secrets: bool, created_by: str,
            extra_databases=(), extra_secret_paths=()) -> Backup:
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
        for path in extra_databases:
            path = Path(path).expanduser().resolve()
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
            secret_targets = _secret_files(config, extra_secret_paths)
            for index, (path, references) in enumerate(sorted(secret_targets.items(), key=lambda item: str(item[0]))):
                path = path.expanduser()
                if path.is_symlink() or not path.is_file():
                    skipped_secrets.extend(references)
                    continue
                name = f"secrets/{index}"
                target = destination / name
                target.parent.mkdir(mode=0o700, exist_ok=True)
                shutil.copyfile(path, target)
                target.chmod(0o600)
                sync_file(target)
                secret_entries.append({
                    "reference": references[0],
                    "references": references,
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
        _sync_directory(destination)
        _sync_directory(root)
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
    except sqlite3.Error as exc:
        raise BackupError(f"cannot finalize a SQLite snapshot ({type(exc).__name__})") from None
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
        databases=sum(1 for row in manifest.get("databases") or () if row.get("exists")),
        include_secrets=bool(manifest.get("include_secrets")),
        schema_versions={key: value for key, value in (manifest.get("schema_versions") or {}).items()
                         if type(value) is int},
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


def _backup_id_time(name: str) -> str | None:
    try:
        return datetime.strptime(name.split("-", 1)[0], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return None


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
            result.append(Backup(name, root / name, created_at=_backup_id_time(name),
                                 valid=False, error=str(exc)))
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
    expected: dict[str, tuple[int, str]] = {}
    schema_versions = {}
    for row in databases:
        if not isinstance(row, dict):
            raise BackupError("invalid backup database entry")
        path = row.get("path")
        if not isinstance(path, str) or not Path(path).is_absolute() or path in seen_paths:
            raise BackupError("invalid backup database path")
        seen_paths.add(path)
        if type(row.get("exists")) is not bool:
            raise BackupError("invalid backup database existence marker")
        role = row.get("role")
        if role is not None and (not isinstance(role, str) or role not in {"state", "watch", "users", "jobs"}):
            raise BackupError("invalid backup database role")
        schema = row.get("schema")
        if schema is not None and (type(schema) is not int or schema < 0):
            raise BackupError("invalid backup database schema")
        if row["exists"]:
            name = row.get("backup")
            if not isinstance(name, str) or not DATABASE_FILE.fullmatch(name) or name in expected:
                raise BackupError("invalid backup database filename")
            if not _valid_size(row.get("size")) or not _valid_hash(row.get("sha256")) or not _valid_hash(row.get("logical_sha256")):
                raise BackupError("invalid backup database checksum")
            if type(row.get("mode")) is not int:
                raise BackupError("invalid backup database mode")
            expected[name] = (row["size"], row["sha256"])
            if role is not None:
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
    expected["config.toml"] = (config_row["size"], config_row["sha256"])
    secrets = manifest.get("secrets")
    if not isinstance(secrets, list):
        raise BackupError("invalid backup secret list")
    for row in secrets:
        if not isinstance(row, dict):
            raise BackupError("invalid backup secret entry")
        name = row.get("file")
        if not isinstance(name, str) or not re.fullmatch(r"secrets/[0-9]{1,4}", name) or name in expected:
            raise BackupError("invalid backup secret filename")
        if not isinstance(row.get("reference"), str) or not row["reference"]:
            raise BackupError("invalid backup secret reference")
        references = row.get("references", [row["reference"]])
        if (not isinstance(references, list) or not references
                or any(not isinstance(item, str) or not item for item in references)
                or references[0] != row["reference"]):
            raise BackupError("invalid backup secret references")
        if not isinstance(row.get("path"), str) or not Path(row["path"]).is_absolute():
            raise BackupError("invalid backup secret path")
        if not _valid_size(row.get("size")) or not _valid_hash(row.get("sha256")) or type(row.get("mode")) is not int:
            raise BackupError("invalid backup secret checksum")
        expected[name] = (row["size"], row["sha256"])
    if manifest.get("schema_versions") != schema_versions:
        raise BackupError("backup schema versions do not match its databases")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise BackupError("invalid backup file list")
    listed: dict[str, tuple[int, str]] = {}
    total = 0
    for row in files:
        if not isinstance(row, dict):
            raise BackupError("invalid backup file entry")
        name = row.get("name")
        if not isinstance(name, str) or name in listed:
            raise BackupError("invalid backup file name")
        if not _valid_size(row.get("size")) or not _valid_hash(row.get("sha256")):
            raise BackupError("invalid backup file checksum")
        listed[name] = (row["size"], row["sha256"])
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
        raise BackupBusy(f"{operation.replace('-', ' ')} refused: {RunInProgress(lock.holder)}")
    try:
        yield
    finally:
        lock.release()


def _failure(operation: str, exc: BaseException) -> BackupError:
    return BackupError(f"{operation} failed ({type(exc).__name__})")


def create(config: AppConfig, *, include_secrets: bool = False, created_by: str = "cli") -> Backup:
    try:
        with _locked(config, "backup-create"):
            return _create(config, include_secrets=include_secrets, created_by=created_by)
    except BackupError:
        raise
    except (CVEBeaconError, OSError, sqlite3.Error, shutil.Error) as exc:
        raise _failure("backup creation", exc) from None


def verify(config: AppConfig, backup_id: str) -> Backup:
    try:
        with _locked(config, "backup-verify"):
            backup, _ = _verify(config, backup_id)
        return backup
    except BackupError:
        raise
    except (CVEBeaconError, OSError, sqlite3.Error, shutil.Error) as exc:
        raise _failure("backup verification", exc) from None


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
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise BackupError(
            "cannot confirm that dashboard jobs are idle; stop the dashboard "
            f"service before restoring ({type(exc).__name__})"
        ) from None
    return [dict(row) for row in rows]


@dataclass(frozen=True)
class _StagedFile:
    kind: str
    target: Path
    temporary: Path
    reference: str | None = None


def _rewrite_secret_paths(node, base: Path, copies: dict[Path, Path]) -> None:
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if key.endswith("_file") and isinstance(value, str):
                raw = Path(value).expanduser()
                target = (raw if raw.is_absolute() else base / raw).resolve()
                if target in copies:
                    node[key] = str(copies[target])
            else:
                _rewrite_secret_paths(value, base, copies)
    elif isinstance(node, list):
        for item in node:
            _rewrite_secret_paths(item, base, copies)


def _validate_restored_config(config: AppConfig, source: Path, manifest: dict):
    """Load the backed-up configuration with the running loader.

    Secret file references are validated against private copies of the files
    that this restore would install, so missing live secrets do not reject a
    complete backup and no live path is touched.
    """
    base = Path(config.config_path).parent
    directory = None
    copies: dict[Path, Path] = {}
    validation = None
    try:
        if manifest["secrets"]:
            directory = tempfile.TemporaryDirectory(prefix=".backup-validate-", dir=base)
            for index, row in enumerate(manifest["secrets"]):
                target = Path(row["path"]).expanduser().resolve()
                staged = Path(directory.name) / str(index)
                shutil.copyfile(source / row["file"], staged)
                staged.chmod(0o600)
                copies[target] = staged
        raw = (source / manifest["config"]["name"]).read_bytes()
        document = tomllib.loads(raw.decode("utf-8"))
        _rewrite_secret_paths(document, base, copies)
        from .dashboard_config import dumps

        content = dumps(document).encode("utf-8")
        descriptor, name = tempfile.mkstemp(prefix=".backup-config-", dir=base)
        validation = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        validation.chmod(0o600)
        restored = load_config(validation)
        return restored, directory, copies
    except (CVEBeaconError, OSError, ValueError, UnicodeError):
        if directory is not None:
            directory.cleanup()
        raise BackupError("backup configuration is not compatible with this version") from None
    finally:
        if validation is not None:
            validation.unlink(missing_ok=True)


def _allowed_paths(config: AppConfig):
    data = Path(config.database_path).parent.resolve()
    configured = {path.expanduser().resolve() for path, _, _ in _configured_databases(config)}
    secrets = set(_secret_files(config))
    return data, configured, secrets


def _preserved_absent(manifest: dict) -> list[str]:
    preserved = []
    for row in manifest["databases"]:
        if not row["exists"] and Path(row["path"]).exists():
            preserved.append(row.get("role") or Path(row["path"]).name)
    return preserved


def _validate_restore(config: AppConfig, restored: AppConfig, manifest: dict,
                      validation_copies: dict[Path, Path]) -> None:
    """Refuse every unsafe target before the first write."""
    current_data, current_configured, current_secrets = _allowed_paths(config)
    restored_data, restored_configured, restored_secrets_by_path = _allowed_paths(restored)
    staged_to_target = {staged: target for target, staged in validation_copies.items()}
    restored_secrets = {
        staged_to_target.get(path, path) for path in restored_secrets_by_path
    }
    seen: set[Path] = {Path(config.config_path).resolve()}
    backup_directory = backup_root(config).resolve()
    for row in manifest["databases"]:
        if not row["exists"]:
            continue
        raw = Path(row["path"])
        if raw.is_symlink():
            raise BackupError("restore target must not be a symbolic link")
        target = raw.resolve()
        if target in seen:
            raise BackupError("backup contains duplicate restore targets")
        seen.add(target)
        if _inside(target, backup_directory):
            raise BackupError("restore target must not be inside the backup store")
        if not (_inside(target, current_data) or _inside(target, restored_data)
                or target in current_configured or target in restored_configured):
            raise BackupError("restore target is outside the configured state")
        if target.exists() and not target.is_file():
            raise BackupError("restore target is not a regular file")
    for row in manifest["secrets"]:
        raw = Path(row["path"])
        if raw.is_symlink():
            raise BackupError("restore target must not be a symbolic link")
        target = raw.resolve()
        if target in seen:
            raise BackupError("backup contains duplicate restore targets")
        seen.add(target)
        if _inside(target, backup_directory):
            raise BackupError("restore target must not be inside the backup store")
        if not (_inside(target, current_data) or _inside(target, restored_data)
                or target in current_secrets or target in restored_secrets):
            raise BackupError("restore target is outside the configured secret files")
        if target.exists() and not target.is_file():
            raise BackupError("restore target is not a regular file")


def _stage_file(source: Path, target: Path, expected: str, *, prefix: str) -> Path:
    try:
        private_directory(target.parent)
    except (CVEBeaconError, OSError) as exc:
        raise BackupError(f"cannot create a restore directory ({type(exc).__name__})") from None
    descriptor, name = tempfile.mkstemp(prefix=prefix, dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as stream:
            shutil.copyfileobj(stream, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o600)
        if digest(temporary) != expected:
            raise BackupError("staged restore file checksum differs")
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _restore_database_content(source: Path, target: Path) -> None:
    """Copy a verified snapshot into a live database with SQLite's backup API."""
    try:
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=30)) as src:
            with closing(sqlite3.connect(target, timeout=30)) as dst:
                src.backup(dst, pages=-1)
                if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise BackupError("restored database integrity check failed")
        if os.name == "posix":
            target.chmod(0o600)
    except BackupError:
        raise
    except sqlite3.Error as exc:
        raise BackupError(f"database restore failed ({type(exc).__name__})") from None
    except OSError as exc:
        raise BackupError(f"database restore failed ({type(exc).__name__})") from None


def _replace_staged(item: _StagedFile) -> None:
    if item.kind == "database":
        _restore_database_content(item.temporary, item.target)
        return
    replace_file(item.temporary, item.target)
    _sync_directory(item.target.parent)


def _stage_restore(source: Path, manifest: dict, config: AppConfig,
                   skip_roles: set[str]) -> tuple[list[_StagedFile], list[Path]]:
    items: list[_StagedFile] = []
    created: list[Path] = []
    try:
        for row in manifest["databases"]:
            if not row["exists"] or row.get("role") in skip_roles:
                continue
            target = Path(row["path"]).resolve()
            if not target.exists():
                created.append(target)
            items.append(_StagedFile(
                "database", target,
                _stage_file(source / row["backup"], target, row["sha256"], prefix=".backup-db-"),
                row.get("role"),
            ))
        config_target = Path(config.config_path)
        if not config_target.exists():
            created.append(config_target)
        items.append(_StagedFile(
            "config", config_target,
            _stage_file(source / manifest["config"]["name"], config_target,
                        manifest["config"]["sha256"], prefix=".backup-config-"),
            "config",
        ))
        for row in manifest["secrets"]:
            target = Path(row["path"]).resolve()
            if not target.exists():
                created.append(target)
            items.append(_StagedFile(
                "secret", target,
                _stage_file(source / row["file"], target, row["sha256"], prefix=".backup-secret-"),
                row["reference"],
            ))
        return items, created
    except BaseException:
        for item in items:
            item.temporary.unlink(missing_ok=True)
        raise


def _rollback(config: AppConfig, safety: Backup, *, skip_roles: set[str],
              created: list[Path]) -> None:
    """Best-effort return to the pre-restore safety backup."""
    manifest = _load_manifest(safety.path)
    items, _ = _stage_restore(safety.path, manifest, config, skip_roles)
    safety_targets = {item.target for item in items}
    try:
        for item in items:
            _replace_staged(item)
        for target in created:
            if target in safety_targets:
                continue
            target.unlink(missing_ok=True)
            for suffix in ("-wal", "-shm", "-journal"):
                Path(str(target) + suffix).unlink(missing_ok=True)
            _sync_directory(target.parent)
        for target in {item.target.parent for item in items}:
            _sync_directory(target)
    finally:
        for item in items:
            item.temporary.unlink(missing_ok=True)


def restore(config: AppConfig, backup_id: str) -> dict:
    """Verify, validate, snapshot, stage and atomically apply one backup."""
    try:
        return _restore(config, backup_id)
    except BackupError:
        raise
    except (CVEBeaconError, OSError, sqlite3.Error, shutil.Error) as exc:
        raise _failure("backup restore", exc) from None


def _restore(config: AppConfig, backup_id: str) -> dict:
    # Refuse contention before verification, validation or any filesystem work.
    with _locked(config, "backup-restore"):
        return _restore_locked(config, backup_id)


def _restore_locked(config: AppConfig, backup_id: str) -> dict:
    backup, manifest = _verify(config, backup_id)
    _refuse_newer(manifest)
    restored, validation_directory, validation_copies = _validate_restored_config(
        config, backup.path, manifest
    )
    try:
        _validate_restore(config, restored, manifest, validation_copies)
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
        skip_roles = {"users", "jobs"} if own_job is not None else set()
        preserved = _preserved_absent(manifest)
        safety = _create(
            config,
            include_secrets=bool(manifest["secrets"]),
            created_by="pre-restore",
            extra_databases=[Path(row["path"]) for row in manifest["databases"] if row["exists"]],
            extra_secret_paths=[Path(row["path"]) for row in manifest["secrets"]],
        )
        items: list[_StagedFile] = []
        created: list[Path] = []
        try:
            items, created = _stage_restore(backup.path, manifest, config, skip_roles)
            try:
                for item in items:
                    _replace_staged(item)
                from .update_state import migrate

                migrate(load_config(config.config_path))
            except KeyboardInterrupt:
                _rollback(config, safety, skip_roles=skip_roles, created=created)
                raise
            except BaseException as exc:
                try:
                    _rollback(config, safety, skip_roles=skip_roles, created=created)
                except BaseException as rollback_exc:
                    raise BackupError(
                        f"restore failed ({type(exc).__name__}) and automatic rollback "
                        f"from safety backup {safety.id} is incomplete "
                        f"({type(rollback_exc).__name__}); restore it manually"
                    ) from None
                raise BackupError(
                    f"restore failed ({type(exc).__name__}); previous state restored "
                    f"from safety backup {safety.id}"
                ) from None
        finally:
            for item in items:
                item.temporary.unlink(missing_ok=True)
        skipped = sorted({
            row["role"] for row in manifest["databases"]
            if row.get("role") in skip_roles and row["exists"]
        })
        return {
            "restored": backup_id,
            "safety": safety.id,
            "databases": sum(1 for item in items if item.kind == "database"),
            "secrets": [item.reference for item in items if item.kind == "secret"],
            **({"skipped": skipped} if skipped else {}),
            **({"preserved": preserved} if preserved else {}),
        }
    finally:
        if validation_directory is not None:
            validation_directory.cleanup()


def prune(config: AppConfig) -> dict:
    """Delete expired backups while retaining the newest valid ``keep_min``."""
    try:
        with _locked(config, "backup-prune"):
            return _prune(config)
    except BackupError:
        raise
    except (CVEBeaconError, OSError, sqlite3.Error, shutil.Error) as exc:
        raise _failure("backup prune", exc) from None


def _prune(config: AppConfig) -> dict:
    root = backup_root(config)
    if root.is_symlink():
        raise BackupError("backup directory must not be a symbolic link")
    if not root.is_dir():
        return {"removed": [], "kept": 0}
    policy = config.backup
    cutoff = datetime.now(timezone.utc) - timedelta(days=policy.retention_days)
    backups = list_backups(config)
    valid = [backup for backup in backups if backup.valid]
    keep = {backup.id for backup in valid[:policy.keep_min]}
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
        _sync_directory(root)
    return {"removed": removed, "kept": len(backups) - len(removed)}


def _archive_manifest(manifest: dict) -> dict:
    """Remove local filesystem identities from a downloaded manifest."""
    value = json.loads(json.dumps(manifest))
    for index, row in enumerate(value["databases"]):
        row["path"] = row.get("backup") or f"absent-{index}.db"
    value["config"]["source"] = value["config"]["name"]
    for row in value["secrets"]:
        row["path"] = row["file"]
    value["archived"] = True
    return value


def build_archive(config: AppConfig, backup_id: str, *, compress: bool | None = None) -> BinaryIO:
    """Stream one verified backup through a temporary, unnamed file."""
    try:
        with _locked(config, "backup-download"):
            return _build_archive(config, backup_id, compress=compress)
    except BackupError:
        raise
    except (CVEBeaconError, OSError, sqlite3.Error, shutil.Error, tarfile.TarError) as exc:
        raise _failure("backup download", exc) from None


def _build_archive(config: AppConfig, backup_id: str, *, compress: bool | None = None) -> BinaryIO:
    backup, manifest = _verify(config, backup_id)
    gzip = config.backup.compress if compress is None else compress
    buffer = tempfile.TemporaryFile()
    try:
        with tarfile.open(fileobj=buffer, mode="w:gz" if gzip else "w") as archive:
            for row in manifest["files"]:
                archive.add(backup.path / row["name"], arcname=f"{backup.id}/{row['name']}")
            raw = json.dumps(_archive_manifest(manifest), ensure_ascii=True,
                             sort_keys=True, indent=2).encode("utf-8")
            info = tarfile.TarInfo(f"{backup.id}/{BACKUP_MANIFEST}")
            info.size = len(raw)
            info.mtime = int(datetime.now(timezone.utc).timestamp())
            archive.addfile(info, io.BytesIO(raw))
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
    try:
        return _cli(args, config)
    except BackupBusy as exc:
        if dashboard_job_id() is not None:
            print(f"error: {exc}", file=sys.stderr)
            return DASHBOARD_LOCK_CONFLICT_EXIT
        raise


def _cli(args, config: AppConfig) -> int:
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
        if result.get("preserved"):
            print("left live data in place for entries absent from the backup: "
                  + ", ".join(result["preserved"]))
        return 0
    if command == "prune":
        result = prune(config)
        print(f"removed {len(result['removed'])} backup(s); {result['kept']} retained")
        return 0
    raise BackupError("unsupported backup command")
