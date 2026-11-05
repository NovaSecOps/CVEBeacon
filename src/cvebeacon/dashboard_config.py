"""Permission-scoped forms and validated, reversible configuration replacement."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import MISSING, dataclass, field, fields, replace
from datetime import date, datetime, time, timezone
import difflib
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import stat
import tempfile
import threading
import time as clock
import tomllib

from flask import Blueprint, abort, g, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException

from .config import (CANONICAL_FIELDS, OPTIONAL_FIELDS, DashboardConfig,
                     EmailConfig, HttpConfig, InventoryConfig, SourceConfig,
                     TeamsConfig, WatchConfig, load_config)
from .errors import CVEBeaconError, ConfigurationError
from .locking import LOCK_NAME, run_lock_path
from .watch.channels import (CREDENTIAL_FIELDS, ChannelConfig, COMMON_KEYS, TYPE_KEYS,
                             ENV_NAME_PATTERN, SECRET_FILE_LIMIT, SecretRef)
from .watch.directories import ensure_private_directory
from .watch.rules import Rule, EVENT_KINDS, LEAF_KEYS
from .watch.users import UserStore

MAX_CONFIG = 256 * 1024
KEEP_BACKUPS = 10
PREVIEW_SECONDS = 600
MAX_PENDING_PER_SESSION = 32
ABSENT_VERSION = "missing-configuration"
SECRET_PREFIX = ".dashboard-secret-"
STAGE_PREFIX = ".dashboard-staged-"
_VALIDATING = ContextVar("config_validation", default=False)
_RELOADING = ContextVar("config_reload", default=None)
_CONFIG_LOCKS = {}
_CONFIG_LOCKS_GUARD = threading.Lock()


def _config_thread_lock(path):
    key = str(path.resolve())
    with _CONFIG_LOCKS_GUARD:
        return _CONFIG_LOCKS.setdefault(key, threading.RLock())


@contextmanager
def _config_writer_lock(path):
    """Serialize configuration writers in this process and across processes."""
    thread_lock = _config_thread_lock(path)
    thread_lock.acquire()
    descriptor = None
    acquired = False
    try:
        lock_path = path.with_name(".config-" + path.name + ".lock")
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(lock_path, flags | os.O_CREAT, 0o600)
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise ConfigurationError("Configuration writer lock is unsafe")
            if os.name == "posix":
                if details.st_uid != os.geteuid():
                    raise ConfigurationError("Configuration writer lock is unsafe")
                if stat.S_IMODE(details.st_mode) & 0o077:
                    raise ConfigurationError("Configuration writer lock must be private")
            try:
                config_details = path.stat(follow_symlinks=False)
            except OSError:
                config_details = None
            if config_details is not None and (
                    config_details.st_dev, config_details.st_ino
            ) == (details.st_dev, details.st_ino):
                raise ConfigurationError("Configuration writer lock must not be the configuration file")
            if os.name == "posix":
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            else:
                import msvcrt
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            acquired = True
        except ConfigurationError:
            raise
        except OSError as exc:
            raise ConfigurationError("Cannot acquire the configuration writer lock") from exc
        yield
    finally:
        try:
            try:
                if acquired:
                    try:
                        if os.name == "posix":
                            import fcntl
                            fcntl.flock(descriptor, fcntl.LOCK_UN)
                        else:
                            import msvcrt
                            os.lseek(descriptor, 0, os.SEEK_SET)
                            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    except Exception:
                        logging.getLogger("cvebeacon").warning(
                            "Configuration writer lock release failed; continuing"
                        )
            finally:
                try:
                    if descriptor is not None:
                        os.close(descriptor)
                except Exception:
                    logging.getLogger("cvebeacon").warning(
                        "Configuration writer lock descriptor close failed; continuing"
                    )
        finally:
            try:
                thread_lock.release()
            except Exception:
                logging.getLogger("cvebeacon").warning(
                    "Configuration writer mutex release failed; continuing"
                )


class _ValidationLogFilter(logging.Filter):
    def filter(self, record):
        # Loader warnings can include user-controlled rule/channel labels.
        return not _VALIDATING.get()


logging.getLogger("cvebeacon").addFilter(_ValidationLogFilter())


def value(item):
    """Serialize a TOML value, including inline condition tables."""
    if isinstance(item, bool):
        return "true" if item else "false"
    if isinstance(item, str):
        return json.dumps(item, ensure_ascii=False).replace("\x7f", "\\u007f")
    if isinstance(item, int):
        # tomllib (and therefore load_config) accepts arbitrary-size integers.
        # Rejecting them here would make accepted live configurations unreadable.
        return str(item)
    if isinstance(item, float):
        return repr(item)
    if isinstance(item, (datetime, date, time)):
        return item.isoformat()
    if isinstance(item, list):
        return "[" + ", ".join(value(child) for child in item) + "]"
    if isinstance(item, dict):
        return "{ " + ", ".join(f"{value(key)} = {value(child)}" for key, child in item.items()) + " }"
    raise ValueError("Unsupported TOML value")


def dumps(document):
    """Write tables and arrays of tables; quote every key unambiguously."""
    lines = []

    def table(data, path=(), header=None):
        if header:
            lines.append(header)
        nested = []
        for key, item in data.items():
            child = (*path, key)
            name = ".".join(value(part) for part in child)
            if isinstance(item, dict):
                nested.append((item, child, f"[{name}]"))
            elif isinstance(item, list) and item and all(isinstance(row, dict) for row in item):
                nested.extend((row, child, f"[[{name}]]") for row in item)
            else:
                lines.append(f"{value(key)} = {value(item)}")
        lines.append("")
        for args in nested:
            table(*args)

    table(document)
    return "\n".join(lines)


def defaults(cls, **overrides):
    result = {}
    for field in fields(cls):
        result[field.name] = (field.default if field.default is not MISSING else
                              field.default_factory() if field.default_factory is not MISSING else None)
    return {**result, **overrides}


WATCH_FIELDS = {key: item for key, item in defaults(WatchConfig).items()
                if key not in {"rules", "channels", "reporting_identity"}}
SCHEMAS = {
    "watch": [("watch", WATCH_FIELDS)],
    "sources": [("sources", defaults(SourceConfig))],
    "reporting": [("watch.reporting", {"identity": "open"})],
    "inventory": [("inventory", defaults(InventoryConfig))],
    "dashboard": [("dashboard", defaults(DashboardConfig))],
    "http": [("http", defaults(HttpConfig))],
    "system": [("state", {"database": ".cvebeacon/state.db"}), ("output", {"directory": "reports"})],
    "notifications": [("notifications.teams", defaults(TeamsConfig)),
                      ("notifications.email", defaults(EmailConfig))],
}
SECTIONS = {
    "watch": "edit_watch", "sources": "edit_sources", "rules": "edit_rules",
    "channels": "edit_channels", "reporting": "edit_reporting",
    "inventory": "edit_inventory", "dashboard": "edit_dashboard",
    "http": "edit_http", "system": "edit_system",
    "notifications": "edit_channels", "product-mappings": "edit_inventory",
}
RULE_FIELDS = defaults(Rule)
MAPPING_FIELDS = dict.fromkeys(("vendor", "product", "cpe"))
BOOLEAN_FIELDS = {"enabled", "secure_cookie", "allow_insecure", "notify_reported"}
NUMBER_FIELDS = {"port", "max_items", "priority", "min_interval_seconds", "timeout_seconds",
                 "connect_timeout", "read_timeout", "retries", "backoff_seconds", "header_row",
                 "minimum_request_interval", "backfill_days", "overlap_minutes",
                 "session_lifetime_seconds", "session_idle_seconds"}
COMPLEX_FIELDS = {"sources", "channels", "events", "cvss_providers", "condition", "columns",
                  "to", "cc", "bcc", "recipients"}


def get_table(document, path):
    result = document
    for key in path.split("."):
        result = result.get(key, {})
        if not isinstance(result, dict):
            raise ConfigurationError("Configuration section must be a table")
    return result


def set_table(document, path, data):
    parts = path.split(".")
    result = document
    for key in parts[:-1]:
        result = result.setdefault(key, {})
    if path == "watch":
        data = {**data, **{key: item for key, item in result.get("watch", {}).items()
                          if key in {"rules", "channels", "reporting"}}}
    result[parts[-1]] = data


def check_document(document):
    """Never carry unknown inline credential fields into a preview or rewrite."""
    allowed = {"watch", "product_mappings", "notifications"}
    allowed.update(path for specs in SCHEMAS.values() for path, _ in specs if "." not in path)
    if set(document) - allowed:
        raise ConfigurationError("Unrecognized configuration fields; review the file before editing")
    for specs in SCHEMAS.values():
        for path, schema in specs:
            extra = {"rules", "channels", "reporting"} if path == "watch" else set()
            if set(get_table(document, path)) - set(schema) - extra:
                raise ConfigurationError("Unrecognized configuration fields; review the file before editing")
    if set(get_table(document, "notifications")) - {"teams", "email"}:
        raise ConfigurationError("Unrecognized notification fields")
    inventory = get_table(document, "inventory")
    columns = inventory.get("columns")
    if columns is not None:
        if not isinstance(columns, dict):
            raise ConfigurationError("inventory.columns must be a table")
        allowed_columns = set(CANONICAL_FIELDS) | set(OPTIONAL_FIELDS)
        if set(columns) - allowed_columns:
            raise ConfigurationError("Unrecognized inventory column keys; review the file before editing")
        if any(not isinstance(item, str) for item in columns.values()):
            raise ConfigurationError("Inventory column mappings must be strings")
    rules = get_table(document, "watch").get("rules", [])
    mappings = document.get("product_mappings", [])
    for rows, schema in ((rules, RULE_FIELDS), (mappings, MAPPING_FIELDS)):
        if not isinstance(rows, list) or any(not isinstance(row, dict) or set(row) - set(schema) for row in rows):
            raise ConfigurationError("Unrecognized configuration row fields")
    for row in get_table(document, "watch.channels").values():
        kind = row.get("type") if isinstance(row, dict) else None
        folded = kind.strip().casefold() if isinstance(kind, str) else None
        if not isinstance(row, dict) or folded not in TYPE_KEYS:
            raise ConfigurationError("Unknown channel type")
        if set(row) - COMMON_KEYS - TYPE_KEYS[folded]:
            raise ConfigurationError("Unrecognized channel fields; use secret references")
    # The core loader accepts older env names more liberally. The editor only
    # permits names, never pasted URLs or credential assignments. A channel
    # may itself be named something like data_env, so only string values of
    # credential fields are references.
    def references(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if (key.endswith("_env") and isinstance(child, str)
                        and child.strip() and ENV_NAME_PATTERN.fullmatch(child.strip()) is None):
                    raise ConfigurationError("Credential references must be environment variable names")
                references(child)
        elif isinstance(item, list):
            for child in item:
                references(child)
    references(document)


def redacted(document):
    if isinstance(document, dict):
        return {key: ("[redacted]" if isinstance(child, str)
                      and (key == "url" or key.endswith("_url")) else redacted(child))
                for key, child in document.items()}
    if isinstance(document, list):
        return [redacted(child) for child in document]
    return document


def safe_error(error, document, path):
    message = str(error).replace(str(path), "configuration").replace(str(path.parent), "configuration directory")
    strings = []
    known = {"any", "all", "not", *LEAF_KEYS, *COMMON_KEYS, *RULE_FIELDS, *MAPPING_FIELDS}
    known.update(SECTIONS)
    known.update({"state", "output", "product_mappings", "notifications", "teams", "email"})
    for specs in SCHEMAS.values():
        for path, schema in specs:
            known.update(path.split("."))
            known.update(schema)
    known.update(key for keys in TYPE_KEYS.values() for key in keys)
    def collect(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if key not in known:
                    strings.append(key)
                collect(child)
        elif isinstance(item, list):
            for child in item:
                collect(child)
        elif isinstance(item, str) and item:
            strings.append(item)
    collect(document)
    # Loader guidance can interpolate values with repr() or JSON quoting, so
    # redact the escaped representations as well as the literal strings.
    variants = set()
    for text in strings:
        normalized = {text, text.strip(), text.casefold(), text.strip().casefold()}
        for value in normalized:
            variants.add(value)
            variants.add(repr(value))
            variants.add(repr(value)[1:-1])
            variants.add(json.dumps(value, ensure_ascii=False))
            variants.add(json.dumps(value, ensure_ascii=False)[1:-1])
    # Preserve loader guidance, but never repeat submitted values or unknown
    # keys (including labels and URLs) in error output.
    for text in sorted((item for item in variants if item), key=len, reverse=True):
        if len(text) > 2:
            message = message.replace(text, "[value]")
        else:
            import re
            message = re.sub(r"(?<![\w])" + re.escape(text) + r"(?![\w])", "[value]", message)
    return message


def _private_directory(path):
    if path.is_symlink():
        raise ConfigurationError("Protected directory must not be a symbolic link")
    ensure_private_directory(path)
    if os.name == "posix":
        UserStore._trusted_directory_chain(path)
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise ConfigurationError("Protected directory must have owner-only permissions")
    return path


def read_regular(path, *, private=False):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        current = path.lstat()
        # Compare identity, not whole stat results: Windows fills fstat and
        # lstat fields differently for the same file.
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not stat.S_ISREG(current.st_mode)
                or getattr(current, "st_file_attributes", 0) & 0x400
                or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)):
            raise ConfigurationError("Configuration must be a regular file with one link")
        if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & (0o077 if private else 0o022)):
            raise ConfigurationError("Unsafe configuration ownership or permissions")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            content = handle.read(MAX_CONFIG + 1)
        if len(content) > MAX_CONFIG:
            raise ConfigurationError("Configuration exceeds the size limit")
        signature = hashlib.sha256(content + repr((info.st_dev, info.st_ino, info.st_mtime_ns,
                                                    info.st_mode, info.st_uid, info.st_gid)).encode()).hexdigest()
        return content, info, signature
    finally:
        os.close(fd)


def write_temp(directory, content, *, info=None, prefix=".config-"):
    fd, name = tempfile.mkstemp(prefix=prefix, dir=directory)
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            if info is not None:
                if os.name == "posix":
                    current = os.fstat(handle.fileno())
                    if (current.st_uid, current.st_gid) != (info.st_uid, info.st_gid):
                        os.fchown(handle.fileno(), info.st_uid, info.st_gid)
                os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode)) if hasattr(os, "fchmod") else None
            handle.flush()
            os.fsync(handle.fileno())
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def sync_directory(path):
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def project_document(document, section):
    """Return only the selected section's editable values for its diff."""
    if section in SCHEMAS:
        projected = {}
        for path, schema in SCHEMAS[section]:
            source = get_table(document, path)
            set_table(projected, path, {key: source[key] for key in schema if key in source})
        return projected
    if section == "rules":
        return {"watch": {"rules": get_table(document, "watch").get("rules", [])}}
    if section == "product-mappings":
        return {"product_mappings": document.get("product_mappings", [])}
    if section == "channels":
        return {"watch": {"channels": get_table(document, "watch.channels")}}
    return document


def document_get(document, path, default=None):
    result = document
    for key in path:
        try:
            result = result[key]
        except (KeyError, IndexError, TypeError):
            return default
    return result


def document_set(document, path, value):
    result = document
    for key in path[:-1]:
        result = result[key]
    result[path[-1]] = value


def replacement_document(document, replacements, config):
    """Point every consumer of a replaced target at its staged bytes."""
    result = deepcopy(document)
    staged = {replacement.target: str(replacement.staged) for replacement in replacements}
    for path, value in secret_references(result).items():
        if not path[-1].endswith("_file") or not value:
            continue
        target = effective_reference_path(config, path)
        if target in staged:
            document_set(result, path, staged[target])
            # The paired environment reference would mask the staged bytes for
            # this consumer during validation. Leave the document being saved
            # untouched; only the validation copy drops the environment key.
            parent = document_get(result, path[:-1])
            if isinstance(parent, dict):
                parent.pop(path[-1][:-5] + "_env", None)
    for replacement in replacements:
        document_set(result, replacement.reference, str(replacement.staged))
    return result


def effective_environment(document, path):
    """Return the environment reference the loaded configuration would use."""
    value = document_get(document, path)
    if isinstance(value, str) and value.strip():
        return value.strip()
    if path == ("sources", "nvd_api_key_env"):
        return defaults(SourceConfig)["nvd_api_key_env"]
    return None


def effective_environment_row(row, key, prefix):
    value = row.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    if prefix == ("sources",) and key == "nvd_api_key_env":
        return defaults(SourceConfig)["nvd_api_key_env"]
    return None


def environment_precedence(name):
    try:
        value = os.environ.get(name, "")
    except (TypeError, ValueError):
        return False
    return bool(value and value.strip())


def generated_file_paths(config, current_config):
    """Effective references to editor-generated secret files."""
    directory = _secret_directory(current_config).resolve()
    return {path.resolve() for path in effective_paths(config).values()
            if path.name.startswith(SECRET_PREFIX) and _inside(path.resolve(), directory)}


def _database_paths(path):
    return {
        path,
        path.with_name(path.name + "-wal"),
        path.with_name(path.name + "-shm"),
        path.with_name(path.name + "-journal"),
        Path(str(path) + ".lock"),
    }


def _config_reference_paths(configs):
    result = set()
    for config in configs:
        if config.sources is not None and config.sources.nvd_api_key_file is not None:
            result.add(config.sources.nvd_api_key_file.resolve())
        for channel in config.watch.channels:
            for key in CREDENTIAL_FIELDS.get(channel.type, ()):
                if not key.endswith("_file"):
                    continue
                reference = channel.secret(key[:-5])
                if reference is not None and reference.file is not None:
                    result.add(reference.file.resolve())
    return result


def _operation_storage_paths(config):
    """Files and private directory used by dashboard operations."""
    job_directory = (Path(config.database_path).parent / "dashboard-jobs").resolve()
    files = {(job_directory / "dashboard-jobs.db").resolve()}
    try:
        files.update(path.resolve() for path in job_directory.glob("job-*.log"))
    except OSError:
        pass
    files.add(Path(config.database_path).resolve().parent / LOCK_NAME)
    files.add(run_lock_path(config).resolve())
    return files, {job_directory}


def _candidate_derived_paths(updated, configs):
    """Candidate sidecars, job storage and run locks for changed storage roots."""
    state_changed = not any(_same_path(updated.database_path.resolve(),
                                       config.database_path.resolve())
                            for config in configs)
    state_parent_changed = not any(
        _same_path(updated.database_path.resolve().parent,
                   config.database_path.resolve().parent)
        for config in configs)
    watch_changed = not any(_same_path(updated.watch.database.resolve(),
                                       config.watch.database.resolve())
                            for config in configs)
    watch_parent_changed = not any(
        _same_path(updated.watch.database.resolve().parent,
                   config.watch.database.resolve().parent)
        for config in configs)
    files = set()
    directories = set()
    if state_parent_changed:
        files.add(Path(updated.database_path).resolve().parent / LOCK_NAME)
        job_directory = (Path(updated.database_path).parent / "dashboard-jobs").resolve()
        directories.add(job_directory)
        files.add((job_directory / "dashboard-jobs.db").resolve())
        try:
            files.update(path.resolve() for path in job_directory.glob("job-*.log"))
        except OSError:
            pass
    if state_changed:
        files.update(path.resolve() for path in _database_paths(updated.database_path)
                     if path != updated.database_path)
    if watch_changed:
        files.update(path.resolve() for path in _database_paths(updated.watch.database)
                     if path != updated.watch.database)
    if watch_parent_changed:
        files.update(path.resolve() for path in _database_paths(updated.watch.users_database))
        files.add(Path(updated.watch.database).resolve().parent / LOCK_NAME)
    return files, directories


def _protected_paths(configs, backup_dir, documents=(), *, base=None, reference_target=None):
    """Files and directories that operational or secret writes must not touch."""
    files = set()
    references = set()
    directories = set()
    directories.add(backup_dir.resolve())
    for config in configs:
        files.add(config.config_path.resolve())
        files.add(config.config_path.with_name(
            ".config-" + config.config_path.name + ".lock").resolve())
        files.update(path.resolve() for path in _database_paths(config.watch.database))
        files.update(path.resolve() for path in _database_paths(config.database_path))
        files.update(path.resolve() for path in _database_paths(config.watch.users_database))
        if config.inventory is not None:
            files.add(config.inventory.path.resolve())
        secret_directory = _secret_directory(config).resolve()
        directories.add(secret_directory)
        try:
            if secret_directory.is_dir() and not secret_directory.is_symlink():
                references.update(path.resolve() for path in secret_directory.iterdir()
                                  if path.is_file() and not path.is_symlink())
        except OSError:
            pass
        operation_files, operation_directories = _operation_storage_paths(config)
        files.update(operation_files)
        directories.update(operation_directories)
    references.update(_config_reference_paths(configs))
    for document in documents:
        for path, value in secret_references(document).items():
            if not path[-1].endswith("_file") or not value:
                continue
            try:
                references.add(resolve_reference(value, base))
            except (OSError, RuntimeError, ValueError):
                raise ConfigurationError("Secret file reference is not a valid path") from None
    if reference_target is not None:
        references = {path for path in references
                      if not _same_path(path, reference_target)}
    files.update(references)
    return files, directories


def secret_target(reference, base, configs, backup_dir, *, documents=()):
    """Resolve a writable existing secret file inside the current data directory."""
    if not isinstance(configs, (tuple, list)):
        configs = [configs]
    raw = Path(reference).expanduser()
    if not raw.is_absolute():
        raw = base / raw
    if raw.is_symlink():
        raise ConfigurationError("Secret file reference must not be a symbolic link")
    try:
        target = raw.resolve()
    except (OSError, RuntimeError, ValueError):
        raise ConfigurationError("Secret file reference is not a valid path") from None
    data_directory = configs[0].watch.users_database.parent.resolve()
    if target == data_directory or not _inside(target, data_directory):
        raise ConfigurationError(
            "Secret file content rotation must stay inside the protected data directory"
        )
    protected_files, protected_dirs = _protected_paths(
        configs, backup_dir, documents, base=base, reference_target=target)
    if any(_same_path(target, item) for item in protected_files):
        raise ConfigurationError(
            "Secret file reference must not alias configuration, account, operational or backup data"
        )
    backup_root = backup_dir.resolve()
    if target == backup_root or _inside(target, backup_root):
        raise ConfigurationError("Secret file reference must not alias a backup store")
    secret_directories = {_secret_directory(config).resolve() for config in configs}
    for directory in protected_dirs:
        if target == directory:
            raise ConfigurationError("Secret file reference must not alias a protected directory")
        if _inside(target, directory) and directory not in secret_directories:
            raise ConfigurationError("Secret file reference must not alias a protected directory")
    if not any(_inside(target, directory) for directory in secret_directories):
        for config in configs:
            if _inside(target, config.output_dir.resolve()):
                raise ConfigurationError("Secret file reference must not alias report output files")
    safe_secret_target(target)
    return target


@dataclass
class Pending:
    owner: str
    section: str
    version: str
    document: dict
    expires: float
    staged: tuple[Path, ...]
    replacements: tuple["Replacement", ...]
    lockout: bool
    references: tuple[Path, ...] = ()
    created: float = field(default_factory=clock.time)


@dataclass(frozen=True)
class Replacement:
    target: Path
    staged: Path
    reference: tuple[str, ...]
    environment: tuple[str, ...]


class Editor:
    def __init__(self, app, config, host):
        self.path = config.config_path
        self.config = config
        self.host = host
        self.lock = threading.RLock()
        self.pending = {}
        self.target = app.wsgi_app
        self.active_app = app
        self.jobs = app.extensions.get("dashboard_jobs")
        self.backup_dir = self.path.parent / ("." + self.path.name + ".backups")
        self.secret_dir = config.watch.users_database.parent / "dashboard-secrets"

    def __call__(self, environ, start_response):
        # Select an immutable generation without serializing unrelated requests
        # (password hashing and queries may take time).
        with self.lock:
            target = self.target
        return target(environ, start_response)

    def read_only(self):
        """Whether the configuration directory permits atomic replacement."""
        return not os.access(self.path.parent, os.W_OK | os.X_OK)

    def snapshot(self):
        """Read raw bytes, version signature and the TOML document if parseable."""
        if os.name == "posix":
            UserStore._trusted_directory_chain(self.path.parent)
        try:
            content, info, version = read_regular(self.path)
        except FileNotFoundError:
            return None, b"", None, ABSENT_VERSION
        try:
            document = tomllib.loads(content.decode("utf-8"))
        except (ValueError, UnicodeError):
            document = None
        return document, content, info, version

    def current_version(self):
        try:
            return read_regular(self.path)[2]
        except FileNotFoundError:
            return ABSENT_VERSION

    def read(self):
        document, content, info, version = self.snapshot()
        if document is None:
            if info is None:
                raise ConfigurationError(
                    "Configuration is missing; restore a retained backup or repair the file")
            raise ConfigurationError(
                "Configuration cannot be decoded; restore a retained backup or repair the file")
        # Refuse to render malformed/unknown fields, including nested condition
        # content. Validate the live file directly so a read-only directory can
        # still be viewed without writing a temporary file.
        check_document(document)
        token = _VALIDATING.set(True)
        try:
            config = load_config(self.path)
        except ConfigurationError:
            raise ConfigurationError(
                "Configuration is invalid; restore a retained backup or repair the file") from None
        finally:
            _VALIDATING.reset(token)
        self.secret_dir = config.watch.users_database.parent / "dashboard-secrets"
        return document, content, info, version, config

    def validate(self, document):
        check_document(document)
        try:
            content = dumps(document).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            raise ConfigurationError("Cannot serialize this configuration value") from None
        if len(content) > MAX_CONFIG:
            raise ConfigurationError("Configuration exceeds the size limit")
        temporary = write_temp(self.path.parent, content)
        token = _VALIDATING.set(True)
        try:
            config = replace(load_config(temporary), config_path=self.path)
            if config.inventory is None and not config.watch.enabled:
                raise ConfigurationError("The dashboard requires inventory.path or watch.enabled")
            return config, content
        except ConfigurationError as error:
            raise ConfigurationError(safe_error(error, document, temporary)) from None
        except (TypeError, ValueError, AttributeError):
            raise ConfigurationError("Invalid configuration value type") from None
        finally:
            _VALIDATING.reset(token)
            temporary.unlink(missing_ok=True)

    def _live_staged_paths(self):
        """Effective staged-secret references in current, running and backups.

        Returns None when discovery is incomplete for any reason, so callers
        retain files instead of deleting them and requests never fail here.
        """
        try:
            return self._discover_staged_paths()
        except Exception:  # noqa: BLE001 - discovery must fail closed, quietly
            return None

    def _discover_staged_paths(self):
        live = set()
        configs = [self.config]
        if self.path.exists() or self.path.is_symlink():
            # Only a regular, unlinked live file is loaded; anything else
            # (FIFO, symlink, directory) makes discovery incomplete.
            if self.path.is_symlink() or not self.path.is_file():
                return None
            try:
                configs.append(load_config(self.path))
            except (OSError, CVEBeaconError, ValueError, TypeError):
                return None
        for config in configs:
            live.update(path.resolve() for path in effective_paths(config).values())
        if self.backup_dir.exists():
            if self.backup_dir.is_symlink() or not self.backup_dir.is_dir():
                return None
            try:
                entries = list(self.backup_dir.iterdir())
            except OSError:
                return None
            for entry in entries:
                if not _backup_name(entry.name):
                    continue
                try:
                    document = tomllib.loads(
                        read_regular(entry, private=True)[0].decode("utf-8"))
                except (OSError, ValueError, UnicodeError, CVEBeaconError):
                    return None
                for path, value in secret_references(document).items():
                    if not path[-1].endswith("_file") or not isinstance(value, str):
                        continue
                    text = value.strip()
                    if not text:
                        continue
                    try:
                        live.add(resolve_reference(text, self.path.parent))
                    except (OSError, RuntimeError, ValueError):
                        return None
        return live

    def _cleanup_orphans(self):
        live = self._live_staged_paths()
        if live is None:
            return
        active = {path for pending in self.pending.values()
                  for path in (*pending.staged, *pending.references)}
        now = clock.time()
        data_directory = self.config.watch.users_database.parent
        directories = {
            self.secret_dir,
            data_directory / "dashboard-secrets",
            data_directory,
        }
        for directory in directories:
            try:
                if not directory.is_dir() or directory.is_symlink():
                    continue
                if (directory != data_directory and os.name == "posix"
                        and stat.S_IMODE(directory.stat().st_mode) & 0o077):
                    continue
                for path in directory.iterdir():
                    if not path.name.startswith(STAGE_PREFIX):
                        continue
                    if path in active or path.resolve() in live:
                        continue
                    try:
                        age = now - path.lstat().st_mtime
                    except OSError:
                        continue
                    if age > PREVIEW_SECONDS:
                        path.unlink(missing_ok=True)
            except OSError:
                continue

    def cleanup(self):
        with _config_writer_lock(self.path):
            for identifier, pending in list(self.pending.items()):
                if pending.expires < clock.monotonic():
                    self.discard(identifier)
            self._cleanup_orphans()

    def discard(self, identifier, *, committed=False):
        pending = self.pending.pop(identifier, None)
        if not pending:
            return
        active = {path for identifier2, pending2 in self.pending.items()
                  if identifier2 != identifier
                  for path in (*pending2.staged, *pending2.references)}
        live = self._live_staged_paths()
        if live is None:
            return
        for path in pending.staged:
            if (path.name.startswith(STAGE_PREFIX) and path not in active
                    and path.resolve() not in live):
                path.unlink(missing_ok=True)

    def _check_direct_urls(self, current, candidate, *, rollback):
        if rollback:
            return
        old_channels = get_table(current, "watch.channels")
        new_channels = get_table(candidate, "watch.channels")
        for name, row in old_channels.items():
            if not isinstance(row, dict) or "url" not in row:
                continue
            replacement = new_channels.get(name)
            if isinstance(replacement, dict) and replacement.get("url") != row["url"]:
                if ("url" not in replacement and
                        (replacement.get("url_env") or replacement.get("url_file"))):
                    # Converting a legacy direct URL to a reference is allowed;
                    # the reference change itself still needs manage_secrets.
                    continue
                raise ConfigurationError(
                    "Existing generic webhook endpoints are read-only; use url_env or url_file for a replacement channel"
                )
        for name, row in new_channels.items():
            if not isinstance(row, dict) or "url" not in row:
                continue
            legacy = old_channels.get(name)
            if isinstance(legacy, dict) and legacy.get("url") == row["url"]:
                continue
            if any(isinstance(item, dict) and item.get("url") == row["url"]
                   for item in old_channels.values()):
                # A renamed channel keeps the same direct endpoint.
                continue
            raise ConfigurationError(
                "Inline generic webhook URLs are only retained unchanged from an existing channel; "
                "use url_env or url_file for new or changed endpoints"
            )

    def _check_replacement(self, current, candidate, replacement,
                           current_config, candidate_config):
        old_target = effective_reference_path(current_config, replacement.reference)
        new_target = effective_reference_path(candidate_config, replacement.reference)
        return old_target is not None and old_target == new_target == replacement.target

    def preview(self, section, document, version, staged=(), replacements=(), *, current_document, current_config):
        if self.read_only():
            raise ConfigurationError("The configuration directory is read-only")
        self.cleanup()
        mine = sum(1 for pending in self.pending.values() if pending.owner == g.sid)
        if mine >= MAX_PENDING_PER_SESSION:
            raise ConfigurationError("Too many pending previews for this session; try again later")
        invalid_current = current_document is None or current_config is None
        unparseable = current_document is None
        checks_config = current_config or self.config
        if unparseable and section == "rollback" and "manage_secrets" not in g.permissions:
            abort(403)
        file_changed, env_changed = raw_reference_changes(
            current_document, document, self.config, self.path.parent,
            current_valid=current_config is not None)
        if file_changed and not g.user.is_admin:
            abort(403)
        if env_changed and "manage_secrets" not in g.permissions:
            abort(403)
        if replacements:
            candidate_config = self.validate(document)[0]
            validation_document = replacement_document(
                document, replacements, candidate_config)
        else:
            candidate_config = None
            validation_document = document
        updated, _ = self.validate(validation_document)
        authority_config = candidate_config or updated
        if ((path_authority_changed(authority_config, checks_config, self.config)
                or dashboard_authority_changed(authority_config, checks_config, self.config))
                and not g.user.is_admin):
            abort(403)
        if (credential_authority_changed(authority_config, checks_config, self.config)
                and "manage_secrets" not in g.permissions):
            abort(403)
        if current_document is not None:
            self._check_direct_urls(current_document, document, rollback=section == "rollback")
        for replacement in replacements:
            if not self._check_replacement(current_document or {}, document, replacement,
                                           checks_config, authority_config):
                raise ConfigurationError("Secret reference changed; create a new preview")
            explicit_environment = document_get(document, replacement.environment)
            environment = effective_environment(document, replacement.environment)
            if (isinstance(explicit_environment, str) and explicit_environment) or (
                    environment and environment_precedence(environment)):
                raise ConfigurationError(
                    f"Cannot stage new file contents while {environment} is set; "
                    "the environment value would take precedence, so unset it or keep using the environment reference"
                )
        check_protected_paths(updated, self.path, self.backup_dir,
                              [checks_config, self.config],
                              [document] if invalid_current else
                              [item for item in (current_document, document) if item is not None])
        lockout = (invalid_current or
                   updated.dashboard != self.config.dashboard or
                   updated.dashboard != checks_config.dashboard or
                   updated.watch.users_database != self.config.watch.users_database or
                   updated.watch.users_database != checks_config.watch.users_database)
        if lockout:
            if updated.watch.users_database != self.config.watch.users_database or \
                    updated.watch.users_database != checks_config.watch.users_database:
                if not g.user.is_admin:
                    abort(403)
                users = UserStore(updated.watch.users_database)
                if not users.dashboard_accounts() or not users.has_admin():
                    raise ConfigurationError("The destination account database needs an enabled administrator")
        references = generated_file_paths(authority_config, checks_config)
        owned = {replacement.staged for replacement in replacements}
        for path in references - owned:
            try:
                os.utime(path, None)
            except OSError:
                raise ConfigurationError(
                    "Cannot renew the shared protection for a staged secret; try the preview again"
                ) from None
        identifier = secrets.token_hex(32)
        self.pending[identifier] = Pending(g.sid, section, version, document,
                                          clock.monotonic() + PREVIEW_SECONDS, tuple(staged),
                                          tuple(replacements), lockout, tuple(references))
        return identifier, lockout

    def backups(self):
        if not self.backup_dir.exists():
            return []
        _private_directory(self.backup_dir)
        return sorted((path.name for path in self.backup_dir.iterdir()
                       if _backup_name(path.name)), reverse=True)[:KEEP_BACKUPS]

    def commit(self, identifier, section, users, permission, confirmed):
        if self.read_only():
            raise ConfigurationError("The configuration directory is read-only")
        self.cleanup()
        with _config_writer_lock(self.path):
            return self._commit_locked(identifier, section, users, permission, confirmed)

    def _commit_locked(self, identifier, section, users, permission, confirmed):
        pending = self.pending.get(identifier)
        if not pending or pending.owner != g.sid or pending.section != section:
            abort(400)
        if pending.lockout and not confirmed:
            raise ConfigurationError("Confirm the access and session changes before saving")
        original = recovery = temporary = backup = backup_temp = None
        prepared = []
        applied = []
        replaced = False
        committed = False
        transition = None
        try:
            # Prepare against a stable raw snapshot. A live file that fails the
            # loader may still be replaced through a retained backup, but a
            # normal section save cannot be composed from unparseable bytes.
            old, original, info, version = self.snapshot()
            if old is None and section != "rollback":
                raise ConfigurationError(
                    "Current configuration is missing or invalid; restore a retained backup")
            if version != pending.version:
                abort(409, "Configuration changed; reload the form")
            if old is not None and section != "rollback":
                check_document(old)
            current_config = None
            if old is not None:
                try:
                    current_config = self.validate(old)[0]
                except ConfigurationError:
                    current_config = None
            checks_config = current_config or self.config
            invalid_current = old is None or current_config is None
            unparseable = old is None
            # Permission checks precede any read of a new reference target.
            with users.transaction() as db:
                probe = None
                for needed in {"view", *permission}:
                    probe = users.require_permission_in(db, g.entry.proof, needed)
                early_permissions = users.permissions_in(db, probe)
            if ((unparseable and section == "rollback"
                    and "manage_secrets" not in early_permissions)):
                abort(403)
            if pending.replacements and "manage_secrets" not in early_permissions:
                abort(403)
            file_changed, env_changed = raw_reference_changes(
                old, pending.document, self.config, self.path.parent,
                current_valid=current_config is not None)
            if file_changed and not probe.is_admin:
                abort(403)
            if env_changed and "manage_secrets" not in early_permissions:
                abort(403)
            updated, content = self.validate(pending.document)
            if ((path_authority_changed(updated, checks_config, self.config)
                    or dashboard_authority_changed(updated, checks_config, self.config))
                    and not probe.is_admin):
                abort(403)
            if (credential_authority_changed(updated, checks_config, self.config)
                    and "manage_secrets" not in early_permissions):
                abort(403)
            for replacement in pending.replacements:
                if not self._check_replacement(old or {}, pending.document, replacement,
                                               checks_config, updated):
                    raise ConfigurationError("Secret reference changed; create a new preview")
                explicit_environment = document_get(pending.document, replacement.environment)
                environment = effective_environment(pending.document, replacement.environment)
                if (isinstance(explicit_environment, str) and explicit_environment) or (
                        environment and environment_precedence(environment)):
                    raise ConfigurationError(
                        f"Cannot stage new file contents while {environment} is set; "
                        "the environment value would take precedence, so unset it or keep using the environment reference"
                    )
                target_info = safe_secret_target(replacement.target)
                try:
                    new_bytes = replacement.staged.read_bytes()
                except OSError:
                    raise ConfigurationError("Staged secret cannot be read") from None
                if len(new_bytes) > SECRET_FILE_LIMIT:
                    raise ConfigurationError("Secret must contain 1–16384 bytes of text")
                secret_directory = _private_directory(_secret_directory(checks_config))
                secret_temp = write_temp(secret_directory, new_bytes, info=target_info,
                                         prefix=SECRET_PREFIX)
                prepared.append((replacement, target_info, secret_temp))
            self.validate(replacement_document(pending.document, pending.replacements, updated))
            # The reloaded application uses final references; SecretRef resolves
            # file contents dynamically, so preparation does not touch live files.
            from .dashboard import create_app
            token = _RELOADING.set(self)
            try:
                replacement_app = create_app(updated, host=self.host, jobs=self.jobs)
            finally:
                _RELOADING.reset(token)
            destination_users = replacement_app.extensions["dashboard_users"]
            if not destination_users.dashboard_accounts():
                raise ConfigurationError("Configuration changes cannot turn off account authentication")
            if not destination_users.has_admin():
                raise ConfigurationError("The destination account database needs an enabled administrator")
            if self.jobs is not None:
                transition = self.jobs.reserve_reconfigure(updated, destination_users)
            # The shared writer guard covers the account transaction, every
            # permission/credential check, target capture and live writes, the
            # transaction exit, and compensation below.
            with users.transaction() as db:
                for needed in {"view", *permission}:
                    actor = users.require_permission_in(db, g.entry.proof, needed)
                if self.current_version() != version:
                    abort(409, "Configuration changed; reload the form")
                if ((unparseable and section == "rollback"
                        and "manage_secrets" not in users.permissions_in(db, actor))):
                    abort(403)
                if ((path_authority_changed(updated, checks_config, self.config)
                        or dashboard_authority_changed(updated, checks_config, self.config))
                        and not actor.is_admin):
                    abort(403)
                if pending.replacements and "manage_secrets" not in users.permissions_in(db, actor):
                    abort(403)
                if (credential_authority_changed(updated, checks_config, self.config)
                        and "manage_secrets" not in users.permissions_in(db, actor)):
                    abort(403)
                if old is not None:
                    self._check_direct_urls(old, pending.document, rollback=section == "rollback")
                lockout = (pending.lockout or invalid_current or
                           updated.dashboard != self.config.dashboard or
                           updated.dashboard != checks_config.dashboard or
                           updated.watch.users_database != self.config.watch.users_database or
                           updated.watch.users_database != checks_config.watch.users_database)
                if lockout and not confirmed:
                    raise ConfigurationError("Confirm the access and session changes before saving")
                if (updated.watch.users_database != self.config.watch.users_database or
                        updated.watch.users_database != checks_config.watch.users_database):
                    if not actor.is_admin:
                        abort(403)
                    destination = UserStore(updated.watch.users_database)
                    if not destination.dashboard_accounts() or not destination.has_admin():
                        raise ConfigurationError("The destination account database needs an enabled administrator")
                check_protected_paths(updated, self.path, self.backup_dir,
                                      [checks_config, self.config],
                                      [pending.document] if invalid_current else
                                      [item for item in (old, pending.document) if item is not None])
                for replacement, target_info, secret_temp in prepared:
                    if not self._check_replacement(old or {}, pending.document, replacement,
                                                   checks_config, updated):
                        raise ConfigurationError("Secret reference changed; create a new preview")
                    target_info = safe_secret_target(replacement.target)
                    try:
                        old_bytes = read_regular(replacement.target, private=True)[0]
                    except OSError:
                        raise ConfigurationError("Secret file cannot be read") from None
                    os.replace(secret_temp, replacement.target)
                    # Record recovery immediately after the live replacement.
                    applied.append((replacement.target, old_bytes, target_info))
                    sync_directory(replacement.target.parent)
                # Backup and prepare both replacement and recovery bytes before
                # the final version check and atomic replacement. A missing live
                # file has nothing to back up or restore.
                if info is not None:
                    backup_dir = _private_directory(self.backup_dir)
                    backup = backup_dir / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ-") + secrets.token_hex(8) + ".toml")
                    backup_temp = write_temp(backup_dir, original)
                    os.replace(backup_temp, backup)
                    sync_directory(backup_dir)
                temporary = write_temp(self.path.parent, content, info=info)
                if info is not None:
                    recovery = write_temp(self.path.parent, original, info=info)
                if self.current_version() != version:
                    abort(409, "Configuration changed; reload the form")
                changed = sum(1 for line in difflib.ndiff(
                    dumps(old).splitlines() if old is not None else [],
                    dumps(pending.document).splitlines())
                              if line.startswith(("+ ", "- ")))
                new_references = {value for value in secret_references(pending.document).values()
                                  if isinstance(value, str)}
                secret_writes = len(prepared) + sum(
                    1 for path in pending.staged
                    if path.name.startswith(SECRET_PREFIX) and str(path) in new_references)
                users._append_audit(db, f"config_save:{section}:changed_lines={changed}:secrets={secret_writes}",
                                    actor.username, datetime.now(timezone.utc).isoformat(), actor=actor.username)
                os.replace(temporary, self.path)
                replaced = True
                sync_directory(self.path.parent)
            if transition is not None:
                transition.publish()
                transition = None
            committed = True
            self.config = updated
            self.target = replacement_app.wsgi_app
            self.active_app = replacement_app
            self.secret_dir = updated.watch.users_database.parent / "dashboard-secrets"
        except BaseException:
            if transition is not None:
                try:
                    transition.abort()
                except Exception:
                    logging.getLogger("cvebeacon").warning(
                        "Job manager reservation cleanup failed; continuing")
            if not committed:
                for target, old_bytes, target_info in reversed(applied):
                    try:
                        restore = write_temp(target.parent, old_bytes, info=target_info, prefix=SECRET_PREFIX)
                        os.replace(restore, target)
                        sync_directory(target.parent)
                    except OSError:
                        logging.getLogger("cvebeacon").error("Secret file recovery failed")
                recovered = not replaced
                if replaced:
                    try:
                        if recovery is not None:
                            os.replace(recovery, self.path)
                        else:
                            self.path.unlink(missing_ok=True)
                        sync_directory(self.path.parent)
                        recovered = True
                    except OSError:
                        logging.getLogger("cvebeacon").error(
                            "Configuration recovery failed; inspect the live file and retained backups")
                if backup and recovered:
                    backup.unlink(missing_ok=True)
            raise
        finally:
            cleanup_paths = [temporary, recovery, backup_temp]
            cleanup_paths.extend(item[2] for item in prepared)
            for path in cleanup_paths:
                if not path:
                    continue
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    logging.getLogger("cvebeacon").warning(
                        "Configuration temporary cleanup failed; continuing"
                    )
        # Backup retention is maintenance, not part of the committed change.
        try:
            if self.backup_dir.exists():
                for name in sorted(path.name for path in self.backup_dir.iterdir() if _backup_name(path.name))[:-KEEP_BACKUPS]:
                    (self.backup_dir / name).unlink(missing_ok=True)
        except OSError:
            logging.getLogger("cvebeacon").warning("Configuration saved; backup retention cleanup failed")
        # Cleanup after the commit cannot undo a successful save.
        try:
            self.discard(identifier, committed=True)
        except OSError:
            logging.getLogger("cvebeacon").warning("Configuration saved; staged secret cleanup failed")


def _backup_name(name):
    import re
    return re.fullmatch(r"[0-9]{8}T[0-9]{12}Z-[0-9a-f]{16}\.toml", name) is not None


def _walk(document):
    if isinstance(document, dict):
        for key, child in document.items():
            yield (key,), child
            for path, value in _walk(child):
                yield (key, *path), value
    elif isinstance(document, list):
        for index, child in enumerate(document):
            for path, value in _walk(child):
                yield (index, *path), value


def secret_references(document):
    """Map each *reference* location to its configured string value."""
    return {path: item for path, item in _walk(document)
            if isinstance(path[-1], str) and path[-1].endswith(("_env", "_file"))
            and isinstance(item, str)}


def _channel_kind(row):
    kind = row.get("type") if isinstance(row, dict) else None
    return kind.strip().casefold() if isinstance(kind, str) else None


def channel_has_credentials(row):
    """Whether a raw channel row carries a secret reference or direct URL."""
    if not isinstance(row, dict):
        return False
    if isinstance(row.get("url"), str) and row.get("url").strip():
        return True
    kind = _channel_kind(row)
    if kind not in CREDENTIAL_FIELDS:
        return False
    # Whitespace-only values are absent, as the loader treats them.
    return any(isinstance(row.get(key), str) and row.get(key).strip()
               for key in CREDENTIAL_FIELDS[kind])


def _config_channel_has_credentials(channel):
    if isinstance(channel.options.get("url"), str) and channel.options.get("url"):
        return True
    return any(isinstance(item, SecretRef) for item in channel.options.values())


def effective_reference_path(config, reference):
    """Resolve a raw TOML reference position through the loader's config."""
    if reference == ("sources", "nvd_api_key_file"):
        return config.sources.nvd_api_key_file
    if (len(reference) >= 4 and reference[0] == "watch"
            and reference[1] == "channels" and reference[-1].endswith("_file")):
        channel = next((item for item in config.watch.channels
                        if item.name == reference[2]), None)
        if channel is None:
            return None
        secret = channel.secret(reference[-1][:-5])
        return secret.file if secret is not None else None
    return None


def credential_identities(config):
    """Loader-resolved credential-bearing rows and their effective references."""
    identities = {
        ("source", "nvd_api_key"): (
            "source", config.sources.nvd_api_key_env,
            config.sources.nvd_api_key_file,
        ),
        ("notifications", "teams"): config.teams,
        ("notifications", "email"): config.email,
    }
    for channel in config.watch.channels:
        if _config_channel_has_credentials(channel):
            identities[("channel", channel.name)] = channel
    return identities


def credential_authority_changed(candidate, baseline, running):
    """Whether a credential-bearing row differs from either baseline."""
    candidate_rows = credential_identities(candidate)
    baseline_rows = credential_identities(baseline)
    running_rows = credential_identities(running)
    for identity, value in candidate_rows.items():
        if identity not in baseline_rows or baseline_rows[identity] != value:
            return True
        if identity not in running_rows or running_rows[identity] != value:
            return True
    candidate_info = _config_channel_info(candidate)
    for rows, other in ((baseline_rows, baseline), (running_rows, running)):
        other_info = _config_channel_info(other)
        for identity in rows:
            if (identity[0] == "channel" and identity not in candidate_rows
                    and _channel_owner_replaced(candidate_info, other_info, identity[1])):
                return True
    return False


def _raw_channel_info(document, base):
    if not isinstance(document, dict):
        return None
    watch = document.get("watch")
    if watch is not None and not isinstance(watch, dict):
        return None
    channels = (watch or {}).get("channels") if isinstance(watch, dict) else None
    if channels is None:
        return {}
    if not isinstance(channels, dict):
        return None
    result = {}
    for name, row in channels.items():
        if not isinstance(row, dict):
            return None
        kind = _channel_kind(row)
        files = {}
        for key, value in row.items():
            if not isinstance(key, str) or not key.endswith("_file"):
                continue
            if value is None:
                continue
            if not isinstance(value, str):
                return None
            if value.strip():
                try:
                    files[key] = str(resolve_reference(value.strip(), base))
                except (OSError, RuntimeError, ValueError):
                    return None
        result[name] = (kind, files)
    return result


def _config_channel_info(config):
    result = {}
    for channel in config.watch.channels:
        files = {key: str(reference.file)
                 for key in CREDENTIAL_FIELDS.get(channel.type, ())
                 if key.endswith("_file")
                 for reference in (channel.secret(key[:-5]),)
                 if reference is not None and reference.file is not None}
        result[channel.name] = (channel.type, files)
    return result


def _channel_info_renames(candidate_info, baseline_info):
    if candidate_info is None or baseline_info is None:
        return {}
    candidate_names = set(candidate_info)
    deleted = set(baseline_info) - candidate_names
    pairs = {}
    used = set()
    for name in candidate_names - set(baseline_info):
        kind, files = candidate_info[name]
        for old in sorted(deleted - used):
            if baseline_info[old] == (kind, files):
                pairs[name] = old
                used.add(old)
                break
    return pairs


def _channel_owner_replaced(candidate_info, baseline_info, name):
    """Whether a vanished channel is replaced by a same-type channel rename."""
    if candidate_info is None or baseline_info is None:
        return True
    if name in candidate_info:
        return True
    old = baseline_info.get(name)
    if old is None:
        return False
    old_type = old[0]
    return any(candidate_name not in baseline_info and info[0] == old_type
               for candidate_name, info in candidate_info.items())


DEFAULT_REFERENCES = {
    ("sources", "nvd_api_key_env"): defaults(SourceConfig)["nvd_api_key_env"],
    ("dashboard", "password_hash_env"): defaults(DashboardConfig)["password_hash_env"],
    ("notifications", "teams", "webhook_env"): defaults(TeamsConfig)["webhook_env"],
    ("notifications", "email", "tenant_id_env"): defaults(EmailConfig)["tenant_id_env"],
    ("notifications", "email", "client_id_env"): defaults(EmailConfig)["client_id_env"],
    ("notifications", "email", "client_secret_env"): defaults(EmailConfig)["client_secret_env"],
}


def _raw_reference_map(document, base):
    if not isinstance(document, dict):
        return None
    for table in ("sources", "notifications", "dashboard", "watch"):
        if table in document and not isinstance(document[table], dict):
            return None
    notifications = document.get("notifications")
    if isinstance(notifications, dict):
        for key in ("teams", "email"):
            if key in notifications and not isinstance(notifications[key], dict):
                return None
    values = dict(DEFAULT_REFERENCES)
    for path, value in secret_references(document).items():
        text = value.strip()
        if path[-1].endswith("_file"):
            if not text:
                continue
            try:
                values[path] = str(resolve_reference(text, base))
            except (OSError, RuntimeError, ValueError):
                return None
        elif text:
            values[path] = text
    return values


def _config_reference_map(config):
    values = dict(DEFAULT_REFERENCES)
    values[("sources", "nvd_api_key_env")] = config.sources.nvd_api_key_env
    values[("dashboard", "password_hash_env")] = config.dashboard.password_hash_env
    values[("notifications", "teams", "webhook_env")] = config.teams.webhook_env
    values[("notifications", "email", "tenant_id_env")] = config.email.tenant_id_env
    values[("notifications", "email", "client_id_env")] = config.email.client_id_env
    values[("notifications", "email", "client_secret_env")] = config.email.client_secret_env
    if config.sources.nvd_api_key_file is not None:
        values[("sources", "nvd_api_key_file")] = str(config.sources.nvd_api_key_file)
    for channel in config.watch.channels:
        for key in CREDENTIAL_FIELDS.get(channel.type, ()):
            if not key.endswith("_file"):
                continue
            reference = channel.secret(key[:-5])
            if reference is None:
                continue
            if reference.env is not None:
                values[("watch", "channels", channel.name, key[:-5] + "_env")] = reference.env
            if reference.file is not None:
                values[("watch", "channels", channel.name, key)] = str(reference.file)
    return values


def _mapped_reference_key(path, renames):
    if (len(path) >= 4 and path[0] == "watch" and path[1] == "channels"
            and path[2] in renames):
        return (*path[:2], renames[path[2]], *path[3:])
    return path


def raw_reference_changes(current_document, candidate, running_config, base, *, current_valid=True):
    """Cheap pre-validation check for changed environment and file references."""
    candidate_map = _raw_reference_map(candidate, base)
    if candidate_map is None:
        return True, True
    baselines = []
    current_map = (_raw_reference_map(current_document, base)
                   if current_valid and current_document is not None else None)
    candidate_info = _raw_channel_info(candidate, base)
    if current_map is not None:
        current_info = _raw_channel_info(current_document, base)
        baselines.append((current_map, _channel_info_renames(
            candidate_info, current_info), current_info))
    running_map = _config_reference_map(running_config)
    running_info = _config_channel_info(running_config)
    baselines.append((running_map, _channel_info_renames(
        candidate_info, running_info), running_info))
    file_changed = env_changed = False
    for baseline_map, renames, baseline_info in baselines:
        translated = {_mapped_reference_key(key, renames): value
                      for key, value in candidate_map.items()}
        for key, value in translated.items():
            if baseline_map.get(key) == value:
                continue
            if key[-1].endswith("_file"):
                file_changed = True
            else:
                env_changed = True
        for key in baseline_map:
            if key in translated:
                continue
            if (len(key) >= 3 and key[0] == "watch" and key[1] == "channels"
                    and not _channel_owner_replaced(candidate_info, baseline_info, key[2])):
                continue
            if key[-1].endswith("_file"):
                file_changed = True
            else:
                env_changed = True
    return file_changed, env_changed


def effective_paths(config):
    """The loader's resolved filesystem identities for an AppConfig."""
    values = {
        ("state",): config.database_path,
        ("watch",): config.watch.database,
        ("users",): config.watch.users_database,
        ("output",): config.output_dir,
    }
    if config.inventory is not None:
        values[("inventory",)] = config.inventory.path
    if config.sources.nvd_api_key_file is not None:
        values[("source", "nvd_api_key_file")] = config.sources.nvd_api_key_file
    for channel in config.watch.channels:
        for key in CREDENTIAL_FIELDS.get(channel.type, ()):
            if not key.endswith("_file"):
                continue
            reference = channel.secret(key[:-5])
            if reference is not None and reference.file is not None:
                values[("channel", channel.name, key)] = reference.file
    return values


def _channel_file_paths(channel):
    return {key: reference.file for key in CREDENTIAL_FIELDS.get(channel.type, ())
            if key.endswith("_file")
            for reference in (channel.secret(key[:-5]),)
            if reference is not None and reference.file is not None}


def _channel_renames(candidate, other):
    """Map candidate channel names to matching deleted channels in ``other``."""
    other_names = {channel.name for channel in other.watch.channels}
    candidate_names = {channel.name for channel in candidate.watch.channels}
    deleted = other_names - candidate_names
    pairs = {}
    used = set()
    other_by_name = {channel.name: channel for channel in other.watch.channels}
    for name, channel in ((item.name, item) for item in candidate.watch.channels):
        if name in other_names:
            continue
        for old in sorted(deleted - used):
            previous = other_by_name[old]
            if (previous.type == channel.type
                    and _channel_file_paths(previous) == _channel_file_paths(channel)):
                pairs[name] = old
                used.add(old)
                break
    return pairs


def _mapped_identity(identity, renames):
    if identity[0] == "channel" and identity[1] in renames:
        return (identity[0], renames[identity[1]], *identity[2:])
    return identity


def path_authority_changed(candidate, baseline, running):
    """Whether a candidate changes effective filesystem paths as the loader sees them."""
    candidate_paths = effective_paths(candidate)
    baseline_paths = effective_paths(baseline)
    running_paths = effective_paths(running)
    baseline_renames = _channel_renames(candidate, baseline)
    running_renames = _channel_renames(candidate, running)
    candidate_info = _config_channel_info(candidate)
    for identity, path in candidate_paths.items():
        baseline_identity = _mapped_identity(identity, baseline_renames)
        if baseline_paths.get(baseline_identity) != path:
            return True
        running_identity = _mapped_identity(identity, running_renames)
        if running_paths.get(running_identity) != path:
            return True
    baseline_present = {_mapped_identity(identity, baseline_renames)
                        for identity in candidate_paths}
    running_present = {_mapped_identity(identity, running_renames)
                       for identity in candidate_paths}
    for identity in baseline_paths:
        if identity in baseline_present:
            continue
        if (identity[0] == "channel"
                and not _channel_owner_replaced(candidate_info,
                                                _config_channel_info(baseline),
                                                identity[1])):
            continue
        return True
    for identity in running_paths:
        if identity in running_present:
            continue
        if (identity[0] == "channel"
                and not _channel_owner_replaced(candidate_info,
                                                _config_channel_info(running),
                                                identity[1])):
            continue
        return True
    return False


def dashboard_authority_changed(candidate, baseline, running):
    return (candidate.dashboard != baseline.dashboard
            or candidate.dashboard != running.dashboard)

def resolve_reference(value, base):
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def safe_secret_target(path):
    """Validate the existing file behind a secret reference before rewriting it."""
    if path.is_symlink():
        raise ConfigurationError("Secret file must not be a symbolic link")
    try:
        details = path.lstat()
    except OSError:
        raise ConfigurationError("Secret file cannot be read") from None
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise ConfigurationError("Secret file must be a regular file with one link")
    if os.name == "posix":
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise ConfigurationError("Secret file must be owned by this account and private")
    try:
        UserStore._trusted_directory_chain(path.parent)
    except CVEBeaconError:
        raise ConfigurationError("Secret file directory is not trusted") from None
    return details


def _same_path(left, right):
    if left == right:
        return True
    try:
        return left.exists() and right.exists() and left.samefile(right)
    except OSError:
        return False


def _inside(path, directory):
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def check_protected_paths(updated, config_path, backup_dir, configs, documents=()):
    """Reject settings that would place operational data in a protected store."""
    protected_files, protected_dirs = _protected_paths(
        configs, backup_dir, documents, base=config_path.parent)
    existing_files = set(protected_files)
    existing_dirs = set(protected_dirs)
    # The candidate's own primary paths are the values under test. Protect
    # their sidecars and the account store, but allow an unchanged primary path.
    for path in _database_paths(updated.watch.database) - {updated.watch.database}:
        protected_files.add(path.resolve())
    for path in _database_paths(updated.database_path) - {updated.database_path}:
        protected_files.add(path.resolve())
    protected_files.update(path.resolve() for path in
                           _database_paths(updated.watch.users_database))
    operation_files, operation_directories = _operation_storage_paths(updated)
    protected_files.update(operation_files)
    protected_dirs.update(operation_directories)
    protected_dirs.add(_secret_directory(updated).resolve())

    def aliases_protected_file(path, unchanged):
        resolved = path.resolve()
        if any(_same_path(resolved, item) for item in unchanged):
            return False
        if any(_same_path(resolved, item) for item in protected_files):
            return True
        return any(any(_same_path(parent, item) for item in protected_files)
                   for parent in resolved.parents)

    def aliases_protected_directory(path):
        resolved = path.resolve()
        return any(resolved == directory or _inside(resolved, directory)
                   for directory in protected_dirs)

    watch_unchanged = {config.watch.database.resolve() for config in configs}
    state_unchanged = {config.database_path.resolve() for config in configs}
    output_unchanged = {config.output_dir.resolve() for config in configs}
    inventory_unchanged = {config.inventory.path.resolve() for config in configs
                           if config.inventory is not None}
    operations = [("watch.database", updated.watch.database, watch_unchanged),
                  ("state.database", updated.database_path, state_unchanged),
                  ("output.directory", updated.output_dir, output_unchanged)]
    if updated.inventory is not None:
        operations.append(("inventory.path", updated.inventory.path, inventory_unchanged))
    for label, path, unchanged in operations:
        if aliases_protected_file(path, unchanged):
            raise ConfigurationError(f"{label} must not alias the configuration, account, secret or operational store")
        if aliases_protected_directory(path):
            raise ConfigurationError(f"{label} must not alias a protected directory")
    for index, (label, path, _) in enumerate(operations):
        for other_label, other, _ in operations[index + 1:]:
            if _same_path(path.resolve(), other.resolve()):
                raise ConfigurationError(f"{label} and {other_label} must not use the same path")

    derived_files, derived_dirs = _candidate_derived_paths(updated, configs)
    for path in derived_files:
        resolved = path.resolve()
        if (any(_same_path(resolved, item) for item in existing_files)
                or any(resolved == directory or _inside(resolved, directory)
                       for directory in existing_dirs)
                or any(any(_same_path(parent, item) for item in existing_files)
                       for parent in resolved.parents)):
            raise ConfigurationError(
                "A derived dashboard storage path must not overlap protected data")
    for directory in derived_dirs:
        resolved = directory.resolve()
        if (any(_same_path(resolved, item) for item in existing_files)
                or any(resolved == item or _inside(resolved, item) for item in existing_dirs)
                or any(any(_same_path(parent, item) for item in existing_files)
                       for parent in resolved.parents)):
            raise ConfigurationError(
                "A derived dashboard storage path must not overlap protected data")
        if (any(_inside(item, resolved) for item in existing_files)
                or any(_inside(item, resolved) for item in existing_dirs)):
            raise ConfigurationError(
                "A derived dashboard storage path must not contain protected data")



def _kind(key):
    if key in BOOLEAN_FIELDS or key.endswith("_enabled"):
        return "boolean"
    if key in NUMBER_FIELDS:
        return "number"
    if key in COMPLEX_FIELDS:
        return "toml"
    return "string"


def _secret_directory(config):
    return config.watch.users_database.parent / "dashboard-secrets"


def groups_for(section, document, *, new_type="smtp", row_types=None, count=None,
               can_manage=False, can_admin=False):
    groups = []
    if section in SCHEMAS:
        for path, schema in SCHEMAS[section]:
            groups.append((path, schema, get_table(document, path), tuple(path.split("."))))
    elif section in {"rules", "product-mappings"}:
        rows = get_table(document, "watch").get("rules", []) if section == "rules" else document.get("product_mappings", [])
        schema = RULE_FIELDS if section == "rules" else MAPPING_FIELDS
        prefix = ("watch", "rules") if section == "rules" else ("product_mappings",)
        for index in range(count if count is not None else len(rows) + 1):
            groups.append((f"{section} {index + 1}", schema, rows[index] if index < len(rows) else {}, (*prefix, index)))
    else:
        rows = list(get_table(document, "watch.channels").items())
        if row_types is None:
            row_types = [row["type"] for _, row in rows] + [new_type]
        for index, kind in enumerate(row_types):
            folded = kind.strip().casefold() if isinstance(kind, str) else kind
            if folded not in TYPE_KEYS:
                abort(400)
            name = rows[index][0] if index < len(rows) else ""
            data = {"name": name, **rows[index][1]} if index < len(rows) else {"type": kind}
            common_defaults = defaults(ChannelConfig)
            if folded == "telegram":
                common_defaults["min_interval_seconds"] = 3.0
            schema = {key: common_defaults.get(key) for key in ["name", *sorted(COMMON_KEYS | TYPE_KEYS[folded])]}
            groups.append((f"{kind} channel {index + 1}", schema, data,
                           ("watch", "channels", name)))
    output = []
    for index, (label, schema, data, prefix) in enumerate(groups):
        credential_bearing = section == "channels" and channel_has_credentials(data)
        readonly_channel = credential_bearing and not can_manage
        readonly_dashboard = section == "dashboard" and not can_admin
        readonly_notifications = section == "notifications" and not can_manage
        controls = []
        for key in schema:
            item = data.get(key)
            reference = key.endswith(("_env", "_file"))
            direct_url = key == "url"
            text = "" if item is None or direct_url else str(item) if _kind(key) == "string" else value(item)
            default = schema[key]
            if isinstance(default, tuple):
                default = list(default)
            hint = ("" if default is None else str(default) if isinstance(default, Path) else value(default))
            if label == "watch" and key == "database":
                hint = "cvebeacon-watch.db beside the state database"
            if direct_url and item is not None:
                hint = "Existing endpoint is hidden and retained"
            path_value = key in {"database", "directory", "path"} or key.endswith("_file")
            controls.append({"key": key, "id": f"g{index}_{key}", "value": text, "default": hint,
                             "kind": _kind(key), "secret": key.endswith("_file"),
                             "existing": bool(item),
                             "readonly": (readonly_channel or readonly_dashboard
                                          or readonly_notifications or direct_url) or
                             (reference and not can_manage) or
                             (path_value and not can_admin),
                             "allow_new_secret": (
                                 key.endswith("_file") and can_manage
                                 and (can_admin or bool(item)))})
        output.append({"label": label, "controls": controls, "data": data, "prefix": prefix,
                       "readonly_reason": (
                           "This channel carries a credential or secret reference. "
                           "Editing or replacing it requires manage_secrets; you may delete it."
                           if readonly_channel else
                           ("Dashboard sign-in and session settings are administrator-only."
                            if readonly_dashboard else
                            ("Legacy notification channels are credential-bearing; "
                             "changing them requires manage_secrets."
                             if readonly_notifications else None)))})
    return output


def parse_form(editor, section, document, current_config, permissions, *, can_admin=False):
    can_manage = "manage_secrets" in permissions
    try:
        count = int(request.form.get("row_count", "1"))
        if not 1 <= count <= 101:
            abort(400)
    except ValueError:
        abort(400)
    row_types = [request.form.get(f"g{index}_type") for index in range(count)] if section == "channels" else None
    groups = groups_for(section, document, count=count, row_types=row_types,
                        can_manage=can_manage, can_admin=can_admin)
    rows, staged, replacements, secret_requests = [], [], [], []
    expected = {"csrf", "version", "action", "row_count"}
    try:
        for index, group in enumerate(groups):
            row = {}
            prefix = group["prefix"]
            expected.add(f"remove{index}")
            remove = request.form.get(f"remove{index}") == "yes"
            for control in group["controls"]:
                key, name = control["key"], control["id"]
                expected.add(name)
                text = request.form.get(name, "")
                if not remove and (text != "" if control["kind"] == "string" else text.strip() != ""):
                    if control["kind"] == "string":
                        row[key] = text
                    else:
                        try:
                            parsed = tomllib.loads("value = " + text)
                            if set(parsed) != {"value"}:
                                raise ValueError
                            row[key] = parsed["value"]
                        except (ValueError, RecursionError):
                            raise ConfigurationError("Enter a valid TOML value in numeric, boolean and structured fields") from None
                if control["secret"]:
                    secret_name = name + "_new"
                    expected.add(secret_name)
                    secret = request.form.get(secret_name, "")
                    if secret and not remove:
                        if not can_manage:
                            raise ConfigurationError(
                                "Staging new secret file contents requires manage_secrets")
                        secret_requests.append((index, group["data"], row, key, secret, prefix))
            if ("url" in group["data"] and "url" not in row
                    and not row.get("url_env") and not row.get("url_file") and not remove):
                # Keep a legacy direct endpoint only when no reference replaces it.
                row["url"] = group["data"]["url"]
            rows.append(None if remove else row)
        if set(request.form) - expected or any(len(request.form.getlist(key)) != 1 for key in request.form):
            abort(400)
        directory = None
        for index, data, row, key, secret, prefix in secret_requests:
            if row is None:
                continue
            if section == "channels" and not row.get("name"):
                continue
            if section == "channels":
                old_name = data.get("name")
                new_name = row.get("name")
                if old_name and new_name and old_name != new_name:
                    raise ConfigurationError(
                        "Rename the channel and rotate its secret file in separate saves"
                    )
            if directory is None:
                directory = _private_directory(_secret_directory(current_config))
            if not secret.strip() or len(secret.encode("utf-8")) > SECRET_FILE_LIMIT:
                raise ConfigurationError("Secret must contain 1–16384 bytes of text")
            paired_env = key[:-5] + "_env"
            explicit_environment = row.get(paired_env)
            environment_key = effective_environment_row(row, paired_env, prefix)
            if (isinstance(explicit_environment, str) and explicit_environment) or (
                    environment_key and environment_precedence(environment_key)):
                raise ConfigurationError(
                    f"Cannot stage new file contents while {environment_key} is set; "
                    "the environment value would take precedence, so unset it or keep using the environment reference"
                )
            current_reference = data.get(key)
            submitted_reference = row.get(key)
            reference_path = (*prefix, key)
            environment_path = (*prefix, paired_env)
            if (isinstance(current_reference, str) and current_reference
                    and submitted_reference == current_reference):
                target = effective_reference_path(current_config, reference_path)
                if target is None:
                    raise ConfigurationError("Secret file reference is not a configured file")
                target = secret_target(str(target), editor.path.parent,
                                       [current_config, editor.config], editor.backup_dir,
                                       documents=[document])
                staged_path = write_temp(directory, secret.encode("utf-8"), prefix=STAGE_PREFIX)
                staged.append(staged_path)
                replacements.append(Replacement(target, staged_path, reference_path, environment_path))
            else:
                if not can_admin:
                    raise ConfigurationError(
                        "Creating or changing a file secret path requires an administrator")
                staged_path = write_temp(directory, secret.encode("utf-8"), prefix=SECRET_PREFIX)
                staged.append(staged_path)
                row[key] = str(staged_path)
        coalesced = {}
        for replacement in replacements:
            existing = coalesced.get(replacement.target)
            if existing is None:
                coalesced[replacement.target] = replacement
                continue
            try:
                same = existing.staged.read_bytes() == replacement.staged.read_bytes()
            except OSError:
                raise ConfigurationError("Staged secret cannot be read") from None
            if not same:
                raise ConfigurationError(
                    "Conflicting new contents were supplied for one shared secret file"
                )
            replacement.staged.unlink(missing_ok=True)
            staged.remove(replacement.staged)
        replacements = list(coalesced.values())
        candidate = deepcopy(document)
        if section in SCHEMAS:
            for (path, _), row in zip(SCHEMAS[section], rows):
                set_table(candidate, path, row if row is not None else {})
        elif section == "rules":
            candidate.setdefault("watch", {})["rules"] = [
                row for row in rows if row is not None and row.get("name")
            ]
        elif section == "product-mappings":
            candidate["product_mappings"] = [
                row for row in rows if row is not None and row.get("vendor")
            ]
        else:
            channels = {}
            for row in rows:
                if row is None:
                    continue
                row = dict(row)
                name = row.pop("name", "")
                if name:
                    if name in channels:
                        raise ConfigurationError("Duplicate channel name")
                    channels[name] = row
            candidate.setdefault("watch", {})["channels"] = channels
        referenced = {value for value in secret_references(candidate).values() if isinstance(value, str)}
        for path in list(staged):
            if path.name.startswith(SECRET_PREFIX) and str(path) not in referenced:
                path.unlink(missing_ok=True)
                staged.remove(path)
        return candidate, staged, replacements
    except BaseException:
        for path in staged:
            path.unlink(missing_ok=True)
        raise



def register_config(app, config, *, host):
    """Register isolated routes and a dispatcher for immutable reloads."""
    from .dashboard import requires
    editor = _RELOADING.get() or Editor(app, config, host)
    app.extensions["dashboard_config"] = editor
    blueprint = Blueprint("config_editor", __name__, url_prefix="/config")

    @blueprint.before_request
    def accounts_only():
        if not g.accounts or g.user is None:
            abort(403)
        editor.lock.acquire()
        g.config_lock = True
        if app is not editor.active_app:
            return render_template(
                "config_error.html",
                error="Configuration changed; reload the configuration page",
                read_only=editor.read_only(),
            ), 409
        if not editor.read_only():
            editor.cleanup()

    @blueprint.teardown_request
    def release_lock(error):
        if g.pop("config_lock", False):
            editor.lock.release()

    @blueprint.get("/")
    @requires("view")
    def index():
        return render_template("config_index.html", sections=SECTIONS,
                               read_only=editor.read_only())

    def page(section, permission):
        error, preview, diff, lockout, staged = None, None, None, False, []
        document = None
        status = 400
        try:
            document, _, _, version, current_config = editor.read()
            if request.method == "POST":
                if editor.read_only():
                    raise ConfigurationError(
                        "The configuration directory is read-only. Ask the operator to enable "
                        "editing for the dashboard service, then reload this page.")
                action = request.form.get("action")
                if action == "confirm":
                    editor.commit(request.form.get("preview"), section, app.extensions["dashboard_users"],
                                  {permission}, request.form.get("lockout") == "yes")
                    return redirect(url_for("login"), code=303)
                if action != "preview":
                    abort(400, "Unsupported configuration action; reload the form")
                if request.form.get("version") != version:
                    abort(409, "Configuration changed; reload the form")
                candidate, staged, replacements = parse_form(editor, section, document, current_config,
                                                             g.permissions, can_admin=g.user.is_admin)
                preview, lockout = editor.preview(
                    section, candidate, version, staged, replacements,
                    current_document=document, current_config=current_config,
                )
                staged = []
                diff = "\n".join(difflib.unified_diff(
                    dumps(redacted(project_document(document, section))).splitlines(),
                    dumps(redacted(project_document(candidate, section))).splitlines(),
                    fromfile="current", tofile="proposed", lineterm=""))
            new_type = request.args.get("new_type", "smtp")
            return render_template("config_section.html", section=section,
                                   groups=groups_for(section, document, new_type=new_type,
                                                     can_manage="manage_secrets" in g.permissions,
                                                     can_admin=g.user.is_admin),
                                   version=version, preview=preview, diff=diff, lockout=lockout,
                                   channel_types=sorted(TYPE_KEYS), events=EVENT_KINDS, leaves=LEAF_KEYS,
                                   read_only=editor.read_only())
        except ConfigurationError as exc:
            error = safe_error(exc, document or {}, editor.path)
        except HTTPException as exc:
            if exc.code not in {400, 409}:
                raise
            error, status = exc.description, exc.code
        finally:
            for path in staged:
                path.unlink(missing_ok=True)
        return render_template("config_error.html", error=error,
                               read_only=editor.read_only()), status

    for section, permission in SECTIONS.items():
        def route(section=section, permission=permission):
            return page(section, permission)
        blueprint.add_url_rule("/" + section, endpoint=section, view_func=requires(("view", permission))(route),
                               methods=["GET", "POST"])

    @blueprint.route("/backups", methods=["GET", "POST"])
    @requires(("view", *sorted(set(SECTIONS.values()))))
    def backups():
        preview, diff, lockout = None, None, False
        status = 400
        try:
            document, _, _, version = editor.snapshot()
            if request.method == "POST":
                if editor.read_only():
                    raise ConfigurationError(
                        "The configuration directory is read-only, so rollback is disabled. "
                        "Ask the operator to enable editing for the dashboard service.")
                if request.form.get("action") == "confirm":
                    editor.commit(request.form.get("preview"), "rollback", app.extensions["dashboard_users"],
                                  set(SECTIONS.values()), request.form.get("lockout") == "yes")
                    return redirect(url_for("login"), code=303)
                if request.form.get("action") != "preview":
                    abort(400, "Unsupported rollback action; reload the form")
                if request.form.get("version") != version:
                    abort(409, "Configuration changed; reload the form")
                name = request.form.get("backup", "")
                if name not in editor.backups():
                    abort(400, "Choose a retained backup")
                raw = read_regular(editor.backup_dir / name, private=True)[0]
                try:
                    candidate = tomllib.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeError):
                    raise ConfigurationError("Backup cannot be decoded") from None
                current_config = None
                if document is not None:
                    try:
                        current_config = editor.validate(document)[0]
                    except ConfigurationError:
                        current_config = None
                current_invalid = document is None or current_config is None
                preview, lockout = editor.preview(
                    "rollback", candidate, version,
                    current_document=document, current_config=current_config,
                )
                if not current_invalid:
                    diff = "\n".join(difflib.unified_diff(dumps(redacted(document)).splitlines(),
                                                         dumps(redacted(candidate)).splitlines(),
                                                         fromfile="current", tofile="backup", lineterm=""))
                else:
                    diff = ""
            else:
                if document is None:
                    current_invalid = True
                else:
                    try:
                        editor.read()
                        current_invalid = False
                    except ConfigurationError:
                        current_invalid = True
            return render_template("config_backups.html", backups=editor.backups(), version=version,
                                   preview=preview, diff=diff, lockout=lockout,
                                   current_invalid=current_invalid,
                                   read_only=editor.read_only())
        except ConfigurationError as exc:
            return render_template("config_error.html", error=safe_error(exc, {}, editor.path),
                                   read_only=editor.read_only()), 400
        except HTTPException as exc:
            if exc.code not in {400, 409}:
                raise
            return render_template("config_error.html", error=exc.description,
                                   read_only=editor.read_only()), exc.code

    app.register_blueprint(blueprint)
    if _RELOADING.get() is None:
        app.wsgi_app = editor
