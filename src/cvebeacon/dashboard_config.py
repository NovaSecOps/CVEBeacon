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

from .config import (CANONICAL_FIELDS, OPTIONAL_FIELDS, DashboardConfig,
                     EmailConfig, HttpConfig, InventoryConfig, SourceConfig,
                     TeamsConfig, WatchConfig, load_config)
from .errors import CVEBeaconError, ConfigurationError
from .watch.channels import ChannelConfig, COMMON_KEYS, TYPE_KEYS, ENV_NAME_PATTERN, SECRET_FILE_LIMIT
from .watch.directories import ensure_private_directory
from .watch.rules import Rule, EVENT_KINDS, LEAF_KEYS
from .watch.users import UserStore

MAX_CONFIG = 256 * 1024
KEEP_BACKUPS = 10
PREVIEW_SECONDS = 600
MAX_PENDING_PER_SESSION = 32
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
        if acquired:
            if os.name == "posix":
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            else:
                import msvcrt
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        if descriptor is not None:
            os.close(descriptor)
        thread_lock.release()


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
    # permits names, never pasted URLs or credential assignments.
    def references(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if key.endswith("_env") and (not isinstance(child, str) or not ENV_NAME_PATTERN.fullmatch(child)):
                    raise ConfigurationError("Credential references must be environment variable names")
                references(child)
        elif isinstance(item, list):
            for child in item:
                references(child)
    references(document)


def redacted(document):
    if isinstance(document, dict):
        return {key: ("[redacted]" if key == "url" or key.endswith("_url") else redacted(child))
                for key, child in document.items()}
    if isinstance(document, list):
        return [redacted(child) for child in document]
    return document


def safe_error(error, document, path):
    message = str(error).replace(str(path), "configuration").replace(str(path.parent), "configuration directory")
    strings = []
    known = {"any", "all", "not", *LEAF_KEYS, *COMMON_KEYS, *RULE_FIELDS, *MAPPING_FIELDS}
    known.update(SECTIONS)
    known.update(key for specs in SCHEMAS.values() for _, schema in specs for key in schema)
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
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.lstat() != info:
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


def replacement_document(document, replacements, base):
    """Point every consumer of a replaced target at its staged bytes."""
    result = deepcopy(document)
    staged = {replacement.target: str(replacement.staged) for replacement in replacements}
    for path, value in secret_references(result).items():
        if not path[-1].endswith("_file") or not isinstance(value, str) or not value:
            continue
        try:
            target = resolve_reference(value, base)
        except (OSError, RuntimeError):
            continue
        if target in staged:
            document_set(result, path, staged[target])
    for replacement in replacements:
        document_set(result, replacement.reference, str(replacement.staged))
    return result


def effective_environment(document, path):
    """Return the environment reference the loaded configuration would use."""
    value = document_get(document, path)
    if isinstance(value, str) and value:
        return value
    if path == ("sources", "nvd_api_key_env"):
        return defaults(SourceConfig)["nvd_api_key_env"]
    return None


def effective_environment_row(row, key, prefix):
    value = row.get(key)
    if isinstance(value, str) and value:
        return value
    if prefix == ("sources",) and key == "nvd_api_key_env":
        return defaults(SourceConfig)["nvd_api_key_env"]
    return None


def environment_precedence(name):
    try:
        value = os.environ.get(name, "")
    except (TypeError, ValueError):
        return False
    return bool(value and value.strip())


def generated_file_paths(document, base, config):
    """References that name editor-generated secret files in the data directory."""
    directory = _secret_directory(config).resolve()
    result = set()
    for path, value in secret_references(document).items():
        if not path[-1].endswith("_file") or not isinstance(value, str) or not value:
            continue
        raw = Path(value).expanduser()
        if not raw.is_absolute():
            raw = base / raw
        resolved = raw.resolve()
        if resolved.name.startswith(SECRET_PREFIX) and _inside(resolved, directory):
            result.add(resolved)
    return result


def _database_paths(path):
    return {
        path,
        path.with_name(path.name + "-wal"),
        path.with_name(path.name + "-shm"),
        path.with_name(path.name + "-journal"),
        Path(str(path) + ".lock"),
    }


def _protected_target_paths(configs, backup_dir):
    protected = set()
    protected.add(backup_dir)
    for config in configs:
        protected.add(config.config_path)
        protected.add(config.output_dir)
        protected.add(_secret_directory(config))
        protected.add(config.config_path.with_name(".config-" + config.config_path.name + ".lock"))
        protected.update(_database_paths(config.watch.database))
        protected.update(_database_paths(config.database_path))
        protected.update(_database_paths(config.watch.users_database))
        if config.inventory is not None:
            protected.add(config.inventory.path)
    return protected


def secret_target(reference, base, configs, backup_dir):
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
    protected = _protected_target_paths(configs, backup_dir)
    if any(_same_path(target, item) for item in protected):
        raise ConfigurationError(
            "Secret file reference must not alias configuration, account, operational or backup data"
        )
    if _inside(target, backup_dir.resolve()):
        raise ConfigurationError("Secret file reference must not alias a backup store")
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
        self.backup_dir = self.path.parent / ("." + self.path.name + ".backups")
        self.secret_dir = config.watch.users_database.parent / "dashboard-secrets"
        try:
            self.cleanup()
        except (OSError, CVEBeaconError, ValueError):
            pass

    def __call__(self, environ, start_response):
        # Select an immutable generation without serializing unrelated requests
        # (password hashing and queries may take time).
        with self.lock:
            target = self.target
        return target(environ, start_response)

    def read(self):
        if os.name == "posix":
            UserStore._trusted_directory_chain(self.path.parent)
        content, info, version = read_regular(self.path)
        try:
            document = tomllib.loads(content.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise ConfigurationError("Configuration cannot be decoded") from None
        # Files can be changed outside this process after startup. Refuse to
        # render malformed/unknown fields, including nested condition content.
        config, _ = self.validate(document)
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
            if config.inventory is None:
                raise ConfigurationError("The dashboard requires inventory.path")
            return config, content
        except ConfigurationError as error:
            raise ConfigurationError(safe_error(error, document, temporary)) from None
        except (TypeError, ValueError, AttributeError):
            raise ConfigurationError("Invalid configuration value type") from None
        finally:
            _VALIDATING.reset(token)
            temporary.unlink(missing_ok=True)

    def _live_reference_paths(self):
        """Return paths named by the current file and every retained backup."""
        live = set()
        documents = []
        try:
            content = read_regular(self.path)[0]
            documents.append((self.path.parent, tomllib.loads(content.decode("utf-8"))))
        except (OSError, ValueError, UnicodeError, CVEBeaconError):
            return None
        if self.backup_dir.exists():
            if self.backup_dir.is_symlink() or not self.backup_dir.is_dir():
                return None
            for name in self.backup_dir.iterdir():
                if not _backup_name(name.name):
                    continue
                try:
                    raw = read_regular(name, private=True)[0]
                    documents.append((self.path.parent, tomllib.loads(raw.decode("utf-8"))))
                except (OSError, ValueError, UnicodeError, CVEBeaconError):
                    return None
        for base, document in documents:
            for path in secret_references(document).values():
                if isinstance(path, str) and path:
                    try:
                        live.add(resolve_reference(path, base))
                    except (OSError, RuntimeError, ValueError):
                        return None
        return live

    def _cleanup_orphans(self):
        live = self._live_reference_paths()
        if live is None:
            logging.getLogger("cvebeacon").warning(
                "Staged secret cleanup deferred: reference discovery is incomplete"
            )
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
                    if not path.name.startswith((SECRET_PREFIX, STAGE_PREFIX)):
                        continue
                    if path in live or path in active:
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
        live = self._live_reference_paths()
        if live is None:
            logging.getLogger("cvebeacon").warning(
                "Staged secret cleanup deferred: reference discovery is incomplete"
            )
        active = {path for identifier2, pending2 in self.pending.items()
                  if identifier2 != identifier
                  for path in (*pending2.staged, *pending2.references)}
        for path in pending.staged:
            if path.name.startswith((SECRET_PREFIX, STAGE_PREFIX)):
                if path in active:
                    continue
                if path.name.startswith(SECRET_PREFIX):
                    if live is None:
                        # An unreadable current file or backup may still name it.
                        continue
                    if path.resolve() in live:
                        # A committed configuration or retained backup still names it.
                        continue
                    try:
                        # Another application may have renewed this file as a lease.
                        if path.stat().st_mtime > pending.created:
                            continue
                    except OSError:
                        continue
                path.unlink(missing_ok=True)
            else:
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
                raise ConfigurationError(
                    "Existing generic webhook endpoints are read-only; use url_env or url_file for a replacement channel"
                )
        for name, row in new_channels.items():
            if not isinstance(row, dict) or "url" not in row:
                continue
            legacy = old_channels.get(name)
            if not isinstance(legacy, dict) or legacy.get("url") != row["url"]:
                raise ConfigurationError(
                    "Inline generic webhook URLs are only retained unchanged from an existing channel; "
                    "use url_env or url_file for new or changed endpoints"
                )

    def _check_replacement(self, current, candidate, replacement, current_config):
        base = self.path.parent
        old_value = document_get(current, replacement.reference)
        new_value = document_get(candidate, replacement.reference)
        if not isinstance(old_value, str) or not isinstance(new_value, str):
            return False
        old_target = secret_target(old_value, base, [current_config, self.config], self.backup_dir)
        new_target = secret_target(new_value, base, [current_config, self.config], self.backup_dir)
        return old_target == new_target == replacement.target

    def preview(self, section, document, version, staged=(), replacements=(), *, current_document, current_config):
        self.cleanup()
        mine = sum(1 for pending in self.pending.values() if pending.owner == g.sid)
        if mine >= MAX_PENDING_PER_SESSION:
            raise ConfigurationError("Too many pending previews for this session; try again later")
        validation_document = replacement_document(document, replacements, self.path.parent)
        updated, _ = self.validate(validation_document)
        if (reference_escape(current_document, document, direct_urls=True)
                and "manage_secrets" not in g.permissions):
            abort(403)
        self._check_direct_urls(current_document, document, rollback=section == "rollback")
        for replacement in replacements:
            if not self._check_replacement(current_document, document, replacement, current_config):
                raise ConfigurationError("Secret reference changed; create a new preview")
            explicit_environment = document_get(document, replacement.environment)
            environment = effective_environment(document, replacement.environment)
            if (isinstance(explicit_environment, str) and explicit_environment) or (
                    environment and environment_precedence(environment)):
                raise ConfigurationError(
                    f"Cannot stage new file contents while {environment} is set; "
                    "the environment value would take precedence, so unset it or keep using the environment reference"
                )
        check_protected_paths(updated, self.path, self.backup_dir, [current_config, self.config])
        lockout = (updated.dashboard != self.config.dashboard or
                   updated.dashboard != current_config.dashboard or
                   updated.watch.users_database != self.config.watch.users_database or
                   updated.watch.users_database != current_config.watch.users_database)
        if lockout:
            if updated.watch.users_database != self.config.watch.users_database or \
                    updated.watch.users_database != current_config.watch.users_database:
                if not g.user.is_admin:
                    abort(403)
                users = UserStore(updated.watch.users_database)
                if not users.dashboard_accounts() or not users.has_admin():
                    raise ConfigurationError("The destination account database needs an enabled administrator")
        references = generated_file_paths(document, self.path.parent, current_config)
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
        try:
            # Validate and prepare against a stable snapshot. Preparation
            # creates only private temporary files; live targets are untouched.
            old, original, info, version, current_config = self.read()
            if version != pending.version:
                abort(409, "Configuration changed; reload the form")
            for replacement in pending.replacements:
                if not self._check_replacement(old, pending.document, replacement, current_config):
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
                secret_directory = _private_directory(_secret_directory(current_config))
                secret_temp = write_temp(secret_directory, new_bytes, info=target_info,
                                         prefix=SECRET_PREFIX)
                prepared.append((replacement, target_info, secret_temp))
            self.validate(replacement_document(pending.document, pending.replacements, self.path.parent))
            # The reloaded application uses final references; SecretRef resolves
            # file contents dynamically, so preparation does not touch live files.
            updated, content = self.validate(pending.document)
            from .dashboard import create_app
            token = _RELOADING.set(self)
            try:
                replacement_app = create_app(updated, host=self.host)
            finally:
                _RELOADING.reset(token)
            destination_users = replacement_app.extensions["dashboard_users"]
            if not destination_users.dashboard_accounts():
                raise ConfigurationError("Configuration changes cannot turn off account authentication")
            if not destination_users.has_admin():
                raise ConfigurationError("The destination account database needs an enabled administrator")
            # The shared writer guard covers the account transaction, every
            # permission/credential check, target capture and live writes, the
            # transaction exit, and compensation below.
            with users.transaction() as db:
                for needed in {"view", *permission}:
                    actor = users.require_permission_in(db, g.entry.proof, needed)
                if read_regular(self.path)[2] != version:
                    abort(409, "Configuration changed; reload the form")
                if (reference_escape(old, pending.document, direct_urls=True)
                        and "manage_secrets" not in users.permissions_in(db, actor)):
                    abort(403)
                self._check_direct_urls(old, pending.document, rollback=section == "rollback")
                lockout = (pending.lockout or
                           updated.dashboard != self.config.dashboard or
                           updated.dashboard != current_config.dashboard or
                           updated.watch.users_database != self.config.watch.users_database or
                           updated.watch.users_database != current_config.watch.users_database)
                if lockout and not confirmed:
                    raise ConfigurationError("Confirm the access and session changes before saving")
                if (updated.watch.users_database != self.config.watch.users_database or
                        updated.watch.users_database != current_config.watch.users_database):
                    if not actor.is_admin:
                        abort(403)
                    destination = UserStore(updated.watch.users_database)
                    if not destination.dashboard_accounts() or not destination.has_admin():
                        raise ConfigurationError("The destination account database needs an enabled administrator")
                check_protected_paths(updated, self.path, self.backup_dir, [current_config, self.config])
                for replacement, target_info, secret_temp in prepared:
                    if not self._check_replacement(old, pending.document, replacement, current_config):
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
                # the final version check and atomic replacement.
                backup_dir = _private_directory(self.backup_dir)
                backup = backup_dir / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ-") + secrets.token_hex(8) + ".toml")
                backup_temp = write_temp(backup_dir, original)
                os.replace(backup_temp, backup)
                sync_directory(backup_dir)
                temporary = write_temp(self.path.parent, content, info=info)
                recovery = write_temp(self.path.parent, original, info=info)
                if read_regular(self.path)[2] != version:
                    abort(409, "Configuration changed; reload the form")
                changed = sum(1 for line in difflib.ndiff(dumps(old).splitlines(), dumps(pending.document).splitlines())
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
            committed = True
            self.config = updated
            self.target = replacement_app.wsgi_app
            self.active_app = replacement_app
            self.secret_dir = updated.watch.users_database.parent / "dashboard-secrets"
        except BaseException:
            if not committed:
                for target, old_bytes, target_info in reversed(applied):
                    try:
                        restore = write_temp(target.parent, old_bytes, info=target_info, prefix=SECRET_PREFIX)
                        os.replace(restore, target)
                        sync_directory(target.parent)
                    except OSError:
                        logging.getLogger("cvebeacon").error("Secret file recovery failed")
                if replaced:
                    os.replace(recovery, self.path)
                    sync_directory(self.path.parent)
                if backup:
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
    """Map each *reference* location to its configured value."""
    return {path: item for path, item in _walk(document)
            if isinstance(path[-1], str) and path[-1].endswith(("_env", "_file"))}


def direct_webhook_urls(document):
    channels = get_table(document, "watch").get("channels")
    if not isinstance(channels, dict):
        return {}
    result = {}
    for name, row in channels.items():
        if isinstance(row, dict) and "url" in row:
            result[("watch", "channels", name, "url")] = row["url"]
    return result


def reference_escape(document, replacement, *, direct_urls=False):
    """Whether a candidate changes a secret reference (or a direct URL)."""
    old = secret_references(document)
    new = secret_references(replacement)
    if direct_urls:
        old.update(direct_webhook_urls(document))
        new.update(direct_webhook_urls(replacement))
    return old != new


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


def check_protected_paths(updated, config_path, backup_dir, configs):
    """Reject settings that would place operational data in a protected store."""
    account_databases = {config.watch.users_database.resolve() for config in configs}
    account_databases.add(updated.watch.users_database.resolve())
    protected_files = {config_path.resolve(), *account_databases}
    protected_dirs = {backup_dir.resolve()}
    for config in [*configs, updated]:
        protected_dirs.add((config.watch.users_database.parent / "dashboard-secrets").resolve())
    existing_files = set(protected_files)
    for directory in protected_dirs:
        try:
            if directory.is_dir() and not directory.is_symlink():
                existing_files.update(path.resolve() for path in directory.iterdir()
                                      if path.is_file() and not path.is_symlink())
        except OSError:
            continue

    def protected_file(path):
        return any(_same_path(path, item) for item in existing_files)

    def protected_directory(path):
        resolved = path.resolve()
        return any(resolved == directory or _inside(resolved, directory)
                   for directory in protected_dirs)

    users_database = updated.watch.users_database.resolve()
    for label, path in (("watch.database", updated.watch.database),
                        ("state.database", updated.database_path),
                        ("output.directory", updated.output_dir)):
        resolved = path.resolve()
        if resolved == users_database or protected_file(resolved):
            raise ConfigurationError(f"{label} must not alias the configuration, account or protected store")
    for label, path in (("watch.database", updated.watch.database),
                        ("state.database", updated.database_path),
                        ("output.directory", updated.output_dir)):
        if protected_directory(path):
            raise ConfigurationError(f"{label} must not alias a backup or secret directory")



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


def groups_for(section, document, *, new_type="smtp", row_types=None, count=None, can_manage=False):
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
            controls.append({"key": key, "id": f"g{index}_{key}", "value": text, "default": hint,
                             "kind": _kind(key), "secret": key.endswith("_file"),
                             "readonly": direct_url or (reference and not can_manage),
                             "allow_new_secret": key.endswith("_file") and (can_manage or bool(item))})
        output.append({"label": label, "controls": controls, "data": data, "prefix": prefix})
    return output


def parse_form(editor, section, document, current_config, permissions):
    can_manage = "manage_secrets" in permissions
    try:
        count = int(request.form.get("row_count", "1"))
        if not 1 <= count <= 101:
            abort(400)
    except ValueError:
        abort(400)
    row_types = [request.form.get(f"g{index}_type") for index in range(count)] if section == "channels" else None
    groups = groups_for(section, document, count=count, row_types=row_types, can_manage=can_manage)
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
                if key == "url" and not text and key in group["data"] and not remove:
                    row[key] = group["data"][key]
                if control["secret"]:
                    secret_name = name + "_new"
                    expected.add(secret_name)
                    secret = request.form.get(secret_name, "")
                    if secret and not remove:
                        secret_requests.append((index, group["data"], row, key, secret, prefix))
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
                target = secret_target(current_reference, editor.path.parent,
                                       [current_config, editor.config], editor.backup_dir)
                staged_path = write_temp(directory, secret.encode("utf-8"), prefix=STAGE_PREFIX)
                staged.append(staged_path)
                replacements.append(Replacement(target, staged_path, reference_path, environment_path))
            else:
                if not can_manage:
                    raise ConfigurationError(
                        "Changing or creating a secret file reference requires manage_secrets"
                    )
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
            abort(409)
        editor.cleanup()

    @blueprint.teardown_request
    def release_lock(error):
        if g.pop("config_lock", False):
            editor.lock.release()

    @blueprint.get("/")
    @requires("view")
    def index():
        return render_template("config_index.html", sections=SECTIONS)

    def page(section, permission):
        error, preview, diff, lockout, staged = None, None, None, False, []
        document = None
        try:
            document, _, _, version, current_config = editor.read()
            if request.method == "POST":
                action = request.form.get("action")
                if action == "confirm":
                    editor.commit(request.form.get("preview"), section, app.extensions["dashboard_users"],
                                  {permission}, request.form.get("lockout") == "yes")
                    return redirect(url_for("login"), code=303)
                if action != "preview":
                    abort(400)
                if request.form.get("version") != version:
                    abort(409, "Configuration changed; reload the form")
                candidate, staged, replacements = parse_form(editor, section, document, current_config,
                                                             g.permissions)
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
                                                     can_manage="manage_secrets" in g.permissions),
                                   version=version, preview=preview, diff=diff, lockout=lockout,
                                   channel_types=sorted(TYPE_KEYS), events=EVENT_KINDS, leaves=LEAF_KEYS)
        except ConfigurationError as exc:
            error = safe_error(exc, document or {}, editor.path)
        finally:
            for path in staged:
                path.unlink(missing_ok=True)
        return render_template("config_error.html", error=error), 400

    for section, permission in SECTIONS.items():
        def route(section=section, permission=permission):
            return page(section, permission)
        blueprint.add_url_rule("/" + section, endpoint=section, view_func=requires(("view", permission))(route),
                               methods=["GET", "POST"])

    @blueprint.route("/backups", methods=["GET", "POST"])
    @requires(("view", *sorted(set(SECTIONS.values()))))
    def backups():
        preview, diff, lockout = None, None, False
        try:
            document, _, _, version, current_config = editor.read()
            if request.method == "POST":
                if request.form.get("action") == "confirm":
                    editor.commit(request.form.get("preview"), "rollback", app.extensions["dashboard_users"],
                                  set(SECTIONS.values()), request.form.get("lockout") == "yes")
                    return redirect(url_for("login"), code=303)
                if request.form.get("action") != "preview" or request.form.get("version") != version:
                    abort(409)
                name = request.form.get("backup", "")
                if name not in editor.backups():
                    abort(400)
                raw = read_regular(editor.backup_dir / name, private=True)[0]
                try:
                    candidate = tomllib.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeError):
                    raise ConfigurationError("Backup cannot be decoded") from None
                preview, lockout = editor.preview(
                    "rollback", candidate, version,
                    current_document=document, current_config=current_config,
                )
                diff = "\n".join(difflib.unified_diff(dumps(redacted(document)).splitlines(),
                                                     dumps(redacted(candidate)).splitlines(),
                                                     fromfile="current", tofile="backup", lineterm=""))
            return render_template("config_backups.html", backups=editor.backups(), version=version,
                                   preview=preview, diff=diff, lockout=lockout)
        except ConfigurationError as exc:
            return render_template("config_error.html", error=safe_error(exc, {}, editor.path)), 400

    app.register_blueprint(blueprint)
    if _RELOADING.get() is None:
        app.wsgi_app = editor
