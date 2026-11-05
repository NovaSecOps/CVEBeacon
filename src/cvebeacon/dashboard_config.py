"""Permission-scoped forms and validated, reversible configuration replacement."""

from __future__ import annotations

from contextvars import ContextVar
from copy import deepcopy
from dataclasses import MISSING, dataclass, fields, replace
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

from .config import (DashboardConfig, EmailConfig, HttpConfig, InventoryConfig,
                     SourceConfig, TeamsConfig, WatchConfig, load_config)
from .errors import ConfigurationError
from .watch.channels import ChannelConfig, COMMON_KEYS, TYPE_KEYS, ENV_NAME_PATTERN, SECRET_FILE_LIMIT
from .watch.directories import ensure_private_directory
from .watch.rules import Rule, EVENT_KINDS, LEAF_KEYS
from .watch.users import UserStore

MAX_CONFIG = 256 * 1024
KEEP_BACKUPS = 10
PREVIEW_SECONDS = 600
_VALIDATING = ContextVar("config_validation", default=False)
_RELOADING = ContextVar("config_reload", default=None)


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
        if not -(2**63) <= item < 2**63:
            raise ValueError("TOML integer out of range")
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
    rules = get_table(document, "watch").get("rules", [])
    mappings = document.get("product_mappings", [])
    for rows, schema in ((rules, RULE_FIELDS), (mappings, MAPPING_FIELDS)):
        if not isinstance(rows, list) or any(not isinstance(row, dict) or set(row) - set(schema) for row in rows):
            raise ConfigurationError("Unrecognized configuration row fields")
    for row in get_table(document, "watch.channels").values():
        if not isinstance(row, dict) or row.get("type") not in TYPE_KEYS:
            raise ConfigurationError("Unknown channel type")
        if set(row) - COMMON_KEYS - TYPE_KEYS[row["type"]]:
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
        return {key: ("[redacted]" if key == "url" else redacted(child)) for key, child in document.items()}
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
    # Preserve loader guidance, but never repeat submitted values or unknown
    # keys (including labels and URLs) in error output.
    for text in sorted(set(strings), key=len, reverse=True):
        if len(text) > 2:
            message = message.replace(text, "[value]")
        elif text:
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


def write_temp(directory, content, *, info=None):
    fd, name = tempfile.mkstemp(prefix=".config-", dir=directory)
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


@dataclass
class Pending:
    owner: str
    section: str
    version: str
    document: dict
    expires: float
    staged: tuple[Path, ...]
    lockout: bool


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
        self.validate(document)
        return document, content, info, version

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

    def cleanup(self):
        for identifier, pending in list(self.pending.items()):
            if pending.expires < clock.monotonic():
                self.discard(identifier)

    def discard(self, identifier, *, committed=False):
        pending = self.pending.pop(identifier, None)
        if pending and not committed:
            for path in pending.staged:
                path.unlink(missing_ok=True)

    def preview(self, section, document, version, staged=()):
        self.cleanup()
        if len(self.pending) >= 256:
            raise ConfigurationError("Too many pending previews; try again later")
        updated, _ = self.validate(document)
        lockout = (updated.dashboard != self.config.dashboard or
                   updated.watch.users_database != self.config.watch.users_database)
        if updated.watch.users_database != self.config.watch.users_database:
            if not g.user.is_admin:
                abort(403)
            users = UserStore(updated.watch.users_database)
            if not users.dashboard_accounts() or not users.has_admin():
                raise ConfigurationError("The destination account database needs an enabled administrator")
        identifier = secrets.token_hex(32)
        self.pending[identifier] = Pending(g.sid, section, version, document,
                                          clock.monotonic() + PREVIEW_SECONDS, tuple(staged), lockout)
        return identifier, lockout

    def backups(self):
        if not self.backup_dir.exists():
            return []
        _private_directory(self.backup_dir)
        return sorted((path.name for path in self.backup_dir.iterdir()
                       if _backup_name(path.name)), reverse=True)[:KEEP_BACKUPS]

    def commit(self, identifier, section, users, permission, confirmed):
        self.cleanup()
        pending = self.pending.get(identifier)
        if not pending or pending.owner != g.sid or pending.section != section:
            abort(400)
        if pending.lockout and not confirmed:
            raise ConfigurationError("Confirm the access and session changes before saving")
        updated, content = self.validate(pending.document)
        from .dashboard import create_app
        token = _RELOADING.set(self)
        try:
            replacement = create_app(updated, host=self.host)
        finally:
            _RELOADING.reset(token)
        destination_users = replacement.extensions["dashboard_users"]
        if not destination_users.dashboard_accounts():
            raise ConfigurationError("Configuration changes cannot turn off account authentication")
        if not destination_users.has_admin():
            raise ConfigurationError("The destination account database needs an enabled administrator")
        # The account write transaction serializes writers across processes and
        # rechecks a revoked proof/permission before filesystem side effects.
        original = recovery = temporary = backup = backup_temp = None
        replaced = False
        try:
            with users.transaction() as db:
                for needed in {"view", *permission}:
                    actor = users.require_permission_in(db, g.entry.proof, needed)
                old, original, info, version = self.read()
                if version != pending.version:
                    abort(409, "Configuration changed; reload the form")
                if updated.watch.users_database != self.config.watch.users_database and not actor.is_admin:
                    abort(403)
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
                users._append_audit(db, f"config_save:{section}:changed_lines={changed}", actor.username,
                                    datetime.now(timezone.utc).isoformat(), actor=actor.username)
                os.replace(temporary, self.path)
                replaced = True
                sync_directory(self.path.parent)
            self.config = updated
            self.target = replacement.wsgi_app
            self.active_app = replacement
            self.secret_dir = updated.watch.users_database.parent / "dashboard-secrets"
            self.discard(identifier, committed=True)
        except BaseException:
            if replaced:
                os.replace(recovery, self.path)
                sync_directory(self.path.parent)
            if backup:
                backup.unlink(missing_ok=True)
            raise
        finally:
            for path in (temporary, recovery, backup_temp):
                if path:
                    path.unlink(missing_ok=True)
        # Backup retention is maintenance, not part of the committed change.
        try:
            for name in sorted(path.name for path in self.backup_dir.iterdir() if _backup_name(path.name))[:-KEEP_BACKUPS]:
                (self.backup_dir / name).unlink(missing_ok=True)
        except OSError:
            logging.getLogger("cvebeacon").warning("Configuration saved; backup retention cleanup failed")


def _backup_name(name):
    import re
    return re.fullmatch(r"[0-9]{8}T[0-9]{12}Z-[0-9a-f]{16}\.toml", name) is not None


def _kind(key):
    if key in BOOLEAN_FIELDS or key.endswith("_enabled"):
        return "boolean"
    if key in NUMBER_FIELDS:
        return "number"
    if key in COMPLEX_FIELDS:
        return "toml"
    return "string"


def groups_for(section, document, *, new_type="smtp", row_types=None, count=None):
    groups = []
    if section in SCHEMAS:
        for path, schema in SCHEMAS[section]:
            groups.append((path, schema, get_table(document, path)))
    elif section in {"rules", "product-mappings"}:
        rows = get_table(document, "watch").get("rules", []) if section == "rules" else document.get("product_mappings", [])
        schema = RULE_FIELDS if section == "rules" else MAPPING_FIELDS
        for index in range(count if count is not None else len(rows) + 1):
            groups.append((f"{section} {index + 1}", schema, rows[index] if index < len(rows) else {}))
    else:
        rows = list(get_table(document, "watch.channels").items())
        if row_types is None:
            row_types = [row["type"] for _, row in rows] + [new_type]
        for index, kind in enumerate(row_types):
            if kind not in TYPE_KEYS:
                abort(400)
            data = {"name": rows[index][0], **rows[index][1]} if index < len(rows) else {"type": kind}
            common_defaults = defaults(ChannelConfig)
            if kind == "telegram":
                common_defaults["min_interval_seconds"] = 3.0
            schema = {key: common_defaults.get(key) for key in ["name", *sorted(COMMON_KEYS | TYPE_KEYS[kind])]}
            groups.append((f"{kind} channel {index + 1}", schema, data))
    output = []
    for index, (label, schema, data) in enumerate(groups):
        controls = []
        for key in schema:
            item = data.get(key)
            text = "" if item is None or key == "url" else str(item) if _kind(key) == "string" else value(item)
            default = schema[key]
            if isinstance(default, tuple):
                default = list(default)
            hint = ("" if default is None else str(default) if isinstance(default, Path) else value(default))
            if label == "watch" and key == "database":
                hint = "cvebeacon-watch.db beside the state database"
            controls.append({"key": key, "id": f"g{index}_{key}", "value": text, "default": hint, "kind": _kind(key),
                             "secret": key.endswith("_file")})
        output.append({"label": label, "controls": controls, "data": data})
    return output


def parse_form(editor, section, document):
    try:
        count = int(request.form.get("row_count", "1"))
        if not 1 <= count <= 101:
            abort(400)
    except ValueError:
        abort(400)
    row_types = [request.form.get(f"g{index}_type") for index in range(count)] if section == "channels" else None
    groups = groups_for(section, document, count=count, row_types=row_types)
    rows, staged = [], []
    expected = {"csrf", "version", "action", "row_count"}
    try:
        for index, group in enumerate(groups):
            row = {}
            expected.add(f"remove{index}")
            remove = request.form.get(f"remove{index}") == "yes"
            for control in group["controls"]:
                key, name = control["key"], control["id"]
                expected.add(name)
                text = request.form.get(name, "")
                if text.strip() and not remove:
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
                        if not secret.strip() or len(secret.encode("utf-8")) > SECRET_FILE_LIMIT:
                            raise ConfigurationError("Secret must contain 1–16384 bytes of text")
                        directory = _private_directory(editor.secret_dir)
                        path = write_temp(directory, secret.encode("utf-8"))
                        staged.append(path)
                        row[key] = str(path)
            rows.append({} if remove else row)
        if set(request.form) - expected or any(len(request.form.getlist(key)) != 1 for key in request.form):
            abort(400)
        candidate = deepcopy(document)
        if section in SCHEMAS:
            for (path, _), row in zip(SCHEMAS[section], rows):
                set_table(candidate, path, row)
        elif section == "rules":
            candidate.setdefault("watch", {})["rules"] = [row for row in rows if row.get("name")]
        elif section == "product-mappings":
            candidate["product_mappings"] = [row for row in rows if row.get("vendor")]
        else:
            channels = {}
            for row in rows:
                row = dict(row)
                name = row.pop("name", "")
                if name:
                    if name in channels:
                        raise ConfigurationError("Duplicate channel name")
                    channels[name] = row
            candidate.setdefault("watch", {})["channels"] = channels
        return candidate, staged
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
            document, _, _, version = editor.read()
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
                candidate, staged = parse_form(editor, section, document)
                preview, lockout = editor.preview(section, candidate, version, staged)
                staged = []
                diff = "\n".join(difflib.unified_diff(dumps(redacted(document)).splitlines(),
                                                     dumps(redacted(candidate)).splitlines(),
                                                     fromfile="current", tofile="proposed", lineterm=""))
            new_type = request.args.get("new_type", "smtp")
            return render_template("config_section.html", section=section,
                                   groups=groups_for(section, document, new_type=new_type), version=version,
                                   preview=preview, diff=diff, lockout=lockout,
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
            document, _, _, version = editor.read()
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
                preview, lockout = editor.preview("rollback", candidate, version)
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
