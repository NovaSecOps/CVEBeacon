"""Guided and permission-checked management of client inventories."""

from __future__ import annotations

from collections import OrderedDict
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from io import BytesIO, StringIO
from pathlib import Path
import secrets
from threading import BoundedSemaphore, Lock
from time import monotonic
import unicodedata

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, send_file, url_for

from . import web_assets
from .clients import client_name, client_page
from .dashboard import _text, requires
from .dashboard_ops import require_accounts, schedule_scan_state
from .errors import ConfigurationError, InventoryValidationError, StateError
from .inventory import SUPPORTED_FORMATS
from .inventory_preview import FIELDS, FIELD_LABELS, preview_upload
from .inventory_journal import recover, stage_change, sync_directory
from .locking import OperationLock
from .managed_inventory import (
    HISTORY_LIMIT, KEY, InventoryPermissionDenied, InventoryRevisionConflict, ManagedInventoryCollision, VERSION,
    client_key, encode_profile, normalized_client, publish_managed_inventory, read_inventory, read_profile,
    versions,
)
from .private_storage import private_directory
from .web_inventory import MAX_BYTES, read_bytes

UPLOAD_REQUEST_BYTES = MAX_BYTES + 64 * 1024
MAX_PASTE_BYTES = 100_000
PREVIEW_TTL = 10 * 60
_PREVIEW_SLOT = BoundedSemaphore(1)
MANAGE = ("view", "manage_inventory")


@dataclass(frozen=True, slots=True)
class PendingUpload:
    session: str
    key: str
    data: bytes
    suffix: str
    previous: str
    expires: float


class PendingUploads:
    """Keep unfinished uploads in bounded memory with no durable draft files."""

    def __init__(self):
        self.lock = Lock()
        self.items = OrderedDict()

    def _expire(self):
        for token, pending in list(self.items.items()):
            if pending.expires <= monotonic():
                self.items.pop(token)

    def add(self, pending):
        with self.lock:
            self._expire()
            size = sum(len(item.data) for item in self.items.values())
            while size + len(pending.data) > MAX_BYTES or len(self.items) >= 32:
                _, oldest = self.items.popitem(last=False)
                size -= len(oldest.data)
            token = secrets.token_urlsafe(24)
            self.items[token] = pending
            return token

    def get(self, token, key):
        with self.lock:
            self._expire()
            item = self.items.get(token)
            if item and item.session == g.sid and item.key == key:
                return item
        return None

    def remove(self, token):
        with self.lock:
            self.items.pop(token, None)


def _current(path):
    try:
        return read_bytes(path)
    except FileNotFoundError:
        return None


def _revision(data):
    return hashlib.sha256(data).hexdigest() if data is not None else "empty"


def _users():
    return current_app.extensions["dashboard_users"]


def _changes_allowed(config):
    require_accounts()
    if not config.managed_inventory or not set(MANAGE) <= g.permissions:
        abort(403)


def _preview(*args, **kwargs):
    if not _PREVIEW_SLOT.acquire(blocking=False):
        raise ConfigurationError("Another inventory is being checked. Try again in a moment.")
    try:
        return preview_upload(*args, **kwargs)
    finally:
        _PREVIEW_SLOT.release()


def _notes():
    value = request.form.get("notes", "").replace("\r\n", "\n").replace("\r", "\n").strip(" ")
    if len(request.form.getlist("notes")) > 1 or len(value) > 1000:
        raise ConfigurationError("Enter up to 1,000 characters in Notes.")
    if any(unicodedata.category(char) in {"Cc", "Cs"} and char != "\n" for char in value):
        raise ConfigurationError("Notes contain an unsupported character.")
    return value


def _commit_change(config, event, key, detail, changes):
    users = _users()
    sync_directory(config.inventory_directory.parent)
    try:
        with users.transaction() as db:
            actor = _require_writer(db)
            stage_change(config.inventory_directory, db, users, actor, event, key, detail, changes)
    finally:
        recover(config.inventory_directory, users.path)


def _require_writer(db):
    try:
        actor = _users().require_permission_in(db, g.entry.proof, "manage_inventory")
        _users().require_permission_in(db, g.entry.proof, "view")
        return actor
    except ConfigurationError:
        abort(403)


def create_blueprint(config):
    bp = Blueprint("client_inventory", __name__, url_prefix="/watch/clients")
    pending_uploads = PendingUploads()
    directory = config.inventory_directory

    def active_path(key):
        path = directory / f"{key}.json"
        return None if config.inventory and path == config.inventory.path else path

    def profile_for(key):
        if not KEY.fullmatch(key):
            abort(404)
        path = directory / f"{key}.client"
        if config.managed_inventory:
            recover(directory, config.watch.users_database)
        if config.managed_inventory and not directory.is_symlink() and (path.exists() or path.is_symlink()):
            try:
                return read_profile(directory, key)
            except FileNotFoundError:
                pass
            except (ValueError, ConfigurationError):
                abort(404)
        hint = _text(request.args, "name", limit=120)
        if hint:
            try:
                if client_key(normalized_client(hint)) == key:
                    name = client_name(config.database_path, hint)
                    if name is not None:
                        return {"name": normalized_client(name), "notes": "", "contact": ""}
            except ConfigurationError:
                pass
        abort(404)

    def locked():
        lock = OperationLock(config, "client-inventory")
        if not lock.acquire():
            raise ConfigurationError("A scan or inventory change is in progress. Try again when it finishes.")
        try:
            recover(directory, config.watch.users_database)
        except BaseException:
            lock.release()
            raise
        return lock

    def detail_url(key, profile, **kwargs):
        return url_for(".detail", key=key, name=profile["name"], **kwargs)

    def render_detail(key, profile, *, error=None, notice=None, status=200, pasted_text="", paste_format="csv"):
        path = active_path(key)
        warning = None
        data = None
        count = None
        web_asset_count = None
        try:
            allowlist_path = (config.database_path.parent / "web-assets" /
                              (web_assets.client_key(profile["name"]) + ".json"))
            allowlist, _ = web_assets.read_allowlist(allowlist_path, profile["name"])
            web_asset_count = len(allowlist["assets"])
        except (OSError, ValueError, ConfigurationError, StateError):
            pass
        try:
            if path is not None and config.managed_inventory and not directory.is_symlink() and (
                    path.exists() or path.is_symlink()):
                private_directory(directory, owner_only=True)
                data = _current(path)
                if data is not None:
                    count = len(read_inventory(data, client=profile["name"]))
        except (OSError, ValueError, InventoryValidationError, StateError):
            warning = "The current inventory could not be read. Upload a replacement or ask an administrator to check storage."
        scan, summaries, _ = client_page(config.database_path, limit=1, name=profile["name"])
        upload = _users().latest_inventory_upload(key, profile["name"]) if data is not None and g.accounts else None
        return render_template(
            "client_inventory.html", key=key, profile=profile, scan=scan,
            summary=summaries[0] if summaries else None, count=count, upload=upload,
            web_asset_count=web_asset_count,
            enabled=config.managed_inventory and path is not None, error=error, notice=notice, warning=warning,
            pasted_text=pasted_text, paste_format=paste_format,
            scan_schedule=schedule_scan_state(config) if count is not None else None,
            revision=_revision(data), present=data is not None,
            history=[item.name.split(".")[1] for item in versions(path)[:HISTORY_LIMIT]]
            if path is not None and config.managed_inventory and not directory.is_symlink() else [],
        ), status

    @bp.app_template_global()
    def version_stamp(value):
        try:
            return datetime.strptime(value, "%Y%m%dT%H%M%S%fZ").strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            return value

    @bp.route("/add", methods=["GET", "POST"])
    @requires(MANAGE)
    def add():
        _changes_allowed(config)
        if request.method == "GET":
            return render_template("client_add.html")
        profile = {
            "name": request.form.get("name", ""),
            "notes": request.form.get("notes", ""),
            "contact": _text(request.form, "contact", limit=200),
        }
        try:
            if len(request.form.getlist("name")) != 1:
                abort(400)
            profile["name"] = normalized_client(profile["name"])
            profile["notes"] = _notes()
            key = client_key(profile["name"])
            lock = locked()
            try:
                private_directory(directory, owner_only=True)
                path = directory / f"{key}.client"
                if path.exists() or path.is_symlink():
                    raise ConfigurationError("That client already exists. Open it from the Clients page.")
                _commit_change(config, "client_added", key, {"client": profile["name"]},
                               {"profile": (path, encode_profile(profile))})
            finally:
                lock.release()
        except ConfigurationError as exc:
            return render_template("client_add.html", error=str(exc), profile=profile), 400
        except (OSError, StateError):
            return render_template("client_add.html", error="The client could not be saved. Check storage and retry.",
                                   profile=profile), 503
        return redirect(detail_url(key, profile), code=303)

    @bp.get("/<key>")
    @requires("view")
    def detail(key):
        profile = profile_for(key)
        notices = {
            "saved": "Inventory saved.",
            "restored": "Inventory restored.",
            "removed": ("Inventory removed. Your next scan will use the remaining inventories."
                        if config.effective_inventory is not None else
                        "Inventory removed. You can upload or restore an inventory to run scans."),
        }
        return render_detail(key, profile, notice=notices.get(request.args.get("result")))

    @bp.get("/inventory-template")
    @requires("view")
    def inventory_template():
        example = {
            "asset_id": "example-asset-001",
            "vendor": "Example Vendor",
            "product": "Example Product",
            "version": "1.0.0",
            "category": "example-software",
            "system_id": "example-system",
        }
        output = StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(FIELDS)
        writer.writerow([example.get(field, "") for field in FIELDS])
        response = send_file(
            BytesIO(output.getvalue().encode("utf-8")), mimetype="text/csv",
            as_attachment=True, download_name="inventory-template.csv", max_age=0,
        )
        return response

    def preview_page(key, profile, preview, token, mode, *, error=None, status=200):
        return render_template(
            "client_inventory_preview.html", key=key, profile=profile, preview=preview,
            token=token, fields=FIELD_LABELS, mode=mode, error=error,
        ), status

    @bp.post("/<key>/upload")
    @requires(MANAGE)
    def upload(key):
        _changes_allowed(config)
        profile = profile_for(key)
        path = active_path(key)
        if path is None:
            abort(409)
        keep_pasted_text = ""
        paste_format = "csv"
        try:
            files = request.files.getlist("inventory")
            pasted_values = request.form.getlist("pasted_rows")
            format_values = request.form.getlist("paste_format")
            pasted_text = pasted_values[0] if len(pasted_values) == 1 else ""
            pasted_data = None
            paste_encoding_error = False
            paste_too_large = False
            if pasted_values:
                try:
                    encoded_values = [value.encode("utf-8") for value in pasted_values]
                except UnicodeEncodeError:
                    paste_encoding_error = True
                else:
                    paste_too_large = sum(map(len, encoded_values)) > MAX_PASTE_BYTES
                    if len(pasted_values) == 1:
                        pasted_data = encoded_values[0]
                    if len(pasted_values) == 1 and not paste_too_large:
                        keep_pasted_text = pasted_text
            chosen_format = None
            if len(format_values) == 1:
                selected_format = format_values[0].strip().casefold()
                if selected_format in {"csv", "json", "yaml"}:
                    paste_format = chosen_format = selected_format
            if paste_too_large:
                raise ConfigurationError(
                    "Your pasted text was not kept because it is over 100 KB. Paste less, or upload a file."
                )
            if paste_encoding_error:
                raise ConfigurationError("Paste rows as UTF-8 text.")
            if len(files) > 1 or len(pasted_values) > 1:
                raise ConfigurationError("Choose a file or paste rows, not both.")
            has_file = len(files) == 1 and bool(files[0].filename)
            has_paste = bool(pasted_text.strip())
            if has_file and has_paste:
                raise ConfigurationError("Choose a file or paste rows, not both.")
            if not has_file and not has_paste:
                raise ConfigurationError("Choose a file or paste rows.")
            if has_file:
                suffix = Path(files[0].filename).suffix.casefold()
                if suffix.removeprefix(".") not in SUPPORTED_FORMATS and suffix != ".yml":
                    raise ConfigurationError("Choose a CSV, XLSX, JSON or YAML file.")
                data = files[0].stream.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise ConfigurationError("That file is too large. Choose a file up to 32 MiB.")
            else:
                if len(format_values) != 1:
                    raise ConfigurationError("Choose CSV, JSON or YAML for pasted rows.")
                # Use only a valid submitted choice; the display default must not stand in for it.
                suffix = {"csv": ".csv", "json": ".json", "yaml": ".yaml"}.get(chosen_format)
                if suffix is None:
                    raise ConfigurationError("Choose CSV, JSON or YAML for pasted rows.")
                data = pasted_data
            if directory.exists() or directory.is_symlink():
                private_directory(directory, owner_only=True)
            previous = _revision(_current(path))
            preview = _preview(data, suffix, profile["name"])
            token = pending_uploads.add(PendingUpload(g.sid, key, data, suffix, previous, monotonic() + PREVIEW_TTL))
            return preview_page(key, profile, preview, token, "add")
        except ConfigurationError as exc:
            return render_detail(
                key, profile, error=str(exc), status=400,
                pasted_text=keep_pasted_text, paste_format=paste_format,
            )
        except (OSError, StateError, ValueError):
            return render_detail(
                key, profile, error="The upload could not be read. Check storage and retry.", status=503,
                pasted_text=keep_pasted_text, paste_format=paste_format,
            )

    @bp.post("/<key>/review")
    @requires(MANAGE)
    def review(key):
        _changes_allowed(config)
        profile = profile_for(key)
        path = active_path(key)
        if path is None:
            abort(409)
        token = _text(request.form, "token", required=True, limit=64)
        pending = pending_uploads.get(token, key)
        if pending is None:
            return render_detail(key, profile, error="This preview has expired. Upload the file again.", status=409)
        action = _text(request.form, "action", required=True)
        mode = _text(request.form, "mode", required=True)
        if mode not in {"replace", "add"} or action not in {"preview", "previous", "next", "jump", "save"}:
            abort(400)
        page_text = _text(request.form, "jump_page" if action == "jump" else "page", limit=6)
        if not page_text.isascii() or not page_text.isdecimal():
            abort(400)
        page = max(1, int(page_text) + {"previous": -1, "next": 1}.get(action, 0))
        choices = {field: _text(request.form, field, limit=4) for field in FIELDS}
        preview = None
        try:
            preview = _preview(pending.data, pending.suffix, profile["name"], choices, page=page)
            if action != "save":
                return preview_page(key, profile, preview, token, mode)
            if preview.errors or not preview.assets:
                return preview_page(key, profile, preview, token, mode, status=400,
                                    error="Fix the errors and make sure at least one row is ready before saving.")
            publish_managed_inventory(
                config, path, preview.assets, expected_revision=pending.previous, users=_users(),
                proof=g.entry.proof, mode=mode, client=profile["name"], profile=profile,
                precondition=lambda previous: pending_uploads.get(token, key) is not None,
                after_publish=lambda: pending_uploads.remove(token),
            )
            return redirect(detail_url(key, profile, result="saved"), code=303)
        except InventoryRevisionConflict:
            return render_detail(key, profile, error="This inventory changed. Upload the file again.", status=409)
        except InventoryPermissionDenied:
            abort(403)
        except (ConfigurationError, ManagedInventoryCollision) as exc:
            if preview is None:
                return render_detail(key, profile, error=str(exc), status=400)
            return preview_page(key, profile, preview, token, mode, error=str(exc), status=400)
        except (OSError, ValueError, StateError, InventoryValidationError):
            return render_detail(key, profile, error="The inventory could not be saved. Check storage and retry.", status=503)

    @bp.get("/<key>/download")
    @requires("view")
    def download(key):
        profile = profile_for(key)
        path = active_path(key)
        if path is None or not config.managed_inventory or directory.is_symlink():
            abort(404)
        try:
            private_directory(directory, owner_only=True)
            data = _current(path)
            if data is None:
                abort(404)
            read_inventory(data, client=profile["name"])
        except (OSError, ValueError, StateError, InventoryValidationError):
            abort(409)
        return send_file(BytesIO(data), mimetype="application/json", as_attachment=True,
                         download_name="inventory.json", max_age=0)

    @bp.post("/<key>/inventory")
    @requires(MANAGE)
    def change(key):
        _changes_allowed(config)
        profile = profile_for(key)
        path = active_path(key)
        if path is None:
            abort(409)
        action = _text(request.form, "action", required=True)
        if action not in {"restore", "remove"}:
            abort(403)
        expected = _text(request.form, "revision", required=True, limit=64)
        try:
            restore_stamp = None
            precondition = None
            if action == "restore":
                def restore_stamp():
                    stamp = _text(request.form, "version", required=True, limit=32)
                    if not VERSION.fullmatch(stamp):
                        abort(400)
                    return stamp
            else:
                def confirm_remove(previous):
                    if previous is None or _text(request.form, "confirm") != "remove":
                        raise ConfigurationError("Confirm that you want to remove this inventory.")
                    return True

                precondition = confirm_remove
            publish_managed_inventory(
                config, path, [], expected_revision=expected, users=_users(), proof=g.entry.proof,
                mode=action, client=profile["name"], profile=profile, restore_stamp=restore_stamp,
                precondition=precondition,
            )
        except InventoryRevisionConflict:
            return render_detail(
                key, profile, error="This inventory changed. Review the current inventory before continuing.",
                status=409,
            )
        except InventoryPermissionDenied:
            abort(403)
        except (ConfigurationError, ManagedInventoryCollision) as exc:
            return render_detail(key, profile, error=str(exc), status=409)
        except (OSError, ValueError, StateError, InventoryValidationError):
            return render_detail(key, profile, error="The inventory change failed. Check storage and retry.", status=503)
        return redirect(detail_url(key, profile, result="restored" if action == "restore" else "removed"), code=303)

    return bp
