"""Guided and permission-checked management of client inventories."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
from pathlib import Path
import secrets
from threading import Lock
from time import monotonic

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, send_file, url_for

from .clients import client_name, client_page
from .config import InventoryConfig
from .dashboard import _text, requires
from .dashboard_ops import require_accounts
from .errors import ConfigurationError, InventoryValidationError, StateError
from .inventory import MAX_CONTRACT_ROWS, SUPPORTED_FORMATS, load_inventory
from .inventory_preview import FIELDS, FIELD_LABELS, preview_upload
from .locking import OperationLock
from .managed_inventory import (
    HISTORY_LIMIT, KEY, ManagedInventoryCollision, VERSION, archive, encode_records,
    normalized_client, prune, read_inventory, read_profile, versions,
)
from .private_storage import private_directory
from .web_assets import client_key, replace_bytes
from .web_inventory import MAX_BYTES, read_bytes

UPLOAD_REQUEST_BYTES = MAX_BYTES + 64 * 1024
PREVIEW_TTL = 10 * 60


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


def _manage():
    require_accounts()
    if "manage_inventory" not in g.permissions:
        abort(403)


def _audit(db, actor, event, key, detail):
    stamp = datetime.now(timezone.utc).isoformat()
    action = f"{event}:{key}:" + json.dumps(detail, ensure_ascii=True, separators=(",", ":"))
    _users()._append_audit(db, action, actor.username, stamp, actor=actor.username)


def _publish(config, path, profile, previous, assets, mode):
    """Publish within the authorized account transaction and roll back on error."""
    label = profile["name"]
    profile_path = path.with_suffix(".client")
    archive_path = None
    change_started = new_profile = False
    data = encode_records(assets) if assets else None
    if data is not None:
        # Check the exact bytes we will save, including contract size and value bounds.
        read_inventory(data, client=label)
        inventory = config.inventory or InventoryConfig(path=None)
        inventory = replace(inventory, managed_directory=path.parent)
        try:
            load_inventory(
                inventory, snapshot_directory=path.parent.parent / "web-inventory",
                managed_candidate=(path, assets),
            )
        except ManagedInventoryCollision:
            raise
        except (InventoryValidationError, OSError, ValueError, StateError) as exc:
            raise ConfigurationError(
                "The other inventories could not be checked. Ask an administrator to check the inventory settings."
            ) from exc

    try:
        with _users().transaction() as db:
            actor = _require_writer(db)
            _audit(db, actor, "inventory_saved" if assets else "inventory_removed", path.stem,
                   {"client": label, "row_count": len(assets), "mode": mode})
            if not profile_path.exists():
                new_profile = True
                replace_bytes(profile_path, _profile_bytes(profile))
            if previous is not None:
                try:
                    read_inventory(previous, client=label)
                except (InventoryValidationError, ValueError):
                    pass  # A corrupt current file is replaceable without archiving it.
                else:
                    archive_path = archive(path, previous)
            change_started = True
            if data is None:
                path.unlink()
            else:
                replace_bytes(path, data)
    except BaseException:
        if change_started:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                replace_bytes(path, previous)
        if archive_path:
            archive_path.unlink(missing_ok=True)
        if new_profile:
            profile_path.unlink(missing_ok=True)
        raise
    prune(path)


def _profile_bytes(profile):
    return (json.dumps(profile, ensure_ascii=True) + "\n").encode("ascii")


def _require_writer(db):
    try:
        return _users().require_permission_in(db, g.entry.proof, "manage_inventory")
    except ConfigurationError:
        abort(403)


def create_blueprint(config):
    bp = Blueprint("client_inventory", __name__, url_prefix="/watch/clients")
    pending_uploads = PendingUploads()
    directory = config.inventory_directory

    def profile_for(key):
        if not KEY.fullmatch(key):
            abort(404)
        if directory.exists() or directory.is_symlink():
            private_directory(directory, owner_only=True)
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
        return lock

    def detail_url(key, profile, **kwargs):
        return url_for(".detail", key=key, name=profile["name"], **kwargs)

    def render_detail(key, profile, *, error=None, notice=None, status=200):
        path = directory / f"{key}.json"
        warning = None
        data = None
        count = None
        try:
            if directory.exists() or directory.is_symlink():
                private_directory(directory, owner_only=True)
            data = _current(path)
            if data is not None:
                count = len(read_inventory(data, client=profile["name"]))
        except (OSError, ValueError, InventoryValidationError, StateError):
            warning = "The current inventory could not be read. Upload a replacement or ask an administrator to check storage."
        scan, summaries, _ = client_page(config.database_path, limit=1, name=profile["name"])
        upload = _users().latest_inventory_upload(key) if data is not None and g.accounts else None
        return render_template(
            "client_inventory.html", key=key, profile=profile, scan=scan,
            summary=summaries[0] if summaries else None, count=count, upload=upload,
            enabled=config.managed_inventory, error=error, notice=notice, warning=warning,
            revision=_revision(data), present=data is not None,
            history=[item.name.split(".")[1] for item in versions(path)[:HISTORY_LIMIT]],
        ), status

    @bp.app_template_global()
    def version_stamp(value):
        try:
            return datetime.strptime(value, "%Y%m%dT%H%M%S%fZ").strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            return value

    @bp.route("/add", methods=["GET", "POST"])
    @requires("manage_inventory")
    def add():
        _manage()
        if request.method == "GET":
            return render_template("client_add.html")
        profile = {
            "name": request.form.get("name", ""),
            "notes": _text(request.form, "notes", limit=1000),
            "contact": _text(request.form, "contact", limit=200),
        }
        try:
            if len(request.form.getlist("name")) != 1:
                abort(400)
            profile["name"] = normalized_client(profile["name"])
            key = client_key(profile["name"])
            lock = locked()
            try:
                private_directory(directory, owner_only=True)
                path = directory / f"{key}.client"
                if path.exists() or path.is_symlink():
                    raise ConfigurationError("That client already exists. Open it from the Clients page.")
                writing = False
                try:
                    with _users().transaction() as db:
                        actor = _require_writer(db)
                        _audit(db, actor, "client_added", key, {"client": profile["name"]})
                        writing = True
                        replace_bytes(path, _profile_bytes(profile))
                except BaseException:
                    if writing:
                        path.unlink(missing_ok=True)
                    raise
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
            "saved": "Inventory saved. Your next scheduled scan will include it automatically.",
            "restored": "Inventory restored. Your next scheduled scan will include it automatically.",
            "removed": "Inventory removed. Your next scan will use the remaining inventories.",
        }
        return render_detail(key, profile, notice=notices.get(request.args.get("result")))

    def preview_page(key, profile, preview, token, mode, *, error=None, status=200):
        return render_template(
            "client_inventory_preview.html", key=key, profile=profile, preview=preview,
            token=token, fields=FIELD_LABELS, mode=mode, error=error,
        ), status

    @bp.post("/<key>/upload")
    @requires("manage_inventory")
    def upload(key):
        _manage()
        profile = profile_for(key)
        if not config.managed_inventory:
            abort(403)
        try:
            files = request.files.getlist("inventory")
            if len(files) != 1 or not files[0].filename:
                raise ConfigurationError("Choose an inventory file to upload.")
            suffix = Path(files[0].filename).suffix.casefold()
            if suffix.removeprefix(".") not in SUPPORTED_FORMATS and suffix != ".yml":
                raise ConfigurationError("Choose a CSV, XLSX, JSON or YAML file.")
            data = files[0].stream.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ConfigurationError("That file is too large. Choose a file up to 32 MiB.")
            previous = _revision(_current(directory / f"{key}.json"))
            preview = preview_upload(data, suffix, profile["name"])
            token = pending_uploads.add(PendingUpload(g.sid, key, data, suffix, previous, monotonic() + PREVIEW_TTL))
            return preview_page(key, profile, preview, token, "replace")
        except ConfigurationError as exc:
            return render_detail(key, profile, error=str(exc), status=400)
        except (OSError, StateError, ValueError):
            return render_detail(key, profile, error="The upload could not be read. Check storage and retry.", status=503)

    @bp.post("/<key>/review")
    @requires("manage_inventory")
    def review(key):
        _manage()
        profile = profile_for(key)
        if not config.managed_inventory:
            abort(403)
        token = _text(request.form, "token", required=True, limit=64)
        pending = pending_uploads.get(token, key)
        if pending is None:
            return render_detail(key, profile, error="This preview has expired. Upload the file again.", status=409)
        action = _text(request.form, "action", required=True)
        mode = _text(request.form, "mode", required=True)
        if mode not in {"replace", "add"} or action not in {"preview", "previous", "next", "save"}:
            abort(400)
        page_text = _text(request.form, "page", limit=6)
        if not page_text.isascii() or not page_text.isdecimal():
            abort(400)
        page = max(1, int(page_text) + {"previous": -1, "next": 1}.get(action, 0))
        choices = {field: _text(request.form, field, limit=4) for field in FIELDS}
        preview = None
        try:
            preview = preview_upload(pending.data, pending.suffix, profile["name"], choices, page=page)
            if action != "save":
                return preview_page(key, profile, preview, token, mode)
            if preview.errors or not preview.assets:
                return preview_page(key, profile, preview, token, mode, status=400,
                                    error="Fix the errors and make sure at least one row is ready before saving.")
            lock = locked()
            try:
                private_directory(directory, owner_only=True)
                path = directory / f"{key}.json"
                previous = _current(path)
                if pending_uploads.get(token, key) is None or _revision(previous) != pending.previous:
                    return render_detail(key, profile, error="This inventory changed. Upload the file again.", status=409)
                assets = preview.assets
                if mode == "add" and previous is not None:
                    try:
                        original = read_inventory(previous, client=profile["name"])
                    except (InventoryValidationError, ValueError) as exc:
                        raise ConfigurationError("The current inventory is unreadable. Choose Replace to start again.") from exc
                    seen = {asset.asset_id.casefold() for asset in original}
                    if any(asset.asset_id.casefold() in seen for asset in assets):
                        raise ConfigurationError(
                            "An uploaded asset ID is already in this client's inventory. "
                            "Use unique IDs or choose Replace."
                        )
                    assets = original + assets
                if len(assets) > MAX_CONTRACT_ROWS:
                    raise ConfigurationError("This inventory would exceed 100,000 rows. Import fewer rows.")
                _publish(config, path, profile, previous, assets, mode)
                pending_uploads.remove(token)
            finally:
                lock.release()
            return redirect(detail_url(key, profile, result="saved"), code=303)
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
        try:
            data = _current(directory / f"{key}.json")
            if data is None:
                abort(404)
            read_inventory(data, client=profile["name"])
        except (OSError, ValueError, StateError, InventoryValidationError):
            abort(409)
        return send_file(BytesIO(data), mimetype="application/json", as_attachment=True,
                         download_name="inventory.json", max_age=0)

    @bp.post("/<key>/inventory")
    @requires("manage_inventory")
    def change(key):
        _manage()
        profile = profile_for(key)
        action = _text(request.form, "action", required=True)
        if action not in {"restore", "remove"} or (action == "restore" and not config.managed_inventory):
            abort(403)
        expected = _text(request.form, "revision", required=True, limit=64)
        try:
            lock = locked()
            try:
                private_directory(directory, owner_only=True)
                path = directory / f"{key}.json"
                previous = _current(path)
                if _revision(previous) != expected:
                    raise ConfigurationError("This inventory changed. Review the current inventory before continuing.")
                if action == "restore":
                    stamp = _text(request.form, "version", required=True, limit=32)
                    if not VERSION.fullmatch(stamp):
                        abort(400)
                    version = path.with_name(f"{key}.{stamp}.json")
                    if version not in versions(path)[:HISTORY_LIMIT]:
                        raise ConfigurationError("That version is no longer available.")
                    assets = read_inventory(read_bytes(version), client=profile["name"])
                else:
                    if previous is None or _text(request.form, "confirm") != "remove":
                        raise ConfigurationError("Confirm that you want to remove this inventory.")
                    assets = []
                _publish(config, path, profile, previous, assets, action)
            finally:
                lock.release()
        except (ConfigurationError, ManagedInventoryCollision) as exc:
            return render_detail(key, profile, error=str(exc), status=409)
        except (OSError, ValueError, StateError, InventoryValidationError):
            return render_detail(key, profile, error="The inventory change failed. Check storage and retry.", status=503)
        return redirect(detail_url(key, profile, result="restored" if action == "restore" else "removed"), code=303)

    return bp
