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

from . import dashboard_web, web_assets
from .clients import client_name, client_page
from .dashboard import _text, requires
from .dashboard_ops import require_accounts, schedule_scan_state
from .errors import ConfigurationError, InventoryValidationError, StateError
from .inventory import SUPPORTED_FORMATS, load_inventory
from .inventory_preview import FIELDS, FIELD_LABELS, preview_upload
from .inventory_journal import recover, stage_change, sync_directory
from .locking import OperationLock
from .managed_inventory import (
    HISTORY_LIMIT, KEY, InventoryPermissionDenied, InventoryRevisionConflict, ManagedInventoryCollision, VERSION,
    UNASSIGNED_KEY, client_key, encode_profile, inventory_files, normalized_client,
    profiles, publish_managed_inventory, publish_unassigned_inventory, read_inventory,
    read_profile, read_unassigned_inventory, versions,
)
from .private_storage import private_directory
from .web_inventory import MAX_BYTES, read_bytes, read_web_snapshot

UPLOAD_REQUEST_BYTES = MAX_BYTES + 64 * 1024
MAX_PASTE_BYTES = 100_000
DETAIL_PAGE_SIZE = 100
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
    client: str = ""
    profile: dict | None = None


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

    def get(self, token, key=None):
        with self.lock:
            self._expire()
            item = self.items.get(token)
            if item and item.session == g.sid and (key is None or item.key == key):
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
    bp = Blueprint("client_inventory", __name__)
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

    def render_detail(
        key, profile, *, error=None, notice=None, status=200, pasted_text="", paste_format="csv",
        unassigned=False,
    ):
        path = active_path(key)
        warning = None
        data = None
        count = None
        assets = []
        web_asset_count = None
        if not unassigned:
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
                    assets = (
                        read_unassigned_inventory(data) if unassigned
                        else read_inventory(data, client=profile["name"])
                    )
                    count = len(assets)
        except (OSError, ValueError, InventoryValidationError, StateError):
            warning = "The current inventory could not be read. Upload a replacement or ask an administrator to check storage."
        if unassigned:
            scan, summaries = None, ()
        else:
            scan, summaries, _ = client_page(config.database_path, limit=1, name=profile["name"])
        upload = (_users().latest_inventory_upload(key, "" if unassigned else profile["name"])
                  if data is not None and g.accounts else None)
        if unassigned:
            detail_href = url_for(".unassigned_detail")
            download_href = url_for(".unassigned_download")
            change_href = url_for(".unassigned_change")
            upload_href = url_for(".inventory_add")
        else:
            detail_href = detail_url(key, profile)
            download_href = url_for(".download", key=key, name=profile["name"])
            change_href = url_for(".change", key=key, name=profile["name"])
            upload_href = detail_href + "#upload-inventory"
        row_page_text = _text(request.args, "rows_page", limit=6)
        if row_page_text and (not row_page_text.isascii() or not row_page_text.isdecimal()):
            abort(400)
        row_pages = max(1, (count + DETAIL_PAGE_SIZE - 1) // DETAIL_PAGE_SIZE) if count is not None else 1
        row_page = min(max(1, int(row_page_text or "1")), row_pages)
        row_start = (row_page - 1) * DETAIL_PAGE_SIZE
        display_assets = assets[row_start:row_start + DETAIL_PAGE_SIZE]
        if row_page > 1:
            row_previous = (
                url_for(".unassigned_detail", rows_page=row_page - 1) if unassigned else
                url_for(".detail", key=key, name=profile["name"], rows_page=row_page - 1)
            )
        else:
            row_previous = None
        if row_page < row_pages:
            row_next = (
                url_for(".unassigned_detail", rows_page=row_page + 1) if unassigned else
                url_for(".detail", key=key, name=profile["name"], rows_page=row_page + 1)
            )
        else:
            row_next = None
        return render_template(
            "client_inventory.html", key=key, profile=profile, scan=scan,
            summary=summaries[0] if summaries else None, count=count, assets=display_assets, upload=upload,
            web_asset_count=web_asset_count,
            enabled=config.managed_inventory and path is not None, error=error, notice=notice, warning=warning,
            pasted_text=pasted_text, paste_format=paste_format,
            scan_schedule=schedule_scan_state(config) if count is not None else None,
            revision=_revision(data), present=data is not None,
            is_unassigned=unassigned, detail_href=detail_href, download_href=download_href,
            change_href=change_href, upload_href=upload_href, all_inventory_url=url_for(".index"),
            row_page=row_page, row_pages=row_pages,
            row_start=row_start + 1 if count else 0,
            row_end=min(row_start + len(display_assets), count or 0),
            row_previous=row_previous, row_next=row_next,
            history=[item.name.split(".")[1] for item in versions(path)[:HISTORY_LIMIT]]
            if path is not None and config.managed_inventory and not directory.is_symlink() else [],
        ), status

    @bp.app_template_global()
    def version_stamp(value):
        try:
            return datetime.strptime(value, "%Y%m%dT%H%M%S%fZ").strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            return value

    @bp.app_template_global()
    def inventory_timestamp(value):
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                return value
            return stamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (AttributeError, TypeError, ValueError):
            return value

    def web_result_count():
        directory = config.database_path.parent / "web-inventory"
        total = 0
        try:
            for path in sorted(directory.glob("*.json")):
                if path.name.endswith(".manifest.json"):
                    continue
                try:
                    assets, _ = read_web_snapshot(path)
                except (OSError, ValueError, ConfigurationError, InventoryValidationError, StateError):
                    continue
                total += len(assets)
        except OSError:
            pass
        return total

    @bp.get("/inventory")
    @requires("view")
    def index():
        no_client = None
        clients = []
        configured = None
        storage_warning = False
        if config.managed_inventory:
            try:
                recover(directory, config.watch.users_database)
            except (OSError, StateError):
                storage_warning = True
            try:
                by_key = {client_key(item["name"]): item for item in profiles(
                    directory, config.watch.users_database,
                )}
            except (OSError, ValueError, ConfigurationError, StateError):
                by_key = {}
                storage_warning = True
            if not storage_warning:
                for path in inventory_files(directory, configured=config.inventory.path if config.inventory else None):
                    try:
                        data = _current(path)
                        if data is None:
                            continue
                        if path.name == f"{UNASSIGNED_KEY}.json":
                            rows = read_unassigned_inventory(data)
                            upload = _users().latest_inventory_upload(UNASSIGNED_KEY, "") if g.accounts else None
                            no_client = {
                                "count": len(rows),
                                "last_saved": upload[1] if upload else datetime.fromtimestamp(
                                    path.stat().st_mtime, timezone.utc).isoformat(),
                            }
                            continue
                        profile = by_key.get(path.stem)
                        if profile is None:
                            storage_warning = True
                            continue
                        rows = read_inventory(data, client=profile["name"])
                        clients.append({
                            "name": profile["name"], "key": path.stem, "count": len(rows),
                            "url": detail_url(path.stem, profile),
                        })
                    except (OSError, ValueError, ConfigurationError, InventoryValidationError, StateError):
                        storage_warning = True
                        continue
        if config.inventory and config.inventory.path is not None and config.inventory.path.is_file():
            try:
                from dataclasses import replace as replace_dataclass
                configured_inventory = replace_dataclass(
                    config.inventory, web_snapshots=False, managed_directory=None, managed_users_path=None,
                )
                configured = {"count": len(load_inventory(configured_inventory)), "readable": True}
            except (OSError, ValueError, ConfigurationError, InventoryValidationError, StateError):
                configured = {"count": None, "readable": False}
        web_count = web_result_count()
        has_inventory = bool(no_client or clients or configured or web_count or storage_warning)
        can_manage = bool(
            config.managed_inventory and g.accounts and {"view", "manage_inventory"} <= g.permissions
        )
        return render_template(
            "inventory.html", no_client=no_client,
            clients=sorted(clients, key=lambda item: item["name"].casefold()),
            configured=configured, web_count=web_count, has_inventory=has_inventory,
            can_manage=can_manage, storage_warning=storage_warning,
        )

    def render_inventory_add(*, error=None, status=200, client="", new_client="", pasted_text="", paste_format="csv"):
        return render_template(
            "inventory.html", add_page=True, error=error, clients=dashboard_web._inventory_clients(config),
            selected_client=client, new_client_name=new_client, pasted_text=pasted_text,
            paste_format=paste_format,
        ), status

    @bp.get("/inventory/add")
    @requires(MANAGE)
    def inventory_add():
        _changes_allowed(config)
        return render_inventory_add()

    def resolve_inventory_target(selected, typed_name):
        if selected and typed_name:
            raise ConfigurationError("Choose an existing client or enter a new client name, not both.")
        candidates = dashboard_web._inventory_clients(config)
        if selected:
            wanted_key = client_key(normalized_client(selected))
            name = next((candidate for candidate in candidates
                         if client_key(normalized_client(candidate)) == wanted_key), None)
            if name is None:
                raise ConfigurationError("Choose a client from the list, or leave Client set to No client.")
        elif typed_name:
            normalized = normalized_client(typed_name)
            wanted_key = client_key(normalized)
            name = next((candidate for candidate in candidates
                         if client_key(normalized_client(candidate)) == wanted_key), normalized)
        else:
            return UNASSIGNED_KEY, "", None
        name = normalized_client(name)
        key = client_key(name)
        profile_path = directory / f"{key}.client"
        if profile_path.exists() or profile_path.is_symlink():
            try:
                profile = read_profile(directory, key)
            except (OSError, ValueError, ConfigurationError, StateError) as exc:
                raise ConfigurationError("That client profile could not be read. Check storage and retry.") from exc
        else:
            profile = {"name": name, "notes": "", "contact": ""}
        return key, name, profile

    def read_upload_payload():
        files = request.files.getlist("inventory")
        pasted_values = request.form.getlist("pasted_rows")
        format_values = request.form.getlist("paste_format")
        pasted_text = pasted_values[0] if len(pasted_values) == 1 else ""
        pasted_data = None
        paste_encoding_error = False
        paste_too_large = False
        try:
            encoded_values = [value.encode("utf-8") for value in pasted_values]
        except UnicodeEncodeError:
            paste_encoding_error = True
        else:
            paste_too_large = sum(map(len, encoded_values)) > MAX_PASTE_BYTES
            if len(pasted_values) == 1:
                pasted_data = encoded_values[0]
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
        display_format = "csv"
        if len(format_values) == 1 and format_values[0].strip().casefold() in {"csv", "json", "yaml"}:
            display_format = format_values[0].strip().casefold()
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
            chosen_format = format_values[0].strip().casefold()
            suffix = {"csv": ".csv", "json": ".json", "yaml": ".yaml"}.get(chosen_format)
            if suffix is None:
                raise ConfigurationError("Choose CSV, JSON or YAML for pasted rows.")
            data = pasted_data
            display_format = chosen_format
        return data, suffix, pasted_text if has_paste else "", display_format

    @bp.route("/watch/clients/add", methods=["GET", "POST"])
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

    @bp.get("/watch/clients/<key>")
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

    @bp.get("/watch/clients/inventory-template")
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

    def preview_page(
        key, profile, client, preview, token, mode, *, error=None, status=200,
        general=False, unassigned=False,
    ):
        target_name = "No client" if unassigned else client
        if general:
            back_url = url_for(".index")
            back_label = "Back to Inventory"
            review_url = url_for(".inventory_review")
        else:
            back_url = detail_url(key, profile)
            back_label = "Back to " + profile["name"]
            review_url = url_for(".review", key=key, name=profile["name"])
        return render_template(
            "client_inventory_preview.html", key=key, profile=profile, preview=preview,
            client=client, target_name=target_name, back_url=back_url, back_label=back_label,
            review_url=review_url, general=general, is_unassigned=unassigned,
            token=token, fields=FIELD_LABELS, mode=mode, error=error,
        ), status

    def handle_upload(key, client, profile, *, general=False, selected_client="", new_client=""):
        unassigned = key == UNASSIGNED_KEY
        path = active_path(key)
        if path is None:
            abort(409)
        keep_pasted_text = ""
        paste_format = "csv"
        pasted_values = request.form.getlist("pasted_rows")
        format_values = request.form.getlist("paste_format")
        if len(pasted_values) == 1:
            try:
                if len(pasted_values[0].encode("utf-8")) <= MAX_PASTE_BYTES:
                    keep_pasted_text = pasted_values[0]
            except UnicodeEncodeError:
                pass
        if len(format_values) == 1 and format_values[0].strip().casefold() in {"csv", "json", "yaml"}:
            paste_format = format_values[0].strip().casefold()
        try:
            data, suffix, keep_pasted_text, paste_format = read_upload_payload()
            if directory.exists() or directory.is_symlink():
                private_directory(directory, owner_only=True)
            previous = _revision(_current(path))
            preview = _preview(data, suffix, client)
            token = pending_uploads.add(PendingUpload(
                g.sid, key, data, suffix, previous, monotonic() + PREVIEW_TTL,
                client=client, profile=profile,
            ))
            return preview_page(
                key, profile, client, preview, token, "add", general=general, unassigned=unassigned,
            )
        except ConfigurationError as exc:
            if general:
                return render_inventory_add(
                    error=str(exc), status=400, client=selected_client, new_client=new_client,
                    pasted_text=keep_pasted_text, paste_format=paste_format,
                )
            return render_detail(key, profile, error=str(exc), status=400,
                                 pasted_text=keep_pasted_text, paste_format=paste_format)
        except (OSError, StateError, ValueError):
            message = "The upload could not be read. Check storage and retry."
            if general:
                return render_inventory_add(error=message, status=503, client=selected_client,
                                            new_client=new_client, pasted_text=keep_pasted_text,
                                            paste_format=paste_format)
            return render_detail(key, profile, error=message, status=503,
                                 pasted_text=keep_pasted_text, paste_format=paste_format)

    @bp.post("/watch/clients/<key>/upload")
    @requires(MANAGE)
    def upload(key):
        _changes_allowed(config)
        profile = profile_for(key)
        return handle_upload(key, profile["name"], profile)

    @bp.post("/inventory/upload")
    @requires(MANAGE)
    def inventory_upload():
        _changes_allowed(config)
        try:
            if len(request.form.getlist("client")) != 1 or len(request.form.getlist("new_client")) != 1:
                abort(400)
            selected = _text(request.form, "client", limit=128)
            typed_name = _text(request.form, "new_client", limit=128)
            key, client, profile = resolve_inventory_target(selected, typed_name)
        except ConfigurationError as exc:
            return render_inventory_add(error=str(exc), status=400,
                                        client=request.form.get("client", ""),
                                        new_client=request.form.get("new_client", ""))
        return handle_upload(key, client, profile, general=True,
                             selected_client=selected, new_client=typed_name)

    def review_flow(key, profile, client, token, *, general=False):
        unassigned = key == UNASSIGNED_KEY
        path = active_path(key)
        if path is None:
            abort(409)
        pending = pending_uploads.get(token, key)
        if pending is None:
            message = "This preview has expired. Upload the file again."
            if general:
                return render_inventory_add(error=message, status=409)
            return render_detail(key, profile, error=message, status=409)
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
            preview = _preview(pending.data, pending.suffix, pending.client, choices, page=page)
            if action != "save":
                return preview_page(
                    key, profile, pending.client, preview, token, mode,
                    general=general, unassigned=unassigned,
                )
            if preview.errors or not preview.assets:
                return preview_page(
                    key, profile, pending.client, preview, token, mode, general=general,
                    unassigned=unassigned, status=400,
                    error="Fix the errors and make sure at least one row is ready before saving.",
                )
            publisher = publish_unassigned_inventory if unassigned else publish_managed_inventory
            if unassigned:
                publisher(
                    config, preview.assets, expected_revision=pending.previous, users=_users(),
                    proof=g.entry.proof, mode=mode,
                    precondition=lambda previous: pending_uploads.get(token, key) is not None,
                    after_publish=lambda: pending_uploads.remove(token),
                )
                return redirect(url_for(".unassigned_detail", result="saved"), code=303)
            publisher(
                config, path, preview.assets, expected_revision=pending.previous, users=_users(),
                proof=g.entry.proof, mode=mode, client=pending.client, profile=pending.profile,
                precondition=lambda previous: pending_uploads.get(token, key) is not None,
                after_publish=lambda: pending_uploads.remove(token),
            )
            return redirect(detail_url(key, profile, result="saved"), code=303)
        except InventoryRevisionConflict:
            return render_detail(key, profile, error="This inventory changed. Upload the file again.",
                                 status=409, unassigned=unassigned)
        except InventoryPermissionDenied:
            abort(403)
        except (ConfigurationError, ManagedInventoryCollision) as exc:
            if preview is None:
                return render_detail(key, profile, error=str(exc), status=400, unassigned=unassigned)
            return preview_page(key, profile, pending.client, preview, token, mode, error=str(exc), status=400,
                                general=general, unassigned=unassigned)
        except (OSError, ValueError, StateError, InventoryValidationError):
            return render_detail(key, profile, error="The inventory could not be saved. Check storage and retry.",
                                 status=503, unassigned=unassigned)

    @bp.post("/watch/clients/<key>/review")
    @requires(MANAGE)
    def review(key):
        _changes_allowed(config)
        profile = profile_for(key)
        token = _text(request.form, "token", required=True, limit=64)
        return review_flow(key, profile, profile["name"], token)

    @bp.post("/inventory/review")
    @requires(MANAGE)
    def inventory_review():
        _changes_allowed(config)
        token = _text(request.form, "token", required=True, limit=64)
        pending = pending_uploads.get(token)
        if pending is None:
            return render_inventory_add(error="This preview has expired. Upload the file again.", status=409)
        profile = pending.profile or {"name": "No client", "notes": "", "contact": ""}
        return review_flow(pending.key, profile, pending.client, token, general=True)

    def download_inventory(key, profile=None, *, unassigned=False):
        path = active_path(key)
        if path is None or not config.managed_inventory or directory.is_symlink():
            abort(404)
        try:
            private_directory(directory, owner_only=True)
            data = _current(path)
            if data is None:
                abort(404)
            if unassigned:
                read_unassigned_inventory(data)
            else:
                read_inventory(data, client=profile["name"])
        except (OSError, ValueError, StateError, InventoryValidationError):
            abort(409)
        return send_file(BytesIO(data), mimetype="application/json", as_attachment=True,
                         download_name="inventory.json", max_age=0)

    @bp.get("/watch/clients/<key>/download")
    @requires("view")
    def download(key):
        return download_inventory(key, profile_for(key))

    def change_inventory(key, profile, *, unassigned=False):
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
            if unassigned:
                publish_unassigned_inventory(
                    config, [], expected_revision=expected, users=_users(), proof=g.entry.proof,
                    mode=action, restore_stamp=restore_stamp, precondition=precondition,
                )
            else:
                publish_managed_inventory(
                    config, path, [], expected_revision=expected, users=_users(), proof=g.entry.proof,
                    mode=action, client=profile["name"], profile=profile, restore_stamp=restore_stamp,
                    precondition=precondition,
                )
        except InventoryRevisionConflict:
            return render_detail(
                key, profile, error="This inventory changed. Review the current inventory before continuing.",
                status=409, unassigned=unassigned,
            )
        except InventoryPermissionDenied:
            abort(403)
        except (ConfigurationError, ManagedInventoryCollision) as exc:
            return render_detail(key, profile, error=str(exc), status=409, unassigned=unassigned)
        except (OSError, ValueError, StateError, InventoryValidationError):
            return render_detail(key, profile, error="The inventory change failed. Check storage and retry.",
                                 status=503, unassigned=unassigned)
        if unassigned:
            return redirect(url_for(".unassigned_detail", result="restored" if action == "restore" else "removed"),
                            code=303)
        return redirect(detail_url(key, profile, result="restored" if action == "restore" else "removed"), code=303)

    @bp.post("/watch/clients/<key>/inventory")
    @requires(MANAGE)
    def change(key):
        _changes_allowed(config)
        return change_inventory(key, profile_for(key))

    @bp.get("/inventory/unassigned")
    @requires("view")
    def unassigned_detail():
        profile = {"name": "No client", "notes": "", "contact": ""}
        notices = {
            "saved": "Inventory saved.",
            "restored": "Inventory restored.",
            "removed": ("Inventory removed. Your next scan will use the remaining inventories."
                        if config.effective_inventory is not None else
                        "Inventory removed. You can upload or restore an inventory to run scans."),
        }
        return render_detail(
            UNASSIGNED_KEY, profile, unassigned=True,
            notice=notices.get(request.args.get("result")),
        )

    @bp.get("/inventory/unassigned/download")
    @requires("view")
    def unassigned_download():
        return download_inventory(UNASSIGNED_KEY, unassigned=True)

    @bp.post("/inventory/unassigned/inventory")
    @requires(MANAGE)
    def unassigned_change():
        _changes_allowed(config)
        profile = {"name": "No client", "notes": "", "contact": ""}
        return change_inventory(UNASSIGNED_KEY, profile, unassigned=True)

    return bp
