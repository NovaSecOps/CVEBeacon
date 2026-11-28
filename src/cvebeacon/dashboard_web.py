"""Forms and results for explicitly authorised client web assets."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import math
import re
import stat
import unicodedata
from urllib.parse import urlsplit

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .clients import client_name, client_page
from .dashboard import _text, requires
from .dashboard_inventory import MANAGE, _changes_allowed, _current, _publish, _revision, inventory_lock
from .dashboard_jobs import JobQueueFull, build_command
from .dashboard_ops import require_accounts
from .errors import CVEBeaconError, ConfigurationError, InventoryValidationError, StateError
from .inventory import MAX_CONTRACT_ROWS
from .locking import OperationLock, RunInProgress
from .managed_inventory import (
    ManagedInventoryCollision, client_key as inventory_client_key, normalized_client, profiles,
    read_inventory, read_profile,
)
from .private_storage import private_directory
from .publication import PublicationTimeout
from .state import StateStore
from . import web_assets
from . import web_inventory_actions as actions
from . import web_inventory_sync as sync
from . import web_reported
from .web_assets import (COMPANION_NOTICE, client_label, directories,
                         paths, read_allowlist, save_allowlist, validate_allowlist)
from .web_assets_import import register as register_import
from .web_inventory import decode_json, read_bytes, read_web_snapshot

_RUN_STATUSES = {"success", "partial", "failed", "no-usable-versions"}
_RUN_STATE_LABELS = {
    "success": ("Succeeded", "success"),
    "partial": ("Partial", "warning"),
    "failed": ("Failed", "danger"),
    "no-usable-versions": ("No usable versions", "warning"),
}
_LEGACY_QUERY_LIMITS = {
    "view": 8, "version": 16, "inv": 16, "rep": 16, "category": 80, "site": 256,
    "tech": 80, "sync_page": 6, "sync_result": 20, "added": 6, "marked": 6,
    "withdrawn": 6, "imported": 6, "prefill_url": 2048,
}
_EVIDENCE_KINDS = frozenset({
    "header", "cookie", "meta", "url", "html", "script", "style", "manifest",
    "robots", "icon", "implied", "dom", "text",
})
# Mirror the optional detector's category vocabulary without importing Extensions into Core.
_WEB_PRODUCT_CATEGORIES = frozenset({
    "web-server", "application-server", "language", "framework", "cms", "js-library",
    "css-library", "edge", "ops-tool", "hosted-platform", "application", "reverse-proxy",
    "analytics",
})
_NPM_NAME_PART = re.compile(r"[a-z0-9][a-z0-9._~-]{0,213}\Z")
_NPM_SCOPE_PART = re.compile(r"[a-z0-9][a-z0-9._~-]{0,213}\Z")
_FETCH_FAILURE_REASONS = {
    "unreachable", "tls-error", "blocked", "redirect-blocked", "timeout", "too-large",
    "unsupported-encoding",
}
_REASON_LABELS = {
    "unreachable": "Could not reach site",
    "tls-error": "TLS certificate or handshake problem",
    "blocked": "Request blocked",
    "redirect-blocked": "Too many redirects or redirect not allowed",
    "timeout": "Request timed out",
    "too-large": "Page too large",
    "unsupported-encoding": "Unsupported response encoding",
    "no-technologies": "No products recognised",
    "version-unknown": "Version not disclosed",
    "version-conflict": "Conflicting versions",
}


_ROW_LIMIT = 500


def _sync_page_number(values):
    value = values.get("sync_page", "")
    if not 1 <= len(value) <= 6 or not value.isascii() or not value.isdecimal():
        return 1
    return max(1, int(value))


def _passthrough_query(values):
    """Known legacy query values for a redirect; unknown or malformed values are ignored."""
    result = {}
    for name, limit in _LEGACY_QUERY_LIMITS.items():
        entries = values.getlist(name)
        if len(entries) != 1:
            continue
        value = entries[0].strip()
        if not value or len(value) > limit or any(ord(char) < 32 for char in value):
            continue
        result[name] = value
    confidence = [value for value in values.getlist("conf")[:8] if value in _CONFIDENCE_CHOICES]
    if confidence:
        result["conf"] = confidence
    return result


def _site_url(entry):
    """The saved target as a display URL; malformed entries show what was stored."""
    try:
        scheme = str(entry.get("scheme", "https")).casefold()
        if scheme not in {"http", "https"}:
            scheme = "https"
        host = entry.get("hostname") or urlsplit(entry.get("url", "")).hostname or ""
        port = int(entry.get("port") or (443 if scheme == "https" else 80))
        path = entry.get("path") or "/"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{scheme}://{host}:{port}{path}" if host else str(entry.get("url", ""))
    except (TypeError, ValueError, AttributeError):
        return str(entry.get("url", "") or entry.get("hostname", ""))


def _expiry_state(value, now):
    """Server-side expiry state: none, active, soon (30 days), expired or invalid."""
    if not value:
        return "none"
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        moment = moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return "invalid"
    if moment <= now:
        return "expired"
    if moment <= now + timedelta(days=30):
        return "soon"
    return "active"


def _short_date(value):
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        moment = moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return ""
    return moment.strftime("%d %b")


def _run_is_stale(value, now):
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        moment = moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return True
    return now - moment > timedelta(days=7)


_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
_CONFIDENCE_CHOICES = ("high", "medium", "low")
_NO_SITE = "Site not recorded"
_INVENTORY_UNREADABLE = ("The saved inventory for this client could not be read. "
                         "Open the client's Inventory page to check it.")
_STATUS_CHOICES = ("monitored", "ready", "review", "service")
_REP_CHOICES = ("any", "reported", "not", "changed")
_CONFIDENCE_NAMES = {"high": "High", "medium": "Medium", "low": "Low"}
_SYNC_MESSAGES = {
    "mode": "Inventory sync setting saved.",
    "ignore": "Product ignored until it changes.",
    "keep-version": "Kept the inventory version.",
    "update": "Updated the inventory version.",
    "remove": "Removed the product from the inventory.",
    "keep-removal": "Kept the product in the inventory.",
    "reconsider": "The product is eligible for removal again after complete detection.",
}


def _site_label(item):
    return item.get("hostname") or _NO_SITE


def _filter_args(args, categories, sites):
    """Read the product filters from the query string; invalid values reset to the default."""
    def single(name, limit=80):
        value = args.get(name, "")
        if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
            return ""
        return value.strip()

    chosen = [value for value in args.getlist("conf")[:8] if value in _CONFIDENCE_CHOICES]
    conf = set(chosen) if chosen else set(_CONFIDENCE_CHOICES)
    version = single("version", 16)
    inventory = single("inv", 16)
    category = single("category")
    site = single("site", 256)
    reported = single("rep", 16)
    return {
        "conf": conf,
        "version": version if version in {"with", "without"} else "any",
        "inv": inventory if inventory in _STATUS_CHOICES else "any",
        "category": category if category in categories else "",
        "site": site if site in sites else "",
        "tech": single("tech"),
        "rep": reported if reported in _REP_CHOICES else "any",
        "view": "tech" if single("view", 8) == "tech" else "site",
    }


def _filters_active(flt):
    return (flt["conf"] != set(_CONFIDENCE_CHOICES) or flt["version"] != "any" or flt["inv"] != "any"
            or flt["rep"] != "any" or bool(flt["category"] or flt["site"] or flt["tech"]))


def _matches(item, flt):
    """Whether a decorated product passes the filters. The page and the add actions share this."""
    needle = flt["tech"].casefold()
    return bool(
        (item["confidence_class"] in flt["conf"] or (
            item["confidence_class"] == "neutral" and flt["conf"] == set(_CONFIDENCE_CHOICES)))
        and (flt["version"] == "any" or item["has_version"] == (flt["version"] == "with"))
        and (flt["inv"] == "any" or item["status"] == flt["inv"])
        and (flt["rep"] == "any" or item["rep"] == flt["rep"])
        and (not flt["category"] or flt["category"] in item["category_labels"])
        and (not flt["site"] or _site_label(item) == flt["site"])
        and (not needle or needle in item["display_name"].casefold()))


def _filter_text(flt):
    """Plain words for the confirmation page: which filter produced the list."""
    parts = []
    if flt["conf"] != set(_CONFIDENCE_CHOICES):
        names = [_CONFIDENCE_NAMES[level] for level in _CONFIDENCE_CHOICES if level in flt["conf"]]
        parts.append(" or ".join(names) + " confidence")
    if flt["version"] != "any":
        parts.append("a detected version" if flt["version"] == "with" else "no detected version")
    if flt["category"]:
        parts.append("category " + flt["category"])
    if flt["site"]:
        parts.append("site " + flt["site"])
    if flt["tech"]:
        parts.append("a name containing \u201c" + flt["tech"] + "\u201d")
    if flt["rep"] != "any":
        parts.append({"reported": "a report mark", "not": "no report mark",
                      "changed": "a version changed since it was reported"}[flt["rep"]])
    if flt["inv"] != "any":
        parts.append("status " + actions.STATUS_LABELS[flt["inv"]])
    return "Ready products with " + ", ".join(parts) if parts else "All ready products"


def _decorate_product(item):
    """Display fields derived from one saved product; shared by the page and the add actions."""
    item["display_name"] = item.get("name") or f"{item.get('vendor', '')}/{item.get('product', '')}"
    versions = [version for version in item.get("versions", []) if version.strip()]
    item["has_version"] = bool(versions)
    item["display_version"] = ", ".join(versions) or "Version not disclosed"
    confidence = item.get("confidence", "").casefold()
    item["confidence_label"] = confidence.title() if confidence in _CONFIDENCE_NAMES else "Unknown"
    item["confidence_class"] = confidence if confidence in _CONFIDENCE_NAMES else "neutral"
    item["category_labels"] = item.get("categories", [item.get("category") or "Category not recorded"])


def _report_state(item, marks):
    """not, reported, or changed (the version shown now differs from the marked one)."""
    mark = marks.get(item.get("asset_id"))
    item["mark"] = mark
    if mark is None:
        return "not"
    return "reported" if mark["version"] == web_reported.shown_version(item) else "changed"


def _technology_rows(rows):
    """One row per technology, in one pass over the already filtered product rows."""
    groups = {}
    for item in rows:
        group = groups.setdefault(item["display_name"].casefold(), {
            "name": item["display_name"], "sites": {}, "versions": {}, "categories": [],
            "rank": 0, "label": "Unknown", "class": "neutral", "items": [],
        })
        group["items"].append(item)
        site = _site_label(item)
        versions = [v for v in item.get("versions", []) if v.strip()]
        group["sites"].setdefault(site, []).append((", ".join(versions), item))
        for version in versions or [""]:
            group["versions"][version] = group["versions"].get(version, 0) + 1
        for category in item["category_labels"]:
            if category not in group["categories"]:
                group["categories"].append(category)
        rank = _CONFIDENCE_RANK.get(item.get("confidence", "").casefold(), 0)
        if rank > group["rank"] or (rank == group["rank"] == 0):
            group["rank"], group["label"], group["class"] = rank, item["confidence_label"], item["confidence_class"]
    result = []
    for group in groups.values():
        group["status"] = actions.best_status(entry["status"] for entry in group["items"])
        group["cve"] = _merge_cve(entry["cve"] for entry in group["items"])
        group["site_count"] = len(group["sites"])
        marked = [entry for entry in group["items"] if entry["mark"] is not None]
        group["reported_sites"] = len({_site_label(entry) for entry in marked})
        group["reported_changed"] = any(entry["rep"] == "changed" for entry in marked)
        group["reported_at"] = max((entry["mark"]["reported_at"] for entry in marked), default="")
        group["version_counts"] = sorted(
            ((v, n) for v, n in group["versions"].items() if v), key=lambda pair: (-pair[1], pair[0]))
        group["undisclosed"] = group["versions"].get("", 0)
        group["site_rows"] = [
            (site, version, entry["confidence_label"], entry["confidence_class"])
            for site, entries in sorted(group["sites"].items(), key=lambda pair: pair[0].casefold())
            for version, entry in entries
        ]
        result.append(group)
    result.sort(key=lambda g: (-g["site_count"], g["name"].casefold()))
    return result


def _severity_level(score):
    if score is None:
        return "unknown"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "none"


def _cve_cell(item, summary, unavailable):
    """What the Known CVEs column shows for one product."""
    if item["status"] != "monitored":
        return {"state": "unmonitored"}
    if unavailable:
        return {"state": "unavailable"}
    found = [(asset_id, *summary[asset_id]) for asset_id in item["covered_ids"] if asset_id in summary]
    if not found:
        return {"state": "clear"}
    scores = [score for _, _, score in found if score is not None]
    top = max(scores) if scores else None
    return {"state": "found", "count": sum(count for _, count, _ in found), "score": top,
            "level": _severity_level(top), "asset": found[0][0]}


def _merge_cve(cells):
    """The highest severity across the sites of one technology."""
    cells = [cell for cell in cells if cell["state"] != "unmonitored"]
    if not cells:
        return {"state": "unmonitored"}
    if any(cell["state"] == "unavailable" for cell in cells):
        return {"state": "unavailable"}
    found = [cell for cell in cells if cell["state"] == "found"]
    if not found:
        return {"state": "clear"}
    scores = [cell["score"] for cell in found if cell["score"] is not None]
    top = max(scores) if scores else None
    return {"state": "found", "count": sum(cell["count"] for cell in found), "score": top,
            "level": _severity_level(top), "asset": found[0]["asset"]}


def _snapshot_ids(rows, client):
    if not rows:
        return set()
    key = web_assets.client_key(client)
    return {record.asset_id for record in rows
            if record.client.strip() and web_assets.client_key(record.client) == key}


def _in_snapshot(item, snapshot_ids):
    """Whether the product has a row in the saved snapshot. Older review files are guessed."""
    if isinstance(item.get("inventory"), bool):
        return item["inventory"]
    return bool([v for v in item.get("versions", []) if v.strip()]) or item.get("asset_id") in snapshot_ids


def _read_managed(config, client, *, preserve_client=False):
    """The client's managed inventory as (raw bytes or None, rows). A missing file is empty."""
    directory = config.inventory_directory
    try:
        if directory.is_symlink():
            raise ValueError("inventory storage is a symbolic link")
        data = _current(directory / f"{inventory_client_key(client)}.json")
        return data, ([] if data is None else read_inventory(data, preserve_client=preserve_client))
    except (OSError, ValueError, CVEBeaconError):
        raise ConfigurationError(_INVENTORY_UNREADABLE) from None


def _client_profile(config, client):
    """The saved client details, or the details a first add will create."""
    directory = config.inventory_directory
    key = inventory_client_key(client)
    path = directory / f"{key}.client"
    if directory.is_symlink():
        raise ConfigurationError(_INVENTORY_UNREADABLE)
    if path.exists() or path.is_symlink():
        try:
            return read_profile(directory, key)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, CVEBeaconError):
            raise ConfigurationError(_INVENTORY_UNREADABLE) from None
    return {"name": normalized_client(client), "notes": "", "contact": ""}


def _host(entry):
    try:
        host = entry.get("hostname") or urlsplit(entry.get("url", "")).hostname or ""
        host.encode("utf-8")
        return host
    except (ValueError, TypeError, AttributeError):
        return ""


def _editable_entry(entry):
    try:
        json.dumps(entry, ensure_ascii=False).encode("utf-8")
    except UnicodeError:
        # Reject corrupt display values without disabling removal/recovery.
        return {"hostname": "Invalid saved asset; remove it or review the local file"}
    result = dict(entry)
    if "url" in entry:
        try:
            parsed = urlsplit(entry["url"])
            result.update(hostname=parsed.hostname or "", scheme=parsed.scheme,
                          port=parsed.port or (443 if parsed.scheme == "https" else 80),
                          path=parsed.path or "/")
        except (ValueError, TypeError, AttributeError):
            pass  # Keep recovery controls available for malformed local entries.
    return result


def _audit_detail(client, host, *, stored=False):
    detail = json.dumps({"client": client, "host": host}, ensure_ascii=False)
    if stored and len(detail) > 1024:
        # Corrupt saved hosts must remain removable without unbounded audit data.
        detail = json.dumps({"client": client, "host": "invalid"}, ensure_ascii=False)
    return detail


def _review_metadata(detail, client):
    if not isinstance(detail, dict) or detail.get("client") != client:
        raise ValueError("invalid review")
    products, reviews, run = detail.get("products", []), detail.get("reviews", []), detail.get("run")
    if (not isinstance(products, list) or not isinstance(reviews, list)
            or any(not isinstance(item, dict) for item in products + reviews)
            or (run is not None and not isinstance(run, dict))):
        raise ValueError("invalid review metadata")
    def text(value):
        return (isinstance(value, str) and len(value) <= 8192
                and not any(0xD800 <= ord(char) <= 0xDFFF for char in value))
    def valid_npm_package(value):
        if not isinstance(value, str) or len(value) > 214:
            return False
        if value.startswith("@"):
            parts = value[1:].split("/", 1)
            return (len(parts) == 2 and bool(parts[0]) and bool(parts[1])
                    and _NPM_SCOPE_PART.fullmatch(parts[0]) is not None
                    and _NPM_NAME_PART.fullmatch(parts[1]) is not None)
        return _NPM_NAME_PART.fullmatch(value) is not None
    for item in products + reviews:
        for field in ("asset_id", "hostname", "vendor", "product", "category", "confidence",
                      "reason", "detail", "name", "ecosystem", "package", "cpe"):
            if field in item and not text(item[field]):
                raise ValueError("invalid review text")
        if "name" in item and (not item["name"].strip() or len(item["name"]) > 256):
            raise ValueError("invalid review name")
        if ("ecosystem" in item) != ("package" in item):
            raise ValueError("incomplete review package identity")
        if "package" in item and (item.get("ecosystem") != "npm"
                or not valid_npm_package(item["package"])):
            raise ValueError("invalid review package identity")
        for field in ("versions", "evidence_types", "implied_by"):
            if field in item and (not isinstance(item[field], list)
                                  or any(not text(value) for value in item[field])):
                raise ValueError("invalid review list")
        if "categories" in item:
            categories = item["categories"]
            if (not isinstance(categories, list) or len(categories) > 64
                    or any(not text(value) or value not in _WEB_PRODUCT_CATEGORIES
                           for value in categories)):
                raise ValueError("invalid review categories")
        if "evidence_types" in item and any(kind not in _EVIDENCE_KINDS
                                             for kind in item["evidence_types"]):
            raise ValueError("invalid review evidence kind")
        if "evidence" in item:
            evidence = item["evidence"]
            if not isinstance(evidence, list) or len(evidence) > 20:
                raise ValueError("invalid review evidence")
            for entry in evidence:
                if (not isinstance(entry, dict)
                        or any(field not in entry or not text(entry[field])
                               for field in ("kind", "source", "excerpt"))
                        or len(entry["excerpt"]) > 160
                        or entry["kind"] not in _EVIDENCE_KINDS):
                    raise ValueError("invalid review evidence text")
                if ("sha256" in entry) != ("bytes" in entry):
                    raise ValueError("incomplete review file metadata")
                if ("sha256" in entry and (not isinstance(entry["sha256"], str)
                        or re.fullmatch(r"[0-9a-fA-F]{64}", entry["sha256"]) is None)):
                    raise ValueError("invalid review evidence hash")
                if "bytes" in entry and (type(entry["bytes"]) is not int or entry["bytes"] < 0):
                    raise ValueError("invalid review evidence size")
        for field in ("status", "retry_after", "redirects_followed"):
            if field in item and (type(item[field]) is not int or item[field] < 0):
                raise ValueError("invalid review number")
        if "redirect_target" in item:
            target = item["redirect_target"]
            if (not isinstance(target, dict) or set(target) != {"scheme", "host", "port"}
                    or target.get("scheme") not in {"http", "https"}
                    or not text(target.get("host")) or type(target.get("port")) is not int
                    or not 1 <= target["port"] <= 65535):
                raise ValueError("invalid redirect target")
    if run is not None:
        for field in ("started_at", "ended_at", "status"):
            if field in run and not text(run[field]):
                raise ValueError("invalid run text")
        if "status" in run and run["status"] not in _RUN_STATUSES:
            raise ValueError("invalid run status")
        for field in ("asset_count", "fetched_count", "products_recognized", "products_with_version",
                      "resources_fetched", "resources_skipped", "fingerprint_technologies",
                      "fingerprint_stopped", "analysis_stopped"):
            if field in run and (type(run[field]) is not int or run[field] < 0):
                raise ValueError("invalid run count")
        if (run.get("asset_count", 0) < run.get("fetched_count", 0)
                or run.get("products_recognized", 0) < run.get("products_with_version", 0)):
            raise ValueError("invalid run counts")
        if "saved_snapshot_generated_at" in run and not text(run["saved_snapshot_generated_at"]):
            raise ValueError("invalid saved snapshot timestamp")
        for field in ("snapshot_updated", "review_truncated", "fingerprint_error"):
            if field in run and type(run[field]) is not bool:
                raise ValueError("invalid run flag")
        if "request_count" in run and (type(run["request_count"]) is not int or run["request_count"] < 0):
            raise ValueError("invalid run request count")
        if "resources_skipped_by_reason" in run:
            skipped = run["resources_skipped_by_reason"]
            if (not isinstance(skipped, dict) or len(skipped) > 100
                    or "resources_skipped" not in run
                    or any(not text(reason) or not reason or len(reason) > 128
                           or type(count) is not int or count < 0
                           for reason, count in skipped.items())
                    or sum(skipped.values()) != run["resources_skipped"]):
                raise ValueError("invalid resource skip counts")
        if "duration_seconds" in run and (type(run["duration_seconds"]) not in (int, float)
                or (type(run["duration_seconds"]) is float and not math.isfinite(run["duration_seconds"]))
                or run["duration_seconds"] < 0):
            raise ValueError("invalid run duration")
    return products, reviews, run


def _inventory_clients(config):
    """Use the names shown on Clients, including dashboard-managed profiles."""
    names = {}
    if config.managed_inventory:
        try:
            for profile in profiles(config.inventory_directory, config.watch.users_database):
                name = normalized_client(profile["name"])
                names.setdefault(inventory_client_key(name), name)
        except (CVEBeaconError, OSError, ValueError):
            pass
    try:
        _, summaries, _ = client_page(config.database_path, limit=1000)
        for summary in summaries:
            name = normalized_client(summary.name)
            names.setdefault(inventory_client_key(name), name)
    except (CVEBeaconError, OSError, ValueError):
        pass
    return sorted(names.values(), key=str.casefold)


def _canonical_client(config, value, candidates=None):
    # An allowlist saved before names were matched to inventory clients stays
    # reachable under the label it was saved with; never fork it into a new file.
    try:
        existing, _ = paths(config, value)
        if existing.exists() or existing.is_symlink():
            return value
    except (CVEBeaconError, OSError, ValueError):
        pass
    name = normalized_client(value)
    wanted = inventory_client_key(name)
    for candidate in candidates if candidates is not None else _inventory_clients(config):
        if inventory_client_key(candidate) == wanted:
            return candidate
    scanned = client_name(config.database_path, name)
    return normalized_client(scanned) if scanned is not None else name


def _redirect_target_urls(target):
    if not isinstance(target, dict):
        return None, None
    scheme, host, port = target.get("scheme"), target.get("host"), target.get("port")
    if (scheme not in {"http", "https"} or not isinstance(host, str)
            or type(port) is not int or not 1 <= port <= 65535):
        return None, None
    if not host or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:" for character in host):
        return None, None
    authority = f"[{host}]" if ":" in host else host
    display = f"{scheme}://{authority}:{port}"
    return display, display + "/"


def _prefill_entry(value):
    if not value:
        return {}
    try:
        parsed = urlsplit(value)
        scheme, hostname = parsed.scheme.casefold(), parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        if (scheme not in {"http", "https"} or not hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"} or not 1 <= port <= 65535):
            raise ValueError("invalid prefill URL")
        return {"hostname": hostname, "scheme": scheme, "port": port, "path": "/"}
    except (TypeError, ValueError):
        raise ValueError("invalid prefill URL") from None


def create_web_blueprint(config):
    blueprint = Blueprint("web", __name__, url_prefix="/web-assets")

    def manager():
        return current_app.extensions["dashboard_jobs"]

    def read_marks(output, client):
        """The client's report marks; a missing file is FileNotFoundError, a bad one ValueError."""
        return web_reported.parse(read_bytes(web_reported.marks_path(output)), web_assets.client_key, client)

    def render(client="", *, page="overview", error=None, status=200, prefill_url="", added=0, marked=None,
               withdrawn=None, sync_notice=None):
        clients, document, version = [], None, "new"
        products, reviews, run, snapshot, snapshot_rows = [], [], None, None, []
        last_job, truncated, removed = None, False, False
        site_rows, site_summary = [], {}
        inventory_clients = _inventory_clients(config)
        prefill_entry = _prefill_entry(prefill_url) if prefill_url else {}
        versions_hidden = False
        available = web_assets.companion_available()
        sync_settings, sync_view, sync_warning = None, None, None
        now = datetime.now(timezone.utc)
        try:
            assets_dir, _ = directories(config)
            for path in sorted(assets_dir.glob("*.json"))[:1000]:
                try:
                    item = decode_json(read_bytes(path))
                    name = client_label(item["client"])
                    if paths(config, name)[0] == path:
                        clients.append(name)
                except (CVEBeaconError, ValueError, OSError, KeyError, TypeError):
                    error = error or "A saved allowlist could not be read; review the local file"
            if client:
                path, output = paths(config, client)
                document, version = read_allowlist(path, client)
                client = document["client"]
                try:
                    sync_settings = sync.mode(config, path)
                    if page == "overview" and status == 200 and config.managed_inventory:
                        sync_view = sync.inspect(config, client)
                except ConfigurationError as exc:
                    sync_warning = str(exc)
                except (CVEBeaconError, OSError, ValueError):
                    sync_warning = sync.WRITE_WARNING
                document = {**document, "assets": [_editable_entry(row) for row in document["assets"]]}
                ca = document.get("ca_bundle", "")
                if not isinstance(ca, str) or any(0xD800 <= ord(char) <= 0xDFFF for char in ca):
                    document["ca_bundle"] = ""
                site_rows = [
                    {"entry": entry, "index": index, "url": _site_url(entry),
                     "expiry": _expiry_state(entry.get("expires_at"), now)}
                    for index, entry in enumerate(document["assets"])
                ]
                site_summary = {
                    "redirects": sum(1 for entry in document["assets"]
                                     if entry.get("allow_redirects", True)),
                    "private": sum(1 for entry in document["assets"]
                                   if entry.get("allow_private_address", False)),
                    "soon": sum(1 for row in site_rows if row["expiry"] == "soon"),
                    "expired": sum(1 for row in site_rows if row["expiry"] == "expired"),
                }
                removed = output.with_name(output.name + ".removed").exists()
                if output.exists() or output.is_symlink():
                    try:
                        snapshot_rows, snapshot = read_web_snapshot(output, preserve_client=True)
                    except (CVEBeaconError, ValueError, OSError):
                        error = error or "The saved snapshot is invalid; it will be skipped by scans"
                review_path = output.with_name(output.name + ".review.json")
                if review_path.exists() or review_path.is_symlink():
                    detail = decode_json(read_bytes(review_path))
                    products, reviews, run = _review_metadata(detail, client)
                    truncated = len(products) > 1000 or len(reviews) > 1000
                    versions_hidden = any(item.get("reason") == "version-unknown" for item in reviews)
                    for item in reviews:
                        display, target_url = _redirect_target_urls(item.get("redirect_target"))
                        if display is not None:
                            item["redirect_display"] = display
                            item["redirect_url"] = target_url
                    if run is not None:
                        run = dict(run)
                        failed_assets = {item.get("asset_id") for item in reviews
                                         if item.get("reason") in _FETCH_FAILURE_REASONS and item.get("asset_id")}
                        asset_count = len(document["assets"])
                        run.setdefault("asset_count", asset_count)
                        run.setdefault("fetched_count", max(0, asset_count - len(failed_assets)))
                        run.setdefault("products_recognized", len(products))
                        run.setdefault("products_with_version", sum(bool(item.get("versions")) for item in products))
                        run.setdefault("saved_snapshot_generated_at", snapshot["generated_at"] if snapshot else "")
                        run.setdefault("snapshot_updated", False)
                    products, reviews = products[:1000], reviews[:1000]
                last_job = next((job for job in manager().store.recent(200)
                                 if job.operation in {"web-detect", "web-plan"}
                                 and "web-detect" in job.argv
                                 and (job.argv[job.argv.index("web-detect") + 1:][:1] == (client,)
                                      or (client.startswith("-") and job.argv[-2:] == ("--", client)))), None)
        except (CVEBeaconError, ValueError, OSError, TypeError, KeyError):
            error = error or "Web asset storage could not be read; review the local files"
        evidence_words = {
            "header": "header", "cookie": "cookie", "meta": "meta",
            "html": "markup", "url": "link", "script": "script",
            "style": "stylesheet", "manifest": "manifest", "robots": "robots.txt",
        }
        snapshot_inventory_ids = _snapshot_ids(snapshot_rows, client)
        for item in products:
            _decorate_product(item)
            # Newer review files record whether a row was created; older ones are guessed.
            item["in_inventory"] = _in_snapshot(item, snapshot_inventory_ids)
            labels = [evidence_words[kind] for kind in item.get("evidence_types", [])
                      if kind in evidence_words]
            labels.extend(f"Inferred from {source}" for source in item.get("implied_by", []))
            if not labels and "implied" in item.get("evidence_types", []):
                labels.append("Inferred")
            item["evidence_labels"] = list(dict.fromkeys(labels))
        marks, reported_warning = {}, None
        if client and products:
            try:
                marks = read_marks(paths(config, client)[1], client)
            except FileNotFoundError:
                pass
            except (CVEBeaconError, ValueError, OSError):
                reported_warning = web_reported.INVALID
        snapshots_on = config.inventory is not None and config.inventory.web_snapshots
        managed_warning = None
        managed_assets = []
        if client and products and config.managed_inventory:
            try:
                managed_assets = _read_managed(config, client)[1]
            except ConfigurationError:
                managed_warning = ("The inventory saved for this client could not be read, so none of "
                                   "these products are shown as monitored. Check it on the client's Inventory page.")
        managed = actions.ManagedIndex(managed_assets)
        for item in products:
            item["status"], item["covered_ids"] = actions.classify(
                item, snapshots_on=snapshots_on, snapshot_ids=snapshot_inventory_ids, managed=managed)
            item["status_label"] = actions.STATUS_LABELS[item["status"]]
            item["status_badge"] = actions.STATUS_BADGES[item["status"]]
            item["pickable"] = bool(item.get("asset_id")) and item["status"] not in {"monitored", "service"}
            distinct = list(dict.fromkeys(actions.detected_versions(item)))
            item["prefill"] = distinct[0] if len(distinct) == 1 else ""
        covered = sorted({asset_id for item in products for asset_id in item["covered_ids"]})
        findings, findings_unavailable = {}, False
        if covered:
            try:
                findings = StateStore(config.database_path).finding_summary(covered)
            except (StateError, OSError):
                findings_unavailable = True
        for item in products:
            item["cve"] = _cve_cell(item, findings, findings_unavailable)
            item["rep"] = _report_state(item, marks)
        products.sort(key=lambda item: (
            item.get("hostname", "").casefold(), item.get("category", "").casefold(),
            item["display_name"].casefold(),
        ))
        categories = sorted({c for item in products for c in item["category_labels"]}, key=str.casefold)
        site_names = sorted({_site_label(item) for item in products}, key=str.casefold)
        flt = _filter_args(request.args, set(categories), set(site_names))
        chips = dict(high=0, medium=0, low=0, with_version=0, without_version=0,
                     monitored=0, ready=0, review=0, service=0, reported=0, changed=0, **{"not": 0})
        matched, technologies, chip_sites = [], set(), set()
        for item in products:
            chip_sites.add(_site_label(item))
            technologies.add(item["display_name"].casefold())
            if item["confidence_class"] in chips:
                chips[item["confidence_class"]] += 1
            chips["with_version" if item["has_version"] else "without_version"] += 1
            chips[item["status"]] += 1
            chips[item["rep"]] += 1
            if _matches(item, flt):
                matched.append(item)
        chips.update(technologies=len(technologies), sites=len(chip_sites))
        flt["active"] = _filters_active(flt)
        can_add = bool(g.accounts and config.managed_inventory and {"view", "manage_inventory"} <= g.permissions)
        can_report = bool(g.accounts and "report" in g.permissions)
        ready_total = chips["ready"]
        ready_shown = len({item["asset_id"] for item in matched
                           if item["status"] == "ready" and item.get("asset_id")})
        quick = []
        for key, levels, label in (
                ("high", ("high",), "Add all High confidence ready products"),
                ("not-low", ("high", "medium"), "Add all except Low confidence")):
            count = len({item["asset_id"] for item in products
                         if item["status"] == "ready" and item.get("asset_id")
                         and item["confidence_class"] in levels})
            if count:
                quick.append({"key": key, "levels": levels, "label": label, "count": count})
        tech_rows, site_groups = [], []
        if flt["view"] == "tech":
            tech_rows = _technology_rows(matched)
            list_total = len(tech_rows)
            tech_rows = tech_rows[:_ROW_LIMIT]
        else:
            list_total = len(matched)
            for number, item in enumerate(matched[:_ROW_LIMIT], 1):
                item["row_no"] = number
                if not site_groups or site_groups[-1][0] != _site_label(item):
                    site_groups.append((_site_label(item), []))
                site_groups[-1][1].append(item)
        sync_changes = [] if sync_view is None else sorted(
            ((identity, change) for identity, change in sync_view.proposals.items()
             if sync_settings.mode == "review" or change.kind == "remove"),
            key=lambda item: (item[1].product.casefold(), item[1].site.casefold(), item[0]),
        )
        sync_pages = max(1, (len(sync_changes) + _ROW_LIMIT - 1) // _ROW_LIMIT)
        sync_page = min(_sync_page_number(request.args), sync_pages)
        sync_start = (sync_page - 1) * _ROW_LIMIT
        site_count = len(document["assets"]) if document else 0
        show_changes = bool(document and config.managed_inventory and sync_settings
                            and sync_settings.mode in {"review", "auto"})
        change_counts = {"add": 0, "update": 0, "remove": 0}
        for _, change in sync_changes:
            change_counts[change.kind] = change_counts.get(change.kind, 0) + 1
        run_label, run_badge = _RUN_STATE_LABELS.get((run or {}).get("status"), ("Not run yet", "neutral"))
        last_run_short = _short_date(run.get("started_at")) if run else ""
        last_run_help = (
            f"{run.get('fetched_count', 0)} of {run.get('asset_count', site_count)} sites fetched"
            if run else "No detection run yet")
        run_tone = ""
        if run:
            run_tone = "success" if run.get("status") == "success" else "warning"
            if _run_is_stale(run.get("started_at"), now):
                run_tone = "warning"
        can_manage = bool(g.accounts and "manage_web_assets" in g.permissions)
        section_primary_action = (
            "run" if page in {"overview", "detection"} and client and document and document["assets"]
            and g.accounts and "run" in g.permissions and available else "")
        section_primary_url, section_primary_label = "", ""
        if client and can_manage:
            section_primary_url = url_for("web.sites", client=client, _anchor="add-asset")
            section_primary_label = "Add site"
        if section_primary_action:
            section_primary_label = ("Detect web technologies" if page == "detection" else "Run detection")
        if page == "sites":
            section_description = ("Add, change and remove the sites this client has authorised you to check."
                                   if client else "Record the websites a client has authorised you to check.")
        elif page == "detection":
            section_description = (
                "Run detection, check what the last run saved and review entries that need a person."
                if client else "Run detection for a client and review saved detection entries.")
        elif client:
            section_description = (
                f"{site_count} authorised site{'' if site_count == 1 else 's'}, "
                f"{len(products)} detected product{'' if len(products) == 1 else 's'}, "
                f"{'last checked ' + last_run_short if run else 'no detection run yet'}.")
        else:
            section_description = "Record the websites a client has authorised you to check."
        next_steps = []
        if client and document:
            if not site_count:
                next_steps.append({
                    "state": "todo", "title": "Add the first authorised site",
                    "detail": "No sites are authorised for this client yet.",
                    "url": url_for("web.sites", client=client, _anchor="add-asset"),
                    "action_label": "Add site"})
            else:
                if not run:
                    next_steps.append({
                        "state": "todo", "title": "Run the first detection",
                        "detail": "Detection is manual and has not run for this client.",
                        "url": url_for("web.detection", client=client),
                        "action_label": "Run detection"})
                if reviews:
                    next_steps.append({
                        "state": "attention",
                        "title": f"Review {len(reviews)} detection entr{'y' if len(reviews) == 1 else 'ies'}",
                        "detail": "Saved results include entries that need a person to decide.",
                        "url": url_for("web.detection", client=client),
                        "action_label": "Review"})
                if chips["ready"]:
                    next_steps.append({
                        "state": "todo",
                        "title": f"Add {chips['ready']} product{'' if chips['ready'] == 1 else 's'} to inventory",
                        "detail": "Ready products can be added to this client's inventory for CVE checks.",
                        "url": url_for("web.index", client=client, _anchor="detected-products"),
                        "action_label": "Open"})
                if show_changes and sync_changes:
                    next_steps.append({
                        "state": "todo",
                        "title": f"Review {len(sync_changes)} inventory change{'' if len(sync_changes) == 1 else 's'}",
                        "detail": "Detection proposes additions, updates or removals in the inventory.",
                        "url": url_for("web.index", client=client, _anchor="inventory-sync"),
                        "action_label": "Open"})
            if not next_steps:
                next_steps.append({
                    "state": "done", "title": "Open the technology report",
                    "detail": "No outstanding work for this client.",
                    "url": url_for("tech_report.index", client=client),
                    "action_label": "Open report"})
        next_steps = next_steps[:3]
        tab_counts = {
            "sites": site_count,
            "detection": len(reviews),
            "products": chips["ready"],
            "changes": len(sync_changes) if show_changes else 0,
        }
        has_client_inventory = bool(
            client and config.managed_inventory
            and (config.inventory_directory / f"{inventory_client_key(client)}.client").is_file())
        template = {"sites": "web_assets_sites.html", "detection": "web_assets_detection.html"}.get(
            page, "web_assets.html")
        return render_template(template, clients=sorted(clients, key=str.casefold),
                               inventory_clients=inventory_clients, client=client,
                               document=document, version=version, products=products, reviews=reviews,
                               run=run, snapshot=snapshot, available=available, notice=COMPANION_NOTICE,
                               last_job=last_job, truncated=truncated, removed=removed, error=error,
                               versions_hidden=versions_hidden, reason_labels=_REASON_LABELS,
                               prefill_entry=prefill_entry, prefill_url=prefill_url, flt=flt, chips=chips,
                               categories=categories, site_names=site_names, matched_count=len(matched),
                               total_products=len(products), tech_rows=tech_rows, site_groups=site_groups,
                               row_limit=_ROW_LIMIT, list_total=list_total, confidence_choices=_CONFIDENCE_CHOICES,
                               can_add=can_add, can_report=can_report, ready_shown=ready_shown,
                               quick_actions=quick, reported_warning=reported_warning,
                               marked=marked, withdrawn=withdrawn, managed_enabled=config.managed_inventory,
                               ready_total=ready_total, managed_warning=managed_warning,
                               sync_settings=sync_settings, sync_view=sync_view,
                               sync_changes=sync_changes[sync_start:sync_start + _ROW_LIMIT],
                               sync_page=sync_page, sync_pages=sync_pages,
                               sync_warning=sync_warning, sync_choices=sync.MODE_CHOICES,
                               sync_coverage_warning=sync.COVERAGE_WARNING,
                               sync_removal_choices=sync.REMOVAL_CHOICES,
                               sync_notice=sync_notice, sync_waiting=sync.WAITING,
                               added=added, client_key=inventory_client_key(client) if client else "",
                               status_labels=actions.STATUS_LABELS, status_badges=actions.STATUS_BADGES,
                               page=page, section_page=page, site_rows=site_rows, site_count=site_count,
                               site_summary=site_summary, tab_counts=tab_counts, show_changes=show_changes,
                               next_steps=next_steps, run_label=run_label, run_badge=run_badge,
                               run_tone=run_tone, last_run_short=last_run_short,
                               last_run_help=last_run_help, change_counts=change_counts,
                               has_client_inventory=has_client_inventory,
                               section_description=section_description,
                               section_primary_action=section_primary_action,
                               section_primary_url=section_primary_url,
                               section_primary_label=section_primary_label), status

    @blueprint.get("")
    @requires("view")
    def index():
        label = _text(request.args, "client", limit=256)
        prefill_url = _text(request.args, "prefill_url", limit=2048)
        def count(name):
            value = _text(request.args, name, limit=6)
            return int(value) if value.isascii() and value.isdecimal() else None
        try:
            client = _canonical_client(config, client_label(label)) if label else ""
        except (ConfigurationError, ValueError):
            abort(400)
        imported = count("imported")
        if client and imported:
            return redirect(url_for("web.sites", client=client, imported=imported), code=302)
        if client and prefill_url:
            return redirect(url_for("web.sites", client=client, prefill_url=prefill_url,
                                    _anchor="add-asset"), code=302)
        return render(client, prefill_url=prefill_url, added=count("added") or 0,
                      marked=count("marked"), withdrawn=count("withdrawn"),
                      sync_notice=_SYNC_MESSAGES.get(_text(request.args, "sync_result", limit=20)))

    @blueprint.get("/overview")
    @requires("view")
    def overview():
        label = _text(request.args, "client", limit=256)
        try:
            client = _canonical_client(config, client_label(label)) if label else ""
        except (ConfigurationError, ValueError):
            abort(400)
        params = _passthrough_query(request.args)
        params.pop("client", None)
        return redirect(url_for("web.index", client=client, **params) if client
                        else url_for("web.index", **params), code=302)

    @blueprint.get("/sites")
    @requires("view")
    def sites():
        label = _text(request.args, "client", limit=256)
        prefill_url = _text(request.args, "prefill_url", limit=2048)
        try:
            return render(_canonical_client(config, client_label(label)) if label else "",
                          page="sites", prefill_url=prefill_url)
        except (ConfigurationError, ValueError):
            abort(400)

    @blueprint.get("/detection")
    @requires("view")
    def detection():
        label = _text(request.args, "client", limit=256)
        try:
            return render(_canonical_client(config, client_label(label)) if label else "",
                          page="detection")
        except (ConfigurationError, ValueError):
            abort(400)

    @blueprint.post("/save")
    @requires("manage_web_assets")
    def save():
        require_accounts()
        try:
            client = client_label(_canonical_client(
                config, _text(request.form, "client", required=True)))
        except ConfigurationError:
            abort(400)
        action = _text(request.form, "action", required=True)
        if action not in {"add", "change", "remove", "remove-all"}:
            abort(400)
        lock = OperationLock(config, "web-assets")
        if not lock.acquire():
            return render(client, page="sites", error=str(RunInProgress(lock.holder)), status=409)
        try:
            extra_changes = []
            path, output = paths(config, client)
            current, version = read_allowlist(path, client)
            client = current["client"]
            if _text(request.form, "version", required=True) != version:
                raise ConfigurationError("This allowlist changed; reload before saving")
            candidate = deepcopy(current)
            index = len(candidate["assets"])
            if action not in {"add", "remove-all"}:
                try:
                    index = int(_text(request.form, "index", required=True, limit=5))
                except ValueError:
                    abort(400)
                if not 0 <= index < len(candidate["assets"]):
                    abort(400)
            if action == "remove-all":
                if _text(request.form, "confirm") != "yes":
                    abort(400)
                candidate["assets"] = []
                host = ""
            elif action == "remove":
                entry = candidate["assets"].pop(index)
                host = _host(entry)
            else:
                if _text(request.form, "attest") != "yes":
                    raise ConfigurationError("Attest authorisation before saving this asset")
                try:
                    port = int(_text(request.form, "port", required=True, limit=5))
                    redirects = int(_text(request.form, "max_redirects", required=True, limit=2))
                except ValueError:
                    abort(400)
                entry = {"hostname": _text(request.form, "hostname", required=True),
                         "scheme": _text(request.form, "scheme", required=True, limit=5),
                         "port": port, "path": _text(request.form, "path", required=True, limit=2048),
                         "allow_redirects": _text(request.form, "allow_redirects") == "yes",
                         "max_redirects": redirects,
                         "allow_private_address": _text(request.form, "allow_private_address") == "yes",
                         "authorized_by": g.user.username,
                         "authorized_at": datetime.now(timezone.utc).isoformat()}
                expiry = _text(request.form, "expires_at", limit=64)
                if expiry:
                    entry["expires_at"] = expiry
                host = entry["hostname"]
                if action == "add":
                    candidate["assets"].append(entry)
                else:
                    candidate["assets"][index] = entry
                ca = _text(request.form, "ca_bundle", limit=2048)
                if ca != current.get("ca_bundle", ""):
                    if not g.user.is_admin:
                        abort(403)
                    if ca:
                        candidate["ca_bundle"] = ca
                    else:
                        candidate.pop("ca_bundle", None)
                    for position, row in enumerate(candidate["assets"]):
                        if position != index:
                            extra_changes.append(_audit_detail(client, _host(row), stored=True))
                        row.update(authorized_by=g.user.username, authorized_at=entry["authorized_at"])
            validate_allowlist(config, path, candidate)
            details = [_audit_detail(client, _host(row), stored=True)
                       for row in current["assets"]] if action == "remove-all" else [
                           _audit_detail(client, host, stored=action == "remove")]
            event = "web_asset_" + ("remove" if action == "remove-all" else action)
            users = current_app.extensions["dashboard_users"]
            targets = [path]
            marker = output.with_name(output.name + ".removed")
            if action == "remove-all":
                targets += [output, output.with_name(output.name + ".manifest.json"),
                            output.with_name(output.name + ".review.json"),
                            web_reported.marks_path(output), marker]
            elif action == "remove":
                targets.append(marker)
            if action == "remove-all":
                for target in targets[1:]:
                    try:
                        info = target.lstat()
                    except FileNotFoundError:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        raise ConfigurationError(
                            "A saved result path is a directory; move it out of "
                            "web-inventory and retry removal"
                        )
            originals = {}
            for target in targets:
                try:
                    originals[target] = read_bytes(target) if target.exists() or target.is_symlink() else None
                except (CVEBeaconError, ValueError, OSError):
                    if action != "remove-all" or target == path:
                        raise
                    # Bad results must not block recovery. Retire them without
                    # keeping an unsafe/unbounded copy to restore on rollback.
            writing = False
            try:
                # Account writers cannot revoke the proof or authority between
                # this check, the audit and the final filesystem replacement.
                with users.transaction() as db:
                    actor = users.require_permission_in(db, g.entry.proof, "manage_web_assets")
                    if candidate.get("ca_bundle", "") != current.get("ca_bundle", "") and not actor.is_admin:
                        abort(403)
                    stamp = datetime.now(timezone.utc).isoformat()
                    def audit(name, detail):
                        if len(detail) > 1024 or any(ord(char) < 32 for char in detail):
                            raise ConfigurationError("invalid audit detail")
                        users._append_audit(db, name + ":" + detail, actor.username, stamp, actor=actor.username)
                    for detail in details:
                        audit(event, detail)
                    for detail in extra_changes:
                        audit("web_asset_change", detail)
                    if action == "change" and _host(current["assets"][index]) != host:
                        audit("web_asset_replaced", _audit_detail(
                            client, _host(current["assets"][index]), stored=True))
                    if action == "remove-all":
                        audit("web_snapshot_remove", json.dumps({"client": client}, ensure_ascii=False))
                    writing = True
                    save_allowlist(path, candidate)
                    if action == "remove-all":
                        for target in targets[1:]:
                            try:
                                target.unlink(missing_ok=True)
                            except OSError as exc:
                                raise ConfigurationError(
                                    "Saved results could not be removed; close open readers, "
                                    "check file permissions and retry"
                                ) from exc
                    elif action == "remove":
                        save_allowlist(marker, {"client": client})
            except BaseException:
                if writing:
                    for target, data in originals.items():
                        if data is None:
                            target.unlink(missing_ok=True)
                        else:
                            web_assets.replace_bytes(target, data)
                raise
        except (CVEBeaconError, ValueError, OSError) as exc:
            message = (str(exc) if isinstance(exc, (ConfigurationError, PublicationTimeout))
                       else "The web allowlist could not be saved")
            return render(client, page="sites", error=message, status=400)
        finally:
            lock.release()
        return redirect(url_for("web.sites", client=client), code=303)

    def saved_products(client):
        """The client's detected products, re-read from the saved review (never from the form)."""
        path, output = paths(config, client)
        client = read_allowlist(path, client)[0]["client"]
        review_path = output.with_name(output.name + ".review.json")
        if not (review_path.exists() or review_path.is_symlink()):
            return [], set()
        snapshot_rows = []
        if output.exists() or output.is_symlink():
            try:
                snapshot_rows = read_web_snapshot(output, preserve_client=True)[0]
            except (CVEBeaconError, ValueError, OSError):
                pass
        try:
            products = _review_metadata(decode_json(read_bytes(review_path)), client)[0][:1000]
        except (CVEBeaconError, ValueError, OSError):
            raise ConfigurationError("The saved detection results could not be read.") from None
        snapshot_ids = _snapshot_ids(snapshot_rows, client)
        for item in products:
            item["in_inventory"] = _in_snapshot(item, snapshot_ids)
        return products, snapshot_ids

    def filtered_picks(client, products, managed, snapshots_on, snapshot_ids):
        """Asset IDs of the ready products that pass the posted filters, from saved data only."""
        for item in products:
            _decorate_product(item)
            item["status"] = actions.classify(
                item, snapshots_on=snapshots_on, snapshot_ids=snapshot_ids, managed=managed)[0]
        try:
            marks = read_marks(paths(config, client)[1], client)
        except FileNotFoundError:
            marks = {}
        except (CVEBeaconError, ValueError, OSError):
            marks = {}  # The page shows no marks for an unreadable file; the action agrees.
        for item in products:
            item["rep"] = _report_state(item, marks)
        categories = {c for item in products for c in item["category_labels"]}
        sites = {_site_label(item) for item in products}
        flt = _filter_args(request.form, categories, sites)
        picks = list(dict.fromkeys(
            item["asset_id"] for item in products
            if item.get("asset_id") and item["status"] == "ready" and _matches(item, flt)))
        return picks, _filter_text(flt)

    def plan(client):
        """Rebuild everything to add from saved data plus the asset IDs and versions typed."""
        mode = _text(request.form, "action", required=True)
        if mode not in {"selected", "all", "filtered"}:
            abort(400)
        picks = request.form.getlist("pick")
        if len(picks) > actions.MAX_PICKS:
            raise ConfigurationError(
                "Too many products were selected at once. Select at most 2,000, or use Add all ready products.")
        if mode == "selected" and not picks:
            raise ConfigurationError("Select at least one product to add.")
        versions = {pick: request.form.get("v-" + pick, "") for pick in set(picks)}
        products, snapshot_ids = saved_products(client)
        profile = _client_profile(config, client)
        data, assets = _read_managed(config, profile["name"])
        snapshots_on = config.inventory is not None and config.inventory.web_snapshots
        managed = actions.ManagedIndex(assets)
        description = ""
        if mode == "filtered":
            picks, description = filtered_picks(client, products, managed, snapshots_on, snapshot_ids)
            if not picks:
                raise ConfigurationError("No ready products match those filters.")
        rows, skipped, unknown = actions.plan_rows(
            products, picks, versions, profile["name"], snapshots_on=snapshots_on, snapshot_ids=snapshot_ids,
            managed=managed, everything=mode == "all")
        return profile, data, assets, rows, skipped, unknown, description

    def form_client():
        _changes_allowed(config)
        try:
            return client_label(_canonical_client(config, _text(request.form, "client", required=True)))
        except ConfigurationError:
            abort(400)

    def sync_add_plan(client):
        current = sync.session(config, client)
        picks = request.form.getlist("pick")
        token = _text(request.form, "sync_token", required=True, limit=64)
        if current is None or current.settings.mode != "review" or len(picks) != 1:
            raise ConfigurationError(sync.STALE)
        identity = picks[0]
        proposal = current.require(identity, token)
        if proposal.kind != "add":
            raise ConfigurationError(sync.STALE)
        return current, identity, proposal, token

    @blueprint.post("/inventory/sync")
    @requires(MANAGE)
    def inventory_sync():
        client = form_client()
        action = _text(request.form, "action", required=True, limit=20)
        if action not in {"mode", "ignore", "keep-version", "update", "remove", "keep-removal", "reconsider"}:
            abort(400)
        lock = None
        try:
            lock = inventory_lock(config)
            if action == "mode":
                path, _ = paths(config, client)
                document, _ = read_allowlist(path, client)
                sync.save_mode(config, path, document["client"],
                               _text(request.form, "mode", required=True, limit=12),
                               _text(request.form, "auto_remove", limit=12) or "default",
                               current_app.extensions["dashboard_users"], g.entry.proof)
            else:
                current = sync.session(config, client)
                if current is None:
                    raise ConfigurationError(sync.STALE)
                current.decide(_text(request.form, "asset_id", required=True, limit=64),
                               _text(request.form, "sync_token", required=True, limit=64), action)
        except PermissionError:
            abort(403)
        except ConfigurationError as exc:
            return render(client, error=str(exc), status=409)
        except (CVEBeaconError, OSError, ValueError):
            return render(client, error=sync.WRITE_WARNING, status=503)
        finally:
            if lock is not None:
                lock.release()
        sync_page = _sync_page_number(request.form)
        return redirect(url_for("web.index", client=client, sync_result=action,
                                sync_page=sync_page if sync_page > 1 else None), code=303)

    @blueprint.post("/inventory/preview")
    @requires(MANAGE)
    def inventory_preview():
        client = form_client()
        token, lock = "", None
        try:
            if request.form.get("action") == "sync-add":
                lock = inventory_lock(config)
                current, identity, proposal, token = sync_add_plan(client)
                profile, data = current.profile, current.previous
                rows = [(current.evidence.products[identity], proposal.new)]
                skipped, unknown, description = [], 0, ""
            else:
                profile, data, _, rows, skipped, unknown, description = plan(client)
        except (ConfigurationError, ValueError, OSError, StateError, InventoryValidationError) as exc:
            return render(client, error=str(exc) if isinstance(exc, ConfigurationError)
                          else "The products could not be checked. Check storage and retry.", status=400)
        finally:
            if lock is not None:
                lock.release()
        new_assets = [asset for _, asset in rows]
        return render_template(
            "web_inventory_preview.html", client=client, rows=rows, skipped=skipped, unknown=unknown,
            revision=_revision(data), digest=actions.digest(new_assets),
            new_inventory=data is None, label=profile["name"], description=description, sync_token=token), 200

    @blueprint.post("/inventory/save")
    @requires(MANAGE)
    def inventory_save():
        client = form_client()
        revision = _text(request.form, "revision", required=True, limit=64)
        digest = _text(request.form, "digest", required=True, limit=64)
        try:
            lock = inventory_lock(config)
        except ConfigurationError as exc:
            return render(client, error=str(exc), status=409)
        try:
            if request.form.get("action") == "sync-add":
                current, identity, proposal, _ = sync_add_plan(client)
                if _revision(current.previous) != revision or actions.digest([proposal.new]) != digest:
                    raise ConfigurationError(sync.STALE)
                current.commit({identity: proposal}, "web-sync-add")
                return redirect(url_for("web.index", client=client, added=1), code=303)
            profile, data, assets, rows, _, _, _ = plan(client)
            new_assets = [asset for _, asset in rows]
            if _revision(data) != revision or actions.digest(new_assets) != digest or not new_assets:
                raise ConfigurationError(
                    "The inventory or the detection results changed since you checked them. "
                    "Nothing was added. Select the products again.")
            directory = config.inventory_directory
            private_directory(directory, owner_only=True)
            seen = {asset.asset_id.casefold() for asset in assets}
            added = [asset for asset in new_assets if asset.asset_id.casefold() not in seen]
            if len(assets) + len(added) > MAX_CONTRACT_ROWS:
                raise ConfigurationError("This inventory would exceed 100,000 rows. Add fewer products.")
            path = directory / f"{inventory_client_key(profile['name'])}.json"
            _publish(config, path, profile, data, assets + added, "add")
        except (ConfigurationError, ManagedInventoryCollision) as exc:
            return render(client, error=str(exc), status=409)
        except (OSError, ValueError, StateError, InventoryValidationError):
            return render(client, error="The inventory could not be saved. Check storage and retry.", status=503)
        finally:
            lock.release()
        return redirect(url_for("web.index", client=client, added=len(added)), code=303)

    @blueprint.post("/reported")
    @requires("report")
    def reported():
        require_accounts()
        try:
            client = client_label(_canonical_client(
                config, _text(request.form, "client", required=True)))
        except ConfigurationError:
            abort(400)
        action = _text(request.form, "action", required=True)
        if action not in {"mark", "withdraw"}:
            abort(400)
        note = _text(request.form, "note", limit=web_reported.MAX_NOTE) if action == "mark" else ""
        if any(unicodedata.category(char) in {"Cf", "Cs", "Zl", "Zp"} for char in note):
            abort(400)
        picks = request.form.getlist("pick")
        if len(picks) > web_reported.MAX_PICKS:
            return render(client, error="Too many products were selected at once. Select at most 2,000.",
                          status=400)
        if not picks:
            return render(client, error="Select at least one product first.", status=400)
        lock = OperationLock(config, "web-assets")
        if not lock.acquire():
            return render(client, error=str(RunInProgress(lock.holder)), status=409)
        try:
            products, _ = saved_products(client)
            known = {item["asset_id"]: item for item in products
                     if web_reported.ASSET_ID.fullmatch(item.get("asset_id") or "")}
            chosen = [asset_id for asset_id in dict.fromkeys(picks) if asset_id in known]
            path, output = paths(config, client)
            client = read_allowlist(path, client)[0]["client"]
            target = web_reported.marks_path(output)
            try:
                marks = read_marks(output, client)
            except FileNotFoundError:
                marks = {}
            if action == "mark":
                stamp = datetime.now(timezone.utc).isoformat()
                for asset_id in chosen:
                    marks[asset_id] = {"version": web_reported.shown_version(known[asset_id]),
                                       "reported_at": stamp, "by": g.user.username[:web_reported.MAX_BY],
                                       "note": note}
                count = len(chosen)
            else:
                count = sum(marks.pop(asset_id, None) is not None for asset_id in chosen)
            if not chosen:
                raise ConfigurationError("None of the selected products are in the saved detection results.")
            if len(marks) > web_reported.MAX_MARKS:
                raise ConfigurationError("Too many report marks are saved for this client.")
            detail = json.dumps({"client": client, "action": action, "count": count,
                                 "user": g.user.username}, ensure_ascii=False)
            users = current_app.extensions["dashboard_users"]
            with users.transaction() as db:
                actor = users.require_permission_in(db, g.entry.proof, "report")
                users._append_audit(db, "web_report_" + action + ":" + detail, actor.username,
                                    datetime.now(timezone.utc).isoformat(), actor=actor.username)
                web_assets.replace_bytes(target, web_reported.encode(client, marks))
        except (CVEBeaconError, ValueError, OSError) as exc:
            if isinstance(exc, ConfigurationError):
                message = str(exc)
            elif isinstance(exc, FileNotFoundError):
                message = "The saved detection results could not be read."
            else:
                message = web_reported.INVALID if isinstance(exc, ValueError) else (
                    "The report marks could not be saved. Check storage and retry.")
            return render(client, error=message, status=400)
        finally:
            lock.release()
        return redirect(url_for("web.index", client=client,
                                **{"marked" if action == "mark" else "withdrawn": count}), code=303)

    @blueprint.post("/run")
    @requires("run")
    def run_job():
        require_accounts()
        try:
            client = client_label(_canonical_client(
                config, _text(request.form, "client", required=True)))
        except ConfigurationError:
            abort(400)
        action = _text(request.form, "action", required=True)
        if action not in {"web-detect", "web-plan"}:
            abort(400)
        try:
            path, _ = paths(config, client)
            document, _ = read_allowlist(path, client)
            if not document["assets"]:
                raise ConfigurationError("Save an attested web asset before running detection")
            argv = build_command(config, action, client=document["client"])
            job = manager().submit(action, started_by=g.user.username, argv=argv)
        except (RunInProgress, JobQueueFull) as exc:
            return render(client, page="detection", error=str(exc), status=409)
        except (CVEBeaconError, ValueError, OSError) as exc:
            return render(client, page="detection", error=str(exc) if isinstance(exc, ConfigurationError)
                          else "The web detection job could not be started", status=400)
        return redirect(url_for("operations.job_detail", job_id=job.id), code=303)

    register_import(blueprint, config, lambda client, **kwargs: render(client, page="sites", **kwargs))
    return blueprint
