"""Forms and results for explicitly authorised client web assets."""

from copy import deepcopy
from datetime import datetime, timezone
import json
import math
import re
import stat
from urllib.parse import urlsplit

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .clients import client_name, client_page
from .dashboard import _text, requires
from .dashboard_jobs import JobQueueFull, build_command
from .dashboard_ops import require_accounts
from .errors import CVEBeaconError, ConfigurationError
from .locking import OperationLock, RunInProgress
from .managed_inventory import client_key as inventory_client_key, normalized_client, profiles
from .publication import PublicationTimeout
from . import web_assets
from .web_assets import (COMPANION_NOTICE, client_label, directories,
                         paths, read_allowlist, save_allowlist, validate_allowlist)
from .web_inventory import decode_json, read_bytes, read_web_snapshot

_RUN_STATUSES = {"success", "partial", "failed", "no-usable-versions"}
_EVIDENCE_KINDS = frozenset({
    "header", "cookie", "meta", "url", "html", "script", "style", "manifest",
    "robots", "icon", "implied", "dom", "text",
})
# Mirror the optional detector's category vocabulary without importing Extensions into Core.
_WEB_PRODUCT_CATEGORIES = frozenset({
    "web-server", "application-server", "language", "framework", "cms", "js-library",
    "css-library", "edge", "ops-tool", "hosted-platform", "application", "reverse-proxy",
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
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
_CONFIDENCE_CHOICES = ("high", "medium", "low")
_NO_SITE = "Site not recorded"


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
    return {
        "conf": conf,
        "version": version if version in {"with", "without"} else "any",
        "inv": inventory if inventory in {"in", "review"} else "any",
        "category": category if category in categories else "",
        "site": site if site in sites else "",
        "tech": single("tech"),
        "view": "tech" if single("view", 8) == "tech" else "site",
    }


def _technology_rows(rows):
    """One row per technology, in one pass over the already filtered product rows."""
    groups = {}
    for item in rows:
        group = groups.setdefault(item["display_name"].casefold(), {
            "name": item["display_name"], "sites": {}, "versions": {}, "categories": [],
            "rank": 0, "label": "Unknown", "class": "neutral", "in_inventory": False,
        })
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
        group["in_inventory"] = group["in_inventory"] or item["in_inventory"]
    result = []
    for group in groups.values():
        group["site_count"] = len(group["sites"])
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
                      "reason", "detail", "name", "ecosystem", "package"):
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

    def render(client="", *, error=None, status=200, prefill_url=""):
        clients, document, version = [], None, "new"
        products, reviews, run, snapshot, snapshot_rows = [], [], None, None, []
        last_job, truncated, removed = None, False, False
        inventory_clients = _inventory_clients(config)
        prefill_entry = _prefill_entry(prefill_url) if prefill_url else {}
        versions_hidden = False
        available = web_assets.companion_available()
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
                document = {**document, "assets": [_editable_entry(row) for row in document["assets"]]}
                ca = document.get("ca_bundle", "")
                if not isinstance(ca, str) or any(0xD800 <= ord(char) <= 0xDFFF for char in ca):
                    document["ca_bundle"] = ""
                removed = output.with_name(output.name + ".removed").exists()
                if output.exists() or output.is_symlink():
                    try:
                        snapshot_rows, snapshot = read_web_snapshot(output)
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
        confidence_classes = {"high": "high", "medium": "medium", "low": "low"}
        snapshot_inventory_ids = {
            getattr(record, "asset_id", "") for record in snapshot_rows
            if getattr(record, "version", "") or getattr(record, "cpe", "")
        }
        for item in products:
            item["display_name"] = item.get("name") or (
                f"{item.get('vendor', '')}/{item.get('product', '')}"
            )
            versions = [version for version in item.get("versions", []) if version.strip()]
            item["has_version"] = bool(versions)
            item["display_version"] = ", ".join(versions) or "Version not disclosed"
            confidence = item.get("confidence", "").casefold()
            item["confidence_label"] = (
                confidence.title() if confidence in confidence_classes else "Unknown"
            )
            item["confidence_class"] = confidence_classes.get(confidence, "neutral")
            item["category_labels"] = item.get(
                "categories", [item.get("category") or "Category not recorded"]
            )
            # Newer review files record whether a row was created; older ones are guessed.
            item["in_inventory"] = (
                item["inventory"] if isinstance(item.get("inventory"), bool)
                else item["has_version"] or item.get("asset_id") in snapshot_inventory_ids
            )
            labels = [evidence_words[kind] for kind in item.get("evidence_types", [])
                      if kind in evidence_words]
            labels.extend(f"Inferred from {source}" for source in item.get("implied_by", []))
            if not labels and "implied" in item.get("evidence_types", []):
                labels.append("Inferred")
            item["evidence_labels"] = list(dict.fromkeys(labels))
        products.sort(key=lambda item: (
            item.get("hostname", "").casefold(), item.get("category", "").casefold(),
            item["display_name"].casefold(),
        ))
        categories = sorted({c for item in products for c in item["category_labels"]}, key=str.casefold)
        site_names = sorted({_site_label(item) for item in products}, key=str.casefold)
        flt = _filter_args(request.args, set(categories), set(site_names))
        needle = flt["tech"].casefold()
        chips = dict(high=0, medium=0, low=0, with_version=0, without_version=0)
        matched, technologies, chip_sites = [], set(), set()
        for item in products:
            chip_sites.add(_site_label(item))
            technologies.add(item["display_name"].casefold())
            if item["confidence_class"] in chips:
                chips[item["confidence_class"]] += 1
            chips["with_version" if item["has_version"] else "without_version"] += 1
            if ((item["confidence_class"] in flt["conf"] or (
                    item["confidence_class"] == "neutral" and flt["conf"] == set(_CONFIDENCE_CHOICES)))
                    and (flt["version"] == "any" or item["has_version"] == (flt["version"] == "with"))
                    and (flt["inv"] == "any" or item["in_inventory"] == (flt["inv"] == "in"))
                    and (not flt["category"] or flt["category"] in item["category_labels"])
                    and (not flt["site"] or _site_label(item) == flt["site"])
                    and (not needle or needle in item["display_name"].casefold())):
                matched.append(item)
        chips.update(technologies=len(technologies), sites=len(chip_sites))
        flt["active"] = (flt["conf"] != set(_CONFIDENCE_CHOICES) or flt["version"] != "any"
                         or flt["inv"] != "any" or bool(flt["category"] or flt["site"] or flt["tech"]))
        tech_rows, site_groups = [], []
        if flt["view"] == "tech":
            tech_rows = _technology_rows(matched)
            list_total = len(tech_rows)
            tech_rows = tech_rows[:_ROW_LIMIT]
        else:
            list_total = len(matched)
            for item in matched[:_ROW_LIMIT]:
                if not site_groups or site_groups[-1][0] != _site_label(item):
                    site_groups.append((_site_label(item), []))
                site_groups[-1][1].append(item)
        return render_template("web_assets.html", clients=sorted(clients, key=str.casefold),
                               inventory_clients=inventory_clients, client=client,
                               document=document, version=version, products=products, reviews=reviews,
                               run=run, snapshot=snapshot, available=available, notice=COMPANION_NOTICE,
                               last_job=last_job, truncated=truncated, removed=removed, error=error,
                               versions_hidden=versions_hidden, reason_labels=_REASON_LABELS,
                               prefill_entry=prefill_entry, prefill_url=prefill_url, flt=flt, chips=chips,
                               categories=categories, site_names=site_names, matched_count=len(matched),
                               total_products=len(products), tech_rows=tech_rows, site_groups=site_groups,
                               row_limit=_ROW_LIMIT, list_total=list_total, confidence_choices=_CONFIDENCE_CHOICES), status

    @blueprint.get("")
    @requires("view")
    def index():
        label = _text(request.args, "client", limit=256)
        prefill_url = _text(request.args, "prefill_url", limit=2048)
        try:
            return render(_canonical_client(config, client_label(label)) if label else "",
                          prefill_url=prefill_url)
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
            return render(client, error=str(RunInProgress(lock.holder)), status=409)
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
                            output.with_name(output.name + ".review.json"), marker]
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
            return render(client, error=message, status=400)
        finally:
            lock.release()
        return redirect(url_for("web.index", client=client), code=303)

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
            return render(client, error=str(exc), status=409)
        except (CVEBeaconError, ValueError, OSError) as exc:
            return render(client, error=str(exc) if isinstance(exc, ConfigurationError)
                          else "The web detection job could not be started", status=400)
        return redirect(url_for("operations.job_detail", job_id=job.id), code=303)

    return blueprint
