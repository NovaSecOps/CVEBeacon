"""Build a client technology exposure report from saved observations and findings."""

from collections import defaultdict
from contextlib import ExitStack, closing
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import json
import re
import sqlite3

from . import web_inventory_actions as actions
from .dashboard_web import _CONFIDENCE_CHOICES as CONFIDENCE_CHOICES
from .dashboard_web import (
    _CONFIDENCE_RANK, _in_snapshot, _read_managed, _review_metadata,
    _severity_level, _site_label, _snapshot_ids,
)
from .errors import CVEBeaconError, ConfigurationError, StateError
from .watch.reported import normalize_cve_id
from .watch.rules import _exploitation_level, _exploitation_sources
from .watch.store import WatchStore
from .web_assets import client_key, paths, read_allowlist
from .web_inventory import decode_json, read_bytes, read_web_snapshot

PRESETS = ("7", "30", "60", "90")
FIELDS = {
    "published": "CVE published",
    "first_seen": "First found by CVEBeacon",
    "modified": "Last modified",
}
SEVERITIES = ("unknown", "none", "low", "medium", "high", "critical")
EXPLOITATION = {"active": "Active", "poc": "PoC", "none": "None", "unknown": "Unknown"}
PAGE_ROWS = 1_000
PAGE_CVES_PER_ROW = 200
EXPORT_CVES = 50_000
FINDINGS_CAP = 200_000


class InvalidReportFilters(ValueError):
    """The report query contains an invalid filter selection."""


@dataclass(frozen=True)
class Window:
    kind: str
    field: str
    start: date | None
    end: date | None

    def includes(self, value):
        if self.kind == "all":
            return True
        return value is not None and self.start.isoformat() <= value[:10] <= self.end.isoformat()

    def as_dict(self):
        return {
            "kind": self.kind, "field": self.field,
            "from": self.start.isoformat() if self.start is not None else None,
            "to": self.end.isoformat() if self.end is not None else None,
        }


def _arg(args, key, default="", limit=32):
    values = args.getlist(key)
    if not values:
        return default
    if len(values) != 1 or len(values[0]) > limit or any(ord(c) < 32 for c in values[0]):
        raise ValueError("invalid report option")
    return values[0]


def _date_arg(args, key):
    value = _arg(args, key, limit=10)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise ValueError("invalid report date")
    return date.fromisoformat(value)


def read_window(args, today):
    """Return the effective UTC window and whether invalid input had to be reset."""
    default = Window("30", "published", today - timedelta(days=29), today)
    try:
        kind = _arg(args, "window", "30")
        field = _arg(args, "field", "published")
        if field not in FIELDS:
            raise ValueError("invalid report date field")
        if kind == "all":
            return Window(kind, field, None, None), False
        if kind == "range":
            start, end = _date_arg(args, "from"), _date_arg(args, "to")
            if not start <= end <= today or (end - start).days >= 3650:
                raise ValueError("invalid report range")
            return Window(kind, field, start, end), False
        if kind == "days":
            value = _arg(args, "days", limit=4)
            if not re.fullmatch(r"[0-9]{1,4}", value) or not 1 <= int(value) <= 3650:
                raise ValueError("invalid report day count")
        elif kind not in PRESETS:
            raise ValueError("invalid report window")
        else:
            value = kind
        end = _date_arg(args, "end") if "end" in args else today
        if not 0 <= (today - end).days <= 3650:
            raise ValueError("invalid report end date")
        start = end - timedelta(days=int(value) - 1)
        return Window(kind, field, start, end), False
    except (ValueError, OverflowError):
        return default, True


def _choice(args, key, choices, default="", limit=32):
    try:
        value = _arg(args, key, limit=limit)
    except ValueError:
        return default
    return value if value in choices else default


def read_filters(args, sites, categories, *, vulncheck=False):
    # A hidden field distinguishes an unchecked checkbox from the initial GET.
    marker = args.getlist("filters")
    if marker and marker != ["1"]:
        raise InvalidReportFilters
    confidence = args.getlist("conf")
    if len(confidence) > len(CONFIDENCE_CHOICES) or any(value not in CONFIDENCE_CHOICES for value in confidence):
        raise InvalidReportFilters
    chosen = [value for value in CONFIDENCE_CHOICES if value in confidence]
    return {
        "site": _choice(args, "site", sites, limit=256),
        "category": _choice(args, "category", categories, limit=80),
        "conf": chosen or list(CONFIDENCE_CHOICES),
        "status": _choice(args, "status", actions.STATUS_LABELS, "any"),
        "severity": _choice(args, "severity", SEVERITIES[2:], "any"),
        "kev": _choice(args, "kev",
                       ("cisa", "eu", "vulncheck", "either") if vulncheck else ("cisa", "eu", "either"),
                       "any"),
        "exploited": _choice(args, "exploited", ("active", "poc"), "any"),
        "show_empty": _choice(args, "show_empty", ("0", "1"),
                              "0" if marker else "1") == "1",
    }


def _technology_key(item):
    # The detector can record a technology once per endpoint. Group repeated
    # observations on the same hostname while preserving distinct package/CPE identities.
    return (
        _site_label(item).casefold(), item.get("vendor", "").casefold(),
        (item.get("product") or item.get("name", "")).casefold(),
        item.get("ecosystem", ""), item.get("package", ""), item.get("cpe", ""),
    )


def _group_products(products, snapshot_ids, snapshots_on, managed_assets):
    managed = actions.ManagedIndex(managed_assets, require_same_site=True)
    groups = {}
    for item in products:
        key = _technology_key(item)
        site = _site_label(item)
        name = item.get("name") or f"{item.get('vendor', '')}/{item.get('product', '')}"
        row = groups.setdefault(key, {
            "site": site, "technology": name, "versions": set(), "categories": set(),
            "asset_ids": set(), "covered_ids": set(), "status": "service", "confidence": "unknown",
        })
        item["in_inventory"] = _in_snapshot(item, snapshot_ids)
        status, covered = actions.classify(item, snapshots_on=snapshots_on,
                                           snapshot_ids=snapshot_ids, managed=managed)
        row["status"] = actions.best_status((row["status"], status))
        row["covered_ids"].update(covered)
        if item.get("asset_id"):
            row["asset_ids"].add(item["asset_id"])
        row["versions"].update(actions.detected_versions(item))
        row["categories"].update(item.get("categories") or [item.get("category") or "Category not recorded"])
        confidence = item.get("confidence", "").casefold()
        if _CONFIDENCE_RANK.get(confidence, 0) > _CONFIDENCE_RANK.get(row["confidence"], 0):
            row["confidence"] = confidence
    for row in groups.values():
        for key in ("versions", "categories", "asset_ids", "covered_ids"):
            row[key] = sorted(row[key], key=lambda value: (value.casefold(), value))
    return sorted(groups.values(), key=lambda row: (row["site"].casefold(), row["technology"].casefold()))


def _read_technologies(config, client, notices):
    snapshot_ids = set()
    snapshots_on = config.inventory is not None and config.inventory.web_snapshots
    managed_assets = []
    _, output = paths(config, client)
    review = output.with_name(output.name + ".review.json")
    try:
        detail = decode_json(read_bytes(review))
    except FileNotFoundError:
        return []
    products, _, _ = _review_metadata(detail, client)
    if output.exists() or output.is_symlink():
        try:
            snapshot_ids = _snapshot_ids(read_web_snapshot(output, preserve_client=True)[0], client)
        except (CVEBeaconError, OSError, ValueError):
            snapshots_on = False
            notices.append("The saved web snapshot could not be read. Snapshot coverage is unavailable.")
    if config.managed_inventory and products:
        try:
            _, assets = _read_managed(config, client, preserve_client=True)
            if assets and client_key(assets[0].client) != client_key(client):
                raise ConfigurationError("Managed inventory owner differs from the report client.")
            managed_assets = assets
        except ConfigurationError:
            notices.append("The managed inventory could not be read. Managed inventory coverage is unavailable.")
    return _group_products(products, snapshot_ids, snapshots_on, managed_assets)


def reported_marks(client):
    """Return saved reporting marks keyed by detection asset ID when available."""
    return {}


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        return None


def _number(value, limit):
    return value if type(value) in (float, int) and 0 <= value <= limit else None


def _finding_text(value):
    return value.encode("utf-8", "replace").decode("utf-8") if isinstance(value, str) else None


def _finding_list(value):
    if isinstance(value, list):
        return [_finding_text(item) for item in value if isinstance(item, str)]
    return []


def _finding(record, *, vulncheck=False):
    vuln = json.loads(record["vulnerability"])
    if not isinstance(vuln, dict):
        raise ValueError("invalid saved vulnerability")
    try:
        identifier = normalize_cve_id(vuln.get("cve_id") or record["cve_id"])
    except ConfigurationError:
        return None
    cvss = _number(vuln.get("cvss_score"), 10)
    value = {
        "cve_id": identifier, "advisory_id": _finding_text(vuln.get("advisory_id")) or record["cve_id"],
        "summary": _finding_text(vuln.get("summary")), "applicability": record["applicability"],
        "published": _timestamp(vuln.get("published")), "modified": _timestamp(vuln.get("modified")),
        "first_seen": _timestamp(record["first_seen"]), "last_seen": _timestamp(record["last_seen"]),
        "severity": _severity_level(cvss), "cvss_score": cvss, "cvss_version": _finding_text(vuln.get("cvss_version")),
        "epss_score": _number(vuln.get("epss_score"), 1),
        "epss_percentile": _number(vuln.get("epss_percentile"), 1),
        "cisa_kev": vuln.get("cisa_kev"), "eu_kev": vuln.get("eu_kev"),
        "fixed_versions": _finding_list(vuln.get("fixed_versions")), "references": _finding_list(vuln.get("references")),
    }
    if vulncheck:
        value["vulncheck_kev"] = vuln.get("vulncheck_kev")
        value["vulncheck_date_added"] = _timestamp(vuln.get("vulncheck_date_added"))
    return value


def _is_client(value, expected_key):
    try:
        return client_key(value) == expected_key
    except ConfigurationError:
        return False


def _read_findings(path, client, asset_ids, *, vulncheck=False):
    """Read bounded, client-scoped findings in one read-only transaction."""
    by_asset = defaultdict(list)
    if not asset_ids or not path.exists():
        return by_asset, False
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='current_findings' AND type='table'").fetchone():
            return by_asset, False
        expected_key = client_key(client)
        db.create_function("report_client_matches", 1, lambda value: _is_client(value, expected_key))
        remaining = FINDINGS_CAP
        for start in range(0, len(asset_ids), 500):
            chunk = asset_ids[start:start + 500]
            placeholders = ",".join("?" for _ in chunk)
            for record in db.execute(
                "SELECT f.asset_id, f.cve_id, f.first_seen, f.last_seen, "
                "json_extract(f.payload_json, '$.applicability') AS applicability, "
                "json_extract(f.payload_json, '$.vulnerability') AS vulnerability "
                f"FROM current_findings f WHERE f.asset_id IN ({placeholders}) "
                "AND report_client_matches(json_extract(f.payload_json, '$.asset.client')) "
                "AND COALESCE(json_extract(f.payload_json, '$.applicability'), '') != 'not_affected' "
                "AND NOT EXISTS (SELECT 1 FROM advisory_aliases a WHERE a.asset_id=f.asset_id "
                "AND a.alias=f.cve_id AND a.primary_id!=f.cve_id) ORDER BY f.asset_id, f.cve_id LIMIT ?",
                (*chunk, remaining),
            ):
                finding = (
                    _finding(record, vulncheck=True) if vulncheck else _finding(record)
                )
                if finding is not None:
                    by_asset[record["asset_id"]].append(finding)
                remaining -= 1
                if not remaining:
                    return by_asset, True
    return by_asset, False


def _ignore_missing(values, select=max):
    return select((value for value in values if value is not None), default=None)


def _merge_finding(left, right):
    """Consolidate a CVE seen on both snapshot and managed rows for this technology."""
    if right["cvss_score"] is not None and (left["cvss_score"] is None or right["cvss_score"] > left["cvss_score"]):
        for key in ("severity", "cvss_score", "cvss_version"):
            left[key] = right[key]
    for key in ("published", "first_seen"):
        left[key] = _ignore_missing((left[key], right[key]), min)
    for key in ("modified", "last_seen", "epss_score", "epss_percentile", "cisa_kev", "eu_kev"):
        left[key] = _ignore_missing((left[key], right[key]))
    for key in ("vulncheck_kev", "vulncheck_date_added"):
        if key in left or key in right:
            left[key] = _ignore_missing((left.get(key), right.get(key)))
    for key in ("fixed_versions", "references"):
        left[key] = list(dict.fromkeys((*left[key], *right[key])))
    if right["applicability"] == "affected" or not left["applicability"]:
        left["applicability"] = right["applicability"]
    if not left["summary"]:
        left["summary"] = right["summary"]


def _current_cves(row, by_asset):
    current = {}
    for asset_id in row["covered_ids"]:
        for finding in by_asset.get(asset_id, ()):
            cve_id = finding["cve_id"]
            if cve_id in current:
                _merge_finding(current[cve_id], finding)
            else:
                current[cve_id] = finding.copy()
    return current.values()


def _watch_exploitation(config, stack):
    # Use one read snapshot for the whole report.
    if not config.watch.enabled:
        return lambda _identifier: ("unknown", ())
    store = WatchStore(config.watch.database)
    try:
        if not store.path.is_file():
            return lambda _identifier: ("unknown", ())
        db = stack.enter_context(store.read())
    except (StateError, OSError, ValueError):
        return lambda _identifier: ("unknown", ())

    def exploitation(identifier):
        try:
            view = store._view(db, identifier, config.watch.sources)
            if view is not None:
                return _exploitation_level(view), _exploitation_sources(view)
        except (StateError, sqlite3.Error, OSError, TypeError, ValueError, KeyError):
            pass
        return "unknown", ()

    return exploitation


def _technology_matches(row, filters):
    confidence = filters["conf"]
    return (
        (not filters["site"] or row["site"] == filters["site"])
        and (not filters["category"] or filters["category"] in row["categories"])
        and (row["confidence"] in confidence or confidence == list(CONFIDENCE_CHOICES))
        and (filters["status"] == "any" or row["status"] == filters["status"])
    )


def _cve_matches(cve, window, filters):
    kev = filters["kev"]
    minimum = filters["severity"]
    return (
        window.includes(cve[window.field])
        and (minimum == "any" or SEVERITIES.index(cve["severity"]) >= SEVERITIES.index(minimum))
        and (kev == "any" or kev in ("cisa", "either") and cve["cisa_kev"]
             or kev in ("eu", "either") and cve["eu_kev"]
             or kev in ("vulncheck", "either") and cve.get("vulncheck_kev"))
    )


def _matching_cves(current, window, filters, exploitation):
    for cve in current:
        if _cve_matches(cve, window, filters):
            level, sources = exploitation(cve["cve_id"])
            chosen = filters["exploited"]
            if chosen == "any" or level == "active" or chosen == "poc" and level == "poc":
                yield {**cve, "exploitation": level, "exploitation_sources": sources}


def _row_summary(cves, current_count, coverage):
    max_cvss = _ignore_missing(cve["cvss_score"] for cve in cves)
    return {
        "window_count": len(cves) if coverage != "unavailable" else None,
        "current_count": current_count if coverage != "unavailable" else None,
        "coverage": coverage,
        "severity": _severity_level(max_cvss), "max_cvss": max_cvss,
        "cisa_kev": any(cve["cisa_kev"] for cve in cves),
        "eu_kev": any(cve["eu_kev"] for cve in cves),
        "vulncheck_kev": any(cve.get("vulncheck_kev") for cve in cves),
        "exploitation": next((level for level in EXPLOITATION
                              if any(cve["exploitation"] == level for cve in cves)), "unknown"),
        "max_epss": _ignore_missing(cve["epss_score"] for cve in cves),
        "newest_published": _ignore_missing(cve["published"] for cve in cves),
        "first_found": _ignore_missing((cve["first_seen"] for cve in cves), min),
    }


def build_report(config, client, args, *, export=False, now=None):
    """Build the same filtered report for the dashboard and each export format."""
    now = now or datetime.now(timezone.utc)
    window, invalid = read_window(args, now.date())
    notices = []
    if invalid:
        notices.append("Invalid time window. Showing the last 30 days by CVE published date.")
    try:
        allowlist, _ = paths(config, client)
        client = read_allowlist(allowlist, client)[0]["client"]
        technologies = _read_technologies(config, client, notices)
    except (CVEBeaconError, ValueError, OSError, TypeError, KeyError):
        notices.append("Saved web detections could not be read.")
        technologies = []
    sites = sorted({row["site"] for row in technologies}, key=str.casefold)
    categories = sorted({category for row in technologies for category in row["categories"]}, key=str.casefold)
    vulncheck_on = bool(getattr(config, "vulncheck_active", lambda: False)())
    filters = read_filters(args, sites, categories, vulncheck=vulncheck_on)
    selected = [row for row in technologies if _technology_matches(row, filters)]
    unmonitored = sum(row["status"] != "monitored" for row in selected)
    asset_ids = sorted({asset_id for row in selected for asset_id in row["covered_ids"]})
    findings_unavailable = findings_capped = False
    try:
        by_asset, findings_capped = _read_findings(
            config.database_path, client, asset_ids, vulncheck=vulncheck_on
        )
    except (CVEBeaconError, sqlite3.Error, OSError, ValueError, TypeError, KeyError):
        by_asset = {}
        findings_unavailable = True
        notices.append("Current CVE findings could not be read. Counts for monitored technologies are unavailable.")
    if findings_capped:
        notices.append(f"Results were truncated at {FINDINGS_CAP:,} findings; narrow the window or filters.")

    rows, chip_sets, severities = [], defaultdict(set), {}
    matched_rows = monitored = retained_cves = 0
    cves_capped = False
    with ExitStack() as stack:
        lookup = _watch_exploitation(config, stack)
        exploitation_cache = {}

        def exploitation(identifier):
            return exploitation_cache.get(identifier) or lookup(identifier)

        for row in selected:
            current = _current_cves(row, by_asset)
            cves = list(_matching_cves(current, window, filters, exploitation))
            if not cves and not filters["show_empty"] and not (findings_unavailable and row["covered_ids"]):
                continue
            matched_rows += 1
            monitored += row["status"] == "monitored"
            chip_sets["sites"].add(row["site"])
            for cve in cves:
                identifier = cve["cve_id"]
                rank = SEVERITIES.index(cve["severity"])
                severities[identifier] = max(rank, severities.get(identifier, 0))
                keys = ("cisa_kev", "eu_kev", "active")
                if vulncheck_on:
                    keys = ("cisa_kev", "eu_kev", "vulncheck_kev", "active")
                for key in keys:
                    if cve.get(key) or cve["exploitation"] == key:
                        chip_sets[key].add(identifier)
            if export or len(rows) < PAGE_ROWS:
                limit = EXPORT_CVES - retained_cves if export else PAGE_CVES_PER_ROW
                coverage = ("unmonitored" if not row["covered_ids"] else
                            "unavailable" if findings_unavailable else "monitored")
                totals = _row_summary(cves, len(current), coverage)
                cves.sort(key=lambda cve: (-SEVERITIES.index(cve["severity"]), cve["cve_id"]))
                capped = len(cves) > limit
                retained = cves[:limit]
                rows.append({**row, **totals, "cves": retained, "cves_capped": capped})
                exploitation_cache.update((cve["cve_id"], (cve["exploitation"], cve["exploitation_sources"]))
                                          for cve in retained)
                retained_cves += len(retained)
                cves_capped |= capped
    if not vulncheck_on:
        for row in rows:
            row.pop("vulncheck_kev", None)
            for cve in row["cves"]:
                cve.pop("vulncheck_kev", None)
                cve.pop("vulncheck_date_added", None)
    summary_keys = ("sites", "cisa_kev", "eu_kev", "active")
    if vulncheck_on:
        summary_keys = ("sites", "cisa_kev", "eu_kev", "vulncheck_kev", "active")
    summary = {
        **{key: len(chip_sets[key]) for key in summary_keys},
        "cves": len(severities),
        "critical": sum(rank == SEVERITIES.index("critical") for rank in severities.values()),
        "high": sum(rank == SEVERITIES.index("high") for rank in severities.values()),
        "technologies": matched_rows, "monitored": monitored, "unmonitored": matched_rows - monitored,
    }
    return {
        "client": client, "window": window.as_dict(), "generated_at": now.isoformat(),
        "filters": filters, "technologies": rows, "summary": summary, "notices": notices,
        "sites": sites, "categories": categories, "unmonitored": unmonitored,
        "rows_capped": matched_rows > len(rows), "cves_capped": cves_capped, "findings_capped": findings_capped,
    }
