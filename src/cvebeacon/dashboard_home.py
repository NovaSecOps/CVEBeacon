"""Derived Home KPI context and its short-lived per-application cache."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from threading import RLock
import time

from .errors import CVEBeaconError
from .inventory import load_inventory

HOME_CACHE_EXTENSION = "dashboard_home_metrics_cache"
HOME_CACHE_SECONDS = 30
ALERT_DESCRIPTION = (
    "Counts queued, sending, failed or unsure Watch delivery rows; "
    "this activity is not inventory-specific."
)

_INVENTORY_CARDS = (
    (
        "Affected findings",
        "Affected findings",
        "Known findings marked affected on inventory items that still match the scan result.",
        "findings",
    ),
    (
        "Needs review",
        "Needs review",
        "Known findings where the scan could not confirm whether they apply.",
        "review",
    ),
    (
        "Assets with unknown coverage",
        "Coverage unknown assets",
        "The latest result does not establish coverage for these inventory items.",
        "coverage",
    ),
)


class HomeContextCache:
    """Cache one derived Home context; failed refreshes never expose old data."""

    def __init__(self, ttl_seconds: float = HOME_CACHE_SECONDS, clock=time.monotonic):
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = RLock()
        self._key = None
        self._expires = 0.0
        self._value = None

    def get(self, key, build):
        with self._lock:
            key_value = key() if callable(key) else key
            now = self._clock()
            if self._value is not None and self._key == key_value and now < self._expires:
                return self._value
            # Clear first so an expired value cannot survive a failed rebuild.
            self._key = None
            self._expires = 0.0
            self._value = None
            value = build()
            self._key = key() if callable(key) else key
            self._expires = self._clock() + self._ttl
            self._value = value
            return value


def cached_home_context(app, key, build):
    """Return the per-app cached context, building it under a single lock."""
    cache = app.extensions.get(HOME_CACHE_EXTENSION)
    if cache is None:
        cache = HomeContextCache()
        cache = app.extensions.setdefault(HOME_CACHE_EXTENSION, cache)
    return cache.get(key, build)


def _path_fingerprint(path) -> tuple:
    if path is None:
        return ()
    path = Path(path)
    stamps = []
    for candidate in (
        path,
        path.with_name(path.name + "-wal"),
    ):
        try:
            details = candidate.stat()
        except OSError:
            stamps.append(None)
        else:
            stamps.append((details.st_mtime_ns, details.st_size))
    return tuple(stamps)


def home_cache_key(config) -> tuple:
    """Include small file stamps so a new scan or inventory bypasses the TTL."""
    inventory = getattr(config, "inventory", None)
    inventory_path = getattr(inventory, "path", None)
    managed_directory = getattr(config, "inventory_directory", None)
    return (
        str(config.database_path),
        _path_fingerprint(config.database_path),
        str(config.watch.database),
        _path_fingerprint(config.watch.database),
        bool(config.watch.enabled),
        _path_fingerprint(inventory_path),
        _path_fingerprint(managed_directory) if config.managed_inventory else (),
    )


def build_home_snapshot(
    config,
    state_store,
    watch_store,
    *,
    inventory_config,
    inventory_configured: bool,
    links: dict[str, str],
    now: datetime | None = None,
) -> tuple[dict, dict]:
    """Read the existing scan snapshot and aggregate only fields Home renders."""
    from .dashboard import _inventory_match, _old

    data = state_store.dashboard_snapshot()
    now = now or datetime.now(timezone.utc)
    data["inventory_warnings"] = []
    data["inventory_error"] = False
    assets = {}
    categories = Counter()
    if inventory_config is not None:
        try:
            for asset in load_inventory(
                inventory_config,
                snapshot_directory=config.database_path.parent / "web-inventory",
                managed_warnings=data["inventory_warnings"],
            ):
                assets[asset.asset_id] = asset
                categories[asset.category or "Uncategorized"] += 1
        except CVEBeaconError:
            data["inventory_error"] = True
    latest, attempt = data["latest"], data["attempt"]
    data["stale"] = latest is None or _old(latest["completed_at"], now)
    data["failed"] = (
        bool(latest and latest["status"] != "completed")
        or bool(attempt and attempt["status"] != "completed")
    )
    data["unfinished"] = bool(attempt and attempt["status"] == "running")

    counts = {
        "Affected findings": 0,
        "Needs review": 0,
        "Coverage unknown assets": 0,
    }
    if not data["inventory_error"]:
        unseen = set(assets)
        explicitly_unknown = 0
        for item in data["assets"]:
            asset_id = item["asset"]["asset_id"]
            current = assets.get(asset_id)
            if current is not None and _inventory_match(item["asset"], assets):
                unseen.discard(asset_id)
                explicitly_unknown += item.get("coverage") == "coverage_unknown"
        counts["Coverage unknown assets"] = len(unseen) + explicitly_unknown
        for row in data["findings"]:
            if _inventory_match(row["finding"]["asset"], assets):
                applicability = row["finding"]["applicability"]
                if applicability in {"affected", "needs_review"}:
                    counts["Affected findings" if applicability == "affected" else "Needs review"] += 1
    data["counts"] = counts
    data["categories"] = categories
    for row in data["health"]:
        row["freshness"] = "stale" if _old(row["checked_at"], now) else "cached observation"

    # These row collections were only needed for the single aggregation pass.
    data["assets"] = []
    data["findings"] = []
    home = build_home_context(
        config,
        data,
        watch_store,
        inventory_configured=inventory_configured,
        links=links,
        now=now,
    )
    return data, home


def _age(timestamp: str, now: datetime) -> str | None:
    try:
        parsed = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    seconds = (now - parsed.astimezone(timezone.utc)).total_seconds()
    if seconds < 0:
        return None
    if seconds < 60:
        return "less than a minute"
    if seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    if seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    return f"{int(seconds // 86400)} days"


def _attempt_is_distinct(latest, attempt) -> bool:
    if not attempt:
        return False
    if not latest:
        return True
    if attempt.get("run_id"):
        if attempt["run_id"] != latest.get("run_id"):
            return True
        return _status_label(attempt.get("status")) != _status_label(latest.get("status"))
    try:
        started = datetime.fromisoformat(attempt["started_at"])
        completed = datetime.fromisoformat(latest["completed_at"])
        return started > completed
    except (KeyError, TypeError, ValueError):
        return True


def _status_label(value) -> str:
    return {
        "completed": "Finished",
        "failed": "Failed",
        "running": "Running",
    }.get(value, "Not known")


def _watch_delivery_counts(store) -> tuple[str, dict[str, int]]:
    """Read only outstanding Watch delivery counts without touching watch_cve."""
    db = None
    try:
        db = store._connect_readonly()
        has_history = db.execute("SELECT 1 FROM watch_delivery LIMIT 1").fetchone() is not None
        rows = db.execute(
            "SELECT status, COUNT(*) AS count FROM watch_delivery "
            "WHERE status IN ('pending','sending','failed','ambiguous') GROUP BY status"
        ).fetchall()
    except (CVEBeaconError, OSError, sqlite3.Error, ValueError):
        return "could_not_check", {}
    finally:
        if db is not None:
            db.close()
    if not has_history:
        return "empty", {}
    counts = {"pending": 0, "sending": 0, "failed": 0, "ambiguous": 0}
    for row in rows:
        counts[row["status"]] = int(row["count"])
    return "available", counts


def _inventory_card_value(state: str, counts: dict, count_key: str) -> int | str:
    if state == "not_configured":
        return "Add inventory"
    if state == "no_scan_recorded":
        return "No scan recorded"
    if state == "could_not_check":
        return "Unknown"
    value = counts.get(count_key)
    return int(value) if isinstance(value, int) and value >= 0 else "Unknown"


def build_home_context(
    config,
    data: dict,
    watch_store,
    *,
    inventory_configured: bool,
    links: dict[str, str],
    now: datetime | None = None,
) -> dict:
    """Build five Home cards from the existing scan aggregation and Watch rows."""
    now = now or datetime.now(timezone.utc)
    latest = data.get("latest")
    scan_error = bool(data.get("home_scan_error"))
    if not inventory_configured:
        inventory_state = "not_configured"
    elif scan_error or data.get("inventory_error"):
        inventory_state = "could_not_check"
    elif not latest:
        inventory_state = "no_scan_recorded"
    else:
        inventory_state = "available"

    counts = data.get("counts") or {}
    if inventory_state == "available" and any(
        not isinstance(counts.get(key), int) or counts[key] < 0
        for key in ("Affected findings", "Needs review", "Coverage unknown assets")
    ):
        inventory_state = "could_not_check"

    scan_stale = bool(latest and data.get("stale"))
    scan_failed = bool(data.get("failed"))
    freshness = ""
    if latest:
        completed = latest.get("completed_at")
        age = _age(completed, now) if completed else None
        if completed:
            freshness = f" Latest scan: {completed}"
            if age:
                freshness += f" ({age} old)"
            freshness += "."
        if scan_stale:
            freshness += " Stale scan data: the scan is over 24 hours old or its time is unknown."
        if scan_failed:
            freshness += " The latest scan needs attention."

    cards = []
    for title, count_key, description, link_key in _INVENTORY_CARDS:
        value = _inventory_card_value(inventory_state, counts, count_key)
        help_text = description
        if inventory_state == "not_configured":
            help_text = "Add inventory to see these numbers."
        elif inventory_state == "no_scan_recorded":
            help_text += " No scan recorded."
        elif inventory_state == "could_not_check":
            help_text += " Could not check."
        else:
            help_text += freshness
            if title == "Affected findings" and value == 0:
                help_text += " No affected findings recorded for this inventory."
        if inventory_state == "not_configured":
            value = "Add inventory"
        tone = None
        if inventory_state == "could_not_check" or scan_stale or scan_failed:
            tone = "warning"
        elif value not in (0, "Unknown", "No scan recorded", "Add inventory"):
            tone = "critical" if title == "Affected findings" else "warning"
        cards.append({
            "title": title,
            "value": value,
            "help": help_text,
            "tone": tone,
            "href": links[link_key],
        })

    if scan_error:
        latest_value = "Unknown"
        latest_help = "The latest stored scan run and the most recent attempt. Could not check."
        latest_tone = "warning"
    elif not latest:
        latest_help = "The latest stored scan run and the most recent attempt."
        attempt = data.get("attempt")
        if attempt and attempt.get("status") == "running":
            latest_value = "Scan in progress"
            latest_tone = "warning"
            latest_help = "No stored scan result yet."
        else:
            latest_value = "No scan recorded"
            latest_tone = None
        if attempt:
            latest_help += (
                f" Latest attempt: {_status_label(attempt.get('status'))}, "
                f"started {attempt.get('started_at') or 'time not recorded'}."
            )
    else:
        latest_value = latest.get("completed_at") or "Unknown"
        latest_help = f"Latest stored scan result: {_status_label(latest.get('status'))}."
        if _attempt_is_distinct(latest, data.get("attempt")):
            attempt = data["attempt"]
            latest_help += (
                f" Latest attempt: {_status_label(attempt.get('status'))}, "
                f"started {attempt.get('started_at') or 'time not recorded'}."
            )
        if scan_stale:
            latest_help += " Stale scan data."
        if scan_failed:
            latest_help += " The latest scan needs attention."
        latest_tone = "warning" if scan_stale or scan_failed else None
    cards.append({
        "title": "Latest scan",
        "value": latest_value,
        "help": latest_help,
        "tone": latest_tone,
        "href": links["scan"],
    })

    if not config.watch.enabled:
        alert_value = "Watch mode is off"
        alert_help = ALERT_DESCRIPTION
        alert_tone = None
    else:
        delivery_state, delivery_counts = _watch_delivery_counts(watch_store)
        if delivery_state == "could_not_check":
            alert_value = "Unknown"
            alert_help = ALERT_DESCRIPTION + " Could not check."
            alert_tone = "warning"
        elif delivery_state == "empty":
            alert_value = "No alert delivery state recorded"
            alert_help = ALERT_DESCRIPTION
            alert_tone = None
        else:
            alert_value = (
                f"Queued {delivery_counts['pending']} · Sending {delivery_counts['sending']} · "
                f"Failed {delivery_counts['failed']} · Unsure {delivery_counts['ambiguous']}"
            )
            alert_help = ALERT_DESCRIPTION + " Gave up is included in failed."
            alert_tone = "warning" if any(delivery_counts.values()) else None
    cards.insert(3, {
        "title": "Alerts waiting or uncertain",
        "value": alert_value,
        "help": alert_help,
        "tone": alert_tone,
        "href": links["alerts"],
    })
    return {
        "cards": cards,
        "inventory_state": inventory_state,
        "scan_error": scan_error,
    }


def unavailable_home_context(*, inventory_configured: bool, watch_enabled: bool, links: dict[str, str]) -> dict:
    """Render unknown states after a Home context refresh itself failed."""
    cards = []
    for title, _count_key, description, link_key in _INVENTORY_CARDS:
        if not inventory_configured:
            value, help_text = "Add inventory", "Add inventory to see these numbers."
            tone = None
        else:
            value, help_text = "Unknown", f"{description} Could not check."
            tone = "warning"
        cards.append({"title": title, "value": value, "help": help_text,
                      "tone": tone, "href": links[link_key]})
    if not watch_enabled:
        alert_value, alert_help, alert_tone = "Watch mode is off", ALERT_DESCRIPTION, None
    else:
        alert_value, alert_help, alert_tone = "Unknown", ALERT_DESCRIPTION + " Could not check.", "warning"
    cards.insert(3, {"title": "Alerts waiting or uncertain", "value": alert_value,
                     "help": alert_help, "tone": alert_tone, "href": links["alerts"]})
    cards.append({"title": "Latest scan", "value": "Unknown",
                  "help": "The latest stored scan run and the most recent attempt. Could not check.",
                  "tone": "warning", "href": links["scan"]})
    return {"cards": cards, "inventory_state": "could_not_check", "scan_error": True}
