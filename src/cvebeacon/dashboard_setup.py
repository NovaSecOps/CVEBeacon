"""Getting-started checklist for the Home page.

Every step is derived on each page load from state the dashboard already has.
Nothing is stored, so there is no dismissed state and no new configuration.
A finished or inapplicable step is shown as it is; missing data is never
reported as a good state.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Callable, Mapping

from flask import current_app, g, url_for

from . import backup
from .clients import client_page
from .config import AppConfig
from .dashboard_jobs import MAX_HISTORY
from .dashboard_ops import schedule_scan_state
from .errors import CVEBeaconError
from .managed_inventory import has_managed_inventory
from .watch.reported import format_timestamp

STALE_SYNC_DAYS = 3
STALE_BACKUP_DAYS = 7
STEP_STATES = frozenset({"done", "todo", "attention", "unknown", "na"})
READ_FAILURES = (CVEBeaconError, OSError, sqlite3.Error)

SOURCES_TITLE = "Turn on watching and get the first data"
CHANNEL_TITLE = "Set up and test a way to receive alerts"
RULE_TITLE = "Choose what should trigger an alert"
INVENTORY_TITLE = "Add inventory"
SCHEDULE_TITLE = "Run CVEBeacon automatically"
BACKUP_TITLE = "Make a backup"
WATCH_UNREADABLE = "The watch data could not be read. Open the Watch overview for details."
INVENTORY_UNREADABLE = "Inventory information could not be read. Open Inventory for details."


@dataclass(frozen=True, slots=True)
class Step:
    """One row of the checklist; field names match the setup_checklist macro."""

    id: str
    title: str
    state: str
    detail: str
    action_url: str | None = None
    action_label: str | None = None
    hint: str | None = None


@dataclass(frozen=True, slots=True)
class InventoryInfo:
    """Whether an inventory exists and how many assets a completed scan read."""

    exists: bool
    scanned: int


@dataclass(frozen=True, slots=True)
class Viewer:
    """Who is reading Home and which endpoints this application registers."""

    accounts: bool
    permissions: frozenset[str] = frozenset()
    endpoints: frozenset[str] = frozenset()
    is_admin: bool = False
    link: Callable[[str, Mapping[str, object]], str] | None = None

    @classmethod
    def from_flask(cls, app) -> "Viewer":
        return cls(
            accounts=bool(getattr(g, "accounts", False)),
            permissions=frozenset(getattr(g, "permissions", ())),
            endpoints=frozenset(app.view_functions),
            is_admin=bool(getattr(getattr(g, "user", None), "is_admin", False)),
        )

    def can(self, permission: str) -> bool:
        """True only in account mode and with the named permission."""
        return self.accounts and permission in self.permissions

    def has(self, endpoint: str) -> bool:
        return endpoint in self.endpoints

    def url(self, endpoint: str, values: Mapping[str, object] | None = None) -> str:
        if self.link is not None:
            return self.link(endpoint, dict(values or {}))
        return url_for(endpoint, **(values or {}))


@dataclass(frozen=True, slots=True)
class Setup:
    """Checklist rows plus the counts and open state the Home template needs."""

    items: tuple[Step, ...]
    done: int
    total: int
    unknown: int
    open: bool

    @classmethod
    def from_steps(cls, steps) -> "Setup":
        items = tuple(steps)
        return cls(
            items=items,
            done=sum(item.state == "done" for item in items),
            total=len(items),
            unknown=sum(item.state == "unknown" for item in items),
            open=any(item.state in {"todo", "attention"} for item in items),
        )


def _age(value, now: datetime) -> timedelta | None:
    """Return a non-negative age, or None for unreadable and future values."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed > now:
        return None
    return now - parsed


def _failure_names(value) -> tuple[str, ...]:
    if not isinstance(value, str):
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _failed_test_detail(names) -> str:
    """One sentence naming up to three failed channels and any remainder."""
    shown = list(names)[:3]
    quoted = [f'"{name}"' for name in shown]
    if len(names) > len(shown):
        listed = ", ".join(quoted)
        return f"The last test to {listed} and {len(names) - len(shown)} more failed."
    if len(quoted) == 1:
        return f"The last test to {quoted[0]} failed."
    return f"The last test to {', '.join(quoted[:-1])} and {quoted[-1]} failed."


def _link(
    viewer: Viewer,
    permission: str | None,
    endpoint: str,
    label: str,
    hint: str | None,
    *,
    values: Mapping[str, object] | None = None,
    fallback: str | None = None,
    fallback_values: Mapping[str, object] | None = None,
    admin: bool = False,
) -> tuple[str | None, str | None, str | None]:
    """Build one action link, or return the permission hint instead.

    Endpoints from packages that may not be merged yet fall back to the page
    that already provides the same work.
    """
    allowed = viewer.is_admin if admin else viewer.can(permission or "")
    url = None
    if allowed:
        if viewer.has(endpoint):
            url = viewer.url(endpoint, values)
        elif fallback is not None and viewer.has(fallback):
            url = viewer.url(fallback, fallback_values)
    if url is not None:
        return url, label, None
    return None, None, hint if viewer.accounts and not allowed else None


def _step(
    step_id: str,
    title: str,
    state: str,
    detail: str,
    action: tuple[str | None, str | None, str | None] = (None, None, None),
) -> Step:
    if state not in STEP_STATES:
        raise ValueError(f"unknown setup step state {state!r}")
    action_url, action_label, hint = action
    return Step(step_id, title, state, detail, action_url, action_label, hint)


def _sources_step(config: AppConfig, meta, now: datetime, viewer: Viewer) -> Step:
    if not config.watch.enabled:
        return _step(
            "sources", SOURCES_TITLE, "todo",
            "Watch mode is off, so CVEBeacon is not collecting vulnerability data.",
            _link(viewer, "edit_watch", "config_editor.watch", "Turn on watch mode",
                  "Ask an administrator to turn on watch mode."),
        )
    if meta is None:
        return _step(
            "sources", SOURCES_TITLE, "unknown", WATCH_UNREADABLE,
            _link(viewer, "view", "watch.overview", "Open Watch overview", None),
        )
    initial_pending = bool(meta.get("initial_mode") and not meta.get("initial_sync_completed_at"))
    if initial_pending:
        return _step(
            "sources", SOURCES_TITLE, "todo",
            "The first sync has not finished. Run it again if it stopped.",
            _link(viewer, "run", "operations.index", "Open Operations",
                  "Ask someone who may run jobs to start the first sync."),
        )
    failures = _failure_names(meta.get("last_sync_failures"))
    if failures:
        return _step(
            "sources", SOURCES_TITLE, "attention",
            f"The last sync failed for: {', '.join(failures)}. Data may be out of date.",
            _link(viewer, "view", "watch.overview", "See sync details", None),
        )
    sources = tuple(config.watch.sources or ())
    if not sources:
        return _step(
            "sources", SOURCES_TITLE, "todo",
            "Watch mode is on, but no data source is selected.",
            _link(viewer, "edit_watch", "config_editor.watch", "Choose sources",
                  "Ask an administrator to choose data sources."),
        )
    last_sync_at = meta.get("last_sync_at")
    if not last_sync_at:
        return _step(
            "sources", SOURCES_TITLE, "todo",
            "Watch mode is on, but no data has been downloaded yet.",
            _link(viewer, "run", "operations.index", "Run the first sync",
                  "Ask someone who may run jobs to start the first sync."),
        )
    age = _age(last_sync_at, now)
    if age is None:
        return _step(
            "sources", SOURCES_TITLE, "unknown", WATCH_UNREADABLE,
            _link(viewer, "view", "watch.overview", "Open Watch overview", None),
        )
    if age > timedelta(days=STALE_SYNC_DAYS):
        return _step(
            "sources", SOURCES_TITLE, "attention",
            f"The last sync started {age.days} days ago. Data may be out of date.",
            _link(viewer, "view", "watch.overview", "See sync details", None),
        )
    return _step(
        "sources", SOURCES_TITLE, "done",
        f"Watching {len(sources)} sources. Last sync {format_timestamp(last_sync_at)}.",
    )


def _job_stamp(job) -> str:
    for value in (job.ended_at, job.started_at, job.created_at):
        if value:
            return format_timestamp(value)
    return ""


def _channel_step(config: AppConfig, jobs, viewer: Viewer) -> Step:
    enabled = tuple(channel for channel in config.watch.channels if channel.enabled)
    if not enabled:
        return _step(
            "channel", CHANNEL_TITLE, "todo", "No alert channel is set up yet.",
            _link(viewer, "edit_channels", "config_editor.channel_wizard", "Add a channel",
                  "Ask an administrator to add an alert channel.",
                  fallback="config_editor.channels"),
        )
    if jobs is None:
        return _step(
            "channel", CHANNEL_TITLE, "unknown", "Test history could not be read.",
            _link(viewer, "view", "operations.index", "Open Operations", None),
        )
    names = {channel.name for channel in enabled}
    latest = {}
    for job in jobs:
        if job.operation != "notify-test" or not job.argv:
            continue
        name = job.argv[-1]
        if name not in names:
            continue
        current = latest.get(name)
        if current is None or job.id > current.id:
            latest[name] = job

    def accepted(job) -> bool:
        return job.status == "succeeded" and job.exit_code == 0

    tested = [channel.name for channel in enabled
              if channel.name in latest and accepted(latest[channel.name])]
    failed = [channel.name for channel in enabled
              if channel.name in latest and latest[channel.name].status == "failed"]
    if tested:
        name = tested[0]
        detail = (
            f'"{name}" accepted a test message on {_job_stamp(latest[name])}. '
            "Accepted means the service took it; check that it arrived."
        )
        if len(enabled) > 1:
            detail += f" {len(tested)} of {len(enabled)} channels tested."
        if failed:
            # A failure on another channel must not be hidden by a success.
            detail += " " + _failed_test_detail(failed)
            job = latest[failed[0]]
            return _step(
                "channel", CHANNEL_TITLE, "attention", detail,
                _link(viewer, "view", "operations.channel_test_result", "Review the test", None,
                      values={"name": failed[0], "job_id": job.id},
                      fallback="operations.job_detail", fallback_values={"job_id": job.id}),
            )
        return _step("channel", CHANNEL_TITLE, "done", detail)
    if failed:
        name = failed[0]
        job = latest[name]
        return _step(
            "channel", CHANNEL_TITLE, "attention",
            f'The last test to "{name}" failed. Alerts may not reach anyone.',
            _link(viewer, "view", "operations.channel_test_result", "Review the test", None,
                  values={"name": name, "job_id": job.id},
                  fallback="operations.job_detail", fallback_values={"job_id": job.id}),
        )
    name = next((channel.name for channel in enabled if channel.name not in latest),
                enabled[0].name)
    return _step(
        "channel", CHANNEL_TITLE, "todo",
        f'Channel "{name}" is set up, but there is no recent test on record.',
        _link(viewer, "test_channel", "operations.channel_test_form", "Send a test",
              "Ask someone who may send tests.",
              values={"name": name}, fallback="operations.index"),
    )


def _rule_step(config: AppConfig, viewer: Viewer) -> Step:
    channels = {channel.name for channel in config.watch.channels if channel.enabled}
    sending = [rule for rule in config.watch.rules
               if rule.enabled and channels.intersection(rule.channels)]
    if sending:
        count = len(sending)
        detail = ("1 rule sends alerts to an enabled channel." if count == 1
                  else f"{count} rules send alerts to an enabled channel.")
        return _step("rule", RULE_TITLE, "done", detail)
    return _step(
        "rule", RULE_TITLE, "todo",
        "No enabled rule sends alerts to an enabled channel, so no alert will be delivered.",
        _link(viewer, "edit_rules", "config_editor.rules", "Create a rule",
              "Ask someone who may edit alert rules."),
    )


def _inventory_step(inventory_info: InventoryInfo | None, viewer: Viewer) -> Step:
    if inventory_info is None:
        return _step(
            "inventory", INVENTORY_TITLE, "unknown", INVENTORY_UNREADABLE,
            _link(viewer, "view", "client_inventory.index", "Open Inventory", None),
        )
    if inventory_info.exists and inventory_info.scanned > 0:
        return _step(
            "inventory", INVENTORY_TITLE, "done",
            "An inventory is available and has been scanned.",
        )
    detail = (
        "Inventory is available, but no completed scan includes its assets yet."
        if inventory_info.exists else
        "No inventory has been added yet, so there is nothing to scan."
    )
    return _step(
        "inventory", INVENTORY_TITLE, "todo", detail,
        _link(viewer, "manage_inventory", "client_inventory.inventory_add", "Add inventory",
              "Ask someone who may manage inventories."),
    )


def _schedule_step(state: str, viewer: Viewer) -> Step:
    if state in {"scan", "watch"}:
        return _step(
            "schedule", SCHEDULE_TITLE, "done",
            "A schedule is installed for this configuration. Open Schedule for the times.",
        )
    if state == "none":
        return _step(
            "schedule", SCHEDULE_TITLE, "todo",
            "Nothing is scheduled. CVEBeacon only runs when someone starts it.",
            _link(viewer, "manage_schedule", "operations.schedule", "Set a schedule",
                  "Ask an administrator to set a schedule."),
        )
    return _step(
        "schedule", SCHEDULE_TITLE, "unknown",
        "The schedule could not be checked on this server.",
        _link(viewer, "manage_schedule", "operations.schedule", "Open Schedule",
              "Ask an administrator to check the schedule."),
    )


def _backup_step(info, now: datetime, viewer: Viewer) -> Step | None:
    if not viewer.has("backups.index"):
        return None
    hint = "Ask an administrator to create a backup."
    if info is None:
        return _step(
            "backup", BACKUP_TITLE, "unknown", "Backups could not be read.",
            _link(viewer, "view", "backups.index", "Open Backups", None),
        )
    last = info.get("last")
    if not last:
        detail = "No valid backup exists yet." if info.get("count") else "No backup exists yet."
        return _step(
            "backup", BACKUP_TITLE, "todo", detail,
            _link(viewer, None, "backups.index", "Open Backups", hint, admin=True),
        )
    age = _age(last, now)
    if age is None:
        return _step(
            "backup", BACKUP_TITLE, "unknown", "Backups could not be read.",
            _link(viewer, "view", "backups.index", "Open Backups", None),
        )
    if age > timedelta(days=STALE_BACKUP_DAYS):
        return _step(
            "backup", BACKUP_TITLE, "attention", f"The newest backup is {age.days} days old.",
            _link(viewer, None, "backups.index", "Open Backups", hint, admin=True),
        )
    return _step(
        "backup", BACKUP_TITLE, "done",
        f"Last backup {format_timestamp(last)}. Use Verify on the Backups page "
        "before you rely on it.",
    )


def build_setup(
    config: AppConfig,
    *,
    meta,
    jobs,
    schedule_state: str,
    backup_info,
    now: datetime,
    viewer: Viewer,
    inventory_info: InventoryInfo | None = None,
) -> list[Step]:
    """Build the checklist from already-read state; reads nothing itself.

    ``None`` for meta, jobs, backup_info or inventory_info means the read failed
    and that step is reported as "Could not check".
    """
    steps = [
        _sources_step(config, meta, now, viewer),
        _channel_step(config, jobs, viewer),
        _rule_step(config, viewer),
        _inventory_step(inventory_info, viewer),
        _schedule_step(schedule_state, viewer),
    ]
    backup_step = _backup_step(backup_info, now, viewer)
    if backup_step is not None:
        steps.append(backup_step)
    return steps


def _watch_metadata(config: AppConfig):
    """Read watch metadata only when the database already exists."""
    if not config.watch.enabled:
        return {}
    if not Path(config.watch.database).is_file():
        return {}
    from .dashboard_watch import STATE_KEY
    state = current_app.extensions.get(STATE_KEY)
    store = state.get("store") if isinstance(state, dict) else None
    if store is None:
        return None
    try:
        return store.metadata()
    except READ_FAILURES:
        return None


def _recent_jobs():
    manager = current_app.extensions.get("dashboard_jobs")
    if manager is None:
        return None
    try:
        return manager.store.recent(MAX_HISTORY)
    except READ_FAILURES:
        return None


def _schedule_state(config: AppConfig) -> str:
    try:
        return schedule_scan_state(config)
    except READ_FAILURES:
        return "unknown"


def _backup_info(config: AppConfig, viewer: Viewer):
    if not viewer.has("backups.index"):
        return None
    try:
        return backup.summary(config)
    except READ_FAILURES:
        return None


def _completed_scan_exists(path: Path) -> bool:
    """Whether a completed scan is on record, without opening a WAL connection.

    A read-only WAL connection leaves ``-wal``/``-shm`` files beside the scan
    database. When no writer is active the main file is read immutably, which
    creates nothing; anything unclear falls through to the normal read so the
    existing error handling still applies.
    """
    for suffix in ("-wal", "-journal"):
        if Path(str(path) + suffix).exists():
            return True
    try:
        uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True, timeout=0.1)) as db:
            row = db.execute(
                "SELECT 1 FROM runs WHERE status='completed' LIMIT 1"
            ).fetchone()
            return row is not None
    except (sqlite3.Error, OSError, ValueError):
        return True


def _scan_asset_count(path: Path, run_id: str) -> int:
    sidecar = any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-journal"))
    uri = path.resolve().as_uri() + ("?mode=ro" if sidecar else "?mode=ro&immutable=1")
    with closing(sqlite3.connect(uri, uri=True, timeout=0.1)) as db:
        row = db.execute("SELECT asset_count FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        raise sqlite3.DatabaseError("completed inventory scan could not be read")
    return max(0, int(row[0]))


def _inventory_info(config: AppConfig):
    try:
        source = config.inventory
        exists = bool(source and source.path is not None and source.path.is_file())
        if config.managed_inventory and has_managed_inventory(config.inventory_directory):
            exists = True
        if source and source.web_snapshots:
            from .web_inventory import append_snapshots
            snapshots = append_snapshots([], config.database_path.parent / "web-inventory")
            exists = exists or bool(snapshots)

        path = Path(config.database_path)
        scanned = 0
        if path.is_file() and _completed_scan_exists(path):
            scan, _, _ = client_page(path, limit=1)
            if scan is None:
                raise sqlite3.DatabaseError("completed inventory scan could not be read")
            scanned = _scan_asset_count(path, scan.run_id)
        return InventoryInfo(exists=exists, scanned=scanned)
    except READ_FAILURES:
        return None


def gather(config: AppConfig, *, viewer: Viewer, now: datetime | None = None) -> Setup:
    """Read the real state once, then build the checklist."""
    steps = build_setup(
        config,
        meta=_watch_metadata(config),
        jobs=_recent_jobs(),
        schedule_state=_schedule_state(config),
        backup_info=_backup_info(config, viewer),
        inventory_info=_inventory_info(config),
        now=now or datetime.now(timezone.utc),
        viewer=viewer,
    )
    return Setup.from_steps(steps)
