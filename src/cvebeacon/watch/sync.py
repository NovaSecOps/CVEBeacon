"""Synchronise the watch database from public sources."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Callable

from ..config import AppConfig, WatchConfig
from ..errors import CVEBeaconError, SourceError, StateError
from ..http import HttpClient
from . import feeds
from .store import WatchStore

FULL_HISTORY_START = datetime(1999, 1, 1, tzinfo=timezone.utc)
NVD_REQUEST_ESTIMATE = 400
EUVD_REQUEST_ESTIMATE = 4200
EPSS_MISSING_LIMIT = 1000
PENDING_LIMIT = 25
LONG_GAP = timedelta(days=feeds.NVD_WINDOW_DAYS)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class SourceSummary:
    source: str
    requests: int = 0
    records: int = 0
    new: int = 0
    changed: int = 0
    ignored: int = 0
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SyncReport:
    summaries: tuple[SourceSummary, ...] = ()
    cancelled: bool = False
    baseline: bool = False

    @property
    def failures(self) -> tuple[str, ...]:
        return tuple(summary.source for summary in self.summaries if summary.error)


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _require_enabled(watch: WatchConfig) -> None:
    if not watch.enabled:
        raise CVEBeaconError("watch mode is disabled; set [watch] enabled = true")


def _cursor_time(value: str | None) -> datetime:
    if not value:
        raise StateError("watch database has no NVD cursor")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise StateError("watch database has an invalid NVD cursor") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _cursor_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise StateError("watch database has an invalid EUVD cursor") from exc


def _stored_date(value: str | None, label: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise StateError(f"watch database has an invalid {label}") from exc


def _confirm_full_history(
    start: datetime,
    now: datetime,
    *,
    assume_yes: bool,
    confirm: Callable[[str], bool],
    interval: float,
) -> bool:
    windows = feeds.nvd_windows(start, now)
    hours = (NVD_REQUEST_ESTIMATE + EUVD_REQUEST_ESTIMATE) * interval / 3600
    print(
        f"full history: {len(windows)} NVD window(s), roughly {NVD_REQUEST_ESTIMATE}+ NVD "
        f"requests and roughly {EUVD_REQUEST_ESTIMATE:,} EUVD requests"
    )
    print(
        "full history takes several hours and uses a lot of bandwidth "
        f"(about {hours:.0f} hour(s) at the current pacing)"
    )
    if assume_yes:
        return True
    return confirm("Synchronise the full NVD history? [y/N] ")


def _confirm(message: str) -> bool:
    try:
        return input(message).strip().casefold() in {"y", "yes"}
    except EOFError:
        return False


def sync_watch(
    config: AppConfig,
    http: HttpClient,
    *,
    assume_yes: bool = False,
    clock: Callable[[], datetime] = _utc_now,
    confirm: Callable[[str], bool] = _confirm,
) -> SyncReport:
    watch = config.watch
    _require_enabled(watch)
    store = WatchStore(watch.database, clock=clock)
    metadata = store.metadata()
    now = _clock_value(clock)
    today = now.date()
    first_run = "initialized_at" not in metadata
    stored_mode = metadata.get("initial_mode")
    mode = stored_mode or (watch.initial if first_run else "baseline")
    interval = config.sources.minimum_request_interval

    if first_run and stored_mode is None and watch.initial == "baseline":
        store.record_baseline(
            nvd_cursor=now.isoformat(),
            initialized_at=now.isoformat(),
            euvd_cursor=today.isoformat() if "euvd" in watch.sources else None,
            initial_window_start=today.isoformat(),
        )
        return SyncReport(
            summaries=tuple(SourceSummary(source) for source in watch.sources),
            baseline=True,
        )

    initial_run = first_run
    if initial_run:
        if mode == "baseline":
            store.record_baseline(
                nvd_cursor=now.isoformat(),
                initialized_at=now.isoformat(),
                euvd_cursor=today.isoformat() if "euvd" in watch.sources else None,
                initial_window_start=today.isoformat(),
            )
            return SyncReport(
                summaries=tuple(SourceSummary(source) for source in watch.sources),
                baseline=True,
            )
        resumed = metadata.get("nvd_cursor") is not None
        if resumed:
            nvd_start = _cursor_time(metadata.get("nvd_cursor"))
        elif mode == "backfill":
            nvd_start = now - timedelta(days=watch.backfill_days)
        else:
            nvd_start = FULL_HISTORY_START
            if not _confirm_full_history(
                nvd_start,
                now,
                assume_yes=assume_yes,
                confirm=confirm,
                interval=interval,
            ):
                return SyncReport(cancelled=True)
        intended_euvd_start = (
            today - timedelta(days=watch.backfill_days)
            if mode == "backfill"
            else FULL_HISTORY_START.date()
        )
        euvd_start = _cursor_date(metadata.get("euvd_cursor")) or intended_euvd_start
        nvd_end = now
        initialized_at = now.isoformat()
    else:
        nvd_start = _cursor_time(metadata.get("nvd_cursor")) - timedelta(
            minutes=watch.overlap_minutes
        )
        nvd_end = now
        euvd_start = _cursor_date(metadata.get("euvd_cursor")) or today
        initialized_at = metadata.get("initialized_at") or now.isoformat()

    euvd_start = min(euvd_start, today)
    initial_window_start = _stored_date(
        metadata.get("initial_window_start"), "initial window start"
    )
    if initial_window_start is None:
        initial_date = _cursor_time(
            metadata.get("initialized_at") or initialized_at
        ).date()
        if mode == "backfill":
            initial_window_start = initial_date - timedelta(days=watch.backfill_days)
        elif mode == "full":
            initial_window_start = FULL_HISTORY_START.date()
        else:
            initial_window_start = initial_date
    kev_pending_since = (
        None if mode == "full" else initial_window_start.isoformat()
    )
    cursor_value = metadata.get("nvd_cursor")
    if cursor_value and now - _cursor_time(cursor_value) > LONG_GAP:
        print(
            "warning: the NVD cursor is more than 120 days old; "
            "catching up in bounded windows"
        )

    api_key = config.secret(config.sources.nvd_api_key_env)
    nvd_requests = nvd_records = nvd_new = nvd_changed = 0
    alert_ids: set[str] = set()
    summaries: list[SourceSummary] = []
    pending_windows = list(reversed(feeds.nvd_windows(nvd_start, nvd_end)))
    first_commit = True
    while pending_windows:
        window_start, window_end = pending_windows.pop()
        feed = feeds.fetch_nvd_window(
            http,
            start=window_start,
            end=window_end,
            api_key=api_key,
            interval=interval,
        )
        nvd_requests += feed.requests
        if feed.split:
            middle = window_start + (window_end - window_start) / 2
            pending_windows.append((middle, window_end))
            pending_windows.append((window_start, middle))
            continue
        window_cursor = window_end
        if feed.timestamp is not None:
            window_cursor = min(window_end, feed.timestamp)
        meta = {"nvd_cursor": window_cursor.isoformat()}
        if first_commit and initial_run:
            meta["initial_mode"] = mode
            meta["initial_window_start"] = initial_window_start.isoformat()
            if "euvd" in watch.sources and "euvd_cursor" not in metadata:
                meta["euvd_cursor"] = intended_euvd_start.isoformat()
        first_commit = False
        if initial_run and not pending_windows:
            meta["initialized_at"] = initialized_at
            meta["initial_complete"] = "true"
        counts = store.upsert(
            feed.records,
            meta=meta,
            cisa_kev_configured="cisa_kev" in watch.sources,
        )
        nvd_records += len(feed.records)
        nvd_new += counts.new
        nvd_changed += counts.changed
        alert_ids.update(counts.new_ids)
        alert_ids.update(counts.changed_ids)

    if initial_run and first_commit:
        meta = {
            "nvd_cursor": nvd_end.isoformat(),
            "initial_mode": mode,
            "initial_window_start": initial_window_start.isoformat(),
            "initialized_at": initialized_at,
            "initial_complete": "true",
        }
        if "euvd" in watch.sources and "euvd_cursor" not in metadata:
            meta["euvd_cursor"] = intended_euvd_start.isoformat()
        store.set_metadata(meta)

    if "euvd" in watch.sources:
        euvd_requests = euvd_records = euvd_new = euvd_changed = euvd_ignored = 0
        euvd_error: str | None = None
        for chunk_start, chunk_end in feeds.euvd_chunks(euvd_start, today):
            try:
                feed = feeds.fetch_euvd(http, start=chunk_start, end=chunk_end)
            except SourceError as exc:
                euvd_error = str(exc)
                break
            counts = store.apply_euvd(
                feed.updates, meta={"euvd_cursor": chunk_end.isoformat()}
            )
            euvd_requests += feed.requests
            euvd_records += len(feed.updates)
            euvd_new += counts.new
            euvd_changed += counts.changed
            euvd_ignored += feed.ignored
            alert_ids.update(counts.new_ids)
            alert_ids.update(counts.changed_ids)
        summaries.append(
            SourceSummary(
                "euvd",
                euvd_requests,
                euvd_records,
                euvd_new,
                euvd_changed,
                ignored=euvd_ignored,
                error=euvd_error,
            )
        )

    cisa_catalog = None
    eu_catalog = None
    if "cisa_kev" in watch.sources:
        try:
            cisa = feeds.fetch_kev(http)
        except SourceError as exc:
            summaries.append(SourceSummary("cisa_kev", error=str(exc)))
        else:
            cisa_catalog = cisa
            counts = store.apply_kev(
                cisa, {}, clear_cisa=True, pending_since=kev_pending_since
            )
            alert_ids.update(counts.new_ids)
            alert_ids.update(counts.changed_ids)
            summaries.append(
                SourceSummary("cisa_kev", 1, len(cisa), counts.new, counts.changed)
            )

    if "eu_kev" in watch.sources:
        try:
            eu = feeds.fetch_kev(http, eu=True)
        except SourceError as exc:
            summaries.append(SourceSummary("eu_kev", error=str(exc)))
        else:
            eu_catalog = eu
            counts = store.apply_kev(
                {}, eu, clear_eu=True, pending_since=kev_pending_since
            )
            alert_ids.update(counts.new_ids)
            alert_ids.update(counts.changed_ids)
            summaries.append(SourceSummary("eu_kev", 1, len(eu), counts.new, counts.changed))

    store.expire_pending(now=now)
    for row in store.pending(limit=PENDING_LIMIT):
        try:
            result = feeds.fetch_nvd_cve(
                http, row.cve_id, api_key=api_key, interval=interval
            )
        except SourceError:
            store.pending_attempt(row.cve_id)
            continue
        nvd_requests += result.requests
        counts = store.upsert(
            [result.record],
            cisa_kev_configured="cisa_kev" in watch.sources,
            cisa_catalog=cisa_catalog,
            eu_catalog=eu_catalog,
        )
        store.drop_pending(row.cve_id)
        nvd_records += 1
        nvd_new += counts.new
        nvd_changed += counts.changed
        alert_ids.update(counts.new_ids)
        alert_ids.update(counts.changed_ids)

    summaries.insert(0, SourceSummary("nvd", nvd_requests, nvd_records, nvd_new, nvd_changed))

    if "epss" in watch.sources:
        try:
            identifiers = set(alert_ids)
            identifiers.update(store.epss_without_date(limit=EPSS_MISSING_LIMIT))
            floor_due = metadata.get("epss_floor_date") != today.isoformat()
            floor_scores: dict[str, tuple[float, float, date]] = {}
            requests = 0
            if floor_due:
                floor_scores, floor_requests = feeds.fetch_epss_floor(
                    http, floor=watch.epss_floor
                )
                requests += floor_requests
                stale = set(store.epss_at_or_above_floor(watch.epss_floor)) - set(
                    floor_scores
                )
                identifiers.update(stale)
            scores, batch_requests = feeds.fetch_epss_scores(http, identifiers)
            requests += batch_requests
            merged = {**floor_scores, **scores}
            counts = store.apply_epss(
                merged,
                meta={"epss_floor_date": today.isoformat()} if floor_due else None,
            )
            summaries.append(
                SourceSummary(
                    "epss",
                    requests,
                    len(merged),
                    counts.new,
                    counts.changed,
                )
            )
        except SourceError as exc:
            summaries.append(SourceSummary("epss", error=str(exc)))

    return SyncReport(summaries=tuple(summaries))


def watch_status(watch: WatchConfig) -> str:
    _require_enabled(watch)
    status = WatchStore(watch.database).status(epss_floor=watch.epss_floor)
    meta = status["meta"]
    lines = [
        f"database: {status['database']}",
        f"schema version: {meta.get('schema_version', 'unknown')}",
        f"nvd cursor: {meta.get('nvd_cursor', 'not set')}",
        f"euvd cursor: {meta.get('euvd_cursor', 'not set')}",
        f"epss floor date: {meta.get('epss_floor_date', 'not set')}",
        f"rows: {status['rows']}",
        f"with KEV: {status['any_kev']} (CISA {status['cisa_kev']}, EU {status['eu_kev']})",
        f"with active SSVC: {status['active_ssvc']}",
        f"with EPSS above {watch.epss_floor:g}: {status['epss_above']}",
    ]
    return "\n".join(lines)
