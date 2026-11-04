"""Synchronise the watch database from public sources."""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Callable

from ..config import AppConfig, WatchConfig
from ..errors import CVEBeaconError, SourceError, StateError
from ..http import HttpClient, Throttle
from . import feeds
from .records import EPSS_BANDS
from .rules import rule_epss_thresholds
from .store import WatchStore

FULL_HISTORY_START = datetime(1999, 1, 1, tzinfo=timezone.utc)
NVD_REQUEST_ESTIMATE = 400
EUVD_REQUEST_ESTIMATE = 4200
LOOKUP_LIMIT = 25
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
    lookup_failures: int = 0
    error: str | None = None
    throttled: int = 0
    throttle_wait: float = 0.0


@dataclass(frozen=True, slots=True)
class SyncReport:
    summaries: tuple[SourceSummary, ...] = ()
    cancelled: bool = False
    baseline: bool = False
    touched_ids: tuple[str, ...] = ()
    initial_evaluation: bool = False

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
    hours = (
        NVD_REQUEST_ESTIMATE * interval
        + EUVD_REQUEST_ESTIMATE * feeds.EUVD_MIN_INTERVAL
    ) / 3600
    print(
        f"full history: {len(windows)} NVD window(s), roughly {NVD_REQUEST_ESTIMATE}+ NVD "
        f"requests and roughly {EUVD_REQUEST_ESTIMATE:,} EUVD requests"
    )
    print("full history also downloads 1 EPSS file per day")
    print(
        "full history takes several hours and uses a lot of bandwidth "
        f"(about {hours:.0f} hour(s) at the current pacing)"
    )
    if assume_yes:
        return True
    if confirm is _confirm:
        try:
            interactive = sys.stdin.isatty()
        except (AttributeError, ValueError):
            interactive = False
        if not interactive:
            print(
                "full history requires confirmation: run 'cvebeacon watch sync "
                "--yes' once first, or pass --yes."
            )
            return False
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
    sleep: Callable[[float], None] = time.sleep,
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
    initial_evaluation = (
        metadata.get("initial_mode") in ("backfill", "full")
        and "initial_evaluated_at" not in metadata
    ) or (first_run and mode in ("backfill", "full"))
    interval = config.sources.minimum_request_interval
    catalogs = tuple(watch.sources)
    policy_touched = store.apply_view_policy(catalogs)

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
    lookup_since = None if mode == "full" else initial_window_start.isoformat()
    cursor_value = metadata.get("nvd_cursor")
    if cursor_value and now - _cursor_time(cursor_value) > LONG_GAP:
        print(
            "warning: the NVD cursor is more than 120 days old; "
            "catching up in bounded windows"
        )

    api_key = config.nvd_api_key()
    nvd_before = http.requests
    nvd_records = nvd_new = nvd_changed = 0
    lookup_failures = 0
    touched: set[str] = set(policy_touched)
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
        counts = store.upsert_nvd(feed.records, meta=meta, catalogs=catalogs)
        nvd_records += len(feed.records)
        nvd_new += counts.new
        nvd_changed += counts.changed
        touched.update(counts.touched_ids)

    if initial_run and first_commit:
        meta = {
            "nvd_cursor": nvd_end.isoformat(),
            "initial_mode": mode,
            "initial_window_start": initial_window_start.isoformat(),
            "initialized_at": initialized_at,
        }
        if "euvd" in watch.sources and "euvd_cursor" not in metadata:
            meta["euvd_cursor"] = intended_euvd_start.isoformat()
        store.set_metadata(meta)

    nvd_requests = http.requests - nvd_before

    throttle = Throttle(sleep=sleep)

    if "euvd" in watch.sources:
        euvd_before = http.requests
        euvd_throttled_before = throttle.count
        euvd_waited_before = throttle.waited
        euvd_records = euvd_new = euvd_changed = euvd_ignored = 0
        euvd_error: str | None = None
        euvd_cursor = _cursor_date(metadata.get("euvd_cursor"))
        pending_chunks = list(reversed(feeds.euvd_chunks(euvd_start, today)))
        while pending_chunks:
            chunk_start, chunk_end = pending_chunks.pop()
            try:
                feed = feeds.fetch_euvd(
                    http,
                    start=chunk_start,
                    end=chunk_end,
                    throttle=throttle,
                )
            except SourceError as exc:
                euvd_error = str(exc)
                break
            if feed.split:
                span = (chunk_end - chunk_start).days
                middle = chunk_start + timedelta(days=span // 2)
                pending_chunks.append((middle + timedelta(days=1), chunk_end))
                pending_chunks.append((chunk_start, middle))
                continue
            cursor_day = (
                chunk_end
                if euvd_cursor is None
                else max(euvd_cursor, chunk_end)
            )
            counts = store.replace_euvd_items(
                feed.updates,
                meta={"euvd_cursor": cursor_day.isoformat()},
                catalogs=catalogs,
            )
            euvd_cursor = cursor_day
            euvd_records += len(feed.updates)
            euvd_new += counts.new
            euvd_changed += counts.changed
            euvd_ignored += feed.ignored
            touched.update(counts.touched_ids)
        summaries.append(
            SourceSummary(
                "euvd",
                http.requests - euvd_before,
                euvd_records,
                euvd_new,
                euvd_changed,
                ignored=euvd_ignored,
                error=euvd_error,
                throttled=throttle.count - euvd_throttled_before,
                throttle_wait=throttle.waited - euvd_waited_before,
            )
        )

    store.prune_euvd(now=now)

    if "cisa_kev" in watch.sources:
        cisa_before = http.requests
        try:
            cisa = feeds.fetch_kev(http)
        except SourceError as exc:
            summaries.append(
                SourceSummary(
                    "cisa_kev", http.requests - cisa_before, error=str(exc)
                )
            )
        else:
            counts = store.replace_kev("cisa", cisa, catalogs=catalogs)
            touched.update(counts.touched_ids)
            summaries.append(
                SourceSummary(
                    "cisa_kev",
                    http.requests - cisa_before,
                    len(cisa),
                    counts.new,
                    counts.changed,
                )
            )

    if "eu_kev" in watch.sources:
        eu_before = http.requests
        eu_throttled_before = throttle.count
        eu_waited_before = throttle.waited
        try:
            eu = feeds.fetch_kev(http, eu=True, throttle=throttle)
        except SourceError as exc:
            summaries.append(
                SourceSummary(
                    "eu_kev",
                    http.requests - eu_before,
                    error=str(exc),
                    throttled=throttle.count - eu_throttled_before,
                    throttle_wait=throttle.waited - eu_waited_before,
                )
            )
        else:
            counts = store.replace_kev("eu", eu, catalogs=catalogs)
            touched.update(counts.touched_ids)
            summaries.append(
                SourceSummary(
                    "eu_kev",
                    http.requests - eu_before,
                    len(eu),
                    counts.new,
                    counts.changed,
                    throttled=throttle.count - eu_throttled_before,
                    throttle_wait=throttle.waited - eu_waited_before,
                )
            )

    store.sync_lookups(
        [source for source in watch.sources if source in ("cisa_kev", "eu_kev")],
        initial_window_start=lookup_since,
        now=now,
        include_euvd="euvd" in watch.sources,
    )
    lookup_before = http.requests
    for row in store.due_lookups(now=now, limit=LOOKUP_LIMIT):
        try:
            result = feeds.fetch_nvd_cve(
                http, row.cve_id, api_key=api_key, interval=interval
            )
        except SourceError as exc:
            store.lookup_failed(row.cve_id, error=str(exc), now=now)
            lookup_failures += 1
            continue
        counts = store.upsert_nvd([result.record], catalogs=catalogs)
        nvd_records += 1
        nvd_new += counts.new
        nvd_changed += counts.changed
        touched.update(counts.touched_ids)

    nvd_requests += http.requests - lookup_before

    summaries.insert(
        0,
        SourceSummary(
            "nvd",
            nvd_requests,
            nvd_records,
            nvd_new,
            nvd_changed,
            lookup_failures=lookup_failures,
        ),
    )

    if "epss" in watch.sources:
        epss_before = http.requests
        epss_records = epss_changed = 0
        epss_error: str | None = None
        stored_day = _stored_date(metadata.get("epss_file_day"), "EPSS file day")
        if stored_day is None or stored_day < today:
            counter = [0]
            fallback = stored_day is None or stored_day < today - timedelta(days=1)
            thresholds = set(EPSS_BANDS)
            thresholds.update(rule_epss_thresholds(watch.rules))
            try:
                result = store.replace_epss(
                    feeds.fetch_epss_daily(
                        http,
                        today=today,
                        counter=counter,
                        fallback=fallback,
                    ),
                    thresholds=thresholds,
                )
            except SourceError as exc:
                if not fallback and exc.status_code in (403, 404):
                    pass
                else:
                    epss_error = str(exc)
            else:
                epss_records = result.rows
                epss_changed = len(result.changed_ids)
                touched.update(result.changed_ids)
        summaries.append(
            SourceSummary(
                "epss",
                http.requests - epss_before,
                epss_records,
                changed=epss_changed,
                error=epss_error,
            )
        )

    report = SyncReport(
        summaries=tuple(summaries),
        touched_ids=tuple(sorted(touched)),
        initial_evaluation=initial_evaluation,
    )
    if initial_evaluation and not report.failures:
        store.set_metadata({"initial_sync_completed_at": now.isoformat()})
    return report


def watch_status(watch: WatchConfig) -> str:
    _require_enabled(watch)
    store = WatchStore(watch.database)
    status = store.status(catalogs=watch.sources)
    meta = status["meta"]
    lines = [
        f"database: {status['database']}",
        f"schema version: {meta.get('schema_version', 'unknown')}",
        f"nvd cursor: {meta.get('nvd_cursor', 'not set')}",
        f"euvd cursor: {meta.get('euvd_cursor', 'not set')}",
        f"epss score date: {status['epss_date'] or 'not set'}",
        f"rows: {status['rows']}",
        f"euvd items: {status['euvd_items']}",
        f"KEV catalog entries: CISA {status['cisa_kev']}, EU {status['eu_kev']}",
        f"watched CVEs in KEV: {status['any_watched']} "
        f"(CISA {status['cisa_watched']}, EU {status['eu_watched']})",
        f"with active SSVC: {status['active_ssvc']}",
        f"with EPSS: {status['epss_rows']}",
        f"lookups pending/backing off: {status['lookups']}",
    ]
    for row in store.delivery_status(channel.name for channel in watch.channels):
        lines.append(
            f"channel {row.channel}: pending {row.pending}, "
            f"failed {row.failed} ({row.given_up} given up), "
            f"ambiguous {row.ambiguous}, sending {row.sending}, last success "
            f"{row.last_success or 'never'}"
        )
    return "\n".join(lines)
