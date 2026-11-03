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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class SourceSummary:
    source: str
    requests: int = 0
    records: int = 0
    new: int = 0
    changed: int = 0
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


def _confirm_full_history(
    start: datetime,
    now: datetime,
    *,
    assume_yes: bool,
    confirm: Callable[[str], bool],
) -> bool:
    windows = feeds.nvd_windows(start, now)
    print(
        f"full history: {len(windows)} NVD window(s), estimated at least {len(windows)} request(s)"
    )
    print("full history takes a long time and uses a lot of bandwidth")
    if assume_yes:
        return True
    return confirm("Synchronise the full NVD history? [y/N] ")


def _confirm(message: str) -> bool:
    return input(message).strip().casefold() in {"y", "yes"}


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
    summaries: list[SourceSummary] = []

    if first_run and watch.initial == "baseline":
        store.record_baseline(
            nvd_cursor=now.isoformat(),
            initialized_at=now.isoformat(),
            euvd_cursor=today.isoformat() if "euvd" in watch.sources else None,
        )
        return SyncReport(
            summaries=tuple(SourceSummary(source) for source in watch.sources),
            baseline=True,
        )

    if first_run:
        if watch.initial == "backfill":
            nvd_start = now - timedelta(days=watch.backfill_days)
            euvd_start = today - timedelta(days=watch.backfill_days)
        else:
            nvd_start = FULL_HISTORY_START
            euvd_start = FULL_HISTORY_START.date()
            if not _confirm_full_history(
                nvd_start, now, assume_yes=assume_yes, confirm=confirm
            ):
                return SyncReport(cancelled=True)
        nvd_end = now
        initialized_at = now.isoformat()
    else:
        nvd_start = _cursor_time(metadata.get("nvd_cursor")) - timedelta(
            minutes=watch.overlap_minutes
        )
        nvd_end = now
        initialized_at = metadata.get("initialized_at") or now.isoformat()
        euvd_start = _cursor_date(metadata.get("euvd_cursor")) or today
        euvd_start = min(euvd_start, today)

    api_key = config.secret(config.sources.nvd_api_key_env)
    nvd = feeds.fetch_nvd(
        http,
        start=nvd_start,
        end=nvd_end,
        api_key=api_key,
        interval=config.sources.minimum_request_interval,
    )
    counts = store.upsert(
        nvd.records,
        meta={"nvd_cursor": nvd_end.isoformat(), "initialized_at": initialized_at},
    )
    alert_ids = set(counts.new_ids) | set(counts.changed_ids)
    summaries.append(
        SourceSummary(
            "nvd", nvd.requests, len(nvd.records), counts.new, counts.changed
        )
    )

    if "euvd" in watch.sources:
        try:
            euvd = feeds.fetch_euvd(http, start=euvd_start, end=today)
        except SourceError as exc:
            summaries.append(SourceSummary("euvd", error=str(exc)))
        else:
            counts = store.apply_euvd(
                euvd.updates, meta={"euvd_cursor": today.isoformat()}
            )
            alert_ids.update(counts.new_ids)
            alert_ids.update(counts.changed_ids)
            summaries.append(
                SourceSummary(
                    "euvd",
                    euvd.requests,
                    len(euvd.updates),
                    counts.new,
                    counts.changed,
                )
            )

    if "cisa_kev" in watch.sources:
        try:
            cisa = feeds.fetch_kev(http)
        except SourceError as exc:
            summaries.append(SourceSummary("cisa_kev", error=str(exc)))
        else:
            counts = store.apply_kev(cisa, {})
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
            counts = store.apply_kev({}, eu)
            alert_ids.update(counts.new_ids)
            alert_ids.update(counts.changed_ids)
            summaries.append(
                SourceSummary("eu_kev", 1, len(eu), counts.new, counts.changed)
            )

    if "epss" in watch.sources:
        try:
            scores, requests = feeds.fetch_epss_scores(http, alert_ids)
            floor_scores: dict[str, tuple[float, float, date]] = {}
            floor_due = metadata.get("epss_floor_date") != today.isoformat()
            if floor_due:
                floor_scores, floor_requests = feeds.fetch_epss_floor(
                    http, floor=watch.epss_floor
                )
                requests += floor_requests
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
        f"with EPSS >= {watch.epss_floor:g}: {status['epss_above']}",
    ]
    return "\n".join(lines)
