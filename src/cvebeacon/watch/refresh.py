"""Refresh exactly one public CVE and evaluate its rules without a full sync."""
from __future__ import annotations

from datetime import datetime, timezone
import json

from ..errors import SourceError
from ..sources.cve_list import CVEListSource
from ..sources.epss import EPSSSource
from ..sources.euvd import SEARCH_URL
from . import feeds
from .records import EUVDUpdate, WatchRecord, euvd_datetime
from ..sources.common import source_payload
from .reported import normalize_cve_id
from .store import WatchStore
from .sync import SourceSummary, SyncReport, _require_enabled


class _LookupHTTP:
    """Cap CVE List records at 4 MiB and other lookup/catalog replies at 8 MiB."""
    def __init__(self, http):
        self.http = http

    @property
    def requests(self):
        return self.http.requests

    def get_json(self, url, *, source, **kwargs):
        allowed = {key: value for key, value in kwargs.items()
                   if key in {"params", "headers", "minimum_interval"}}
        cap = 4 * 1024 * 1024 if source == "cve_list" else 8 * 1024 * 1024
        raw = b"".join(self.http.stream_bytes(url, source=source, byte_cap=cap, **allowed))
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise SourceError(source, "source returned invalid JSON") from exc


@source_payload("euvd")
def _euvd_updates(payload, identifier):
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list) or type(payload.get("total")) is not int or payload["total"] != len(payload["items"]) or len(payload["items"]) > 100:
        raise SourceError("euvd", "invalid or incomplete per-ID result")
    updates = []
    for item in payload["items"]:
        aliases = tuple(value for raw in feeds._alias_values(item.get("aliases")) if (value := feeds.cve_id(raw)))
        if identifier not in aliases:
            continue
        cvss, _ = feeds._euvd_cvss(item)
        updates.append(EUVDUpdate(aliases, item.get("id"), item.get("exploitedSince"), cvss,
                                  euvd_datetime(item.get("dateUpdated")), feeds._euvd_vendors(item)))
    return updates


def refresh_watch(config, http, identifier):
    identifier = normalize_cve_id(identifier)
    _require_enabled(config.watch)
    http = _LookupHTTP(http)
    store = WatchStore(config.watch.database)
    store.initialize()
    summaries = []
    catalogs = config.watch.sources
    for source in catalogs:
        before = http.requests
        records = new = changed = 0
        error = None
        try:
            if source == "nvd":
                result = feeds.fetch_nvd_cve(http, identifier, api_key=config.nvd_api_key(), interval=config.sources.minimum_request_interval)
                counts = store.upsert_nvd([result.record], catalogs=catalogs)
                new, changed = counts.new, counts.changed
                records = 1
            elif source == "cve_list":
                payload = CVEListSource(http).record(identifier)
                counts = store.upsert_cve_list([payload], catalogs=catalogs)
                new, changed = counts.new, counts.changed
                records = 1
            elif source == "euvd":
                payload = http.get_json(SEARCH_URL, source="euvd", params={"text": identifier, "page": 0, "size": 100}, minimum_interval=feeds.EUVD_MIN_INTERVAL)
                updates = _euvd_updates(payload, identifier)
                counts = store.upsert_euvd_cve(identifier, updates, catalogs=catalogs)
                new, changed = counts.new, counts.changed
                records = len(updates)
                if updates:
                    best = max(updates, key=lambda item: item.rank())
                    raw = next(item for item in payload["items"] if item.get("id") == best.euvd_id)
                    record = WatchRecord(identifier, "published",
                                         euvd_datetime(raw.get("datePublished")), best.date_updated,
                                         str(raw.get("description") or "") or None)
                    counts = store.upsert_discovered("euvd", record, payload=raw, catalogs=catalogs)
                    new, changed = counts.new, counts.changed
            elif source == "epss":
                scores = EPSSSource(http).scores([identifier])
                with store.transaction() as db:
                    if identifier in scores:
                        score, percentile, day = scores[identifier]
                        db.execute("INSERT OR REPLACE INTO watch_epss VALUES (?,?,?,?)", (identifier, score, percentile, day.isoformat()))
                        records = 1
                    else:
                        db.execute("DELETE FROM watch_epss WHERE cve_id=?", (identifier,))
            elif source in {"cisa_kev", "eu_kev"}:
                # These public catalogs have no per-ID endpoint. Download a
                # bounded catalog and modify only this CVE's normalized row.
                catalog = "eu" if source == "eu_kev" else "cisa"
                fields = feeds.fetch_kev(http, eu=catalog == "eu")
                entry = fields.get(identifier)
                with store.transaction() as db:
                    db.execute("DELETE FROM watch_kev WHERE catalog=? AND cve_id=?", (catalog, identifier))
                    if entry is not None:
                        db.execute("INSERT INTO watch_kev VALUES (?,?,?,?,?,?)",
                                   (catalog, identifier, entry.added, entry.due, entry.required_action, entry.ransomware))
                        records = 1
                if entry is not None:
                    record = WatchRecord(identifier, "published", last_modified=entry.added)
                    counts = store.upsert_discovered(source, record,
                        payload={"added": entry.added, "due": entry.due,
                                 "required_action": entry.required_action, "ransomware": entry.ransomware},
                        catalogs=catalogs)
                    new, changed = counts.new, counts.changed
        except SourceError as exc:
            if exc.status_code != 404 or source not in {"nvd", "cve_list"}:
                error = str(exc)
        summary = SourceSummary(source, http.requests - before, records, new, changed, error=error)
        summaries.append(summary)
        # A targeted lookup does not advance any complete-feed cursor.
        with store.transaction() as db:
            db.execute("INSERT OR REPLACE INTO watch_source_check VALUES (?,?,?,?,?)",
                       (identifier, source, None if error else int(records > 0),
                        datetime.now(timezone.utc).isoformat(), error))
    result = store.evaluate_one(identifier, config.watch.rules, catalogs=catalogs)
    return SyncReport(tuple(summaries), touched_ids=(identifier,)), result
