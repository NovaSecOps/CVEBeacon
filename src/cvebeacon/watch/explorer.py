"""Bounded local CVE search and source provenance."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from ..errors import StateError
from ..sources.common import cve_id

SOURCES = ("nvd", "euvd", "cve_list", "cisa_kev", "eu_kev", "epss")
MAX_QUERY = 256


@dataclass(frozen=True)
class SearchResult:
    records: tuple
    total: int
    fts: bool = False


def search(store, *, query="", source="", kev="", severity="", since=None, until=None,
           has_events="", reported="", client_ids=None, sort="modified", limit=50, offset=0,
           use_fts=True, catalogs=SOURCES):
    if not isinstance(query, str) or len(query) > MAX_QUERY:
        raise StateError("Search must be at most 256 characters")
    query = query.strip()
    limit = max(1, min(int(limit), 100))
    offset = max(0, min(int(offset), 5_000_000))
    store.initialize()
    with store.transaction() as db:
        where, values = [], []
        identifier = cve_id(query)
        fts = False
        if query:
            if identifier:
                where.append("c.cve_id=?")
                values.append(identifier)
            else:
                tokens = re.findall(r"\w+", query, re.UNICODE)[:32]
                fts = bool(use_fts and tokens and db.execute("SELECT 1 FROM sqlite_master WHERE name='watch_fts'").fetchone())
                if fts:
                    where.append("c.cve_id IN (SELECT cve_id FROM watch_fts WHERE watch_fts MATCH ?)")
                    values.append(' AND '.join('"' + token + '"*' for token in tokens))
                else:
                    where.append("c.cve_id IN (SELECT cve_id FROM watch_search WHERE text LIKE ? ESCAPE '\\')")
                    values.append('%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
        presence = {
            "nvd": "EXISTS(SELECT 1 FROM watch_provider p WHERE p.cve_id=c.cve_id AND p.source='nvd')",
            "cve_list": "EXISTS(SELECT 1 FROM watch_provider p WHERE p.cve_id=c.cve_id AND p.source='cve_list')",
            "euvd": "EXISTS(SELECT 1 FROM watch_euvd_alias a WHERE a.cve_id=c.cve_id)",
            "epss": "EXISTS(SELECT 1 FROM watch_epss e WHERE e.cve_id=c.cve_id)",
            "cisa_kev": "EXISTS(SELECT 1 FROM watch_kev k WHERE k.cve_id=c.cve_id AND k.catalog='cisa')",
            "eu_kev": "EXISTS(SELECT 1 FROM watch_kev k WHERE k.cve_id=c.cve_id AND k.catalog='eu')",
        }
        if source:
            if source not in presence:
                raise StateError("Unknown source filter")
            where.append(presence[source])
        kev_sql = "(" + presence['cisa_kev'] + " OR " + presence['eu_kev'] + " OR c.cisa_kev_added IS NOT NULL)"
        score = "max(COALESCE((SELECT max(json_extract(j.value,'$.score')) FROM json_each(c.cvss_json) j),-1),COALESCE((SELECT max(i.score) FROM watch_euvd_item i JOIN watch_euvd_alias a ON a.euvd_id=i.euvd_id WHERE a.cve_id=c.cve_id),-1))"
        if kev in ("yes", "no"):
            where.append(("NOT " if kev == "no" else "") + kev_sql)
        if severity:
            bands = {"critical": (9, 10.1), "high": (7, 9), "medium": (4, 7), "low": (0.1, 4), "none": (0, 0.1), "unknown": (-1, 0)}
            if severity not in bands:
                raise StateError("Unknown severity filter")
            low, high = bands[severity]
            where.append(f"{score} >= ? AND {score} < ?")
            values.extend((low, high))
        for bound, operator in ((since, ">="), (until, "<=")):
            if bound:
                where.append(f"substr(c.published,1,10) {operator} ?")
                values.append(bound.isoformat())
        for value, sql in ((has_events, "EXISTS(SELECT 1 FROM watch_event e WHERE e.cve_id=c.cve_id)"),
                           (reported, "EXISTS(SELECT 1 FROM watch_report r WHERE r.cve_id=c.cve_id AND r.action='report' AND NOT EXISTS(SELECT 1 FROM watch_report newer WHERE newer.cve_id=r.cve_id AND newer.id>r.id))")):
            if value in ("yes", "no"):
                where.append(("NOT " if value == "no" else "") + sql)
        if client_ids is not None:
            # A bounded temporary table avoids SQLite's parameter limit and
            # leaves client identities entirely in the local scan database.
            db.execute("CREATE TEMP TABLE selected_cves(cve_id TEXT PRIMARY KEY)")
            db.executemany("INSERT OR IGNORE INTO selected_cves VALUES (?)", ((i,) for i in client_ids))
            where.append("c.cve_id IN (SELECT cve_id FROM selected_cves)")
        orders = {"published": "c.published", "modified": "c.last_modified", "cvss": score,
                  "epss": "(SELECT epss FROM watch_epss e WHERE e.cve_id=c.cve_id)", "kev": kev_sql}
        if sort not in orders:
            raise StateError("Unknown sort order")
        condition = " WHERE " + " AND ".join(where) if where else ""
        total = db.execute("SELECT count(*) FROM watch_cve c" + condition, values).fetchone()[0]
        rows = db.execute("SELECT c.cve_id FROM watch_cve c" + condition + " ORDER BY " + orders[sort] + " DESC,c.cve_id DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
        return SearchResult(tuple(store._view(db, row[0], catalogs) for row in rows), total, fts)


def source_presence(store, identifier):
    store.initialize()
    with store.transaction() as db:
        meta = {row[0]: row[1] for row in db.execute("SELECT key,value FROM watch_meta")}
        providers = {row['source']: row for row in db.execute("SELECT * FROM watch_provider WHERE cve_id=?", (identifier,))}
        checks = {row["source"]: row for row in db.execute("SELECT * FROM watch_source_check WHERE cve_id=?", (identifier,))}
        output = []
        for source in SOURCES:
            updated = None
            checked = meta.get(f"sync_{source}_at") or meta.get(f"sync_{source}_success_at")
            if source in ("nvd", "cve_list"):
                row = providers.get(source)
                present = row is not None
                if row:
                    updated, checked = row['source_updated'], row['checked_at']
            elif source == "euvd":
                row = db.execute("SELECT max(i.date_updated),max(i.seen_at) FROM watch_euvd_item i JOIN watch_euvd_alias a ON a.euvd_id=i.euvd_id WHERE a.cve_id=?", (identifier,)).fetchone()
                present = row[1] is not None
                if present:
                    updated, checked = row
            elif source == "epss":
                row = db.execute("SELECT score_date FROM watch_epss WHERE cve_id=?", (identifier,)).fetchone()
                present = row is not None
                updated = row[0] if row else None
            else:
                row = db.execute("SELECT date_added FROM watch_kev WHERE catalog=? AND cve_id=?", ('cisa' if source == 'cisa_kev' else 'eu', identifier)).fetchone()
                present = row is not None
                updated = row[0] if row else None
            # A failed or zero-request baseline run is not evidence of absence.
            check = checks.get(source)
            if check is not None and (not checked or check["checked_at"] > checked):
                checked = check["checked_at"]
            synced = bool(meta.get(f"sync_{source}_success_at")) or bool(meta.get(f"sync_{source}_requests", "0") != "0" and not meta.get(f"sync_{source}_error"))
            output.append({"source": source, "state": "present" if present else "absent" if synced or (check is not None and check["present"] == 0) else "not synced",
                           "updated": updated, "checked": checked, "error": bool(check["error"] if check is not None else meta.get(f"sync_{source}_error"))})
        return tuple(output)
