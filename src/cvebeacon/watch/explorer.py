"""Bounded local CVE search and source provenance."""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import closing
import json
import re
import sqlite3

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
    with store.read() as db, closing(sqlite3.connect(":memory:")) as matcher:
        active = tuple(name for name in SOURCES if name in catalogs)
        enabled = "(" + ",".join("'" + name + "'" for name in active) + ")" if active else "('')"
        fallback = f"(SELECT p.record_json FROM watch_provider p WHERE p.cve_id=b.cve_id AND p.source IN {enabled} ORDER BY CASE p.source WHEN 'cve_list' THEN 0 WHEN 'euvd' THEN 1 ELSE 2 END LIMIT 1)"
        official = "(SELECT p.record_json FROM watch_provider p WHERE p.cve_id=b.cve_id AND p.source='cve_list')" if "cve_list" in active else "NULL"
        def base_field(name, empty="NULL"):
            fallback_value = f"json_extract({fallback},'$.{name}')"
            primary = f"b.{name}"
            if name != "status":
                missing = "'[]'" if name == "cvss_json" else "''"
                primary = f"COALESCE(NULLIF(b.{name},{missing}),json_extract({official},'$.{name}'),b.{name})"
            return f"CASE WHEN o.cve_id IS NOT NULL THEN COALESCE({fallback_value},{empty}) ELSE {primary} END AS effective_{name}"
        fields = [base_field(name, "'[]'" if name == "cvss_json" else "'reserved'" if name == "status" else "NULL") for name in ("description", "published", "last_modified", "cvss_json", "status")]
        cte = "WITH base AS (SELECT b.*," + ",".join(fields) + " FROM watch_cve b LEFT JOIN watch_origin o ON o.cve_id=b.cve_id) "
        where, values = [], []
        identifier = cve_id(query)
        fts = False
        if query:
            if identifier:
                where.append("c.cve_id=?")
                values.append(identifier)
            else:
                tokens = re.findall(r"\w+", query, re.UNICODE)[:32]
                legacy = db.execute("SELECT value FROM watch_meta WHERE key='schema_version'").fetchone()[0] != '8'
                fts = bool(use_fts and tokens and (legacy or db.execute("SELECT 1 FROM sqlite_master WHERE name='watch_fts'").fetchone()))
                if fts:
                    try:
                        matcher.execute("CREATE VIRTUAL TABLE candidate USING fts5(text,content='')")
                    except sqlite3.OperationalError as exc:
                        if 'no such module' not in str(exc).lower():
                            raise
                        fts = False
                if fts:
                    # Reuse the exact SQLite tokenizer and prefix semantics on
                    # one candidate at a time. No historical text copy, index
                    # backfill or persistent write is needed for legacy NVD.
                    ascii_terms = re.findall(r"[A-Za-z0-9]+", " ".join(tokens)) if all(token.isascii() for token in tokens) else ()
                    last_text, last_result = None, 0
                    def matches(text, expression):
                        nonlocal last_text, last_result
                        if text == last_text:
                            return last_result
                        # This rejection is safe only when both sides are
                        # ASCII. Unicode/diacritic behavior belongs to FTS5.
                        if ascii_terms and text.isascii():
                            folded = text.lower()
                            if any(term.lower() not in folded for term in ascii_terms):
                                return 0
                        matcher.execute("INSERT INTO candidate(candidate) VALUES ('delete-all')")
                        matcher.execute("INSERT INTO candidate VALUES (?)", (text,))
                        last_result = matcher.execute("SELECT EXISTS(SELECT 1 FROM candidate WHERE candidate MATCH ?)", (expression,)).fetchone()[0]
                        last_text = text
                        return last_result
                    db.create_function("watch_text_match", 2, matches)
                    expression = ' AND '.join('"' + token + '"*' for token in tokens)
                else:
                    expression = '%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
                texts = f"COALESCE((SELECT group_concat(text,char(10)) FROM (SELECT s.text FROM watch_search s WHERE s.cve_id=c.cve_id AND s.source IN {enabled} ORDER BY s.source)),'')"
                texts += " || CASE WHEN NOT EXISTS(SELECT 1 FROM watch_origin o WHERE o.cve_id=c.cve_id) THEN char(10)||COALESCE(c.description,'') ELSE '' END"
                where.append(f"watch_text_match({texts},?)" if fts else f"({texts}) LIKE ? ESCAPE '\\'")
                values.append(expression)
        presence = {
            "nvd": "NOT EXISTS(SELECT 1 FROM watch_origin o WHERE o.cve_id=c.cve_id)",
            "cve_list": "EXISTS(SELECT 1 FROM watch_provider p WHERE p.cve_id=c.cve_id AND p.source='cve_list')",
            "euvd": "(EXISTS(SELECT 1 FROM watch_euvd_override ov WHERE ov.cve_id=c.cve_id AND json_array_length(ov.items_json)>0) OR (NOT EXISTS(SELECT 1 FROM watch_euvd_override ov WHERE ov.cve_id=c.cve_id) AND EXISTS(SELECT 1 FROM watch_euvd_alias a WHERE a.cve_id=c.cve_id)))",
            "epss": "EXISTS(SELECT 1 FROM watch_epss e WHERE e.cve_id=c.cve_id)",
            "cisa_kev": "EXISTS(SELECT 1 FROM watch_kev k WHERE k.cve_id=c.cve_id AND k.catalog='cisa')",
            "eu_kev": "EXISTS(SELECT 1 FROM watch_kev k WHERE k.cve_id=c.cve_id AND k.catalog='eu')",
        }
        if source:
            if source not in presence:
                raise StateError("Unknown source filter")
            where.append(presence[source] if source in active else "0")
        cisa = presence['cisa_kev'] if 'cisa_kev' in active else "c.cisa_kev_added IS NOT NULL"
        eu = presence['eu_kev'] if 'eu_kev' in active else "0"
        kev_sql = f"({cisa} OR {eu})"
        base_score = "COALESCE((SELECT max(json_extract(j.value,'$.score')) FROM json_each(CASE WHEN json_valid(c.effective_cvss_json) THEN c.effective_cvss_json ELSE '[]' END) j),-1)"
        shared_score = "(SELECT i.score FROM watch_euvd_item i JOIN watch_euvd_alias a ON a.euvd_id=i.euvd_id WHERE a.cve_id=c.cve_id ORDER BY watch_euvd_rank(i.exploited_since,i.date_updated,i.euvd_id) DESC LIMIT 1)"
        override_score = "(SELECT json_extract(j.value,'$.score') FROM watch_euvd_override ov,json_each(ov.items_json) j WHERE ov.cve_id=c.cve_id ORDER BY watch_euvd_rank(json_extract(j.value,'$.exploited_since'),json_extract(j.value,'$.date_updated'),json_extract(j.value,'$.euvd_id')) DESC LIMIT 1)"
        euvd_score = f"CASE WHEN EXISTS(SELECT 1 FROM watch_euvd_override ov WHERE ov.cve_id=c.cve_id) THEN {override_score} ELSE {shared_score} END" if 'euvd' in active else "NULL"
        score = f"max({base_score},COALESCE({euvd_score},-1))"
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
                where.append(f"substr(c.effective_published,1,10) {operator} ?")
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
        orders = {"published": "c.effective_published", "modified": "c.effective_last_modified", "cvss": score,
                  "epss": "(SELECT epss FROM watch_epss e WHERE e.cve_id=c.cve_id)" if "epss" in active else "NULL", "kev": kev_sql}
        if sort not in orders:
            raise StateError("Unknown sort order")
        condition = " WHERE " + " AND ".join(where) if where else ""
        total = db.execute(cte + "SELECT count(*) FROM base c" + condition, values).fetchone()[0]
        rows = db.execute(cte + "SELECT c.cve_id FROM base c" + condition + " ORDER BY " + orders[sort] + " DESC,c.cve_id DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
        return SearchResult(tuple(store._view(db, row[0], catalogs) for row in rows), total, fts)


def source_presence(store, identifier):
    with store.read() as db:
        meta = {row[0]: row[1] for row in db.execute("SELECT key,value FROM watch_meta")}
        providers = {row['source']: row for row in db.execute("SELECT source,source_updated,checked_at FROM watch_provider WHERE cve_id=?", (identifier,))}
        checks = {row["source"]: row for row in db.execute("SELECT * FROM watch_source_check WHERE cve_id=?", (identifier,))}
        output = []
        for source in SOURCES:
            updated = None
            checked = meta.get(f"sync_{source}_at") or meta.get(f"sync_{source}_success_at")
            if source == "nvd":
                row = db.execute("SELECT c.last_modified,c.updated_at FROM watch_cve c WHERE c.cve_id=? AND NOT EXISTS(SELECT 1 FROM watch_origin o WHERE o.cve_id=c.cve_id)", (identifier,)).fetchone()
                present = row is not None
                if row:
                    updated, checked = row
            elif source == "cve_list":
                row = providers.get(source)
                present = row is not None
                if row:
                    updated, checked = row['source_updated'], row['checked_at']
            elif source == "euvd":
                row = db.execute("SELECT max(i.date_updated),max(i.seen_at) FROM watch_euvd_item i JOIN watch_euvd_alias a ON a.euvd_id=i.euvd_id WHERE a.cve_id=?", (identifier,)).fetchone()
                present = row[1] is not None
                if present:
                    updated, checked = row
                override = db.execute("SELECT items_json,checked_at FROM watch_euvd_override WHERE cve_id=?", (identifier,)).fetchone()
                if override is not None:
                    items = json.loads(override[0])
                    present = present or bool(items)
                    checked = override[1]
                    updated = max((item.get("date_updated") or "" for item in items), default=None)
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
            check_is_latest = check is not None and (not checked or check["checked_at"] >= checked)
            if check_is_latest:
                checked = check["checked_at"]
            synced = bool(meta.get(f"sync_{source}_success_at")) or bool(meta.get(f"sync_{source}_requests", "0") != "0" and not meta.get(f"sync_{source}_error"))
            state = "present (last check absent)" if present and check_is_latest and check["present"] == 0 else "present" if present else "absent" if synced or (check is not None and check["present"] == 0) else "not synced"
            output.append({"source": source, "state": state,
                           "updated": updated, "checked": checked, "error": bool(check["error"] if check_is_latest else meta.get(f"sync_{source}_error"))})
        return tuple(output)
