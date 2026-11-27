"""Bounded local CVE search and source provenance."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from itertools import islice
from contextlib import closing
import json
import re
import sqlite3
import unicodedata

from ..clients import MAX_CLIENT_CVES
from ..errors import StateError
from ..sources.common import cve_id
from . import explorer_index
from .records import CVSS_PROVIDERS, CVSS_VERSIONS, EUVDUpdate, SSVC_EXPLOITATION, _names
from .rules import _first_match

SOURCES = ("nvd", "euvd", "cve_list", "cisa_kev", "eu_kev", "vulncheck", "epss")
MAX_QUERY = 256
KEV_FILTERS = ("cisa", "eu", "vulncheck", "either", "neither")
EXPLOITATION_FILTERS = (*SSVC_EXPLOITATION, "unknown")
SEVERITY_MINIMA = {"critical": 9, "high": 7, "medium": 4, "low": 0.1, "none": 0}
SEVERITY_BANDS = (*SEVERITY_MINIMA, "unknown")
MAX_NAME_FILTER_ITEMS = 20
MAX_NAME_FILTER_LENGTH = 120
MAX_STORED_NAME_PAIRS = 1_000
MAX_STORED_EUVD_NAME_PAIRS = 50


@dataclass(frozen=True)
class SearchResult:
    records: tuple
    total: int | None
    fts: bool = False


def _choices(values, allowed, label):
    if isinstance(values, str):
        values = (values,) if values else ()
    if (not isinstance(values, (tuple, list)) or len(values) > len(allowed)
            or any(not isinstance(value, str) or value not in allowed for value in values)):
        raise StateError(f"Invalid {label} filter")
    return tuple(dict.fromkeys(values))


def _number_range(low, high, maximum, label):
    for value in (low, high):
        if value is not None and (type(value) not in (int, float) or not 0 <= value <= maximum):
            raise StateError(f"{label} bounds must be between 0 and {maximum}")
    if low is not None and high is not None and low > high:
        raise StateError(f"{label} minimum exceeds its maximum")


def _date_range(low, high, label):
    if any(value is not None and type(value) is not date for value in (low, high)):
        raise StateError(f"Invalid {label} date")
    if low and high and low > high:
        raise StateError(f"{label} start date follows its end date")


def _name_filter(values, label):
    message = (f"Enter up to {MAX_NAME_FILTER_ITEMS} {label} names of at most "
               f"{MAX_NAME_FILTER_LENGTH} characters each")
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    if not isinstance(values, (tuple, list)):
        raise StateError(message)
    names = []
    for value in values:
        if not isinstance(value, str):
            raise StateError(message)
        name = value.strip()
        if not name:
            continue
        if (len(name) > MAX_NAME_FILTER_LENGTH
                or any(unicodedata.category(char) in {"Cc", "Cf"} for char in name)):
            raise StateError(message)
        names.append(name)
    if len(names) > MAX_NAME_FILTER_ITEMS:
        raise StateError(message)
    unique = {}
    for name in names:
        unique.setdefault(name.casefold(), name)
    return tuple(unique.values())


def _load_name_json(value, *, limit=MAX_STORED_NAME_PAIRS):
    """Load stored name data; bad data means no names."""
    if not isinstance(value, str):
        return None
    try:
        result = json.loads(value)
    except (UnicodeError, ValueError, RecursionError):
        return None
    return (result if isinstance(result, list)
            and len(result) <= limit else None)


def _array_field_names(items, field):
    if items is None:
        return ()
    return tuple(
        text for item in items if isinstance(item, dict)
        if (text := str(item.get(field) or "").strip())
    )


def _effective_name_match(products_json, euvd_json, field, names_json):
    products = _load_name_json(products_json, limit=MAX_STORED_NAME_PAIRS)
    euvd = _load_name_json(euvd_json, limit=MAX_STORED_EUVD_NAME_PAIRS)
    names = _load_name_json(names_json)
    if names is None:
        return 0
    values = _names((*_array_field_names(products or [], field),
                     *_array_field_names(euvd or [], field)), limit=500)
    return int(any(_first_match(values, name) is not None for name in names
                   if isinstance(name, str)))


class _EuvdNames:
    """Return vendor data from the highest-ranked EUVD item for one CVE."""

    def __init__(self):
        self.rank = None
        self.values = []

    def step(self, euvd_id, exploited_since, date_updated, vendors_json):
        candidate = EUVDUpdate(
            (),
            euvd_id if isinstance(euvd_id, str) else None,
            exploited_since if isinstance(exploited_since, str) else None,
            date_updated=date_updated if isinstance(date_updated, str) else None,
        )
        rank = candidate.rank()
        if self.rank is None or rank > self.rank:
            self.rank = rank
            self.values = _load_name_json(
                vendors_json, limit=MAX_STORED_EUVD_NAME_PAIRS,
            ) or []

    def finalize(self):
        return json.dumps(self.values, ensure_ascii=False, separators=(",", ":"))


def _json_array_is_valid(expression):
    """SQL predicate that checks JSON type before any JSON operation."""
    return (
        f"CASE WHEN typeof({expression})!='text' THEN 0 "
        f"WHEN json_valid({expression}) THEN json_type({expression})='array' ELSE 0 END"
    )


def _json_array_or_empty(expression):
    return f"CASE WHEN ({_json_array_is_valid(expression)}) THEN {expression} ELSE '[]' END"


def _json_or_empty_object(expression):
    return (
        f"CASE WHEN typeof({expression})!='text' THEN '{{}}' "
        f"WHEN json_valid({expression}) THEN {expression} ELSE '{{}}' END"
    )


def _name_filter_gate(names, catalogs):
    """Return a safe SQL superset gate for simple ASCII name filters."""
    if not names or any(
        not name.isascii()
        or any(quote in name for quote in ("'", '"'))
        or "\\" in name
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
        for name in names
    ):
        return None, ()
    bypass = [
        "typeof(c.products_json)!='text'",
        "length(c.products_json)!=length(CAST(c.products_json AS BLOB))",
        "instr(c.products_json,char(92))>0",
        "c.provider_only",
        "c.official_record IS NOT NULL",
    ]
    if "euvd" in catalogs:
        bypass.extend((
            "EXISTS(SELECT 1 FROM watch_euvd_alias a WHERE a.cve_id=c.cve_id)",
            "EXISTS(SELECT 1 FROM watch_euvd_override ov WHERE ov.cve_id=c.cve_id)",
        ))
    text_checks = " OR ".join("instr(lower(c.products_json),?)>0" for _ in names)
    return "(" + " OR ".join((*bypass, "(" + text_checks + ")")) + ")", tuple(
        name.lower() for name in names
    )


def _effective_products_json(catalogs):
    allowed = (set(catalogs) if catalogs else
               {"nvd", "cve_list", "euvd", "cisa_kev", "eu_kev", "vulncheck"})

    def provider(source):
        return (
            "(SELECT json_extract(" + _json_or_empty_object("p.record_json") + ","
            "'$.products_json') FROM watch_provider p "
            f"WHERE p.cve_id=c.cve_id AND p.source='{source}')"
        )

    provider_priority = ("cve_list", "euvd", "cisa_kev", "eu_kev")
    choices = [provider(source) for source in provider_priority if source in allowed]
    inherited = ("COALESCE(" + ",".join((*choices, "'[]'")) + ")"
                 if choices else "'[]'")
    official = provider("cve_list") if "cve_list" in allowed else "NULL"
    valid_products = _json_array_is_valid("c.products_json")
    return (
        "(CASE WHEN EXISTS(SELECT 1 FROM watch_origin o WHERE o.cve_id=c.cve_id) "
        f"THEN {inherited} "
        f"WHEN NOT ({valid_products}) THEN c.products_json "
        "WHEN json_array_length(c.products_json)>0 THEN c.products_json "
        f"ELSE COALESCE({official},c.products_json,'[]') END)"
    )


def _range_conditions(where, values, field, low, high):
    for value, operator in ((low, ">="), (high, "<=")):
        if value is not None:
            where.append(f"{field} {operator} ?")
            values.append(value)


def _in(values):
    return "(" + ",".join("?" for _ in values) + ")"


def search(store, *, query="", source="", kev="", severity="", since=None, until=None,
           has_events="", reported="", client_ids=None, vendor_names=None, product_names=None,
           sort="modified", limit=50, offset=0,
           use_fts=True, catalogs=SOURCES, exploitation="", epss_min=None, epss_max=None,
           cvss_min=None, cvss_max=None, cvss_version="", cvss_provider="",
           modified_since=None, modified_until=None, count_total=True):
    if not isinstance(query, str) or len(query) > MAX_QUERY:
        raise StateError("Search must be at most 256 characters")
    query = query.strip()
    source = _choices(source, SOURCES, "source")
    kev = _choices(kev, (*KEV_FILTERS, "yes", "no"), "KEV")
    severity = _choices(severity, SEVERITY_BANDS, "severity")
    exploitation = _choices(exploitation, EXPLOITATION_FILTERS, "exploitation")
    cvss_version = _choices(cvss_version, CVSS_VERSIONS, "CVSS version")
    cvss_provider = _choices(cvss_provider, CVSS_PROVIDERS, "CVSS provider")
    has_events = _choices(has_events, ("yes", "no"), "events")
    reported = _choices(reported, ("yes", "no"), "reported")
    if len(has_events) > 1 or len(reported) > 1:
        raise StateError("Events and reported filters each accept one choice")
    _number_range(epss_min, epss_max, 1, "EPSS")
    _number_range(cvss_min, cvss_max, 10, "CVSS")
    _date_range(since, until, "Publication")
    _date_range(modified_since, modified_until, "Modification")
    limit = max(1, min(int(limit), 100))
    offset = max(0, min(int(offset), 5_000_000))
    if client_ids is not None:
        client_ids = tuple(islice(client_ids, MAX_CLIENT_CVES + 1))
        if len(client_ids) > MAX_CLIENT_CVES:
            raise StateError("Client filter exceeds the local result limit")
    vendor_names = _name_filter(vendor_names, "vendor")
    product_names = _name_filter(product_names, "product")
    with store.read() as db, closing(sqlite3.connect(":memory:")) as matcher:
        active = tuple(name for name in SOURCES if name in catalogs)
        enabled = "(" + ",".join("'" + name + "'" for name in active) + ")" if active else "('')"
        fallback = f"(SELECT p.record_json FROM watch_provider p WHERE p.cve_id=b.cve_id AND p.source IN {enabled} ORDER BY CASE p.source WHEN 'cve_list' THEN 0 WHEN 'euvd' THEN 1 WHEN 'cisa_kev' THEN 2 ELSE 3 END LIMIT 1)"
        official = "(SELECT p.record_json FROM watch_provider p WHERE p.cve_id=b.cve_id AND p.source='cve_list')" if "cve_list" in active else "NULL"
        fields = [
            f"CASE WHEN o.cve_id IS NOT NULL THEN json_extract({fallback},'$.{name}') "
            f"ELSE COALESCE(NULLIF(b.{name},''),json_extract({official},'$.{name}'),b.{name}) "
            f"END AS effective_{name}"
            for name in ("published", "last_modified")
        ]
        fields.append(f"{official} AS official_record")
        cte = (
            "WITH base AS (SELECT b.*,o.cve_id IS NOT NULL AS provider_only,"
            + ",".join(fields) + " FROM watch_cve b LEFT JOIN watch_origin o ON o.cve_id=b.cve_id) "
        )
        where, values = [], []
        identifier = cve_id(query)
        fts = False
        if query:
            if identifier:
                where.append("c.cve_id=?")
                values.append(identifier)
            else:
                tokens = re.findall(r"\w+", query, re.UNICODE)[:32]
                legacy = int(db.execute("SELECT value FROM watch_meta WHERE key='schema_version'").fetchone()[0]) < 8
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
            "vulncheck": "EXISTS(SELECT 1 FROM watch_vulncheck_kev k WHERE k.cve_id=c.cve_id)",
        }
        if source:
            where.append("(" + " OR ".join(presence[name] if name in active else "0" for name in source) + ")")
        cisa = presence["cisa_kev"] if "cisa_kev" in active else "c.cisa_kev_added IS NOT NULL"
        eu = presence["eu_kev"] if "eu_kev" in active else "0"
        vulncheck = presence["vulncheck"] if "vulncheck" in active else "0"
        kev_sql = f"({cisa} OR {eu} OR {vulncheck})"
        kev_clauses = {"cisa": cisa, "eu": eu, "vulncheck": vulncheck,
                       "either": kev_sql, "neither": f"NOT {kev_sql}",
                       "yes": kev_sql, "no": f"NOT {kev_sql}"}
        positive_kev = bool(kev and not {"neither", "no"}.intersection(kev))
        if kev:
            either = bool({"either", "yes"}.intersection(kev))
            requested = tuple(name for name in ("cisa", "eu") if either or name in kev)
            if (positive_kev and requested and all(f"{name}_kev" in active for name in requested)
                    and (not either or "vulncheck" not in active)):
                where.append(f"c.cve_id IN (SELECT cve_id FROM watch_kev WHERE catalog IN {_in(requested)})")
                values.extend(requested)
            else:
                where.append("(" + " OR ".join(kev_clauses[name] for name in kev) + ")")

        score_filter = bool(cvss_version or cvss_provider or cvss_min is not None or cvss_max is not None)
        marker = db.execute("SELECT value FROM watch_meta WHERE key='explorer_storage'").fetchone()
        indexed = bool(marker and marker[0] == explorer_index.STORAGE)
        maximum_only = bool(indexed and score_filter and not cvss_version and not cvss_provider
                            and (cvss_max is None or cvss_max == 10))
        metric_filter = bool(exploitation or severity or sort == "cvss" or maximum_only)
        search_from = " FROM base c"
        if indexed:
            indexed_sources = tuple(name for name in explorer_index.SOURCES if name == "nvd" or name in active)
            def metrics(field):
                columns = [f"m.{name}_{field}" for name in indexed_sources]
                return f"max({','.join(columns)})" if len(columns) > 1 else columns[0]
            score = metrics("score")
            if metric_filter:
                search_from += " JOIN watch_explorer_metrics m ON m.cve_id=c.cve_id"
            if exploitation:
                where.append(f"{metrics('exploitation')} IN {_in(exploitation)}")
                values.extend(explorer_index.EXPLOITATION_LEVELS[name] for name in exploitation)
            if severity:
                bands = " ".join(f"WHEN {score} >= {minimum} THEN '{band}'"
                                 for band, minimum in SEVERITY_MINIMA.items())
                where.append(f"(CASE {bands} ELSE 'unknown' END) IN {_in(severity)}")
                values.extend(severity)
        else:
            euvd_scores = ""
            euvd_exploited = "0"
            if "euvd" in active:
                shared_items = (
                    "FROM watch_euvd_item i JOIN watch_euvd_alias a ON a.euvd_id=i.euvd_id "
                    "WHERE a.cve_id=c.cve_id AND NOT EXISTS("
                    "SELECT 1 FROM watch_euvd_override ov WHERE ov.cve_id=c.cve_id)"
                )
                override_items = "FROM watch_euvd_override ov,json_each(ov.items_json) j WHERE ov.cve_id=c.cve_id"
                euvd_scores = (
                    f" UNION ALL SELECT i.version,'euvd',i.score {shared_items} AND i.version IS NOT NULL"
                    f" UNION ALL SELECT json_extract(j.value,'$.version'),'euvd',json_extract(j.value,'$.score') "
                    f"{override_items} AND json_extract(j.value,'$.version') IS NOT NULL"
                )
                euvd_exploited = (
                    f"(EXISTS(SELECT 1 {shared_items} AND NULLIF(i.exploited_since,'') IS NOT NULL) OR "
                    f"EXISTS(SELECT 1 {override_items} AND NULLIF(json_extract(j.value,'$.exploited_since'),'') IS NOT NULL))"
                )
            if exploitation:
                official_ssvc = "json_extract(c.official_record,'$.ssvc_exploitation')"
                status = (
                    f"CASE WHEN {euvd_exploited} OR 'active' IN (c.ssvc_exploitation,{official_ssvc}) THEN 'active' "
                    f"WHEN 'poc' IN (c.ssvc_exploitation,{official_ssvc}) THEN 'poc' "
                    f"WHEN 'none' IN (c.ssvc_exploitation,{official_ssvc}) THEN 'none' ELSE 'unknown' END"
                )
                where.append(f"{status} IN {_in(exploitation)}")
                values.extend(exploitation)

            score_rows = (
                "SELECT json_extract(j.value,'$.version') AS version, json_extract(j.value,'$.provider') AS provider, "
                "json_extract(j.value,'$.score') AS score "
                "FROM json_each(CASE WHEN json_valid(c.cvss_json) THEN c.cvss_json ELSE '[]' END) j "
                "WHERE NOT c.provider_only UNION ALL "
                "SELECT json_extract(j.value,'$.version'),json_extract(j.value,'$.provider'),json_extract(j.value,'$.score') "
                "FROM json_each(json_extract(c.official_record,'$.cvss_json')) j" + euvd_scores
            )
            score = f"COALESCE((SELECT max(score) FROM ({score_rows})),-1)"
            if severity:
                bands = " ".join(f"WHEN max(score) >= {minimum} THEN '{band}'"
                                 for band, minimum in SEVERITY_MINIMA.items())
                where.append(f"(SELECT CASE {bands} ELSE 'unknown' END FROM ({score_rows})) IN {_in(severity)}")
                values.extend(severity)

        if maximum_only:
            where.append(f"{score} >= ?")
            values.append(cvss_min if cvss_min is not None else 0)
        elif score_filter:
            cvss_conditions = []
            cvss_values = []
            _range_conditions(cvss_conditions, cvss_values, "score", cvss_min, cvss_max)
            for field, selected in (("version", cvss_version), ("provider", cvss_provider)):
                if selected:
                    cvss_conditions.append(f"{field} IN {_in(selected)}")
                    cvss_values.extend(selected)
            if indexed:
                if indexed_sources != explorer_index.SOURCES:
                    cvss_conditions.append(f"source IN {_in(indexed_sources)}")
                    cvss_values.extend(indexed_sources)
                predicate = " AND ".join(cvss_conditions)
                where.append(f"EXISTS(SELECT 1 FROM watch_explorer_score s WHERE s.cve_id=c.cve_id AND {predicate})")
            else:
                where.append(
                    f"EXISTS(SELECT 1 FROM ({score_rows}) WHERE score IS NOT NULL AND "
                    + " AND ".join(cvss_conditions) + ")"
                )
            values.extend(cvss_values)

        epss = "(SELECT epss FROM watch_epss e WHERE e.cve_id=c.cve_id)" if "epss" in active else "NULL"
        _range_conditions(where, values, epss, epss_min, epss_max)
        for field, low, high in (("effective_published", since, until),
                                 ("effective_last_modified", modified_since, modified_until)):
            _range_conditions(where, values, f"substr(c.{field},1,10)",
                              low.isoformat() if low else None, high.isoformat() if high else None)
        for selected, sql in (
            (has_events, "c.cve_id IN (SELECT e.cve_id FROM watch_event e)"),
            (reported, "(SELECT r.action FROM watch_report r WHERE r.cve_id=c.cve_id ORDER BY r.id DESC LIMIT 1) IS 'report'"),
        ):
            if selected:
                where.append(("NOT " if selected[0] == "no" else "") + f"({sql})")
        if client_ids is not None:
            db.execute("CREATE TEMP TABLE selected_cves(cve_id TEXT PRIMARY KEY)")
            db.executemany("INSERT OR IGNORE INTO selected_cves VALUES (?)", ((i,) for i in client_ids))
            where.append("c.cve_id IN (SELECT cve_id FROM selected_cves)")
        if vendor_names or product_names:
            db.create_function("watch_rule_name_match", 4, _effective_name_match)
            db.create_aggregate("watch_rule_euvd_names", 4, _EuvdNames)
            products_json = _effective_products_json(catalogs)
            for field, names in (("vendor", vendor_names), ("product", product_names)):
                if not names:
                    continue
                names_json = json.dumps(names, ensure_ascii=False)
                gate, gate_values = _name_filter_gate(names, catalogs)
                euvd = "'[]'"
                if "euvd" in catalogs:
                    override_items = (
                        "json_each(" + _json_array_or_empty("ov.items_json") + ")"
                    )
                    override_value = (
                        "CASE WHEN json_valid(j.value) THEN j.value ELSE '{}' END"
                    )
                    euvd = (
                        "CASE WHEN EXISTS(SELECT 1 FROM watch_euvd_override ov "
                        "WHERE ov.cve_id=c.cve_id) THEN COALESCE((SELECT "
                        "watch_rule_euvd_names(json_extract(" + override_value + ",'$.euvd_id'),"
                        "json_extract(" + override_value + ",'$.exploited_since'),"
                        "json_extract(" + override_value + ",'$.date_updated'),"
                        "json_extract(" + override_value + ",'$.vendors_json')) "
                        "FROM watch_euvd_override ov," + override_items + " j "
                        "WHERE ov.cve_id=c.cve_id),'[]') ELSE COALESCE((SELECT "
                        "watch_rule_euvd_names(i.euvd_id,i.exploited_since,"
                        "i.date_updated,i.vendors_json) FROM watch_euvd_alias a "
                        "JOIN watch_euvd_item i ON i.euvd_id=a.euvd_id "
                        "WHERE a.cve_id=c.cve_id),'[]') END"
                    )
                match = f"watch_rule_name_match({products_json},{euvd},?,?)"
                where.append(f"CASE WHEN {gate} THEN {match} ELSE 0 END" if gate else match)
                if gate:
                    values.extend(gate_values)
                values.extend((field, names_json))
        orders = {"published": "c.effective_published", "modified": "c.effective_last_modified", "cvss": score,
                  "epss": epss, "kev": kev_sql}
        if sort not in orders:
            raise StateError("Unknown sort order")
        condition = " WHERE " + " AND ".join(where) if where else ""
        total = None
        if count_total:
            total = db.execute(cte + "SELECT count(*)" + search_from + condition, values).fetchone()[0]
        rows = db.execute(cte + "SELECT c.cve_id" + search_from + condition + " ORDER BY " + orders[sort] + " DESC,c.cve_id DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
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
            if source == "vulncheck" and not (
                checked or meta.get(f"sync_{source}_note") or checks.get(source)
                or db.execute(
                    "SELECT 1 FROM watch_vulncheck_kev WHERE cve_id=?", (identifier,)
                ).fetchone()
            ):
                # VulnCheck is optional and absent from older configurations.
                continue
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
            elif source == "vulncheck":
                row = db.execute("SELECT date_added FROM watch_vulncheck_kev WHERE cve_id=?", (identifier,)).fetchone()
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
