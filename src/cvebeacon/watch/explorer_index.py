"""SQLite projections for exact filtering without reading full CVE records."""

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS watch_explorer_metrics (
        cve_id TEXT PRIMARY KEY,
        nvd_score REAL NOT NULL DEFAULT -1,
        cve_list_score REAL NOT NULL DEFAULT -1,
        euvd_score REAL NOT NULL DEFAULT -1,
        nvd_exploitation INTEGER NOT NULL DEFAULT 0,
        cve_list_exploitation INTEGER NOT NULL DEFAULT 0,
        euvd_exploitation INTEGER NOT NULL DEFAULT 0
    ) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS watch_explorer_score (
        cve_id TEXT NOT NULL, source TEXT NOT NULL, version TEXT NOT NULL,
        provider TEXT NOT NULL, score REAL NOT NULL,
        PRIMARY KEY(cve_id,source,version,provider,score)
    ) WITHOUT ROWID""",
)

STORAGE = "indexed-v1"
SOURCES = ("nvd", "cve_list", "euvd")
EXPLOITATION_LEVELS = {"unknown": 0, "none": 1, "poc": 2, "active": 3}


def _json_array(expression):
    return f"CASE WHEN json_valid({expression}) THEN {expression} ELSE '[]' END"


def _ssvc_level(expression):
    return f"CASE {expression} WHEN 'active' THEN 3 WHEN 'poc' THEN 2 WHEN 'none' THEN 1 ELSE 0 END"


def _score_rows(source, identifiers):
    if source == "euvd":
        return (
            "SELECT a.cve_id,'euvd',i.version,'euvd',i.score "
            "FROM watch_euvd_alias a JOIN watch_euvd_item i USING(euvd_id) "
            f"WHERE a.cve_id IN ({identifiers}) AND i.score BETWEEN 0 AND 10 AND i.version IS NOT NULL "
            "AND NOT EXISTS(SELECT 1 FROM watch_euvd_override o WHERE o.cve_id=a.cve_id) "
            "UNION SELECT o.cve_id,'euvd',json_extract(j.value,'$.version'),'euvd',"
            "json_extract(j.value,'$.score') FROM watch_euvd_override o,json_each(o.items_json) j "
            f"WHERE o.cve_id IN ({identifiers}) AND json_extract(j.value,'$.score') BETWEEN 0 AND 10 "
            "AND json_extract(j.value,'$.version') IS NOT NULL"
        )
    if source == "nvd":
        table = "watch_cve"
        scores = "r.cvss_json"
        scope = "NOT EXISTS(SELECT 1 FROM watch_origin o WHERE o.cve_id=r.cve_id)"
    else:
        table = "watch_provider"
        scores = "json_extract(CASE WHEN json_valid(r.record_json) THEN r.record_json END,'$.cvss_json')"
        scope = "r.source='cve_list'"
    return (
        f"SELECT DISTINCT r.cve_id,'{source}',json_extract(j.value,'$.version'),"
        "json_extract(j.value,'$.provider'),json_extract(j.value,'$.score') "
        f"FROM {table} r,json_each({_json_array(scores)}) j WHERE r.cve_id IN ({identifiers}) "
        f"AND {scope} AND j.type='object' AND json_extract(j.value,'$.score') BETWEEN 0 AND 10 "
        "AND json_extract(j.value,'$.version') IS NOT NULL AND json_extract(j.value,'$.provider') IS NOT NULL"
    )


def _exploitation(source):
    if source == "nvd":
        status = (
            "SELECT c.ssvc_exploitation FROM watch_cve c WHERE c.cve_id=watch_explorer_metrics.cve_id "
            "AND NOT EXISTS(SELECT 1 FROM watch_origin o WHERE o.cve_id=c.cve_id)"
        )
    elif source == "cve_list":
        status = (
            "SELECT json_extract(CASE WHEN json_valid(p.record_json) THEN p.record_json END,'$.ssvc_exploitation') "
            "FROM watch_provider p WHERE p.cve_id=watch_explorer_metrics.cve_id AND p.source='cve_list'"
        )
    else:
        return (
            "CASE WHEN EXISTS(SELECT 1 FROM watch_euvd_override o "
            "WHERE o.cve_id=watch_explorer_metrics.cve_id) THEN "
            "3 * EXISTS(SELECT 1 FROM watch_euvd_override o,json_each(o.items_json) j "
            "WHERE o.cve_id=watch_explorer_metrics.cve_id "
            "AND NULLIF(json_extract(j.value,'$.exploited_since'),'') IS NOT NULL) ELSE "
            "3 * EXISTS(SELECT 1 FROM watch_euvd_alias a JOIN watch_euvd_item i USING(euvd_id) "
            "WHERE a.cve_id=watch_explorer_metrics.cve_id AND NULLIF(i.exploited_since,'') IS NOT NULL) END"
        )
    return _ssvc_level(f"({status})")


def _refresh_metrics(source, identifiers=None):
    scope = f" WHERE cve_id IN ({identifiers})" if identifiers is not None else ""
    return (
        f"UPDATE watch_explorer_metrics SET {source}_score=COALESCE(("
        "SELECT max(score) FROM watch_explorer_score s "
        f"WHERE s.cve_id=watch_explorer_metrics.cve_id AND s.source='{source}'),-1), "
        f"{source}_exploitation={_exploitation(source)}{scope}"
    )


def _triggers(db):
    # The projections follow the source storage even when SQLite changes aliases
    # through a foreign-key cascade or replaces a scoped EUVD observation.
    for table, source, events, condition in (
        ("watch_cve", "nvd", ("INSERT", "UPDATE OF cvss_json,ssvc_exploitation", "DELETE"), ""),
        ("watch_origin", "nvd", ("INSERT", "DELETE"), ""),
        ("watch_provider", "cve_list", ("INSERT", "UPDATE OF record_json", "DELETE"), "source='cve_list'"),
        ("watch_euvd_alias", "euvd", ("INSERT", "DELETE"), ""),
        ("watch_euvd_override", "euvd", ("INSERT", "UPDATE OF items_json", "DELETE"), ""),
        ("watch_euvd_item", "euvd", ("INSERT", "UPDATE OF score,version,exploited_since", "DELETE"), ""),
    ):
        for event in events:
            verb = event.split()[0].lower()
            row = "old" if verb == "delete" else "new"
            ids = f"SELECT {row}.cve_id AS cve_id"
            if table == "watch_euvd_item":
                ids = f"SELECT cve_id FROM watch_euvd_alias WHERE euvd_id={row}.euvd_id"
            guard = f" WHEN {row}.{condition}" if condition else ""
            db.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_explorer_{verb} AFTER {event} ON {table}{guard} BEGIN "
                f"INSERT INTO watch_explorer_metrics(cve_id) SELECT t.cve_id FROM ({ids}) t "
                "WHERE NOT EXISTS(SELECT 1 FROM watch_explorer_metrics m WHERE m.cve_id=t.cve_id); "
                f"DELETE FROM watch_explorer_score WHERE source='{source}' AND cve_id IN ({ids}); "
                f"INSERT INTO watch_explorer_score {_score_rows(source, ids)}; "
                f"{_refresh_metrics(source, ids)}; END"
            )


def initialize(db):
    marker = db.execute("SELECT value FROM watch_meta WHERE key='explorer_storage'").fetchone()
    if marker is None or marker[0] != STORAGE:
        ids = (
            "SELECT cve_id FROM watch_cve UNION SELECT cve_id FROM watch_provider WHERE source='cve_list' "
            "UNION SELECT cve_id FROM watch_euvd_alias UNION SELECT cve_id FROM watch_euvd_override"
        )
        db.execute("DELETE FROM watch_explorer_score")
        db.execute("DELETE FROM watch_explorer_metrics")
        db.execute(f"INSERT INTO watch_explorer_metrics(cve_id) {ids}")
        for source in SOURCES:
            db.execute("INSERT INTO watch_explorer_score " +
                       _score_rows(source, "SELECT cve_id FROM watch_explorer_metrics"))
            db.execute(_refresh_metrics(source))
        db.execute("INSERT OR REPLACE INTO watch_meta VALUES ('explorer_storage',?)", (STORAGE,))
    _triggers(db)
