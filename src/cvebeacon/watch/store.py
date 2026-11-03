"""Transactional SQLite storage for recently changed CVEs.

Each source keeps its own raw table.  The alert-relevant view of a CVE is
derived from those tables and only its fingerprint is stored in ``watch_view``.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from ..errors import StateError
from .records import (
    CVSSEntry,
    EUVDUpdate,
    KEVFields,
    Product,
    WatchRecord,
    build_view,
    canonical_json,
    epss_band,
)

SCHEMA_VERSION = 1
EUVD_MAX_AGE_DAYS = 30
EPSS_WRITE_BATCH = 5000
KEV_CATALOGS = ("cisa", "eu")

_NVD_CONTENT_COLUMNS = (
    "published",
    "last_modified",
    "status",
    "description",
    "source_identifier",
    "cvss_json",
    "cwes_json",
    "products_json",
    "references_json",
    "ssvc_exploitation",
    "cisa_kev_added",
    "cisa_kev_due",
    "cisa_required_action",
    "cisa_ransomware",
)

_EPSS_BAND_SQL = (
    "CASE WHEN {column} < 0.1 THEN 0 "
    "WHEN {column} < 0.5 THEN 1 "
    "WHEN {column} < 0.9 THEN 2 ELSE 3 END"
)

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS watch_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS watch_cve (
        cve_id TEXT PRIMARY KEY,
        published TEXT,
        last_modified TEXT,
        status TEXT NOT NULL CHECK(status IN ('published','rejected')),
        description TEXT,
        source_identifier TEXT,
        cvss_json TEXT NOT NULL,
        cwes_json TEXT NOT NULL,
        products_json TEXT NOT NULL,
        references_json TEXT NOT NULL,
        ssvc_exploitation TEXT CHECK(ssvc_exploitation IN ('none','poc','active') OR ssvc_exploitation IS NULL),
        cisa_kev_added TEXT,
        cisa_kev_due TEXT,
        cisa_required_action TEXT,
        cisa_ransomware TEXT,
        first_seen TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        nvd_fingerprint TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS watch_cve_ssvc ON watch_cve(ssvc_exploitation)",
    """CREATE TABLE IF NOT EXISTS watch_euvd_item (
        euvd_id TEXT PRIMARY KEY,
        cve_ids_json TEXT NOT NULL,
        date_updated TEXT,
        score REAL,
        version TEXT,
        vector TEXT,
        exploited_since TEXT,
        vendors_json TEXT NOT NULL,
        seen_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS watch_euvd_alias (
        cve_id TEXT NOT NULL,
        euvd_id TEXT NOT NULL,
        PRIMARY KEY(cve_id, euvd_id),
        FOREIGN KEY(euvd_id) REFERENCES watch_euvd_item(euvd_id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS watch_euvd_alias_euvd ON watch_euvd_alias(euvd_id)",
    """CREATE TABLE IF NOT EXISTS watch_kev (
        catalog TEXT NOT NULL CHECK(catalog IN ('cisa','eu')),
        cve_id TEXT NOT NULL,
        date_added TEXT,
        due_date TEXT,
        required_action TEXT,
        ransomware TEXT,
        PRIMARY KEY(catalog, cve_id)
    )""",
    "CREATE INDEX IF NOT EXISTS watch_kev_cve ON watch_kev(cve_id)",
    """CREATE TABLE IF NOT EXISTS watch_epss (
        cve_id TEXT PRIMARY KEY,
        epss REAL NOT NULL,
        percentile REAL NOT NULL,
        score_date TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS watch_view (
        cve_id TEXT PRIMARY KEY,
        fingerprint TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS watch_lookup (
        cve_id TEXT PRIMARY KEY,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        last_error TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS watch_lookup_due ON watch_lookup(next_attempt_at)",
)


@dataclass(frozen=True, slots=True)
class StepCounts:
    new: int = 0
    changed: int = 0
    unchanged: int = 0
    new_ids: tuple[str, ...] = ()
    changed_ids: tuple[str, ...] = ()
    touched_ids: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return self.new + self.changed + self.unchanged


@dataclass(frozen=True, slots=True)
class EpssLoadResult:
    rows: int = 0
    batches: int = 0
    changed_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LookupRow:
    cve_id: str
    attempts: int
    next_attempt_at: str
    last_error: str | None = None


@dataclass(frozen=True, slots=True)
class _ViewCounts:
    new: int = 0
    changed: int = 0
    unchanged: int = 0


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _nvd_content(record: WatchRecord) -> dict[str, Any]:
    return {
        "published": record.published,
        "last_modified": record.last_modified,
        "status": record.status,
        "description": record.description,
        "source_identifier": record.source_identifier,
        "cvss_json": record.cvss_json,
        "cwes_json": record.cwes_json,
        "products_json": record.products_json,
        "references_json": record.references_json,
        "ssvc_exploitation": record.ssvc_exploitation,
        "cisa_kev_added": record.cisa_kev_added,
        "cisa_kev_due": record.cisa_kev_due,
        "cisa_required_action": record.cisa_required_action,
        "cisa_ransomware": record.cisa_ransomware,
    }


def _vendors_json(vendors: Iterable[Product]) -> str:
    return canonical_json([item.as_dict() for item in vendors])


def _euvd_from_row(row: Mapping[str, Any]) -> EUVDUpdate:
    try:
        cve_ids = tuple(json.loads(row["cve_ids_json"]))
        vendors = tuple(Product(**item) for item in json.loads(row["vendors_json"]))
        version = row["version"]
        score = row["score"]
        cvss = None
        if score is not None and version is not None:
            cvss = CVSSEntry("euvd", "euvd", version, score, row["vector"])
        return EUVDUpdate(
            cve_ids,
            row["euvd_id"],
            row["exploited_since"],
            cvss,
            row["date_updated"],
            vendors,
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise StateError("watch database contains an invalid EUVD item") from exc


def _kev_tuple(row: Mapping[str, Any]) -> tuple[str | None, ...]:
    return (
        row["date_added"],
        row["due_date"],
        row["required_action"],
        row["ransomware"],
    )


class WatchStore:
    def __init__(self, path: str | Path, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self.path = Path(path)
        self._clock = clock

    def _connect(self) -> sqlite3.Connection:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA foreign_keys = ON")
            return connection
        except (sqlite3.Error, OSError) as exc:
            raise StateError(f"cannot open watch database {self.path}: {exc}") from exc

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise StateError(f"watch transaction failed: {exc}") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.transaction() as db:
            self._ensure_schema(db)

    @staticmethod
    def _ensure_schema(db: sqlite3.Connection) -> None:
        for statement in _SCHEMA:
            db.execute(statement)
        rows = db.execute("SELECT value FROM watch_meta WHERE key='schema_version'").fetchall()
        if len(rows) > 1:
            raise StateError("ambiguous watch schema metadata; expected one version row")
        if not rows:
            db.execute(
                "INSERT INTO watch_meta(key,value) VALUES ('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
        elif rows[0]["value"] != str(SCHEMA_VERSION):
            raise StateError(f"unsupported watch schema version {rows[0]['value']}")

    def metadata(self) -> dict[str, str]:
        self.initialize()
        with closing(self._connect()) as db:
            return {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM watch_meta")}

    @staticmethod
    def _set_meta(db: sqlite3.Connection, values: Mapping[str, str]) -> None:
        for key, value in values.items():
            db.execute(
                "INSERT INTO watch_meta(key,value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def record_baseline(
        self,
        *,
        nvd_cursor: str,
        initialized_at: str,
        euvd_cursor: str | None = None,
        initial_mode: str = "baseline",
        initial_window_start: str | None = None,
    ) -> None:
        self.initialize()
        values = {
            "nvd_cursor": nvd_cursor,
            "initialized_at": initialized_at,
            "initial_mode": initial_mode,
        }
        if euvd_cursor is not None:
            values["euvd_cursor"] = euvd_cursor
        if initial_window_start is not None:
            values["initial_window_start"] = initial_window_start
        with self.transaction() as db:
            self._set_meta(db, values)

    def set_metadata(self, values: Mapping[str, str]) -> None:
        self.initialize()
        with self.transaction() as db:
            self._set_meta(db, values)

    @staticmethod
    def _record(row: Mapping[str, Any]) -> WatchRecord:
        try:
            return WatchRecord.from_row(row)
        except (TypeError, ValueError, KeyError) as exc:
            raise StateError("watch database contains an invalid CVE record") from exc

    @staticmethod
    def _row(db: sqlite3.Connection, identifier: str) -> sqlite3.Row | None:
        return db.execute(
            "SELECT * FROM watch_cve WHERE cve_id=?", (identifier,)
        ).fetchone()

    def _write_nvd(
        self,
        db: sqlite3.Connection,
        record: WatchRecord,
        now: str,
    ) -> str:
        row = self._row(db, record.cve_id)
        content = _nvd_content(record)
        fingerprint = record.nvd_fingerprint()
        if row is None:
            columns = (
                "cve_id",
                *_NVD_CONTENT_COLUMNS,
                "first_seen",
                "updated_at",
                "nvd_fingerprint",
            )
            values = (record.cve_id, *content.values(), now, now, fingerprint)
            marks = ",".join("?" for _ in columns)
            db.execute(
                f"INSERT INTO watch_cve({','.join(columns)}) VALUES ({marks})", values
            )
            return "new"
        if all(row[column] == content[column] for column in _NVD_CONTENT_COLUMNS):
            return "unchanged"
        columns = (*_NVD_CONTENT_COLUMNS, "updated_at", "nvd_fingerprint")
        assignments = ", ".join(f"{column}=?" for column in columns)
        values = (
            *(content[column] for column in _NVD_CONTENT_COLUMNS),
            now,
            fingerprint,
            record.cve_id,
        )
        db.execute(f"UPDATE watch_cve SET {assignments} WHERE cve_id=?", values)
        return "changed"

    @staticmethod
    def _best_euvd(db: sqlite3.Connection, identifier: str) -> EUVDUpdate | None:
        rows = db.execute(
            "SELECT i.* FROM watch_euvd_item i "
            "JOIN watch_euvd_alias a ON a.euvd_id=i.euvd_id "
            "WHERE a.cve_id=?",
            (identifier,),
        ).fetchall()
        if not rows:
            return None
        candidates = [_euvd_from_row(row) for row in rows]
        return max(candidates, key=lambda item: item.rank())

    @staticmethod
    def _kev_row(
        db: sqlite3.Connection, catalog: str, identifier: str
    ) -> KEVFields | None:
        row = db.execute(
            "SELECT date_added,due_date,required_action,ransomware FROM watch_kev "
            "WHERE catalog=? AND cve_id=?",
            (catalog, identifier),
        ).fetchone()
        if row is None:
            return None
        return KEVFields(
            row["date_added"],
            row["due_date"],
            row["required_action"],
            row["ransomware"],
        )

    @staticmethod
    def _epss_row(
        db: sqlite3.Connection, identifier: str
    ) -> tuple[float, float, str] | None:
        row = db.execute(
            "SELECT epss,percentile,score_date FROM watch_epss WHERE cve_id=?",
            (identifier,),
        ).fetchone()
        if row is None:
            return None
        return row["epss"], row["percentile"], row["score_date"]

    def _view(
        self, db: sqlite3.Connection, identifier: str, catalogs: Sequence[str]
    ) -> Any | None:
        row = self._row(db, identifier)
        if row is None:
            return None
        record = self._record(row)
        return build_view(
            record,
            euvd=self._best_euvd(db, identifier),
            cisa_kev=self._kev_row(db, "cisa", identifier),
            eu_kev=self._kev_row(db, "eu", identifier),
            cisa_catalog="cisa_kev" in catalogs,
            eu_catalog="eu_kev" in catalogs,
            epss=self._epss_row(db, identifier),
        )

    def _refresh_views(
        self,
        db: sqlite3.Connection,
        identifiers: Iterable[str],
        catalogs: Sequence[str],
        now: str,
    ) -> _ViewCounts:
        new = changed = unchanged = 0
        for identifier in dict.fromkeys(identifiers):
            view = self._view(db, identifier, catalogs)
            if view is None:
                db.execute("DELETE FROM watch_view WHERE cve_id=?", (identifier,))
                continue
            fingerprint = view.fingerprint()
            row = db.execute(
                "SELECT fingerprint FROM watch_view WHERE cve_id=?", (identifier,)
            ).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO watch_view(cve_id,fingerprint,updated_at) VALUES (?,?,?)",
                    (identifier, fingerprint, now),
                )
                new += 1
            elif row["fingerprint"] == fingerprint:
                unchanged += 1
            else:
                db.execute(
                    "UPDATE watch_view SET fingerprint=?,updated_at=? WHERE cve_id=?",
                    (fingerprint, now, identifier),
                )
                changed += 1
        return _ViewCounts(new, changed, unchanged)

    def upsert_nvd(
        self,
        records: Sequence[WatchRecord],
        *,
        meta: Mapping[str, str] | None = None,
        catalogs: Sequence[str] = (),
    ) -> StepCounts:
        self.initialize()
        now = _timestamp(self._clock)
        outcomes: list[tuple[str, str]] = []
        with self.transaction() as db:
            for record in records:
                outcome = self._write_nvd(db, record, now)
                db.execute("DELETE FROM watch_lookup WHERE cve_id=?", (record.cve_id,))
                outcomes.append((record.cve_id, outcome))
            written = [
                identifier
                for identifier, outcome in outcomes
                if outcome in ("new", "changed")
            ]
            views = self._refresh_views(db, written, catalogs, now)
            if meta:
                self._set_meta(db, meta)
        new_ids = tuple(identifier for identifier, outcome in outcomes if outcome == "new")
        changed_ids = tuple(
            identifier for identifier, outcome in outcomes if outcome == "changed"
        )
        return StepCounts(
            new=len(new_ids),
            changed=views.changed,
            unchanged=sum(outcome == "unchanged" for _, outcome in outcomes),
            new_ids=new_ids,
            changed_ids=changed_ids,
            touched_ids=tuple(identifier for identifier, _ in outcomes if outcome != "unchanged"),
        )

    def replace_euvd_items(
        self,
        updates: Sequence[EUVDUpdate],
        *,
        meta: Mapping[str, str] | None = None,
        catalogs: Sequence[str] = (),
    ) -> StepCounts:
        self.initialize()
        now = _timestamp(self._clock)
        by_id: dict[str, EUVDUpdate] = {}
        for update in updates:
            if not update.euvd_id:
                raise StateError("EUVD item has no identifier")
            by_id[update.euvd_id] = update
        outcomes: list[tuple[str, str]] = []
        touched: set[str] = set()
        with self.transaction() as db:
            for euvd_id in sorted(by_id):
                update = by_id[euvd_id]
                cve_ids = tuple(sorted(set(update.cve_ids)))
                cve_ids_json = canonical_json(list(cve_ids))
                vendors_json = _vendors_json(update.vendors)
                score = update.cvss.score if update.cvss is not None else None
                version = update.cvss.version if update.cvss is not None else None
                vector = update.cvss.vector if update.cvss is not None else None
                desired = (
                    cve_ids_json,
                    update.date_updated,
                    score,
                    version,
                    vector,
                    update.exploited_since,
                    vendors_json,
                )
                row = db.execute(
                    "SELECT * FROM watch_euvd_item WHERE euvd_id=?", (euvd_id,)
                ).fetchone()
                old_aliases = {
                    alias["cve_id"]
                    for alias in db.execute(
                        "SELECT cve_id FROM watch_euvd_alias WHERE euvd_id=?", (euvd_id,)
                    )
                }
                current = (
                    (
                        row["cve_ids_json"],
                        row["date_updated"],
                        row["score"],
                        row["version"],
                        row["vector"],
                        row["exploited_since"],
                        row["vendors_json"],
                    )
                    if row is not None
                    else None
                )
                if current == desired:
                    continue
                if row is None:
                    db.execute(
                        "INSERT INTO watch_euvd_item("
                        "euvd_id,cve_ids_json,date_updated,score,version,vector,"
                        "exploited_since,vendors_json,seen_at) VALUES (?,?,?,?,?,?,?,?,?)",
                        (euvd_id, *desired, now),
                    )
                    outcomes.append((euvd_id, "new"))
                else:
                    db.execute(
                        "UPDATE watch_euvd_item SET cve_ids_json=?,date_updated=?,"
                        "score=?,version=?,vector=?,exploited_since=?,vendors_json=?,"
                        "seen_at=? WHERE euvd_id=?",
                        (*desired, now, euvd_id),
                    )
                    outcomes.append((euvd_id, "changed"))
                db.execute("DELETE FROM watch_euvd_alias WHERE euvd_id=?", (euvd_id,))
                for identifier in cve_ids:
                    db.execute(
                        "INSERT INTO watch_euvd_alias(cve_id,euvd_id) VALUES (?,?)",
                        (identifier, euvd_id),
                    )
                touched.update(old_aliases)
                touched.update(cve_ids)
            views = self._refresh_views(db, sorted(touched), catalogs, now)
            if meta:
                self._set_meta(db, meta)
        new_items = tuple(identifier for identifier, outcome in outcomes if outcome == "new")
        changed_items = tuple(
            identifier for identifier, outcome in outcomes if outcome == "changed"
        )
        return StepCounts(
            new=len(new_items),
            changed=views.changed + views.new,
            unchanged=0,
            new_ids=new_items,
            changed_ids=changed_items,
            touched_ids=tuple(sorted(touched)),
        )

    def replace_kev(
        self,
        catalog: str,
        fields: Mapping[str, KEVFields],
        *,
        meta: Mapping[str, str] | None = None,
        catalogs: Sequence[str] = (),
    ) -> StepCounts:
        if catalog not in KEV_CATALOGS:
            raise StateError(f"unknown KEV catalog {catalog}")
        self.initialize()
        now = _timestamp(self._clock)
        with self.transaction() as db:
            old = {
                row["cve_id"]: _kev_tuple(row)
                for row in db.execute(
                    "SELECT cve_id,date_added,due_date,required_action,ransomware "
                    "FROM watch_kev WHERE catalog=?",
                    (catalog,),
                )
            }
            new = {
                identifier: (
                    entry.added,
                    entry.due,
                    entry.required_action,
                    entry.ransomware,
                )
                for identifier, entry in fields.items()
            }
            touched = {
                identifier
                for identifier in set(old) | set(new)
                if old.get(identifier) != new.get(identifier)
            }
            db.execute("DELETE FROM watch_kev WHERE catalog=?", (catalog,))
            db.executemany(
                "INSERT INTO watch_kev("
                "catalog,cve_id,date_added,due_date,required_action,ransomware) "
                "VALUES (?,?,?,?,?,?)",
                (
                    (catalog, identifier, *new[identifier])
                    for identifier in sorted(new)
                ),
            )
            views = self._refresh_views(db, sorted(touched), catalogs, now)
            if meta:
                self._set_meta(db, meta)
        added = set(new) - set(old)
        common = set(old) & set(new)
        return StepCounts(
            new=len(added),
            changed=views.changed + views.new,
            unchanged=len(common - touched),
            new_ids=tuple(sorted(added)),
            changed_ids=tuple(sorted(touched)),
            touched_ids=tuple(sorted(touched)),
        )

    def replace_epss(
        self,
        rows: Iterable[tuple[str, float, float, date]],
        *,
        meta: Mapping[str, str] | None = None,
    ) -> EpssLoadResult:
        self.initialize()
        with self.transaction() as db:
            db.execute(
                "CREATE TEMP TABLE watch_epss_load ("
                "cve_id TEXT PRIMARY KEY, epss REAL NOT NULL, "
                "percentile REAL NOT NULL, score_date TEXT NOT NULL, "
                "band INTEGER NOT NULL)"
            )
            batch: list[tuple[str, float, float, str, int]] = []
            total = batches = 0
            for identifier, score, percentile, score_date in rows:
                batch.append(
                    (
                        identifier,
                        score,
                        percentile,
                        score_date.isoformat(),
                        epss_band(score),
                    )
                )
                if len(batch) >= EPSS_WRITE_BATCH:
                    db.executemany(
                        "INSERT OR REPLACE INTO watch_epss_load"
                        "(cve_id,epss,percentile,score_date,band) VALUES (?,?,?,?,?)",
                        batch,
                    )
                    total += len(batch)
                    batches += 1
                    batch.clear()
            if batch:
                db.executemany(
                    "INSERT OR REPLACE INTO watch_epss_load"
                    "(cve_id,epss,percentile,score_date,band) VALUES (?,?,?,?,?)",
                    batch,
                )
                total += len(batch)
                batches += 1
            old_band = _EPSS_BAND_SQL.format(column="o.epss")
            new_band = _EPSS_BAND_SQL.format(column="n.epss")
            changed = {
                row["cve_id"]
                for row in db.execute(
                    "SELECT n.cve_id FROM watch_epss_load n "
                    "JOIN watch_cve c ON c.cve_id=n.cve_id "
                    "LEFT JOIN watch_epss o ON o.cve_id=n.cve_id "
                    f"WHERE o.cve_id IS NULL OR {old_band} <> {new_band} "
                    "UNION "
                    "SELECT o.cve_id FROM watch_epss o "
                    "JOIN watch_cve c ON c.cve_id=o.cve_id "
                    "LEFT JOIN watch_epss_load n ON n.cve_id=o.cve_id "
                    "WHERE n.cve_id IS NULL"
                )
            }
            db.execute("DELETE FROM watch_epss")
            db.execute(
                "INSERT INTO watch_epss(cve_id,epss,percentile,score_date) "
                "SELECT cve_id,epss,percentile,score_date FROM watch_epss_load"
            )
            db.execute("DROP TABLE watch_epss_load")
            if meta:
                self._set_meta(db, meta)
        return EpssLoadResult(total, batches, tuple(sorted(changed)))

    def prune_euvd(self, *, now: datetime) -> int | None:
        """Delete old, non-exploited items that no stored CVE refers to."""
        self.initialize()
        today = now.date().isoformat()
        with self.transaction() as db:
            row = db.execute(
                "SELECT value FROM watch_meta WHERE key='euvd_prune_date'"
            ).fetchone()
            if row is not None and row["value"] == today:
                return None
            cutoff = (now - timedelta(days=EUVD_MAX_AGE_DAYS)).isoformat()
            cursor = db.execute(
                "DELETE FROM watch_euvd_item "
                "WHERE exploited_since IS NULL AND seen_at < ? "
                "AND NOT EXISTS ("
                "SELECT 1 FROM watch_euvd_alias a "
                "JOIN watch_cve c ON c.cve_id=a.cve_id "
                "WHERE a.euvd_id=watch_euvd_item.euvd_id)",
                (cutoff,),
            )
            self._set_meta(db, {"euvd_prune_date": today})
            return cursor.rowcount

    def sync_lookups(
        self,
        catalogs: Sequence[str],
        *,
        initial_window_start: str | None,
        now: datetime,
        include_euvd: bool = True,
    ) -> int:
        """Create, keep and remove lookup entries from current triggers."""
        self.initialize()
        stamp = _timestamp(lambda: now)
        catalog_names = {"cisa_kev": "cisa", "eu_kev": "eu"}
        with self.transaction() as db:
            candidates: set[str] = set()
            if initial_window_start is not None:
                for source_name in catalogs:
                    catalog = catalog_names.get(source_name, source_name)
                    if catalog not in KEV_CATALOGS:
                        continue
                    candidates.update(
                        row["cve_id"]
                        for row in db.execute(
                            "SELECT k.cve_id FROM watch_kev k "
                            "WHERE k.catalog=? AND k.date_added IS NOT NULL "
                            "AND substr(k.date_added,1,10) >= ? "
                            "AND NOT EXISTS ("
                            "SELECT 1 FROM watch_cve c WHERE c.cve_id=k.cve_id)",
                            (catalog, initial_window_start[:10]),
                        )
                    )
            if include_euvd:
                candidates.update(
                    row["cve_id"]
                    for row in db.execute(
                        "SELECT DISTINCT a.cve_id FROM watch_euvd_item i "
                        "JOIN watch_euvd_alias a ON a.euvd_id=i.euvd_id "
                        "WHERE i.exploited_since IS NOT NULL "
                        "AND NOT EXISTS ("
                        "SELECT 1 FROM watch_cve c WHERE c.cve_id=a.cve_id)"
                    )
                )
            existing = {
                row["cve_id"] for row in db.execute("SELECT cve_id FROM watch_lookup")
            }
            for identifier in sorted(candidates - existing):
                db.execute(
                    "INSERT INTO watch_lookup(cve_id,attempts,next_attempt_at,last_error) "
                    "VALUES (?,0,?,NULL)",
                    (identifier, stamp),
                )
            for identifier in sorted(existing - candidates):
                db.execute("DELETE FROM watch_lookup WHERE cve_id=?", (identifier,))
            return len(candidates)

    def due_lookups(self, *, now: datetime, limit: int = 25) -> tuple[LookupRow, ...]:
        self.initialize()
        stamp = _timestamp(lambda: now)
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT cve_id,attempts,next_attempt_at,last_error FROM watch_lookup "
                "WHERE next_attempt_at <= ? ORDER BY next_attempt_at, cve_id LIMIT ?",
                (stamp, limit),
            ).fetchall()
        return tuple(
            LookupRow(
                row["cve_id"],
                row["attempts"],
                row["next_attempt_at"],
                row["last_error"],
            )
            for row in rows
        )

    def lookup_succeeded(self, identifier: str) -> None:
        self.initialize()
        with self.transaction() as db:
            db.execute("DELETE FROM watch_lookup WHERE cve_id=?", (identifier,))

    def lookup_failed(self, identifier: str, *, error: str, now: datetime) -> None:
        self.initialize()
        stamp = _timestamp(lambda: now)
        with self.transaction() as db:
            row = db.execute(
                "SELECT attempts FROM watch_lookup WHERE cve_id=?", (identifier,)
            ).fetchone()
            if row is None:
                return
            attempts = row["attempts"] + 1
            hours = min(2 ** min(attempts - 1, 10), 168)
            following = _timestamp(lambda: now + timedelta(hours=hours))
            db.execute(
                "UPDATE watch_lookup SET attempts=?,next_attempt_at=?,last_error=? "
                "WHERE cve_id=?",
                (attempts, following, error[:500], identifier),
            )

    def refresh_views(
        self, identifiers: Iterable[str], *, catalogs: Sequence[str] = ()
    ) -> StepCounts:
        self.initialize()
        now = _timestamp(self._clock)
        with self.transaction() as db:
            views = self._refresh_views(db, identifiers, catalogs, now)
        return StepCounts(
            new=views.new,
            changed=views.changed,
            unchanged=views.unchanged,
        )

    def view(self, identifier: str, *, catalogs: Sequence[str] = ()) -> Any | None:
        self.initialize()
        with closing(self._connect()) as db:
            return self._view(db, identifier, catalogs)

    def status(self) -> dict[str, Any]:
        self.initialize()
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                meta = {
                    row["key"]: row["value"]
                    for row in db.execute("SELECT key,value FROM watch_meta")
                }
                row_count = db.execute("SELECT COUNT(*) FROM watch_cve").fetchone()[0]
                euvd_items = db.execute(
                    "SELECT COUNT(*) FROM watch_euvd_item"
                ).fetchone()[0]
                cisa_kev = db.execute(
                    "SELECT COUNT(*) FROM watch_kev WHERE catalog='cisa'"
                ).fetchone()[0]
                eu_kev = db.execute(
                    "SELECT COUNT(*) FROM watch_kev WHERE catalog='eu'"
                ).fetchone()[0]
                any_kev = db.execute(
                    "SELECT COUNT(DISTINCT cve_id) FROM watch_kev"
                ).fetchone()[0]
                active_ssvc = db.execute(
                    "SELECT COUNT(*) FROM watch_cve WHERE ssvc_exploitation='active'"
                ).fetchone()[0]
                epss_rows = db.execute("SELECT COUNT(*) FROM watch_epss").fetchone()[0]
                epss_date = db.execute(
                    "SELECT MAX(score_date) FROM watch_epss"
                ).fetchone()[0]
                lookups = db.execute("SELECT COUNT(*) FROM watch_lookup").fetchone()[0]
            finally:
                db.rollback()
        return {
            "database": self.path,
            "meta": meta,
            "rows": row_count,
            "euvd_items": euvd_items,
            "cisa_kev": cisa_kev,
            "eu_kev": eu_kev,
            "any_kev": any_kev,
            "active_ssvc": active_ssvc,
            "epss_rows": epss_rows,
            "epss_date": epss_date,
            "lookups": lookups,
        }
