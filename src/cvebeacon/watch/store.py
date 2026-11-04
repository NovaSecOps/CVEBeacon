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

from ..errors import SourceError, StateError
from .records import (
    EPSS_BANDS,
    CVSSEntry,
    EUVDUpdate,
    KEVFields,
    Product,
    WatchRecord,
    build_view,
    canonical_json,
)
from .rules import (
    EVENT_KINDS,
    AlertSnapshot,
    AlertState,
    Rule,
    evaluate,
    rule_hash,
    snapshot_for,
)

SCHEMA_VERSION = 2
EUVD_MAX_AGE_DAYS = 30
EPSS_WRITE_BATCH = 5000
KEV_CATALOGS = ("cisa", "eu")
VIEW_POLICY_SOURCES = ("cisa_kev", "eu_kev", "euvd")
VIEW_POLICY_BATCH = 5000
EVALUATION_BATCH = 5000

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
        updated_at TEXT NOT NULL
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
    """CREATE TABLE IF NOT EXISTS watch_touched (
        cve_id TEXT PRIMARY KEY,
        touched_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS watch_lookup (
        cve_id TEXT PRIMARY KEY,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        last_error TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS watch_lookup_due ON watch_lookup(next_attempt_at)",
    """CREATE TABLE IF NOT EXISTS watch_alert_state (
        rule TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        first_matched_at TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        rule_hash TEXT NOT NULL,
        PRIMARY KEY(rule, cve_id)
    )""",
    """CREATE TABLE IF NOT EXISTS watch_event (
        id INTEGER PRIMARY KEY,
        rule TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        reasons_json TEXT NOT NULL,
        occurrence TEXT NOT NULL,
        initial INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(rule, cve_id, kind, occurrence)
    )""",
    """CREATE TABLE IF NOT EXISTS watch_delivery (
        event_id INTEGER NOT NULL,
        channel TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','sent','failed')),
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY(event_id, channel)
    )""",
    "CREATE INDEX IF NOT EXISTS watch_event_created ON watch_event(created_at, id)",
    "CREATE INDEX IF NOT EXISTS watch_delivery_status ON watch_delivery(status)",
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
class EvaluationResult:
    evaluated: int = 0
    events: int = 0
    by_kind: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class WatchEventRow:
    id: int
    rule: str
    cve_id: str
    kind: str
    reasons: tuple[str, ...]
    initial: bool
    created_at: str


@dataclass(frozen=True, slots=True)
class _ViewCounts:
    new: int = 0
    changed: int = 0
    unchanged: int = 0
    new_ids: tuple[str, ...] = ()
    changed_ids: tuple[str, ...] = ()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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
    unique: dict[tuple[str, str], Product] = {}
    for item in vendors:
        vendor = item.vendor.strip()
        product = item.product.strip()
        if vendor or product:
            unique.setdefault(
                (vendor.casefold(), product.casefold()), Product(vendor, product)
            )
    return canonical_json(
        [unique[key].as_dict() for key in sorted(unique)[:50]]
    )


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
            self._ensure_schema(db, _timestamp(self._clock))

    @staticmethod
    def _ensure_schema(db: sqlite3.Connection, now: str) -> None:
        db.execute(
            "CREATE TABLE IF NOT EXISTS watch_meta ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        rows = db.execute("SELECT value FROM watch_meta WHERE key='schema_version'").fetchall()
        if len(rows) > 1:
            raise StateError("ambiguous watch schema metadata; expected one version row")
        if not rows:
            for statement in _SCHEMA:
                db.execute(statement)
            db.execute(
                "INSERT INTO watch_meta(key,value) VALUES ('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
            return
        version = rows[0]["value"]
        if version not in {"1", "2"}:
            raise StateError(f"unsupported watch schema version {version}")
        for statement in _SCHEMA:
            db.execute(statement)
        if version == "1":
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(watch_euvd_item)")
            }
            if "vendors_json" not in columns:
                db.execute(
                    "ALTER TABLE watch_euvd_item ADD COLUMN "
                    "vendors_json TEXT NOT NULL DEFAULT '[]'"
                )
            # P1a stored its touch queue but never evaluated it. No rules
            # existed, so there is no evaluation obligation to carry forward.
            db.execute("DELETE FROM watch_touched")
            meta = {
                row["key"]: row["value"]
                for row in db.execute("SELECT key,value FROM watch_meta")
            }
            if "initial_mode" in meta and "initial_evaluated_at" not in meta:
                db.execute(
                    "INSERT INTO watch_meta(key,value) VALUES ('initial_evaluated_at',?)",
                    (meta.get("initialized_at") or now,),
                )
            db.execute(
                "UPDATE watch_meta SET value=? WHERE key='schema_version'",
                (str(SCHEMA_VERSION),),
            )

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

    def pending_evaluations(self, limit: int = 1000) -> tuple[str, ...]:
        """Return queued CVE ids in the order they were first touched."""
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT cve_id FROM watch_touched "
                "ORDER BY touched_at, cve_id LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(row["cve_id"] for row in rows)

    def acknowledge(self, identifiers: Iterable[str]) -> None:
        """Remove evaluation obligations that a consumer has completed."""
        self.initialize()
        with self.transaction() as db:
            db.executemany(
                "DELETE FROM watch_touched WHERE cve_id=?",
                ((identifier,) for identifier in sorted(set(identifiers))),
            )

    def apply_view_policy(self, catalogs: Sequence[str]) -> tuple[str, ...]:
        """Recompute stored views when the configured source selection changes."""
        policy = ",".join(
            sorted(set(catalogs).intersection(VIEW_POLICY_SOURCES))
        )
        self.initialize()
        now = _timestamp(self._clock)
        touched_ids: list[str] = []
        with self.transaction() as db:
            row = db.execute(
                "SELECT value FROM watch_meta WHERE key='view_policy'"
            ).fetchone()
            current = row["value"] if row is not None else None
            if current == policy:
                return ()
            last = ""
            while True:
                rows = db.execute(
                    "SELECT cve_id FROM watch_cve WHERE cve_id > ? "
                    "ORDER BY cve_id LIMIT ?",
                    (last, VIEW_POLICY_BATCH),
                ).fetchall()
                if not rows:
                    break
                identifiers = [item["cve_id"] for item in rows]
                self._refresh_views(db, identifiers, catalogs, now)
                # Vendor and product names are not in the view fingerprint,
                # so every CVE is queued when the derivation policy changes.
                self._mark_touched(db, identifiers, now)
                touched_ids.extend(identifiers)
                last = identifiers[-1]
            self._set_meta(db, {"view_policy": policy})
        return tuple(sorted(set(touched_ids)))

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
        if row is None:
            columns = (
                "cve_id",
                *_NVD_CONTENT_COLUMNS,
                "first_seen",
                "updated_at",
            )
            values = (record.cve_id, *content.values(), now, now)
            marks = ",".join("?" for _ in columns)
            db.execute(
                f"INSERT INTO watch_cve({','.join(columns)}) VALUES ({marks})", values
            )
            return "new"
        if all(row[column] == content[column] for column in _NVD_CONTENT_COLUMNS):
            return "unchanged"
        columns = (*_NVD_CONTENT_COLUMNS, "updated_at")
        assignments = ", ".join(f"{column}=?" for column in columns)
        values = (
            *(content[column] for column in _NVD_CONTENT_COLUMNS),
            now,
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
        euvd = self._best_euvd(db, identifier) if "euvd" in catalogs else None
        return build_view(
            record,
            euvd=euvd,
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
        new_ids: list[str] = []
        changed_ids: list[str] = []
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
                new_ids.append(identifier)
            elif row["fingerprint"] == fingerprint:
                unchanged += 1
            else:
                db.execute(
                    "UPDATE watch_view SET fingerprint=?,updated_at=? WHERE cve_id=?",
                    (fingerprint, now, identifier),
                )
                changed += 1
                changed_ids.append(identifier)
        return _ViewCounts(
            new,
            changed,
            unchanged,
            tuple(new_ids),
            tuple(changed_ids),
        )

    @staticmethod
    def _known_identifiers(
        db: sqlite3.Connection, identifiers: Iterable[str]
    ) -> tuple[str, ...]:
        values = sorted(set(identifiers))
        known: set[str] = set()
        for start in range(0, len(values), 500):
            chunk = values[start : start + 500]
            marks = ",".join("?" for _ in chunk)
            known.update(
                row["cve_id"]
                for row in db.execute(
                    f"SELECT cve_id FROM watch_cve WHERE cve_id IN ({marks})",
                    chunk,
                )
            )
        return tuple(sorted(known))

    @classmethod
    def _mark_touched(
        cls, db: sqlite3.Connection, identifiers: Iterable[str], now: str
    ) -> tuple[str, ...]:
        """Queue evaluation for CVEs that already have an NVD row."""
        known = cls._known_identifiers(db, identifiers)
        db.executemany(
            "INSERT OR IGNORE INTO watch_touched(cve_id,touched_at) VALUES (?,?)",
            ((identifier, now) for identifier in known),
        )
        return known

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
            queued = self._mark_touched(db, written, now)
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
            touched_ids=queued,
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
                    db.execute(
                        "UPDATE watch_euvd_item SET seen_at=? WHERE euvd_id=?",
                        (now, euvd_id),
                    )
                    outcomes.append((euvd_id, "unchanged"))
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
            queued = self._mark_touched(db, touched, now)
            if meta:
                self._set_meta(db, meta)
        new_items = tuple(identifier for identifier, outcome in outcomes if outcome == "new")
        changed_items = tuple(
            identifier for identifier, outcome in outcomes if outcome == "changed"
        )
        return StepCounts(
            new=len(new_items),
            changed=views.changed,
            unchanged=sum(outcome == "unchanged" for _, outcome in outcomes),
            new_ids=new_items,
            changed_ids=changed_items,
            touched_ids=queued,
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
            queued = self._mark_touched(db, touched, now)
            if meta:
                self._set_meta(db, meta)
        added = set(new) - set(old)
        common = set(old) & set(new)
        return StepCounts(
            new=len(added),
            changed=views.changed,
            unchanged=len(common - touched),
            new_ids=tuple(sorted(added)),
            changed_ids=tuple(sorted(touched)),
            touched_ids=queued,
        )

    def replace_epss(
        self,
        rows: Iterable[tuple[str, float, float, date]],
        *,
        meta: Mapping[str, str] | None = None,
        thresholds: Iterable[float] = EPSS_BANDS,
    ) -> EpssLoadResult:
        self.initialize()
        now = _timestamp(self._clock)
        with self.transaction() as db:
            old_rows = db.execute("SELECT COUNT(*) FROM watch_epss").fetchone()[0]
            db.execute(
                "CREATE TEMP TABLE watch_epss_load ("
                "cve_id TEXT PRIMARY KEY, epss REAL NOT NULL, "
                "percentile REAL NOT NULL, score_date TEXT NOT NULL)"
            )
            batch: list[tuple[str, float, float, str]] = []
            total = batches = 0
            for identifier, score, percentile, score_date in rows:
                batch.append(
                    (identifier, score, percentile, score_date.isoformat())
                )
                if len(batch) >= EPSS_WRITE_BATCH:
                    db.executemany(
                        "INSERT OR REPLACE INTO watch_epss_load"
                        "(cve_id,epss,percentile,score_date) VALUES (?,?,?,?)",
                        batch,
                    )
                    total += len(batch)
                    batches += 1
                    batch.clear()
            if batch:
                db.executemany(
                    "INSERT OR REPLACE INTO watch_epss_load"
                    "(cve_id,epss,percentile,score_date) VALUES (?,?,?,?)",
                    batch,
                )
                total += len(batch)
                batches += 1
            if old_rows and total < old_rows / 2:
                raise SourceError("epss", "source returned too few EPSS scores")
            clauses = []
            parameters: list[float] = []
            for threshold in sorted(set(thresholds)):
                clauses.append(
                    "((o.epss < ? AND n.epss >= ?) OR (o.epss >= ? AND n.epss < ?))"
                )
                parameters.extend(
                    (threshold, threshold, threshold, threshold)
                )
            crossing = " OR ".join(clauses) if clauses else "0"
            changed = {
                row["cve_id"]
                for row in db.execute(
                    "SELECT n.cve_id FROM watch_epss_load n "
                    "JOIN watch_cve c ON c.cve_id=n.cve_id "
                    "LEFT JOIN watch_epss o ON o.cve_id=n.cve_id "
                    f"WHERE o.cve_id IS NULL OR ({crossing}) "
                    "UNION "
                    "SELECT o.cve_id FROM watch_epss o "
                    "JOIN watch_cve c ON c.cve_id=o.cve_id "
                    "LEFT JOIN watch_epss_load n ON n.cve_id=o.cve_id "
                    "WHERE n.cve_id IS NULL",
                    parameters,
                )
            }
            file_day = db.execute(
                "SELECT MAX(score_date) FROM watch_epss_load"
            ).fetchone()[0]
            db.execute("DELETE FROM watch_epss")
            db.execute(
                "INSERT INTO watch_epss(cve_id,epss,percentile,score_date) "
                "SELECT cve_id,epss,percentile,score_date FROM watch_epss_load"
            )
            db.execute("DROP TABLE watch_epss_load")
            values = {"epss_file_day": file_day} if file_day else {}
            values.update(meta or {})
            if values:
                self._set_meta(db, values)
            self._mark_touched(db, changed, now)
        return EpssLoadResult(total, batches, tuple(sorted(changed)))

    @staticmethod
    def _alert_state(
        db: sqlite3.Connection, rule: str, identifier: str
    ) -> tuple[AlertState, str] | None:
        row = db.execute(
            "SELECT first_matched_at,snapshot_json,rule_hash FROM watch_alert_state "
            "WHERE rule=? AND cve_id=?",
            (rule, identifier),
        ).fetchone()
        if row is None:
            return None
        try:
            snapshot = AlertSnapshot.from_dict(json.loads(row["snapshot_json"]))
            stored_hash = str(row["rule_hash"])
        except (TypeError, ValueError, KeyError) as exc:
            raise StateError(
                f"watch alert state for rule {rule!r} and CVE {identifier} "
                "is invalid"
            ) from exc
        return AlertState(row["first_matched_at"], snapshot), stored_hash

    @staticmethod
    def _backlog_before(db: sqlite3.Connection) -> date | None:
        rows = {
            row["key"]: row["value"]
            for row in db.execute(
                "SELECT key,value FROM watch_meta "
                "WHERE key IN ('initial_window_start','initialized_at')"
            )
        }
        value = rows.get("initial_window_start") or rows.get("initialized_at")
        if not value:
            return None
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None

    def _evaluate_batch(
        self,
        db: sqlite3.Connection,
        identifiers: Sequence[str],
        rules: Sequence[Rule],
        catalogs: Sequence[str],
        now: datetime,
        initial: bool,
    ) -> dict[str, int]:
        created: dict[str, int] = {}
        stamp = _timestamp(lambda: now)
        backlog_before = self._backlog_before(db)
        for identifier in identifiers:
            view = self._view(db, identifier, catalogs)
            if view is None:
                continue
            for rule in rules:
                if not rule.enabled:
                    continue
                key = rule.name.casefold()
                current_hash = rule_hash(rule)
                stored = self._alert_state(db, key, identifier)
                if stored is not None and stored[1] != current_hash:
                    # The definition changed. Keep the old match, refresh the
                    # comparison baseline, and emit nothing for this evaluation.
                    snapshot = snapshot_for(view, rule)
                    db.execute(
                        "UPDATE watch_alert_state SET snapshot_json=?,rule_hash=? "
                        "WHERE rule=? AND cve_id=?",
                        (
                            canonical_json(snapshot.as_dict()),
                            current_hash,
                            key,
                            identifier,
                        ),
                    )
                    continue
                previous = stored[0] if stored is not None else None
                state, events = evaluate(
                    view,
                    previous,
                    rule,
                    now=now,
                    backlog_before=backlog_before,
                )
                if state is None:
                    continue
                db.execute(
                    "INSERT INTO watch_alert_state("
                    "rule,cve_id,first_matched_at,snapshot_json,rule_hash) "
                    "VALUES (?,?,?,?,?) "
                    "ON CONFLICT(rule,cve_id) DO UPDATE SET "
                    "snapshot_json=excluded.snapshot_json,"
                    "rule_hash=excluded.rule_hash",
                    (
                        key,
                        identifier,
                        state.first_matched_at,
                        canonical_json(state.snapshot.as_dict()),
                        current_hash,
                    ),
                )
                for event in events:
                    reasons_json = canonical_json(list(event.reasons))
                    cursor = db.execute(
                        "INSERT OR IGNORE INTO watch_event("
                        "rule,cve_id,kind,reasons_json,occurrence,initial,created_at) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (
                            event.rule.casefold(),
                            event.cve_id,
                            event.kind,
                            reasons_json,
                            event.occurrence,
                            1 if event.initial or (initial and event.kind == "match") else 0,
                            stamp,
                        ),
                    )
                    if cursor.rowcount == 0:
                        continue
                    event_id = cursor.lastrowid
                    db.executemany(
                        "INSERT OR IGNORE INTO watch_delivery("
                        "event_id,channel,status,attempts,last_error,updated_at) "
                        "VALUES (?,?,'pending',0,NULL,?)",
                        ((event_id, channel, stamp) for channel in rule.channels),
                    )
                    created[event.kind] = created.get(event.kind, 0) + 1
        return created

    @staticmethod
    def _evaluation_result(
        evaluated: int, created: dict[str, int]
    ) -> EvaluationResult:
        by_kind = tuple(
            (kind, created[kind]) for kind in EVENT_KINDS if created.get(kind)
        )
        return EvaluationResult(
            evaluated=evaluated,
            events=sum(created.values()),
            by_kind=by_kind,
        )

    def evaluate_touched(
        self,
        rules: Sequence[Rule],
        *,
        catalogs: Sequence[str] = (),
        initial: bool = False,
        complete: bool = True,
        limit: int = EVALUATION_BATCH,
    ) -> EvaluationResult:
        """Evaluate and acknowledge the durable touched queue in batches.

        ``complete`` is false when the originating sync had source failures, so
        an initial evaluation is repeated before the initial window is closed.
        """
        if limit < 1:
            raise StateError("watch evaluation batch size must be positive")
        self.initialize()
        evaluated = 0
        created: dict[str, int] = {}
        while True:
            with self.transaction() as db:
                rows = db.execute(
                    "SELECT cve_id FROM watch_touched "
                    "ORDER BY touched_at, cve_id LIMIT ?",
                    (limit,),
                ).fetchall()
                if not rows:
                    break
                identifiers = [row["cve_id"] for row in rows]
                now = _clock_value(self._clock)
                counts = self._evaluate_batch(
                    db, identifiers, rules, catalogs, now, initial
                )
                for kind, count in counts.items():
                    created[kind] = created.get(kind, 0) + count
                db.executemany(
                    "DELETE FROM watch_touched WHERE cve_id=?",
                    ((identifier,) for identifier in identifiers),
                )
                evaluated += len(identifiers)
        if initial and complete:
            self.set_metadata(
                {"initial_evaluated_at": _timestamp(self._clock)}
            )
        return self._evaluation_result(evaluated, created)

    def evaluate_all(
        self,
        rules: Sequence[Rule],
        *,
        catalogs: Sequence[str] = (),
        initial: bool = True,
        limit: int = EVALUATION_BATCH,
    ) -> EvaluationResult:
        """Evaluate every stored CVE, in batches, without consuming the queue."""
        if limit < 1:
            raise StateError("watch evaluation batch size must be positive")
        self.initialize()
        evaluated = 0
        created: dict[str, int] = {}
        last = ""
        while True:
            with self.transaction() as db:
                rows = db.execute(
                    "SELECT cve_id FROM watch_cve WHERE cve_id > ? "
                    "ORDER BY cve_id LIMIT ?",
                    (last, limit),
                ).fetchall()
                if not rows:
                    break
                identifiers = [row["cve_id"] for row in rows]
                now = _clock_value(self._clock)
                counts = self._evaluate_batch(
                    db, identifiers, rules, catalogs, now, initial
                )
                for kind, count in counts.items():
                    created[kind] = created.get(kind, 0) + count
                evaluated += len(identifiers)
                last = identifiers[-1]
        return self._evaluation_result(evaluated, created)

    def events(
        self,
        *,
        limit: int = 50,
        rule: str | None = None,
        pending: bool = False,
    ) -> tuple[WatchEventRow, ...]:
        if limit < 1:
            raise StateError("event limit must be positive")
        self.initialize()
        clauses = []
        parameters: list[Any] = []
        if rule is not None:
            clauses.append("e.rule = ?")
            parameters.append(rule.casefold())
        if pending:
            clauses.append(
                "EXISTS (SELECT 1 FROM watch_delivery d "
                "WHERE d.event_id=e.id AND d.status='pending')"
            )
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(limit)
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT e.id,e.rule,e.cve_id,e.kind,e.reasons_json,"
                "e.initial,e.created_at FROM watch_event e"
                + where
                + " ORDER BY e.created_at DESC, e.id DESC LIMIT ?",
                parameters,
            ).fetchall()
        output: list[WatchEventRow] = []
        for row in rows:
            try:
                reasons = tuple(str(item) for item in json.loads(row["reasons_json"]))
            except (TypeError, ValueError) as exc:
                raise StateError("watch database contains an invalid event") from exc
            output.append(
                WatchEventRow(
                    row["id"],
                    row["rule"],
                    row["cve_id"],
                    row["kind"],
                    reasons,
                    bool(row["initial"]),
                    row["created_at"],
                )
            )
        return tuple(output)

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

    def view(self, identifier: str, *, catalogs: Sequence[str] = ()) -> Any | None:
        self.initialize()
        with closing(self._connect()) as db:
            return self._view(db, identifier, catalogs)

    def status(self, *, catalogs: Sequence[str] = ()) -> dict[str, Any]:
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
                if "cisa_kev" in catalogs:
                    cisa_watched = {
                        row["cve_id"]
                        for row in db.execute(
                            "SELECT DISTINCT k.cve_id FROM watch_kev k "
                            "JOIN watch_cve c ON c.cve_id=k.cve_id "
                            "WHERE k.catalog='cisa'"
                        )
                    }
                else:
                    cisa_watched = {
                        row["cve_id"]
                        for row in db.execute(
                            "SELECT cve_id FROM watch_cve "
                            "WHERE cisa_kev_added IS NOT NULL "
                            "OR cisa_kev_due IS NOT NULL "
                            "OR cisa_required_action IS NOT NULL "
                            "OR cisa_ransomware IS NOT NULL"
                        )
                    }
                if "eu_kev" in catalogs:
                    eu_watched = {
                        row["cve_id"]
                        for row in db.execute(
                            "SELECT DISTINCT k.cve_id FROM watch_kev k "
                            "JOIN watch_cve c ON c.cve_id=k.cve_id "
                            "WHERE k.catalog='eu'"
                        )
                    }
                else:
                    eu_watched = set()
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
            "cisa_watched": len(cisa_watched),
            "eu_watched": len(eu_watched),
            "any_watched": len(cisa_watched | eu_watched),
            "active_ssvc": active_ssvc,
            "epss_rows": epss_rows,
            "epss_date": epss_date,
            "lookups": lookups,
        }
