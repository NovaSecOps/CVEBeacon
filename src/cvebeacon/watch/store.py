"""Transactional SQLite storage for recently changed CVEs.

Each source keeps its own raw table.  The alert-relevant view of a CVE is
derived from those tables and only its fingerprint is stored in ``watch_view``.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from ..errors import SourceError, StateError
from .records import (
    EPSS_BANDS,
    CVSSEntry,
    DeliveryEvent,
    EUVDUpdate,
    InitialDigest,
    KEVFields,
    Product,
    ReportedMark,
    WatchRecord,
    build_view,
    canonical_json,
)
from .reported import (
    NOTICE_KINDS,
    NOTICE_RULE,
    NoticeDelivery,
    ReportedEntry,
    normalize_cve_id,
    validate_identity,
    validate_note,
)
from .rules import (
    EVENT_KINDS,
    AlertSnapshot,
    AlertState,
    Rule,
    evaluate,
    providers_hash,
    rebase_severity,
    rule_hash,
)

SCHEMA_VERSION = 5
EUVD_MAX_AGE_DAYS = 30
EPSS_WRITE_BATCH = 5000
KEV_CATALOGS = ("cisa", "eu")
VIEW_POLICY_SOURCES = ("cisa_kev", "eu_kev", "euvd", "epss")
VIEW_POLICY_BATCH = 5000
EVALUATION_BATCH = 5000
DELIVERY_RETRY_BASE_SECONDS = 300
DELIVERY_RETRY_CAP_SECONDS = 6 * 3600
DELIVERY_MAX_ATTEMPTS = 10
DELIVERY_SELECT_LIMIT = 1000
DELIVERY_RECOVERY_SECONDS = 600
DELIVERY_RETRY_FLOOR = "1970-01-01T00:00:00+00:00"
_LATEST_REPORT_SQL = (
    "SELECT r.id,r.cve_id,r.action,r.by,r.note,r.at FROM watch_report r "
    "WHERE r.action='report' AND NOT EXISTS ("
    "SELECT 1 FROM watch_report x WHERE x.cve_id=r.cve_id AND x.id > r.id)"
)
# The claim uses ``last_error`` to remember that a row was ambiguous before
# this attempt, so a bulk failure can keep it ambiguous without an id list.
_INITIAL_AMBIGUOUS = "__ambiguous_before_retry__"
_RETRY_SECONDS_SQL = (
    "CASE WHEN d.attempts <= 1 THEN 300 "
    "WHEN d.attempts = 2 THEN 600 "
    "WHEN d.attempts = 3 THEN 1200 "
    "WHEN d.attempts = 4 THEN 2400 "
    "WHEN d.attempts = 5 THEN 4800 "
    "WHEN d.attempts = 6 THEN 9600 "
    "WHEN d.attempts = 7 THEN 19200 "
    "ELSE 21600 END"
)

# Previous statuses from which each target is allowed. ``sent`` is final and an
# ``ambiguous`` row may only become ``sent`` or stay ``ambiguous``. A claim goes
# to ``sending`` through ``claim_delivery`` rather than ``mark_delivery``.
DELIVERY_PREDECESSORS = {
    "pending": ("sending", "failed"),
    "sending": ("pending", "failed"),
    "sent": ("pending", "sending", "failed", "ambiguous"),
    "failed": ("pending", "sending", "failed"),
    "ambiguous": ("pending", "sending", "failed", "ambiguous"),
}


class _ClaimConflict(Exception):
    """Another run already owns at least one row in this claim."""

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
        providers_hash TEXT NOT NULL,
        PRIMARY KEY(rule, cve_id)
    )""",
    """CREATE TABLE IF NOT EXISTS watch_event (
        id INTEGER PRIMARY KEY,
        rule TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        reasons_json TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}',
        occurrence TEXT NOT NULL,
        initial INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(rule, cve_id, kind, occurrence)
    )""",
    """CREATE TABLE IF NOT EXISTS watch_delivery (
        event_id INTEGER NOT NULL,
        channel TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','sending','sent','failed','ambiguous')),
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        first_attempt_at TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY(event_id, channel)
    )""",
    """CREATE TABLE IF NOT EXISTS watch_report (
        id INTEGER PRIMARY KEY,
        cve_id TEXT NOT NULL,
        action TEXT NOT NULL CHECK(action IN ('report','unreport')),
        by TEXT NOT NULL,
        note TEXT,
        at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS watch_event_created ON watch_event(created_at, id)",
    "CREATE INDEX IF NOT EXISTS watch_delivery_status ON watch_delivery(status)",
    "CREATE INDEX IF NOT EXISTS watch_report_cve ON watch_report(cve_id, id)",
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
    initial_sync_pending: bool = False


@dataclass(frozen=True, slots=True)
class WatchEventRow:
    id: int
    rule: str
    cve_id: str
    kind: str
    reasons: tuple[str, ...]
    initial: bool
    created_at: str
    details: Mapping[str, Any] = field(default_factory=dict)
    published: str | None = None
    first_seen: str | None = None


@dataclass(frozen=True, slots=True)
class DeliveryStatusRow:
    channel: str
    pending: int = 0
    sending: int = 0
    failed: int = 0
    given_up: int = 0
    ambiguous: int = 0
    last_success: str | None = None


@dataclass(frozen=True, slots=True)
class ReportOutcome:
    """The result of recording or withdrawing one client-report mark."""

    entry: ReportedEntry | None = None
    changed: bool = False
    event_id: int | None = None
    channels: tuple[str, ...] = ()


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


def _alert_columns_current(db: sqlite3.Connection) -> bool:
    alert = {row["name"] for row in db.execute("PRAGMA table_info(watch_alert_state)")}
    event = {row["name"] for row in db.execute("PRAGMA table_info(watch_event)")}
    return {"rule_hash", "providers_hash"} <= alert and "occurrence" in event


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
        if version not in {"1", "2", "3", "4", "5"}:
            raise StateError(f"unsupported watch schema version {version}")
        if version in {"2", "3", "4", "5"} and not _alert_columns_current(db):
            # Pre-release builds wrote schema 2 without these columns. They are
            # not migrated; the operator deletes the file and resyncs.
            raise StateError(
                "watch database was created by a pre-release build; "
                "delete it and run `watch sync` again"
            )
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
            # P1a stored EUVD items without vendor names and never re-read them.
            # Rewinding the cursor makes the next sync re-read the initial window.
            if meta.get("initial_window_start") and meta.get("euvd_cursor"):
                db.execute(
                    "UPDATE watch_meta SET value=? WHERE key='euvd_cursor'",
                    (meta["initial_window_start"],),
                )
        if version in {"1", "2"}:
            WatchStore._migrate_event_details(db)
            WatchStore._migrate_delivery_statuses(db)
        elif version == "3":
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(watch_delivery)")
            }
            if "first_attempt_at" not in columns:
                db.execute(
                    "ALTER TABLE watch_delivery ADD COLUMN first_attempt_at TEXT"
                )
        if version != str(SCHEMA_VERSION):
            db.execute(
                "UPDATE watch_meta SET value=? WHERE key='schema_version'",
                (str(SCHEMA_VERSION),),
            )

    @staticmethod
    def _migrate_event_details(db: sqlite3.Connection) -> None:
        columns = {
            row["name"] for row in db.execute("PRAGMA table_info(watch_event)")
        }
        if "details_json" not in columns:
            db.execute(
                "ALTER TABLE watch_event ADD COLUMN "
                "details_json TEXT NOT NULL DEFAULT '{}'"
            )

    @staticmethod
    def _migrate_delivery_statuses(db: sqlite3.Connection) -> None:
        """Rebuild the delivery table with the version 3 status set."""
        db.execute("DROP TABLE IF EXISTS watch_delivery_v3")
        db.execute(
            "CREATE TABLE watch_delivery_v3 ("
            "event_id INTEGER NOT NULL,"
            "channel TEXT NOT NULL,"
            "status TEXT NOT NULL CHECK(status IN "
            "('pending','sending','sent','failed','ambiguous')),"
            "attempts INTEGER NOT NULL DEFAULT 0,"
            "last_error TEXT,"
            "first_attempt_at TEXT,"
            "updated_at TEXT NOT NULL,"
            "PRIMARY KEY(event_id, channel))"
        )
        db.execute(
            "INSERT OR IGNORE INTO watch_delivery_v3"
            "(event_id,channel,status,attempts,last_error,first_attempt_at,updated_at) "
            "SELECT event_id,channel,status,attempts,last_error,NULL,updated_at "
            "FROM watch_delivery"
        )
        db.execute("DROP TABLE watch_delivery")
        db.execute("ALTER TABLE watch_delivery_v3 RENAME TO watch_delivery")
        db.execute(
            "CREATE INDEX IF NOT EXISTS watch_delivery_status "
            "ON watch_delivery(status)"
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
            epss=self._epss_row(db, identifier) if "epss" in catalogs else None,
            first_seen=row["first_seen"],
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
            "SELECT first_matched_at,snapshot_json,providers_hash FROM watch_alert_state "
            "WHERE rule=? AND cve_id=?",
            (rule, identifier),
        ).fetchone()
        if row is None:
            return None
        try:
            snapshot = AlertSnapshot.from_dict(json.loads(row["snapshot_json"]))
            stored_providers = str(row["providers_hash"])
        except (TypeError, ValueError, KeyError) as exc:
            raise StateError(
                f"watch alert state for rule {rule!r} and CVE {identifier} "
                "is invalid"
            ) from exc
        return AlertState(row["first_matched_at"], snapshot), stored_providers

    @staticmethod
    def _backlog_before(db: sqlite3.Connection) -> date | None:
        rows = {
            row["key"]: row["value"]
            for row in db.execute(
                "SELECT key,value FROM watch_meta "
                "WHERE key IN ('initial_window_start','initialized_at','initial_mode')"
            )
        }
        if rows.get("initial_mode") == "baseline":
            value = rows.get("initialized_at") or rows.get("initial_window_start")
        else:
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
                current_providers = providers_hash(rule)
                stored = self._alert_state(db, key, identifier)
                previous = None
                if stored is not None:
                    previous, stored_providers = stored
                    # Only a CVSS provider change moves the stored severity bands.
                    # Other edits keep the old marks, so escalations that arrive
                    # with the edit still fire.
                    if stored_providers != current_providers:
                        previous = rebase_severity(previous, view, rule)
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
                    "rule,cve_id,first_matched_at,snapshot_json,rule_hash,providers_hash) "
                    "VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(rule,cve_id) DO UPDATE SET "
                    "snapshot_json=excluded.snapshot_json,"
                    "rule_hash=excluded.rule_hash,"
                    "providers_hash=excluded.providers_hash",
                    (
                        key,
                        identifier,
                        state.first_matched_at,
                        canonical_json(state.snapshot.as_dict()),
                        current_hash,
                        current_providers,
                    ),
                )
                for event in events:
                    reasons_json = canonical_json(list(event.reasons))
                    details_json = canonical_json(dict(event.details))
                    cursor = db.execute(
                        "INSERT OR IGNORE INTO watch_event("
                        "rule,cve_id,kind,reasons_json,details_json,occurrence,"
                        "initial,created_at) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (
                            event.rule.casefold(),
                            event.cve_id,
                            event.kind,
                            reasons_json,
                            details_json,
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
        evaluated: int,
        created: dict[str, int],
        *,
        initial_sync_pending: bool = False,
    ) -> EvaluationResult:
        by_kind = tuple(
            (kind, created[kind]) for kind in EVENT_KINDS if created.get(kind)
        )
        return EvaluationResult(
            evaluated=evaluated,
            events=sum(created.values()),
            by_kind=by_kind,
            initial_sync_pending=initial_sync_pending,
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
        """Evaluate every stored CVE, in batches, without consuming the queue.

        When a ``backfill`` or ``full`` database has finished a failure-free
        initial sync and still owes the initial evaluation, this pass closes
        initialization the same way ``watch run`` does: it acknowledges each
        evaluated batch inside that batch's transaction and records
        ``initial_evaluated_at`` after the whole pass succeeds. While the
        initial sync is unproven or incomplete, initialization stays open and
        the queue is kept.
        """
        if limit < 1:
            raise StateError("watch evaluation batch size must be positive")
        self.initialize()
        metadata = self.metadata()
        initial_pending = (
            initial
            and metadata.get("initial_mode") in ("backfill", "full")
            and "initial_evaluated_at" not in metadata
        )
        close_initial = (
            initial_pending and "initial_sync_completed_at" in metadata
        )
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
                if close_initial:
                    db.executemany(
                        "DELETE FROM watch_touched WHERE cve_id=?",
                        ((identifier,) for identifier in identifiers),
                    )
                evaluated += len(identifiers)
                last = identifiers[-1]
        if close_initial:
            self.set_metadata(
                {"initial_evaluated_at": _timestamp(self._clock)}
            )
        return self._evaluation_result(
            evaluated,
            created,
            initial_sync_pending=initial_pending and not close_initial,
        )

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
        clauses = [
            "e.kind NOT IN (" + ",".join("?" for _ in NOTICE_KINDS) + ")"
        ]
        parameters: list[Any] = list(NOTICE_KINDS)
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
                "e.details_json,e.initial,e.created_at,"
                "c.published AS published,c.first_seen AS first_seen "
                "FROM watch_event e LEFT JOIN watch_cve c ON c.cve_id=e.cve_id"
                + where
                + " ORDER BY e.created_at DESC, e.id DESC LIMIT ?",
                parameters,
            ).fetchall()
        output: list[WatchEventRow] = []
        for row in rows:
            try:
                reasons = tuple(str(item) for item in json.loads(row["reasons_json"]))
                details = json.loads(row["details_json"] or "{}")
            except (TypeError, ValueError) as exc:
                raise StateError("watch database contains an invalid event") from exc
            if not isinstance(details, dict):
                raise StateError("watch database contains an invalid event")
            output.append(
                WatchEventRow(
                    row["id"],
                    row["rule"],
                    row["cve_id"],
                    row["kind"],
                    reasons,
                    bool(row["initial"]),
                    row["created_at"],
                    details,
                    row["published"],
                    row["first_seen"],
                )
            )
        return tuple(output)

    @staticmethod
    def _report_entry(row: Mapping[str, Any]) -> ReportedEntry:
        return ReportedEntry(
            int(row["id"]),
            str(row["cve_id"]),
            str(row["action"]),
            str(row["by"]),
            row["note"],
            str(row["at"]),
        )

    @staticmethod
    def _latest_report_row(
        db: sqlite3.Connection, identifier: object
    ) -> sqlite3.Row | None:
        return db.execute(
            "SELECT id,cve_id,action,by,note,at FROM watch_report "
            "WHERE cve_id=? ORDER BY id DESC LIMIT 1",
            (identifier,),
        ).fetchone()

    @staticmethod
    def _latest_report(
        db: sqlite3.Connection, identifier: str
    ) -> ReportedEntry | None:
        row = WatchStore._latest_report_row(db, identifier)
        return None if row is None else WatchStore._report_entry(row)

    @staticmethod
    def _record_report_notice(
        db: sqlite3.Connection,
        entry: ReportedEntry,
        channels: Sequence[str],
        now: str,
    ) -> int | None:
        """Queue the optional notice through the normal delivery ledger."""
        if not channels:
            return None
        if entry.action == "report":
            kind = "reported"
            reason = f"reported to clients by {entry.by}"
        else:
            kind = "unreported"
            reason = f"report withdrawn by {entry.by}"
        cursor = db.execute(
            "INSERT INTO watch_event("
            "rule,cve_id,kind,reasons_json,details_json,occurrence,initial,created_at) "
            "VALUES (?,?,?,?,?,?,0,?)",
            (
                NOTICE_RULE,
                entry.cve_id,
                kind,
                canonical_json([reason]),
                canonical_json({"by": entry.by, "note": entry.note}),
                f"{entry.action}:{entry.id}",
                now,
            ),
        )
        event_id = int(cursor.lastrowid)
        db.executemany(
            "INSERT INTO watch_delivery("
            "event_id,channel,status,attempts,last_error,updated_at) "
            "VALUES (?,?,'pending',0,NULL,?)",
            ((event_id, channel, now) for channel in channels),
        )
        return event_id

    def report_cve(
        self,
        cve_id: object,
        *,
        by: object,
        note: object | None = None,
        force: bool = False,
        notify_channels: Iterable[str] = (),
    ) -> ReportOutcome:
        """Mark a stored CVE as reported to clients.

        The caller resolves the identity; this store keeps it as free text.
        The latest ``watch_report`` row is the current state. A repeated mark
        keeps the existing row and notification; ``force`` appends a new one.
        """
        identifier = normalize_cve_id(cve_id)
        identity = validate_identity(by)
        text = validate_note(note)
        channels = tuple(sorted({str(name) for name in notify_channels if name}))
        self.initialize()
        now = _timestamp(self._clock)
        with self.transaction() as db:
            known = db.execute(
                "SELECT 1 FROM watch_cve WHERE cve_id=?", (identifier,)
            ).fetchone()
            if known is None:
                raise StateError(f"{identifier} is not in the watch database")
            latest = self._latest_report(db, identifier)
            if latest is not None and latest.action == "report" and not force:
                return ReportOutcome(latest, False)
            cursor = db.execute(
                "INSERT INTO watch_report(cve_id,action,by,note,at) "
                "VALUES (?,?,?,?,?)",
                (identifier, "report", identity, text, now),
            )
            entry = ReportedEntry(
                int(cursor.lastrowid), identifier, "report", identity, text, now
            )
            event_id = self._record_report_notice(db, entry, channels, now)
        return ReportOutcome(entry, True, event_id, channels)

    def unreport_cve(
        self,
        cve_id: object,
        *,
        by: object,
        note: object | None = None,
        notify_channels: Iterable[str] = (),
    ) -> ReportOutcome:
        """Withdraw the current report mark by appending an ``unreport`` row."""
        identifier = normalize_cve_id(cve_id)
        identity = validate_identity(by)
        text = validate_note(note)
        channels = tuple(sorted({str(name) for name in notify_channels if name}))
        self.initialize()
        now = _timestamp(self._clock)
        with self.transaction() as db:
            latest = self._latest_report(db, identifier)
            if latest is None or latest.action != "report":
                return ReportOutcome(None, False)
            cursor = db.execute(
                "INSERT INTO watch_report(cve_id,action,by,note,at) "
                "VALUES (?,?,?,?,?)",
                (identifier, "unreport", identity, text, now),
            )
            entry = ReportedEntry(
                int(cursor.lastrowid), identifier, "unreport", identity, text, now
            )
            event_id = self._record_report_notice(db, entry, channels, now)
        return ReportOutcome(entry, True, event_id, channels)

    def reported_entries(self) -> tuple[ReportedEntry, ...]:
        """Return the full append-only audit trail, oldest first."""
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT id,cve_id,action,by,note,at FROM watch_report ORDER BY id"
            ).fetchall()
        return tuple(self._report_entry(row) for row in rows)

    def reported_cves(self) -> tuple[ReportedEntry, ...]:
        """Return the latest ``report`` row of every currently reported CVE."""
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                _LATEST_REPORT_SQL + " ORDER BY r.at, r.id"
            ).fetchall()
        return tuple(self._report_entry(row) for row in rows)

    @staticmethod
    def _reported_marks_in(
        db: sqlite3.Connection, identifiers: Iterable[str]
    ) -> dict[str, ReportedMark]:
        values = sorted({str(value) for value in identifiers if value})
        if not values:
            return {}
        output: dict[str, ReportedMark] = {}
        for start in range(0, len(values), 500):
            chunk = values[start : start + 500]
            marks = ",".join("?" for _ in chunk)
            rows = db.execute(
                "SELECT r.cve_id,r.by,r.note,r.at FROM watch_report r "
                "JOIN (SELECT cve_id,MAX(id) AS id FROM watch_report "
                f"WHERE cve_id IN ({marks}) GROUP BY cve_id) m ON m.id=r.id "
                "WHERE r.action='report'",
                chunk,
            ).fetchall()
            for row in rows:
                output[str(row["cve_id"])] = ReportedMark(
                    str(row["cve_id"]), str(row["by"]), row["note"], str(row["at"])
                )
        return output

    def reported_marks(
        self, identifiers: Iterable[str]
    ) -> dict[str, ReportedMark]:
        """Return the current mark for each of ``identifiers`` that has one."""
        self.initialize()
        with closing(self._connect()) as db:
            return self._reported_marks_in(db, identifiers)

    def notice_deliveries(
        self,
    ) -> dict[tuple[str, int], tuple[NoticeDelivery, ...]]:
        """Return notice delivery states keyed by (action, report id)."""
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT e.kind,e.occurrence,d.channel,d.status,d.attempts,"
                "d.last_error FROM watch_event e "
                "JOIN watch_delivery d ON d.event_id=e.id "
                "WHERE e.rule=? ORDER BY e.id, d.channel",
                (NOTICE_RULE,),
            ).fetchall()
        output: dict[tuple[str, int], list[NoticeDelivery]] = {}
        for row in rows:
            action = "report" if row["kind"] == "reported" else "unreport"
            _, _, raw_id = str(row["occurrence"]).partition(":")
            try:
                key = (action, int(raw_id))
            except ValueError:
                continue
            output.setdefault(key, []).append(
                NoticeDelivery(
                    str(row["channel"]),
                    str(row["status"]),
                    int(row["attempts"]),
                    row["last_error"],
                )
            )
        return {key: tuple(value) for key, value in output.items()}

    @staticmethod
    def _reported_mark(
        db: sqlite3.Connection, identifier: object
    ) -> ReportedMark | None:
        row = WatchStore._latest_report_row(db, identifier)
        if row is None or row["action"] != "report":
            return None
        return ReportedMark(
            str(row["cve_id"]), str(row["by"]), row["note"], str(row["at"])
        )

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def delivery_retry_delay(attempts: int) -> timedelta:
        exponent = max(0, attempts - 1)
        return timedelta(
            seconds=min(
                DELIVERY_RETRY_BASE_SECONDS * (2**exponent),
                DELIVERY_RETRY_CAP_SECONDS,
            )
        )

    def recover_sending(
        self, *, older_than_seconds: float = DELIVERY_RECOVERY_SECONDS
    ) -> int:
        """Treat deliveries left in ``sending`` by a crash as ambiguous.

        A newer ``sending`` row belongs to a live run and is left alone.
        """
        self.initialize()
        current = _clock_value(self._clock)
        cutoff = (
            current - timedelta(seconds=max(0.0, older_than_seconds))
        ).isoformat()
        with self.transaction() as db:
            cursor = db.execute(
                "UPDATE watch_delivery SET status='ambiguous', "
                "first_attempt_at=COALESCE(first_attempt_at, updated_at), "
                "updated_at=?, last_error='interrupted before confirmation' "
                "WHERE status='sending' AND updated_at < ?",
                (_timestamp(self._clock), cutoff),
            )
            return cursor.rowcount

    @staticmethod
    def _initial_condition(
        channel: str, include_ambiguous: bool, now: str
    ) -> tuple[str, tuple[Any, ...]]:
        """Rows one initial digest may cover, including the retry backoff."""
        return (
            "d.channel=? AND e.initial=1 AND ("
            "d.status='pending' OR "
            "(d.status='failed' AND d.attempts < ? AND "
            "julianday(d.updated_at) + (" + _RETRY_SECONDS_SQL + ")/86400.0 "
            "<= julianday(?)) OR "
            "(d.status='ambiguous' AND ?))",
            (channel, DELIVERY_MAX_ATTEMPTS, now, 1 if include_ambiguous else 0),
        )

    @staticmethod
    def _initial_order(
        catalogs: Sequence[str],
    ) -> tuple[tuple[str, ...], tuple[str, ...], str]:
        """Order initial rows in SQL without building a view for each one.

        This is a close approximation of ``messages.sort_events``. KEV entries
        and active exploitation come first, then the highest CVSS score and
        EPSS. The sampled rows are sorted exactly before rendering.

        The first tuple orders rows, the second orders distinct CVEs for the
        sample, and the last value is the optional EPSS join.
        """
        kev = []
        if "cisa_kev" in catalogs:
            kev.append(
                "EXISTS (SELECT 1 FROM watch_kev k "
                "WHERE k.catalog='cisa' AND k.cve_id=e.cve_id)"
            )
        else:
            kev.append("c.cisa_kev_added IS NOT NULL")
        if "eu_kev" in catalogs:
            kev.append(
                "EXISTS (SELECT 1 FROM watch_kev k "
                "WHERE k.catalog='eu' AND k.cve_id=e.cve_id)"
            )
        exploitation = ["c.ssvc_exploitation='active'"]
        if "euvd" in catalogs:
            exploitation.append(
                "EXISTS (SELECT 1 FROM watch_euvd_alias a "
                "JOIN watch_euvd_item i ON i.euvd_id=a.euvd_id "
                "WHERE a.cve_id=e.cve_id AND i.exploited_since IS NOT NULL)"
            )
        modern = (
            "(SELECT MAX(CAST(json_extract(value,'$.score') AS REAL)) "
            "FROM json_each(c.cvss_json) "
            "WHERE json_extract(value,'$.version') <> '2.0')"
        )
        any_score = (
            "(SELECT MAX(CAST(json_extract(value,'$.score') AS REAL)) "
            "FROM json_each(c.cvss_json))"
        )
        cvss = f"COALESCE({modern}, {any_score}, -1)"
        if "euvd" in catalogs:
            euvd_score = (
                "(SELECT MAX(i.score) FROM watch_euvd_alias a "
                "JOIN watch_euvd_item i ON i.euvd_id=a.euvd_id "
                "WHERE a.cve_id=e.cve_id)"
            )
            cvss = f"MAX({cvss}, COALESCE({euvd_score}, -1))"
        join = ""
        if "epss" in catalogs:
            join = "LEFT JOIN watch_epss p ON p.cve_id=e.cve_id"
            epss = "COALESCE(p.epss, -1)"
        else:
            epss = "(-1.0)"
        kev_case = f"CASE WHEN ({' OR '.join(kev)}) THEN 0 ELSE 1 END"
        exploitation_case = (
            f"CASE WHEN ({' OR '.join(exploitation)}) THEN 0 ELSE 1 END"
        )
        order = (
            kev_case,
            exploitation_case,
            f"{cvss} DESC",
            f"{epss} DESC",
            "e.created_at",
            "e.id",
        )
        # Every sort key except the row identity is constant for one CVE, so
        # the aggregate picks the same top CVEs as the row order would.
        grouped = (
            f"MIN({kev_case})",
            f"MIN({exploitation_case})",
            f"MAX({cvss}) DESC",
            f"MAX({epss}) DESC",
            "MIN(e.created_at)",
            "MIN(e.id)",
        )
        return order, grouped, join

    def _delivery_event(
        self,
        db: sqlite3.Connection,
        row: Mapping[str, Any],
        catalogs: Sequence[str],
        marks: Mapping[str, ReportedMark] | None = None,
    ) -> DeliveryEvent | None:
        view = self._view(db, row["cve_id"], catalogs)
        if view is None:
            return None
        try:
            reasons = tuple(str(item) for item in json.loads(row["reasons_json"]))
            details = json.loads(row["details_json"] or "{}")
        except (TypeError, ValueError) as exc:
            raise StateError("watch database contains an invalid event") from exc
        if not isinstance(details, dict):
            raise StateError("watch database contains an invalid event")
        mark = (
            marks.get(str(row["cve_id"]))
            if marks is not None
            else self._reported_mark(db, row["cve_id"])
        )
        return DeliveryEvent(
            row["id"],
            row["rule"],
            row["cve_id"],
            row["kind"],
            reasons,
            bool(row["initial"]),
            row["created_at"],
            view,
            details,
            str(row["status"]),
            mark,
        )

    def delivery_events(
        self,
        channel: str,
        *,
        catalogs: Sequence[str] = (),
        now: datetime | None = None,
        include_ambiguous: bool = False,
        limit: int = DELIVERY_SELECT_LIMIT,
        event_ids: Iterable[int] | None = None,
    ) -> tuple[DeliveryEvent, ...]:
        """Return non-initial deliveries one channel may send now, oldest first.

        Initial rows are handled by :meth:`claim_initial_digest` and
        :meth:`claim_initial_chunk`, which keep the backlog out of memory.
        ``event_ids`` limits the result to those events, which the report and
        unreport commands use to attempt only their own notice.
        """
        if limit < 1:
            raise StateError("delivery batch size must be positive")
        selected: tuple[int, ...] | None = None
        if event_ids is not None:
            selected = tuple(sorted({int(value) for value in event_ids}))
            if not selected:
                return ()
            if len(selected) > DELIVERY_SELECT_LIMIT:
                raise StateError("too many delivery events selected")
        self.initialize()
        current = _clock_value(lambda: now) if now is not None else _clock_value(self._clock)
        base = (
            "SELECT e.id,e.rule,e.cve_id,e.kind,e.reasons_json,e.details_json,"
            "e.initial,e.created_at,d.status,d.attempts,d.updated_at,d.first_attempt_at "
            "FROM watch_event e JOIN watch_delivery d ON d.event_id=e.id "
            "WHERE d.channel=? AND e.initial=0 AND ("
            "d.status='pending' OR "
            "(d.status='failed' AND d.attempts < ?) OR "
            "(d.status='ambiguous' AND ?))"
        )
        parameters: list[Any] = [
            channel,
            DELIVERY_MAX_ATTEMPTS,
            1 if include_ambiguous else 0,
        ]
        if selected is not None:
            base += " AND e.id IN (" + ",".join("?" for _ in selected) + ")"
            parameters.extend(selected)
        with closing(self._connect()) as db:
            found = db.execute(
                base + " ORDER BY e.created_at, e.id LIMIT ?",
                (*parameters, limit),
            ).fetchall()
            marks = self._reported_marks_in(
                db, (row["cve_id"] for row in found)
            )
            output: list[DeliveryEvent] = []
            for row in found:
                if row["status"] == "failed":
                    updated = self._parse_timestamp(row["updated_at"])
                    delay = self.delivery_retry_delay(int(row["attempts"]))
                    if updated is not None and updated + delay > current:
                        continue
                event = self._delivery_event(db, row, catalogs, marks)
                if event is not None:
                    output.append(event)
        return tuple(output)

    def claim_initial_digest(
        self,
        channel: str,
        *,
        catalogs: Sequence[str] = (),
        now: datetime | None = None,
        max_items: int,
        include_ambiguous: bool = False,
    ) -> InitialDigest | None:
        """Count and claim every selected initial row, sampling only the top ones.

        Counts come from SQL, and only ``max_items`` rows get a full view. The
        whole selected set moves to ``sending`` in the same transaction, so no
        event id list for the backlog is kept in Python.
        """
        if max_items < 1:
            raise StateError("initial digest sample size must be positive")
        self.initialize()
        current = _clock_value(lambda: now) if now is not None else _clock_value(self._clock)
        stamp = current.isoformat()
        try:
            with self.transaction() as db:
                condition, parameters = self._initial_condition(
                    channel, include_ambiguous, stamp
                )
                counts = db.execute(
                    "SELECT e.rule,e.kind,COUNT(*) AS count,"
                    "SUM(CASE WHEN d.status='ambiguous' THEN 1 ELSE 0 END) "
                    "AS ambiguous FROM watch_event e "
                    "JOIN watch_delivery d ON d.event_id=e.id "
                    "WHERE " + condition + " GROUP BY e.rule,e.kind "
                    "ORDER BY e.rule,e.kind",
                    parameters,
                ).fetchall()
                total = sum(int(row["count"]) for row in counts)
                if total == 0:
                    return None
                prior_ambiguous = sum(
                    int(row["ambiguous"] or 0) for row in counts
                )
                cves = int(
                    db.execute(
                        "SELECT COUNT(DISTINCT e.cve_id) FROM watch_event e "
                        "JOIN watch_delivery d ON d.event_id=e.id "
                        "WHERE " + condition,
                        parameters,
                    ).fetchone()[0]
                )
                order, grouped, join = self._initial_order(catalogs)
                sampled_cves = [
                    row["cve_id"]
                    for row in db.execute(
                        "SELECT e.cve_id FROM watch_event e "
                        "JOIN watch_delivery d ON d.event_id=e.id "
                        "JOIN watch_cve c ON c.cve_id=e.cve_id " + join +
                        " WHERE " + condition +
                        " GROUP BY e.cve_id ORDER BY " + ", ".join(grouped) +
                        " LIMIT ?",
                        (*parameters, max_items),
                    )
                ]
                if not sampled_cves:
                    return None
                placeholders = ",".join("?" for _ in sampled_cves)
                sampled = db.execute(
                    "SELECT e.id,e.rule,e.cve_id,e.kind,e.reasons_json,"
                    "e.details_json,e.initial,e.created_at,d.status,d.attempts "
                    "FROM watch_event e JOIN watch_delivery d ON d.event_id=e.id "
                    "JOIN watch_cve c ON c.cve_id=e.cve_id " + join +
                    " WHERE " + condition +
                    f" AND e.cve_id IN ({placeholders}) ORDER BY " +
                    ", ".join(order),
                    (*parameters, *sampled_cves),
                ).fetchall()
                cursor = db.execute(
                    "UPDATE watch_delivery SET status='sending', "
                    "first_attempt_at=COALESCE(first_attempt_at, ?), updated_at=?, "
                    "last_error=CASE WHEN status='ambiguous' THEN ? ELSE NULL END "
                    "WHERE channel=? AND status IN ('pending','failed','ambiguous') "
                    "AND event_id IN ("
                    "SELECT e.id FROM watch_event e "
                    "JOIN watch_delivery d ON d.event_id=e.id "
                    "WHERE " + condition + ")",
                    (stamp, stamp, _INITIAL_AMBIGUOUS, channel, *parameters),
                )
                if cursor.rowcount != total:
                    raise _ClaimConflict
                marks = self._reported_marks_in(
                    db, (row["cve_id"] for row in sampled)
                )
                events = tuple(
                    event
                    for row in sampled
                    if (event := self._delivery_event(db, row, catalogs, marks))
                    is not None
                )
                return InitialDigest(
                    events,
                    tuple(
                        (row["rule"], row["kind"], int(row["count"]))
                        for row in counts
                    ),
                    cves,
                    total,
                    prior_ambiguous,
                )
        except _ClaimConflict:
            return None

    def claim_initial_chunk(
        self,
        channel: str,
        *,
        catalogs: Sequence[str] = (),
        now: datetime | None = None,
        include_ambiguous: bool = False,
        limit: int = DELIVERY_SELECT_LIMIT,
    ) -> tuple[DeliveryEvent, ...]:
        """Claim and return one bounded chunk of initial rows for a webhook."""
        if limit < 1:
            raise StateError("initial delivery chunk size must be positive")
        self.initialize()
        current = _clock_value(lambda: now) if now is not None else _clock_value(self._clock)
        stamp = current.isoformat()
        try:
            with self.transaction() as db:
                condition, parameters = self._initial_condition(
                    channel, include_ambiguous, stamp
                )
                rows = db.execute(
                    "SELECT e.id,e.rule,e.cve_id,e.kind,e.reasons_json,"
                    "e.details_json,e.initial,e.created_at,d.status,d.attempts "
                    "FROM watch_event e JOIN watch_delivery d ON d.event_id=e.id "
                    "JOIN watch_cve c ON c.cve_id=e.cve_id "
                    "WHERE " + condition + " ORDER BY e.created_at, e.id LIMIT ?",
                    (*parameters, limit),
                ).fetchall()
                if not rows:
                    return ()
                identifiers = [int(row["id"]) for row in rows]
                placeholders = ",".join("?" for _ in identifiers)
                cursor = db.execute(
                    "UPDATE watch_delivery SET status='sending', "
                    "first_attempt_at=COALESCE(first_attempt_at, ?), updated_at=?, "
                    "last_error=CASE WHEN status='ambiguous' THEN ? ELSE NULL END "
                    "WHERE channel=? AND status IN ('pending','failed','ambiguous') "
                    f"AND event_id IN ({placeholders})",
                    (stamp, stamp, _INITIAL_AMBIGUOUS, channel, *identifiers),
                )
                if cursor.rowcount != len(identifiers):
                    raise _ClaimConflict
                marks = self._reported_marks_in(
                    db, (row["cve_id"] for row in rows)
                )
                return tuple(
                    event
                    for row in rows
                    if (event := self._delivery_event(db, row, catalogs, marks))
                    is not None
                )
        except _ClaimConflict:
            return ()

    def _initial_claim_stamp(self, now: datetime) -> str:
        """Return the ``updated_at`` value the claim wrote for ``now``."""
        return _clock_value(lambda: now).isoformat()

    def mark_initial_sent(self, channel: str, *, now: datetime) -> int:
        """Mark the initial rows this run claimed for ``channel`` as sent."""
        self.initialize()
        stamp = self._initial_claim_stamp(now)
        with self.transaction() as db:
            cursor = db.execute(
                "UPDATE watch_delivery SET status='sent', last_error=NULL, "
                "updated_at=? WHERE channel=? AND status='sending' "
                "AND updated_at=? "
                "AND event_id IN (SELECT id FROM watch_event WHERE initial=1)",
                (_timestamp(self._clock), channel, stamp),
            )
            return cursor.rowcount

    def mark_initial_failed(
        self,
        channel: str,
        *,
        now: datetime,
        error: str,
        attempts_limit: int | None = None,
        ambiguous: bool = False,
    ) -> int:
        """Mark the claimed initial rows failed, keeping prior ambiguity."""
        self.initialize()
        stamp = self._initial_claim_stamp(now)
        marked = _timestamp(self._clock)
        if attempts_limit is None:
            attempts_sql = "attempts=attempts+1"
            attempts_parameters: tuple[Any, ...] = ()
        else:
            attempts_sql = (
                "attempts=CASE WHEN attempts + 1 >= ? THEN ? "
                "ELSE attempts + 1 END"
            )
            attempts_parameters = (attempts_limit, DELIVERY_MAX_ATTEMPTS)
        with self.transaction() as db:
            cursor = db.execute(
                "UPDATE watch_delivery SET "
                "status=CASE WHEN ? OR last_error=? THEN 'ambiguous' "
                "ELSE 'failed' END, "
                + attempts_sql
                + ", last_error=?, updated_at=?, "
                "first_attempt_at=COALESCE(first_attempt_at, ?) "
                "WHERE channel=? AND status='sending' AND updated_at=? "
                "AND event_id IN (SELECT id FROM watch_event WHERE initial=1)",
                (
                    1 if ambiguous else 0,
                    _INITIAL_AMBIGUOUS,
                    *attempts_parameters,
                    (error or "")[:500],
                    marked,
                    marked,
                    channel,
                    stamp,
                ),
            )
            return cursor.rowcount

    def release_initial(self, channel: str, *, now: datetime) -> int:
        """Return claimed initial rows to pending (or their prior ambiguity)."""
        self.initialize()
        stamp = self._initial_claim_stamp(now)
        with self.transaction() as db:
            cursor = db.execute(
                "UPDATE watch_delivery SET "
                "status=CASE WHEN last_error=? THEN 'ambiguous' ELSE 'pending' END, "
                "last_error=NULL, updated_at=? WHERE channel=? AND status='sending' "
                "AND updated_at=? "
                "AND event_id IN (SELECT id FROM watch_event WHERE initial=1)",
                (_INITIAL_AMBIGUOUS, _timestamp(self._clock), channel, stamp),
            )
            return cursor.rowcount

    def release_delivery(
        self,
        event_ids: Iterable[int],
        channel: str,
        *,
        status: str = "pending",
    ) -> int:
        """Undo a claim before its first message, without counting an attempt."""
        if status not in {"pending", "ambiguous"}:
            raise StateError(f"cannot release a delivery to {status!r}")
        identifiers = sorted({int(value) for value in event_ids})
        if not identifiers:
            return 0
        now = _timestamp(self._clock)
        changed = 0
        with self.transaction() as db:
            for start in range(0, len(identifiers), 500):
                chunk = identifiers[start : start + 500]
                placeholders = ",".join("?" for _ in chunk)
                cursor = db.execute(
                    "UPDATE watch_delivery SET status=?, last_error=NULL, "
                    f"updated_at=? WHERE event_id IN ({placeholders}) "
                    "AND channel=? AND status='sending'",
                    (status, now, *chunk, channel),
                )
                changed += cursor.rowcount
        return changed

    def claim_notice(
        self,
        event_id: int,
        channel: str,
        *,
        statuses: Sequence[str] = ("pending", "failed", "ambiguous"),
    ) -> bool:
        """Claim one notice after earlier notices for the CVE are resolved.

        A notice for a CVE and channel waits while an earlier notice for the
        same pair is pending, sending, ambiguous, or failed below the attempt
        cap. A notice that reached the cap no longer blocks. Ambiguous rows stay
        blocking even during an explicit ambiguous retry; once an earlier notice
        completes in this run, the successor can follow it in audit order.
        """
        allowed = tuple(
            status
            for status in statuses
            if status in {"pending", "failed", "ambiguous"}
        )
        if not allowed:
            raise StateError("a delivery claim needs a retryable status")
        self.initialize()
        now = _timestamp(self._clock)
        allowed_placeholders = ",".join("?" for _ in allowed)
        notice_placeholders = ",".join("?" for _ in NOTICE_KINDS)
        with self.transaction() as db:
            event = db.execute(
                "SELECT kind,cve_id FROM watch_event WHERE id=?", (event_id,)
            ).fetchone()
            if event is None or event["kind"] not in NOTICE_KINDS:
                raise StateError("notice claim requires a notice event")
            blocking = db.execute(
                "SELECT 1 FROM watch_event p "
                "JOIN watch_delivery d ON d.event_id=p.id "
                "WHERE p.cve_id=? AND d.channel=? "
                f"AND p.kind IN ({notice_placeholders}) AND p.id < ? AND ("
                "d.status IN ('pending','sending','ambiguous') OR "
                "(d.status='failed' AND d.attempts < ?)) "
                "LIMIT 1",
                (
                    event["cve_id"],
                    channel,
                    *NOTICE_KINDS,
                    event_id,
                    DELIVERY_MAX_ATTEMPTS,
                ),
            ).fetchone()
            if blocking is not None:
                return False
            cursor = db.execute(
                "UPDATE watch_delivery SET status='sending', "
                "first_attempt_at=COALESCE(first_attempt_at, ?), updated_at=? "
                "WHERE event_id=? AND channel=? "
                f"AND status IN ({allowed_placeholders})",
                (now, now, event_id, channel, *allowed),
            )
            return cursor.rowcount == 1

    def claim_delivery(
        self,
        event_ids: Iterable[int],
        channel: str,
        *,
        statuses: Sequence[str] = ("pending", "failed", "ambiguous"),
    ) -> bool:
        """Atomically move this run's rows to ``sending``.

        The update is conditional on the current status, so two runs that
        selected the same rows cannot both send them. A partial claim is
        rolled back and reported as a loss.
        """
        identifiers = sorted({int(value) for value in event_ids})
        if not identifiers:
            return False
        allowed = tuple(
            status
            for status in statuses
            if status in {"pending", "failed", "ambiguous"}
        )
        if not allowed:
            raise StateError("a delivery claim needs a retryable status")
        now = _timestamp(self._clock)
        allowed_placeholders = ",".join("?" for _ in allowed)
        try:
            with self.transaction() as db:
                changed = 0
                # Keep each statement well below SQLite's variable limit while
                # still claiming the whole group in one transaction.
                for start in range(0, len(identifiers), 500):
                    chunk = identifiers[start : start + 500]
                    placeholders = ",".join("?" for _ in chunk)
                    cursor = db.execute(
                        "UPDATE watch_delivery SET status='sending', "
                        "first_attempt_at=COALESCE(first_attempt_at, ?), updated_at=? "
                        f"WHERE channel=? AND event_id IN ({placeholders}) "
                        f"AND status IN ({allowed_placeholders})",
                        (now, now, channel, *chunk, *allowed),
                    )
                    changed += cursor.rowcount
                if changed != len(identifiers):
                    raise _ClaimConflict
        except _ClaimConflict:
            return False
        return True

    def reset_failed(self, channel: str) -> int:
        """Make every failed row eligible for an explicit retry."""
        self.initialize()
        with self.transaction() as db:
            cursor = db.execute(
                "UPDATE watch_delivery SET attempts=0, first_attempt_at=NULL, "
                "updated_at=? WHERE channel=? AND status='failed'",
                (DELIVERY_RETRY_FLOOR, channel),
            )
            return cursor.rowcount

    def mark_delivery(
        self,
        event_ids: Iterable[int],
        channel: str,
        status: str,
        *,
        error: str | None = None,
        attempts_limit: int | None = None,
    ) -> int:
        """Move delivery rows through the state machine in one transaction.

        ``sent`` is final. An ``ambiguous`` row may only become ``sent`` or
        stay ``ambiguous`` (plus the internal claim to ``sending``), so a stale
        or retried attempt can never downgrade it to ``failed``.
        """
        if status not in DELIVERY_PREDECESSORS:
            raise StateError(f"unknown delivery status {status!r}")
        identifiers = sorted({int(value) for value in event_ids})
        if not identifiers:
            return 0
        now = _timestamp(self._clock)
        retryable = status in {"failed", "ambiguous"}
        allowed = DELIVERY_PREDECESSORS[status]
        allowed_placeholders = ",".join("?" for _ in allowed)
        changed = 0
        with self.transaction() as db:
            for identifier in identifiers:
                if retryable:
                    if attempts_limit is not None:
                        cursor = db.execute(
                            "UPDATE watch_delivery SET status=?, "
                            "attempts=CASE WHEN attempts + 1 >= ? THEN ? "
                            "ELSE attempts + 1 END, last_error=?, updated_at=?, "
                            "first_attempt_at=COALESCE(first_attempt_at, ?) "
                            "WHERE event_id=? AND channel=? "
                            f"AND status IN ({allowed_placeholders})",
                            (
                                status,
                                attempts_limit,
                                DELIVERY_MAX_ATTEMPTS,
                                (error or "")[:500],
                                now,
                                now,
                                identifier,
                                channel,
                                *allowed,
                            ),
                        )
                    else:
                        cursor = db.execute(
                            "UPDATE watch_delivery SET status=?, "
                            "attempts=attempts+1, last_error=?, updated_at=?, "
                            "first_attempt_at=COALESCE(first_attempt_at, ?) "
                            "WHERE event_id=? AND channel=? "
                            f"AND status IN ({allowed_placeholders})",
                            (
                                status,
                                (error or "")[:500],
                                now,
                                now,
                                identifier,
                                channel,
                                *allowed,
                            ),
                        )
                else:
                    cursor = db.execute(
                        "UPDATE watch_delivery SET status=?, last_error=NULL, "
                        "updated_at=?, first_attempt_at=COALESCE(first_attempt_at, ?) "
                        "WHERE event_id=? AND channel=? "
                        f"AND status IN ({allowed_placeholders})",
                        (status, now, now, identifier, channel, *allowed),
                    )
                changed += cursor.rowcount
        return changed

    def delivery_status(
        self, channels: Iterable[str] = ()
    ) -> tuple[DeliveryStatusRow, ...]:
        """Return per-channel delivery counts for status output."""
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT channel,status,COUNT(*) AS count,"
                "MAX(CASE WHEN status='sent' THEN updated_at END) AS last_success,"
                "SUM(CASE WHEN status='failed' AND attempts >= ? THEN 1 ELSE 0 END) "
                "AS given_up "
                "FROM watch_delivery GROUP BY channel,status",
                (DELIVERY_MAX_ATTEMPTS,),
            ).fetchall()
        values: dict[str, dict[str, Any]] = {}
        for row in rows:
            entry = values.setdefault(
                row["channel"],
                {
                    "pending": 0,
                    "sending": 0,
                    "failed": 0,
                    "given_up": 0,
                    "ambiguous": 0,
                    "last_success": None,
                },
            )
            if row["status"] in {"pending", "sending", "failed", "ambiguous"}:
                entry[row["status"]] = int(row["count"])
            if row["status"] == "failed" and row["given_up"]:
                entry["given_up"] = int(row["given_up"])
            if row["last_success"] and (
                entry["last_success"] is None
                or row["last_success"] > entry["last_success"]
            ):
                entry["last_success"] = row["last_success"]
        for channel in channels:
            values.setdefault(
                channel,
                {
                    "pending": 0,
                    "sending": 0,
                    "failed": 0,
                    "given_up": 0,
                    "ambiguous": 0,
                    "last_success": None,
                },
            )
        return tuple(
            DeliveryStatusRow(channel, **values[channel])
            for channel in sorted(values)
        )

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

    def first_seen(self, identifier: str) -> str | None:
        """Return when a stored CVE was first seen, or None when it is absent."""
        self.initialize()
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT first_seen FROM watch_cve WHERE cve_id=?", (identifier,)
            ).fetchone()
        return None if row is None else str(row["first_seen"])

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
                reported = db.execute(
                    "SELECT COUNT(*) FROM (" + _LATEST_REPORT_SQL + ")"
                ).fetchone()[0]
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
            "reported": reported,
        }
