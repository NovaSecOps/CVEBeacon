"""Transactional SQLite storage for recently changed CVEs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from ..errors import StateError
from .records import (
    CVSSEntry,
    EUVDUpdate,
    KEVFields,
    WatchRecord,
    canonical_json,
    collapse_euvd,
)

SCHEMA_VERSION = 1
PENDING_ATTEMPT_LIMIT = 10
PENDING_EUVD_MAX_AGE_DAYS = 30

_CONTENT_COLUMNS = (
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
    "eu_kev_added",
    "euvd_id",
    "euvd_exploited_since",
    "epss",
    "epss_percentile",
    "epss_date",
)

NVD_OWNED_COLUMNS = (
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
EUVD_OWNED_COLUMNS = ("cvss_json", "euvd_id", "euvd_exploited_since")
CISA_KEV_OWNED_COLUMNS = (
    "cisa_kev_added",
    "cisa_kev_due",
    "cisa_required_action",
    "cisa_ransomware",
)
EU_KEV_OWNED_COLUMNS = ("eu_kev_added",)
EPSS_OWNED_COLUMNS = ("epss", "epss_percentile", "epss_date")

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
        eu_kev_added TEXT,
        euvd_id TEXT,
        euvd_exploited_since TEXT,
        epss REAL,
        epss_percentile REAL,
        epss_date TEXT,
        first_seen TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        fingerprint TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS watch_cve_cisa_kev ON watch_cve(cisa_kev_added)",
    "CREATE INDEX IF NOT EXISTS watch_cve_eu_kev ON watch_cve(eu_kev_added)",
    "CREATE INDEX IF NOT EXISTS watch_cve_ssvc ON watch_cve(ssvc_exploitation)",
    "CREATE INDEX IF NOT EXISTS watch_cve_epss ON watch_cve(epss)",
    """CREATE TABLE IF NOT EXISTS watch_pending (
        cve_id TEXT PRIMARY KEY,
        reason TEXT NOT NULL CHECK(reason IN ('euvd','cisa_kev','eu_kev')),
        euvd_json TEXT,
        first_seen TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0
    )""",
    "CREATE INDEX IF NOT EXISTS watch_pending_first_seen ON watch_pending(first_seen)",
)


@dataclass(frozen=True, slots=True)
class PendingCVE:
    cve_id: str
    reason: str
    euvd_json: str | None
    first_seen: str
    attempts: int

    @property
    def euvd(self) -> EUVDUpdate | None:
        return _euvd_from_json(self.euvd_json)

    @property
    def alert_relevant(self) -> bool:
        if self.reason in ("cisa_kev", "eu_kev"):
            return True
        update = self.euvd
        return update is not None and bool(update.exploited_since)


@dataclass(frozen=True, slots=True)
class UpsertCounts:
    new: int = 0
    changed: int = 0
    unchanged: int = 0
    new_ids: tuple[str, ...] = ()
    changed_ids: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return self.new + self.changed + self.unchanged


def _counts(outcomes: Sequence[tuple[str, str]]) -> UpsertCounts:
    priority = {"unchanged": 0, "changed": 1, "new": 2}
    best: dict[str, str] = {}
    for identifier, outcome in outcomes:
        if priority[outcome] > priority.get(best.get(identifier, ""), -1):
            best[identifier] = outcome
    entries = list(best.items())
    return UpsertCounts(
        new=sum(outcome == "new" for _, outcome in entries),
        changed=sum(outcome == "changed" for _, outcome in entries),
        unchanged=sum(outcome == "unchanged" for _, outcome in entries),
        new_ids=tuple(identifier for identifier, outcome in entries if outcome == "new"),
        changed_ids=tuple(identifier for identifier, outcome in entries if outcome == "changed"),
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _content(record: WatchRecord) -> dict[str, Any]:
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
        "eu_kev_added": record.eu_kev_added,
        "euvd_id": record.euvd_id,
        "euvd_exploited_since": record.euvd_exploited_since,
        "epss": record.epss,
        "epss_percentile": record.epss_percentile,
        "epss_date": record.epss_date,
    }


def _euvd_json(update: EUVDUpdate) -> str:
    return canonical_json(
        {
            "euvd_id": update.euvd_id,
            "exploited_since": update.exploited_since,
            "date_updated": update.date_updated,
            "cvss": update.cvss.as_dict() if update.cvss is not None else None,
        }
    )


def _euvd_from_json(value: str | None) -> EUVDUpdate | None:
    if value is None:
        return None
    try:
        data = json.loads(value)
        if not isinstance(data, dict):
            raise ValueError("not an object")
        raw_cvss = data.get("cvss")
        cvss = CVSSEntry(**raw_cvss) if isinstance(raw_cvss, dict) else None
        return EUVDUpdate(
            (),
            data.get("euvd_id"),
            data.get("exploited_since"),
            cvss,
            data.get("date_updated"),
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise StateError("watch database contains invalid pending EUVD data") from exc


def _apply_euvd_fields(record: WatchRecord, update: EUVDUpdate) -> WatchRecord:
    """Replace the EUVD-owned fields, dropping the old EUVD score first."""
    cvss = tuple(entry for entry in record.cvss if entry.provider != "euvd")
    if update.cvss is not None:
        cvss += (update.cvss,)
    return replace(
        record,
        euvd_id=update.euvd_id,
        euvd_exploited_since=update.exploited_since,
        cvss=cvss,
    )


def _merge_nvd(
    existing: WatchRecord | None, incoming: WatchRecord, *, cisa_owned_by_catalog: bool
) -> WatchRecord:
    """Replace NVD-owned fields while preserving fields owned by other sources."""
    if existing is None:
        return incoming
    cvss = tuple(entry for entry in incoming.cvss if entry.provider != "euvd") + tuple(
        entry for entry in existing.cvss if entry.provider == "euvd"
    )
    cisa_values: dict[str, Any] = {}
    for name in CISA_KEV_OWNED_COLUMNS:
        stored = getattr(existing, name)
        if cisa_owned_by_catalog and stored is not None:
            cisa_values[name] = stored
    return replace(
        incoming,
        cvss=cvss,
        eu_kev_added=existing.eu_kev_added,
        euvd_id=existing.euvd_id,
        euvd_exploited_since=existing.euvd_exploited_since,
        epss=existing.epss,
        epss_percentile=existing.epss_percentile,
        epss_date=existing.epss_date,
        **cisa_values,
    )


def _kev_on_or_after(added: str | None, baseline_at: str | None) -> bool:
    if baseline_at is None:
        return True
    if not added:
        return False
    return added[:10] >= baseline_at[:10]


def _stronger_reason(current: str, incoming: str) -> str:
    if current in ("cisa_kev", "eu_kev"):
        return current
    return incoming


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
    ) -> None:
        self.initialize()
        values = {
            "nvd_cursor": nvd_cursor,
            "initialized_at": initialized_at,
            "initial_mode": initial_mode,
            "initial_complete": "true",
        }
        if euvd_cursor is not None:
            values["euvd_cursor"] = euvd_cursor
        with self.transaction() as db:
            self._set_meta(db, values)

    def set_metadata(self, values: Mapping[str, str]) -> None:
        self.initialize()
        with self.transaction() as db:
            self._set_meta(db, values)

    @staticmethod
    def _record(row: sqlite3.Row) -> WatchRecord:
        try:
            return WatchRecord.from_row(row)
        except (TypeError, ValueError, KeyError) as exc:
            raise StateError("watch database contains an invalid CVE record") from exc

    @staticmethod
    def _row(db: sqlite3.Connection, identifier: str) -> sqlite3.Row | None:
        return db.execute(
            "SELECT * FROM watch_cve WHERE cve_id=?", (identifier,)
        ).fetchone()

    def _write(
        self,
        db: sqlite3.Connection,
        identifier: str,
        build: Callable[[WatchRecord | None], WatchRecord | None],
        now: str,
        owned: tuple[str, ...],
    ) -> str | None:
        row = self._row(db, identifier)
        existing = self._record(row) if row is not None else None
        final = build(existing)
        if final is None:
            return None
        content = _content(final)
        fingerprint = final.fingerprint()
        if existing is None:
            columns = ("cve_id", *_CONTENT_COLUMNS, "first_seen", "updated_at", "fingerprint")
            values = (identifier, *content.values(), now, now, fingerprint)
            marks = ",".join("?" for _ in columns)
            db.execute(f"INSERT INTO watch_cve({','.join(columns)}) VALUES ({marks})", values)
            return "new"
        if all(row[column] == content[column] for column in owned):
            return "unchanged"
        columns = (*owned, "updated_at", "fingerprint")
        assignments = ", ".join(f"{column}=?" for column in columns)
        values = (*(content[column] for column in owned), now, fingerprint, identifier)
        db.execute(f"UPDATE watch_cve SET {assignments} WHERE cve_id=?", values)
        return "changed" if row["fingerprint"] != fingerprint else "unchanged"

    @staticmethod
    def _pending_euvd(db: sqlite3.Connection) -> dict[str, EUVDUpdate]:
        rows = db.execute(
            "SELECT cve_id, euvd_json FROM watch_pending WHERE euvd_json IS NOT NULL"
        ).fetchall()
        output: dict[str, EUVDUpdate] = {}
        for row in rows:
            update = _euvd_from_json(row["euvd_json"])
            if update is not None:
                output[row["cve_id"]] = update
        return output

    @staticmethod
    def _put_pending(
        db: sqlite3.Connection,
        identifier: str,
        reason: str,
        euvd_json: str | None,
        now: str,
    ) -> None:
        row = db.execute(
            "SELECT reason, euvd_json FROM watch_pending WHERE cve_id=?", (identifier,)
        ).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO watch_pending(cve_id,reason,euvd_json,first_seen,attempts) "
                "VALUES (?,?,?,?,0)",
                (identifier, reason, euvd_json, now),
            )
            return
        db.execute(
            "UPDATE watch_pending SET reason=?, euvd_json=? WHERE cve_id=?",
            (
                _stronger_reason(row["reason"], reason),
                euvd_json if euvd_json is not None else row["euvd_json"],
                identifier,
            ),
        )

    def upsert(
        self,
        records: Sequence[WatchRecord],
        *,
        meta: Mapping[str, str] | None = None,
        cisa_kev_configured: bool = True,
    ) -> UpsertCounts:
        self.initialize()
        now = _timestamp(self._clock)
        outcomes: list[tuple[str, str]] = []
        with self.transaction() as db:
            pending = self._pending_euvd(db)
            for record in records:
                if record.cve_id in pending:
                    update = pending.pop(record.cve_id)
                    db.execute("DELETE FROM watch_pending WHERE cve_id=?", (record.cve_id,))
                    if self._row(db, record.cve_id) is None:
                        record = _apply_euvd_fields(record, update)
                outcome = self._write(
                    db,
                    record.cve_id,
                    lambda existing, record=record: _merge_nvd(
                        existing,
                        record,
                        cisa_owned_by_catalog=cisa_kev_configured,
                    ),
                    now,
                    NVD_OWNED_COLUMNS,
                )
                if outcome is not None:
                    outcomes.append((record.cve_id, outcome))
            if meta:
                self._set_meta(db, meta)
        return _counts(outcomes)

    def apply_euvd(
        self,
        updates: Sequence[EUVDUpdate],
        *,
        meta: Mapping[str, str] | None = None,
    ) -> UpsertCounts:
        self.initialize()
        now = _timestamp(self._clock)
        outcomes: list[tuple[str, str]] = []
        collapsed = collapse_euvd(updates)
        with self.transaction() as db:
            for identifier in sorted(collapsed):
                update = collapsed[identifier]
                if self._row(db, identifier) is None:
                    self._put_pending(db, identifier, "euvd", _euvd_json(update), now)
                    continue

                def build(
                    existing: WatchRecord | None, update: EUVDUpdate = update
                ) -> WatchRecord | None:
                    if existing is None:
                        return None
                    return _apply_euvd_fields(existing, update)

                outcome = self._write(db, identifier, build, now, EUVD_OWNED_COLUMNS)
                if outcome is not None:
                    outcomes.append((identifier, outcome))
            if meta:
                self._set_meta(db, meta)
        return _counts(outcomes)

    def _kev_identifiers(self, db: sqlite3.Connection, *, cisa: bool) -> list[str]:
        if cisa:
            query = (
                "SELECT cve_id FROM watch_cve WHERE cisa_kev_added IS NOT NULL "
                "OR cisa_kev_due IS NOT NULL OR cisa_required_action IS NOT NULL "
                "OR cisa_ransomware IS NOT NULL"
            )
        else:
            query = "SELECT cve_id FROM watch_cve WHERE eu_kev_added IS NOT NULL"
        return [row["cve_id"] for row in db.execute(query)]

    def apply_kev(
        self,
        cisa: Mapping[str, KEVFields],
        eu: Mapping[str, KEVFields],
        *,
        meta: Mapping[str, str] | None = None,
        clear_cisa: bool = False,
        clear_eu: bool = False,
        baseline_at: str | None = None,
    ) -> UpsertCounts:
        self.initialize()
        now = _timestamp(self._clock)
        outcomes: list[tuple[str, str]] = []
        with self.transaction() as db:
            for identifier in sorted(set(cisa) | set(eu)):
                cisa_entry = cisa.get(identifier)
                eu_entry = eu.get(identifier)
                owned: tuple[str, ...] = ()
                if cisa_entry is not None:
                    owned += CISA_KEV_OWNED_COLUMNS
                if eu_entry is not None:
                    owned += EU_KEV_OWNED_COLUMNS

                if self._row(db, identifier) is None:
                    reason = "cisa_kev" if cisa_entry is not None else "eu_kev"
                    added = cisa_entry.added if cisa_entry is not None else eu_entry.added
                    if _kev_on_or_after(added, baseline_at):
                        self._put_pending(db, identifier, reason, None, now)
                    continue

                def build(
                    existing: WatchRecord | None,
                    cisa_entry: KEVFields | None = cisa_entry,
                    eu_entry: KEVFields | None = eu_entry,
                ) -> WatchRecord | None:
                    if existing is None:
                        return None
                    changes: dict[str, Any] = {}
                    if cisa_entry is not None:
                        changes.update(
                            cisa_kev_added=cisa_entry.added,
                            cisa_kev_due=cisa_entry.due,
                            cisa_required_action=cisa_entry.required_action,
                            cisa_ransomware=cisa_entry.ransomware,
                        )
                    if eu_entry is not None:
                        changes["eu_kev_added"] = eu_entry.added
                    return replace(existing, **changes)

                outcome = self._write(db, identifier, build, now, owned)
                if outcome is not None:
                    outcomes.append((identifier, outcome))

            if clear_cisa:
                for identifier in self._kev_identifiers(db, cisa=True):
                    if identifier in cisa:
                        continue
                    outcome = self._write(
                        db,
                        identifier,
                        lambda existing: None
                        if existing is None
                        else replace(
                            existing,
                            cisa_kev_added=None,
                            cisa_kev_due=None,
                            cisa_required_action=None,
                            cisa_ransomware=None,
                        ),
                        now,
                        CISA_KEV_OWNED_COLUMNS,
                    )
                    if outcome is not None:
                        outcomes.append((identifier, outcome))
            if clear_eu:
                for identifier in self._kev_identifiers(db, cisa=False):
                    if identifier in eu:
                        continue
                    outcome = self._write(
                        db,
                        identifier,
                        lambda existing: None
                        if existing is None
                        else replace(existing, eu_kev_added=None),
                        now,
                        EU_KEV_OWNED_COLUMNS,
                    )
                    if outcome is not None:
                        outcomes.append((identifier, outcome))
            if meta:
                self._set_meta(db, meta)
        return _counts(outcomes)

    def apply_epss(
        self,
        scores: Mapping[str, tuple[float, float, date]],
        *,
        meta: Mapping[str, str] | None = None,
    ) -> UpsertCounts:
        self.initialize()
        now = _timestamp(self._clock)
        outcomes: list[tuple[str, str]] = []
        with self.transaction() as db:
            for identifier in sorted(scores):
                score, percentile, score_date = scores[identifier]

                def build(
                    existing: WatchRecord | None,
                    score: float = score,
                    percentile: float = percentile,
                    score_date: date = score_date,
                ) -> WatchRecord | None:
                    if existing is None:
                        return None
                    return replace(
                        existing,
                        epss=score,
                        epss_percentile=percentile,
                        epss_date=score_date.isoformat(),
                    )

                outcome = self._write(db, identifier, build, now, EPSS_OWNED_COLUMNS)
                if outcome is not None:
                    outcomes.append((identifier, outcome))
            if meta:
                self._set_meta(db, meta)
        return _counts(outcomes)

    def epss_without_date(self, *, limit: int) -> tuple[str, ...]:
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT cve_id FROM watch_cve WHERE epss_date IS NULL "
                "ORDER BY first_seen, cve_id LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(row["cve_id"] for row in rows)

    def epss_at_or_above_floor(self, floor: float) -> tuple[str, ...]:
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT cve_id FROM watch_cve WHERE epss IS NOT NULL AND epss >= ? "
                "ORDER BY cve_id",
                (floor,),
            ).fetchall()
        return tuple(row["cve_id"] for row in rows)

    def pending(self, *, limit: int = 25) -> tuple[PendingCVE, ...]:
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT cve_id, reason, euvd_json, first_seen, attempts FROM watch_pending "
                "ORDER BY first_seen, cve_id"
            ).fetchall()
        output = [
            PendingCVE(
                row["cve_id"], row["reason"], row["euvd_json"], row["first_seen"], row["attempts"]
            )
            for row in rows
        ]
        alert = [item for item in output if item.alert_relevant]
        return tuple(alert[:limit])

    def expire_pending(self, *, now: datetime) -> None:
        self.initialize()
        cutoff = (now - timedelta(days=PENDING_EUVD_MAX_AGE_DAYS)).isoformat()
        with self.transaction() as db:
            rows = db.execute(
                "SELECT cve_id, reason, euvd_json, first_seen FROM watch_pending"
            ).fetchall()
            for row in rows:
                if row["reason"] != "euvd" or row["first_seen"] >= cutoff:
                    continue
                update = _euvd_from_json(row["euvd_json"])
                if update is None or not update.exploited_since:
                    db.execute("DELETE FROM watch_pending WHERE cve_id=?", (row["cve_id"],))

    def pending_attempt(self, identifier: str) -> None:
        self.initialize()
        with self.transaction() as db:
            db.execute(
                "UPDATE watch_pending SET attempts=attempts+1 WHERE cve_id=?", (identifier,)
            )
            row = db.execute(
                "SELECT attempts FROM watch_pending WHERE cve_id=?", (identifier,)
            ).fetchone()
            if row is not None and row["attempts"] >= PENDING_ATTEMPT_LIMIT:
                db.execute("DELETE FROM watch_pending WHERE cve_id=?", (identifier,))

    def drop_pending(self, identifier: str) -> None:
        self.initialize()
        with self.transaction() as db:
            db.execute("DELETE FROM watch_pending WHERE cve_id=?", (identifier,))

    def status(self, *, epss_floor: float) -> dict[str, Any]:
        self.initialize()
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                meta = {
                    row["key"]: row["value"]
                    for row in db.execute("SELECT key,value FROM watch_meta")
                }
                row_count = db.execute("SELECT COUNT(*) FROM watch_cve").fetchone()[0]
                cisa_kev = db.execute(
                    "SELECT COUNT(*) FROM watch_cve WHERE cisa_kev_added IS NOT NULL"
                ).fetchone()[0]
                eu_kev = db.execute(
                    "SELECT COUNT(*) FROM watch_cve WHERE eu_kev_added IS NOT NULL"
                ).fetchone()[0]
                any_kev = db.execute(
                    "SELECT COUNT(*) FROM watch_cve "
                    "WHERE cisa_kev_added IS NOT NULL OR eu_kev_added IS NOT NULL"
                ).fetchone()[0]
                active_ssvc = db.execute(
                    "SELECT COUNT(*) FROM watch_cve WHERE ssvc_exploitation='active'"
                ).fetchone()[0]
                epss_above = db.execute(
                    "SELECT COUNT(*) FROM watch_cve WHERE epss IS NOT NULL AND epss >= ?",
                    (epss_floor,),
                ).fetchone()[0]
            finally:
                db.rollback()
        return {
            "database": self.path,
            "meta": meta,
            "rows": row_count,
            "cisa_kev": cisa_kev,
            "eu_kev": eu_kev,
            "any_kev": any_kev,
            "active_ssvc": active_ssvc,
            "epss_above": epss_above,
        }
