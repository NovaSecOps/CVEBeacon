"""Transactional SQLite monitoring history and per-channel delivery state."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing, contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Sequence

from .errors import StateError
from .models import Finding, QueryResult, HealthStatus

SCHEMA_VERSION = 3


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def material_fingerprint(finding: Finding) -> str:
    """Hash fields that should produce an alert; EPSS and timestamp churn are excluded."""
    value = {
        "cve_id": finding.vulnerability.primary_id,
        "applicability": finding.applicability.value,
        "rejected": finding.vulnerability.rejected,
        "cvss": [finding.vulnerability.cvss_score, finding.vulnerability.cvss_vector, finding.vulnerability.cvss_version],
        "kev": [finding.vulnerability.cisa_kev, finding.vulnerability.eu_kev],
        "evidence": sorted(set(
            (
                item.source,
                item.role,
                json.dumps(
                    _canonical({key: item.details[key] for key in ("state", "affected", "products", "sources", "configurations") if item.details.get(key) is not None}),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ),
            )
            for item in finding.evidence
            if any(item.details.get(key) is not None for key in ("state", "affected", "products", "sources", "configurations"))
        )),
        "conflicts": sorted(finding.conflicts),
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _canonical(value):
    if isinstance(value, dict):
        return {key: _canonical(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted((_canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            return connection
        except (sqlite3.Error, OSError) as exc:
            raise StateError(f"cannot open state database {self.path}: {exc}") from exc

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise StateError(f"state transaction failed: {exc}") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.transaction() as db:
            db.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS schema_info (
                    version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('completed','failed')),
                    asset_count INTEGER NOT NULL,
                    finding_count INTEGER NOT NULL,
                    coverage_unknown_count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS current_findings (
                    asset_id TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY(asset_id, cve_id)
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    occurred_at TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK(event_type IN ('new','changed')),
                    fingerprint TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_health (
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    asset_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    message TEXT NOT NULL,
                    freshness_at TEXT,
                    PRIMARY KEY(run_id, asset_id, source)
                );
                CREATE TABLE IF NOT EXISTS deliveries (
                    event_id INTEGER NOT NULL REFERENCES events(event_id),
                    channel TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','accepted','failed')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    error TEXT,
                    PRIMARY KEY(event_id, channel)
                );
                CREATE INDEX IF NOT EXISTS events_asset_cve ON events(asset_id, cve_id, occurred_at);
                CREATE TABLE IF NOT EXISTS scan_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL CHECK(status IN ('running','completed','failed')),
                    run_id TEXT REFERENCES runs(run_id),
                    message TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scan_assets (
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    asset_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY(run_id, asset_id)
                );
                CREATE TABLE IF NOT EXISTS advisory_aliases (
                    asset_id TEXT NOT NULL,
                    alias TEXT NOT NULL,
                    primary_id TEXT NOT NULL,
                    PRIMARY KEY(asset_id, alias)
                );
                """
            )
            row = db.execute("SELECT version FROM schema_info LIMIT 1").fetchone()
            if row is None:
                db.execute("INSERT INTO schema_info(version) VALUES (?)", (SCHEMA_VERSION,))
            elif row["version"] in {1, 2}:
                db.execute("UPDATE schema_info SET version=?", (SCHEMA_VERSION,))
            elif row["version"] != SCHEMA_VERSION:
                raise StateError(f"unsupported state schema version {row['version']}")

    def record_scan(self, results: Sequence[QueryResult], *, channels: Sequence[str] = (), attempt_id: str | None = None) -> tuple[str, list[int]]:
        self.initialize()
        run_id = str(uuid.uuid4())
        started = completed = _timestamp()
        event_ids: list[int] = []
        try:
            with self.transaction() as db:
                findings = [item for result in results for item in result.findings]
                db.execute(
                    "INSERT INTO runs VALUES (?,?,?,?,?,?,?)",
                    (run_id, started, completed, "failed" if any(result.coverage is not None or any(health.status in {HealthStatus.FAILED, HealthStatus.DEGRADED} for health in result.source_health) for result in results) else "completed", len(results), len(findings), sum(result.coverage is not None for result in results)),
                )
                for result in results:
                    db.execute("INSERT INTO scan_assets VALUES (?,?,?)", (
                        run_id, result.asset.asset_id, json.dumps({"asset": asdict(result.asset),
                            "coverage": result.coverage.value if result.coverage else None,
                            "coverage_reason": result.coverage_reason}, ensure_ascii=False),
                    ))
                    for health in result.source_health:
                        db.execute(
                            "INSERT INTO source_health VALUES (?,?,?,?,?,?,?)",
                            (run_id, result.asset.asset_id, health.source, health.status.value, health.checked_at.isoformat(), health.message, health.freshness_at.isoformat() if health.freshness_at else None),
                        )
                    for finding in result.findings:
                        identifiers = finding.vulnerability.identifiers
                        if not identifiers:
                            raise StateError("finding requires a primary advisory identifier")
                        # Prefer an existing persisted identity. A later CVE alias
                        # must not turn a known advisory into a new alert.
                        marks = ",".join("?" for _ in identifiers)
                        linked = {row[0] for row in db.execute(
                            f"SELECT primary_id FROM advisory_aliases WHERE asset_id=? AND alias IN ({marks})",
                            (finding.asset.asset_id, *identifiers))}
                        candidates = sorted(set(identifiers) | linked)
                        marks = ",".join("?" for _ in candidates)
                        previous_rows = db.execute(
                            f"SELECT cve_id,fingerprint,first_seen,payload_json FROM current_findings WHERE asset_id=? AND cve_id IN ({marks}) ORDER BY first_seen,cve_id",
                            (finding.asset.asset_id, *candidates)).fetchall()
                        previous = previous_rows[0] if previous_rows else None
                        primary = previous["cve_id"] if previous else finding.vulnerability.primary_id
                        finding = replace(finding, vulnerability=replace(finding.vulnerability, advisory_id=primary))
                        payload = json.dumps(finding.to_dict(), sort_keys=True, ensure_ascii=False)
                        fingerprint = material_fingerprint(finding)
                        failed_sources = {health.source for health in result.source_health if health.status != HealthStatus.OK}
                        core_sources = {"osv"} if result.asset.identity_path in {"purl", "ecosystem", "commit"} else {"nvd", "cve_list", "euvd"}
                        core_incomplete = any(health.source in core_sources and health.status in {HealthStatus.FAILED, HealthStatus.DEGRADED} for health in result.source_health)
                        if previous and core_incomplete and not finding.vulnerability.rejected:
                            # Retain the last observation rather than turn a failed
                            # applicability refresh into a resolution or new baseline.
                            continue
                        if previous and failed_sources.intersection({"cisa_kev", "eu_kev", "epss"}):
                            old = json.loads(previous["payload_json"])
                            old_vuln = old["vulnerability"]
                            updates = {}
                            for source, fields in (("cisa_kev", ("cisa_kev",)), ("eu_kev", ("eu_kev",))):
                                if source in failed_sources:
                                    updates.update({field: old_vuln[field] for field in fields})
                            # Historical KEV claims keep their original retrieval
                            # time; source_health describes the failed refresh.
                            from .models import Evidence
                            old_evidence = tuple(Evidence(**{**item, "retrieved_at": datetime.fromisoformat(item["retrieved_at"])}) for item in old["evidence"] if item["source"] in failed_sources.intersection({"cisa_kev", "eu_kev"}))
                            finding = replace(finding, vulnerability=replace(finding.vulnerability, **updates), evidence=tuple(item for item in finding.evidence if item.source not in failed_sources.intersection({"cisa_kev", "eu_kev"})) + old_evidence)
                            payload = json.dumps(finding.to_dict(), sort_keys=True, ensure_ascii=False)
                            fingerprint = material_fingerprint(finding)
                        event_type = "new" if previous is None else ("changed" if previous["fingerprint"] != fingerprint else None)
                        first_seen = previous["first_seen"] if previous else completed
                        # Keep historical finding/event/delivery rows byte-for-byte.
                        # The alias index selects a single current representative.
                        for alias in set(candidates) | {primary}:
                            db.execute("UPDATE advisory_aliases SET primary_id=? WHERE asset_id=? AND primary_id=?",
                                       (primary, finding.asset.asset_id, alias))
                            db.execute("INSERT INTO advisory_aliases VALUES (?,?,?) ON CONFLICT(asset_id,alias) DO UPDATE SET primary_id=excluded.primary_id",
                                       (finding.asset.asset_id, alias, primary))
                        db.execute(
                            """INSERT INTO current_findings(asset_id,cve_id,first_seen,last_seen,fingerprint,payload_json)
                               VALUES (?,?,?,?,?,?)
                               ON CONFLICT(asset_id,cve_id) DO UPDATE SET
                                 last_seen=excluded.last_seen, fingerprint=excluded.fingerprint, payload_json=excluded.payload_json""",
                            (finding.asset.asset_id, primary, first_seen, completed, fingerprint, payload),
                        )
                        if event_type:
                            cursor = db.execute(
                                "INSERT INTO events(run_id,occurred_at,asset_id,cve_id,event_type,fingerprint,payload_json) VALUES (?,?,?,?,?,?,?)",
                                (run_id, completed, finding.asset.asset_id, primary, event_type, fingerprint, payload),
                            )
                            event_id = int(cursor.lastrowid)
                            event_ids.append(event_id)
                            for channel in channels:
                                db.execute(
                                    "INSERT INTO deliveries(event_id,channel,state,updated_at) VALUES (?,?,?,?)",
                                    (event_id, channel, "pending", completed),
                                )
                if attempt_id:
                    db.execute("UPDATE scan_attempts SET run_id=? WHERE attempt_id=?", (run_id, attempt_id))
        except (sqlite3.Error, OSError) as exc:
            raise StateError(f"scan state transaction failed: {exc}") from exc
        return run_id, event_ids

    def start_scan(self) -> str:
        self.initialize()
        identifier = str(uuid.uuid4())
        with self.transaction() as db:
            db.execute("INSERT INTO scan_attempts VALUES (?,?,NULL,'running',NULL,?)",
                       (identifier, _timestamp(), "Scan in progress; completion not yet recorded"))
        return identifier

    def finish_scan(self, identifier: str, *, successful: bool) -> None:
        with self.transaction() as db:
            db.execute("UPDATE scan_attempts SET completed_at=?,status=?,message=? WHERE attempt_id=?",
                       (_timestamp(), "completed" if successful else "failed",
                        "Scan and configured deliveries completed" if successful else "Scan failed, coverage was incomplete, or delivery failed; inspect scanner logs", identifier))

    def dashboard_snapshot(self) -> dict:
        """Read one consistent view without changing findings, events or delivery state."""
        self.initialize()
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            def one(sql):
                row = db.execute(sql).fetchone()
                return dict(row) if row else None
            latest = one("SELECT * FROM runs ORDER BY completed_at DESC LIMIT 1")
            run_id = latest["run_id"] if latest else ""
            snapshot = {
                "latest": latest,
                "successful": one("SELECT * FROM runs WHERE status='completed' ORDER BY completed_at DESC LIMIT 1"),
                "attempt": one("SELECT * FROM scan_attempts ORDER BY started_at DESC LIMIT 1"),
                "findings": [{"finding": json.loads(row["payload_json"]), "first_seen": row["first_seen"], "last_seen": row["last_seen"]}
                             for row in db.execute("SELECT * FROM current_findings f WHERE NOT EXISTS (SELECT 1 FROM advisory_aliases a WHERE a.asset_id=f.asset_id AND a.alias=f.cve_id AND a.primary_id!=f.cve_id) ORDER BY asset_id,cve_id")],
                "assets": [json.loads(row[0]) for row in db.execute("SELECT payload_json FROM scan_assets WHERE run_id=?", (run_id,))],
                "health": [dict(row) for row in db.execute("SELECT asset_id,source,status,checked_at,message,freshness_at FROM source_health WHERE run_id=? ORDER BY asset_id,source", (run_id,))],
                "events": [dict(row) for row in db.execute("SELECT event_id,occurred_at,asset_id,cve_id,event_type FROM events ORDER BY event_id DESC LIMIT 20")],
                "deliveries": [dict(row) for row in db.execute("SELECT d.event_id,d.channel,d.state,d.attempts,d.updated_at,e.asset_id,e.cve_id FROM deliveries d JOIN events e ON e.event_id=d.event_id ORDER BY d.updated_at DESC LIMIT 20")],
                "delivery_counts": [dict(row) for row in db.execute("SELECT channel,state,COUNT(*) AS count FROM deliveries GROUP BY channel,state")],
            }
            db.rollback()
            return snapshot

    def pending_events(self, channel: str) -> list[sqlite3.Row]:
        self.initialize()
        with closing(self._connect()) as db:
            return list(db.execute(
                """SELECT e.*, d.state, d.attempts FROM events e JOIN deliveries d ON d.event_id=e.event_id
                   WHERE d.channel=? AND d.state IN ('pending','failed') ORDER BY e.event_id""", (channel,)
            ))

    def mark_delivery(self, channel: str, event_ids: Sequence[int], *, accepted: bool, error: str | None = None) -> None:
        if not event_ids:
            return
        state = "accepted" if accepted else "failed"
        placeholders = ",".join("?" for _ in event_ids)
        with self.transaction() as db:
            db.execute(
                f"UPDATE deliveries SET state=?, attempts=attempts+1, updated_at=?, error=? WHERE channel=? AND event_id IN ({placeholders}) AND state!='accepted'",
                (state, _timestamp(), error, channel, *event_ids),
            )

    def history(self, *, asset_id: str | None = None, cve_id: str | None = None, limit: int = 100, before_event_id: int | None = None) -> list[dict[str, object]]:
        self.initialize()
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise StateError("history limit must be an integer from 1 through 10000")
        clauses, values = [], []
        if asset_id:
            clauses.append("asset_id=?"); values.append(asset_id)
        if cve_id:
            if cve_id.casefold().startswith("cve-"):
                cve_id = cve_id.upper()
            clauses.append("(cve_id=? OR cve_id IN (SELECT primary_id FROM advisory_aliases WHERE alias=? AND advisory_aliases.asset_id=events.asset_id))")
            values.extend((cve_id, cve_id))
        if before_event_id is not None:
            if type(before_event_id) is not int or not 1 <= before_event_id <= 2**63 - 1:
                raise StateError("history cursor must be a positive event ID")
            clauses.append("event_id<?"); values.append(before_event_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with closing(self._connect()) as db:
            rows = db.execute(f"SELECT event_id,run_id,occurred_at,asset_id,cve_id,event_type FROM events{where} ORDER BY event_id DESC LIMIT ?", (*values, limit)).fetchall()
            return [dict(row) for row in rows]

    def latest_findings(self) -> list[dict[str, object]]:
        self.initialize()
        with closing(self._connect()) as db:
            return [json.loads(row[0]) for row in db.execute("SELECT payload_json FROM current_findings f WHERE NOT EXISTS (SELECT 1 FROM advisory_aliases a WHERE a.asset_id=f.asset_id AND a.alias=f.cve_id AND a.primary_id!=f.cve_id) ORDER BY asset_id,cve_id")]

    def history_event(self, event_id: int) -> dict | None:
        self.initialize()
        with closing(self._connect()) as db:
            row = db.execute("SELECT event_id,occurred_at,event_type,payload_json FROM events WHERE event_id=?", (event_id,)).fetchone()
            return {"event_id": row["event_id"], "occurred_at": row["occurred_at"], "event_type": row["event_type"],
                    "finding": json.loads(row["payload_json"])} if row else None
