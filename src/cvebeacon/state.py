"""Transactional SQLite monitoring history and per-channel delivery state."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Sequence

from .errors import StateError
from .models import Finding, QueryResult, HealthStatus

SCHEMA_VERSION = 1


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def material_fingerprint(finding: Finding) -> str:
    """Hash fields that should produce an alert; EPSS and timestamp churn are excluded."""
    value = {
        "cve_id": finding.vulnerability.cve_id,
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
                """
            )
            row = db.execute("SELECT version FROM schema_info LIMIT 1").fetchone()
            if row is None:
                db.execute("INSERT INTO schema_info(version) VALUES (?)", (SCHEMA_VERSION,))
            elif row["version"] != SCHEMA_VERSION:
                raise StateError(f"unsupported state schema version {row['version']}")

    def record_scan(self, results: Sequence[QueryResult], *, channels: Sequence[str] = ()) -> tuple[str, list[int]]:
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
                    for health in result.source_health:
                        db.execute(
                            "INSERT INTO source_health VALUES (?,?,?,?,?,?,?)",
                            (run_id, result.asset.asset_id, health.source, health.status.value, health.checked_at.isoformat(), health.message, health.freshness_at.isoformat() if health.freshness_at else None),
                        )
                    for finding in result.findings:
                        payload = json.dumps(finding.to_dict(), sort_keys=True, ensure_ascii=False)
                        fingerprint = material_fingerprint(finding)
                        previous = db.execute(
                            "SELECT fingerprint, first_seen, payload_json FROM current_findings WHERE asset_id=? AND cve_id=?",
                            (finding.asset.asset_id, finding.vulnerability.cve_id),
                        ).fetchone()
                        failed_sources = {health.source for health in result.source_health if health.status != HealthStatus.OK}
                        core_incomplete = any(health.source in {"nvd", "cve_list", "euvd"} and health.status in {HealthStatus.FAILED, HealthStatus.DEGRADED} for health in result.source_health)
                        if previous and core_incomplete and not finding.vulnerability.rejected:
                            # Retain the last observation rather than turn a failed
                            # applicability refresh into a resolution or new baseline.
                            continue
                        if previous and failed_sources.intersection({"cisa_kev", "eu_kev", "epss"}):
                            from dataclasses import replace
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
                        db.execute(
                            """INSERT INTO current_findings(asset_id,cve_id,first_seen,last_seen,fingerprint,payload_json)
                               VALUES (?,?,?,?,?,?)
                               ON CONFLICT(asset_id,cve_id) DO UPDATE SET
                                 last_seen=excluded.last_seen, fingerprint=excluded.fingerprint, payload_json=excluded.payload_json""",
                            (finding.asset.asset_id, finding.vulnerability.cve_id, first_seen, completed, fingerprint, payload),
                        )
                        if event_type:
                            cursor = db.execute(
                                "INSERT INTO events(run_id,occurred_at,asset_id,cve_id,event_type,fingerprint,payload_json) VALUES (?,?,?,?,?,?,?)",
                                (run_id, completed, finding.asset.asset_id, finding.vulnerability.cve_id, event_type, fingerprint, payload),
                            )
                            event_id = int(cursor.lastrowid)
                            event_ids.append(event_id)
                            for channel in channels:
                                db.execute(
                                    "INSERT INTO deliveries(event_id,channel,state,updated_at) VALUES (?,?,?,?)",
                                    (event_id, channel, "pending", completed),
                                )
        except (sqlite3.Error, OSError) as exc:
            raise StateError(f"scan state transaction failed: {exc}") from exc
        return run_id, event_ids

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

    def history(self, *, asset_id: str | None = None, cve_id: str | None = None, limit: int = 100) -> list[dict[str, object]]:
        self.initialize()
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise StateError("history limit must be an integer from 1 through 10000")
        clauses, values = [], []
        if asset_id:
            clauses.append("asset_id=?"); values.append(asset_id)
        if cve_id:
            clauses.append("cve_id=?"); values.append(cve_id.upper())
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with closing(self._connect()) as db:
            rows = db.execute(f"SELECT event_id,run_id,occurred_at,asset_id,cve_id,event_type FROM events{where} ORDER BY event_id DESC LIMIT ?", (*values, limit)).fetchall()
            return [dict(row) for row in rows]

    def latest_findings(self) -> list[dict[str, object]]:
        self.initialize()
        with closing(self._connect()) as db:
            return [json.loads(row[0]) for row in db.execute("SELECT payload_json FROM current_findings ORDER BY asset_id,cve_id")]
