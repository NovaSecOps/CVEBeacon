"""Optional, read-only STIX 2.1 export of inventory findings.

The bundle is built from the latest successful inventory run. It deliberately
does not read the watch database, query public sources, or write monitoring
state. Only ``affected`` and ``needs_review`` findings are exported so that an
unknown or excluded applicability is never presented as a confirmed match.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
import uuid
import warnings
from collections.abc import Callable, Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any

from .errors import CVEBeaconError, ReportingError, StateError
from .identity import (
    PURL_ECOSYSTEMS,
    package_name,
    parse_purl,
    purl_string,
    validate_client_name,
)

STIX_VERSION = "2.1"
CREATED_TABLE = "stix_object_created"
# Fixed project namespace for UUIDv5 identifiers. Changing it would make
# re-exports create new objects instead of updating the existing ones.
STIX_NAMESPACE = uuid.UUID("1c0ca72c-9854-4be1-b48b-ef2e89900fdc")

EXPORTED_STATES = ("affected", "needs_review")
_APPLICABILITY_RANK = {"affected": 2, "needs_review": 1}
_CONFIDENCE_RANK = {"high": 2, "limited": 1}
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_OBJECT_ORDER = {
    "identity": 0,
    "software": 1,
    "vulnerability": 2,
    "relationship": 3,
    "report": 4,
}


@dataclass(frozen=True, slots=True)
class ExportFinding:
    """One stored finding selected from a successful inventory run."""

    asset: Mapping[str, Any]
    finding: Mapping[str, Any]
    first_seen: str
    last_seen: str
    client: str = ""

    @property
    def applicability(self) -> str:
        return _applicability(self.finding)


@dataclass(frozen=True, slots=True)
class ScanSnapshot:
    """The latest successful run, its findings, and full current history."""

    run_id: str
    completed_at: str
    findings: tuple[ExportFinding, ...]
    history: tuple[ExportFinding, ...] = ()
    history_skipped: int = 0


@dataclass
class _Aggregate:
    states: set[str]
    state_sources: dict[str, set[str]]
    state_confidence: dict[str, str]
    first_seen: datetime
    last_seen: datetime
    clients: dict[str, str] = field(default_factory=dict)


def _connect_readonly(path: Path) -> sqlite3.Connection:
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        return connection
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise StateError(f"cannot read state database: {exc}") from exc


def _latest_run(db: sqlite3.Connection) -> sqlite3.Row | None:
    return db.execute(
        "SELECT run_id,completed_at FROM runs WHERE status='completed' "
        "ORDER BY completed_at DESC, rowid DESC LIMIT 1"
    ).fetchone()


def _detail_rows(
    db: sqlite3.Connection, run_id: str
) -> list[sqlite3.Row] | None:
    try:
        return list(
            db.execute(
                "SELECT asset_id,advisory_id,first_seen,last_seen,payload_json "
                "FROM scan_finding_details WHERE run_id=? "
                "ORDER BY asset_id,advisory_id",
                (run_id,),
            )
        )
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return None
        raise


def _fallback_rows(
    db: sqlite3.Connection, run_id: str, completed_at: str
) -> list[sqlite3.Row]:
    """Read a run written before run-scoped finding details existed.

    The current-findings cache is only accepted when its ``last_seen`` is the
    exact completion time of the selected successful run. A later failed run
    therefore cannot leak newer observations into the export.
    """
    try:
        return list(
            db.execute(
                "SELECT sf.asset_id,sf.advisory_id,cf.first_seen,cf.last_seen,"
                "cf.payload_json FROM scan_findings sf "
                "JOIN current_findings cf ON cf.asset_id=sf.asset_id "
                "AND cf.cve_id=sf.advisory_id COLLATE NOCASE "
                "WHERE sf.run_id=? AND sf.identifier=sf.advisory_id "
                "AND cf.last_seen=? ORDER BY sf.asset_id,sf.advisory_id",
                (run_id, completed_at),
            )
        )
    except sqlite3.OperationalError as exc:
        if "no such table" not in str(exc):
            raise
    try:
        return list(
            db.execute(
                "SELECT asset_id,cve_id AS advisory_id,first_seen,last_seen,"
                "payload_json FROM current_findings WHERE last_seen=? "
                "ORDER BY asset_id,cve_id",
                (completed_at,),
            )
        )
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return []
        raise


def _current_rows(db: sqlite3.Connection) -> list[sqlite3.Row]:
    try:
        return list(
            db.execute(
                "SELECT asset_id,cve_id AS advisory_id,first_seen,last_seen,"
                "payload_json FROM current_findings "
                "ORDER BY asset_id,cve_id",
            )
        )
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return []
        raise


def _run_clients(db: sqlite3.Connection, run_id: str) -> dict[str, str]:
    try:
        rows = db.execute(
            "SELECT asset_id,client FROM scan_asset_clients WHERE run_id=?",
            (run_id,),
        )
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return {}
        raise
    return {
        str(row["asset_id"]): str(row["client"])
        for row in rows
        if str(row["client"]).strip()
    }


def _export_finding(
    row: sqlite3.Row, clients: Mapping[str, str]
) -> ExportFinding:
    try:
        payload = json.loads(row["payload_json"])
    except (TypeError, ValueError) as exc:
        raise StateError("state database contains an invalid finding") from exc
    if not isinstance(payload, dict):
        raise StateError("state database contains an invalid finding")
    asset = payload.get("asset")
    if not isinstance(asset, dict):
        raise StateError("state database contains an invalid finding")
    clean_asset = {
        key: value for key, value in asset.items() if key != "client"
    }
    finding = {key: value for key, value in payload.items() if key != "asset"}
    asset_id = str(row["asset_id"])
    client = clients.get(asset_id, "")
    if not client:
        client = str(asset.get("client") or "")
    return ExportFinding(
        asset=clean_asset,
        finding=finding,
        first_seen=str(row["first_seen"]),
        last_seen=str(row["last_seen"]),
        client=client,
    )


def _export_findings(
    rows: Iterable[sqlite3.Row], clients: Mapping[str, str]
) -> tuple[ExportFinding, ...]:
    return tuple(_export_finding(row, clients) for row in rows)


def _history_findings(
    rows: Iterable[sqlite3.Row], clients: Mapping[str, str]
) -> tuple[tuple[ExportFinding, ...], int]:
    """Read advisory history, skipping and counting unrelated malformed rows."""
    output: list[ExportFinding] = []
    skipped = 0
    for row in rows:
        try:
            item = _export_finding(row, clients)
            _parse_timestamp(item.first_seen)
        except StateError:
            skipped += 1
            continue
        output.append(item)
    return tuple(output), skipped


def read_latest_successful_scan(path: str | Path) -> ScanSnapshot:
    """Read the latest completed inventory run without creating or changing state."""
    database = Path(path)
    if not database.is_file():
        raise StateError(
            "state database not found; run a scan before exporting STIX"
        )
    try:
        with closing(_connect_readonly(database)) as db:
            db.execute("BEGIN")
            run = _latest_run(db)
            if run is None:
                return ScanSnapshot("", "", ())
            run_id = str(run["run_id"])
            completed_at = str(run["completed_at"])
            rows = _detail_rows(db, run_id)
            if not rows:
                rows = _fallback_rows(db, run_id, completed_at)
            clients = _run_clients(db, run_id)
            history, history_skipped = _history_findings(
                _current_rows(db), clients
            )
            return ScanSnapshot(
                run_id,
                completed_at,
                _export_findings(rows or (), clients),
                history,
                history_skipped,
            )
    except sqlite3.Error as exc:
        raise StateError(f"cannot read state database for STIX export: {exc}") from exc


def parse_since(value: str) -> datetime:
    """Parse a date or ISO 8601 timestamp as a UTC instant."""
    text = str(value or "").strip()
    if not text:
        raise CVEBeaconError("--since requires a date or timestamp")
    try:
        if _DATE_ONLY.fullmatch(text):
            return datetime.combine(
                date.fromisoformat(text), time.min, tzinfo=timezone.utc
            )
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.upper().endswith("Z") else text
        )
    except ValueError as exc:
        raise CVEBeaconError(
            f"--since must be an ISO 8601 date or timestamp: {text}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def select_findings(
    findings: Iterable[ExportFinding],
    *,
    client: str | None = None,
    since: str | None = None,
) -> tuple[ExportFinding, ...]:
    """Select exportable findings by applicability, client, and first-seen time."""
    selected_client = None
    if client is not None:
        selected_client = client.strip()
        if not selected_client:
            raise CVEBeaconError("--client requires a client label")
        try:
            validate_client_name(selected_client)
        except ValueError as exc:
            raise CVEBeaconError(f"invalid --client label: {exc}") from exc
    start = parse_since(since) if since is not None else None
    output: list[ExportFinding] = []
    for item in findings:
        if item.applicability not in EXPORTED_STATES:
            continue
        if selected_client is not None and (
            item.client.strip().casefold() != selected_client.casefold()
        ):
            continue
        if start is not None and _parse_timestamp(item.first_seen) < start:
            continue
        output.append(item)
    return tuple(output)


def _parse_timestamp(value: object) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise StateError("state contains a finding without a timestamp")
    try:
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.upper().endswith("Z") else text
        )
    except ValueError as exc:
        raise StateError("state contains an invalid finding timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _text(value: object, limit: int = 32_000) -> str:
    return _CONTROL.sub("", str(value or "").strip())[:limit]


def _applicability(finding: Mapping[str, Any]) -> str:
    value = finding.get("applicability")
    if hasattr(value, "value"):
        value = value.value
    return str(value or "").strip().casefold()


def _values(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = (value,)
    return tuple(
        str(item).strip() for item in items if str(item or "").strip()
    )


def _vulnerability_name(vulnerability: Mapping[str, Any]) -> str:
    candidates = (
        vulnerability.get("cve_id"),
        vulnerability.get("advisory_id"),
        *_values(vulnerability.get("aliases")),
        *_values(vulnerability.get("source_ids")),
    )
    for candidate in candidates:
        text = _text(candidate)
        if _CVE_ID.fullmatch(text):
            return text.upper()
    primary = _text(
        vulnerability.get("advisory_id") or vulnerability.get("cve_id")
    )
    if primary:
        return primary
    for candidate in candidates:
        text = _text(candidate)
        if text:
            return text
    return ""


def _external_references(name: str) -> list[dict[str, str]]:
    if _CVE_ID.fullmatch(name):
        return [
            {
                "source_name": "nvd",
                "external_id": name,
                "url": f"https://nvd.nist.gov/vuln/detail/{name}",
            },
            {
                "source_name": "cve",
                "external_id": name,
                "url": f"https://www.cve.org/CVERecord?id={name}",
            },
        ]
    return [{"source_name": "advisory", "external_id": name}]


def _sources(finding: Mapping[str, Any]) -> set[str]:
    evidence = finding.get("evidence")
    if not isinstance(evidence, (list, tuple)):
        return set()
    return {
        _text(item.get("source"))
        for item in evidence
        if isinstance(item, Mapping) and _text(item.get("source"))
    }


def _confidence_key(value: str) -> tuple[int, str]:
    text = value.casefold()
    return (_CONFIDENCE_RANK.get(text, 0), text)


def _state_key(value: str) -> tuple[int, str]:
    return (-_APPLICABILITY_RANK.get(value, 0), value)


def _highest_applicability(states: Iterable[str]) -> str:
    return max(
        states,
        key=lambda value: (
            _APPLICABILITY_RANK.get(value, 0),
            value,
        ),
    )


def _object_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, key)}"


def _purl_coordinate(value: str):
    """Return a sanitised package coordinate and its parsed form.

    Qualifiers and subpaths are intentionally dropped. They can carry
    repository, download, VCS, or token-bearing values that must not appear in
    an export, and they do not identify the package version itself.
    """
    if not value:
        return "", None
    try:
        parsed = parse_purl(value)
    except ValueError:
        return "", None
    sanitised = purl_string(parsed._replace(qualifiers={}, subpath=None))
    return sanitised, parsed


def _software_fields(asset: Mapping[str, Any]) -> dict[str, str]:
    purl, parsed = _purl_coordinate(_text(asset.get("purl")))
    version = _text(asset.get("version")) or _text(
        parsed.version if parsed is not None else ""
    )
    ecosystem = _text(asset.get("ecosystem")) or (
        PURL_ECOSYSTEMS.get(parsed.type, "") if parsed is not None else ""
    )
    cpe = _text(asset.get("cpe"))
    product = _text(asset.get("product")) or (
        package_name(parsed) if parsed is not None else ""
    )
    return {
        "name": product
        or cpe
        or version
        or "unknown software",
        "vendor": _text(asset.get("vendor")),
        "version": version,
        "cpe": cpe,
        "purl": purl,
        "ecosystem": ecosystem,
    }


def _software_key(asset: Mapping[str, Any]) -> str:
    fields = _software_fields(asset)
    if fields["purl"]:
        return "purl|" + fields["purl"] + "|" + fields["version"]
    if fields["cpe"]:
        return "cpe|" + fields["cpe"] + "|" + fields["version"]
    return "product|" + "|".join(
        (
            fields["ecosystem"].casefold(),
            fields["vendor"].casefold(),
            _text(asset.get("product")).casefold(),
            fields["version"],
        )
    )


def _software_object(asset: Mapping[str, Any]) -> dict[str, Any]:
    fields = _software_fields(asset)
    value: dict[str, Any] = {
        "type": "software",
        "spec_version": STIX_VERSION,
        "id": _object_id("software", "software|" + _software_key(asset)),
        "name": fields["name"],
    }
    if fields["vendor"]:
        value["vendor"] = fields["vendor"]
    if fields["version"]:
        value["version"] = fields["version"]
    if fields["cpe"].startswith("cpe:2.3:"):
        value["cpe"] = fields["cpe"]
    if fields["purl"]:
        value["x_cvebeacon_purl"] = fields["purl"]
    if fields["ecosystem"]:
        value["x_cvebeacon_ecosystem"] = fields["ecosystem"]
    return value


def _merge_software(
    software: dict[str, dict[str, Any]], asset: Mapping[str, Any]
) -> str:
    candidate = _software_object(asset)
    key = candidate["id"]
    current = software.get(key)
    if current is None:
        software[key] = candidate
        return key
    for name in ("name", "vendor"):
        left = _text(candidate.get(name))
        right = _text(current.get(name))
        if left and (
            not right
            or (left.casefold(), left) < (right.casefold(), right)
        ):
            if left != right:
                current[name] = left
    for name in ("cpe", "x_cvebeacon_purl", "x_cvebeacon_ecosystem"):
        if candidate.get(name) and not current.get(name):
            current[name] = candidate[name]
    return key


def _merge_aggregate(
    aggregate: _Aggregate | None,
    *,
    state: str,
    sources: Iterable[str],
    first_seen: datetime,
    last_seen: datetime,
    confidence: str,
    client: str,
    include_clients: bool,
) -> _Aggregate:
    if aggregate is None:
        aggregate = _Aggregate(
            states={state},
            state_sources={state: set(sources)},
            state_confidence={},
            first_seen=first_seen,
            last_seen=max(first_seen, last_seen),
        )
    else:
        aggregate.states.add(state)
        aggregate.state_sources.setdefault(state, set()).update(sources)
        aggregate.first_seen = min(aggregate.first_seen, first_seen)
        aggregate.last_seen = max(aggregate.last_seen, last_seen)
    if confidence and (
        not aggregate.state_confidence.get(state)
        or _confidence_key(confidence)
        > _confidence_key(aggregate.state_confidence[state])
    ):
        aggregate.state_confidence[state] = confidence
    if include_clients and client.strip():
        label = client.strip()
        key = label.casefold()
        current = aggregate.clients.get(key)
        if current is None or (label.casefold(), label) < (
            current.casefold(),
            current,
        ):
            aggregate.clients[key] = label
    return aggregate


def _history_indexes(
    history: Iterable[ExportFinding],
) -> tuple[dict[str, datetime], dict[str, datetime], dict[str, datetime]]:
    """Return earliest observations by vulnerability, relationship, and client.

    ``current_findings`` keeps a row and its original first-seen time after a
    finding disappears from a later scan. Using that full history keeps
    ``created`` stable while the same object ID remains in an export.
    """
    vulnerability_first: dict[str, datetime] = {}
    relationship_first: dict[str, datetime] = {}
    client_first: dict[str, datetime] = {}
    for item in history:
        vulnerability = item.finding.get("vulnerability")
        if not isinstance(vulnerability, Mapping):
            continue
        name = _vulnerability_name(vulnerability)
        if not name:
            continue
        try:
            first_seen = _parse_timestamp(item.first_seen)
        except StateError:
            continue
        vulnerability_id = _object_id(
            "vulnerability", "vulnerability|" + name.upper()
        )
        vulnerability_first[vulnerability_id] = min(
            first_seen,
            vulnerability_first.get(vulnerability_id, first_seen),
        )
        state = item.applicability
        if state in EXPORTED_STATES:
            software_id = _object_id(
                "software", "software|" + _software_key(item.asset)
            )
            relationship_id = _object_id(
                "relationship",
                "relationship|has|"
                + software_id
                + "|"
                + vulnerability_id
                + "|"
                + state,
            )
            relationship_first[relationship_id] = min(
                first_seen,
                relationship_first.get(relationship_id, first_seen),
            )
        client = item.client.strip()
        if client:
            client_first[client.casefold()] = min(
                first_seen,
                client_first.get(client.casefold(), first_seen),
            )
    return vulnerability_first, relationship_first, client_first


def build_bundle(
    findings: Iterable[ExportFinding],
    *,
    generated_at: datetime | None = None,
    include_clients: bool = False,
    history: Iterable[ExportFinding] = (),
) -> dict[str, Any]:
    """Build a deterministic STIX 2.1 bundle from selected inventory findings."""
    generated = _utc(generated_at)
    generated_text = _format_timestamp(generated)
    (
        history_vulnerability_first,
        history_relationship_first,
        history_client_first,
    ) = _history_indexes(history)

    vulnerabilities: dict[str, dict[str, Any]] = {}
    software: dict[str, dict[str, Any]] = {}
    relationships: dict[str, dict[str, Any]] = {}
    identities: dict[str, dict[str, Any]] = {}
    vulnerability_aggregates: dict[str, _Aggregate] = {}
    relationship_aggregates: dict[str, _Aggregate] = {}
    vulnerability_names: dict[str, str] = {}
    relationship_parts: dict[str, tuple[str, str, str]] = {}
    identity_first_seen: dict[str, datetime] = {}
    included_clients: dict[str, str] = {}
    report_created: datetime | None = None
    summaries: dict[str, str] = {}

    items = tuple(findings)
    for item in items:
        state = item.applicability
        if state not in EXPORTED_STATES:
            continue
        vulnerability = item.finding.get("vulnerability")
        if not isinstance(vulnerability, Mapping):
            raise StateError("state database contains an invalid finding")
        name = _vulnerability_name(vulnerability)
        if not name:
            raise StateError(
                "state database contains a finding without an identifier"
            )
        first_seen = _parse_timestamp(item.first_seen)
        last_seen = max(first_seen, _parse_timestamp(item.last_seen))
        sources = _sources(item.finding)
        confidence = _text(item.finding.get("confidence"))

        vulnerability_id = _object_id("vulnerability", "vulnerability|" + name.upper())
        vulnerability_aggregates[vulnerability_id] = _merge_aggregate(
            vulnerability_aggregates.get(vulnerability_id),
            state=state,
            sources=sources,
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=confidence,
            client="",
            include_clients=False,
        )
        current_name = vulnerability_names.get(vulnerability_id)
        if current_name is None or (
            (name.casefold(), name) < (current_name.casefold(), current_name)
        ):
            vulnerability_names[vulnerability_id] = name
        summary = _text(vulnerability.get("summary"))
        if summary and (
            vulnerability_id not in summaries
            or (summary.casefold(), summary)
            < (
                summaries[vulnerability_id].casefold(),
                summaries[vulnerability_id],
            )
        ):
            summaries[vulnerability_id] = summary

        software_id = _merge_software(software, item.asset)
        relationship_id = _object_id(
            "relationship",
            "relationship|has|"
            + software_id
            + "|"
            + vulnerability_id
            + "|"
            + state,
        )
        relationship_aggregates[relationship_id] = _merge_aggregate(
            relationship_aggregates.get(relationship_id),
            state=state,
            sources=sources,
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=confidence,
            client=item.client,
            include_clients=include_clients,
        )
        relationship_parts[relationship_id] = (
            software_id,
            vulnerability_id,
            state,
        )
        if include_clients and item.client.strip():
            client = item.client.strip()
            key = client.casefold()
            current_label = included_clients.get(key)
            if current_label is None or (key, client) < (
                current_label.casefold(),
                current_label,
            ):
                included_clients[key] = client
            identity_id = _object_id(
                "identity", "identity|client|" + key
            )
            identity_first_seen[identity_id] = min(
                first_seen,
                identity_first_seen.get(identity_id, first_seen),
            )
            current = identities.get(identity_id)
            if current is None or (
                (client.casefold(), client)
                < (
                    _text(current["name"]).casefold(),
                    _text(current["name"]),
                )
            ):
                identities[identity_id] = {
                    "type": "identity",
                    "spec_version": STIX_VERSION,
                    "id": identity_id,
                    "created": generated_text,
                    "modified": generated_text,
                    "name": client,
                    "identity_class": "organization",
                }

    for vulnerability_id, aggregate in vulnerability_aggregates.items():
        name = vulnerability_names[vulnerability_id]
        highest = _highest_applicability(aggregate.states)
        sources = aggregate.state_sources.get(highest, set())
        confidence = aggregate.state_confidence.get(highest, "")
        created = history_vulnerability_first.get(
            vulnerability_id, aggregate.first_seen
        )
        report_created = (
            created
            if report_created is None
            else min(report_created, created)
        )
        value: dict[str, Any] = {
            "type": "vulnerability",
            "spec_version": STIX_VERSION,
            "id": vulnerability_id,
            "created": _format_timestamp(created),
            "modified": _format_timestamp(
                max(aggregate.last_seen, created)
            ),
            "name": name,
            "external_references": _external_references(name),
            "x_cvebeacon_applicability": highest,
            "x_cvebeacon_states": sorted(
                aggregate.states, key=_state_key
            ),
            "x_cvebeacon_first_seen": _format_timestamp(created),
        }
        if sources:
            value["x_cvebeacon_sources"] = sorted(
                sources, key=lambda item: (item.casefold(), item)
            )
        if confidence:
            value["x_cvebeacon_confidence"] = confidence
        if vulnerability_id in summaries:
            value["description"] = summaries[vulnerability_id]
        vulnerabilities[vulnerability_id] = value

    for identity_id, value in identities.items():
        created = history_client_first.get(
            _text(value["name"]).casefold(),
            identity_first_seen[identity_id],
        )
        value["created"] = _format_timestamp(created)
        value["modified"] = _format_timestamp(max(generated, created))

    for relationship_id, aggregate in relationship_aggregates.items():
        source_ref, target_ref, state = relationship_parts[relationship_id]
        sources = aggregate.state_sources.get(state, set())
        confidence = aggregate.state_confidence.get(state, "")
        created = history_relationship_first.get(
            relationship_id, aggregate.first_seen
        )
        report_created = (
            created
            if report_created is None
            else min(report_created, created)
        )
        value = {
            "type": "relationship",
            "spec_version": STIX_VERSION,
            "id": relationship_id,
            "created": _format_timestamp(created),
            "modified": _format_timestamp(
                max(aggregate.last_seen, created)
            ),
            "relationship_type": "has",
            "source_ref": source_ref,
            "target_ref": target_ref,
            "x_cvebeacon_applicability": state,
            "x_cvebeacon_first_seen": _format_timestamp(created),
        }
        if sources:
            value["x_cvebeacon_sources"] = sorted(
                sources, key=lambda item: (item.casefold(), item)
            )
        if confidence:
            value["x_cvebeacon_confidence"] = confidence
        if include_clients and aggregate.clients:
            labels = sorted(
                aggregate.clients.values(),
                key=lambda item: (item.casefold(), item),
            )
            value["x_cvebeacon_clients"] = labels
            value["x_cvebeacon_client_refs"] = [
                _object_id("identity", "identity|client|" + label.casefold())
                for label in labels
            ]
        relationships[relationship_id] = value

    objects = {**identities, **software, **vulnerabilities, **relationships}
    object_refs = sorted(
        objects, key=lambda value: (_OBJECT_ORDER.get(objects[value]["type"], 9), value)
    )
    if object_refs:
        clients = sorted(
            included_clients.values(),
            key=lambda item: (item.casefold(), item),
        )
        if include_clients and clients:
            label = clients[0] if len(clients) == 1 else "multiple clients"
            report_name = f"CVEBeacon findings for {label}"
        else:
            report_name = "CVEBeacon findings"
        report_id = _object_id(
            "report", "report|" + "|".join(object_refs)
        )
        report_created = report_created or generated
        report_modified = max(generated, report_created)
        objects[report_id] = {
            "type": "report",
            "spec_version": STIX_VERSION,
            "id": report_id,
            "created": _format_timestamp(report_created),
            "modified": _format_timestamp(report_modified),
            "published": _format_timestamp(report_modified),
            "name": report_name,
            "report_types": ["vulnerability"],
            "description": (
                "Inventory-derived vulnerability applicability export. "
                "Review access and handling rules before sharing."
            ),
            "object_refs": object_refs,
        }

    ordered = sorted(
        objects.values(),
        key=lambda value: (
            _OBJECT_ORDER.get(value["type"], 9),
            value["id"],
        ),
    )
    bundle_id = _object_id(
        "bundle",
        "bundle|"
        + ("|".join(item["id"] for item in ordered) if ordered else "empty"),
    )
    bundle = {"type": "bundle", "id": bundle_id}
    if ordered:
        bundle["objects"] = ordered
    return bundle


def _read_created_ledger(database: str | Path) -> dict[str, str]:
    """Read the first-created ledger, treating a missing table as empty."""
    try:
        with closing(_connect_readonly(Path(database))) as db:
            db.execute("BEGIN")
            rows = db.execute(
                f"SELECT object_id,created FROM {CREATED_TABLE}"
            ).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return {}
        raise StateError(
            "cannot read the STIX created ledger from the state database"
        ) from exc
    output: dict[str, str] = {}
    for row in rows:
        created = str(row["created"])
        try:
            _parse_timestamp(created)
        except StateError:
            continue
        output[str(row["object_id"])] = created
    return output


def _clamp_created_timestamps(value: dict[str, Any], created: str) -> None:
    created_at = _parse_timestamp(created)
    value["created"] = created
    for key in ("modified", "published"):
        if key not in value:
            continue
        current = _parse_timestamp(value[key])
        if current < created_at:
            value[key] = _format_timestamp(created_at)


def _apply_created_ledger(
    bundle: Mapping[str, Any], ledger: Mapping[str, str]
) -> dict[str, str]:
    """Apply stored created values and return first-created rows to add."""
    pending: dict[str, str] = {}
    for value in bundle.get("objects", ()):
        if "created" not in value:
            continue
        object_id = str(value["id"])
        stored = ledger.get(object_id)
        if stored is None:
            pending[object_id] = str(value["created"])
        else:
            _clamp_created_timestamps(value, stored)
    return pending


def _write_created_ledger(
    database: str | Path, pending: Mapping[str, str]
) -> bool:
    if not pending:
        return True
    try:
        connection = sqlite3.connect(str(database), timeout=5.0)
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute(
                f"CREATE TABLE IF NOT EXISTS {CREATED_TABLE} ("
                "object_id TEXT PRIMARY KEY, created TEXT NOT NULL)"
            )
            connection.executemany(
                f"INSERT INTO {CREATED_TABLE}(object_id,created) "
                "VALUES (?,?) ON CONFLICT(object_id) DO UPDATE SET "
                "created=excluded.created",
                sorted(pending.items()),
            )
            connection.commit()
        finally:
            connection.close()
    except (sqlite3.Error, OSError):
        return False
    return True


def _warn(warning: Callable[[str], None] | None, message: str) -> None:
    if warning is not None:
        warning(message)
    else:
        warnings.warn(message, RuntimeWarning, stacklevel=3)


def export_stix(
    database: str | Path,
    output: str | Path,
    *,
    client: str | None = None,
    include_clients: bool = False,
    since: str | None = None,
    generated_at: datetime | None = None,
    warning: Callable[[str], None] | None = None,
) -> Path:
    """Export the latest successful inventory run as one STIX 2.1 bundle."""
    snapshot = read_latest_successful_scan(database)
    if snapshot.history_skipped:
        _warn(
            warning,
            "skipped "
            f"{snapshot.history_skipped} malformed historical finding "
            "row(s) while deriving created timestamps",
        )
    selected = select_findings(
        snapshot.findings, client=client, since=since
    )
    bundle = build_bundle(
        selected,
        generated_at=generated_at,
        include_clients=include_clients,
        history=snapshot.history,
    )
    try:
        ledger = _read_created_ledger(database)
    except StateError:
        _warn(
            warning,
            "the STIX created ledger could not be read; using computed "
            "created timestamps",
        )
        ledger = {}
    pending = _apply_created_ledger(bundle, ledger)
    if not _write_created_ledger(database, pending):
        _warn(
            warning,
            "the STIX created ledger is read-only; using computed created "
            "timestamps for new objects",
        )
    return write_bundle(bundle, output)


def write_bundle(bundle: Mapping[str, Any], path: str | Path) -> Path:
    """Write one JSON bundle atomically, without creating partial output."""
    destination = Path(path)
    temporary: Path | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=destination.parent,
            suffix=".json",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(bundle, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(temporary, destination)
    except (OSError, TypeError, ValueError) as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise ReportingError(
            f"cannot write STIX bundle {destination}: {exc}"
        ) from exc
    return destination
