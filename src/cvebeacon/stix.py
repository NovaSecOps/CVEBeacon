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
from collections.abc import Iterable, Mapping
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
    validate_client_name,
)

STIX_VERSION = "2.1"
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
    """The latest successful inventory run and its stored findings."""

    run_id: str
    completed_at: str
    findings: tuple[ExportFinding, ...]


@dataclass
class _Aggregate:
    states: set[str]
    sources: set[str]
    first_seen: datetime
    last_seen: datetime
    confidence: str = ""
    clients: set[str] = field(default_factory=set)


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
                "AND cf.cve_id=sf.advisory_id "
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


def _export_findings(
    rows: Iterable[sqlite3.Row], clients: Mapping[str, str]
) -> tuple[ExportFinding, ...]:
    output: list[ExportFinding] = []
    for row in rows:
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
        output.append(
            ExportFinding(
                asset=clean_asset,
                finding=finding,
                first_seen=str(row["first_seen"]),
                last_seen=str(row["last_seen"]),
                client=client,
            )
        )
    return tuple(output)


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
            return ScanSnapshot(
                run_id,
                completed_at,
                _export_findings(rows or (), clients),
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


def _software_key(asset: Mapping[str, Any]) -> str:
    version = _text(asset.get("version"))
    purl = _text(asset.get("purl"))
    if purl:
        return "purl|" + purl + "|" + version
    cpe = _text(asset.get("cpe"))
    if cpe:
        return "cpe|" + cpe + "|" + version
    values = [
        _text(asset.get("ecosystem")).casefold(),
        _text(asset.get("vendor")).casefold(),
        _text(asset.get("product")).casefold(),
        version,
    ]
    return "product|" + "|".join(values)


def _parsed_purl(value: str):
    if not value:
        return None
    try:
        return parse_purl(value)
    except ValueError:
        return None


def _software_object(asset: Mapping[str, Any]) -> dict[str, Any]:
    purl = _text(asset.get("purl"))
    parsed = _parsed_purl(purl)
    name = (
        _text(asset.get("product"))
        or (package_name(parsed) if parsed is not None else "")
        or purl
        or _text(asset.get("cpe"))
        or _text(asset.get("version"))
        or "unknown software"
    )
    value: dict[str, Any] = {
        "type": "software",
        "spec_version": STIX_VERSION,
        "id": _object_id("software", "software|" + _software_key(asset)),
        "name": name,
    }
    vendor = _text(asset.get("vendor"))
    version = _text(asset.get("version")) or (
        parsed.version if parsed is not None else ""
    )
    cpe = _text(asset.get("cpe"))
    ecosystem = _text(asset.get("ecosystem")) or (
        PURL_ECOSYSTEMS.get(parsed.type, "") if parsed is not None else ""
    )
    if vendor:
        value["vendor"] = vendor
    if version:
        value["version"] = version
    if cpe.startswith("cpe:2.3:"):
        value["cpe"] = cpe
    if purl:
        value["x_cvebeacon_purl"] = purl
    if ecosystem:
        value["x_cvebeacon_ecosystem"] = ecosystem
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
            sources=set(sources),
            first_seen=first_seen,
            last_seen=max(first_seen, last_seen),
        )
    else:
        aggregate.states.add(state)
        aggregate.sources.update(sources)
        aggregate.first_seen = min(aggregate.first_seen, first_seen)
        aggregate.last_seen = max(aggregate.last_seen, last_seen)
    if confidence and (
        not aggregate.confidence
        or _confidence_key(confidence)
        > _confidence_key(aggregate.confidence)
    ):
        aggregate.confidence = confidence
    if include_clients and client.strip():
        aggregate.clients.add(client.strip())
    return aggregate


def build_bundle(
    findings: Iterable[ExportFinding],
    *,
    generated_at: datetime | None = None,
    include_clients: bool = False,
) -> dict[str, Any]:
    """Build a deterministic STIX 2.1 bundle from selected inventory findings."""
    generated = _utc(generated_at)
    generated_text = _format_timestamp(generated)

    vulnerabilities: dict[str, dict[str, Any]] = {}
    software: dict[str, dict[str, Any]] = {}
    relationships: dict[str, dict[str, Any]] = {}
    identities: dict[str, dict[str, Any]] = {}
    vulnerability_aggregates: dict[str, _Aggregate] = {}
    relationship_aggregates: dict[str, _Aggregate] = {}
    vulnerability_names: dict[str, str] = {}
    relationship_parts: dict[str, tuple[str, str]] = {}
    included_clients: set[str] = set()
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
            client=item.client,
            include_clients=include_clients,
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
            "relationship|has|" + software_id + "|" + vulnerability_id,
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
        )
        if include_clients and item.client.strip():
            client = item.client.strip()
            included_clients.add(client)
            identity_id = _object_id(
                "identity", "identity|client|" + client.casefold()
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
        value: dict[str, Any] = {
            "type": "vulnerability",
            "spec_version": STIX_VERSION,
            "id": vulnerability_id,
            "created": _format_timestamp(aggregate.first_seen),
            "modified": _format_timestamp(aggregate.last_seen),
            "name": name,
            "external_references": _external_references(name),
            "x_cvebeacon_applicability": _highest_applicability(
                aggregate.states
            ),
            "x_cvebeacon_sources": sorted(
                aggregate.sources, key=lambda item: (item.casefold(), item)
            ),
            "x_cvebeacon_first_seen": _format_timestamp(
                aggregate.first_seen
            ),
        }
        if aggregate.confidence:
            value["x_cvebeacon_confidence"] = aggregate.confidence
        if vulnerability_id in summaries:
            value["description"] = summaries[vulnerability_id]
        vulnerabilities[vulnerability_id] = value

    for relationship_id, aggregate in relationship_aggregates.items():
        source_ref, target_ref = relationship_parts[relationship_id]
        value = {
            "type": "relationship",
            "spec_version": STIX_VERSION,
            "id": relationship_id,
            "created": _format_timestamp(aggregate.first_seen),
            "modified": _format_timestamp(aggregate.last_seen),
            "relationship_type": "has",
            "source_ref": source_ref,
            "target_ref": target_ref,
            "x_cvebeacon_applicability": _highest_applicability(
                aggregate.states
            ),
            "x_cvebeacon_sources": sorted(
                aggregate.sources, key=lambda item: (item.casefold(), item)
            ),
            "x_cvebeacon_first_seen": _format_timestamp(
                aggregate.first_seen
            ),
        }
        if aggregate.confidence:
            value["x_cvebeacon_confidence"] = aggregate.confidence
        if include_clients and aggregate.clients:
            value["x_cvebeacon_clients"] = sorted(
                aggregate.clients, key=lambda item: (item.casefold(), item)
            )
        relationships[relationship_id] = value

    objects = {**identities, **software, **vulnerabilities, **relationships}
    object_refs = sorted(
        objects, key=lambda value: (_OBJECT_ORDER.get(objects[value]["type"], 9), value)
    )
    if object_refs:
        clients = sorted(
            included_clients,
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
        objects[report_id] = {
            "type": "report",
            "spec_version": STIX_VERSION,
            "id": report_id,
            "created": generated_text,
            "modified": generated_text,
            "published": generated_text,
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
        "bundle", "bundle|" + "|".join(item["id"] for item in ordered)
    )
    return {"type": "bundle", "id": bundle_id, "objects": ordered}


def export_stix(
    database: str | Path,
    output: str | Path,
    *,
    client: str | None = None,
    include_clients: bool = False,
    since: str | None = None,
    generated_at: datetime | None = None,
) -> Path:
    """Export the latest successful inventory run as one STIX 2.1 bundle."""
    snapshot = read_latest_successful_scan(database)
    selected = select_findings(
        snapshot.findings, client=client, since=since
    )
    bundle = build_bundle(
        selected,
        generated_at=generated_at,
        include_clients=include_clients,
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
