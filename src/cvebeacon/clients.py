"""Client assignment and read-only correlation with inventory findings.

Inventory assets may carry an optional ``client`` label. A watch CVE affects a
client when the latest successful inventory scan recorded an ``affected`` or
``needs_review`` finding for that CVE on one of the client's assets.

Correlation only reads the monitoring state database. It never creates or
migrates it, and it never changes applicability: the stored finding status is
used as it is. Client names stay local; they are never sent to public sources.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .watch.catalog import DEFAULT_LANGUAGE, catalog_for, translate

MAX_CLIENT_LENGTH = 120
MAX_REQUESTED_CVES = 200
AFFECTED_STATUSES = ("affected", "needs_review")


@dataclass(frozen=True, slots=True)
class ClientImpact:
    """One client affected by a CVE, with the number of matching assets."""

    name: str
    assets: int
    status: str


@dataclass(frozen=True, slots=True)
class ClientFinding:
    cve_id: str
    status: str


@dataclass(frozen=True, slots=True)
class ClientSummary:
    name: str
    assets: int
    findings: tuple[ClientFinding, ...]


@dataclass(frozen=True, slots=True)
class ScanInfo:
    run_id: str
    completed_at: str


def _connect(path: str | Path) -> sqlite3.Connection | None:
    source = Path(path)
    try:
        if not source.is_file():
            return None
        uri = source.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        return connection
    except (sqlite3.Error, OSError, ValueError):
        return None


def _read(path: str | Path, operation, default):
    connection = _connect(path)
    if connection is None:
        return default
    try:
        with closing(connection):
            return operation(connection)
    except (sqlite3.Error, OSError, TypeError, ValueError):
        return default


def _latest_successful_scan(db: sqlite3.Connection) -> ScanInfo | None:
    row = db.execute(
        "SELECT run_id,completed_at FROM runs WHERE status='completed' "
        "ORDER BY completed_at DESC, rowid DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    return ScanInfo(str(row["run_id"]), str(row["completed_at"]))


def _client_name(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if (
        not text
        or len(text) > MAX_CLIENT_LENGTH
        or any(ord(character) < 32 for character in text)
    ):
        return ""
    return text


def _payload(value: object) -> Mapping[str, object]:
    if not isinstance(value, str):
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _asset_client(value: object) -> str:
    asset = _payload(value).get("asset")
    if not isinstance(asset, dict):
        return ""
    return _client_name(asset.get("client"))


def _display_name(names: Iterable[str]) -> str:
    """Choose one stable spelling for a client name that differs only by case."""
    values = set(names)
    return min(values, key=lambda item: (item.casefold(), item)) if values else ""


def latest_successful_scan(path: str | Path) -> ScanInfo | None:
    """Return the newest completed inventory run, if the state database exists."""
    return _read(path, _latest_successful_scan, None)


def client_summaries(
    path: str | Path,
) -> tuple[ScanInfo | None, tuple[ClientSummary, ...]]:
    """Return client asset counts and currently affected CVEs from one scan."""

    def read(db: sqlite3.Connection):
        scan = _latest_successful_scan(db)
        if scan is None:
            return None, ()
        rows = db.execute(
            "SELECT s.asset_id, s.payload_json AS asset_json, "
            "f.cve_id AS finding_cve, f.payload_json AS finding_json "
            "FROM scan_assets s "
            "LEFT JOIN current_findings f ON f.asset_id = s.asset_id "
            "WHERE s.run_id = ? ORDER BY s.asset_id, f.cve_id",
            (scan.run_id,),
        ).fetchall()
        clients: dict[str, dict[str, object]] = {}
        for row in rows:
            name = _asset_client(row["asset_json"])
            if not name:
                continue
            key = name.casefold()
            entry = clients.setdefault(
                key, {"names": set(), "assets": set(), "findings": {}}
            )
            entry["names"].add(name)
            entry["assets"].add(str(row["asset_id"]))
            if row["finding_cve"] is None:
                continue
            finding = _payload(row["finding_json"])
            status = finding.get("applicability")
            if status not in AFFECTED_STATUSES:
                continue
            cve_id = str(row["finding_cve"]).upper()
            previous = entry["findings"].get(cve_id)
            if previous != "affected":
                entry["findings"][cve_id] = status
        output = []
        for entry in clients.values():
            findings = tuple(
                ClientFinding(cve_id, status)
                for cve_id, status in sorted(entry["findings"].items())
            )
            output.append(
                ClientSummary(
                    _display_name(entry["names"]),
                    len(entry["assets"]),
                    findings,
                )
            )
        output.sort(key=lambda item: (item.name.casefold(), item.name))
        return scan, tuple(output)

    return _read(path, read, (None, ()))


def _requested_names(cve_ids: Iterable[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in cve_ids:
        text = str(value).strip()
        if text:
            output.setdefault(text.upper(), text)
    return output


def _merge_impact(
    impacts: dict[str, dict[str, object]],
    cve_id: str,
    name: str,
    asset_id: str,
    status: str,
) -> None:
    entry = impacts.setdefault(cve_id, {"names": set(), "assets": defaultdict(set), "status": {}})
    key = name.casefold()
    entry["names"].add(name)
    entry["assets"][key].add(asset_id)
    previous = entry["status"].get(key)
    if previous != "affected" and (previous is None or status == "affected"):
        entry["status"][key] = status


def _affected_chunk(
    db: sqlite3.Connection,
    run_id: str,
    requested: Mapping[str, str],
    impacts: dict[str, dict[str, object]],
) -> None:
    names = tuple(requested)
    marks = ",".join("?" for _ in names)
    alias_rows = db.execute(
        "SELECT a.asset_id, a.alias, a.primary_id FROM advisory_aliases a "
        "JOIN scan_assets s ON s.asset_id = a.asset_id AND s.run_id = ? "
        "WHERE a.alias IN (" + marks + ")",
        (run_id, *names),
    ).fetchall()
    alias_primary: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in alias_rows:
        alias_primary[(str(row["asset_id"]), str(row["alias"]).upper())].add(
            str(row["primary_id"]).upper()
        )
    candidate_primaries = set(names)
    for values in alias_primary.values():
        candidate_primaries.update(values)
    primitive_marks = ",".join("?" for _ in candidate_primaries)
    rows = db.execute(
        "SELECT s.asset_id, s.payload_json AS asset_json, "
        "f.cve_id AS finding_cve, f.payload_json AS finding_json "
        "FROM scan_assets s JOIN current_findings f "
        "ON f.asset_id = s.asset_id "
        "WHERE s.run_id = ? AND UPPER(f.cve_id) IN (" + primitive_marks + ")",
        (run_id, *sorted(candidate_primaries)),
    ).fetchall()
    for row in rows:
        finding = _payload(row["finding_json"])
        status = finding.get("applicability")
        if status not in AFFECTED_STATUSES:
            continue
        asset_id = str(row["asset_id"])
        primary = str(row["finding_cve"]).upper()
        matched = [
            cve_id
            for cve_id in names
            if cve_id == primary
            or primary in alias_primary.get((asset_id, cve_id), ())
        ]
        if not matched:
            continue
        name = _asset_client(row["asset_json"])
        if not name:
            continue
        for cve_id in matched:
            _merge_impact(impacts, cve_id, name, asset_id, status)


def affected_clients(
    path: str | Path, cve_ids: Iterable[str]
) -> dict[str, tuple[ClientImpact, ...]]:
    """Return the clients affected by each requested CVE.

    The result is keyed by the uppercase CVE identifier. CVEs without an
    affected or needs-review finding are omitted.
    """
    requested = _requested_names(cve_ids)
    if not requested:
        return {}
    names = tuple(requested)

    def read(db: sqlite3.Connection):
        scan = _latest_successful_scan(db)
        if scan is None:
            return {}
        impacts: dict[str, dict[str, object]] = {}
        for start in range(0, len(names), MAX_REQUESTED_CVES):
            _affected_chunk(
                db,
                scan.run_id,
                {name: requested[name] for name in names[start : start + MAX_REQUESTED_CVES]},
                impacts,
            )
        output: dict[str, tuple[ClientImpact, ...]] = {}
        for cve_id, entry in impacts.items():
            values = []
            for key, assets in entry["assets"].items():
                values.append(
                    ClientImpact(
                        _display_name(
                            name
                            for name in entry["names"]
                            if name.casefold() == key
                        ),
                        len(assets),
                        entry["status"][key],
                    )
                )
            values.sort(key=lambda item: (item.name.casefold(), item.name))
            output[cve_id] = tuple(values)
        return output

    return _read(path, read, {})


def client_cves(path: str | Path, name: str) -> tuple[str, ...]:
    """Return the CVEs currently affecting one client, by exact name."""
    wanted = name.strip().casefold()
    if not wanted:
        return ()
    _, clients = client_summaries(path)
    for client in clients:
        if client.name.casefold() == wanted:
            return tuple(item.cve_id for item in client.findings)
    return ()


def format_client_names(
    impacts: Sequence[ClientImpact],
    *,
    language: str = DEFAULT_LANGUAGE,
    limit: int | None = None,
) -> str:
    """Format a comma-separated client list, or an empty string."""
    if not impacts:
        return ""
    catalog = catalog_for(language)
    shown = list(impacts if limit is None else impacts[:limit])
    labels = []
    for impact in shown:
        label = impact.name
        if impact.status == "needs_review":
            label = translate(catalog, "client_review_suffix", name=label)
        labels.append(label)
    text = ", ".join(labels)
    if limit is not None and len(impacts) > limit:
        text += ", " + translate(
            catalog, "affected_clients_more", count=len(impacts) - limit
        )
    return text


def format_affected_clients(
    impacts: Sequence[ClientImpact],
    *,
    language: str = DEFAULT_LANGUAGE,
    limit: int | None = None,
) -> str:
    """Format the localized "Affected clients:" line, or an empty string."""
    names = format_client_names(impacts, language=language, limit=limit)
    if not names:
        return ""
    return translate(catalog_for(language), "affected_clients", clients=names)


def impacts_for(
    clients: Mapping[str, Sequence[ClientImpact]] | None, cve_id: str
) -> tuple[ClientImpact, ...]:
    if not clients:
        return ()
    return tuple(clients.get(str(cve_id).upper(), ()))
