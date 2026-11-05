"""Client assignment and read-only correlation with inventory findings.

Inventory assets may carry an optional ``client`` label. A watch CVE affects a
client when the latest successful inventory scan recorded an ``affected`` or
``needs_review`` finding for that CVE on one of the client's assets.

Correlation reads the run-scoped snapshot written by ``StateStore.record_scan``
(``scan_asset_clients`` and ``scan_findings``), never the mutable
``current_findings`` cache. The newest run with ``status='completed'`` is the
only scan considered. Client names stay local; they are never sent to public
sources.
"""

from __future__ import annotations

import html
import re
import sqlite3
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from .watch.catalog import DEFAULT_LANGUAGE, catalog_for, translate

MAX_REQUESTED_CVES = 100
MAX_IMPACT_CLIENTS = 100
MAX_IMPACT_ROWS = MAX_REQUESTED_CVES * MAX_IMPACT_CLIENTS
MAX_SUMMARY_CLIENTS = 1000
MAX_CLIENT_FINDINGS = 100
MAX_CLIENT_CVES = 100_000
AFFECTED_STATUSES = ("affected", "needs_review")
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~])")


@dataclass(frozen=True, slots=True)
class ClientImpact:
    """One client affected by a CVE, with the number of matching assets."""

    name: str
    assets: int
    status: str


@dataclass(frozen=True, slots=True)
class ClientImpacts:
    """Bounded client impacts for one CVE and the count left out."""

    clients: tuple[ClientImpact, ...] = ()
    omitted: int = 0

    def __bool__(self) -> bool:
        return bool(self.clients)

    def __iter__(self):
        return iter(self.clients)

    def __len__(self) -> int:
        return len(self.clients)

    def __getitem__(self, index):
        return self.clients[index]


@dataclass(frozen=True, slots=True)
class ClientFinding:
    cve_id: str
    status: str
    is_cve: bool = True


@dataclass(frozen=True, slots=True)
class ClientSummary:
    name: str
    assets: int
    findings: tuple[ClientFinding, ...]
    omitted_findings: int = 0


@dataclass(frozen=True, slots=True)
class ScanInfo:
    run_id: str
    completed_at: str


def _connect(path: str | Path) -> sqlite3.Connection | None:
    source = Path(path)
    try:
        if not source.is_file():
            return None
        # immutable=1 avoids inventing -wal/-shm files next to a quiescent
        # database. When a writer has left a WAL, read through it normally.
        params = "mode=ro"
        if not any(
            source.with_name(source.name + suffix).exists()
            for suffix in ("-wal", "-shm")
        ):
            params += "&immutable=1"
        uri = source.resolve().as_uri() + "?" + params
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
    except (sqlite3.Error, OSError, TypeError, ValueError, KeyError):
        return default


def _fetch(cursor: sqlite3.Cursor, limit: int) -> list[sqlite3.Row]:
    return cursor.fetchmany(limit + 1)


def _latest_successful_scan(db: sqlite3.Connection) -> ScanInfo | None:
    row = db.execute(
        "SELECT run_id,completed_at FROM runs WHERE status='completed' "
        "ORDER BY completed_at DESC, rowid DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    return ScanInfo(str(row["run_id"]), str(row["completed_at"]))


def _display_name(names: Iterable[str]) -> str:
    values = set(names)
    return min(values, key=lambda item: (item.casefold(), item)) if values else ""


def latest_successful_scan(path: str | Path) -> ScanInfo | None:
    """Return the newest completed inventory run, if the state database exists."""
    return _read(path, _latest_successful_scan, None)


def _requested_names(cve_ids: Iterable[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in cve_ids:
        text = str(value).strip().upper()
        if text:
            output.setdefault(text, text)
    return output


def _impact_rows(
    db: sqlite3.Connection, run_id: str, names: Sequence[str]
) -> list[sqlite3.Row]:
    marks = ",".join("?" for _ in names)
    cursor = db.execute(
        "SELECT identifier, client, assets, rank, total, rn FROM ("
        " SELECT sf.identifier AS identifier, sac.client_key AS client_key,"
        " MIN(sac.client) AS client,"
        " COUNT(DISTINCT sf.asset_id) AS assets,"
        " MIN(CASE sf.applicability WHEN 'affected' THEN 1 ELSE 2 END) AS rank,"
        " COUNT(*) OVER (PARTITION BY sf.identifier) AS total,"
        " ROW_NUMBER() OVER ("
        "PARTITION BY sf.identifier ORDER BY sac.client_key"
        ") AS rn"
        " FROM scan_findings sf JOIN scan_asset_clients sac"
        " ON sac.run_id = sf.run_id AND sac.asset_id = sf.asset_id"
        " WHERE sf.run_id = ? AND sac.client_key <> ''"
        " AND sf.applicability IN ('affected','needs_review')"
        " AND sf.identifier IN (" + marks + ")"
        " GROUP BY sf.identifier, sac.client_key"
        ") WHERE rn <= ? ORDER BY identifier, rn",
        (run_id, *names, MAX_IMPACT_CLIENTS),
    )
    return _fetch(cursor, MAX_IMPACT_ROWS)


def _affected_from_run(
    db: sqlite3.Connection, run_id: str, requested: Mapping[str, str]
) -> dict[str, ClientImpacts]:
    names = tuple(requested)
    collected: dict[str, dict[str, object]] = {}
    totals: dict[str, int] = {}
    for start in range(0, len(names), MAX_REQUESTED_CVES):
        chunk = names[start : start + MAX_REQUESTED_CVES]
        for row in _impact_rows(db, run_id, chunk):
            cve_id = str(row["identifier"])
            key = str(row["client"]).casefold()
            entry = collected.setdefault(
                cve_id, {"names": set(), "assets": defaultdict(int), "status": {}}
            )
            entry["names"].add(str(row["client"]))
            entry["assets"][key] = int(row["assets"])
            previous = entry["status"].get(key)
            status = "affected" if int(row["rank"]) == 1 else "needs_review"
            if previous != "affected":
                entry["status"][key] = status
            totals[cve_id] = int(row["total"])
    output: dict[str, ClientImpacts] = {}
    for cve_id, entry in collected.items():
        values = [
            ClientImpact(
                _display_name(
                    name for name in entry["names"] if name.casefold() == key
                ),
                assets,
                entry["status"][key],
            )
            for key, assets in entry["assets"].items()
        ]
        values.sort(key=lambda item: (item.name.casefold(), item.name))
        output[cve_id] = ClientImpacts(
            tuple(values), max(0, totals.get(cve_id, len(values)) - len(values))
        )
    return output


def affected_clients(
    path: str | Path, cve_ids: Iterable[str]
) -> dict[str, ClientImpacts]:
    """Return the clients affected by each requested CVE in the latest scan.

    Identifiers are matched case-insensitively because the snapshot stores them
    upper-cased, including CVE aliases of package advisories.
    """
    requested = _requested_names(cve_ids)
    if not requested:
        return {}

    def read(db: sqlite3.Connection):
        scan = _latest_successful_scan(db)
        if scan is None:
            return {}
        return _affected_from_run(db, scan.run_id, requested)

    return _read(path, read, {})


def affected_clients_on_connection(
    db: sqlite3.Connection, cve_ids: Iterable[str]
) -> dict[str, ClientImpacts]:
    """Correlate through an existing read-only connection (Automation reader)."""
    requested = _requested_names(cve_ids)
    if not requested:
        return {}
    try:
        scan = _latest_successful_scan(db)
        if scan is None:
            return {}
        return _affected_from_run(db, scan.run_id, requested)
    except (sqlite3.Error, OSError, TypeError, ValueError, KeyError):
        return {}


def _client_page_rows(
    db: sqlite3.Connection, run_id: str, names: Sequence[str], limit: int
) -> list[sqlite3.Row]:
    marks = ",".join("?" for _ in names)
    cursor = db.execute(
        "WITH grouped AS ("
        " SELECT sac.client_key AS client_key, MIN(sac.client) AS client,"
        " sf.advisory_id AS advisory_id,"
        " MIN(CASE WHEN sf.identifier LIKE 'CVE-%' THEN sf.identifier END) AS cve,"
        " COUNT(DISTINCT sf.asset_id) AS assets,"
        " MIN(CASE sf.applicability WHEN 'affected' THEN 1 ELSE 2 END) AS rank"
        " FROM scan_findings sf JOIN scan_asset_clients sac"
        " ON sac.run_id = sf.run_id AND sac.asset_id = sf.asset_id"
        " WHERE sf.run_id = ? AND sf.applicability IN ('affected','needs_review')"
        " AND sac.client_key IN (" + marks + ")"
        " GROUP BY sac.client_key, sf.advisory_id"
        ")"
        " SELECT client_key, client, COALESCE(cve, advisory_id) AS display_id,"
        " assets, rank, total, rn FROM ("
        " SELECT grouped.*, COUNT(*) OVER (PARTITION BY client_key) AS total,"
        " ROW_NUMBER() OVER ("
        "PARTITION BY client_key ORDER BY COALESCE(cve, advisory_id)"
        ") AS rn FROM grouped"
        ") WHERE rn <= ? ORDER BY client_key, rn",
        (run_id, *names, MAX_CLIENT_FINDINGS),
    )
    return _fetch(cursor, len(names) * MAX_CLIENT_FINDINGS)


def client_page(
    path: str | Path, *, limit: int = 50, offset: int = 0
) -> tuple[ScanInfo | None, tuple[ClientSummary, ...], int]:
    """Return one bounded page of clients with counts and current findings."""
    if limit < 1 or limit > 1000:
        raise ValueError("client page limit must be from 1 through 1000")
    if offset < 0:
        raise ValueError("client page offset must not be negative")

    def read(db: sqlite3.Connection):
        scan = _latest_successful_scan(db)
        if scan is None:
            return None, (), 0
        total = int(
            db.execute(
                "SELECT COUNT(DISTINCT client_key) FROM scan_asset_clients "
                "WHERE run_id=? AND client_key<>''",
                (scan.run_id,),
            ).fetchone()[0]
        )
        rows = db.execute(
            "SELECT client_key, MIN(client) AS client, COUNT(*) AS assets "
            "FROM scan_asset_clients WHERE run_id=? AND client_key<>'' "
            "GROUP BY client_key ORDER BY client_key LIMIT ? OFFSET ?",
            (scan.run_id, limit, offset),
        ).fetchall()
        keys = [str(row["client_key"]) for row in rows]
        findings: dict[str, list[sqlite3.Row]] = defaultdict(list)
        totals: dict[str, int] = {}
        if keys:
            for row in _client_page_rows(db, scan.run_id, keys, limit):
                findings[str(row["client_key"])].append(row)
                totals[str(row["client_key"])] = int(row["total"])
        clients = []
        for row in rows:
            key = str(row["client_key"])
            name = str(row["client"])
            values = findings.get(key, [])
            items = tuple(
                ClientFinding(
                    str(item["display_id"]),
                    "affected" if int(item["rank"]) == 1 else "needs_review",
                    str(item["display_id"]).startswith("CVE-"),
                )
                for item in values
            )
            clients.append(
                ClientSummary(
                    name,
                    int(row["assets"]),
                    items,
                    max(0, totals.get(key, len(items)) - len(items)),
                )
            )
        return scan, tuple(clients), total

    return _read(path, read, (None, (), 0))


def client_summaries(
    path: str | Path,
) -> tuple[ScanInfo | None, tuple[ClientSummary, ...]]:
    """Return up to the first bounded page of client summaries."""
    scan, clients, _ = client_page(path, limit=MAX_SUMMARY_CLIENTS)
    return scan, clients


def client_names(path: str | Path) -> tuple[str, ...]:
    """Return distinct client labels from the latest successful scan."""
    def read(db: sqlite3.Connection):
        scan = _latest_successful_scan(db)
        if scan is None:
            return ()
        rows = db.execute(
            "SELECT MIN(client) AS client FROM scan_asset_clients "
            "WHERE run_id=? AND client_key<>'' GROUP BY client_key "
            "ORDER BY client_key LIMIT ?",
            (scan.run_id, MAX_SUMMARY_CLIENTS),
        ).fetchall()
        return tuple(str(row["client"]) for row in rows)

    return _read(path, read, ())


def client_cves(path: str | Path, name: str) -> tuple[str, ...]:
    """Return the CVE aliases currently affecting one client, by exact name."""
    wanted = name.strip().casefold()
    if not wanted:
        return ()

    def read(db: sqlite3.Connection):
        scan = _latest_successful_scan(db)
        if scan is None:
            return ()
        cursor = db.execute(
            "SELECT DISTINCT sf.identifier FROM scan_findings sf "
            "JOIN scan_asset_clients sac "
            "ON sac.run_id = sf.run_id AND sac.asset_id = sf.asset_id "
            "WHERE sf.run_id=? AND sac.client_key=? "
            "AND sf.applicability IN ('affected','needs_review') "
            "AND sf.identifier LIKE 'CVE-%' ORDER BY sf.identifier LIMIT ?",
            (scan.run_id, wanted, MAX_CLIENT_CVES + 1),
        )
        rows = cursor.fetchmany(MAX_CLIENT_CVES + 1)
        return tuple(str(row["identifier"]) for row in rows[:MAX_CLIENT_CVES])

    return _read(path, read, ())


def _impact_parts(value) -> tuple[tuple[ClientImpact, ...], int]:
    if isinstance(value, ClientImpacts):
        return value.clients, value.omitted
    return tuple(value or ()), 0


def markdown_escape_client(value: str) -> str:
    """Render a client name as literal Markdown text, including raw HTML."""
    escaped = html.escape(value, quote=True)
    return _MARKDOWN_SPECIAL.sub(r"\\\1", escaped)


def format_client_names(
    impacts,
    *,
    language: str = DEFAULT_LANGUAGE,
    limit: int | None = None,
    escape: Callable[[str], str] | None = None,
) -> str:
    """Format a comma-separated client list, or an empty string."""
    clients, omitted = _impact_parts(impacts)
    if not clients:
        return ""
    catalog = catalog_for(language)
    shown = list(clients if limit is None else clients[:limit])
    labels = []
    for impact in shown:
        label = impact.name
        if impact.status == "needs_review":
            label = translate(catalog, "client_review_suffix", name=label)
        labels.append(escape(label) if escape is not None else label)
    text = ", ".join(labels)
    more = omitted + (len(clients) - len(shown) if limit is not None else 0)
    if more:
        text += ", " + translate(catalog, "affected_clients_more", count=more)
    return text


def format_affected_clients(
    impacts,
    *,
    language: str = DEFAULT_LANGUAGE,
    limit: int | None = None,
    escape: Callable[[str], str] | None = None,
) -> str:
    """Format the localized "Affected clients:" line, or an empty string."""
    names = format_client_names(
        impacts, language=language, limit=limit, escape=escape
    )
    if not names:
        return ""
    return translate(catalog_for(language), "affected_clients", clients=names)


def impacts_for(
    clients: Mapping[str, ClientImpacts | Sequence[ClientImpact]] | None,
    cve_id: str,
) -> ClientImpacts:
    if not clients:
        return ClientImpacts()
    value = clients.get(str(cve_id).strip().upper())
    if isinstance(value, ClientImpacts):
        return value
    return ClientImpacts(tuple(value or ()))
