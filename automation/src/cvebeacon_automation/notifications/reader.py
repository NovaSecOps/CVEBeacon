"""Bounded schema-3 read-only material-event projection, without StateStore."""

from contextlib import contextmanager
import math
from pathlib import Path
import sqlite3
import time
import unicodedata
import uuid

from cvebeacon_extensions.contract import decode_json
from ..common import AutomationError, digest, regular


MAX_PAYLOAD = 65536
EVENT_COLUMNS = {"event_id", "run_id", "occurred_at", "asset_id", "cve_id", "event_type", "fingerprint", "payload_json"}


@contextmanager
def core_reader(filename: Path):
    connection = None
    try:
        regular(filename)
        connection = sqlite3.connect(filename.absolute().as_uri() + "?mode=ro", uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_PAYLOAD * 2)
        deadline = time.monotonic() + 5
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        connection.execute("BEGIN")  # Schema checks and event reads share one read-only snapshot.
        version = connection.execute("SELECT version FROM schema_info LIMIT 2").fetchall()
        if len(version) != 1 or type(version[0][0]) is not int or version[0][0] != 3:
            raise AutomationError("unsupported_core_schema")
        tables = connection.execute("SELECT name,type FROM sqlite_master WHERE name IN ('schema_info','events','runs') LIMIT 4").fetchall()
        if {tuple(row) for row in tables} != {("schema_info", "table"), ("events", "table"), ("runs", "table")}:
            raise AutomationError("unsupported_core_schema")
        if {row[1] for row in connection.execute("PRAGMA table_info(events)")} != EVENT_COLUMNS:
            raise AutomationError("unsupported_core_schema")
        yield connection
    except (sqlite3.Error, OSError, ValueError) as exc:
        if isinstance(exc, AutomationError):
            raise
        raise AutomationError("core_events_unreadable") from None
    finally:
        if connection is not None:
            connection.close()


def _label(value, maximum=160):
    if not isinstance(value, str):
        return "unknown"
    # Flatten untrusted controls/line breaks; labels cannot inject new alert fields.
    text = "".join(c if unicodedata.category(c)[0] != "C" and unicodedata.category(c) not in {"Zl", "Zp"} else " " for c in value)
    return text[:maximum] or "unknown"


def render_event(row) -> tuple[str, str]:
    try:
        run = str(uuid.UUID(row["run_id"]))
        if run != row["run_id"] or type(row["event_id"]) is not int or row["event_id"] <= 0:
            raise ValueError()
        if row["event_type"] not in {"new", "changed"} or row["payload"] is None:
            raise ValueError()
        payload = decode_json(row["payload"].encode("utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("asset"), dict) or not isinstance(payload.get("vulnerability"), dict):
            raise ValueError()
        applicability = payload.get("applicability")
        if applicability not in {"affected", "not_affected", "needs_review", "coverage_unknown"}:
            raise ValueError()
        vulnerability, asset = payload["vulnerability"], payload["asset"]
        score = vulnerability.get("cvss_score")
        cvss = str(score) if type(score) in (int, float) and 0 <= score <= 10 and math.isfinite(score) else "unknown"
        def flag(value):
            return "yes" if value is True else "no" if value is False else "unknown"
        text = ("CVEBeacon vulnerability alert\n"
                + "Asset: " + _label(row["asset_id"]) + "\n"
                + "Component: " + _label(asset.get("product")) + " " + _label(asset.get("version"), 80) + "\n"
                + "Advisory: " + _label(row["cve_id"]) + "\n"
                + "Event: " + row["event_type"] + "\nApplicability: " + applicability + "\nCVSS: " + cvss
                + "\nKEV: CISA=" + flag(vulnerability.get("cisa_kev")) + "; EU=" + flag(vulnerability.get("eu_kev")))
        return digest((run + ":" + str(row["event_id"])).encode("ascii")), text
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise AutomationError("invalid_core_event") from None


def event_batch(connection, cursor_id=0, cursor_run="", limit=64):
    if type(cursor_id) is not int or cursor_id < 0 or not 1 <= limit <= 256:
        raise AutomationError("invalid_notification_cursor")
    if cursor_id:
        anchor = connection.execute("SELECT substr(run_id,1,37) FROM events WHERE event_id=?", (cursor_id,)).fetchone()
        if anchor is None or anchor[0] != cursor_run:
            cursor_id = 0  # Replacement/retention: stable run UUID + event ID still deduplicate known rows.
    rows = connection.execute("""SELECT event_id,substr(run_id,1,37) AS run_id,
        substr(asset_id,1,161) AS asset_id,substr(cve_id,1,161) AS cve_id,substr(event_type,1,16) AS event_type,
        CASE WHEN typeof(payload_json)='text' AND length(CAST(payload_json AS BLOB))<=?
             THEN payload_json ELSE NULL END AS payload FROM events WHERE event_id>? ORDER BY event_id LIMIT ?""",
        (MAX_PAYLOAD, cursor_id, limit)).fetchall()
    return rows
