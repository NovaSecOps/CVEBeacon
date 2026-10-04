"""Independent, bounded per-part delivery state; prepared text is durable."""

from contextlib import contextmanager
import sqlite3

from ..common import AutomationError, digest, directory, regular
from ..config import input_paths


STATES = ("pending", "sending", "accepted", "retryable", "permanent", "ambiguous")
MAX_ROWS = 100000
MAX_DATABASE = 256 * 1024 * 1024
TABLE_COLUMNS = {
    "deliveries": {"event_key", "channel", "destination", "provider", "purpose", "part", "text", "transaction_id",
                   "replay_scope", "state", "attempts", "next_retry", "updated_at", "error"},
    "destinations": {"channel", "destination", "provider", "cursor_id", "cursor_run", "next_send"},
    "provider_cooldowns": {"provider", "next_send"},
}


def check_paths(config, core_db=None):
    owned = (config.state_dir / "notification-ledger.sqlite3", config.state_dir / "notifications.lock")
    reserved = [*input_paths(config), config.inventory_path,
                config.inventory_path.with_name(config.inventory_path.name + ".manifest.json"), core_db]
    if any(path.absolute() == other.absolute() for path in owned for other in reserved if other is not None):
        raise AutomationError("notification_state_path_collision")


@contextmanager
def ledger(config, *, readonly=False, core_db=None):
    path = config.state_dir / "notification-ledger.sqlite3"
    connection = None
    try:
        check_paths(config, core_db)
        if path.exists() or path.is_symlink():
            regular(path)
            if path.stat().st_size > MAX_DATABASE:
                raise AutomationError("notification_ledger_capacity")
        elif readonly:
            yield None
            return
        directory(config.state_dir)
        connection = sqlite3.connect(path.absolute().as_uri() + ("?mode=ro" if readonly else "?mode=rwc"), uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 65536)
        connection.execute("PRAGMA synchronous=FULL")
        if readonly:
            connection.execute("PRAGMA query_only=ON")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 0 and not readonly:
            existing = connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
            if existing:
                raise AutomationError("unsupported_notification_ledger")
            connection.executescript("""
                CREATE TABLE deliveries (
                    event_key TEXT NOT NULL, channel TEXT NOT NULL, destination TEXT NOT NULL,
                    provider TEXT NOT NULL, purpose TEXT NOT NULL CHECK(purpose IN ('event','operational','test')),
                    part INTEGER NOT NULL, text TEXT NOT NULL,
                    transaction_id TEXT NOT NULL, replay_scope TEXT NOT NULL, state TEXT NOT NULL
                        CHECK(state IN ('pending','sending','accepted','retryable','permanent','ambiguous')),
                    attempts INTEGER NOT NULL DEFAULT 0, next_retry REAL NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL, error TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(event_key,channel,destination,part));
                CREATE INDEX due_deliveries ON deliveries(channel,destination,state,next_retry,updated_at);
                CREATE TABLE destinations (
                    channel TEXT NOT NULL, destination TEXT NOT NULL, provider TEXT NOT NULL,
                    cursor_id INTEGER NOT NULL DEFAULT 0, cursor_run TEXT NOT NULL DEFAULT '',
                    next_send REAL NOT NULL DEFAULT 0, PRIMARY KEY(channel,destination));
                CREATE TABLE provider_cooldowns (provider TEXT PRIMARY KEY, next_send REAL NOT NULL);
                PRAGMA user_version=1;
            """)
        elif version != 1:
            raise AutomationError("unsupported_notification_ledger")
        names = connection.execute("SELECT name,type FROM sqlite_master WHERE name IN ('deliveries','destinations','provider_cooldowns') LIMIT 4").fetchall()
        if {tuple(row) for row in names} != {(name, "table") for name in TABLE_COLUMNS}:
            raise AutomationError("unsupported_notification_ledger")
        for name, columns in TABLE_COLUMNS.items():
            if {row[1] for row in connection.execute("PRAGMA table_info(" + name + ")")} != columns:
                raise AutomationError("unsupported_notification_ledger")
        yield connection
    except (sqlite3.Error, OSError, ValueError) as exc:
        if isinstance(exc, AutomationError):
            raise
        raise AutomationError("notification_ledger_unavailable") from None
    finally:
        if connection is not None:
            connection.close()


def destination(connection, bound):
    with connection:
        connection.execute("""INSERT OR IGNORE INTO destinations(channel,destination,provider,next_send)
            VALUES (?,?,?,COALESCE((SELECT next_send FROM provider_cooldowns WHERE provider=?),0))""",
            (bound.channel.id, bound.destination, bound.channel.provider, bound.channel.provider))
    return connection.execute("SELECT * FROM destinations WHERE channel=? AND destination=?",
                              (bound.channel.id, bound.destination)).fetchone()


def enforce_replay_scope(connection, bound, timestamp):
    if bound.channel.provider != "matrix":
        return
    with connection:
        connection.execute("""UPDATE deliveries SET state='ambiguous',error='matrix_credential_context_changed',updated_at=?
            WHERE channel=? AND destination=? AND attempts>0 AND replay_scope!=?
            AND state IN ('pending','retryable','sending')""",
            (timestamp, bound.channel.id, bound.destination, bound.replay_scope))
        # Parts which have never entered transmission may use the new context.
        connection.execute("""UPDATE deliveries SET replay_scope=? WHERE channel=? AND destination=?
            AND attempts=0 AND state='pending'""", (bound.replay_scope, bound.channel.id, bound.destination))


def prepare(connection, bound, event_key, parts, timestamp, cursor=None, purpose="event"):
    if purpose not in {"event", "operational", "test"}:
        raise AutomationError("invalid_notification_purpose")
    if connection.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] + len(parts) > MAX_ROWS:
        raise AutomationError("notification_ledger_capacity")
    with connection:
        for index, text in enumerate(parts):
            transaction = "cveb-" + digest((event_key + ":" + bound.channel.id + ":" + bound.destination + ":" + str(index)).encode("ascii"))
            connection.execute("""INSERT OR IGNORE INTO deliveries
                (event_key,channel,destination,provider,purpose,part,text,transaction_id,replay_scope,state,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,'pending',?)""",
                (event_key, bound.channel.id, bound.destination, bound.channel.provider, purpose, index, text, transaction,
                 bound.replay_scope, timestamp))
        if cursor:
            connection.execute("UPDATE destinations SET cursor_id=?,cursor_run=? WHERE channel=? AND destination=?",
                               (cursor[0], cursor[1], bound.channel.id, bound.destination))


def recover(connection, timestamp):
    with connection:
        connection.execute("""UPDATE deliveries SET state=CASE WHEN provider='matrix' THEN 'retryable' ELSE 'ambiguous' END,
            error='interrupted_send',updated_at=? WHERE state='sending'""", (timestamp,))


def due(connection, bound, timestamp, event_key=None, purpose=None):
    target = destination(connection, bound)
    if target["next_send"] > timestamp:
        return None
    return connection.execute("""SELECT rowid,* FROM deliveries
        WHERE channel=? AND destination=? AND state IN ('pending','retryable') AND next_retry<=?
        AND (? IS NULL OR event_key=?)
        AND (? IS NULL OR purpose=?)
        AND NOT EXISTS (SELECT 1 FROM deliveries AS older WHERE older.event_key=deliveries.event_key
           AND older.channel=deliveries.channel AND older.destination=deliveries.destination
           AND older.part<deliveries.part AND older.state!='accepted')
        ORDER BY updated_at,rowid LIMIT 1""",
        (bound.channel.id, bound.destination, timestamp, event_key, event_key, purpose, purpose)).fetchone()


def next_due(connection, bound, event_key=None, purpose=None):
    target = destination(connection, bound)
    row = connection.execute("""SELECT MIN(next_retry) FROM deliveries WHERE channel=? AND destination=?
        AND state IN ('pending','retryable') AND (? IS NULL OR event_key=?) AND (? IS NULL OR purpose=?)
        AND NOT EXISTS (SELECT 1 FROM deliveries AS older
           WHERE older.event_key=deliveries.event_key AND older.channel=deliveries.channel
           AND older.destination=deliveries.destination AND older.part<deliveries.part AND older.state!='accepted')""",
        (bound.channel.id, bound.destination, event_key, event_key, purpose, purpose)).fetchone()
    return max(row[0], target["next_send"]) if row[0] is not None else None


def claim(connection, row, timestamp):
    with connection:
        connection.execute("UPDATE deliveries SET state='sending',attempts=attempts+1,updated_at=? WHERE rowid=?",
                           (timestamp, row["rowid"]))


def finish(connection, bound, row, outcome, timestamp, jitter):
    attempts = row["attempts"] + 1
    delay, state, error = outcome.delay, outcome.state, outcome.error
    if state == "retryable":
        delay = max(delay, min(bound.channel.retry_max, bound.channel.retry_base * 2**(attempts - 1)) * (1 + jitter * 0.25))
        if attempts >= bound.channel.max_attempts:
            state, error = "ambiguous" if bound.channel.provider == "matrix" else "permanent", "attempts_exhausted"
    # A rate-limit delay is never down-clamped to the configured backoff cap.
    with connection:
        connection.execute("UPDATE deliveries SET state=?,error=?,next_retry=?,updated_at=? WHERE rowid=?",
                           (state, error, timestamp + delay, timestamp, row["rowid"]))
        connection.execute("UPDATE destinations SET next_send=? WHERE channel=? AND destination=?",
                           (timestamp + max(bound.channel.interval, delay), bound.channel.id, bound.destination))
        if outcome.provider_wide or bound.channel.provider in {"telegram", "slack"}:
            connection.execute("""INSERT INTO provider_cooldowns(provider,next_send) VALUES (?,?)
                ON CONFLICT(provider) DO UPDATE SET next_send=MAX(next_send,excluded.next_send)""",
                (bound.channel.provider, timestamp + max(bound.channel.interval, delay)))
            connection.execute("UPDATE destinations SET next_send=MAX(next_send,?) WHERE provider=?",
                               (timestamp + max(bound.channel.interval, delay), bound.channel.provider))


def summary(connection, channels):
    result = {item.id: {"provider": item.provider, "enabled": item.enabled, "states": dict.fromkeys(STATES, 0)} for item in channels}
    if connection is not None:
        for row in connection.execute("SELECT channel,state,COUNT(*) FROM deliveries GROUP BY channel,state"):
            if row[0] in result and row[1] in STATES:
                result[row[0]]["states"][row[1]] = row[2]
    unhealthy = any(item["enabled"] and any(item["states"][state] for state in ("sending", "retryable", "permanent", "ambiguous"))
                    for item in result.values())
    return {"version": 1, "channels": result, "unhealthy": unhealthy}
