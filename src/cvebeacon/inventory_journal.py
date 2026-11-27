"""Recover an inventory change from its durable account audit decision."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import re

from .errors import ConfigurationError, StateError
from .private_storage import private_directory
from .snapshot import sync_directory
from .web_assets import client_key as web_client_key, replace_bytes
from .web_inventory import decode_json, read_bytes

LOG = logging.getLogger("cvebeacon")

MARKER = ".inventory-pending"
PARTS = {kind: f"{MARKER}-{kind}" for kind in ("current", "profile", "archive", "sync")}
SYNC_STATE_NAME = re.compile(r"[a-f0-9]{64}(?:\.[a-f0-9]{64})?\.web-sync")
TARGETS = {
    "current": re.compile(r"[a-f0-9]{64}\.json"),
    "profile": re.compile(r"[a-f0-9]{64}\.client"),
    "archive": re.compile(r"[a-f0-9]{64}\.[0-9]{8}T[0-9]{12}Z\.json"),
    "sync": SYNC_STATE_NAME,
}


def remove_file(path):
    # Validate the destination even for a deletion.
    try:
        read_bytes(path)
    except FileNotFoundError:
        return
    path.unlink()
    sync_directory(path.parent)


def pending_exists(directory):
    marker = directory / MARKER
    return marker.exists() or marker.is_symlink()


def _sync_target(key, client):
    from .managed_inventory import client_key

    if client_key(client) != key:
        raise ValueError("web allowlist belongs to a different inventory")
    return f"{key}.{web_client_key(client)}.web-sync"


def _validate_sync_payload(data, client):
    state = decode_json(data)
    if not isinstance(state, dict) or state.get("client") != web_client_key(client):
        raise ValueError("sync state belongs to a different web allowlist")


def stage_change(directory, db, users, actor, event, key, detail, changes, *, sync_client=None):
    """Stage all bytes before committing the audit transaction; publish nothing here."""
    if pending_exists(directory):
        raise StateError("A client inventory change is awaiting recovery.")
    action = event + ":" + json.dumps(detail, ensure_ascii=True, separators=(",", ":"))
    username = actor if isinstance(actor, str) else actor.username
    row_id = users._append_audit(
        db, action, username, datetime.now(timezone.utc).isoformat(), actor=username,
    )
    targets = {}
    for kind, (path, data) in changes.items():
        if path.parent != directory or not TARGETS[kind].fullmatch(path.name) or path.name[:64] != key:
            raise StateError("Invalid inventory change target.")
        if kind == "sync":
            if sync_client is None or path.name != _sync_target(key, sync_client) or data is None:
                raise StateError("Invalid web inventory sync target.")
            _validate_sync_payload(data, sync_client)
        if data is not None:
            replace_bytes(directory / PARTS[kind], data)
        targets[kind] = [path.name, data is not None]
    chain = db.execute("SELECT chain FROM cb_user_audit WHERE id=?", (row_id,)).fetchone()["chain"]
    marker = {"row": row_id, "chain": chain, "key": key, "targets": targets}
    if "sync" in targets:
        marker["web_client"] = sync_client
    replace_bytes(directory / MARKER, json.dumps(marker, ensure_ascii=True).encode("ascii"))


def _read_marker(directory):
    try:
        marker = decode_json(read_bytes(directory / MARKER, 16384))
        row, chain, key, targets = (marker[field] for field in ("row", "chain", "key", "targets"))
        if (type(row) is not int or not 0 < row <= 2**63 - 1
                or not re.fullmatch(r"[a-f0-9]{64}", chain) or not re.fullmatch(r"[a-f0-9]{64}", key)
                or not isinstance(targets, dict) or not targets):
            raise ValueError
        for kind, (name, publish) in targets.items():
            if not TARGETS[kind].fullmatch(name) or name[:64] != key or type(publish) is not bool:
                raise ValueError
        web_client = marker.get("web_client")
        if "sync" in targets:
            # A journal from before per-allowlist state has only the inventory key.
            expected = _sync_target(key, web_client) if web_client is not None else f"{key}.web-sync"
            if targets["sync"] != [expected, True]:
                raise ValueError
        elif web_client is not None:
            raise ValueError
        return row, chain, targets, web_client
    except (ConfigurationError, KeyError, ValueError, TypeError, IndexError) as exc:
        raise StateError("A pending client inventory change could not be read.") from exc


def _discard_orphans(parts):
    for part in parts:
        try:
            remove_file(part)
        except (OSError, StateError, ValueError):
            LOG.warning("Skipping an unsafe orphaned inventory staging file.")


def recover(directory: Path, users_path: Path | None):
    """Resolve a pending change against its committed audit row before reading files."""
    if directory.is_symlink():
        return
    parts = [directory / filename for filename in PARTS.values()]
    marked = pending_exists(directory)
    if not marked and not any(part.exists() or part.is_symlink() for part in parts):
        return
    private_directory(directory, owner_only=True)
    if users_path is None or not users_path.is_file():
        if marked:
            raise StateError("The account database is required to recover a client inventory change.")
        return
    from .watch.users import UserStore

    # Serializes with both an in-flight writer and another recovery process.
    with UserStore(users_path).transaction() as db:
        if not pending_exists(directory):
            _discard_orphans(parts)
            return
        row, chain, targets, web_client = _read_marker(directory)
        committed = db.execute("SELECT 1 FROM cb_user_audit WHERE id=? AND chain=?", (row, chain)).fetchone()
        if committed:
            if web_client is not None:
                # Validate before publishing any part of the transaction.
                try:
                    _validate_sync_payload(read_bytes(directory / PARTS["sync"]), web_client)
                except ValueError as exc:
                    raise StateError("A pending web inventory sync change could not be read.") from exc
            # Publish the current file last. Replaying any prefix is harmless.
            for kind in ("profile", "archive", "sync", "current"):
                if kind in targets:
                    name, publish = targets[kind]
                    path = directory / name
                    if publish:
                        replace_bytes(path, read_bytes(directory / PARTS[kind]))
                    else:
                        remove_file(path)
            if "current" in targets:
                from .managed_inventory import prune
                prune(directory / targets["current"][0])
        remove_file(directory / MARKER)
        _discard_orphans(parts)
