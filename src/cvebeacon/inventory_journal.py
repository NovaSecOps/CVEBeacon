"""Recover an inventory change from its durable account audit decision."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

from .errors import StateError
from .private_storage import private_directory
from .web_assets import replace_bytes
from .web_inventory import decode_json, read_bytes

MARKER = ".inventory-pending"
PARTS = {kind: f"{MARKER}-{kind}" for kind in ("current", "profile", "archive")}
TARGETS = {
    "current": re.compile(r"[a-f0-9]{64}\.json"),
    "profile": re.compile(r"[a-f0-9]{64}\.client"),
    "archive": re.compile(r"[a-f0-9]{64}\.[0-9]{8}T[0-9]{12}Z\.json"),
}


def sync_directory(directory):
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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


def stage_change(directory, db, users, actor, event, key, detail, changes):
    """Stage all bytes before committing the audit transaction; publish nothing here."""
    if pending_exists(directory):
        raise StateError("A client inventory change is awaiting recovery.")
    action = event + ":" + json.dumps(detail, ensure_ascii=True, separators=(",", ":"))
    row_id = users._append_audit(
        db, action, actor.username, datetime.now(timezone.utc).isoformat(), actor=actor.username,
    )
    targets = {}
    for kind, (path, data) in changes.items():
        if path.parent != directory or not TARGETS[kind].fullmatch(path.name):
            raise StateError("Invalid inventory change target.")
        if data is not None:
            replace_bytes(directory / PARTS[kind], data)
        targets[kind] = [path.name, data is not None]
    chain = db.execute("SELECT chain FROM cb_user_audit WHERE id=?", (row_id,)).fetchone()["chain"]
    marker = {"row": row_id, "chain": chain, "key": key, "targets": targets}
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
        return row, chain, targets
    except (KeyError, ValueError, TypeError, IndexError) as exc:
        raise StateError("A pending client inventory change could not be read.") from exc


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
            for part in parts:
                remove_file(part)
            return
        row, chain, targets = _read_marker(directory)
        committed = db.execute("SELECT 1 FROM cb_user_audit WHERE id=? AND chain=?", (row, chain)).fetchone()
        if committed:
            # Publish the current file last. Replaying any prefix is harmless.
            for kind in ("profile", "archive", "current"):
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
        for part in parts:
            remove_file(part)
