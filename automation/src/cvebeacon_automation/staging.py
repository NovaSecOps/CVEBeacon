"""Immutable exact snapshot generations and an atomic monotonic source pointer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os
import tempfile

from cvebeacon_extensions.contract import (ExtensionError, decode_json, manifest_path, read_bytes, read_snapshot,
                                            timestamp)
from .common import AutomationError, atomic, digest, directory, identifier, lock, now, read_json, reader_group, write_json


def source_directory(root: Path, source: str) -> Path:
    directory(root)
    return directory(root / identifier(source, "source_id"))


def current_snapshot(root: Path, source: str) -> Path:
    folder = source_directory(root, source)
    current = read_json(folder / "current.json", 65536)
    if not isinstance(current, dict) or set(current) != {"version", "generation", "inventory_hash", "manifest_hash", "generated_at", "observed_at", "accepted_at"} or type(current.get("version")) is not int or current["version"] != 1:
        raise AutomationError("staging_pointer_invalid")
    generation = current.get("generation", "")
    if not isinstance(generation, str) or len(generation) != 64 or any(c not in "0123456789abcdef" for c in generation):
        raise AutomationError("staging_pointer_invalid")
    if not (folder / generation).is_dir():
        raise AutomationError("staging_pointer_invalid")
    directory(folder / generation)
    inventory = folder / generation / "inventory.json"
    raw = read_bytes(inventory)
    side = read_bytes(manifest_path(inventory), 65536)
    if digest(raw) != current.get("inventory_hash") or digest(side) != current.get("manifest_hash") or digest(raw + b"\x00" + side) != generation:
        raise AutomationError("staging_pointer_invalid")
    metadata = decode_json(side)
    if not isinstance(metadata, dict) or metadata.get("source_id") != source or any(current[key] != metadata.get(key) for key in ("generated_at", "observed_at")):
        raise AutomationError("staging_pointer_invalid")
    try:
        accepted = timestamp(current["accepted_at"])
        generated, observed = timestamp(current["generated_at"]), timestamp(current["observed_at"])
        if observed > generated or generated > accepted or accepted > datetime.now(timezone.utc):
            raise ExtensionError("pointer time ordering")
    except ExtensionError:
        raise AutomationError("staging_pointer_invalid") from None
    return inventory


def publish(root: Path, source: str, inventory: bytes, manifest: bytes, *, max_age_seconds=86400, reader_gid=None) -> dict:
    reader_gid = reader_group(reader_gid)
    folder = source_directory(root, source)
    # Never parse by re-serializing: the manifest binds the exact original bytes.
    with tempfile.TemporaryDirectory(prefix=".validate-", dir=folder) as temporary:
        candidate = Path(temporary) / "inventory.json"
        atomic(candidate, inventory)
        atomic(manifest_path(candidate), manifest)
        snapshot = read_snapshot(candidate, max_age_seconds=max_age_seconds, allow_partial=True)
    if snapshot.manifest["source_id"] != source:
        raise AutomationError("source_identity_mismatch")
    if reader_gid is not None:
        # Explicitly grant a configured local reader group access to this source,
        # never to upload credentials or other state. Historical files untouched.
        os.chown(folder, -1, reader_gid)
        folder.chmod(0o2750)
    inventory_hash, manifest_hash = digest(inventory), digest(manifest)
    generation = digest(inventory + b"\x00" + manifest)
    generated = snapshot.manifest["generated_at"]
    observed = snapshot.manifest["observed_at"]
    with lock(folder / "publish.lock"):
        pointer = folder / "current.json"
        exists = pointer.exists() or pointer.is_symlink()
        previous = read_json(pointer, 65536) if exists else None
        if exists:
            current_snapshot(root, source)  # Reject corrupt state; never reset replay protection.
            if previous["generation"] == generation:
                return {"status": "idempotent", "accepted_at": previous["accepted_at"], "generation": generation}
            if timestamp(generated) <= timestamp(previous["generated_at"]) or timestamp(observed) < timestamp(previous["observed_at"]):
                raise AutomationError("snapshot_replay_or_rollback")
        final = folder / generation
        if final.exists():
            directory(final)
            if read_bytes(final / "inventory.json") != inventory or read_bytes(manifest_path(final / "inventory.json"), 65536) != manifest:
                raise AutomationError("staging_generation_conflict")
            if reader_gid is not None and any(item.stat().st_gid != reader_gid or item.stat().st_mode & 0o040 == 0
                    for item in (final, final / "inventory.json", manifest_path(final / "inventory.json"))):
                raise AutomationError("staging_reader_permissions")
        else:
            # Unreferenced interrupted generations are harmless; pointer is commit point.
            with tempfile.TemporaryDirectory(prefix=".generation-", dir=folder) as pending:
                pending = Path(pending)
                if reader_gid is not None:
                    os.chown(pending, -1, reader_gid)
                    pending.chmod(0o2750)
                atomic(pending / "inventory.json", inventory, read_group=reader_gid)
                atomic(manifest_path(pending / "inventory.json"), manifest, read_group=reader_gid)
                os.rename(pending, final)
        state = dict(version=1, generation=generation, inventory_hash=inventory_hash, manifest_hash=manifest_hash,
                     generated_at=generated, observed_at=observed, accepted_at=now())
        write_json(pointer, state, read_group=reader_gid)
    return {"status": "accepted", "accepted_at": state["accepted_at"], "generation": generation}
