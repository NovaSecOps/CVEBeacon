"""Read saved web inventory using the public exchange contract and core validator."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re

from .config import CANONICAL_FIELDS, OPTIONAL_FIELDS
from .errors import InventoryValidationError, ValidationIssue
from .identity import identity_conflict
from .inventory import validate_records
from .private_storage import private_directory, private_file

LOG = logging.getLogger("cvebeacon")
MAX_BYTES = 32 * 1024 * 1024
MANIFEST_KEYS = {"contract", "collector", "collector_version", "source_id", "generated_at",
                 "observed_at", "sha256", "record_count", "status", "omissions"}


def read_bytes(path: Path, limit: int = MAX_BYTES) -> bytes:
    descriptor = private_file(path, readonly=True)
    with os.fdopen(descriptor, "rb") as handle:
        if os.fstat(handle.fileno()).st_size > limit:
            raise ValueError("file exceeds size limit")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file exceeds size limit")
    return data


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode_json(data: bytes):
    # Bound depth before entering the recursive decoder, including when a caller
    # has raised the process recursion limit. Delimiters in strings do not count.
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise ValueError("JSON nesting exceeds 64 levels")
        elif byte in (93, 125):
            depth -= 1
    def invalid(_):
        raise ValueError("invalid JSON number")
    try:
        return json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique, parse_constant=invalid)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid JSON") from exc


def _label(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        raise ValueError("invalid manifest label")


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError("invalid timestamp")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None or stamp.utcoffset().total_seconds() != 0:
        raise ValueError("timestamp must be UTC")
    return stamp


def read_web_snapshot(path: Path):
    data = read_bytes(path)
    manifest = decode_json(read_bytes(Path(str(path) + ".manifest.json"), 65536))
    if (not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS
            or manifest["contract"] != "cvebeacon.inventory.v1"
            or manifest["collector"] != "web-detect"):
        raise ValueError("invalid web snapshot manifest")
    for field in ("collector", "collector_version", "source_id"):
        _label(manifest[field])
    if manifest["sha256"] != hashlib.sha256(data).hexdigest():
        raise ValueError("snapshot hash does not match manifest")
    if manifest["status"] not in ("success", "partial"):
        raise ValueError("snapshot collection did not succeed")
    omissions = manifest["omissions"]
    if not isinstance(omissions, list) or len(omissions) > 100000:
        raise ValueError("invalid omissions")
    for value in omissions:
        _label(value)
    if bool(omissions) != (manifest["status"] == "partial"):
        raise ValueError("status contradicts omissions")
    generated, observed = (_timestamp(manifest[key]) for key in ("generated_at", "observed_at"))
    if observed > generated or generated > datetime.now(timezone.utc):
        raise ValueError("invalid future timestamp")
    rows = decode_json(data)
    if not isinstance(rows, list) or not 0 < len(rows) <= 100000:
        raise ValueError("snapshot must contain 1–100000 records")
    for row in rows:
        if (not isinstance(row, dict) or set(row) - set(CANONICAL_FIELDS + OPTIONAL_FIELDS)
                or any(not isinstance(value, str) or len(value) > 8192
                       or any(0xD800 <= ord(char) <= 0xDFFF for char in value) for value in row.values())):
            raise ValueError("invalid snapshot row")
    assets = validate_records(rows)
    if len(assets) != len(rows) or any(identity_conflict(asset) for asset in assets):
        raise ValueError("invalid snapshot identity")
    if type(manifest["record_count"]) is not int or manifest["record_count"] != len(assets):
        raise ValueError("snapshot record count mismatch")
    return assets, manifest


def append_snapshots(assets, directory: Path):
    from .errors import StateError
    if not directory.exists() and not directory.is_symlink():
        return assets
    private_directory(directory, owner_only=True)
    seen = {asset.asset_id.casefold() for asset in assets}
    merged = list(assets)
    for path in sorted(directory.glob("*.json")):
        if path.name.endswith((".manifest.json", ".review.json")):
            continue
        try:
            rows, manifest = read_web_snapshot(path)
        except (OSError, ValueError, InventoryValidationError, StateError):
            LOG.warning("Skipping invalid web snapshot %s; check its snapshot and manifest", path.name)
            continue
        for asset in rows:
            if asset.asset_id.casefold() in seen:
                raise InventoryValidationError([ValidationIssue(
                    f"web snapshot asset_id collision: {asset.asset_id}", path.name)])
            seen.add(asset.asset_id.casefold())
        if manifest["status"] == "partial":
            LOG.warning("Using partial web snapshot %s; review its detection results", path.name)
        merged.extend(rows)
    return merged
