"""Bounded inventory exchange and hash-bound, fail-closed snapshot pairs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from cvebeacon.config import CANONICAL_FIELDS, OPTIONAL_FIELDS
from cvebeacon.inventory import validate_records
from cvebeacon.identity import identity_conflict

from . import __version__

CONTRACT = "cvebeacon.inventory.v1"
FIELDS = CANONICAL_FIELDS + OPTIONAL_FIELDS
MAX_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_TEXT = 8192


class ExtensionError(ValueError):
    """Invalid or incomplete extension input; no successful snapshot published."""


def label(value: str, name: str = "source_id") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        raise ExtensionError(f"invalid {name}; use 1–128 ASCII letters, digits, '.', '_', ':', '-'")
    return value


def json_bytes(value) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    except (UnicodeError, ValueError) as exc:
        raise ExtensionError("output contains invalid Unicode or JSON values") from exc


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExtensionError("duplicate JSON object key")
        result[key] = value
    return result


def decode_json(data: bytes):
    if len(data) > MAX_BYTES:
        raise ExtensionError("JSON exceeds size limit")
    # Bound structural depth before invoking CPython's recursive JSON decoder.
    # Do not depend on the process recursion limit (test runners may raise it).
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
                raise ExtensionError("JSON nesting exceeds 64 levels")
        elif byte in (93, 125):
            depth -= 1
    try:
        return json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ExtensionError("non-finite JSON number")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ExtensionError("invalid or excessively nested JSON") from exc


def _regular(path: Path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ExtensionError("snapshot inputs must be regular files, not links or reparse points")


def read_bytes(path: Path, limit: int = MAX_BYTES) -> bytes:
    _regular(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ExtensionError("input is not a bounded regular file")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ExtensionError("input exceeds size limit")
    return data


def canonical_records(records: list[dict]) -> list[dict[str, str]]:
    if not isinstance(records, list) or not 0 < len(records) <= MAX_RECORDS:
        raise ExtensionError("inventory must contain 1–100000 records")
    for row in records:
        if not isinstance(row, dict) or set(row) - set(FIELDS):
            raise ExtensionError("inventory record contains unknown fields")
        if any(not isinstance(value, str) or len(value) > MAX_TEXT or any(0xD800 <= ord(c) <= 0xDFFF for c in value) for value in row.values()):
            raise ExtensionError("inventory values must be bounded text")
    assets = validate_records(records)
    if len(assets) != len(records):
        raise ExtensionError("inventory record was empty; no exchange records may be discarded")
    if any(identity_conflict(asset) for asset in assets):
        raise ExtensionError("conflicting strong identity systems require separate review")
    result = [asdict(asset) for asset in assets]
    if any(len(value) > MAX_TEXT for row in result for value in row.values()):
        raise ExtensionError("normalized inventory value exceeds text limit")
    return sorted(result, key=lambda row: (row["asset_id"].casefold(), row["asset_id"]))


def timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
            raise ValueError()
        return result
    except (ValueError, TypeError, AttributeError) as exc:
        raise ExtensionError("timestamp must be an ISO 8601 UTC value") from exc


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def manifest_path(path: Path) -> Path:
    return path.with_name(path.name + ".manifest.json")


def _atomic(path: Path, data: bytes):
    if path.exists() or path.is_symlink():
        _regular(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".cvebeacon-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_snapshot(path: Path, records: list[dict], *, source_id: str, collector: str,
                   observed_at: str | None = None, omissions: list[str] | None = None) -> dict:
    """Publish inventory then manifest; interrupted pairs fail hash verification.

    Parent directory must already exist and be controlled by the administrator.
    A per-output exclusive lock prevents concurrent cooperating writers.
    """
    path = Path(path)
    label(source_id)
    label(collector, "collector")
    rows = canonical_records(records)
    data = json_bytes(rows)
    if len(data) > MAX_BYTES:
        raise ExtensionError("serialized snapshot exceeds size limit")
    now = utc_now()
    observed = timestamp(observed_at) if observed_at else now
    if observed > now:
        raise ExtensionError("observation time is in the future")
    missing = sorted(set(omissions or []))
    for value in missing:
        label(value, "omission")
    manifest = dict(contract=CONTRACT, collector=collector, collector_version=__version__,
                    source_id=source_id, generated_at=now.isoformat(), observed_at=observed.isoformat(),
                    sha256=hashlib.sha256(data).hexdigest(), record_count=len(rows),
                    status="partial" if missing else "success", omissions=missing)
    metadata = json_bytes(manifest)
    if len(metadata) > 65536:
        raise ExtensionError("manifest exceeds size limit")
    lock = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ExtensionError("output is locked; investigate an interrupted or concurrent writer") from exc
    try:
        os.close(descriptor)
        # Preflight both destinations before replacing either.
        for destination in (path, manifest_path(path)):
            if destination.exists() or destination.is_symlink():
                _regular(destination)
        _atomic(path, data)
        _atomic(manifest_path(path), metadata)
    finally:
        os.unlink(lock)
    return manifest


@dataclass(frozen=True)
class Snapshot:
    records: list[dict[str, str]]
    manifest: dict


def read_snapshot(path: Path, *, max_age_seconds: int = 86400, allow_partial: bool = False,
                  now: datetime | None = None) -> Snapshot:
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds <= 0:
        raise ExtensionError("maximum age must be a positive number of seconds")
    data = read_bytes(Path(path))
    manifest = decode_json(read_bytes(manifest_path(Path(path)), 65536))
    keys = {"contract", "collector", "collector_version", "source_id", "generated_at", "observed_at",
            "sha256", "record_count", "status", "omissions"}
    if not isinstance(manifest, dict) or set(manifest) != keys or manifest["contract"] != CONTRACT:
        raise ExtensionError("unsupported or malformed snapshot manifest")
    for name in ("collector", "collector_version", "source_id"):
        label(manifest[name], name)
    if manifest["sha256"] != hashlib.sha256(data).hexdigest():
        raise ExtensionError("snapshot hash does not match manifest")
    if not isinstance(manifest["status"], str) or manifest["status"] not in {"success", "partial"}:
        raise ExtensionError("snapshot collection did not succeed")
    omissions = manifest["omissions"]
    if not isinstance(omissions, list) or len(omissions) > MAX_RECORDS:
        raise ExtensionError("invalid omissions")
    for value in omissions:
        label(value, "omission")
    if bool(omissions) != (manifest["status"] == "partial"):
        raise ExtensionError("snapshot status contradicts omissions")
    if omissions and not allow_partial:
        raise ExtensionError("partial snapshot requires explicit opt-in")
    generated, observed = timestamp(manifest["generated_at"]), timestamp(manifest["observed_at"])
    current = now or utc_now()
    if observed > generated or generated > current or (current - observed).total_seconds() > max_age_seconds:
        raise ExtensionError("snapshot is stale or has invalid future timestamps")
    rows = canonical_records(decode_json(data))
    if type(manifest["record_count"]) is not int or manifest["record_count"] != len(rows):
        raise ExtensionError("manifest record count does not match inventory")
    return Snapshot(rows, manifest)
