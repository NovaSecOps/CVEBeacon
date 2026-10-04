"""Version 1 JSON envelope preserves both exact snapshot byte streams."""

import base64
import binascii
import hashlib
import json
from pathlib import Path
import tempfile

from cvebeacon_extensions.contract import MAX_BYTES, manifest_path, read_bytes, read_snapshot
from ..common import AutomationError, atomic, identifier

MAX_ENVELOPE = 48 * 1024 * 1024


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AutomationError("upload_duplicate_json_key")
        result[key] = value
    return result


def envelope_json(data: bytes, maximum=MAX_ENVELOPE):
    if not isinstance(data, bytes) or len(data) > maximum:
        raise AutomationError("upload_body_limit")
    # Envelope has no nested values; bound depth before invoking JSON decoder.
    quoted, escaped, depth = False, False, 0
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
            if depth > 4:
                raise AutomationError("upload_envelope_depth")
        elif byte in (93, 125):
            depth -= 1
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(AutomationError("upload_invalid_json")))
    except (UnicodeError, ValueError, RecursionError):
        raise AutomationError("upload_invalid_json") from None


def decode_envelope(data: bytes, maximum=MAX_ENVELOPE):
    value = envelope_json(data, maximum)
    if not isinstance(value, dict) or set(value) != {"version", "source_id", "inventory_b64", "manifest_b64"} or type(value["version"]) is not int or value["version"] != 1:
        raise AutomationError("upload_envelope_schema")
    source = identifier(value["source_id"], "source_id")
    streams = []
    for name, limit in (("inventory_b64", MAX_BYTES), ("manifest_b64", 65536)):
        encoded = value[name]
        if not isinstance(encoded, str) or len(encoded) > 4 * ((limit + 2) // 3):
            raise AutomationError("upload_stream_limit")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise AutomationError("upload_invalid_base64") from None
        if len(decoded) > limit or not decoded:
            raise AutomationError("upload_stream_limit")
        streams.append(decoded)
    return source, *streams


def encode_envelope(source: str, inventory: bytes, manifest: bytes):
    identifier(source, "source_id")
    value = dict(version=1, source_id=source, inventory_b64=base64.b64encode(inventory).decode("ascii"),
                 manifest_b64=base64.b64encode(manifest).decode("ascii"))
    result = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(result) > MAX_ENVELOPE:
        raise AutomationError("upload_body_limit")
    return result


def load_pair(filename: Path, max_age_seconds=86400):
    inventory, manifest = read_bytes(filename), read_bytes(manifest_path(filename), 65536)
    # Validate the captured pair, not an earlier read of mutable source files.
    with tempfile.TemporaryDirectory(prefix="cvebeacon-upload-") as scratch:
        candidate = Path(scratch) / "inventory.json"
        atomic(candidate, inventory)
        atomic(manifest_path(candidate), manifest)
        snapshot = read_snapshot(candidate, max_age_seconds=max_age_seconds, allow_partial=True)
    return snapshot.manifest["source_id"], inventory, manifest
