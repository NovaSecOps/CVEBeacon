"""Private client profiles and inventories shared by dashboard and scans."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import unicodedata

from .errors import ConfigurationError, InventoryValidationError, StateError, ValidationIssue
from .private_storage import private_directory
from .inventory_journal import pending_exists, recover, sync_directory
from .web_assets import client_key as web_client_key, client_label
from .web_inventory import MAX_BYTES, decode_json, read_bytes, read_contract

LOG = logging.getLogger("cvebeacon")
KEY = re.compile(r"[0-9a-f]{64}")
MANAGED_FILE = re.compile(r"[0-9a-f]{64}(?:\.client|(?:\.[0-9]{8}T[0-9]{12}Z)?\.json)")
VERSION = re.compile(r"[0-9]{8}T[0-9]{12}Z")
HISTORY_LIMIT = 5


class ManagedInventoryCollision(InventoryValidationError):
    """An asset ID belongs to multiple inventory files."""


def normalized_client(value):
    client_label(value)
    return client_label(unicodedata.normalize("NFKC", value).strip())


def client_key(value):
    """Normalize managed names without changing existing web asset filenames."""
    return web_client_key(normalized_client(value))


def _names(directory):
    try:
        if directory.is_symlink():
            LOG.warning("Skipping managed inventory storage because it is a symbolic link.")
            return ()
        return tuple(directory.iterdir())
    except FileNotFoundError:
        return ()
    except NotADirectoryError:
        LOG.warning("Skipping managed inventory storage because the inventory storage is not a directory.")
        return ()


def is_managed_file(path):
    return MANAGED_FILE.fullmatch(path.name) is not None


def inventory_files(directory, *, configured=None):
    return sorted(
        path for path in _names(directory)
        if path != configured and path.suffix == ".json" and KEY.fullmatch(path.stem)
    )


def has_managed_inventory(directory):
    return bool(inventory_files(directory))


def has_managed_storage(directory):
    return pending_exists(directory) or any(is_managed_file(path) for path in _names(directory))


def read_inventory(data, *, client=None):
    assets = read_contract(data)
    label = assets[0].client
    if not label or any(asset.client != label for asset in assets) or (client is not None and label != client):
        raise ValueError("inventory rows must belong to the same client")
    return assets


def append_managed_inventory(assets, directory, *, configured=None, users_path=None, warnings=None, candidate=None):
    merged = list(assets)
    seen = {asset.asset_id.casefold(): asset.client or "Unassigned" for asset in assets}
    recover(directory, users_path)
    paths = inventory_files(directory, configured=configured)
    if paths:
        private_directory(directory, owner_only=True)

    def merge(rows):
        for asset in rows:
            key = asset.asset_id.casefold()
            if key in seen:
                raise ManagedInventoryCollision([ValidationIssue(
                    f"An asset ID is shared by clients {seen[key]!r} and {asset.client!r} in different inventory files. "
                    "Give each asset a unique ID."
                )])
            seen[key] = asset.client
        merged.extend(rows)

    for path in paths:
        if candidate is not None and path == candidate[0]:
            continue
        try:
            rows = read_inventory(read_bytes(path))
            if client_key(rows[0].client) != path.stem:
                raise ValueError("file key does not match the client label")
        except (OSError, ValueError, InventoryValidationError, StateError):
            try:
                label = read_profile(directory, path.stem)["name"]
            except (OSError, ValueError, ConfigurationError, StateError):
                label = None
            subject = f" for {label!r}" if label else " for an unidentified client"
            message = f"Skipping invalid client inventory{subject}. Upload a replacement from the Clients page."
            LOG.warning("%s", message)
            if warnings is not None:
                warnings.append(message)
            continue
        merge(rows)
    if candidate is not None:
        merge(candidate[1])
    return merged


def read_profile(directory: Path, key: str):
    if not KEY.fullmatch(key):
        raise ValueError("invalid client key")
    private_directory(directory, owner_only=True)
    data = decode_json(read_bytes(directory / f"{key}.client", 16384))
    if (not isinstance(data, dict) or set(data) != {"name", "notes", "contact"}
            or not all(isinstance(value, str) for value in data.values())
            or client_key(data["name"]) != key):
        raise ValueError("invalid client profile")
    return {**data, "name": normalized_client(data["name"])}


def profiles(directory, users_path=None):
    recover(directory, users_path)
    paths = [path for path in _names(directory) if path.suffix == ".client" and KEY.fullmatch(path.stem)]
    if not paths:
        return ()
    private_directory(directory, owner_only=True)
    found = []
    for path in sorted(paths):
        try:
            found.append(read_profile(directory, path.stem))
        except (OSError, ValueError, ConfigurationError, StateError):
            LOG.warning("Skipping invalid client profile")
    return tuple(sorted(found, key=lambda item: item["name"].casefold()))


def encode_records(assets):
    data = bytearray(b"[")
    for asset in assets:
        if len(data) > 1:
            data.extend(b",")
        data.extend(json.dumps(asdict(asset), ensure_ascii=True, separators=(",", ":")).encode("ascii"))
        if len(data) + 2 > MAX_BYTES:
            raise ConfigurationError("The saved inventory would be too large. Import fewer rows.")
    data.extend(b"]\n")
    return bytes(data)


def versions(path):
    return sorted(
        (item for item in path.parent.glob(f"{path.stem}.*.json")
         if VERSION.fullmatch(item.name.split(".")[1])),
        reverse=True,
    )


def archive_path(path):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return path.with_name(f"{path.stem}.{stamp}.json")


def prune(path):
    excess = versions(path)[HISTORY_LIMIT:]
    for item in excess:
        try:
            item.unlink(missing_ok=True)
        except OSError:
            LOG.warning("Could not remove an old client inventory version")
    if excess:
        sync_directory(path.parent)
