"""Private client profiles and inventories shared by dashboard and scans."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import re
import unicodedata

from .errors import ConfigurationError, InventoryValidationError, StateError, ValidationIssue
from .private_storage import private_directory
from .inventory_journal import UNASSIGNED_KEY, pending_exists, recover, stage_change, sync_directory
from .web_assets import client_key as web_client_key, client_label
from .web_inventory import MAX_BYTES, decode_json, read_bytes, read_contract

LOG = logging.getLogger("cvebeacon")
KEY = re.compile(r"[0-9a-f]{64}")
MANAGED_FILE = re.compile(
    r"(?:[0-9a-f]{64}(?:\.client|(?:\.[0-9]{8}T[0-9]{12}Z)?\.json)"
    r"|unassigned(?:\.[0-9]{8}T[0-9]{12}Z)?\.json)"
)
VERSION = re.compile(r"[0-9]{8}T[0-9]{12}Z")
HISTORY_LIMIT = 5


class ManagedInventoryCollision(InventoryValidationError):
    """An asset ID belongs to multiple inventory files."""


class InventoryRevisionConflict(ConfigurationError):
    """The inventory changed after the caller prepared its candidate."""


class InventoryPermissionDenied(ConfigurationError):
    """The writer lost inventory permissions before publication."""


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
        if (path != configured and path.suffix == ".json"
            and (KEY.fullmatch(path.stem) or path.name == f"{UNASSIGNED_KEY}.json"))
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


def read_unassigned_inventory(data):
    """Validate the reserved inventory's blank-or-uniform client assignment."""
    assets = read_contract(data)
    labels = {asset.client for asset in assets}
    named = {label for label in labels if label}
    if len(named) > 1 or (named and "" in labels):
        raise ValueError("inventory rows must be blank or belong to the same client")
    if named:
        normalized_client(next(iter(named)))
    return assets


def _read_managed_file(path, data):
    if path.name == f"{UNASSIGNED_KEY}.json":
        return read_unassigned_inventory(data)
    rows = read_inventory(data)
    if client_key(rows[0].client) != path.stem:
        raise ValueError("file key does not match the client label")
    return rows


def append_managed_inventory(assets, directory, *, configured=None, users_path=None, warnings=None, candidate=None):
    merged = list(assets)
    seen = {asset.asset_id.casefold(): asset.client or "No client" for asset in assets}
    recover(directory, users_path)
    paths = inventory_files(directory, configured=configured)
    if paths:
        private_directory(directory, owner_only=True)

    def merge(rows):
        for asset in rows:
            key = asset.asset_id.casefold()
            if key in seen:
                owner = asset.client or "No client"
                raise ManagedInventoryCollision([ValidationIssue(
                    f"An asset ID is shared by clients {seen[key]!r} and {owner!r} in different inventory files. "
                    "Give each asset a unique ID."
                )])
            seen[key] = asset.client or "No client"
        merged.extend(rows)

    for path in paths:
        if candidate is not None and path == candidate[0]:
            continue
        try:
            rows = _read_managed_file(path, read_bytes(path))
        except (OSError, ValueError, InventoryValidationError, StateError):
            if path.name == f"{UNASSIGNED_KEY}.json":
                message = "Skipping invalid no-client inventory. Check the inventory file before scanning."
            else:
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
        candidate_path, candidate_rows = candidate
        if candidate_path.name == f"{UNASSIGNED_KEY}.json":
            candidate_rows = read_unassigned_inventory(encode_records(candidate_rows))
        else:
            candidate_rows = read_inventory(encode_records(candidate_rows))
            if client_key(candidate_rows[0].client) != candidate_path.stem:
                raise ValueError("file key does not match the client label")
        merge(candidate_rows)
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


def encode_profile(profile):
    """Encode the client profile stored beside a managed inventory."""
    return (json.dumps(profile, ensure_ascii=True) + "\n").encode("ascii")


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


def publish_managed_inventory(
    config,
    path,
    assets,
    *,
    expected_revision,
    users,
    proof,
    mode,
    client=None,
    profile=None,
    restore_stamp=None,
    precondition=None,
    after_publish=None,
):
    """Publish a client or no-client inventory through one journal transaction.

    ``client`` selects client-name validation; omitting it selects the reserved
    blank-or-one-label rule. Client profiles are staged only for client targets.
    """
    from .inventory import MAX_CONTRACT_ROWS, load_inventory
    from .locking import OperationLock

    directory = config.inventory_directory
    is_unassigned = path == directory / f"{UNASSIGNED_KEY}.json"
    allowed_modes = {"add", "replace", "restore"} if is_unassigned else {
        "add", "replace", "restore", "remove",
    }
    if mode not in allowed_modes:
        if is_unassigned:
            raise ConfigurationError("Choose Add, Replace or Restore for this inventory.")
        raise ConfigurationError("Choose Add, Replace, Restore or Remove for this inventory.")
    if (path.parent != directory
            or (is_unassigned and (client is not None or profile is not None))
            or (not is_unassigned and (
                path.suffix != ".json" or not KEY.fullmatch(path.stem)
                or client is None or client_key(client) != path.stem
            ))):
        raise StateError("Invalid inventory change target.")
    if restore_stamp is not None and (is_unassigned or mode != "restore"):
        raise ConfigurationError("That saved version cannot be used. Choose another version or upload the file again.")
    if not config.managed_inventory:
        raise ConfigurationError("Managed inventory is disabled.")

    lock = OperationLock(config, "client-inventory")
    if not lock.acquire():
        raise ConfigurationError("A scan or inventory change is in progress. Try again when it finishes.")
    try:
        recover(directory, users.path)
        private_directory(directory, owner_only=True)
        try:
            previous = read_bytes(path)
        except FileNotFoundError:
            previous = None
        revision = hashlib.sha256(previous).hexdigest() if previous is not None else "empty"
        if revision != expected_revision:
            raise InventoryRevisionConflict()
        if precondition is not None and not precondition(previous):
            raise InventoryRevisionConflict()

        if restore_stamp is not None:
            if not VERSION.fullmatch(restore_stamp):
                raise ConfigurationError("That version is no longer available.")
            version = path.with_name(f"{path.stem}.{restore_stamp}.json")
            if version not in versions(path)[:HISTORY_LIMIT]:
                raise ConfigurationError("That version is no longer available.")
            try:
                proposed = read_inventory(read_bytes(version), client=client)
            except (InventoryValidationError, ValueError) as exc:
                raise ConfigurationError(
                    "That saved version cannot be used. Choose another version or upload the file again."
                ) from exc
        else:
            proposed = list(assets or ())

        previous_assets = None
        if mode == "add" and previous is not None:
            try:
                previous_assets = (
                    read_unassigned_inventory(previous) if is_unassigned
                    else read_inventory(previous, client=client)
                )
            except (InventoryValidationError, ValueError) as exc:
                message = (
                    "The current no-client inventory is unreadable. Choose Replace only if you intend to discard it."
                    if is_unassigned else
                    "The current inventory is unreadable. Choose Replace only if you intend to discard it."
                )
                raise ConfigurationError(message) from exc
            except ConfigurationError as exc:
                if not is_unassigned:
                    raise
                raise ConfigurationError(
                    "The current no-client inventory is unreadable. Choose Replace only if you intend to discard it."
                ) from exc
        if mode == "add" and previous_assets is not None:
            if not is_unassigned:
                seen = {asset.asset_id.casefold() for asset in previous_assets}
                if any(asset.asset_id.casefold() in seen for asset in proposed):
                    raise ConfigurationError(
                        "An uploaded asset ID is already in this client's inventory. "
                        "Use unique IDs to add rows, or choose Replace if you intend to remove assets not in this file."
                    )
            proposed = [*previous_assets, *proposed]
        if not proposed and is_unassigned:
            raise ConfigurationError("Save at least one inventory row.")
        if len(proposed) > MAX_CONTRACT_ROWS:
            raise ConfigurationError("This inventory would exceed 100,000 rows. Import fewer rows.")

        data = encode_records(proposed) if proposed else None
        if data is None:
            rows = []
        else:
            rows = read_unassigned_inventory(data) if is_unassigned else read_inventory(data, client=client)
            try:
                load_inventory(
                    config.inventory_for_management(),
                    snapshot_directory=config.database_path.parent / "web-inventory",
                    managed_candidate=(path, rows),
                )
            except ManagedInventoryCollision:
                raise
            except (InventoryValidationError, OSError, ValueError, StateError) as exc:
                raise ConfigurationError(
                    "The other inventories could not be checked. Ask an administrator to check the inventory settings."
                ) from exc

        changes = {"current": (path, data)}
        if not is_unassigned and profile is not None:
            profile_path = path.with_suffix(".client")
            if not profile_path.exists() and not profile_path.is_symlink():
                changes["profile"] = (profile_path, encode_profile(profile))
        if previous is not None:
            try:
                if is_unassigned:
                    read_unassigned_inventory(previous)
                else:
                    read_inventory(previous, client=client)
            except (InventoryValidationError, ValueError, ConfigurationError):
                if not is_unassigned:
                    raise
                pass  # An unreadable current file is replaceable without archiving it.
            else:
                changes["archive"] = (archive_path(path), previous)

        label = rows[0].client if is_unassigned else client
        detail = {"client": label, "row_count": len(rows), "mode": mode}
        sync_directory(directory.parent)
        try:
            with users.transaction() as db:
                try:
                    actor = users.require_permission_in(db, proof, "manage_inventory")
                    users.require_permission_in(db, proof, "view")
                except ConfigurationError as exc:
                    raise InventoryPermissionDenied() from exc
                event = "inventory_saved" if is_unassigned or data is not None else "inventory_removed"
                stage_change(directory, db, users, actor, event, path.stem, detail, changes)
        finally:
            recover(directory, users.path)
        if after_publish is not None:
            after_publish()
        return rows
    finally:
        lock.release()


def publish_unassigned_inventory(config, assets, *, expected_revision, users, proof, mode="replace"):
    """Publish the reserved inventory using the shared managed-write transaction."""
    path = config.inventory_directory / f"{UNASSIGNED_KEY}.json"
    try:
        return publish_managed_inventory(
            config, path, assets, expected_revision=expected_revision, users=users, proof=proof, mode=mode,
        )
    except InventoryRevisionConflict as exc:
        raise ConfigurationError(
            "This inventory changed. Review the current inventory before continuing."
        ) from exc
