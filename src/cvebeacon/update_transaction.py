"""One durable transaction record and a fail-closed startup fence."""
from importlib.metadata import version
from pathlib import Path
import re
import sys

from .errors import CVEBeaconError

JOURNAL = "update-journal.json"
PHASES = {"adopting", "quiescing", "snapshot", "installing", "migrating", "switching", "health", "restoring", "rollback-health", "complete"}


def installation_prefix(venv=None):
    venv = Path(venv or sys.prefix).resolve()
    if venv.name != ".venv":
        return None
    if venv.parent.parent.name == "releases":
        return venv.parent.parent.parent
    return venv.parent


def read_record(prefix):
    from .updater import _json, read_bounded, release_version, UpdateError
    try:
        value = _json(read_bounded(Path(prefix) / JOURNAL, 32768))
    except FileNotFoundError:
        return None
    if (not isinstance(value, dict) or value.get("format") != 1 or value.get("phase") not in PHASES
            or value.get("kind") not in {"apply", "adopt"} or not isinstance(value.get("id"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", value["id"])):
        raise UpdateError("an unrecognized update journal requires administrator recovery")
    for key in ("old", "new"):
        release_version(value.get(key))
    if type(value.get("snapshot_ready")) is not bool:
        raise UpdateError("invalid pending update snapshot state")
    if value["phase"] == "complete" and value.get("result") not in {"updated", "rolled-back", "adopted"}:
        raise UpdateError("invalid completed update result")
    backup = value.get("backup")
    if backup is not None and (not isinstance(backup, str) or not re.fullmatch(r"[0-9]{8}T[0-9]{6}-[0-9a-f]{32}", backup)):
        raise UpdateError("invalid pending update snapshot path")
    if value["snapshot_ready"] and (backup is None or not re.fullmatch(r"[0-9a-f]{64}", value.get("manifest_sha256", ""))):
        raise UpdateError("pending update has no verified snapshot manifest")
    return value


def ensure_ready(command, *, prefix=None, running_version=None):
    """Ordinary writers cannot start across an unfinished schema transition."""
    prefix = Path(prefix) if prefix else installation_prefix()
    if prefix is None:
        return
    try:
        record = read_record(prefix)
        if record is None:
            return
        phase = record["phase"]
        expected = record["old"] if phase == "rollback-health" else record["new"]
        if phase == "complete":
            expected = record["new"] if record.get("result") == "updated" else record["old"]
        permitted = command in {"doctor", "serve"} and phase in {"health", "rollback-health", "complete"}
        permitted = permitted or (command == "migrate" and phase == "migrating")
        if permitted and (running_version or version("cvebeacon")) == expected:
            return
    except (OSError, ValueError, CVEBeaconError):
        raise CVEBeaconError("update recovery is required before starting writers") from None
    raise CVEBeaconError("an unfinished update requires recovery before starting writers")
