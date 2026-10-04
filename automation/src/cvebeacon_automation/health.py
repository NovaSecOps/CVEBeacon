"""Operational state contains categories and timestamps, never vulnerability truth."""

from pathlib import Path

from .common import AutomationError, identifier, read_json, write_json


def status(state_dir: Path) -> dict:
    filename = state_dir / "health.json"
    if not filename.exists():
        return {"version": 1, "status": "never_run"}
    value = read_json(filename)
    if (not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1
            or value.get("status") not in {"never_run", "running", "operational", "coverage_warning", "degraded", "failed", "skipped_locked", "interrupted"}
            or type(value.get("consecutive_failures", 0)) is not int
            or not 0 <= value.get("consecutive_failures", 0) <= 10**9):
        raise AutomationError("invalid_automation_health")
    sources = value.get("sources", {})
    if not isinstance(sources, dict) or len(sources) > 128:
        raise AutomationError("invalid_automation_health")
    for name, entry in sources.items():
        identifier(name)
        if not isinstance(entry, dict):
            raise AutomationError("invalid_automation_health")
    return value


def save(state_dir: Path, value: dict):
    write_json(state_dir / "health.json", value)
