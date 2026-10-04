"""Operational state contains categories and timestamps, never vulnerability truth."""

from pathlib import Path

from .common import read_json, write_json


def status(state_dir: Path) -> dict:
    filename = state_dir / "health.json"
    if not filename.exists():
        return {"version": 1, "status": "never_run"}
    return read_json(filename)


def save(state_dir: Path, value: dict):
    write_json(state_dir / "health.json", value)
