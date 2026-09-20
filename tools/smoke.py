"""Offline source/package acceptance checks from an independent working directory."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from openpyxl import load_workbook


def prepare(directory: Path) -> Path:
    root = Path(__file__).resolve().parents[1]
    shutil.copytree(root / "examples", directory / "examples")
    text = (root / "cvebeacon.example.toml").read_text(encoding="utf-8")
    for source in ("nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss"):
        text = text.replace(f"{source}_enabled = true", f"{source}_enabled = false")
    config = directory / "offline.toml"
    config.write_text(text, encoding="utf-8")
    return config


def smoke(directory: Path, executable: Path | None) -> None:
    config = prepare(directory)
    prefix = [str(executable)] if executable else [sys.executable, "-m", "cvebeacon"]
    env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        env.pop(name, None)
    if executable:
        env["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32") if os.name == "nt" else "/usr/bin:/bin"

    def check(args, expected=0):
        result = subprocess.run(prefix + args, cwd=directory, env=env, capture_output=True, text=True, timeout=120)
        assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
        print("PASS", " ".join(args))
        return result.stdout

    check(["--help"])
    check(["inventory", "inspect", "examples/inventory.xlsx"])
    common = ["--config", str(config)]
    for sample in ("offline.toml", "examples/json.toml", "examples/yaml.toml", "examples/xlsx.toml"):
        assert "valid:" in check(["--config", sample, "inventory", "validate"])
    assert json.loads(check(common + ["doctor"]))["state"] == "ok"
    check(common + ["scan", "--report", "xlsx"], 4)
    check(common + ["history"])
    health = json.loads(check(common + ["source-status"]))
    assert health and all(row["status"] == "disabled" for row in health)
    schedule = check(common + ["schedule", "install", "--every", "4", "--dry-run"])
    assert str(config.resolve()) in schedule, schedule
    if executable:
        assert str(executable) in schedule
    for fmt in ("json", "xlsx"):
        check(common + ["export", "--format", fmt, "--output", f"report.{fmt}"])
    payload = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    assert payload
    book = load_workbook(directory / "report.xlsx", read_only=True)
    assert book["Summary"]["H2"].value == "coverage_unknown"
    book.close()
    with closing(sqlite3.connect(directory / ".cvebeacon/state.db")) as db:
        assert db.execute("SELECT status FROM runs").fetchone()[0] == "failed"
        assert db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=lambda value: Path(value).resolve())
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="cvebeacon-smoke-") as temp:
        smoke(Path(temp), args.executable)
