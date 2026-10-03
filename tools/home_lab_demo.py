"""Offline, synthetic three-host lifecycle using the real inventory and core APIs.

Run after installing the core and companion. Never calls a live host collector,
reads a registry/package database, fetches vulnerability data, or sends alerts.
The destination must not already exist; previous demonstrations are preserved.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, closing
from datetime import timedelta
import json
from pathlib import Path
import socket
import sqlite3
from unittest.mock import patch

from cvebeacon.config import AppConfig, InventoryConfig, SourceConfig
from cvebeacon.engine import QueryEngine
from cvebeacon.inventory import load_inventory
from cvebeacon.models import Applicability
from cvebeacon.reporting import write_json, write_xlsx
from cvebeacon.state import StateStore
from cvebeacon_extensions.contract import (
    ExtensionError, json_bytes, manifest_path, read_snapshot, utc_now, write_snapshot,
)
from cvebeacon_extensions.hosts import linux_inventory, publish_host, windows_inventory
from cvebeacon_extensions.merge import merge_snapshots


SOURCES = ("linux-a", "linux-b", "windows-a")
DEBIAN_RELEASE = 'ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID="13"\n'
FEDORA_RELEASE = 'ID=fedora\nNAME="Fedora Linux"\nVERSION_ID="43"\n'


def _require(condition, message):
    if not condition:
        raise RuntimeError("demonstration verification failed: " + message)


def _blocked(*args, **kwargs):
    raise RuntimeError("the synthetic home-lab demo must not access the network")


class _OfflineConfig(AppConfig):
    def secret(self, env_name, *, required=False):
        # QueryEngine requests the optional NVD key even with NVD disabled.
        # This offline demonstration never consults credential environment values.
        return None


class _OfflineTransport:
    def request_json(self, *args, **kwargs):
        return _blocked()


def _observations(changed=False):
    """Supply fabricated adapter inputs, never invoke collect_linux/windows."""
    packages = (
        "installed\tdemo-upgrade\t" + ("2.0-1" if changed else "1.0-1") + "\tamd64\n"
        "installed\tdemo-unchanged\t1.0-1\tamd64\n"
        + ("installed\tdemo-added\t1.0-1\tall\n" if changed else
           "installed\tdemo-remove\t1.0-1\tall\n")
    )
    linux_a = linux_inventory(DEBIAN_RELEASE, packages, backend="dpkg", source_id="linux-a",
                              package_namespace="debian")
    linux_b = linux_inventory(
        FEDORA_RELEASE, "demo-common\t1.0\t1.fc43\tx86_64\t0\n"
        "demo-agent\t3.0\t1.fc43\tx86_64\t0\n",
        backend="rpm", source_id="linux-b", package_namespace="fedora",
    )
    windows_a = windows_inventory(
        {"product": "Windows Example", "version": "12345.7"},
        [{"name": "Example Editor", "vendor": "Example Vendor", "version": "1.0",
          "scope": "machine", "view": "64"},
         {"name": "Example Agent", "vendor": "Example Vendor", "version": "3.0",
          "scope": "machine", "view": "64"}],
        source_id="windows-a",
    )
    return dict(zip(SOURCES, (linux_a, linux_b, windows_a)))


def _publish(directory, observations):
    directory.mkdir()
    paths = []
    for source, (rows, reviews) in observations.items():
        _require(not reviews, "synthetic inputs unexpectedly require review")
        path = directory / f"{source}.json"
        publish_host(path, rows, reviews, source_id=source,
                     collector="synthetic-windows" if source == "windows-a" else "synthetic-linux")
        _require(read_snapshot(path).records == rows, "collector snapshot round trip")
        paths.append(path)
    merged = directory / "inventory.json"
    merge_snapshots(paths, merged, source_id="central", expected_sources=list(SOURCES))
    rows = read_snapshot(merged).records
    _require(len(load_inventory(InventoryConfig(merged))) == len(rows), "core file validation")
    return paths, merged, rows


def _pair(path):
    return path.read_bytes(), manifest_path(path).read_bytes()


def _rejected(action, reason):
    try:
        action()
    except ExtensionError:
        return
    raise RuntimeError("demonstration verification failed: " + reason)


def _scan(root, inventory, phase):
    config = _OfflineConfig(
        config_path=root / "unused-demo-config.toml", inventory=InventoryConfig(inventory),
        database_path=root / "state" / "demo.db", output_dir=root / "reports",
        sources=SourceConfig(osv_enabled=False, nvd_enabled=False, cve_enabled=False,
                             euvd_enabled=False, cisa_kev_enabled=False,
                             eu_kev_enabled=False, epss_enabled=False),
    )
    assets = load_inventory(config.inventory)
    # Reopen core state for every round, exercising persistence across instances.
    store = StateStore(config.database_path)
    attempt = store.start_scan()
    with QueryEngine(config, http=_OfflineTransport()) as engine:
        results = engine.scan(assets, known_findings=store.latest_findings())
    _require(all(result.coverage == Applicability.COVERAGE_UNKNOWN for result in results),
             "offline execution must retain unknown coverage")
    _require(not any(result.findings for result in results), "offline demonstration invented findings")
    run_id, events = store.record_scan(results, channels=(), attempt_id=attempt)
    store.finish_scan(attempt, successful=False)  # Same incomplete-coverage meaning as the CLI.
    _require(not events, "inventory changes must not fabricate vulnerability events")
    write_json(results, config.output_dir / f"{phase}.json")
    if phase == "repeat":
        write_xlsx(results, config.output_dir / "repeat.xlsx")
    return run_id, {"phase": phase, "assets": len(assets), "findings": 0,
                    "material_events": len(events), "coverage_unknown": len(results),
                    "core_run_status": "failed", "reason": "offline sources disabled"}


def _run(root):
    # Exclusive directory creation prevents a demo from reusing operational state
    # or overwriting an earlier demonstration, including an existing symlink.
    root.mkdir(parents=True, exist_ok=False)
    initial = _observations()
    changed = _observations(changed=True)
    _require(_observations() == initial and _observations(changed=True) == changed,
             "pure collector adapters must be deterministic")
    first_paths, first_inventory, old_rows = _publish(root / "initial", initial)
    first_run, first_result = _scan(root, first_inventory, "initial")
    second_paths, second_inventory, new_rows = _publish(root / "changed", changed)

    old = {row["asset_id"]: row for row in old_rows}
    new = {row["asset_id"]: row for row in new_rows}
    removed, added = sorted(old.keys() - new.keys()), sorted(new.keys() - old.keys())
    upgraded = sorted(key for key in old.keys() & new.keys() if old[key] != new[key])
    unchanged = sorted(key for key in old.keys() & new.keys() if old[key] == new[key])
    _require((len(old), len(new), len(removed), len(added), len(upgraded), len(unchanged)) ==
             (10, 10, 1, 1, 1, 8), "expected add/remove/upgrade/unchanged inventory transition")
    _require(old[upgraded[0]]["product"] == new[upgraded[0]]["product"] == "debian/demo-upgrade",
             "upgrade must retain the same asset ID")
    _require(old[upgraded[0]]["version"] == "1.0-1" and new[upgraded[0]]["version"] == "2.0-1",
             "observed versions must change without changing identity")
    _require(old[removed[0]]["product"] == "debian/demo-remove" and new[added[0]]["product"] == "debian/demo-added",
             "only the intended package was replaced")
    second_run, second_result = _scan(root, second_inventory, "changed")

    # A failed query is not a successful zero-package observation. Parsing must
    # finish before publishing. Keep the earlier valid pair byte-for-byte.
    previous_source = _pair(second_paths[0])
    _rejected(lambda: linux_inventory(DEBIAN_RELEASE, "half-installed\tdemo-upgrade\t2.0-1\tamd64\n",
                                     backend="dpkg", source_id="linux-a", package_namespace="debian"),
              "failed collection must stop before publication")
    _require(_pair(second_paths[0]) == previous_source, "failed collection refreshed prior snapshot")

    previous_merged = _pair(second_inventory)
    stale_dir = root / "stale"
    stale_dir.mkdir()
    stale = stale_dir / "linux-b.json"
    write_snapshot(stale, changed["linux-b"][0], source_id="linux-b", collector="synthetic-linux",
                   observed_at=(utc_now() - timedelta(days=2)).isoformat())
    _rejected(lambda: merge_snapshots([second_paths[0], stale, second_paths[2]], second_inventory,
                                     source_id="central", expected_sources=list(SOURCES), max_age_seconds=3600),
              "stale source must stop merge")
    _require(_pair(second_inventory) == previous_merged, "stale merge refreshed prior inventory")
    _rejected(lambda: merge_snapshots([second_paths[0], root / "absent.json", second_paths[2]],
                                     second_inventory, source_id="central", expected_sources=list(SOURCES)),
              "missing required source must stop merge")
    _require(_pair(second_inventory) == previous_merged, "missing source refreshed prior inventory")

    _, repeated_inventory, repeated_rows = _publish(root / "repeat", _observations(changed=True))
    _require(repeated_rows == new_rows and repeated_inventory.read_bytes() == second_inventory.read_bytes(),
             "unchanged repeated collection/merge must retain exact inventory bytes")
    repeated_run, repeated_result = _scan(root, repeated_inventory, "repeat")

    # Read-only SQL verifies per-run history. Only StateStore above writes state.
    database = root / "state" / "demo.db"
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
        runs = db.execute("SELECT run_id,status,asset_count,finding_count FROM runs").fetchall()
        _require(len(runs) == 3 and all(row[1:] == ("failed", 10, 0) for row in runs),
                 "three persisted incomplete-coverage scans, no scans after failure gates")
        historic = {}
        for run in (first_run, second_run, repeated_run):
            historic[run] = {row[0]: json.loads(row[1])["asset"] for row in db.execute(
                "SELECT asset_id,payload_json FROM scan_assets WHERE run_id=?", (run,))}
        _require(removed[0] in historic[first_run] and removed[0] not in historic[second_run]
                 and removed[0] not in historic[repeated_run], "removal must preserve prior scan history")
        _require(historic[first_run][upgraded[0]]["version"] == "1.0-1"
                 and historic[second_run][upgraded[0]]["version"] == "2.0-1",
                 "upgrade must preserve historical version")
        _require(db.execute("SELECT COUNT(*) FROM scan_assets").fetchone()[0] == 30,
                 "per-run asset observations must persist")
        _require(db.execute("SELECT COUNT(*) FROM current_findings").fetchone()[0] == 0
                 and db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
                 and db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0,
                 "demo must not invent findings, events, or deliveries")

    summary = {"scenario": "synthetic-home-lab-v1", "sources": list(SOURCES),
               "runs": [first_result, second_result, repeated_result],
               "changes": {"upgraded": upgraded, "removed": removed, "added": added,
                           "unchanged": unchanged},
               "verified": {"stable_upgrade_id": True, "deterministic_repeat": True,
                            "failed_collection_preserved_snapshot": True,
                            "stale_merge_preserved_snapshot": True,
                            "missing_source_preserved_snapshot": True,
                            "historical_assets_preserved": True, "persisted_scans": 3,
                            "persisted_asset_observations": 30},
               "network": "blocked", "host_collection": "synthetic adapter inputs only",
               "coverage": "unknown; this offline demonstration does not assess vulnerabilities"}
    with (root / "summary.json").open("xb") as handle:
        handle.write(json_bytes(summary))
    return summary


def run_demo(output: Path) -> dict:
    """Run a single-threaded offline demo in a new administrator-chosen directory."""
    output = Path(output).absolute()
    with ExitStack() as guard:
        for target in ((socket.socket, "connect"), (socket.socket, "connect_ex"), (socket, "getaddrinfo")):
            guard.enter_context(patch.object(*target, _blocked))
        return _run(output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new directory for synthetic artifacts")
    args = parser.parse_args(argv)
    try:
        summary = run_demo(args.output)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"demo failed: {exc}")
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
