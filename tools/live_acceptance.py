"""Opt-in anonymous live acceptance; never imported by the offline test suite."""

import argparse
from contextlib import closing, redirect_stdout, redirect_stderr
from dataclasses import asdict, replace
from datetime import datetime, timezone
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys


def save(root, name, value):
    with (root / name).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)


def package_matrix(root):
    from cvebeacon.config import HttpConfig
    from cvebeacon.http import HttpClient
    from cvebeacon.identity import normalize_asset
    from cvebeacon.models import Asset
    from cvebeacon.osv_applicability import evaluate_osv
    from cvebeacon.sources.osv import OSVSource

    cases = [
        ("PyPI", "requests", "2.31.0", "2.32.0", "CVE-2024-35195"),
        ("npm", "lodash", "4.17.20", "4.17.21", "CVE-2021-23337"),
        ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.15.0", "CVE-2021-44228"),
        ("Go", "golang.org/x/text", "0.3.7", "0.3.8", "CVE-2022-32149"),
        ("crates.io", "time", "0.2.22", "0.2.23", "RUSTSEC-2020-0071"),
        ("NuGet", "Newtonsoft.Json", "12.0.3", "13.0.1", "CVE-2024-21907"),
        ("Debian:11", "zlib", "1:1.2.11.dfsg-2+deb11u1", "1:1.2.11.dfsg-2+deb11u2", "DSA-5218-1"),
    ]
    assets = [normalize_asset(Asset(f"public-matrix-{i}", ecosystem=e, product=p, version=v)) for i, (e, p, v, _, _) in enumerate(cases)]
    with HttpClient(HttpConfig()) as http:
        results = OSVSource(http).query_many(assets)
    rows, non_cve = [], []
    for asset, (_, _, affected, fixed, identifier) in zip(assets, cases):
        result = results[asset.target_key]
        save(root, asset.asset_id + ".json", asdict(result) | {"matched_ids": sorted(result.matched_ids)})
        matching = [record for record in result.records if identifier in [record["id"], *record.get("aliases", [])]]
        decisions = [{"id": record["id"], "aliases": record.get("aliases", []), "modified": record["modified"],
                      "affected": evaluate_osv(asset, record).state.value,
                      "fixed": evaluate_osv(replace(asset, version=fixed), record).state.value} for record in matching]
        from cvebeacon.reconcile import reconcile
        from cvebeacon.models import Vulnerability
        fixed_decisions = [evaluate_osv(replace(asset, version=fixed), record) for record in matching]
        reconciled = reconcile(asset, Vulnerability(advisory_id=identifier), (), fixed_decisions).applicability.value if matching else None
        contradictory = any(d["fixed"] == "affected" for d in decisions) and any(d["fixed"] == "not_affected" for d in decisions)
        rows.append({"ecosystem": asset.ecosystem, "package": asset.product, "affected_version": affected,
                     "fixed_boundary": fixed, "identifier": identifier, "error": result.error, "decisions": decisions,
                     "fixed_reconciled": reconciled, "source_disagreement": contradictory,
                     "passed": not result.error and any(d["affected"] == "affected" and d["fixed"] == "not_affected" for d in decisions)
                         and (not contradictory or reconciled == "needs_review")})
        for record in result.records:
            if not any(value.startswith("CVE-") for value in [record["id"], *record.get("aliases", [])]):
                non_cve.append({"id": record["id"], "ecosystem": asset.ecosystem,
                                "state": evaluate_osv(asset, record).state.value})
    invalid_rejected = False
    try:
        normalize_asset(Asset("invalid", purl="pkg:pypi/requests@1", version="2"))
    except ValueError:
        invalid_rejected = True
    summary = {"cases": rows, "non_cve": non_cve, "invalid_rejected": invalid_rejected,
               "passed": all(row["passed"] for row in rows) and bool(non_cve) and invalid_rejected}
    save(root, "matrix-summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    return summary["passed"]


def workflow(root):
    from cvebeacon import cli
    from cvebeacon.config import load_config
    from cvebeacon.dashboard import create_app
    from cvebeacon.models import Asset
    from cvebeacon.reporting import write_json, write_xlsx
    from cvebeacon.engine import QueryEngine
    from cvebeacon.inventory import load_inventory

    assets = [Asset("public-appliance", "fortinet", "fortios", "7.0.5", category="firewall"),
              Asset("public-os", "freebsd", "freebsd", "13.0", category="operating_system"),
              Asset("public-infrastructure", "proxmox", "virtual environment", "6.0", category="virtualization",
                    cpe="cpe:2.3:a:proxmox:virtual_environment:6.0:*:*:*:*:*:*:*"),
              Asset("public-server", "apache", "guacamole", "1.3.0", category="server"),
              Asset("public-samba", "samba", "samba", "4.13.0", category="server"),
              Asset("public-database", "redis", "redis", "6.0.0", category="database"),
              Asset("public-library", purl="pkg:pypi/requests@2.32.4", category="library", system_id="public-example-system")]
    save(root, "inventory.json", [asdict(asset) for asset in assets])
    config_path = root / "acceptance.toml"
    config_path.write_text("[inventory]\npath='inventory.json'\n[state]\ndatabase='state.db'\n[output]\ndirectory='reports'\n[notifications.teams]\nenabled=false\n[notifications.email]\nenabled=false\n", encoding="utf-8")
    config = load_config(config_path)
    assert not config.teams.enabled and not config.email.enabled
    operations = []
    def command(name, args, allowed=(0,)):
        print("Running " + name, flush=True)
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["--config", str(config_path), *args])
        save(root, name + ".json", {"exit_code": code, "stdout": out.getvalue(), "stderr": err.getvalue()})
        assert code in allowed, (name, code)
        operations.append({"operation": name, "exit_code": code})
        return out.getvalue()
    command("inspect", ["inventory", "inspect"])
    command("validate", ["inventory", "validate", "--identities"])
    command("doctor", ["doctor"])
    product_query = json.loads(command("query-product", ["query", "--vendor", "apache", "--product", "guacamole", "--version", "1.3.0"]))
    package_query = json.loads(command("query-purl", ["query", "--purl", "pkg:pypi/requests@2.32.4"]))
    assert product_query["findings"] and package_query["findings"]
    assert any(e["source"] == "osv" for f in package_query["findings"] for e in f["evidence"])
    command("scan", ["scan", "--report", "xlsx"], (0, 4))
    command("history", ["history"])
    health = json.loads(command("source-health", ["source-status"]))
    for platform in ("windows", "linux"):
        command("schedule-" + platform, ["schedule", "install", "--every", "4", "--platform", platform, "--dry-run"])
    with closing(sqlite3.connect(config.database_path)) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0
        before = list(db.iterdump())
    client = create_app(config).test_client()
    pages = {}
    for path in ("/", "/findings", "/assets", "/history", "/sources", "/query?mode=package", "/query?mode=purl", "/reports"):
        response = client.get(path)
        assert response.status_code == 200, path
        pages[path] = response.status_code
    save(root, "dashboard.json", pages)
    with closing(sqlite3.connect(config.database_path)) as db:
        assert list(db.iterdump()) == before
    # Fresh non-committing reports exercise the shared report path and ensure
    # coverage/source failures remain present in both formats.
    print("Running report query", flush=True)
    with QueryEngine(config) as engine:
        results = engine.scan(load_inventory(config.inventory))
    write_json(results, root / "report.json")
    write_xlsx(results, root / "report.xlsx")
    with closing(sqlite3.connect(config.database_path)) as db:
        assert list(db.iterdump()) == before
    rows = [{"asset": item.asset.asset_id, "category": item.asset.category, "findings": len(item.findings),
             "states": sorted({finding.applicability.value for finding in item.findings}),
             "coverage": item.coverage.value if item.coverage else None,
             "reason": item.coverage_reason} for item in results]
    assert all(item.findings for item in results), "a sample identity has no findings; review current source identity"
    failures = [row for row in health if row["status"] in {"failed", "degraded"}]
    report_failures = [{"asset_id": item.asset.asset_id, "source": h.source, "status": h.status.value, "message": h.message}
                       for item in results for h in item.source_health if h.status.value in {"failed", "degraded"}]
    summary = {"operations": operations, "assets": rows, "source_failures": failures,
               "report_source_failures": report_failures, "functional_passed": True, "all_sources_healthy": not (failures or report_failures)}
    save(root, "workflow-summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    return not (failures or report_failures)


def non_cve_workflow(root):
    from cvebeacon.config import AppConfig, InventoryConfig
    from cvebeacon.engine import QueryEngine
    from cvebeacon.models import Asset
    from cvebeacon.reporting import write_json, write_xlsx
    from cvebeacon.state import StateStore
    config = AppConfig(root / "non-cve.toml", InventoryConfig(root / "unused.csv"), root / "non-cve.db", root)
    assets = [Asset("debian-affected", product="zlib", version="1:1.2.11.dfsg-2+deb11u1", ecosystem="Debian:11", category="library"),
              Asset("debian-fixed", product="zlib", version="1:1.2.11.dfsg-2+deb11u2", ecosystem="Debian:11", category="library")]
    with QueryEngine(config) as engine:
        results = engine.scan(assets)
    for result, state in zip(results, ("affected", "not_affected")):
        finding = next(f for f in result.findings if f.vulnerability.primary_id == "DSA-5218-1")
        assert finding.applicability.value == state and finding.vulnerability.cve_id is None
        assert all(health.status.value == "ok" for health in result.source_health)
    write_json(results, root / "non-cve-report.json")
    write_xlsx(results, root / "non-cve-report.xlsx")
    store = StateStore(config.database_path)
    _, first = store.record_scan(results)
    _, repeated = store.record_scan(results)
    assert first and not repeated
    assert len(store.history(cve_id="DSA-5218-1")) == 2
    save(root, "non-cve-summary.json", {"passed": True, "first_events": len(first), "repeat_events": len(repeated),
                                        "advisory": "DSA-5218-1", "cve_id": None})
    print("PASS live non-CVE assessment, reports, history and repeat-scan deduplication", flush=True)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-network", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stage", choices=("all", "matrix", "workflow", "non-cve"), default="all")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.output.resolve()
    if not args.child:
        root.mkdir(parents=True, exist_ok=False)
        allowed = {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}
        env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
        env["PYTHONUTF8"] = "1"
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--allow-network", "--output", str(root),
                                 "--stage", args.stage, "--child"], env=env)
        return result.returncode
    save(root, "environment.json", {"variable_names": sorted(os.environ), "anonymous": True,
                                    "started_at": datetime.now(timezone.utc).isoformat()})
    ok = True
    if args.stage in {"all", "matrix"}:
        ok = package_matrix(root) and ok
    if args.stage in {"all", "workflow"}:
        ok = workflow(root) and ok
    if args.stage in {"all", "non-cve"}:
        ok = non_cve_workflow(root) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
