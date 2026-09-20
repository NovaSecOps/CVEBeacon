"""CVEBeacon command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .config import AppConfig, load_config
from .engine import QueryEngine
from .errors import CVEBeaconError, SourceError
from .http import HttpClient
from .inventory import inspect_inventory, load_inventory
from .models import Asset
from .notifications import GraphMailNotifier, TeamsNotifier, alert_items, configured_channels
from .reporting import write_json, write_xlsx
from .scheduling import describe, install, make_plan, remove, status
from .sources import CVEListSource, EPSSSource, KEVSource
from .sources.euvd import SEARCH_URL
from .sources.nvd import CVE_URL
from .state import StateStore

LOG = logging.getLogger("cvebeacon")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cvebeacon", description="Conservative vulnerability monitoring for product inventories")
    parser.add_argument("--config", default="cvebeacon.toml", help="path to TOML configuration")
    parser.add_argument("--verbose", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan the configured inventory and commit monitoring state")
    scan.add_argument("--report", choices=("xlsx", "json"), help="write an on-demand report")
    query = commands.add_parser("query", help="query a product without changing monitoring or delivery state")
    query.add_argument("--vendor", required=True); query.add_argument("--product", required=True); query.add_argument("--version", required=True)
    query.add_argument("--asset-id", default="manual-query")
    asset = commands.add_parser("asset", help="query one configured inventory asset")
    asset.add_argument("asset_id")
    inventory = commands.add_parser("inventory", help="inspect or validate inventory input")
    inventory_sub = inventory.add_subparsers(dest="inventory_command", required=True)
    inspect = inventory_sub.add_parser("inspect"); inspect.add_argument("path", nargs="?")
    validate = inventory_sub.add_parser("validate"); validate.add_argument("path", nargs="?")
    history = commands.add_parser("history", help="show material finding history")
    history.add_argument("--asset-id"); history.add_argument("--cve-id"); history.add_argument("--limit", type=int, default=100)
    export = commands.add_parser("export", help="run a current query and write a report without committing state")
    export.add_argument("--format", choices=("xlsx", "json"), default="xlsx")
    export.add_argument("--output")
    notify = commands.add_parser("notify", help="test configured notification channels")
    notify_sub = notify.add_subparsers(dest="notify_command", required=True)
    notify_test = notify_sub.add_parser("test")
    notify_test.add_argument("--channel", choices=("teams", "email", "all"), default="all")
    doctor = commands.add_parser("doctor", help="validate configuration, inventory, and local state access")
    doctor.add_argument("--live", action="store_true", help="also test enabled public source connectivity")
    commands.add_parser("source-status", help="show source health from the most recent scan")
    schedule = commands.add_parser("schedule", help="manage the native recurring scan")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    add = schedule_sub.add_parser("install"); add.add_argument("--every"); add.add_argument("--platform", choices=("auto", "windows", "linux"), default="auto"); add.add_argument("--dry-run", action="store_true"); add.add_argument("--yes", action="store_true")
    schedule_status = schedule_sub.add_parser("status"); schedule_status.add_argument("--platform", choices=("auto", "windows", "linux"), default="auto")
    delete = schedule_sub.add_parser("remove"); delete.add_argument("--platform", choices=("auto", "windows", "linux"), default="auto"); delete.add_argument("--yes", action="store_true")
    return parser


def _notify_pending(config: AppConfig, store: StateStore, http: HttpClient, channel: str) -> int:
    rows = store.pending_events(channel)
    if not rows: return 0
    items = alert_items(rows)
    ids = [item.event_id for item in items]
    try:
        if channel == "teams":
            TeamsNotifier(http, config.secret(config.teams.webhook_env, required=True) or "").send(items)
        else:
            GraphMailNotifier(
                http,
                tenant_id=config.secret(config.email.tenant_id_env, required=True) or "",
                client_id=config.secret(config.email.client_id_env, required=True) or "",
                client_secret=config.secret(config.email.client_secret_env, required=True) or "",
                sender=config.email.sender, recipients=config.email.recipients,
            ).send(items)
    except CVEBeaconError as exc:
        store.mark_delivery(channel, ids, accepted=False, error=str(exc)[:500])
        raise
    store.mark_delivery(channel, ids, accepted=True)
    return len(items)


def _run_query(config: AppConfig, assets: list[Asset]):
    LOG.info("querying %d asset record(s)", len(assets))
    with QueryEngine(config) as engine:
        results = engine.scan(assets)
    LOG.info("query complete: %d finding(s), %d coverage warning(s)", sum(len(x.findings) for x in results), sum(x.coverage is not None for x in results))
    return results


def _report_path(config: AppConfig, kind: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return config.output_dir / f"cvebeacon-{stamp}.{kind}"


def _source_status(store: StateStore) -> list[dict[str, object]]:
    store.initialize()
    with store._connect() as db:
        row = db.execute("SELECT run_id FROM runs WHERE status='completed' ORDER BY completed_at DESC LIMIT 1").fetchone()
        return [] if row is None else [dict(x) for x in db.execute("SELECT asset_id,source,status,checked_at,message,freshness_at FROM source_health WHERE run_id=? ORDER BY asset_id,source", (row[0],))]


def _live_source_checks(config: AppConfig) -> dict[str, str]:
    target = "CVE-2021-44228"
    checks: dict[str, str] = {}
    with HttpClient(config.http) as http:
        def nvd_check():
            api_key = config.secret(config.sources.nvd_api_key_env)
            payload = http.get_json(CVE_URL, source="nvd", params={"cveId": target}, headers={"apiKey": api_key} if api_key else None)
            if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                raise SourceError("nvd", "connectivity response omitted vulnerabilities")
            return payload

        def euvd_check():
            payload = http.get_json(SEARCH_URL, source="euvd", params={"text": target, "page": 0, "size": 1})
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise SourceError("euvd", "connectivity response omitted items")
            return payload

        operations = []
        if config.sources.nvd_enabled:
            operations.append(("nvd", nvd_check))
        if config.sources.cve_enabled:
            operations.append(("cve_list", lambda: CVEListSource(http).record(target)))
        if config.sources.euvd_enabled:
            operations.append(("euvd", euvd_check))
        kev = KEVSource(http)
        if config.sources.cisa_kev_enabled:
            operations.append(("cisa_kev", kev.cisa))
        if config.sources.eu_kev_enabled:
            operations.append(("eu_kev", kev.eu))
        if config.sources.epss_enabled:
            operations.append(("epss", lambda: EPSSSource(http).scores([target])))
        for name, operation in operations:
            try:
                operation()
                checks[name] = "ok"
            except CVEBeaconError as exc:
                checks[name] = f"failed: {exc}"
    return checks


def run(args: argparse.Namespace) -> int:
    if args.command == "inventory" and args.inventory_command == "inspect" and args.path:
        print(json.dumps(inspect_inventory(args.path), indent=2))
        return 0
    if args.command == "schedule" and args.schedule_command == "status":
        print(status(system=args.platform))
        return 0
    if args.command == "schedule" and args.schedule_command == "remove":
        if not args.yes and input("Remove the CVEBeacon schedule? [y/N] ").strip().casefold() not in {"y", "yes"}: print("cancelled"); return 1
        print("removed" if remove(system=args.platform) else "not installed")
        return 0
    config = load_config(args.config)
    store = StateStore(config.database_path)
    if args.command == "inventory":
        if args.inventory_command == "inspect":
            print(json.dumps(inspect_inventory(args.path or config.inventory.path, header_row=config.inventory.header_row, encoding=config.inventory.encoding, delimiter=config.inventory.delimiter), indent=2))
        else:
            inventory_config = replace(config.inventory, path=Path(args.path).expanduser().resolve()) if args.path else config.inventory
            assets = load_inventory(inventory_config); print(f"valid: {len(assets)} asset(s)")
        return 0
    if args.command == "asset":
        asset = next((item for item in load_inventory(config.inventory) if item.asset_id.casefold() == args.asset_id.casefold()), None)
        if not asset: raise CVEBeaconError(f"asset not found: {args.asset_id}")
        result = _run_query(config, [asset])
        print(json.dumps(result[0].to_dict(), indent=2)); return 0
    if args.command == "query":
        result = _run_query(config, [Asset(args.asset_id, args.vendor, args.product, args.version)])
        print(json.dumps(result[0].to_dict(), indent=2)); return 0
    if args.command in {"scan", "export"}:
        assets = load_inventory(config.inventory)
        results = _run_query(config, assets)
        if args.command == "scan":
            channels = configured_channels(config)
            run_id, events = store.record_scan(results, channels=channels)
            failures = []
            with HttpClient(config.http) as http:
                for channel in channels:
                    try:
                        delivered = _notify_pending(config, store, http, channel)
                        LOG.info("%s channel accepted %d pending event(s)", channel, delivered)
                    except CVEBeaconError as exc: failures.append(str(exc))
            if args.report:
                path = _report_path(config, args.report)
                (write_xlsx if args.report == "xlsx" else write_json)(results, path)
                print(path)
            print(f"run {run_id}: {len(assets)} assets, {sum(len(x.findings) for x in results)} findings, {len(events)} material changes")
            if failures:
                for failure in failures: print(f"notification warning: {failure}", file=sys.stderr)
                return 3
            return 0
        path = Path(args.output).resolve() if args.output else _report_path(config, args.format)
        (write_xlsx if args.format == "xlsx" else write_json)(results, path); print(path); return 0
    if args.command == "history":
        print(json.dumps(store.history(asset_id=args.asset_id, cve_id=args.cve_id, limit=args.limit), indent=2)); return 0
    if args.command == "notify":
        sample = [{"event_id": 0, "asset_id": "test-asset", "cve_id": "CVE-2099-9999", "event_type": "test", "payload_json": json.dumps({"applicability": "needs_review", "vulnerability": {"cvss_score": None, "cisa_kev": False, "eu_kev": False}})}]
        items = alert_items(sample)
        channels = configured_channels(config) if args.channel == "all" else (args.channel,)
        if not channels: raise CVEBeaconError("no notification channels are enabled")
        with HttpClient(config.http) as http:
            for channel in channels:
                if channel == "teams": TeamsNotifier(http, config.secret(config.teams.webhook_env, required=True) or "").send(items)
                else: GraphMailNotifier(http, tenant_id=config.secret(config.email.tenant_id_env, required=True) or "", client_id=config.secret(config.email.client_id_env, required=True) or "", client_secret=config.secret(config.email.client_secret_env, required=True) or "", sender=config.email.sender, recipients=config.email.recipients).send(items)
                print(f"{channel}: accepted by remote service")
        return 0
    if args.command == "doctor":
        assets = load_inventory(config.inventory); store.initialize()
        checks = {"configuration": "ok", "inventory": f"ok ({len(assets)} assets)", "state": "ok", "teams_secret": "not required" if not config.teams.enabled else ("set" if config.secret(config.teams.webhook_env) else "missing"), "email_secrets": "not required" if not config.email.enabled else ("set" if all(config.secret(x) for x in (config.email.tenant_id_env, config.email.client_id_env, config.email.client_secret_env)) else "missing")}
        if args.live:
            checks["live_sources"] = _live_source_checks(config)
        print(json.dumps(checks, indent=2)); return 0 if "missing" not in checks.values() else 2
    if args.command == "source-status": print(json.dumps(_source_status(store), indent=2)); return 0
    if args.command == "schedule":
        if args.every is None:
            selected = input("Interval in hours [2/4/6/12/24, default 4]: ").strip() or "4"
        else:
            selected = args.every
        if selected.casefold().endswith("h"):
            selected = selected[:-1]
        try:
            every = int(selected)
        except ValueError as exc:
            raise CVEBeaconError("schedule interval must look like 4 or 4h") from exc
        plan = make_plan(config.config_path, every, system=args.platform, allow_incompatible=args.dry_run)
        print(describe(plan))
        if args.dry_run: return 0
        if not args.yes and input("Install this schedule? [y/N] ").strip().casefold() not in {"y", "yes"}: print("cancelled"); return 1
        install(plan); print("installed"); return 0
    raise CVEBeaconError("unsupported command")


def main(argv: list[str] | None = None) -> int:
    parser = _parser(); args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    # The HTTP library logs full request URLs at INFO. A Teams Workflow URL is a secret.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    try: return run(args)
    except CVEBeaconError as exc:
        print(f"error: {exc}", file=sys.stderr); return 2
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr); return 130


if __name__ == "__main__":
    raise SystemExit(main())
