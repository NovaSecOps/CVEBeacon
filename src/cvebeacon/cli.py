"""CVEBeacon command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import secrets
import signal
import threading
import sys
import warnings
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from .config import AppConfig, InventoryConfig, load_config
from .clients import affected_clients, format_affected_clients
from .engine import QueryEngine
from .errors import CVEBeaconError, SourceError
from .http import HttpClient
from .inventory import inspect_inventory, load_inventory
from .identity import normalize_asset, identity_conflict
from .locking import OperationLock
from .models import Asset, HealthStatus
from .notifications import GraphMailNotifier, TeamsNotifier, alert_items, configured_channels
from .reporting import write_json, write_xlsx
from .scheduling import default_command, describe, install, make_plan, remove, status
from .sources import CVEListSource, EPSSSource, KEVSource
from .sources.euvd import SEARCH_URL
from .sources.nvd import CVE_URL
from .state import StateStore

LOG = logging.getLogger("cvebeacon")


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        if message.startswith("unrecognized arguments:"):
            message = "unrecognized arguments"
        super().error(message)


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(prog="cvebeacon", description="Conservative vulnerability monitoring for component inventories")
    parser.add_argument("--config", default="cvebeacon.toml", help="path to TOML configuration")
    parser.add_argument("--verbose", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan the configured inventory and commit monitoring state")
    scan.add_argument("--report", choices=("xlsx", "json"), help="write an on-demand report")
    run_all = commands.add_parser("run", help="run scan and watch run in one ordered command")
    run_all.add_argument("--yes", action="store_true", help="skip the full-history confirmation")
    query = commands.add_parser("query", help="query a product or package without changing monitoring or delivery state")
    for field in ("vendor", "product", "version", "ecosystem", "purl", "cpe", "repository", "commit"):
        query.add_argument("--" + field, default="")
    query.add_argument("--asset-id", default="manual-query")
    asset = commands.add_parser("asset", help="query one configured inventory asset")
    asset.add_argument("asset_id")
    inventory = commands.add_parser("inventory", help="inspect or validate inventory input")
    inventory_sub = inventory.add_subparsers(dest="inventory_command", required=True)
    inspect = inventory_sub.add_parser("inspect"); inspect.add_argument("path", nargs="?")
    validate = inventory_sub.add_parser("validate"); validate.add_argument("path", nargs="?")
    validate.add_argument("--identities", action="store_true", help="show the selected identity path for each asset")
    history = commands.add_parser("history", help="show material finding history")
    history.add_argument("--asset-id"); history.add_argument("--cve-id", "--advisory-id", dest="cve_id"); history.add_argument("--limit", type=int, default=100)
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
    serve = commands.add_parser("serve", help="serve the monitoring dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--allow-unauthenticated-remote", action="store_true", help="acknowledge remote access without built-in authentication")
    dashboard = commands.add_parser("dashboard", help="dashboard security helpers")
    dashboard.add_subparsers(dest="dashboard_command", required=True).add_parser("hash-password", help="prompt privately and emit a password hash")
    setup = commands.add_parser("setup", help="write a validated configuration interactively")
    setup.add_argument("--config", dest="setup_config", help="path to write the configuration")
    setup.add_argument("--force", action="store_true", help="overwrite an existing configuration after backing it up")
    schedule = commands.add_parser("schedule", help="manage the native recurring scan or watch")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    add = schedule_sub.add_parser("install"); add.add_argument("--every", "--hours", dest="every"); add.add_argument("--times", help="comma-separated local times such as 07:00,19:00"); add.add_argument("--command", dest="schedule_target", choices=("scan", "watch", "both"), help="what the schedule runs"); add.add_argument("--platform", choices=("auto", "windows", "linux"), default="auto"); add.add_argument("--run-logged-out", action="store_true", help="Windows: run whether the account is logged on (stored password)"); add.add_argument("--account", help="Windows: account for the stored-password task; requires --run-logged-out"); add.add_argument("--password-stdin", action="store_true", help="read the Windows account password from one stdin line"); add.add_argument("--dry-run", action="store_true"); add.add_argument("--yes", action="store_true")
    schedule_status = schedule_sub.add_parser("status"); schedule_status.add_argument("--platform", choices=("auto", "windows", "linux"), default="auto")
    delete = schedule_sub.add_parser("remove"); delete.add_argument("--platform", choices=("auto", "windows", "linux"), default="auto"); delete.add_argument("--yes", action="store_true")
    watch = commands.add_parser("watch", help="keep a local database of recently changed CVEs")
    watch_sub = watch.add_subparsers(dest="watch_command", required=True)
    watch_sync = watch_sub.add_parser("sync", help="refresh the watch database from public sources")
    watch_sync.add_argument("--yes", action="store_true", help="skip the full-history confirmation")
    watch_statement = watch_sub.add_parser("statement", help="render one stored CVE from a statement template")
    watch_statement.add_argument("cve_id")
    watch_statement.add_argument(
        "--template",
        help="template path (.md, .txt or .docx); default is the built-in Markdown template",
    )
    watch_statement.add_argument("--out", required=True, help="output file")
    watch_statement.add_argument(
        "--force", action="store_true", help="overwrite an existing output file"
    )
    watch_run = watch_sub.add_parser("run", help="refresh the watch database, evaluate rules and deliver alerts")
    watch_run.add_argument("--yes", action="store_true", help="skip the full-history confirmation")
    watch_notify = watch_sub.add_parser("notify", help="deliver pending watch alerts")
    watch_notify.add_argument("--channel", help="only deliver through this channel")
    watch_notify.add_argument(
        "--retry-ambiguous",
        action="store_true",
        help="also resend deliveries whose outcome is unknown",
    )
    watch_notify.add_argument(
        "--retry-failed",
        action="store_true",
        help="also retry failed deliveries and reset their attempt count",
    )
    notify_sub = watch_notify.add_subparsers(dest="notify_command")
    notify_test = notify_sub.add_parser("test", help="send one labelled test message")
    notify_test.add_argument("channel")
    watch_sub.add_parser("status", help="show watch database cursors and counts")
    watch_events = watch_sub.add_parser("events", help="list stored watch alert events")
    watch_events.add_argument("--limit", type=int, default=50)
    watch_events.add_argument("--rule")
    watch_events.add_argument("--pending", action="store_true", help="only events with pending deliveries")
    watch_report = watch_sub.add_parser("report", help="mark a CVE as reported to clients")
    watch_report.add_argument("cve_id")
    watch_report.add_argument("--by", help="who reported it; defaults to the OS login name")
    watch_report.add_argument("--user", help="CVEBeacon username for authenticated mode")
    watch_report.add_argument("--note", help="optional single-line note")
    watch_report.add_argument("--force", action="store_true", help="append another mark and notification")
    watch_unreport = watch_sub.add_parser("unreport", help="withdraw a CVE report mark")
    watch_unreport.add_argument("cve_id")
    watch_unreport.add_argument("--by", help="who withdrew it; defaults to the OS login name")
    watch_unreport.add_argument("--user", help="CVEBeacon username for authenticated mode")
    watch_unreport.add_argument("--note", help="optional single-line note")
    watch_reported = watch_sub.add_parser("reported", help="list CVEs marked as reported to clients")
    watch_reported.add_argument("--all", action="store_true", dest="all_history", help="print the full audit trail")
    watch_reported.add_argument("--verify", action="store_true", help="verify the report audit chain")
    watch_reported.add_argument(
        "--format",
        choices=("text", "csv", "json"),
        default="text",
        help="export format for --all",
    )
    watch_evaluate = watch_sub.add_parser("evaluate", help="re-evaluate stored CVEs against the current rules")
    watch_evaluate.add_argument("--all", action="store_true", required=True, dest="all_cves", help="evaluate every stored CVE")
    watch_evaluate.add_argument("--yes", action="store_true", help="skip the confirmation")
    watch_rules = watch_sub.add_parser("rules", help="inspect watch rules")
    watch_rules_sub = watch_rules.add_subparsers(dest="watch_rules_command", required=True)
    watch_rules_sub.add_parser("check", help="validate rules and print their conditions")
    users = commands.add_parser("users", help="manage CVEBeacon user accounts")
    users_sub = users.add_subparsers(dest="users_command", required=True)
    users_add = users_sub.add_parser("add", help="register a CVEBeacon user")
    users_add.add_argument("username")
    users_add.add_argument("--name", help="display name")
    users_add.add_argument("--email", help="optional email address")
    users_add.add_argument("--admin", action="store_true", help="mark the account as an administrator")
    users_add.add_argument("--no-password", action="store_true", help="register a name for registered mode only")
    users_add.add_argument("--admin-user", help="administrator username for authenticated mode")
    users_passwd = users_sub.add_parser("passwd", help="set a user's password")
    users_passwd.add_argument("username")
    users_passwd.add_argument("--admin-user", help="administrator username; omit to change your own password")
    users_disable = users_sub.add_parser("disable", help="disable a user")
    users_disable.add_argument("username")
    users_disable.add_argument("--admin-user", help="administrator username for authenticated mode")
    users_enable = users_sub.add_parser("enable", help="enable a user")
    users_enable.add_argument("username")
    users_enable.add_argument("--admin-user", help="administrator username for authenticated mode")
    users_unlock = users_sub.add_parser("unlock", help="clear a user's failed-login lockout")
    users_unlock.add_argument("username")
    users_unlock.add_argument("--admin-user", help="administrator username for authenticated mode")
    users_sub.add_parser("list", help="list users without password material")
    users_sub.add_parser("verify", help="verify the user-admin audit chain")
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


def _print_sync_report(report) -> None:
    if report.baseline:
        print("baseline mode stores no history; the next sync starts from now")
    for summary in report.summaries:
        line = (
            f"{summary.source}: {summary.requests} request(s), "
            f"{summary.records} record(s), {summary.new} new, "
            f"{summary.changed} changed"
        )
        if summary.ignored:
            line += f", {summary.ignored} score(s) ignored"
        if summary.lookup_failures:
            line += f", {summary.lookup_failures} lookup(s) failed"
        if summary.throttled:
            line += (
                f", throttled {summary.throttled}x, waited "
                f"{summary.throttle_wait:.0f}s"
            )
        if summary.error:
            line += f"; failed: {summary.error}"
        print(line)


def _print_evaluation(result) -> None:
    if result.by_kind:
        counts = ", ".join(f"{kind} {count}" for kind, count in result.by_kind)
        print(f"events: {result.events} new ({counts})")
    else:
        print(f"events: {result.events} new")


def _run_users(args, config: AppConfig) -> int:
    from .passwords import read_new_password, read_password
    from .watch.users import (
        BOOTSTRAP,
        UserStore,
        audit_name,
        validate_display_name,
        validate_email,
        validate_username,
    )

    store = UserStore(config.watch.users_database)
    authenticated = config.watch.reporting_identity == "authenticated"

    def admin_login(name: str):
        password = read_password(f"Admin password for {audit_name(name)}: ")
        proof = store.authenticate(name, password)
        if proof is None or not proof.user.is_admin:
            raise CVEBeaconError("administrator login required")
        return proof

    def require_admin():
        admin_user = getattr(args, "admin_user", None)
        if not authenticated:
            if admin_user is not None:
                raise CVEBeaconError(
                    "--admin-user is only available when "
                    "watch.reporting.identity = authenticated"
                )
            return None
        if admin_user is None:
            raise CVEBeaconError(
                "administrator login required; use --admin-user"
            )
        return admin_login(admin_user)

    command = args.users_command
    if command == "list":
        users = store.users()
        if not users:
            print("no CVEBeacon users")
            return 0
        current = datetime.now(timezone.utc)
        for user in users:
            if user.disabled:
                status = "disabled"
            else:
                status = "enabled"
            if user.locked_until:
                try:
                    locked = datetime.fromisoformat(str(user.locked_until))
                    if locked.tzinfo is None:
                        locked = locked.replace(tzinfo=timezone.utc)
                    if locked.astimezone(timezone.utc) > current:
                        status = "locked"
                except ValueError:
                    status = "locked"
            print(
                "  ".join(
                    (
                        user.username,
                        user.display_name or "-",
                        user.email or "-",
                        "admin" if user.is_admin else "member",
                        status,
                    )
                )
            )
        return 0
    if command == "verify":
        broken = store.verify_audit()
        if broken is not None:
            detail = "an unreadable row" if broken == -1 else f"row {broken}"
            raise CVEBeaconError(
                f"user audit trail is broken at {detail}"
            )
        print(
            f"user-admin audit log verified: {store.audit_count()} row(s)"
        )
        return 0
    if command == "add":
        username = validate_username(args.username)
        display = validate_display_name(args.name)
        email = validate_email(args.email)
        if authenticated and args.no_password:
            raise CVEBeaconError(
                "--no-password is not available when "
                "watch.reporting.identity = authenticated"
            )
        authorization = None
        if authenticated:
            if args.admin_user is not None:
                authorization = admin_login(args.admin_user)
            elif args.admin:
                authorization = BOOTSTRAP
            else:
                raise CVEBeaconError(
                    "administrator login required; use --admin-user"
                )
        elif getattr(args, "admin_user", None) is not None:
            raise CVEBeaconError(
                "--admin-user is only available when "
                "watch.reporting.identity = authenticated"
            )
        if store.find(username) is not None or (
            email is not None and store.resolve(email) is not None
        ):
            raise CVEBeaconError("username or email is already registered")
        password = None
        if not args.no_password:
            password = read_new_password(
                f"Password for {username} (12–1024 characters): ",
                forbidden=(username, email),
            )
        user = store.add(
            username,
            password=password,
            display_name=display,
            email=email,
            is_admin=args.admin,
            authorization=authorization,
        )
        print(f"added {user.username}")
        return 0
    if command == "passwd":
        authorization = None
        if authenticated and args.admin_user is not None:
            authorization = admin_login(args.admin_user)
        elif authenticated:
            user = store.find(args.username)
            if user is None:
                raise CVEBeaconError("user not found")
            current = read_password(
                f"Current password for {audit_name(user.username)}: "
            )
            proof = store.authenticate(user.username, current)
            if proof is None:
                raise CVEBeaconError("invalid username or password")
            authorization = proof
        else:
            if getattr(args, "admin_user", None) is not None:
                raise CVEBeaconError(
                    "--admin-user is only available when "
                    "watch.reporting.identity = authenticated"
                )
        user = store.find(args.username)
        if user is None:
            raise CVEBeaconError("user not found")
        password = read_new_password(
            f"New password for {user.username} (12–1024 characters): ",
            forbidden=(user.username, user.email),
        )
        store.set_password(
            user.username, password, authorization=authorization
        )
        print(f"password changed for {user.username}")
        return 0
    if command == "disable":
        authorization = require_admin()
        user = store.disable(args.username, authorization=authorization)
        print(f"disabled {user.username}")
        return 0
    if command == "enable":
        authorization = require_admin()
        user = store.enable(args.username, authorization=authorization)
        print(f"enabled {user.username}")
        return 0
    if command == "unlock":
        authorization = require_admin()
        user = store.unlock(args.username, authorization=authorization)
        print(f"unlocked {user.username}")
        return 0
    raise CVEBeaconError("unsupported users command")


def _event_line(row, rule_name: str | None = None, reported=None, clients=None) -> str:
    from .watch.messages import date_phrase

    try:
        stamp = datetime.fromisoformat(row.created_at).astimezone(timezone.utc).strftime(
            "%Y-%m-%d %H:%MZ"
        )
    except ValueError:
        stamp = row.created_at
    reasons = "; ".join(row.reasons)
    line = f"{stamp}  {rule_name or row.rule}  {row.cve_id}  {row.kind}"
    if reasons:
        line += f"  {reasons}"
    line += f"  {date_phrase(row.published, row.first_seen)}"
    affected = format_affected_clients(
        (clients or {}).get(row.cve_id.strip().upper(), ()),
        language="en",
        limit=10,
    )
    if affected:
        line += f"  {affected}"
    if reported is not None:
        from .watch.reported import format_reported

        line += f"  {format_reported(reported)}"
    return line


def _require_watch(config: AppConfig) -> None:
    if not config.watch.enabled:
        raise CVEBeaconError("watch mode is disabled; set [watch] enabled = true")


def _password_prompt(username: str) -> str:
    from .passwords import read_password
    from .watch.users import audit_name

    return read_password(f"Password for {audit_name(username)}: ")


_REPORT_EXPORT_FIELDS = (
    "id",
    "cve_id",
    "action",
    "by",
    "user_id",
    "username",
    "identity_mode",
    "os_account",
    "host",
    "at",
    "note",
    "chain",
    "chain_version",
    "legacy",
)


def _report_export_record(entry) -> dict[str, object]:
    return {
        "id": entry.id,
        "cve_id": entry.cve_id,
        "action": entry.action,
        "by": entry.by,
        "user_id": entry.user_id,
        "username": entry.username,
        "identity_mode": entry.identity_mode,
        "os_account": entry.os_account,
        "host": entry.host,
        "at": entry.at,
        "note": entry.note,
        "chain": entry.chain,
        "chain_version": entry.chain_version,
        "legacy": entry.legacy,
    }


def _csv_cell(value: object) -> object:
    if value is None:
        return ""
    text = str(value)
    if text[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        return "'" + text
    return text


def _run_watch(args, config: AppConfig) -> int:
    import csv

    from .watch.delivery import deliver_pending, send_test
    from .watch.reported import (
        format_timestamp,
        identity_label,
        normalize_cve_id,
    )
    from .watch.reporting import ReportService
    from .watch.rules import describe_condition
    from .watch.statements import write_statement
    from .watch.store import WatchStore
    from .watch.sync import sync_watch, watch_status

    if args.watch_command == "status":
        print(watch_status(config.watch))
        return 0
    if args.watch_command == "rules":
        if not config.watch.rules:
            print("no watch rules configured")
        for rule in config.watch.rules:
            suffix = "" if rule.enabled else " [disabled]"
            print(f"{rule.name}: {describe_condition(rule.condition)}{suffix}")
        return 0
    _require_watch(config)
    store = WatchStore(config.watch.database)
    reporting = ReportService(
        store,
        config.watch.users_database,
        config.watch.reporting_identity,
    )

    def notify_channels() -> tuple[str, ...]:
        return tuple(
            channel.name
            for channel in config.watch.channels
            if channel.enabled and channel.notify_reported
        )

    if args.watch_command == "report":
        outcome = reporting.report_cve(
            args.cve_id,
            by=args.by,
            user=getattr(args, "user", None),
            password_prompt=_password_prompt,
            note=args.note,
            force=args.force,
            notify_channels=notify_channels(),
        )
        entry = outcome.entry
        if not outcome.changed:
            print(
                f"{entry.cve_id} is already reported to clients by "
                f"{identity_label(entry.by, entry.username)} "
                f"at {format_timestamp(entry.at)}"
            )
            _print_notice_hint(
                store.notice_deliveries().get(("report", entry.id), ())
            )
            return 0
        print(
            f"{entry.cve_id}  reported to clients by "
            f"{identity_label(entry.by, entry.username)} "
            f"at {format_timestamp(entry.at)}"
        )
        return _deliver_report_notice(config, store, outcome)
    if args.watch_command == "unreport":
        identifier = normalize_cve_id(args.cve_id)
        outcome = reporting.unreport_cve(
            identifier,
            by=args.by,
            user=getattr(args, "user", None),
            password_prompt=_password_prompt,
            note=args.note,
            notify_channels=notify_channels(),
        )
        entry = outcome.entry
        if not outcome.changed or entry is None:
            print(f"{identifier} is not marked as reported to clients")
            return 0
        print(
            f"{entry.cve_id}  report withdrawn by "
            f"{identity_label(entry.by, entry.username)} "
            f"at {format_timestamp(entry.at)}"
        )
        return _deliver_report_notice(config, store, outcome)
    if args.watch_command == "reported":
        if getattr(args, "verify", False):
            broken = store.verify_reports()
            if broken is not None:
                detail = (
                    "an unreadable row"
                    if broken == -1
                    else f"row {broken}"
                )
                raise CVEBeaconError(
                    f"watch report audit trail is broken at {detail}"
                )
            chained, legacy = store.report_chain_counts()
            message = (
                f"watch report audit trail verified: "
                f"{chained} chained row(s)"
            )
            if legacy:
                message += f"; {legacy} legacy row(s) unchained"
            print(message)
            return 0
        export = getattr(args, "format", "text")
        if export != "text" and not args.all_history:
            raise CVEBeaconError("--format csv or json requires --all")
        entries = (
            store.reported_entries() if args.all_history else store.reported_cves()
        )
        if export in {"csv", "json"}:
            records = [_report_export_record(entry) for entry in entries]
            if export == "json":
                print(json.dumps(records, indent=2, ensure_ascii=False))
            else:
                writer = csv.writer(sys.stdout, lineterminator="\n")
                writer.writerow(_REPORT_EXPORT_FIELDS)
                for record in records:
                    writer.writerow(
                        [
                            _csv_cell(record[field])
                            for field in _REPORT_EXPORT_FIELDS
                        ]
                    )
            return 0
        if not entries:
            print("no CVEs are marked as reported to clients")
            return 0
        notice_states = store.notice_deliveries() if args.all_history else {}
        for entry in entries:
            label = identity_label(entry.by, entry.username)
            if args.all_history:
                action = "reported" if entry.action == "report" else "unreported"
                line = (
                    f"{format_timestamp(entry.at)}  {entry.cve_id}  "
                    f"{action} by {label}"
                )
            else:
                line = (
                    f"{entry.cve_id}  {label}  "
                    f"{format_timestamp(entry.at)}"
                )
            if entry.note:
                line += f"  {entry.note}"
            if entry.legacy:
                line += "  [legacy unchained]"
            if args.all_history:
                states = notice_states.get((entry.action, entry.id), ())
                if states:
                    line += "  notices: " + ", ".join(
                        f"{state.channel} {state.status}" for state in states
                    )
                else:
                    line += "  notices: none"
            print(line)
        return 0
    if args.watch_command == "statement":
        print(
            write_statement(
                store,
                args.cve_id,
                catalogs=config.watch.sources,
                template=args.template,
                out=args.out,
                force=args.force,
                client_impacts=affected_clients(
                    config.database_path, (args.cve_id,)
                ).get(args.cve_id.upper(), ()),
            )
        )
        return 0
    if args.watch_command == "notify":
        with HttpClient(config.http) as http:
            if getattr(args, "notify_command", None) == "test":
                outcome = send_test(config, http, args.channel)
                if outcome.ok:
                    print(f"{outcome.channel} ({outcome.type}): test message sent")
                    return 0
                print(
                    f"{outcome.channel} ({outcome.type}): test message failed"
                    + (f"; {outcome.error}" if outcome.error else "")
                )
                return 3
            delivery = deliver_pending(
                config,
                store,
                http,
                channel_names=[args.channel] if args.channel else None,
                retry_ambiguous=args.retry_ambiguous,
                retry_failed=args.retry_failed,
            )
        _print_delivery(delivery, only_selected=bool(args.channel))
        return 3 if delivery.failed else 0
    if args.watch_command == "events":
        display = {rule.name.casefold(): rule.name for rule in config.watch.rules}
        rows = store.events(limit=args.limit, rule=args.rule, pending=args.pending)
        marks = store.reported_marks(row.cve_id for row in rows)
        row_clients = affected_clients(
            config.database_path, (row.cve_id for row in rows)
        )
        for row in rows:
            print(
                _event_line(
                    row,
                    display.get(row.rule.casefold(), row.rule),
                    marks.get(row.cve_id),
                    row_clients,
                )
            )
        return 0
    if args.watch_command == "evaluate":
        if not args.yes:
            try:
                confirmed = input(
                    "Evaluate every stored CVE against the current watch rules? [y/N] "
                ).strip().casefold() in {"y", "yes"}
            except EOFError:
                confirmed = False
            if not confirmed:
                print("cancelled")
                return 1
        result = store.evaluate_all(
            config.watch.rules, catalogs=config.watch.sources, initial=True
        )
        print(f"evaluated: {result.evaluated} CVE(s)")
        _print_evaluation(result)
        if result.initial_sync_pending:
            print("initialization stays open until the initial sync completes")
        return 0
    with HttpClient(config.http) as http:
        if args.watch_command == "sync":
            report = sync_watch(config, http, assume_yes=args.yes)
            if report.cancelled:
                print("cancelled")
                return 1
            _print_sync_report(report)
            return 4 if report.failures else 0
        try:
            report = sync_watch(config, http, assume_yes=args.yes)
            if report.cancelled:
                print("cancelled")
                return 1
            _print_sync_report(report)
            result = store.evaluate_touched(
                config.watch.rules,
                catalogs=config.watch.sources,
                initial=report.initial_evaluation,
                complete=not report.failures,
            )
            _print_evaluation(result)
        except SourceError as exc:
            # A failed source must not hold back alerts that are already queued.
            print(f"error: {exc}", file=sys.stderr)
            delivery = deliver_pending(config, store, http)
            _print_delivery(delivery)
            return 3 if delivery.failed else 2
        delivery = deliver_pending(config, store, http)
    _print_delivery(delivery)
    if delivery.failed:
        return 3
    return 4 if report.failures else 0


def _print_notice_hint(states) -> None:
    statuses = {state.status for state in states}
    if "failed" in statuses:
        print(
            "notice delivery failed earlier; run "
            "`cvebeacon watch notify --retry-failed`"
        )
    elif "ambiguous" in statuses:
        print(
            "notice delivery outcome is unknown; run "
            "`cvebeacon watch notify --retry-ambiguous`"
        )
    elif "pending" in statuses:
        print("notice delivery is still pending; run `cvebeacon watch notify`")


def _deliver_report_notice(config: AppConfig, store, outcome) -> int:
    if not outcome.channels or outcome.event_id is None:
        return 0
    from .watch.delivery import deliver_pending

    with HttpClient(config.http) as http:
        delivery = deliver_pending(
            config,
            store,
            http,
            channel_names=outcome.channels,
            event_ids=(outcome.event_id,),
        )
    _print_delivery(delivery, only_selected=True)
    return 3 if delivery.failed else 0


def _print_delivery(report, *, only_selected: bool = False) -> None:
    from .watch.delivery import format_channel_line

    if report.recovered:
        print(
            f"recovery: {report.recovered} sending delivery row(s) marked ambiguous"
        )
    for summary in report.channels:
        if summary.skipped:
            if only_selected:
                print(f"{summary.channel} ({summary.type}): disabled")
            continue
        print(format_channel_line(summary))


def _inventory_config(config: AppConfig) -> InventoryConfig:
    if config.inventory is None:
        raise CVEBeaconError(
            "this command requires an inventory; add [inventory] path to the configuration"
        )
    return config.inventory


def _inventory_for(config: AppConfig, path: str | None) -> InventoryConfig:
    if not path:
        return _inventory_config(config)
    base = config.inventory or InventoryConfig(path=Path(path).expanduser().resolve())
    return replace(base, path=Path(path).expanduser().resolve())


def _run_query(config: AppConfig, assets: list[Asset], *, known_findings=()):
    LOG.info("querying %d asset record(s)", len(assets))
    with QueryEngine(config) as engine:
        results = engine.scan(assets, known_findings=known_findings)
    LOG.info("query complete: %d finding(s), %d coverage warning(s)", sum(len(x.findings) for x in results), sum(x.coverage is not None for x in results))
    return results


def _report_path(config: AppConfig, kind: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return config.output_dir / f"cvebeacon-{stamp}.{kind}"


def _source_status(store: StateStore) -> list[dict[str, object]]:
    store.initialize()
    with closing(store._connect()) as db:
        row = db.execute("SELECT run_id FROM runs ORDER BY completed_at DESC LIMIT 1").fetchone()
        return [] if row is None else [dict(x) for x in db.execute("SELECT asset_id,source,status,checked_at,message,freshness_at FROM source_health WHERE run_id=? ORDER BY asset_id,source", (row[0],))]


def _live_source_checks(config: AppConfig) -> dict[str, str]:
    target = "CVE-2021-44228"
    checks: dict[str, str] = {}
    with HttpClient(config.http) as http:
        def nvd_check():
            api_key = config.nvd_api_key()
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
        if config.sources.osv_enabled:
            from .sources.osv import OSVSource
            def osv_check():
                asset = Asset("connectivity", ecosystem="PyPI", product="requests", version="2.31.0")
                result = OSVSource(http).query_many([asset])[asset.target_key]
                if result.error:
                    raise SourceError("osv", result.error)
            operations.append(("osv", osv_check))
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


def _run_scan(config: AppConfig, *, report: str | None = None) -> int:
    store = StateStore(config.database_path)
    attempt_id = store.start_scan()
    args = SimpleNamespace(command="scan", report=report)
    try:
        code = _run_configured(args, config, store, attempt_id=attempt_id)
    except BaseException:
        try:
            store.finish_scan(attempt_id, successful=False)
        except CVEBeaconError:
            LOG.error("scan completion status could not be recorded")
        raise
    store.finish_scan(attempt_id, successful=code == 0)
    return code


def _run_all(config: AppConfig, *, yes: bool = False) -> int:
    parts: list[int] = []
    if config.inventory is not None:
        try:
            parts.append(_run_scan(config))
        except CVEBeaconError as exc:
            print(f"error: {exc}", file=sys.stderr)
            parts.append(2)
    if config.watch.enabled:
        try:
            parts.append(
                _run_watch(
                    SimpleNamespace(watch_command="run", yes=yes),
                    config,
                )
            )
        except CVEBeaconError as exc:
            print(f"error: {exc}", file=sys.stderr)
            parts.append(2)
    if not parts:
        raise CVEBeaconError(
            "nothing to run; add an [inventory] path or set [watch] enabled = true"
        )
    if 2 in parts:
        return 2
    if 3 in parts:
        return 3
    if 4 in parts:
        return 4
    if 1 in parts:
        return 1
    if any(code != 0 for code in parts):
        return 2
    return 0


def _lock_required(args: argparse.Namespace) -> bool:
    """Commands that change monitoring, delivery or report state."""
    if args.command in {"scan", "run"}:
        return True
    if args.command != "watch":
        return False
    if args.watch_command in {"sync", "run", "evaluate", "report", "unreport"}:
        return True
    return (
        args.watch_command == "notify"
        and getattr(args, "notify_command", None) != "test"
    )


def run(args: argparse.Namespace) -> int:
    if args.command == "dashboard":
        from .dashboard_auth import hash_password
        print(hash_password())
        return 0
    if args.command == "setup":
        from .setup import run_setup
        return run_setup(args.setup_config or args.config, force=args.force)
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
    lock = None
    if _lock_required(args):
        label = " ".join(
            part
            for part in (
                args.command,
                getattr(args, "watch_command", None),
            )
            if part
        )
        lock = OperationLock(config, label.replace(" ", "-"))
        if not lock.acquire():
            detail = f" ({lock.holder})" if lock.holder else ""
            print(
                f"error: another run is in progress{detail}; wait for it to "
                "finish or cancel it from the dashboard",
                file=sys.stderr,
            )
            return 2
    try:
        if args.command == "users":
            return _run_users(args, config)
        if args.command == "watch":
            return _run_watch(args, config)
        if args.command == "run":
            return _run_all(config, yes=args.yes)
        if (
            args.command in {"doctor", "serve"}
            and config.inventory is None
            and config.watch.enabled
        ):
            raise CVEBeaconError(
                f"{args.command} requires an inventory; add [inventory] path, or use "
                f"'cvebeacon --config {config.config_path} watch run' from cron or "
                "Task Scheduler"
            )
        if args.command in {"scan", "export", "asset", "doctor", "serve"}:
            _inventory_config(config)
        if args.command == "inventory" and not args.path:
            _inventory_config(config)
        if args.command == "scan":
            return _run_scan(config, report=args.report)
        store = StateStore(config.database_path)
        return _run_configured(args, config, store)
    finally:
        if lock is not None:
            lock.release()


def _normalize_password(value: str) -> str:
    try:
        normalized = value.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        normalized.encode("utf-8")
    except UnicodeError as exc:
        raise CVEBeaconError(
            "the account password contains an invalid Unicode sequence"
        ) from exc
    return normalized


def _read_schedule_password(account: str, *, from_stdin: bool) -> str:
    if from_stdin:
        line = sys.stdin.buffer.readline()
        if not line:
            raise CVEBeaconError("no password was provided on stdin")
        try:
            password = line.rstrip(b"\r\n").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CVEBeaconError(
                "the password on stdin is not valid UTF-8"
            ) from exc
        password = _normalize_password(password)
    else:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                password = getpass.getpass(f"Password for {account}: ")
                confirmation = getpass.getpass("Confirm password: ")
            except (getpass.GetPassWarning, EOFError) as exc:
                raise CVEBeaconError("could not read the account password") from exc
        password = _normalize_password(password)
        confirmation = _normalize_password(confirmation)
        if not secrets.compare_digest(
            password.encode("utf-8"), confirmation.encode("utf-8")
        ):
            raise CVEBeaconError("the account passwords do not match")
    if not password:
        raise CVEBeaconError("the account password cannot be empty")
    return password


def _run_configured(args, config: AppConfig, store: StateStore, *, attempt_id=None) -> int:
    if args.command == "serve":
        from .dashboard import serve
        serve(config, host=args.host, port=args.port, allow_unauthenticated_remote=args.allow_unauthenticated_remote)
        return 0
    if args.command == "inventory":
        inventory_config = _inventory_for(config, args.path)
        if args.inventory_command == "inspect":
            print(json.dumps(inspect_inventory(inventory_config.path, header_row=inventory_config.header_row, encoding=inventory_config.encoding, delimiter=inventory_config.delimiter), indent=2))
        else:
            assets = load_inventory(inventory_config); print(f"valid: {len(assets)} asset(s)")
            if args.identities:
                for asset in assets:
                    print(f"{asset.asset_id}: {asset.identity_path}" + (" (conflicting identities require review)" if identity_conflict(asset) else ""))
        return 0
    if args.command == "asset":
        asset = next((item for item in load_inventory(_inventory_config(config)) if item.asset_id.casefold() == args.asset_id.casefold()), None)
        if not asset: raise CVEBeaconError(f"asset not found: {args.asset_id}")
        result = _run_query(config, [asset])
        print(json.dumps(result[0].to_dict(), indent=2)); return 0
    if args.command == "query":
        try:
            asset = normalize_asset(Asset(args.asset_id.strip(), **{field: getattr(args, field).strip() for field in
                ("vendor", "product", "version", "ecosystem", "purl", "cpe", "repository", "commit")}))
        except ValueError as exc:
            raise CVEBeaconError(str(exc)) from exc
        result = _run_query(config, [asset])
        print(json.dumps(result[0].to_dict(), indent=2)); return 0
    if args.command in {"scan", "export"}:
        inventory_config = _inventory_config(config)
        assets = load_inventory(inventory_config)
        results = _run_query(config, assets, known_findings=store.latest_findings()) if args.command == "scan" else _run_query(config, assets)
        if args.command == "scan":
            channels = configured_channels(config)
            run_id, events = store.record_scan(results, channels=channels, attempt_id=attempt_id)
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
            warnings = sum(result.coverage is not None for result in results)
            degraded = any(health.status in {HealthStatus.DEGRADED, HealthStatus.FAILED} for result in results for health in result.source_health)
            print(f"run {run_id}: {len(assets)} assets, {sum(len(x.findings) for x in results)} findings, {len(events)} material changes, {warnings} coverage warnings")
            if failures:
                for failure in failures: print(f"notification warning: {failure}", file=sys.stderr)
                return 3
            return 4 if warnings or degraded else 0
        path = Path(args.output).resolve() if args.output else _report_path(config, args.format)
        if path in {inventory_config.path, config.config_path, config.database_path}:
            raise CVEBeaconError("report output cannot overwrite inventory, configuration or state")
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
        inventory_config = _inventory_config(config)
        assets = load_inventory(inventory_config); store.initialize()
        checks = {"configuration": "ok", "inventory": f"ok ({len(assets)} assets)", "state": "ok", "teams_secret": "not required" if not config.teams.enabled else ("set" if config.secret(config.teams.webhook_env) else "missing"), "email_secrets": "not required" if not config.email.enabled else ("set" if all(config.secret(x) for x in (config.email.tenant_id_env, config.email.client_id_env, config.email.client_secret_env)) else "missing")}
        if args.live:
            checks["live_sources"] = _live_source_checks(config)
        print(json.dumps(checks, indent=2))
        failed_live = any(value != "ok" for value in checks.get("live_sources", {}).values())
        return 2 if "missing" in checks.values() or failed_live else 0
    if args.command == "source-status": print(json.dumps(_source_status(store), indent=2)); return 0
    if args.command == "schedule":
        target = args.schedule_target or default_command(
            inventory=config.inventory is not None, watch=config.watch.enabled
        )
        if target in {"watch", "both"} and not config.watch.enabled:
            raise CVEBeaconError("watch mode is disabled; set [watch] enabled = true")
        if target in {"scan", "both"} and config.inventory is None:
            raise CVEBeaconError("this configuration has no inventory; use --command watch")
        if args.times is not None and args.every is not None:
            raise CVEBeaconError("--times and --every are mutually exclusive")
        if args.password_stdin and not args.run_logged_out:
            raise CVEBeaconError("--password-stdin requires --run-logged-out")
        if args.password_stdin and not args.dry_run:
            if not args.yes:
                raise CVEBeaconError("--password-stdin requires --yes")
            if args.times is None and args.every is None:
                raise CVEBeaconError(
                    "--password-stdin requires --times or --every"
                )
        if args.times is not None:
            plan = make_plan(config.config_path, times=args.times, command=target, system=args.platform, allow_incompatible=args.dry_run, run_logged_out=args.run_logged_out, account=args.account)
        else:
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
            plan = make_plan(config.config_path, every, command=target, system=args.platform, allow_incompatible=args.dry_run, run_logged_out=args.run_logged_out, account=args.account)
        print(describe(plan))
        if args.dry_run: return 0
        if not args.yes and input("Install this schedule? [y/N] ").strip().casefold() not in {"y", "yes"}: print("cancelled"); return 1
        password = None
        try:
            if plan.run_logged_out:
                password = _read_schedule_password(
                    plan.user_id, from_stdin=args.password_stdin
                )
                install(plan, password=password)
            else:
                install(plan)
        finally:
            password = None
        print("installed"); return 0
    raise CVEBeaconError("unsupported command")


def _reject_password_arguments(arguments: list[str]) -> None:
    for value in arguments:
        if value == "--password-stdin":
            continue
        token = value.split("=", 1)[0]
        # argparse expands any unique prefix of a long option, so an
        # abbreviation such as --pa or --pas also names a password option.
        abbreviates_password = token.startswith("--p") and (
            "--password-stdin".startswith(token) or "--password".startswith(token)
        )
        if (
            abbreviates_password
            or token in {"--pass", "--pwd", "--pw", "-p", "-pass", "-pwd", "-pw"}
            or token.startswith("--pass")
            or token.startswith("--pwd")
            or token.startswith("--pw")
            or token.startswith("-p")
        ):
            raise CVEBeaconError(
                "password input is not accepted on the command line; "
                "use the hidden prompt"
            )


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else list(argv)
    # Frozen interpreters may ignore PYTHONUNBUFFERED. Progress must still
    # reach a dashboard pipe before the command finishes.
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and callable(getattr(stream, "reconfigure", None)):
            stream.reconfigure(line_buffering=True)
    break_signal = getattr(signal, "SIGBREAK", None)
    previous_break = None
    if break_signal is not None and threading.current_thread() is threading.main_thread():
        previous_break = signal.getsignal(break_signal)
        signal.signal(break_signal, signal.default_int_handler)
    try:
        _reject_password_arguments(arguments)
        parser = _parser(); args = parser.parse_args(arguments)
        logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
        # The HTTP library logs full request URLs at INFO. A Teams Workflow URL is a secret.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        return run(args)
    except CVEBeaconError as exc:
        print(f"error: {exc}", file=sys.stderr); return 2
    except MemoryError:
        print("error: not enough memory to complete the command", file=sys.stderr); return 2
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr); return 130
    finally:
        if previous_break is not None:
            signal.signal(break_signal, previous_break)


if __name__ == "__main__":
    raise SystemExit(main())
