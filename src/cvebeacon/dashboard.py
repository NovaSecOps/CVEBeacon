"""Server-rendered monitoring views over the existing scanner and state store."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from io import BytesIO
import ipaddress
import logging
import math
from pathlib import Path
import re
import secrets
import tempfile

from flask import Flask, abort, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.exceptions import HTTPException, SecurityError

from .config import AppConfig
from .dashboard_auth import AccountSessions, DashboardAuth, password_hash
from .errors import CVEBeaconError, ConfigurationError, StateError
from .inventory import load_inventory
from .identity import normalize_asset
from .models import Applicability, Asset
from .reporting import write_json, write_xlsx
from .state import StateStore
from .watch.users import BOOTSTRAP, UserStore
from .watch.permissions import PERMISSIONS

LOG = logging.getLogger("cvebeacon")
STALE_AFTER = timedelta(hours=24)
ACCOUNT_COOKIE = "cvebeacon_account"


def requires(permission, *, post=None):
    """Declare route policy; the request guard enforces it centrally."""
    def decorate(function):
        function.dashboard_permissions = {"GET": permission, "POST": post or permission}
        return function
    return decorate


def _loopback(address):
    try:
        return ipaddress.ip_address(address or "").is_loopback
    except ValueError:
        return False


def _old(value: str | None, now: datetime) -> bool:
    if not value:
        return True
    try:
        timestamp = datetime.fromisoformat(value)
        return timestamp.tzinfo is None or now - timestamp > STALE_AFTER or timestamp > now + timedelta(minutes=5)
    except (TypeError, ValueError):
        return True


def _text(values, name: str, *, required=False, limit=256) -> str:
    if len(values.getlist(name)) > 1:
        abort(400)
    value = values.get(name, "").strip()
    if len(value) > limit or any(ord(char) < 32 for char in value) or (required and not value):
        abort(400)
    return value


def _inventory_match(item: dict, assets: dict[str, Asset]) -> bool:
    asset = Asset(**item)
    current = assets.get(asset.asset_id)
    return current is not None and current.target_key == asset.target_key


def create_app(config: AppConfig, *, host: str = "127.0.0.1") -> Flask:
    if config.inventory is None:
        raise CVEBeaconError(
            "inventory dashboard pages require an inventory; add [inventory] path to the configuration"
        )
    users = UserStore(config.watch.users_database)
    account_mode = bool(users.users()) if users.path.exists() else False
    encoded = None if account_mode else password_hash(config)
    auth = DashboardAuth(encoded, config.dashboard.session_lifetime_seconds) if encoded else None
    account_sessions = AccountSessions(config.dashboard.session_lifetime_seconds, config.dashboard.session_idle_seconds)
    app = Flask(__name__)
    app.extensions["dashboard_auth"] = auth
    app.extensions["account_sessions"] = account_sessions
    app.extensions["dashboard_users"] = users
    wildcard = host in {"0.0.0.0", "::"}
    app.config.update(
        SECRET_KEY=secrets.token_bytes(32), DEBUG=False, TESTING=False,
        MAX_CONTENT_LENGTH=8192, MAX_FORM_MEMORY_SIZE=8192,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=config.dashboard.secure_cookie,
        SESSION_COOKIE_NAME="cvebeacon_session",
        TRUSTED_HOSTS=None if wildcard else list({host, "localhost", "127.0.0.1", "[::1]"}),
    )
    store = StateStore(config.database_path)

    @app.before_request
    def protect_request():
        nonlocal account_mode
        if isinstance(request.routing_exception, SecurityError):
            raise request.routing_exception
        if wildcard:
            from urllib.parse import urlsplit
            hostname = urlsplit("//" + request.host).hostname
            if hostname != "localhost":
                try:
                    ipaddress.ip_address(hostname or "")
                except ValueError:
                    abort(400)
        if account_mode and not users.path.exists():
            raise StateError("account store unavailable")
        if not account_mode and users.path.exists():
            if users.users():
                account_mode = True
        g.accounts = account_mode
        g.user, g.permissions, g.entry, g.sid = None, frozenset(), None, None
        if account_mode:
            identifier = request.cookies.get(ACCOUNT_COOKIE)
            g.entry = account_sessions.get(identifier)
            if g.entry and g.entry.proof:
                try:
                    g.user, g.permissions = users.dashboard_identity(g.entry.proof)
                except ConfigurationError:
                    account_sessions.logout(identifier)
                    g.entry = None
            if g.entry:
                g.sid = identifier
            if request.endpoint not in {"login", "static", "bootstrap"} and g.user is None:
                return redirect(url_for("login"), code=303)
        else:
            if auth and request.endpoint not in {"login", "static", "bootstrap"}:
                if not auth.valid(session.get("auth_id")):
                    session.clear()
                    return redirect(url_for("login"), code=303)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            token = _text(request.form, "csrf", required=True)
            if account_mode:
                expected = g.entry.csrf if g.entry else ""
            else:
                expected = session.get("csrf", "")
            if not re.fullmatch(r"[0-9a-f]{64}", token) or not secrets.compare_digest(token, expected):
                abort(400)
        if request.endpoint and request.endpoint != "static":
            policy = getattr(app.view_functions[request.endpoint], "dashboard_permissions", {})
            permission = policy.get("GET" if request.method == "HEAD" else request.method)
            if permission is None and request.method != "OPTIONS":
                abort(403)
            if account_mode and permission not in {None, "public", "self"} and permission not in g.permissions:
                abort(403)

    @app.context_processor
    def shared():
        if getattr(g, "accounts", False):
            if g.entry is None:
                g.sid, g.entry = account_sessions.issue()
                g.set_account_cookie = True
            return {"csrf": g.entry.csrf, "auth_enabled": True,
                    "authenticated": g.user is not None, "accounts": True,
                    "current_user": g.user, "permissions": g.permissions}
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(32)
        return {"csrf": session["csrf"], "auth_enabled": auth is not None,
                "authenticated": bool(auth and auth.valid(session.get("auth_id")))}

    @app.route("/login", methods=["GET", "POST"])
    @requires("public")
    def login():
        if g.accounts:
            failed = False
            if request.method == "POST":
                name = request.form.getlist("username")
                password = request.form.getlist("password")
                proof = users.authenticate(name[0] if len(name) == 1 else None,
                                           password[0] if len(password) == 1 else None)
                if proof:
                    try:
                        identifier, entry = account_sessions.issue(proof)
                    except ConfigurationError:
                        return render_template("login.html", failed=True), 401
                    account_sessions.logout(g.sid)
                    g.sid, g.entry = identifier, entry
                    g.set_account_cookie = True
                    session.clear()
                    return redirect(url_for("overview"), code=303)
                failed = True
            return render_template("login.html", failed=failed), 401 if failed else 200
        if auth is None:
            return redirect(url_for("overview"), code=303)
        failed = False
        if request.method == "POST":
            values = request.form.getlist("password")
            identifier = auth.login(request.remote_addr or "unknown", values[0] if len(values) == 1 else None)
            if identifier:
                auth.logout(session.get("auth_id"))
                session.clear()
                session["auth_id"] = identifier
                session["csrf"] = secrets.token_hex(32)
                return redirect(url_for("overview"), code=303)
            failed = True
        return render_template("login.html", failed=failed), 401 if failed else 200

    @app.post("/logout")
    @requires("self")
    def logout():
        if g.accounts:
            users.record_logout(g.entry.proof)
            account_sessions.logout(g.sid)
            g.sid = None
            g.set_account_cookie = True
            session.clear()
            return redirect(url_for("login"), code=303)
        if auth:
            auth.logout(session.get("auth_id"))
        session.clear()
        return redirect(url_for("login" if auth else "overview"), code=303)

    @app.after_request
    def headers(response):
        if getattr(g, "set_account_cookie", False):
            if g.sid:
                response.set_cookie(ACCOUNT_COOKIE, g.sid, httponly=True, samesite="Strict",
                                    secure=config.dashboard.secure_cookie)
            else:
                response.delete_cookie(ACCOUNT_COOKIE, httponly=True, samesite="Strict",
                                       secure=config.dashboard.secure_cookie)
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(Exception)
    def error(exc):
        if isinstance(exc, SecurityError):
            return "Invalid request host.", 400
        code = exc.code if isinstance(exc, HTTPException) else 503
        if not isinstance(exc, HTTPException):
            LOG.error("dashboard request failed (%s)", type(exc).__name__)
        return render_template("error.html", code=code), code

    def snapshot():
        data = store.dashboard_snapshot()
        now = datetime.now(timezone.utc)
        try:
            assets = {asset.asset_id: asset for asset in load_inventory(config.inventory)}
            data["inventory_error"] = False
        except CVEBeaconError:
            assets = {}
            data["inventory_error"] = True
        data["inventory"] = assets
        data["categories"] = Counter(asset.category or "Uncategorized" for asset in assets.values())
        latest, attempt = data["latest"], data["attempt"]
        data["stale"] = latest is None or _old(latest["completed_at"], now)
        data["failed"] = bool(latest and latest["status"] != "completed") or bool(attempt and attempt["status"] != "completed")
        data["unfinished"] = bool(attempt and attempt["status"] == "running")
        observed_assets = {item["asset"]["asset_id"]: item for item in data["assets"]}
        data["coverage"] = [{"asset": asdict(asset), "coverage":
            observed_assets[asset.asset_id].get("coverage") if asset.asset_id in observed_assets and _inventory_match(observed_assets[asset.asset_id]["asset"], assets) else "coverage_unknown",
            "reason": observed_assets[asset.asset_id].get("coverage_reason") if asset.asset_id in observed_assets and _inventory_match(observed_assets[asset.asset_id]["asset"], assets) else "No scan observation for this inventory identity/version"}
            for asset in assets.values()]
        for row in data["findings"]:
            row["current_inventory"] = _inventory_match(row["finding"]["asset"], assets)
            row["stale"] = _old(row["last_seen"], now) or not latest or row["last_seen"] != latest["completed_at"]
        for row in data["health"]:
            row["freshness"] = "stale" if _old(row["checked_at"], now) else "cached observation"
        current = [row["finding"] for row in data["findings"] if row["current_inventory"]]
        counts = Counter(row["applicability"] for row in current)
        data["counts"] = {"Assets": len(assets), "Affected findings": counts["affected"], "Needs review": counts["needs_review"],
            "Coverage unknown assets": sum(row["coverage"] == "coverage_unknown" for row in data["coverage"]),
            "Assets needing coverage review": sum(row["coverage"] == "needs_review" for row in data["coverage"]),
            "CISA KEV CVEs": len({row["vulnerability"]["cve_id"] for row in current if row["vulnerability"]["cisa_kev"] is True}),
            "EU KEV CVEs": len({row["vulnerability"]["cve_id"] for row in current if row["vulnerability"]["eu_kev"] is True})}
        return data

    @app.get("/")
    @requires("view")
    def overview():
        return render_template("overview.html", data=snapshot())

    @app.get("/findings")
    @requires("view")
    def findings():
        data = snapshot()
        filters = {key: _text(request.args, key) for key in ("q", "asset", "vendor", "product", "version", "category", "system_id", "ecosystem", "purl", "advisory", "cve", "applicability", "cvss", "severity", "cisa", "eu")}
        if filters["applicability"] not in {"", *(item.value for item in Applicability)}:
            abort(400)
        if filters["severity"] not in {"", "critical", "high", "medium", "low", "none", "unknown"}:
            abort(400)
        if any(filters[key] not in {"", "yes", "no", "unknown"} for key in ("cisa", "eu")):
            abort(400)
        try:
            minimum = float(filters["cvss"]) if filters["cvss"] else None
            if minimum is not None and (not math.isfinite(minimum) or not 0 <= minimum <= 10):
                raise ValueError
        except ValueError:
            abort(400)
        rows = []
        for row in data["findings"]:
            finding = row["finding"]
            asset, vuln = finding["asset"], finding["vulnerability"]
            identifiers = {value for value in (vuln.get("advisory_id"), vuln.get("cve_id"), *vuln.get("aliases", []), *vuln.get("source_ids", [])) if value}
            fields = {"asset": asset["asset_id"], **{key: asset.get(key, "") for key in ("vendor", "product", "version", "category", "system_id", "ecosystem", "purl")},
                      "advisory": " ".join(sorted(identifiers)), "cve": " ".join(sorted(value for value in identifiers if value.startswith("CVE-")))}
            if any(filters[key].casefold() not in str(value).casefold() for key, value in fields.items()):
                continue
            if filters["q"].casefold() not in " ".join(str(value) for value in fields.values()).casefold():
                continue
            if filters["applicability"] and finding["applicability"] != filters["applicability"]:
                continue
            score = vuln["cvss_score"]
            severity = "unknown" if score is None else "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "none"
            if minimum is not None and (score is None or score < minimum):
                continue
            if filters["severity"] and severity != filters["severity"]:
                continue
            def kev_label(value):
                return "unknown" if value is None else "yes" if value else "no"
            if any(filters[key] and kev_label(vuln[field]) != filters[key] for key, field in (("cisa", "cisa_kev"), ("eu", "eu_kev"))):
                continue
            rows.append(row)
        data["coverage"] = [row for row in data["coverage"] if row["coverage"] and
            filters["applicability"] in {"", row["coverage"]} and not filters["cve"] and not filters["advisory"] and not filters["cvss"] and
            filters["severity"] in {"", "unknown"} and
            all(filters[key] in {"", "unknown"} for key in ("cisa", "eu")) and
            all(filters[key].casefold() in row["asset"].get(field, "").casefold() for key, field in
                (("asset", "asset_id"), *((key, key) for key in ("vendor", "product", "version", "category", "system_id", "ecosystem", "purl")))) and
            filters["q"].casefold() in " ".join(row["asset"].values()).casefold()]
        return render_template("findings.html", data=data, rows=rows, filters=filters)

    @app.get("/history")
    @requires("view")
    def history():
        asset_id, cve_id = _text(request.args, "asset"), _text(request.args, "cve")
        cursor = _text(request.args, "before")
        if cursor and (not cursor.isascii() or not cursor.isdigit() or not 1 <= int(cursor) <= 2**63 - 1):
            abort(400)
        rows = store.history(asset_id=asset_id or None, cve_id=cve_id or None, limit=200, before_event_id=int(cursor) if cursor else None)
        return render_template("history.html", rows=rows, asset_id=asset_id, cve_id=cve_id,
                               next_cursor=rows[-1]["event_id"] if len(rows) == 200 else None)

    @app.get("/event/<int:event_id>")
    @requires("view")
    def event(event_id):
        if not 1 <= event_id <= 2**63 - 1:
            abort(404)
        value = store.history_event(event_id)
        if value is None:
            abort(404)
        return render_template("event.html", event=value)

    @app.get("/assets")
    @requires("view")
    def assets():
        data = snapshot()
        query = _text(request.args, "q")
        rows = [row for row in data["coverage"] if query.casefold() in " ".join(row["asset"].values()).casefold()]
        return render_template("assets.html", data=data, rows=rows, query=query)

    @app.get("/asset")
    @requires("view")
    def asset():
        identifier = _text(request.args, "asset_id", required=True)
        data = snapshot()
        if identifier not in data["inventory"]:
            abort(404)
        rows = [row for row in data["findings"] if row["finding"]["asset"]["asset_id"] == identifier]
        coverage = next(row for row in data["coverage"] if row["asset"]["asset_id"] == identifier)
        return render_template("asset.html", data=data, asset=data["inventory"][identifier], rows=rows, coverage=coverage)

    @app.route("/query", methods=["GET", "POST"])
    @requires("view", post="run")
    def query():
        result = None
        mode = _text(request.form if request.method == "POST" else request.args, "mode") or "product"
        if mode not in {"product", "package", "purl"}:
            abort(400)
        keys = {"product": ("vendor", "product", "version"), "package": ("ecosystem", "product", "version"), "purl": ("purl",)}[mode]
        values = {key: "" for key in keys}
        if request.method == "POST":
            values = {key: _text(request.form, key, required=True, limit=2048 if key == "purl" else 256) for key in values}
            try:
                target = normalize_asset(Asset("manual-query", **values))
            except ValueError:
                abort(400)
            from .cli import _run_query
            result = _run_query(config, [target])[0].to_dict()
            for health in result["source_health"]:
                health["asset_id"] = result["asset"]["asset_id"]
        return render_template("query.html", result=result, values=values, mode=mode)

    @app.route("/reports", methods=["GET", "POST"])
    @requires("view", post="run")
    def reports():
        if request.method == "GET":
            return render_template("reports.html")
        kind = _text(request.form, "format", required=True)
        if kind not in {"json", "xlsx"}:
            abort(400)
        from .cli import _run_query
        results = _run_query(config, load_inventory(config.inventory))
        with tempfile.TemporaryDirectory(prefix="cvebeacon-report-") as directory:
            path = Path(directory) / f"report.{kind}"
            (write_xlsx if kind == "xlsx" else write_json)(results, path)
            payload = BytesIO(path.read_bytes())
        return send_file(payload, as_attachment=True, download_name=f"cvebeacon-report.{kind}",
                         mimetype="application/json" if kind == "json" else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    @app.get("/sources")
    @requires("view")
    def sources():
        return render_template("sources.html", data=snapshot())

    @app.route("/bootstrap", methods=["GET", "POST"])
    @requires("public")
    def bootstrap():
        # Only the directly connected peer counts; forwarded headers are ignored.
        if not _loopback(request.remote_addr) or users.users():
            abort(403)
        error = None
        if request.method == "POST":
            try:
                users.add(_text(request.form, "username", required=True, limit=64),
                          password=_password("password"), is_admin=True,
                          authorization=BOOTSTRAP, empty_store_only=True)
                session.clear()
                return redirect(url_for("login"), code=303)
            except ConfigurationError as exc:
                error = str(exc)
        return render_template("bootstrap.html", error=error), 400 if error else 200

    def account_required():
        if not g.accounts:
            abort(403)

    def _password(name):
        values = request.form.getlist(name)
        if len(values) != 1 or len(values[0]) > 1024:
            abort(400)
        return values[0]

    @app.route("/users", methods=["GET", "POST"])
    @requires("manage_users")
    def user_list():
        account_required()
        error = None
        if request.method == "POST":
            try:
                role = _text(request.form, "role", required=True, limit=32)
                users.add(_text(request.form, "username", required=True, limit=64),
                          password=_password("password"),
                          display_name=_text(request.form, "display_name", limit=100),
                          email=_text(request.form, "email", limit=254),
                          is_admin=role == "admin", role=role, authorization=g.entry.proof)
                return redirect(url_for("user_list"), code=303)
            except ConfigurationError as exc:
                error = str(exc)
        return render_template("users.html", users=users.users(), roles=users.roles(),
                               user_roles=users.user_roles(), error=error), 400 if error else 200

    @app.route("/users/<username>", methods=["GET", "POST"])
    @requires("manage_users")
    def user_edit(username):
        account_required()
        target = users.find(username)
        if target is None:
            abort(404)
        error = None
        if request.method == "POST":
            action = _text(request.form, "action", required=True)
            try:
                if action == "save":
                    disabled = _text(request.form, "disabled")
                    if disabled not in {"", "yes"}:
                        abort(400)
                    users.edit_user(username, display_name=_text(request.form, "display_name", limit=100),
                                    email=_text(request.form, "email", limit=254),
                                    role=_text(request.form, "role", required=True, limit=32),
                                    disabled=disabled == "yes", authorization=g.entry.proof)
                elif action == "password":
                    users.set_password(username, _password("password"), authorization=g.entry.proof)
                elif action == "unlock":
                    users.unlock(username, authorization=g.entry.proof)
                else:
                    abort(400)
                return redirect(url_for("user_list"), code=303)
            except ConfigurationError as exc:
                error = str(exc)
        return render_template("user_edit.html", target=target, roles=users.roles(),
                               role=users.user_roles().get(target.id), error=error), 400 if error else 200

    @app.route("/roles", methods=["GET", "POST"])
    @requires("manage_users")
    def roles():
        account_required()
        error = None
        if request.method == "POST":
            name = _text(request.form, "name", required=True, limit=32)
            action = _text(request.form, "action", required=True)
            try:
                if action == "save":
                    users.save_role(name, request.form.getlist("permission"), authorization=g.entry.proof)
                elif action == "delete":
                    users.delete_role(name, authorization=g.entry.proof)
                else:
                    abort(400)
                return redirect(url_for("roles"), code=303)
            except ConfigurationError as exc:
                error = str(exc)
        return render_template("roles.html", roles=users.roles(), capabilities=sorted(PERMISSIONS), error=error), 400 if error else 200

    @app.get("/audit")
    @requires("view_audit")
    def audit():
        account_required()
        return render_template("audit.html", entries=users.audit_entries(), broken=users.verify_audit())

    @app.route("/account", methods=["GET", "POST"])
    @requires("self")
    def account():
        account_required()
        error = None
        if request.method == "POST":
            action = _text(request.form, "action", required=True)
            if action == "logout_all":
                users.record_logout(g.entry.proof, all_sessions=True)
            elif action == "password":
                proof = users.authenticate(g.user.username, _password("current_password"))
                if proof is None:
                    error = "Password change unsuccessful. Wait before trying again."
                else:
                    try:
                        users.set_password(g.user.username, _password("password"), authorization=proof)
                    except ConfigurationError as exc:
                        error = str(exc)
            else:
                abort(400)
            if not error:
                account_sessions.logout_all(g.user.id)
                g.sid, g.entry = None, None
                g.set_account_cookie = True
                session.clear()
                return redirect(url_for("login"), code=303)
        now = account_sessions.clock()
        sessions = [(int(now - created), int(now - touched)) for created, touched in account_sessions.own(g.entry.proof)]
        return render_template("account.html", sessions=sessions, error=error), 400 if error else 200

    return app


def serve(config: AppConfig, *, host="127.0.0.1", port=8787, allow_unauthenticated_remote=False) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise CVEBeaconError("dashboard port must be from 1 through 65535")
    if not isinstance(host, str) or not host or len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
        raise CVEBeaconError("dashboard host must be a hostname or IP address")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.casefold() == "localhost"
    if not loopback:
        users = UserStore(config.watch.users_database)
        accounts = bool(users.users()) if users.path.exists() else False
        if not accounts and not password_hash(config):
            if not allow_unauthenticated_remote:
                raise CVEBeaconError("remote dashboard without authentication requires --allow-unauthenticated-remote")
            LOG.warning("Dashboard has no built-in authentication; network and access control are the deployer's responsibility")
        else:
            LOG.warning("Remote password authentication requires browser-facing HTTPS to protect passwords and cookies from interception")
    from waitress import create_server
    app = create_app(config, host=host)
    try:
        server = create_server(app, host=host, port=port, threads=4, expose_tracebacks=False, max_request_body_size=8192)
    except OSError as exc:
        raise CVEBeaconError("dashboard could not bind the requested address and port") from exc
    address = f"[{host}]" if ":" in host else host
    print(f"CVEBeacon dashboard listening at http://{address}:{port}", flush=True)
    try:
        server.run()
    finally:
        server.close()
