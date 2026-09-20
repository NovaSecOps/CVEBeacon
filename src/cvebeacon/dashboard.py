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

from flask import Flask, abort, redirect, render_template, request, send_file, session, url_for
from werkzeug.exceptions import HTTPException, SecurityError

from .config import AppConfig
from .dashboard_auth import DashboardAuth, password_hash
from .errors import CVEBeaconError
from .inventory import load_inventory
from .identity import normalize_asset
from .models import Applicability, Asset
from .reporting import write_json, write_xlsx
from .state import StateStore

LOG = logging.getLogger("cvebeacon")
STALE_AFTER = timedelta(hours=24)


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
    encoded = password_hash(config)
    auth = DashboardAuth(encoded, config.dashboard.session_lifetime_seconds) if encoded else None
    app = Flask(__name__)
    app.extensions["dashboard_auth"] = auth
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
        if auth and request.endpoint not in {"login", "static"}:
            if not auth.valid(session.get("auth_id")):
                session.clear()
                return redirect(url_for("login"), code=303)
        if request.method == "POST":
            token = _text(request.form, "csrf", required=True)
            if not re.fullmatch(r"[0-9a-f]{64}", token) or not secrets.compare_digest(token, session.get("csrf", "")):
                abort(400)

    @app.context_processor
    def shared():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(32)
        return {"csrf": session["csrf"], "auth_enabled": auth is not None,
                "authenticated": bool(auth and auth.valid(session.get("auth_id")))}

    @app.route("/login", methods=["GET", "POST"])
    def login():
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
    def logout():
        if auth:
            auth.logout(session.get("auth_id"))
        session.clear()
        return redirect(url_for("login" if auth else "overview"), code=303)

    @app.after_request
    def headers(response):
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
    def overview():
        return render_template("overview.html", data=snapshot())

    @app.get("/findings")
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
    def history():
        asset_id, cve_id = _text(request.args, "asset"), _text(request.args, "cve")
        cursor = _text(request.args, "before")
        if cursor and (not cursor.isascii() or not cursor.isdigit() or not 1 <= int(cursor) <= 2**63 - 1):
            abort(400)
        rows = store.history(asset_id=asset_id or None, cve_id=cve_id or None, limit=200, before_event_id=int(cursor) if cursor else None)
        return render_template("history.html", rows=rows, asset_id=asset_id, cve_id=cve_id,
                               next_cursor=rows[-1]["event_id"] if len(rows) == 200 else None)

    @app.get("/event/<int:event_id>")
    def event(event_id):
        if not 1 <= event_id <= 2**63 - 1:
            abort(404)
        value = store.history_event(event_id)
        if value is None:
            abort(404)
        return render_template("event.html", event=value)

    @app.get("/assets")
    def assets():
        data = snapshot()
        query = _text(request.args, "q")
        rows = [row for row in data["coverage"] if query.casefold() in " ".join(row["asset"].values()).casefold()]
        return render_template("assets.html", data=data, rows=rows, query=query)

    @app.get("/asset")
    def asset():
        identifier = _text(request.args, "asset_id", required=True)
        data = snapshot()
        if identifier not in data["inventory"]:
            abort(404)
        rows = [row for row in data["findings"] if row["finding"]["asset"]["asset_id"] == identifier]
        coverage = next(row for row in data["coverage"] if row["asset"]["asset_id"] == identifier)
        return render_template("asset.html", data=data, asset=data["inventory"][identifier], rows=rows, coverage=coverage)

    @app.route("/query", methods=["GET", "POST"])
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
    def sources():
        return render_template("sources.html", data=snapshot())

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
        if not password_hash(config):
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
