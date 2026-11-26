"""Read-only release status and administrator-only update requests."""
from importlib.metadata import version
import re

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from .dashboard_ops import _text, requires, require_accounts
from .errors import CVEBeaconError
from .updater import check, read_status, request_update, unsupported_reason


UPDATE_REASON_TEXT = {
    "preflight-crontab-unreadable": "The crontab could not be read inside the update service.",
    "preflight-managed-crontab": "A managed schedule must be removed before the updater can continue.",
    "preflight-failed": "The updater could not complete its access checks.",
    "check-network": "The updater could not reach the release service.",
    "check-failed": "The release check could not be completed.",
    "verify-signature": "The release signature could not be verified.",
    "verify-artifact": "A release artifact could not be verified.",
    "probe-unhealthy": "The dashboard did not pass its health check after starting.",
    "quiesce-failed": "A running service could not be stopped cleanly.",
    "lock-failed": "The updater could not acquire the required locks.",
    "freeze-failed": "The dashboard could not be stopped for the update.",
    "backup-failed": "The pre-update backup could not be created.",
    "backup-database-busy": "A database stayed busy while the update backup was being created.",
    "install-failed": "The verified release could not be installed.",
    "migrate-failed": "The state migration did not complete.",
    "switch-failed": "The updater could not select the new release.",
    "start-failed": "The dashboard could not be started after the update.",
    "doctor-failed": "The local health checks did not pass after the update.",
    "recovery-incomplete": "Automatic recovery could not finish; writes remain blocked until recovery succeeds.",
    "update-failed": "The updater could not complete the requested operation.",
}


def _display_status(config):
    status = read_status(config)
    notes = status.get("notes")
    if isinstance(notes, str):
        status["notes"] = re.sub(r"<!--.*?(?:-->|$)", "", notes, flags=re.DOTALL).strip()
    for key in ("last_request", "last_update"):
        value = status.get(key)
        if isinstance(value, dict) and value.get("reason"):
            value = dict(value)
            value["reason_text"] = UPDATE_REASON_TEXT.get(
                value["reason"], "The updater could not complete the requested operation."
            )
            status[key] = value
    latest = status.get("last_update")
    request_status = status.get("last_request")
    if (isinstance(latest, dict) and latest.get("reason_text")
            and isinstance(request_status, dict) and not request_status.get("reason_text")):
        request_status = dict(request_status)
        request_status["reason_text"] = latest["reason_text"]
        status["last_request"] = request_status
    return status


def create_blueprint(config):
    bp = Blueprint("updates", __name__, url_prefix="/updates")

    @bp.get("/")
    @requires("view")
    def index():
        return render_template("updates.html", status=_display_status(config), current=version("cvebeacon"),
                               enabled=config.update.enabled, notice=unsupported_reason())

    @bp.post("/check")
    @requires("admin")
    def check_now():
        require_accounts()
        if not config.update.enabled:
            flash(
                "Release checks are turned off. An administrator can turn them on in the configuration.",
                "update_check_failed",
            )
            return redirect(url_for("updates.index"), code=303)
        try:
            result = check(config)
            current_app.extensions["dashboard_users"].record_action("update_check", username=g.user.username, actor=g.user.username)
        except (CVEBeaconError, OSError):
            flash("The release check failed. Try again later.", "update_check_failed")
            return redirect(url_for("updates.index"), code=303)
        available = result.get("available") if isinstance(result, dict) else None
        if isinstance(available, str) and available:
            message = f"Version {available} is available."
        else:
            checked_version = result.get("current") if isinstance(result, dict) else None
            if not isinstance(checked_version, str) or not checked_version:
                checked_version = version("cvebeacon")
            message = f"Checked just now. You have the latest release ({checked_version})."
        flash(message, "update_check")
        return redirect(url_for("updates.index"), code=303)

    @bp.post("/request")
    @requires("admin")
    def queue():
        require_accounts()
        if unsupported_reason():
            abort(400)
        try:
            request_update(config, _text(request.form, "version", required=True, limit=96), g.entry.proof,
                           current_app.extensions["dashboard_users"])
        except (CVEBeaconError, OSError):
            return render_template("error.html", code=400, service_error=True, message="Update request refused."), 400
        return redirect(url_for("updates.index"), code=303)

    return bp
