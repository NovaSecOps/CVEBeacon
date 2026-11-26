"""Read-only release status and administrator-only update requests."""
from importlib.metadata import version

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from .dashboard_ops import _text, requires, require_accounts
from .errors import CVEBeaconError
from .updater import EARLIEST, MAX_NOTES, check, diagnostic_version, read_status, request_update, status_time, unsupported_reason


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
    "adopt-failed": "The updater could not finish adopting the installation.",
    "finalize-timers-failed": "The updater could not restart the timers after committing the transaction.",
    "finalize-archive-failed": "The updater could not archive the completed transaction.",
    "finalize-cleanup-failed": "Update cleanup needs administrator review.",
    "policy-invalid": "The administrator's update policy could not be loaded.",
    "request-invalid": "The dashboard update request was invalid.",
    "request-claim-failed": "The updater could not claim the dashboard update request.",
    "version-invalid": "The updater requires a canonical release version.",
    "update-failed": "The updater could not complete the requested operation.",
}


def _strip_comments(notes):
    """Scan once and discard complete or unterminated nested comments."""
    notes = notes[:MAX_NOTES]
    parts = []
    cursor = depth = 0
    while cursor < len(notes):
        if depth == 0:
            opening = notes.find("<!--", cursor)
            if opening == -1:
                parts.append(notes[cursor:])
                break
            parts.append(notes[cursor:opening])
            cursor = opening
        if notes.startswith("<!--", cursor):
            cursor += 4
            if notes.startswith(">", cursor):
                cursor += 1
            elif notes.startswith("->", cursor):
                cursor += 2
            else:
                depth += 1
        elif notes.startswith(("-->", "--!>"), cursor):
            cursor += 4 if notes.startswith("--!>", cursor) else 3
            depth -= 1
        else:
            cursor += 1
    return "".join(parts).strip()


def _reason_text(code):
    return UPDATE_REASON_TEXT.get(code) if isinstance(code, str) else None


def _display_status(config):
    persisted = read_status(config)
    status = {key: persisted[key] for key in ("notes", "available", "last_check",
                                             "last_update", "last_request", "last_attempt") if key in persisted}
    notes = status.get("notes")
    status["notes"] = _strip_comments(notes) if isinstance(notes, str) else ""
    status["available"] = diagnostic_version(status.get("available"))
    checked = status_time(status, "last_check")
    status["last_check"] = checked.strftime("%Y-%m-%d %H:%M UTC") if checked is not None else ""
    attempts = []
    for key in ("last_update", "last_request", "last_attempt"):
        value = status.get(key)
        if not isinstance(value, dict):
            status.pop(key, None)
            continue
        entry = dict(value)
        entry["reason_text"] = _reason_text(entry.get("reason"))
        when = status_time(entry)
        entry["time_display"] = when.strftime("%Y-%m-%d %H:%M UTC") if when is not None else ""
        status[key] = entry
        attempts.append((when or EARLIEST, entry))

    _, latest = max(attempts, key=lambda item: item[0], default=(EARLIEST, {}))
    update = status.get("last_update", {})
    recovery = _reason_text(update.get("recovery_reason"))
    finalization = _reason_text(update.get("finalization_reason"))
    warning = update.get("warning")
    if recovery and update.get("result") == "rollback-failed":
        status["recovery_text"] = UPDATE_REASON_TEXT["recovery-incomplete"]
        if recovery != status["recovery_text"]:
            status["recovery_detail"] = recovery
    elif recovery:
        status["recovery_text"] = recovery
    elif update.get("reason") == "recovery-incomplete":
        status["recovery_text"] = update["reason_text"]
    elif not finalization and warning == "completed update recovery could not verify the selected release":
        status["recovery_text"] = "Recovery could not verify the selected release."

    if finalization:
        status["finalization_text"] = finalization
        status["finalization_recover"] = update.get("finalization_reason") in (
            "finalize-timers-failed", "finalize-archive-failed")
    elif not status.get("recovery_text"):
        if warning == "update committed; run update recover to finish finalization":
            status["finalization_text"] = "The update was committed and finalization still needs to finish."
            status["finalization_recover"] = True
        elif warning == "update committed; temporary-file cleanup needs administrator review":
            status["finalization_text"] = UPDATE_REASON_TEXT["finalize-cleanup-failed"]

    if latest.get("reason_text") and not (
        status.get("recovery_text") and (latest is update or latest.get("reason") == "recovery-incomplete")
    ):
        status["failure"] = latest["reason_text"]
        status["failure_action"] = "recover" if latest.get("reason") == "recovery-incomplete" else "apply"
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
