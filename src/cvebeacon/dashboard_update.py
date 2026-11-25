"""Read-only release status and administrator-only update requests."""
from importlib.metadata import version

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from .dashboard_ops import _text, requires, require_accounts
from .errors import CVEBeaconError
from .updater import check, read_status, request_update, unsupported_reason


def create_blueprint(config):
    bp = Blueprint("updates", __name__, url_prefix="/updates")

    @bp.get("/")
    @requires("view")
    def index():
        return render_template("updates.html", status=read_status(config), current=version("cvebeacon"),
                               enabled=config.update.enabled, notice=unsupported_reason())

    @bp.post("/check")
    @requires("admin")
    def check_now():
        require_accounts()
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
