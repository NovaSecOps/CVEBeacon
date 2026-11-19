"""Administrator backup controls and view-only backup status."""

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, send_file, url_for

from .backup import (
    BackupBusy,
    BackupError,
    build_archive,
    list_backups,
    prune,
    summary,
)
from .dashboard_jobs import JobQueueFull
from .dashboard_ops import _text, require_accounts, requires
from .errors import ConfigurationError
from .locking import RunInProgress


def _manager():
    return current_app.extensions["dashboard_jobs"]


def _can_admin() -> bool:
    return bool(getattr(g, "accounts", False)) and g.user is not None and g.user.is_admin


def _record(action: str, detail: str | None = None) -> None:
    if getattr(g, "accounts", False) and g.user is not None:
        _manager().audit_action(action, g.user.username, detail)


def create_blueprint(config):
    blueprint = Blueprint("backups", __name__, url_prefix="/backups")

    def _render(error: str | None = None, status: int = 200):
        try:
            backups = list_backups(config)
            stats = summary(config)
        except BackupError as exc:
            backups, stats, error = [], {"count": 0, "last": None, "last_id": None, "total_size": 0}, error or str(exc)
        try:
            active = _manager().store.active()
        except Exception:
            active = ()
        return render_template(
            "backups.html",
            backups=backups,
            stats=stats,
            error=error,
            active=active,
            can_admin=_can_admin(),
            retention_days=config.backup.retention_days,
            keep_min=config.backup.keep_min,
        ), status

    @blueprint.get("/")
    @requires("view")
    def index():
        return _render()

    def _submit(operation: str, *, backup_id: str | None = None,
                include_secrets: bool = False, action: str):
        require_accounts()
        detail = backup_id or "new"
        if operation == "backup-create" and include_secrets:
            detail += ":secrets"
        _record(action, detail)
        try:
            argv = _manager().command_builder(
                config, operation, backup_id=backup_id,
                include_secrets=include_secrets,
                created_by=g.user.username if operation == "backup-create" else None,
            )
            job = _manager().submit(
                operation, started_by=g.user.username, argv=argv
            )
        except (RunInProgress, JobQueueFull) as exc:
            return _render(str(exc), status=409)
        except (BackupError, ConfigurationError) as exc:
            return _render(str(exc), status=400)
        return redirect(url_for("operations.job_detail", job_id=job.id), code=303)

    def _known(backup_id: str) -> bool:
        try:
            return any(backup.id == backup_id for backup in list_backups(config))
        except BackupError as exc:
            abort(400, str(exc))

    @blueprint.post("/create")
    @requires("admin")
    def create_backup():
        include = _text(request.form, "include_secrets", limit=8) == "yes"
        return _submit(
            "backup-create", include_secrets=include,
            action="backup_create_requested",
        )

    @blueprint.post("/verify")
    @requires("admin")
    def verify_backup():
        backup_id = _text(request.form, "backup_id", required=True, limit=64)
        if not _known(backup_id):
            abort(404)
        return _submit(
            "backup-verify", backup_id=backup_id,
            action="backup_verify_requested",
        )

    @blueprint.post("/restore")
    @requires("admin")
    def restore_backup():
        backup_id = _text(request.form, "backup_id", required=True, limit=64)
        if not _known(backup_id):
            abort(404)
        if _text(request.form, "confirm", required=True, limit=64) != backup_id:
            abort(400)
        return _submit(
            "backup-restore", backup_id=backup_id,
            action="backup_restore_requested",
        )

    @blueprint.post("/prune")
    @requires("admin")
    def prune_backups():
        require_accounts()
        _record("backup_prune_requested")
        try:
            result = prune(config)
        except BackupBusy as exc:
            return _render(str(exc), status=409)
        except BackupError as exc:
            return _render(str(exc), status=400)
        _record("backup_prune", f"removed={len(result['removed'])}")
        return redirect(url_for("backups.index"), code=303)

    @blueprint.post("/download")
    @requires("admin")
    def download_backup():
        require_accounts()
        backup_id = _text(request.form, "backup_id", required=True, limit=64)
        if not _known(backup_id):
            abort(404)
        _record("backup_download_requested", backup_id)
        try:
            stream = build_archive(config, backup_id)
        except BackupBusy as exc:
            return _render(str(exc), status=409)
        except BackupError as exc:
            return _render(str(exc), status=400)
        try:
            _record("backup_download", backup_id)
        except BaseException:
            stream.close()
            raise
        suffix = ".tar.gz" if config.backup.compress else ".tar"
        return send_file(
            stream,
            as_attachment=True,
            download_name=f"cvebeacon-backup-{backup_id}{suffix}",
            mimetype="application/gzip" if config.backup.compress else "application/x-tar",
        )

    return blueprint
