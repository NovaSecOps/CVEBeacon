"""Dashboard operations: background jobs, channel tests and schedules."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from . import scheduling
from .config import AppConfig
from .dashboard_jobs import (
    FULL_HISTORY_OPERATIONS,
    MAX_HISTORY,
    OPERATION_LABELS,
    RETRY_OPERATIONS,
    RUN_OPERATIONS,
    JobManager,
    full_history_confirmation_required,
)
from .errors import CVEBeaconError, ConfigurationError
from .locking import RunInProgress


def requires(permission):
    """Declare route policy; the shared request guard enforces it centrally."""
    def decorate(function):
        function.dashboard_permissions = {"GET": permission, "POST": permission}
        return function
    return decorate


def _text(values, name: str, *, required=False, limit=256) -> str:
    if len(values.getlist(name)) > 1:
        abort(400)
    value = values.get(name, "").strip()
    if len(value) > limit or any(ord(char) < 32 for char in value) or (required and not value):
        abort(400)
    return value


def _password(values, name: str) -> str:
    items = values.getlist(name)
    if len(items) != 1 or len(items[0]) > 1024:
        abort(400)
    return items[0]


def _manager() -> JobManager:
    return current_app.extensions["dashboard_jobs"]


def _users():
    return current_app.extensions["dashboard_users"]


def _accounts() -> bool:
    return bool(getattr(g, "accounts", False)) and g.user is not None


def require_accounts() -> None:
    if not _accounts():
        abort(403)


def _runner():
    return current_app.extensions.get("dashboard_schedule_runner") or subprocess.run


def _actor() -> str:
    return g.user.username


def _record(action: str) -> None:
    _users().record_action(action, username=_actor(), actor=_actor())


def _operations_context(config: AppConfig, *, error: str | None = None) -> dict:
    manager = _manager()
    channels = tuple(
        channel.name for channel in config.watch.channels if channel.enabled
    )
    return {
        "error": error,
        "active": manager.store.active(),
        "full_history": full_history_confirmation_required(config),
        "channels": channels,
        "watch_enabled": config.watch.enabled,
        "has_inventory": config.inventory is not None,
        "operation_labels": {
            operation: _operation_label(operation) for operation in RUN_OPERATIONS
        },
        "retry_labels": {
            operation: _operation_label(operation) for operation in RETRY_OPERATIONS
        },
    }


def _operation_label(operation: str) -> str:
    return OPERATION_LABELS.get(operation, operation)


def _render_operations(config: AppConfig, *, error: str | None = None, status: int = 200):
    return render_template(
        "operations.html", **_operations_context(config, error=error)
    ), status


def _fallback_install_command(
    config: AppConfig,
    *,
    every: int = 4,
    times: str | None = None,
    command: str | None = None,
    run_logged_out: bool = False,
    account: str | None = None,
) -> str:
    target = command or scheduling.default_command(
        inventory=config.inventory is not None, watch=config.watch.enabled
    )
    parts = [
        sys.executable,
        "-m",
        "cvebeacon",
        "--config",
        str(config.config_path),
        "schedule",
        "install",
    ]
    if times:
        parts.extend(["--times", times])
    else:
        parts.extend(["--every", str(every)])
    parts.extend(["--command", target])
    if run_logged_out:
        parts.append("--run-logged-out")
        if account:
            parts.extend(["--account", account])
        parts.append("--password-stdin")
    parts.append("--yes")
    if os.name == "nt":
        return subprocess.list2cmdline(parts)
    return shlex.join(parts)


def _running_as_root() -> bool:
    return (
        os.name == "posix"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
    )


def _install_block_reason() -> str | None:
    system = scheduling.platform.system().casefold()
    if system not in {"windows", "linux"}:
        return (
            "This host is not Windows or Linux, so the dashboard cannot manage "
            "a native schedule here."
        )
    if _running_as_root():
        return (
            "The dashboard is running as root. A schedule installed here would "
            "run as root, which is usually not the account that should own "
            "monitoring work."
        )
    return None


def _schedule_context(
    config: AppConfig,
    *,
    error: str | None = None,
    fallback_command: str | None = None,
) -> dict:
    runner = _runner()
    status_text = ""
    status_error = None
    try:
        status_text = scheduling.status(run=runner)
    except (CVEBeaconError, OSError) as exc:
        status_error = str(exc)
    return {
        "error": error,
        "status_text": status_text,
        "status_error": status_error,
        "platform_name": scheduling.platform.system(),
        "fallback_command": fallback_command or _fallback_install_command(config),
        "block_reason": _install_block_reason(),
        "default_command": scheduling.default_command(
            inventory=config.inventory is not None, watch=config.watch.enabled
        ),
        "has_inventory": config.inventory is not None,
        "watch_enabled": config.watch.enabled,
    }


def _render_schedule(
    config: AppConfig,
    *,
    error: str | None = None,
    status: int = 200,
    fallback_command: str | None = None,
):
    return render_template(
        "schedule.html",
        **_schedule_context(
            config, error=error, fallback_command=fallback_command
        ),
    ), status


def create_blueprint(config: AppConfig) -> Blueprint:
    blueprint = Blueprint("operations", __name__, url_prefix="/operations")

    @blueprint.record_once
    def setup(state):
        app = state.app
        app.extensions["dashboard_jobs"] = JobManager(
            config, app.extensions["dashboard_users"]
        )
        app.extensions.setdefault("dashboard_schedule_runner", None)

    @blueprint.get("/")
    @requires("view")
    def index():
        return _render_operations(config)

    @blueprint.get("/jobs")
    @requires("view")
    def jobs():
        return render_template(
            "jobs.html",
            jobs=_manager().store.recent(MAX_HISTORY),
            max_jobs=MAX_HISTORY,
        )

    @blueprint.get("/jobs/<int:job_id>")
    @requires("view")
    def job_detail(job_id: int):
        if not 1 <= job_id <= 2**63 - 1:
            abort(404)
        job = _manager().store.get(job_id)
        if job is None:
            abort(404)
        return render_template(
            "job.html", job=job, log=_manager().store.log_tail(job)
        )

    @blueprint.post("/run")
    @requires("run")
    def run_job():
        require_accounts()
        operation = _text(request.form, "operation", required=True, limit=32)
        if operation not in RUN_OPERATIONS:
            abort(400)
        confirmed = _text(request.form, "confirm") == "full-history"
        if (
            operation in FULL_HISTORY_OPERATIONS
            and full_history_confirmation_required(config)
            and not confirmed
        ):
            return _render_operations(
                config,
                error=(
                    "Full-history initial sync needs explicit confirmation. "
                    "Review the warning and use the confirmed form."
                ),
                status=409,
            )
        try:
            argv = _manager().command_builder(
                config, operation, confirmed=confirmed
            )
            job = _manager().submit(
                operation, started_by=_actor(), argv=argv
            )
        except RunInProgress as exc:
            return _render_operations(config, error=str(exc), status=409)
        except ConfigurationError as exc:
            return _render_operations(config, error=str(exc), status=400)
        return redirect(url_for("operations.job_detail", job_id=job.id), code=303)

    @blueprint.post("/retry")
    @requires("retry")
    def retry_jobs():
        require_accounts()
        operation = _text(request.form, "operation", required=True, limit=32)
        if operation not in RETRY_OPERATIONS:
            abort(400)
        try:
            argv = _manager().command_builder(config, operation)
            job = _manager().submit(
                operation, started_by=_actor(), argv=argv
            )
        except RunInProgress as exc:
            return _render_operations(config, error=str(exc), status=409)
        except ConfigurationError as exc:
            return _render_operations(config, error=str(exc), status=400)
        return redirect(url_for("operations.job_detail", job_id=job.id), code=303)

    @blueprint.post("/test")
    @requires("test_channel")
    def test_channel():
        require_accounts()
        channel = _text(request.form, "channel", required=True, limit=64)
        enabled = {
            item.name for item in config.watch.channels if item.enabled
        }
        if channel not in enabled:
            abort(400)
        try:
            argv = _manager().command_builder(
                config, "notify-test", channel=channel
            )
            job = _manager().submit(
                "notify-test", started_by=_actor(), argv=argv
            )
        except RunInProgress as exc:
            return _render_operations(config, error=str(exc), status=409)
        except ConfigurationError as exc:
            return _render_operations(config, error=str(exc), status=400)
        return redirect(url_for("operations.job_detail", job_id=job.id), code=303)

    @blueprint.post("/jobs/<int:job_id>/cancel")
    @requires("run")
    def cancel_job(job_id: int):
        require_accounts()
        if not 1 <= job_id <= 2**63 - 1:
            abort(404)
        if not _manager().cancel(job_id):
            abort(404)
        return redirect(url_for("operations.job_detail", job_id=job_id), code=303)

    @blueprint.get("/schedule")
    @requires("manage_schedule")
    def schedule():
        require_accounts()
        return _render_schedule(config)

    @blueprint.post("/schedule/install")
    @requires("manage_schedule")
    def schedule_install():
        require_accounts()
        blocked = _install_block_reason()
        if blocked:
            return _render_schedule(
                config,
                error=blocked
                + " Use the command-line fallback below from the intended account.",
                status=400,
            )
        mode = _text(request.form, "mode", required=True, limit=16)
        if mode not in {"interval", "times"}:
            abort(400)
        command = _text(request.form, "command", required=True, limit=16)
        if command in {"watch", "both"} and not config.watch.enabled:
            return _render_schedule(
                config, error="watch mode is disabled; set [watch] enabled = true", status=400
            )
        if command in {"scan", "both"} and config.inventory is None:
            return _render_schedule(
                config, error="this configuration has no inventory; choose watch", status=400
            )
        run_logged_out = _text(request.form, "run_logged_out") == "yes"
        account = _text(request.form, "account", limit=256)
        password = _password(request.form, "password") if run_logged_out else None
        times_value = ""
        every_value = 4
        if mode == "times":
            times_value = _text(request.form, "times", required=True, limit=200)
        else:
            raw = _text(request.form, "every", required=True, limit=8)
            try:
                every_value = int(raw)
            except ValueError:
                password = None
                return _render_schedule(
                    config,
                    error="schedule interval must look like 4",
                    status=400,
                )
        fallback = _fallback_install_command(
            config,
            every=every_value,
            times=times_value or None,
            command=command,
            run_logged_out=run_logged_out,
            account=account or None,
        )
        try:
            if mode == "times":
                plan = scheduling.make_plan(
                    config.config_path,
                    times=times_value,
                    command=command,
                    run_logged_out=run_logged_out,
                    account=account or None,
                )
            else:
                plan = scheduling.make_plan(
                    config.config_path,
                    every_value,
                    command=command,
                    run_logged_out=run_logged_out,
                    account=account or None,
                )
            if plan.run_logged_out:
                if not password:
                    raise ConfigurationError(
                        "the Windows account password is required for a "
                        "logged-out schedule"
                    )
                scheduling.install(plan, password=password, run=_runner())
            else:
                scheduling.install(plan, run=_runner())
            try:
                _record("schedule_installed")
            except CVEBeaconError:
                pass
        except (CVEBeaconError, OSError) as exc:
            detail = str(exc)
            if password:
                detail = detail.replace(password, "[redacted]")
            return _render_schedule(
                config, error=detail, status=400, fallback_command=fallback
            )
        finally:
            password = None
        return redirect(url_for("operations.schedule"), code=303)

    @blueprint.post("/schedule/remove")
    @requires("manage_schedule")
    def schedule_remove():
        require_accounts()
        if _text(request.form, "confirm", required=True, limit=16) != "remove":
            abort(400)
        try:
            removed = scheduling.remove(run=_runner())
            try:
                _record("schedule_removed" if removed else "schedule_remove_skipped")
            except CVEBeaconError:
                pass
        except (CVEBeaconError, OSError) as exc:
            return _render_schedule(config, error=str(exc), status=400)
        return redirect(url_for("operations.schedule"), code=303)

    return blueprint
