"""Dashboard pages and actions over the watch database.

The routes live in a separate blueprint so the inventory dashboard and the
watch views can evolve independently.  They reuse the watch store, status
helpers, report service and statement renderer rather than defining a second
set of queries or a second identity system.
"""

from __future__ import annotations

import csv
from datetime import date
from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
from urllib.parse import quote

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    send_file,
    stream_with_context,
    url_for,
)

from .config import AppConfig
from .dashboard import _text, requires
from .errors import CVEBeaconError, ConfigurationError, StateError
from .locking import RunInProgress, RunLock, run_lock_path
from .watch.messages import CVE_URL, EUVD_URL, NVD_URL
from .watch.reported import format_timestamp, identity_label, normalize_cve_id
from .watch.reporting import ReportService
from .watch.rules import EVENT_KINDS
from .watch.statements import (
    default_template_text,
    template_kind,
    write_statement,
)
from .watch.store import EventDeliveries, WatchStore
from .watch.sync import euvd_progress

STATE_KEY = "dashboard_watch"
MAX_STATEMENT_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_REQUEST_BYTES = MAX_STATEMENT_UPLOAD_BYTES + 64 * 1024
EVENT_PAGE_SIZE = 50
REPORT_PAGE_SIZE = 100
TRAIL_PAGE_SIZE = 50
EXPORT_BATCH = 1000
MAX_PAGE = 100_000
MARKS = {
    "reported": "The report was recorded.",
    "unreported": "The report was withdrawn.",
    "already": "This CVE was already reported to clients.",
    "not_reported": "This CVE is not currently reported to clients.",
}

bp = Blueprint("watch", __name__, url_prefix="/watch")


def register_watch(app, config: AppConfig) -> None:
    """Attach the watch blueprint and its per-application state."""
    app.config["MAX_CONTENT_LENGTH"] = max(
        int(app.config.get("MAX_CONTENT_LENGTH") or 0), MAX_REQUEST_BYTES
    )

    def limit_request_body():
        # Statement uploads stream to a temporary file and are bounded by the
        # view. Every other route keeps the original small form limits. The
        # multipart decoder applies max_form_memory_size to its whole buffer,
        # file parts included, so the statement request needs the larger value
        # before the shared CSRF guard parses the form.
        if request.endpoint == "watch.statement":
            request.max_content_length = MAX_REQUEST_BYTES
            request.max_form_memory_size = MAX_REQUEST_BYTES
        else:
            request.max_content_length = 8192
            request.max_form_memory_size = 8192

    # This runs before the shared request guard and its CSRF form read,
    # because the blueprint is registered before that guard is defined.
    app.before_request(limit_request_body)
    app.extensions[STATE_KEY] = {
        "config": config,
        "store": WatchStore(config.watch.database),
    }
    app.jinja_env.globals["watch_stamp"] = _stamp
    app.jinja_env.globals["watch_identity"] = identity_label
    app.register_blueprint(bp)


def _state():
    state = current_app.extensions.get(STATE_KEY)
    if not isinstance(state, dict):
        raise StateError("watch dashboard state is unavailable")
    return state["config"], state["store"]


def _stamp(value: str | None) -> str:
    return format_timestamp(value) if value else ""


def _page_number(name: str = "page") -> int:
    raw = _text(request.args, name) or "1"
    if not raw.isascii() or not raw.isdigit() or not 1 <= int(raw) <= MAX_PAGE:
        abort(400)
    return int(raw)


def _date_filter(name: str) -> date | None:
    raw = _text(request.args, name)
    if not raw:
        return None
    try:
        parsed = date.fromisoformat(raw)
    except ValueError:
        abort(400)
    if parsed == date.max:
        abort(400)
    return parsed


def _cve_from_path(value: str) -> str:
    try:
        return normalize_cve_id(value)
    except ConfigurationError:
        abort(404)


def _reporting(config: AppConfig, store: WatchStore) -> ReportService:
    return ReportService(
        store,
        config.watch.users_database,
        config.watch.reporting_identity,
    )


def _notify_channels(config: AppConfig) -> tuple[str, ...]:
    return tuple(
        channel.name
        for channel in config.watch.channels
        if channel.enabled and channel.notify_reported
    )


def _identity_arguments(config: AppConfig) -> dict[str, object]:
    """Bind a report to the authenticated browser session, never a form field."""
    if g.user is None or g.entry is None or g.entry.proof is None:
        abort(403)
    if config.watch.reporting_identity == "authenticated":
        return {"session": g.entry.proof}
    # Open and registered modes record a name, but the session proof still
    # authorizes the write and is rechecked inside the report transaction.
    return {"by": g.user.username, "session": g.entry.proof}


def _can_report() -> bool:
    return g.user is not None and "report" in g.permissions


def _can_statement() -> bool:
    return not g.accounts or "statement" in g.permissions


def _can_export() -> bool:
    return not g.accounts or "view_audit" in g.permissions


def _cve_context(
    identifier: str,
    *,
    error: str | None = None,
    status: int = 200,
):
    config, store = _state()
    view = store.view(identifier, catalogs=config.watch.sources)
    if view is None:
        abort(404)
    events = store.events(limit=EVENT_PAGE_SIZE, cve=identifier)
    trail_page = _page_number("trail_page")
    trail = store.report_trail(
        identifier,
        limit=TRAIL_PAGE_SIZE + 1,
        offset=(trail_page - 1) * TRAIL_PAGE_SIZE,
    )
    trail_has_next = len(trail) > TRAIL_PAGE_SIZE
    trail = trail[:TRAIL_PAGE_SIZE]
    deliveries = store.event_deliveries(
        (event.id for event in events), per_event=20
    )
    notices = store.notice_deliveries_for(
        identifier,
        (f"{entry.action}:{entry.id}" for entry in trail),
        per_notice=20,
    )
    mark = store.reported_marks((identifier,)).get(identifier)
    banner_key = _text(request.args, "mark")
    banner = MARKS.get(banner_key)
    if banner_key in {"reported", "already"} and mark is None:
        banner = None
    if banner_key in {"unreported", "not_reported"} and mark is not None:
        banner = None
    return render_template(
        "watch_cve.html",
        cve_id=identifier,
        view=view,
        event_rows=[
            {
                "event": row,
                "deliveries": deliveries.get(row.id, EventDeliveries()),
            }
            for row in events
        ],
        trail_rows=[
            {
                "entry": entry,
                "notices": notices.get(
                    (entry.action, entry.id), EventDeliveries()
                ),
            }
            for entry in trail
        ],
        mark_entry=mark,
        trail_page=trail_page,
        trail_page_size=TRAIL_PAGE_SIZE,
        trail_has_previous=trail_page > 1,
        trail_has_next=trail_has_next,
        banner=banner,
        error=error,
        can_report=_can_report(),
        can_statement=_can_statement(),
        nvd_url=NVD_URL.format(cve_id=identifier),
        cve_org_url=CVE_URL.format(cve_id=identifier),
        euvd_url=(
            EUVD_URL.format(euvd_id=quote(view.euvd_id, safe="-_."))
            if view.euvd_id
            else None
        ),
    ), status


@bp.get("")
@requires("view")
def overview():
    config, store = _state()
    status = store.status(catalogs=config.watch.sources)
    meta = status["meta"]
    sources = []
    for name in config.watch.sources:
        prefix = f"sync_{name}_"
        at = meta.get(f"{prefix}at")
        sources.append(
            {
                "source": name,
                "at": _stamp(at),
                "requests": meta.get(f"{prefix}requests", ""),
                "records": meta.get(f"{prefix}records", ""),
                "new": meta.get(f"{prefix}new", ""),
                "changed": meta.get(f"{prefix}changed", ""),
                "error": meta.get(f"{prefix}error", ""),
            }
        )
    initial_mode = meta.get("initial_mode", "")
    return render_template(
        "watch_overview.html",
        status=status,
        meta=meta,
        sources=sources,
        deliveries=store.delivery_status(
            channel.name for channel in config.watch.channels
        ),
        euvd_progress=euvd_progress(meta),
        initial={
            "mode": initial_mode or "not initialized",
            "window_start": meta.get("initial_window_start", ""),
            "initialized_at": _stamp(meta.get("initialized_at")),
            "sync_completed_at": _stamp(meta.get("initial_sync_completed_at")),
            "evaluated_at": _stamp(meta.get("initial_evaluated_at")),
            "sync_pending": bool(initial_mode and not meta.get("initial_sync_completed_at")),
            "evaluation_pending": bool(initial_mode and not meta.get("initial_evaluated_at")),
        },
        last_sync_at=_stamp(meta.get("last_sync_at")),
        failures=meta.get("last_sync_failures", ""),
        watch_enabled=config.watch.enabled,
    )


@bp.get("/events")
@requires("view")
def events():
    config, store = _state()
    filters = {
        key: _text(request.args, key)
        for key in ("rule", "kind", "initial", "since", "until", "cve", "pending")
    }
    if filters["kind"] and filters["kind"] not in EVENT_KINDS:
        abort(400)
    if filters["initial"] not in {"", "yes", "no"}:
        abort(400)
    if filters["pending"] not in {"", "yes", "no"}:
        abort(400)
    since, until = _date_filter("since"), _date_filter("until")
    if since is not None and until is not None and since > until:
        abort(400)
    cve = None
    if filters["cve"]:
        try:
            cve = normalize_cve_id(filters["cve"])
        except ConfigurationError:
            abort(400)
    pending = (
        None
        if filters["pending"] == "no"
        else True
        if filters["pending"] == "yes"
        else False
    )
    initial = (
        None
        if filters["initial"] not in {"yes", "no"}
        else filters["initial"] == "yes"
    )
    page = _page_number()
    rows = store.events(
        limit=EVENT_PAGE_SIZE + 1,
        rule=filters["rule"] or None,
        pending=pending,
        kind=filters["kind"] or None,
        initial=initial,
        cve=cve,
        since=since,
        until=until,
        offset=(page - 1) * EVENT_PAGE_SIZE,
    )
    has_next = len(rows) > EVENT_PAGE_SIZE
    rows = rows[:EVENT_PAGE_SIZE]
    marks = store.reported_marks({row.cve_id for row in rows})
    return render_template(
        "watch_events.html",
        rows=rows,
        marks=marks,
        filters=filters,
        kinds=EVENT_KINDS,
        rule_names=[rule.name for rule in config.watch.rules],
        page=page,
        has_previous=page > 1,
        has_next=has_next,
    )


@bp.get("/cve/<cve_id>")
@requires("view")
def cve(cve_id):
    return _cve_context(_cve_from_path(cve_id))


@bp.post("/cve/<cve_id>/report")
@requires("report")
def report_cve(cve_id):
    config, store = _state()
    identifier = _cve_from_path(cve_id)
    try:
        with RunLock(run_lock_path(config), command="watch report"):
            if store.view(identifier, catalogs=config.watch.sources) is None:
                abort(404)
            note = _text(request.form, "note", limit=500)
            outcome = _reporting(config, store).report_cve(
                identifier,
                note=note,
                notify_channels=_notify_channels(config),
                **_identity_arguments(config),
            )
    except RunInProgress as exc:
        return _cve_context(identifier, error=str(exc), status=409)
    except ConfigurationError as exc:
        return _cve_context(identifier, error=str(exc), status=400)
    except StateError:
        abort(404)
    return redirect(
        url_for(
            "watch.cve",
            cve_id=identifier,
            mark="reported" if outcome.changed else "already",
        ),
        code=303,
    )


@bp.post("/cve/<cve_id>/unreport")
@requires("report")
def unreport_cve(cve_id):
    config, store = _state()
    identifier = _cve_from_path(cve_id)
    try:
        with RunLock(run_lock_path(config), command="watch unreport"):
            if store.view(identifier, catalogs=config.watch.sources) is None:
                abort(404)
            note = _text(request.form, "note", limit=500)
            outcome = _reporting(config, store).unreport_cve(
                identifier,
                note=note,
                notify_channels=_notify_channels(config),
                **_identity_arguments(config),
            )
    except RunInProgress as exc:
        return _cve_context(identifier, error=str(exc), status=409)
    except ConfigurationError as exc:
        return _cve_context(identifier, error=str(exc), status=400)
    except StateError:
        abort(404)
    return redirect(
        url_for(
            "watch.cve",
            cve_id=identifier,
            mark="unreported" if outcome.changed else "not_reported",
        ),
        code=303,
    )


@bp.get("/reported")
@requires("view")
def reported():
    _, store = _state()
    page = _page_number()
    rows = store.reported_cves(
        limit=REPORT_PAGE_SIZE + 1,
        offset=(page - 1) * REPORT_PAGE_SIZE,
    )
    has_next = len(rows) > REPORT_PAGE_SIZE
    return render_template(
        "watch_reported.html",
        rows=rows[:REPORT_PAGE_SIZE],
        page=page,
        has_previous=page > 1,
        has_next=has_next,
        can_export=_can_export(),
    )


@bp.get("/reported/export")
@requires("view_audit")
def export_reported():
    _, store = _state()
    kind = _text(request.args, "format") or "csv"
    if kind not in {"csv", "json"}:
        abort(400)
    from .cli import (
        _REPORT_EXPORT_FIELDS,
        _csv_cell,
        _report_export_record,
    )

    def rows():
        offset = 0
        while True:
            batch = store.reported_entries(limit=EXPORT_BATCH, offset=offset)
            if not batch:
                return
            yield from batch
            if len(batch) < EXPORT_BATCH:
                return
            offset += len(batch)

    if kind == "json":
        def generate():
            yield "["
            first = True
            for entry in rows():
                record = _report_export_record(entry)
                yield ("" if first else ",") + json.dumps(
                    record, ensure_ascii=False
                )
                first = False
            yield "]\n"

        response = Response(
            stream_with_context(generate()), mimetype="application/json"
        )
        filename = "cvebeacon-reported.json"
    else:
        def generate():
            buffer = StringIO()
            writer = csv.writer(buffer, lineterminator="\n")
            writer.writerow(_REPORT_EXPORT_FIELDS)
            yield buffer.getvalue()
            for entry in rows():
                record = _report_export_record(entry)
                buffer.seek(0)
                buffer.truncate(0)
                writer.writerow(
                    [
                        _csv_cell(record[field])
                        for field in _REPORT_EXPORT_FIELDS
                    ]
                )
                yield buffer.getvalue()

        response = Response(
            stream_with_context(generate()), mimetype="text/csv"
        )
        filename = "cvebeacon-reported.csv"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{filename}"'
    )
    return response


def _statement_error(exc: CVEBeaconError, directory: str) -> str:
    """Keep template feedback but never echo a temporary filesystem path."""
    message = str(exc)
    if directory and directory in message:
        return (
            "The statement could not be generated because a temporary file "
            "could not be read or written."
        )
    return message


def _save_upload(upload, path: Path) -> None:
    total = 0
    try:
        with open(path, "xb") as handle:
            while True:
                chunk = upload.stream.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_STATEMENT_UPLOAD_BYTES:
                    abort(413)
                handle.write(chunk)
    except OSError as exc:
        raise CVEBeaconError(
            "could not read the uploaded statement template"
        ) from exc
    if total == 0:
        raise CVEBeaconError("the uploaded statement template is empty")


def _statement_page(identifier: str, *, error: str | None = None, status: int = 200):
    config, store = _state()
    view = store.view(identifier, catalogs=config.watch.sources)
    if view is None:
        abort(404)
    return render_template(
        "watch_statement.html",
        cve_id=identifier,
        view=view,
        builtin=default_template_text(),
        error=error,
        max_upload=MAX_STATEMENT_UPLOAD_BYTES,
        mark_entry=store.reported_marks((identifier,)).get(identifier),
    ), status


@bp.route("/cve/<cve_id>/statement", methods=["GET", "POST"])
@requires("statement")
def statement(cve_id):
    config, store = _state()
    identifier = _cve_from_path(cve_id)
    if request.method == "GET":
        return _statement_page(identifier)
    if store.view(identifier, catalogs=config.watch.sources) is None:
        abort(404)
    choice = _text(request.form, "template", required=True)
    if choice not in {"builtin", "upload"}:
        abort(400)
    template_path: Path | None = None
    output_suffix = ".md"
    with tempfile.TemporaryDirectory(prefix="cvebeacon-statement-") as directory:
        if choice == "upload":
            uploads = request.files.getlist("template_file")
            if len(uploads) != 1 or not uploads[0].filename:
                return _statement_page(
                    identifier,
                    error="Choose one .md, .txt, or .docx template.",
                    status=400,
                )
            upload = uploads[0]
            try:
                kind = template_kind(Path(upload.filename))
            except CVEBeaconError as exc:
                return _statement_page(
                    identifier, error=str(exc), status=400
                )
            suffix = Path(upload.filename).suffix.casefold()
            template_path = Path(directory) / f"template{suffix}"
            output_suffix = ".docx" if kind == "docx" else ".md"
            try:
                _save_upload(upload, template_path)
            except CVEBeaconError as exc:
                return _statement_page(
                    identifier, error=str(exc), status=400
                )
        output = Path(directory) / f"statement{output_suffix}"
        try:
            write_statement(
                store,
                identifier,
                catalogs=config.watch.sources,
                template=template_path,
                out=output,
            )
            payload = output.read_bytes()
        except CVEBeaconError as exc:
            return _statement_page(
                identifier,
                error=_statement_error(exc, directory),
                status=400,
            )
    return send_file(
        BytesIO(payload),
        as_attachment=True,
        download_name=f"{identifier}-statement{output_suffix}",
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "wordprocessingml.document"
            if output_suffix == ".docx"
            else "text/markdown"
        ),
    )
