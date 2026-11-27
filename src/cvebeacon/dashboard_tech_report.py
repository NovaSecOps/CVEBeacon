"""Technology report and exports for the dashboard."""

import csv
from datetime import date
from io import BytesIO, StringIO
import json
import re
import unicodedata

from flask import Blueprint, abort, render_template, request, send_file

from .dashboard import requires
from .dashboard_web import _canonical_client
from .errors import CVEBeaconError
from .reporting import write_xlsx_tables
from .tech_report import (
    CONFIDENCE_CHOICES, EXPLOITATION, FIELDS, PAGE_CVES_PER_ROW, PAGE_ROWS, PRESETS, SEVERITIES,
    InvalidReportFilters, _arg, build_report,
)
from .web_assets import client_label
from .web_inventory_actions import STATUS_BADGES, STATUS_LABELS
from .xlsx_safety import neutralize_formula

TECHNOLOGY_COLUMNS = (
    ("site", "Site"), ("technology", "Technology"), ("versions", "Versions"),
    ("confidence", "Confidence"), ("status", "Status"),
)
SUMMARY_COLUMNS = (
    ("window_count", "CVEs in window"), ("current_count", "Total current CVEs"),
    ("severity", "Highest severity"), ("max_cvss", "Max CVSS"), ("cisa_kev", "CISA KEV"),
    ("eu_kev", "EU KEV"), ("exploitation", "Exploitation"), ("max_epss", "Max EPSS (%)"),
    ("newest_published", "Newest published"), ("first_found", "First found"),
)
CVE_COLUMNS = (
    ("cve_id", "CVE ID"), ("advisory_id", "Advisory ID"), ("summary", "Summary"),
    ("applicability", "Applicability"), ("severity", "Severity"), ("cvss_score", "CVSS"),
    ("cvss_version", "CVSS version"), ("epss_score", "EPSS (%)"),
    ("epss_percentile", "EPSS percentile (%)"), ("cisa_kev", "CISA KEV"), ("eu_kev", "EU KEV"),
    ("exploitation", "Exploitation"), ("exploitation_sources", "Exploitation sources"),
    ("published", "Published"), ("modified", "Last modified"), ("first_seen", "First found"),
    ("last_seen", "Last seen"), ("fixed_versions", "Fixed versions"), ("references", "References"),
)
MIMETYPES = {
    "csv": "text/csv",
    "json": "application/json",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
MAX_QUERY_BYTES = 8 * 1024


def _cells(record, columns):
    for key, _ in columns:
        value = record.get(key)
        if isinstance(value, (list, tuple)):
            value = ", ".join(value)
        elif value is not None:
            if key in {"max_epss", "epss_score", "epss_percentile"}:
                value = round(value * 100, 5)
            elif key == "status":
                value = STATUS_LABELS[value]
            elif key == "exploitation":
                value = EXPLOITATION[value]
        yield value


def _headers(columns):
    return tuple(label for _, label in columns)


def _cve_rows(report, *, include_empty=False):
    for row in report["technologies"]:
        technology = tuple(_cells(row, TECHNOLOGY_COLUMNS))
        if include_empty and row["window_count"] == 0 and report["filters"]["show_empty"]:
            yield (*technology, *(None for _ in CVE_COLUMNS))
        for cve in row["cves"]:
            yield (*technology, *_cells(cve, CVE_COLUMNS))


def _xlsx(report):
    payload = BytesIO()
    window = report["window"]
    dates = f"{window['from']} to {window['to']} UTC" if window["from"] else "All time"
    metadata = [
        ("Client", report["client"]), ("Window", f"{dates} · {FIELDS[window['field']]}"),
        ("Window type", window["kind"]), ("Generated at (UTC)", report["generated_at"]),
        ("Filters", json.dumps(report["filters"], ensure_ascii=False)),
    ]
    if report["cves_capped"]:
        metadata.append(("CVE details", "Capped at 50,000 CVE rows"))
    if report["notices"]:
        metadata.append(("Notices", " ".join(report["notices"])))
    columns = TECHNOLOGY_COLUMNS + SUMMARY_COLUMNS + (("coverage", "Findings coverage"),)
    write_xlsx_tables(payload, metadata, (
        ("Technologies", _headers(columns), (_cells(row, columns) for row in report["technologies"])),
        ("CVEs", _headers(TECHNOLOGY_COLUMNS + CVE_COLUMNS), _cve_rows(report)),
    ))
    payload.seek(0)
    return payload


def _csv(report):
    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(_headers(TECHNOLOGY_COLUMNS + CVE_COLUMNS))
    for row in _cve_rows(report, include_empty=True):
        writer.writerow(neutralize_formula(value) for value in row)
    return BytesIO(output.getvalue().encode("utf-8"))


def _json(report):
    result = {key: report[key] for key in ("client", "window", "generated_at", "filters", "technologies")}
    if report["notices"]:
        result["notices"] = report["notices"]
    return BytesIO(json.dumps(result, ensure_ascii=True, allow_nan=False).encode("utf-8"))


def _download_name(report, ext):
    name = unicodedata.normalize("NFKD", report["client"]).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:64].rstrip("-") or "client"
    start = report["window"]["from"] or "all"
    end = report["window"]["to"] or "all"
    return f"cvebeacon-{slug}-{start}-{end}.{ext}"


def _export_args(report):
    window, filters = report["window"], report["filters"]
    args = {
        "client": report["client"], "window": window["kind"], "field": window["field"],
        "show_empty": int(filters["show_empty"]),
    }
    for key in ("site", "category", "conf", "status", "severity", "kev", "exploited"):
        if filters[key]:
            args[key] = filters[key]
    if window["kind"] == "range":
        args.update({"from": window["from"], "to": window["to"]})
    elif window["kind"] != "all":
        args["end"] = window["to"]
        if window["kind"] == "days":
            args["days"] = (date.fromisoformat(window["to"]) - date.fromisoformat(window["from"])).days + 1
    return args


def create_blueprint(config):
    blueprint = Blueprint("tech_report", __name__, url_prefix="/web-assets/report")

    @blueprint.before_request
    def check_query_size():
        if len(request.query_string) > MAX_QUERY_BYTES:
            return "Report query string exceeds 8 KiB.", 414

    def required_option(name, limit):
        try:
            value = _arg(request.args, name, limit=limit).strip()
        except ValueError:
            abort(400)
        if not value:
            abort(400)
        return value

    def report(*, export=False):
        label = required_option("client", 256)
        try:
            client = _canonical_client(config, client_label(label))
        except (CVEBeaconError, OSError, ValueError):
            abort(400)
        try:
            return build_report(config, client, request.args, export=export)
        except InvalidReportFilters:
            abort(400)

    @blueprint.get("")
    @requires("view")
    def index():
        result = report()
        args = _export_args(result)
        windows = [(days, f"Last {days} days") for days in PRESETS] + [
            ("all", "All time"), ("days", "Custom last N days"), ("range", "Custom date range"),
        ]
        return render_template(
            "tech_report.html", report=result, export_args=args, windows=windows, fields=FIELDS,
            severities=[("any", "Any severity"), *((level, level.title()) for level in SEVERITIES[2:])],
            confidence_choices=CONFIDENCE_CHOICES,
            status_labels=STATUS_LABELS, status_badges=STATUS_BADGES, exploitation=EXPLOITATION,
            page_rows=PAGE_ROWS, page_cves=PAGE_CVES_PER_ROW, formats=MIMETYPES,
        )

    @blueprint.get("/export")
    @requires("view")
    def export():
        kind = required_option("format", 4)
        if kind not in MIMETYPES:
            abort(400)
        result = report(export=True)
        payload = {"csv": _csv, "json": _json, "xlsx": _xlsx}[kind](result)
        response = send_file(payload, as_attachment=True, download_name=_download_name(result, kind),
                             mimetype=MIMETYPES[kind])
        if result["cves_capped"] or result["findings_capped"]:
            response.headers["X-CVEBeacon-Report-Truncated"] = "true"
        if kind == "csv":
            response.headers["X-CVEBeacon-Report-Window"] = json.dumps(result["window"])
            if result["notices"]:
                response.headers["X-CVEBeacon-Report-Notices"] = " ".join(result["notices"])
        return response

    return blueprint
