"""Guided alert-channel setup: type, details, review, then the test step.

The wizard never writes the configuration itself. It builds the same posted
values the full channels page sends, then reuses ``parse_form``,
``Editor.preview`` and ``Editor.commit`` so CSRF, permissions, lockout
confirmation, secret staging/redaction, backups, audit and locks stay in one
place. The test step lives in ``dashboard_ops`` and is linked only when its
endpoint exists.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import difflib

from flask import abort, current_app, g, redirect, render_template, request, url_for
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import HTTPException

from .dashboard_config import (
    FieldValidationError,
    dumps,
    get_table,
    groups_for,
    parse_form,
    project_document,
    redacted,
    retained_form_value,
    safe_error,
)
from .dashboard_config_fields import CHANNEL_REQUIRED
from .errors import ConfigurationError
from .watch.channels import CHANNEL_NAME_PATTERN, CHANNEL_TYPES, COMMON_KEYS, TYPE_KEYS


STEPS = ("Choose type", "Details", "Review", "Test")
PAGE_TITLE = "Add an alert channel"
PAGE_LEAD = (
    "Choose where alerts are sent, enter a few details, then send a test "
    "message. Nothing is saved until you confirm."
)
DETAILS_LEAD = "Fields marked required must be filled in. Everything else can stay empty."
REVIEW_LEAD = "Check the change below. Nothing is saved until you confirm."
NAME_HELP = (
    "A short label, for example security-team. Letters, digits, dot, dash and "
    "underscore; up to 64 characters."
)
SECRET_HELP = (
    "Paste it here. CVEBeacon stores it in a protected file and never shows it "
    "again."
)
SECRET_AGAIN = "For safety, enter the secret again."
DUPLICATE_NAME = "A channel with this name already exists. Choose another name."
INVALID_NAME = ("Name: start with a letter or digit, then use letters, digits, dot, dash "
                "and underscore; up to 64 characters.")
EXPIRED_REVIEW = "This review expired after 10 minutes. Go back and review the details again."
STALE_CONFIG = "The configuration changed. Reload and try again."
READ_ONLY_ERROR = (
    "The configuration directory is read-only. Ask the operator to enable "
    "editing for the dashboard service, then reload this page."
)
SECRET_CAPABILITY = "Needs an administrator who may manage secrets."
ADVANCED_NOTE = "Advanced: set up with the full form"
GENERIC_CHECK = "The details could not be checked. Reload this page and try again."


@dataclass(frozen=True)
class WizardField:
    """One offered setting; ``control`` is text, select, addresses or secret."""

    key: str
    label: str
    help: str
    example: str = ""
    control: str = "text"
    required: bool = False
    options: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class WizardType:
    kind: str
    title: str
    text: str
    fields: tuple[WizardField, ...] = ()

    def secret(self) -> WizardField | None:
        return next((item for item in self.fields if item.control == "secret"), None)


WIZARD_TYPES = (
    WizardType(
        "smtp",
        "Email (mail server)",
        "Send alerts from your own mail server.",
        (
            WizardField("host", "Mail server address",
                        "The address of the mail server that sends alerts.",
                        "smtp.example.com", required=True),
            WizardField("from", "Send from",
                        "The address alerts appear to come from.",
                        "alerts@example.com", required=True),
            WizardField("to", "Send to",
                        "One or more addresses, separated by commas.",
                        "alerts@example.com, security@example.com",
                        control="addresses", required=True),
            WizardField("security", "Security",
                        "Encryption used between CVEBeacon and the mail server.",
                        control="select",
                        options=(("starttls", "Encrypted with STARTTLS (recommended)"),
                                 ("tls", "Encrypted from the start (TLS)"))),
            WizardField("port", "Port",
                        "Leave blank to use 587 for STARTTLS or 465 for TLS.",
                        "587"),
            WizardField("username", "User name",
                        "Needed when the mail server requires a sign-in name.",
                        "alerts@example.com"),
            WizardField("password_file", "Mail password", SECRET_HELP, control="secret"),
        ),
    ),
    WizardType(
        "graph",
        "Email (Microsoft 365)",
        "Send email through your Microsoft 365 tenant.",
        (
            WizardField("tenant_id", "Directory (tenant) ID",
                        "The directory ID that owns the sending mailbox.",
                        "00000000-0000-0000-0000-000000000000", required=True),
            WizardField("client_id", "Application (client) ID",
                        "The application ID registered in Microsoft 365.",
                        "00000000-0000-0000-0000-000000000000", required=True),
            WizardField("sender", "Send from", "The mailbox that sends the alerts.",
                        "alerts@example.com", required=True),
            WizardField("to", "Send to", "One or more addresses, separated by commas.",
                        "alerts@example.com", control="addresses", required=True),
            WizardField("client_secret_file", "Application secret", SECRET_HELP,
                        control="secret", required=True),
        ),
    ),
    WizardType(
        "teams",
        "Microsoft Teams",
        "Post to a Teams channel.",
        (WizardField("webhook_url_file", "Teams webhook address", SECRET_HELP,
                     control="secret", required=True),),
    ),
    WizardType(
        "slack",
        "Slack",
        "Post to a Slack channel.",
        (WizardField("webhook_url_file", "Slack webhook address", SECRET_HELP,
                     control="secret", required=True),),
    ),
    WizardType(
        "discord",
        "Discord",
        "Post to a Discord channel.",
        (WizardField("webhook_url_file", "Discord webhook address", SECRET_HELP,
                     control="secret", required=True),),
    ),
    WizardType(
        "telegram",
        "Telegram",
        "Send to a Telegram chat.",
        (
            WizardField("chat_id", "Chat ID",
                        "The numeric chat ID or @channel name that receives the message.",
                        "123456789", required=True),
            WizardField("bot_token_file", "Bot token", SECRET_HELP,
                        control="secret", required=True),
        ),
    ),
    WizardType(
        "matrix",
        "Matrix",
        "Send to a Matrix room.",
        (
            WizardField("homeserver", "Server address",
                        "The base address of the Matrix server.",
                        "https://matrix.example.org", required=True),
            WizardField("room_id", "Room ID", "The room that receives the messages.",
                        "!room:example.org", required=True),
            WizardField("access_token_file", "Access token", SECRET_HELP,
                        control="secret", required=True),
        ),
    ),
    WizardType(
        "ntfy",
        "ntfy",
        "Push notifications to phones.",
        (
            WizardField("topic", "Topic name", "The topic that phones subscribe to.",
                        "security-alerts", required=True),
            WizardField("server", "Server address",
                        "Leave blank to use https://ntfy.sh.", "https://ntfy.example.org"),
            WizardField("token_file", "Access token", SECRET_HELP, control="secret"),
        ),
    ),
    WizardType(
        "gotify",
        "Gotify",
        "Push to your own Gotify server.",
        (
            WizardField("server", "Server address",
                        "The base address of the Gotify server.",
                        "https://gotify.example.org", required=True),
            WizardField("app_token_file", "Application token", SECRET_HELP,
                        control="secret", required=True),
        ),
    ),
    WizardType(
        "webhook",
        "Generic webhook",
        "Send alerts to any web address that accepts them.",
        (WizardField("url_file", "Webhook address", SECRET_HELP,
                     control="secret", required=True),),
    ),
)

WIZARD_TYPES_BY_KIND = {item.kind: item for item in WIZARD_TYPES}
# Teams bot registration needs several Azure values; the full form stays the
# supported path and the type chooser says so explicitly.
ADVANCED_TYPES = {"teams_bot": "Microsoft Teams"}


def _manage_secrets() -> bool:
    return bool(g.user and g.user.is_admin and "manage_secrets" in g.permissions)


def _type_available(item: WizardType, *, manage_secrets: bool) -> bool:
    secret = item.secret()
    return secret is None or not secret.required or manage_secrets


def _wizard_type(kind: str) -> WizardType:
    item = WIZARD_TYPES_BY_KIND.get(kind.strip().casefold() if isinstance(kind, str) else "")
    if item is None:
        abort(404)
    return item


def _require_type_available(item: WizardType) -> None:
    if not _type_available(item, manage_secrets=_manage_secrets()):
        abort(403)


def _read(editor):
    """Read the live configuration, rendering the existing error page on failure."""
    try:
        return editor.read()
    except ConfigurationError as exc:
        raise _RenderedError(
            "config_error.html",
            {"error": safe_error(exc, [_credential_inputs()], editor.path),
             "read_only": editor.read_only()},
            400,
        ) from None


class _RenderedError(Exception):
    """Internal signal for a page that is already rendered with a status."""

    def __init__(self, template, context, status):
        self.template = template
        self.context = context
        self.status = status


def _new_group(item: WizardType, document, *, manage_secrets: bool, can_admin: bool):
    groups = groups_for("channels", document, new_type=item.kind,
                        can_manage=manage_secrets, can_admin=can_admin)
    index = len(groups) - 1
    return groups, index


def _field_name(index: int, item: WizardField) -> str:
    suffix = "new" if item.control == "secret" else item.key
    return f"g{index}_{item.key}_{suffix}" if item.control == "secret" else f"g{index}_{suffix}"


def _render_form(item: WizardType, version: str, *, index: int, name: str = "",
                 values: dict[str, str] | None = None, errors: dict[str, str] | None = None,
                 error: str | None = None, read_only: bool = False, status: int = 200):
    values = values or {}
    errors = errors or {}
    rows = [{
        "label": "Name (required)",
        "name": f"g{index}_name",
        "value": name,
        "help": NAME_HELP,
        "example": "security-team",
        "error": errors.get(f"g{index}_name"),
        "required": True,
        "optional": False,
        "control": "text",
        "options": (),
    }]
    secret = None
    for wizard_field in item.fields:
        name_attr = _field_name(index, wizard_field)
        label = wizard_field.label + (" (required)" if wizard_field.required else "")
        if wizard_field.control == "secret":
            if not _manage_secrets():
                continue
            secret_help = wizard_field.help
            if error or errors:
                secret_help = f"{secret_help} {SECRET_AGAIN}"
            secret = {
                "label": label,
                "name": name_attr,
                "help": secret_help,
                "error": errors.get(name_attr),
                "required": wizard_field.required,
                "optional": not wizard_field.required,
            }
            continue
        help_text = wizard_field.help
        if wizard_field.example and wizard_field.control != "select":
            help_text = f"{help_text} Example: {wizard_field.example}."
        value = values.get(wizard_field.key)
        if value is None:
            value = (wizard_field.options[0][0]
                     if wizard_field.control == "select" and wizard_field.options else "")
        rows.append({
            "label": label,
            "name": name_attr,
            "value": value,
            "help": help_text,
            "example": wizard_field.example,
            "error": errors.get(name_attr),
            "required": wizard_field.required,
            "optional": not wizard_field.required,
            "control": wizard_field.control,
            "options": wizard_field.options,
        })
    return render_template(
        "channel_wizard_form.html",
        title=PAGE_TITLE,
        lead=DETAILS_LEAD,
        eyebrow=item.title,
        step_labels=STEPS,
        current=2,
        kind=item.kind,
        wizard_type=item,
        fields=rows,
        secret=secret,
        version=version,
        error=error,
        errors=errors,
        read_only=read_only,
    ), status


def _review_diff(document, candidate) -> str:
    return "\n".join(difflib.unified_diff(
        dumps(redacted(project_document(document, "channels"))).splitlines(),
        dumps(redacted(project_document(candidate, "channels"))).splitlines(),
        fromfile="current", tofile="proposed", lineterm=""))


def _render_review(item: WizardType, *, preview: str, diff: str, lockout: bool,
                   error: str | None = None, status: int = 200, read_only: bool = False):
    return render_template(
        "channel_wizard_form.html",
        title=PAGE_TITLE,
        lead=REVIEW_LEAD,
        eyebrow=item.title,
        step_labels=STEPS,
        current=3,
        kind=item.kind,
        wizard_type=item,
        preview=preview,
        diff=diff,
        lockout=lockout,
        error=error,
        errors={},
        read_only=read_only,
    ), status


def _error_page(error: str, status: int, *, read_only: bool):
    return render_template("config_error.html", error=error, read_only=read_only), status


def _retained_values(item: WizardType, index: int, form, controls: dict[str, dict]) -> dict[str, str]:
    values = {}
    for wizard_field in item.fields:
        if wizard_field.control == "secret":
            continue
        control = controls.get(wizard_field.key)
        submitted = form.get(_field_name(index, wizard_field), "")
        if wizard_field.control == "select":
            choices = [choice for choice, _ in wizard_field.options]
            values[wizard_field.key] = submitted if submitted in choices else (
                choices[0] if choices else "")
            continue
        retained = retained_form_value(control, submitted, "channels") if control else None
        values[wizard_field.key] = retained or ""
    return values


def _validate(item: WizardType, index: int, *, form, name: str, secret: str,
              existing: set[str]) -> dict[str, str]:
    errors = {}
    name_field = f"g{index}_name"
    if not name:
        errors[name_field] = "Name is required."
    elif CHANNEL_NAME_PATTERN.fullmatch(name) is None:
        errors[name_field] = INVALID_NAME
    elif name.casefold() in {channel.casefold() for channel in existing}:
        errors[name_field] = DUPLICATE_NAME
    for wizard_field in item.fields:
        field_name = _field_name(index, wizard_field)
        if wizard_field.control == "secret":
            if wizard_field.required and _manage_secrets() and not secret.strip():
                errors[field_name] = f"{wizard_field.label} is required."
            continue
        if wizard_field.control == "select":
            submitted = form.get(field_name, "")
            choices = [choice for choice, _ in wizard_field.options]
            if submitted and submitted not in choices:
                errors[field_name] = f"{wizard_field.label}: choose one of the listed options."
            continue
        submitted = form.get(field_name, "")
        if wizard_field.required and not submitted.strip():
            errors[field_name] = f"{wizard_field.label} is required."
    return errors


def _synthetic_form(groups, item: WizardType, *, name: str,
                    values: dict[str, str], secret: str, version: str) -> MultiDict:
    """Build one parser row; the server selects append mode for this route."""
    data = {}
    new_group = groups[-1]
    secret_key = item.secret().key if item.secret() is not None else None
    for control in new_group["controls"]:
        key = control["key"]
        field_name = f"g0_{key}"
        if key == "name":
            data[field_name] = name
        elif key == "type":
            data[field_name] = item.kind
        else:
            data[field_name] = values.get(key, "")
        if control["secret"] and control["allow_new_secret"]:
            data[field_name + "_new"] = secret if key == secret_key else ""
    data.update({
        "row_count": "1",
        "csrf": request.form.get("csrf", ""),
        "version": version,
        "action": "preview",
    })
    return MultiDict(data)


def _field_error(item: WizardType, index: int, exc: FieldValidationError) -> tuple[str | None, str | None]:
    key = exc.key
    if key is None:
        return None, GENERIC_CHECK
    for wizard_field in item.fields:
        if wizard_field.key != key:
            continue
        reason = exc.reason
        if reason == "required":
            message = f"{wizard_field.label} is required."
        elif reason in {"enum", "environment"}:
            message = f"{wizard_field.label}: choose one of the listed options."
        elif reason == "addresses":
            message = f"{wizard_field.label} needs one or more email addresses, separated by commas."
        else:
            message = f"{wizard_field.label} is not valid. Use the example shown."
        return _field_name(index, wizard_field), message
    return None, GENERIC_CHECK


def _loader_field_error(item: WizardType, index: int, exc: ConfigurationError):
    key = getattr(exc, "field_key", None)
    if item.kind == "webhook" and key == "url":
        key = "url_file"
    field = next((value for value in item.fields if value.key == key), None)
    if field is None:
        return None
    return _field_name(index, field), f"{field.label} is not valid. Check the value and try again."


def _credential_inputs() -> list[str]:
    return [text for key, text in request.form.items()
            if key.endswith(("_env", "_file", "_new"))]


def _pending(editor, identifier: str, kind: str):
    return editor.pending_review(identifier, "channels", ("wizard", kind))


def _exact_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (list(left) == list(right)
                and all(_exact_equal(left[key], right[key]) for key in left))
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _exact_equal(a, b) for a, b in zip(left, right))
    return left == right


def _verified_new_channel_name(before, after, kind: str) -> str | None:
    old = get_table(before, "watch.channels")
    new = get_table(after, "watch.channels")
    added = [name for name in new if name not in old]
    if (len(added) != 1 or list(new) != [*old, added[0]]
            or any(name not in new or not _exact_equal(row, new[name])
                   for name, row in old.items())):
        return None
    row = new[added[0]]
    if not isinstance(row, dict) or row.get("type") != kind:
        return None
    expected = deepcopy(before)
    expected.setdefault("watch", {}).setdefault("channels", {})[added[0]] = deepcopy(row)
    return added[0] if _exact_equal(expected, after) else None


def _reject_repeated_fields(item: WizardType, index: int, form, *, manage_secrets: bool):
    consumed = {"csrf", "version", "action", f"g{index}_name"}
    for wizard_field in item.fields:
        if wizard_field.control != "secret" or manage_secrets:
            consumed.add(_field_name(index, wizard_field))
    if any(len(form.getlist(name)) > 1 for name in consumed):
        abort(400)


def _next_url(name: str | None) -> str:
    if name and "operations.channel_test_form" in current_app.view_functions:
        return url_for("operations.channel_test_form", name=name)
    return url_for("config_editor.channels", saved=1)


def register_channel_wizard(blueprint, editor) -> None:
    """Register the three step routes on the configuration blueprint."""
    from .dashboard import requires

    @blueprint.get("/channels/new")
    @requires(("view", "edit_channels"))
    def channel_wizard():
        manage_secrets = _manage_secrets()
        kind = request.args.get("kind")
        if kind:
            item = _wizard_type(kind)
            _require_type_available(item)
            return redirect(url_for("config_editor.channel_wizard_form", kind=item.kind), code=303)
        types = []
        for item in WIZARD_TYPES:
            available = _type_available(item, manage_secrets=manage_secrets)
            types.append({
                "kind": item.kind,
                "title": item.title,
                "text": item.text,
                "available": available,
                "note": "" if available else SECRET_CAPABILITY,
            })
        advanced = [{
            "kind": kind,
            "title": ADVANCED_TYPES[kind],
            "text": ADVANCED_NOTE,
        } for kind in ADVANCED_TYPES]
        return render_template("channel_wizard_type.html", title=PAGE_TITLE, lead=PAGE_LEAD,
                               step_labels=STEPS, current=1, types=types, advanced=advanced,
                               read_only=editor.read_only())

    @blueprint.route("/channels/new/<kind>", methods=["GET", "POST"])
    @requires(("view", "edit_channels"))
    def channel_wizard_form(kind):
        try:
            item = _wizard_type(kind)
            _require_type_available(item)
            document, _, _, version, current_config = _read(editor)
            manage_secrets = _manage_secrets()
            groups, index = _new_group(item, document, manage_secrets=manage_secrets,
                                       can_admin=g.user.is_admin)
            controls = {control["key"]: control for control in groups[-1]["controls"]}
            existing = set(get_table(document, "watch.channels"))
            read_only = editor.read_only()
            if request.method == "GET":
                return _render_form(item, version, index=index, read_only=read_only)
            if read_only:
                return _render_form(item, version, index=index, error=READ_ONLY_ERROR,
                                    read_only=True, status=400)
            action = request.form.get("action")
            if action == "confirm":
                return _confirm(item, editor, document, version, index, read_only)
            if action != "preview":
                abort(400, "Unsupported configuration action; reload the form")
            if request.form.get("version") != version:
                return _error_page(STALE_CONFIG, 409, read_only=read_only)
            _reject_repeated_fields(item, index, request.form,
                                    manage_secrets=manage_secrets)
            values = _retained_values(item, index, request.form, controls)
            submitted = {wizard_field.key: request.form.get(_field_name(index, wizard_field), "")
                         for wizard_field in item.fields if wizard_field.control != "secret"}
            secret_field = item.secret()
            secret = (request.form.get(_field_name(index, secret_field), "")
                      if secret_field is not None and manage_secrets else "")
            name = (request.form.get(f"g{index}_name", "") or "").strip()
            errors = _validate(item, index, form=request.form, name=name, secret=secret,
                               existing=existing)
            if errors:
                return _render_form(item, version, index=index,
                                    name=_safe_name(name),
                                    values=values, errors=errors, read_only=read_only, status=400)
            synthetic = _synthetic_form(groups, item, name=name, values=submitted,
                                        secret=secret, version=version)
            staged = []
            try:
                candidate, staged, replacements = parse_form(
                    editor, "channels", document, current_config, g.permissions,
                    can_admin=g.user.is_admin, form=synthetic,
                    append_channels=True)
                preview, lockout = editor.preview(
                    "channels", candidate, version, staged, replacements,
                    current_document=document, current_config=current_config,
                    origin=("wizard", item.kind))
                staged = []
                if editor.pending_review(preview, "channels", ("wizard", item.kind)) is None:
                    abort(400, EXPIRED_REVIEW)
                return _render_review(item, preview=preview,
                                      diff=_review_diff(document, candidate),
                                      lockout=lockout, read_only=read_only)
            except FieldValidationError as exc:
                name_attr, message = _field_error(item, index, exc)
                errors = {name_attr: message} if name_attr else {}
                return _render_form(item, version, index=index,
                                    name=_safe_name(name),
                                    values=values, errors=errors,
                                    error=None if errors else message,
                                    read_only=read_only, status=400)
            except ConfigurationError as exc:
                field_error = _loader_field_error(item, index, exc)
                if field_error is not None:
                    field_name, message = field_error
                    return _render_form(item, version, index=index,
                                        name=_safe_name(name), values=values,
                                        errors={field_name: message},
                                        read_only=read_only, status=400)
                error = safe_error(exc, [document or {}, _credential_inputs()], editor.path)
                return _render_form(item, version, index=index,
                                    name=_safe_name(name),
                                    values=values, error=error,
                                    read_only=read_only, status=400)
            finally:
                editor.discard_staged(staged)
        except _RenderedError as exc:
            return render_template(exc.template, **exc.context), exc.status
        except HTTPException as exc:
            if exc.code not in {400, 409}:
                raise
            return _error_page(exc.description or STALE_CONFIG, exc.code,
                               read_only=editor.read_only())

    def _confirm(item: WizardType, editor, document, version: str, index: int, read_only: bool):
        identifier = request.form.get("preview", "")
        pending = _pending(editor, identifier, item.kind)
        if pending is None:
            return _render_form(item, version, index=index, error=EXPIRED_REVIEW,
                                read_only=read_only, status=400)
        name = _verified_new_channel_name(
            pending.baseline_document, pending.document, item.kind)
        if name is None:
            return _error_page(EXPIRED_REVIEW, 400, read_only=read_only)
        try:
            ended = editor.commit(identifier, "channels",
                                  current_app.extensions["dashboard_users"],
                                  {"edit_channels"}, request.form.get("lockout") == "yes",
                                  origin=("wizard", item.kind))
        except HTTPException as exc:
            if exc.code == 409:
                return _error_page(STALE_CONFIG, 409, read_only=editor.read_only())
            if exc.code == 400:
                return _render_form(item, version, index=index, error=EXPIRED_REVIEW,
                                    read_only=editor.read_only(), status=400)
            raise
        except ConfigurationError as exc:
            error = safe_error(exc, [document or {}, _credential_inputs()], editor.path)
            still = _pending(editor, identifier, item.kind)
            if still is not None:
                return _render_review(item, preview=identifier,
                                      diff=_review_diff(document, still.document),
                                      lockout=still.lockout, error=error, status=400,
                                      read_only=editor.read_only())
            return _render_form(item, version, index=index, error=error,
                                read_only=editor.read_only(), status=400)
        if ended:
            return redirect(url_for("login"), code=303)
        return redirect(_next_url(name), code=303)


def _safe_name(value: str) -> str:
    text = (value or "").strip()
    return text if CHANNEL_NAME_PATTERN.fullmatch(text) else ""


def wizard_type_field_names(item: WizardType) -> set[str]:
    """All configuration keys the wizard offers for one type."""
    return {wizard_field.key for wizard_field in item.fields}


def consistency_errors() -> list[str]:
    """Schema-drift problems; an empty list means the wizard matches the loader."""
    errors = []
    kinds = [item.kind for item in WIZARD_TYPES]
    if len(kinds) != len(set(kinds)):
        errors.append("duplicate wizard types")
    for item in WIZARD_TYPES:
        offered = wizard_type_field_names(item)
        unknown = offered - COMMON_KEYS - TYPE_KEYS.get(item.kind, set())
        if unknown:
            errors.append(f"{item.kind}: unknown keys {sorted(unknown)}")
        required = CHANNEL_REQUIRED.get(item.kind, set())
        if not required <= offered:
            errors.append(f"{item.kind}: required keys {sorted(required - offered)} not offered")
        secret = item.secret()
        if secret is not None and secret.key not in TYPE_KEYS.get(item.kind, set()):
            errors.append(f"{item.kind}: secret key {secret.key} is not a channel key")
    listed = set(WIZARD_TYPES_BY_KIND) | set(ADVANCED_TYPES)
    if set(CHANNEL_TYPES) - listed:
        errors.append(f"types not classified: {sorted(set(CHANNEL_TYPES) - listed)}")
    if listed - set(CHANNEL_TYPES):
        errors.append(f"unknown types classified: {sorted(listed - set(CHANNEL_TYPES))}")
    if "teams_bot" in WIZARD_TYPES_BY_KIND:
        errors.append("teams_bot must use the full form")
    return errors
