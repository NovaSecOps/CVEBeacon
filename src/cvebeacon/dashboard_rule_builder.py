"""Form glue for the visual rule builder.

The configuration page owns the request flow.  This module translates the
builder's posted fields into the same ``g{i}_*`` field values the text form
sends, so the unchanged ``parse_form`` -> ``Editor.preview`` -> ``Editor.commit``
pipeline remains the only writer.  It also answers the read-only "which recent
CVEs match this rule" check.  Nothing here reads or writes a configuration file.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from decimal import Decimal
import re
import sqlite3
import tomllib
from typing import Any, Mapping

from flask import abort, current_app, g, has_request_context
from werkzeug.datastructures import MultiDict

from .errors import CVEBeaconError, ConfigurationError
from .rule_builder import (
    BUILD_FIELD_CRITERIA,
    CRITERIA,
    JOINS,
    USE_EXCLUDE,
    USE_INCLUDE,
    USE_NOT_USED,
    build_model,
    describe,
    keep_original_condition,
    read_condition,
)
from .watch.rules import (
    DEFAULT_EVENTS,
    EVENT_KINDS,
    Rule,
    evaluate,
    parse_condition,
    validate_rule_sources,
)

_CRITERION_FIELDS = {
    f"{criterion.key}_{suffix}"
    for criterion in CRITERIA
    for suffix in ("use", "value")
}
_CHECKBOX_FIELDS = {"channels", "events"}
_BUILDER_FIELDS = {"join"} | _CRITERION_FIELDS
_TEXT_FIELDS = {"condition", "channels", "events"}
_ROW_ACTIONS = {"match_rule", "edit_as_text", "use_builder"}
_MODE_BUILDER = "builder"
_MODE_TEXT = "text"
_SELECTED_CHANNEL_ERROR = "Choose at least one channel to send alerts to."
_UNKNOWN_CHANNEL_ERROR = "Choose an alert channel from the list."
_SELECTED_EVENT_ERROR = "Choose at least one kind of change to alert on."
_UNKNOWN_EVENT_ERROR = "Choose an alert type from the list."
_CONDITION_ERROR = "The condition is not valid. Check the criteria and try again."
_CRITERION_ERROR = "This criterion is not valid. Check the value and try again."
_EU_SOURCE_ERROR = (
    "The EU list is not turned on. Turn on eu_kev in Watch settings, then "
    "try again."
)
_EPSS_SOURCE_ERROR = (
    "EPSS data is not turned on. Turn on EPSS data in Watch settings, then "
    "try again."
)
_SAVE_ERROR = "The rule was not saved. Check the highlighted fields."


def _document_rules(document: Any) -> list[dict[str, Any]]:
    watch = document.get("watch") if isinstance(document, Mapping) else None
    rules = watch.get("rules") if isinstance(watch, Mapping) else None
    if not isinstance(rules, list):
        return []
    return [row for row in rules if isinstance(row, dict)]


def _render_value(value: Any) -> str:
    if isinstance(value, tuple):
        return ", ".join(value)
    if isinstance(value, float):
        return format(Decimal(repr(value)), "f")
    return str(value)


def _selection(values, field):
    stripped = {value for value in map(str.strip, values) if value}
    return {value.casefold() for value in stripped} if field == "events" else stripped


def _stored_selection(rule, field):
    return _selection(rule.get(field, DEFAULT_EVENTS if field == "events" else ()), field)


def _selection_value(original, field, selected, choices):
    if selected == _stored_selection(original, field):
        return original.get(field)
    return [choice for choice in choices if choice in selected]


def _render_row(rule, read=None):
    model = read.model if read else None
    row = {
        "mode": _MODE_TEXT if read and model is None else _MODE_BUILDER,
        "join": model.join if model else "any",
        "uses": {key: use for key, (use, _) in model.uses.items()} if model else {},
        "values": {key: _render_value(value) for key, (_, value) in model.uses.items()}
        if model else {},
        "reason": read.reason if read else "",
        "summary": describe(model) if model else "",
    }
    if row["mode"] == _MODE_BUILDER:
        row.update({field: _stored_selection(rule, field) for field in _CHECKBOX_FIELDS})
    return row


def render_rule_builder_rows(document: Any, count: int | None = None):
    """Build the server-owned display state for each rendered rule row."""
    rules = _document_rules(document)
    row_count = len(rules) + 1 if count is None else count
    return {
        index: _render_row(rules[index], read_condition(rules[index].get("condition")))
        if index < len(rules) else _render_row({})
        for index in range(row_count)
    }


def _validate_fields(form, count, channel_count):
    """Validate the submitted shape before using any row or action."""
    from .dashboard_config import RULE_FIELDS

    repeated_fields = {"channels": channel_count, "events": len(EVENT_KINDS)}
    max_row_fields = (
        len(RULE_FIELDS) - len(_TEXT_FIELDS) + 1  # shared fields plus Remove
        + 2 + len(_CRITERION_FIELDS) + sum(repeated_fields.values())
    )
    if sum(len(values) for _, values in form.lists()) > 5 + count * max_row_fields:
        abort(400, "Too many rule form fields")

    scalar = {"csrf", "version", "action", "row_count"} | _ROW_ACTIONS
    modes = {}
    repeated = {}
    for index in range(count):
        mode_key = f"b{index}_mode"
        # Existing callers of the plain text configuration form omit the mode.
        mode = form.get(mode_key, _MODE_TEXT)
        if mode not in {_MODE_BUILDER, _MODE_TEXT}:
            abort(400, "Unknown rule builder mode")
        modes[index] = mode
        scalar.update({mode_key, f"remove{index}"})
        text_fields = RULE_FIELDS if mode == _MODE_TEXT else RULE_FIELDS.keys() - _TEXT_FIELDS
        scalar.update(f"g{index}_{field}" for field in text_fields)
        if mode == _MODE_BUILDER:
            scalar.update(f"b{index}_{field}" for field in _BUILDER_FIELDS)
            if form.get(f"b{index}_join") not in JOINS:
                abort(400, "Unknown rule builder join")
            repeated.update({f"b{index}_{field}": (field, bound)
                             for field, bound in repeated_fields.items()})

    for field, values in form.lists():
        if field in scalar:
            if len(values) != 1:
                abort(400, "Repeated rule form field")
        elif field in repeated:
            kind, bound = repeated[field]
            if len(values) > bound or len(values) != len(_selection(values, kind)):
                abort(400, "Repeated rule form selection")
        else:
            abort(400, "Unknown rule form field")
    return modes


def _retainable(text: str) -> bool:
    from .dashboard_config import _CREDENTIAL_TEXT

    return _CREDENTIAL_TEXT.search(text) is None


def _condition_withheld(condition) -> bool:
    from .dashboard_config import _form_strings

    return any(not _retainable(text) for text in _form_strings(condition))


def _store_rows(rows: dict[int, dict[str, Any]]) -> None:
    if has_request_context():
        g.rule_builder = {"rows": rows}


def _posted_row(form: MultiDict, index: int):
    uses = {criterion.key: form.get(f"b{index}_{criterion.key}_use", "")
            for criterion in CRITERIA}
    values = {criterion.key: form.get(f"b{index}_{criterion.key}_value", "")
              for criterion in CRITERIA}
    return {
        "mode": _MODE_BUILDER,
        "join": form.get(f"b{index}_join", "any"),
        "uses": uses,
        "values": values,
        "channels": _selection(form.getlist(f"b{index}_channels"), "channels"),
        "events": _selection(form.getlist(f"b{index}_events"), "events"),
        "errors": {},
        "summary": "",
    }


def _safe_row(row):
    values = {key: text if _retainable(text) else "" for key, text in row["values"].items()}
    withheld = values != row["values"]
    return {
        **row,
        "uses": {key: use if use in {USE_NOT_USED, USE_INCLUDE, USE_EXCLUDE} else ""
                 for key, use in row["uses"].items()},
        "values": values,
        "channels": {text for text in row["channels"] if _retainable(text)},
        "events": {text for text in row["events"] if _retainable(text)},
        "summary": "" if withheld else row["summary"],
        "withheld": withheld,
    }


def _build_condition(row, original):
    result = build_model(row["join"], row["uses"], row["values"])
    row["errors"].update(result.errors)
    if result.model is None:
        return None, None
    row["summary"] = describe(result.model)
    return keep_original_condition(original.get("condition"), result.model), result.model


def _text_fields(index, original, row, condition, channels):
    from .dashboard_config import value as toml_value

    fields = {f"g{index}_condition": toml_value(condition) if condition is not None else ""}
    for field, choices in (("channels", channels), ("events", EVENT_KINDS)):
        selected = _selection_value(original, field, row[field], choices)
        fields[f"g{index}_{field}"] = toml_value(selected) if selected is not None else ""
    return fields


def _stage_b_field(error: ConfigurationError, model) -> str | None:
    message = str(error)
    for criterion in CRITERIA:
        if re.search(rf"\.{re.escape(criterion.key)}(?:\.|:|\[|\s)", message):
            return criterion.key
    match = re.search(r"\.(?:all|any)\[(\d+)\]", message)
    if match is None:
        return None
    includes = [
        criterion.key
        for criterion in CRITERIA
        if model.uses.get(criterion.key, (None,))[0] == USE_INCLUDE
    ]
    position = int(match.group(1))
    return includes[position] if position < len(includes) else None


def _stage_c_error(error: ConfigurationError) -> tuple[str, str]:
    message = str(error)
    if 'uses kev = "eu"' in message:
        return "kev", _EU_SOURCE_ERROR
    if "uses epss_min" in message:
        return "epss_min", _EPSS_SOURCE_ERROR
    return BUILD_FIELD_CRITERIA, _CONDITION_ERROR


def prepare_rules_form(form, document, current_config, count):
    """Rewrite posted builder rows into the field values the text form sends."""
    channels = [channel.name for channel in current_config.watch.channels]
    modes = _validate_fields(form, count, len(channels))
    prepared = MultiDict((key, value) for key, value in form.items(multi=True)
                         if not key.startswith("b"))
    rules = _document_rules(document)
    rows = {}
    failed = False
    for index, mode in modes.items():
        if mode == _MODE_TEXT:
            rows[index] = _posted_text_row(form, index)
            continue
        row = _posted_row(form, index)
        rows[index] = row
        name = (form.get(f"g{index}_name") or "").strip()
        if not name or form.get(f"remove{index}") == "yes":
            continue
        original = rules[index] if index < len(rules) else {}
        condition, model = _build_condition(row, original)
        if model is None:
            failed = True
            continue
        try:
            parsed = parse_condition(condition, path=f"watch.rules[{index}].condition")
        except ConfigurationError as error:
            key = _stage_b_field(error, model)
            row["errors"][key or BUILD_FIELD_CRITERIA] = (
                _CRITERION_ERROR if key else _CONDITION_ERROR
            )
            failed = True
            continue
        if row["channels"] - set(channels):
            row["errors"]["channels"] = _UNKNOWN_CHANNEL_ERROR
        elif not row["channels"]:
            row["errors"]["channels"] = _SELECTED_CHANNEL_ERROR
        if row["events"] - set(EVENT_KINDS):
            row["errors"]["events"] = _UNKNOWN_EVENT_ERROR
        elif not row["events"]:
            row["errors"]["events"] = _SELECTED_EVENT_ERROR
        try:
            rule = Rule(name=name, condition=parsed, channels=())
            validate_rule_sources([rule], current_config.watch.sources)
        except ConfigurationError as error:
            field, message = _stage_c_error(error)
            row["errors"][field] = message
        if row["errors"]:
            failed = True
            continue
        for field, value in _text_fields(index, original, row, condition, channels).items():
            if value:
                prepared[field] = value
    _store_rows({index: _safe_row(row) if row["mode"] == _MODE_BUILDER else row
                 for index, row in rows.items()})
    if failed:
        abort(400, _SAVE_ERROR)
    return prepared


def _parse_text_value(text: str, field: str, fallback=None):
    if not text.strip():
        return fallback
    try:
        parsed = tomllib.loads("value = " + text)
    except (ValueError, RecursionError):
        raise ConfigurationError(f"The {field} field is not a valid TOML value") from None
    if set(parsed) != {"value"}:
        raise ConfigurationError(f"The {field} field is not a valid TOML value")
    return parsed["value"]


def _posted_text_row(form, index):
    try:
        condition = _parse_text_value(form.get(f"g{index}_condition", ""), "condition")
    except ConfigurationError:
        condition = None
    return {
        "mode": _MODE_TEXT,
        "withheld": _condition_withheld(condition),
        "representable": condition is not None and read_condition(condition).model is not None,
    }


def retain_rule_action_form(form, document, current_config, count):
    """Keep posted row state and translate only the requested mode switch."""
    rules = _document_rules(document)
    channels = [channel.name for channel in current_config.watch.channels]
    modes = _validate_fields(form, count, len(channels))
    actions = _ROW_ACTIONS.intersection(form)
    if len(actions) != 1:
        abort(400, "Choose one rule action")
    action = actions.pop()
    raw_index = form[action]
    if raw_index not in {str(index) for index in range(count)}:
        abort(400, "Unknown rule")
    index = int(raw_index)
    rows = {}
    condition = None
    for position, mode in modes.items():
        if mode == _MODE_TEXT:
            rows[position] = _posted_text_row(form, position)
            continue
        row = _posted_row(form, position)
        original = rules[position] if position < len(rules) else {}
        if any(row["uses"].values()) or original:
            built, _ = _build_condition(row, original)
            if position == index:
                condition = built
        rows[position] = _safe_row(row)
    _store_rows(rows)

    if action == "match_rule":
        return form, None
    row = rows[index]
    original = rules[index] if index < len(rules) else {}
    if action == "edit_as_text":
        if row["mode"] != _MODE_BUILDER:
            abort(400, "Unknown rule builder mode")
        if row["withheld"]:
            return form, None
        if condition is None and (original or any(row["uses"].values())):
            return form, "Check the highlighted criteria before switching to text."
        if (row["channels"] - set(channels) or row["events"] - set(EVENT_KINDS)):
            return form, "Check the selected channels and events before switching to text."
        posted = MultiDict(form)
        for field, value in _text_fields(index, original, row, condition, channels).items():
            posted[field] = value
        rows[index] = {"mode": _MODE_TEXT, "representable": True}
        return posted, None

    if row["mode"] != _MODE_TEXT or read_condition(original.get("condition")).model is None:
        abort(400, "This rule cannot use the builder")
    if row["withheld"]:
        return form, None
    try:
        condition = _parse_text_value(form.get(f"g{index}_condition", ""), "condition")
        selections = {
            field: _parse_text_value(form.get(f"g{index}_{field}", ""), field)
            for field in _CHECKBOX_FIELDS
        }
    except ConfigurationError:
        return form, "Check the condition, channels and events before switching to the builder."
    read = read_condition(condition)
    if read.model is None:
        return form, read.reason
    from .dashboard_config import _toml_equal

    if not _toml_equal(keep_original_condition(original.get("condition"), read.model), condition):
        return form, "Keep editing this condition as text to preserve its structure."
    for field, choices in (("channels", channels), ("events", EVENT_KINDS)):
        selected = selections[field]
        if selected is not None and (
            not isinstance(selected, list) or any(not isinstance(item, str) for item in selected)
        ):
            return form, "Check the channels and events before switching to the builder."
        fallback = DEFAULT_EVENTS if field == "events" else ()
        normalized = _selection(selected if selected is not None else fallback, field)
        if _selection_value(original, field, normalized, choices) != selected:
            return form, "Keep editing the channel or event list as text to preserve its values."
        selections[field] = normalized
    rows[index] = {**_render_row(original, read), **selections}
    return form, None


def match_preview(form, document, current_config):
    """Return preview data for a read-only rule check, or None to continue."""
    raw_index = form.get("match_rule")
    if raw_index is None:
        return None
    index = int(raw_index)
    rules = _document_rules(document)
    if index >= len(rules):
        abort(400, "Unknown rule")
    original = rules[index]
    row = g.rule_builder["rows"][index]
    try:
        if row["mode"] == _MODE_BUILDER:
            posted = _posted_row(form, index)
            condition, _ = _build_condition(posted, original)
            if condition is None:
                raise ConfigurationError("Check the highlighted criteria.")
        else:
            condition = _parse_text_value(form.get(f"g{index}_condition", ""), "condition",
                                          original.get("condition"))
            row["withheld"] = _condition_withheld(condition)
        parsed = parse_condition(condition, path=f"watch.rules[{index}].condition")
    except ConfigurationError:
        return {
            "index": index,
            "error": "Check the highlighted criteria." if row["mode"] == _MODE_BUILDER
            else "The condition is not valid. Check it and try again.",
            "stored": 0,
            "match_count": 0,
            "matches": [],
        }
    rule = dataclasses.replace(current_config.watch.rules[index], condition=parsed)
    if not current_config.watch.database.is_file():
        # A fresh install has no watch database yet.  There is nothing to read,
        # and the empty state is more accurate than an error.
        return {
            "index": index,
            "error": None,
            "stored": 0,
            "match_count": 0,
            "matches": [],
        }
    try:
        state = current_app.extensions["dashboard_watch"]
        store = state["store"]
        result = store.search(
            sort="modified",
            limit=100,
            catalogs=current_config.watch.sources,
            count_total=False,
        )
    except (KeyError, CVEBeaconError, OSError, sqlite3.Error):
        return {
            "index": index,
            "error": "Stored CVEs could not be read. Try again after the next run.",
            "stored": 0,
            "match_count": 0,
            "matches": [],
        }
    candidate = dataclasses.replace(
        rule, events=("match",), old_cves="alert", enabled=True
    )
    now = datetime.now(timezone.utc)
    matches = []
    records = tuple(result.records)
    for view in records:
        alert_state, events = evaluate(view, None, candidate, now)
        if alert_state is None:
            continue
        reasons = events[0].reasons if events and not row.get("withheld") else ()
        score = view.highest_score.score if view.highest_score is not None else None
        matches.append(
            {
                "cve_id": view.cve_id,
                "score": score,
                "reasons": tuple(reasons),
            }
        )
    return {
        "index": index,
        "error": None,
        "stored": len(records),
        "match_count": len(matches),
        "matches": matches[:10],
    }
