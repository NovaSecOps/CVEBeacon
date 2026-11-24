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
    CRITERIA_BY_KEY,
    USE_EXCLUDE,
    USE_INCLUDE,
    USE_NOT_USED,
    build_model,
    describe,
    keep_original_condition,
)
from .watch.rules import (
    EVENT_KINDS,
    Rule,
    evaluate,
    parse_condition,
    validate_rule_sources,
)

_BUILDER_KEY = re.compile(r"b(\d+)_(.+)")
_ALLOWED_ROW_FIELDS = {"mode", "join", "channels", "events"}
_CRITERION_FIELDS = {
    f"{criterion.key}_{suffix}"
    for criterion in CRITERIA
    for suffix in ("use", "value")
}
_ROW_FIELDS = _ALLOWED_ROW_FIELDS | _CRITERION_FIELDS
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


def _without_builder_keys(form: MultiDict) -> MultiDict:
    prepared = MultiDict()
    for key, value in form.items(multi=True):
        if _BUILDER_KEY.fullmatch(key) is None:
            prepared.add(key, value)
    return prepared


def _builder_fields(form: MultiDict, count: int | None) -> dict[int, str]:
    """Validate the shape of every builder field and return its mode by row."""
    modes: dict[int, str] = {}
    seen: dict[int, set[str]] = {}
    for key in form.keys():
        match = _BUILDER_KEY.fullmatch(key)
        if match is None:
            continue
        index = int(match.group(1))
        if count is not None and index >= count:
            abort(400, "Unknown rule row")
        field = match.group(2)
        if field not in _ROW_FIELDS:
            abort(400, "Unknown rule builder field")
        seen.setdefault(index, set()).add(field)
    for index, fields in seen.items():
        mode = _one_value(form, f"b{index}_mode")
        if mode not in {_MODE_BUILDER, _MODE_TEXT}:
            abort(400, "Unknown rule builder mode")
        if mode == _MODE_TEXT:
            # A browser that has JavaScript switched off can still post the
            # visible builder controls when the text radio is checked.  They
            # are ignored, but a posted value can never decide the text source.
            if fields - {"mode"}:
                continue
        else:
            if "join" in fields and len(form.getlist(f"b{index}_join")) > 1:
                abort(400, "Repeated rule builder field")
            for criterion in CRITERIA:
                for suffix in ("use", "value"):
                    name = f"b{index}_{criterion.key}_{suffix}"
                    if name in fields and len(form.getlist(name)) > 1:
                        abort(400, "Repeated rule builder field")
        modes[index] = mode
    return modes


def _one_value(form: MultiDict, name: str) -> str:
    values = form.getlist(name)
    if len(values) > 1:
        abort(400, "Repeated rule builder field")
    return values[0] if values else ""


def _retainable(text: str) -> bool:
    # The configuration page hides credential-looking text from re-rendered
    # forms.  Builder values are ordinary text, so the same filter applies.
    from .dashboard_config import _CREDENTIAL_TEXT

    return _CREDENTIAL_TEXT.search(text) is None


def _store_rows(rows: dict[int, dict[str, Any]]) -> None:
    if has_request_context():
        g.rule_builder = {"rows": rows}


def _posted_row(form: MultiDict, index: int) -> dict[str, Any]:
    uses = {
        criterion.key: _one_value(form, f"b{index}_{criterion.key}_use")
        for criterion in CRITERIA
    }
    values = {
        criterion.key: _one_value(form, f"b{index}_{criterion.key}_value")
        for criterion in CRITERIA
    }
    return {
        "mode": _one_value(form, f"b{index}_mode") or _MODE_TEXT,
        "join": _one_value(form, f"b{index}_join") or "any",
        "uses": uses,
        "values": values,
        "channels": form.getlist(f"b{index}_channels"),
        "events": form.getlist(f"b{index}_events"),
    }


def _safe_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": (
            row.get("mode", _MODE_TEXT)
            if row.get("mode") in {_MODE_BUILDER, _MODE_TEXT}
            else _MODE_TEXT
        ),
        "join": row.get("join", "any") if row.get("join") in {"any", "all"} else "any",
        "uses": {
            key: use if use in {USE_NOT_USED, USE_INCLUDE, USE_EXCLUDE} else ""
            for key, use in (row.get("uses") or {}).items()
            if key in CRITERIA_BY_KEY
        },
        "values": {
            key: text if isinstance(text, str) and _retainable(text) else ""
            for key, text in (row.get("values") or {}).items()
            if key in CRITERIA_BY_KEY
        },
        "channels": [
            text for text in (row.get("channels") or [])
            if isinstance(text, str) and _retainable(text)
        ],
        "events": [
            text for text in (row.get("events") or [])
            if isinstance(text, str) and _retainable(text)
        ],
        "errors": dict(row.get("errors") or {}),
        "reason": str(row.get("reason") or ""),
        "summary": str(row.get("summary") or ""),
    }


def _event_values(form: MultiDict, index: int, original: Mapping[str, Any]) -> list[str]:
    selected = [value for value in form.getlist(f"b{index}_events") if value]
    stored = original.get("events")
    if isinstance(stored, list) and all(isinstance(item, str) for item in stored):
        if set(selected) == set(stored):
            # Keep the stored order so an unrelated save does not rewrite it.
            return list(stored)
        return selected
    if not stored and set(selected) == set(EVENT_KINDS):
        # An omitted events list already means all event kinds.
        return []
    return selected


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
    prepared = _without_builder_keys(form)
    modes = _builder_fields(form, count)
    if not modes:
        return prepared
    rules = _document_rules(document)
    channels = [channel.name for channel in current_config.watch.channels]
    rows: dict[int, dict[str, Any]] = {}
    failed = False
    for index in range(count):
        if index not in modes:
            continue
        mode = modes[index]
        posted = _posted_row(form, index) if mode == _MODE_BUILDER else {}
        if mode == _MODE_TEXT:
            continue
        if form.get(f"remove{index}") == "yes":
            continue
        name = (form.get(f"g{index}_name") or "").strip()
        if not name:
            # The trailing blank row adds a rule only when its name is filled.
            continue
        original = rules[index] if index < len(rules) else {}
        uses = posted["uses"]
        values = posted["values"]
        row: dict[str, Any] = {
            "mode": mode,
            "join": posted["join"],
            "uses": uses,
            "values": values,
            "channels": [value for value in form.getlist(f"b{index}_channels") if value],
            "events": [value for value in form.getlist(f"b{index}_events") if value],
            "errors": {},
            "reason": "",
            "summary": "",
        }
        rows[index] = row
        result = build_model(posted["join"], uses, values)
        for field, message in result.errors:
            row["errors"][field] = message
        if result.model is None:
            failed = True
            continue
        model = result.model
        row["summary"] = describe(model)
        condition = keep_original_condition(original.get("condition"), model)
        try:
            parsed = parse_condition(
                condition, path=f"watch.rules[{index}].condition"
            )
        except ConfigurationError as error:
            # parse_condition is the backstop.  Point the fixed message at the
            # included criterion whose path appears in the error when possible.
            key = _stage_b_field(error, model)
            row["errors"][key or BUILD_FIELD_CRITERIA] = (
                _CRITERION_ERROR if key else _CONDITION_ERROR
            )
            failed = True
            continue
        channel_values = [value for value in form.getlist(f"b{index}_channels") if value]
        unknown_channels = sorted(set(channel_values) - set(channels))
        if unknown_channels:
            row["errors"]["channels"] = _UNKNOWN_CHANNEL_ERROR
        elif not channel_values:
            row["errors"]["channels"] = _SELECTED_CHANNEL_ERROR
        event_values = list(dict.fromkeys(_event_values(form, index, original)))
        unknown_events = sorted(set(event_values) - set(EVENT_KINDS))
        if unknown_events:
            row["errors"]["events"] = _UNKNOWN_EVENT_ERROR
        elif not form.getlist(f"b{index}_events"):
            row["errors"]["events"] = _SELECTED_EVENT_ERROR
        rule = Rule(
            name=name,
            condition=parsed,
            channels=tuple(dict.fromkeys(channel_values)),
            events=tuple(event_values) or EVENT_KINDS,
        )
        try:
            validate_rule_sources([rule], current_config.watch.sources)
        except ConfigurationError as error:
            field, message = _stage_c_error(error)
            row["errors"][field] = message
        if row["errors"]:
            failed = True
            continue
        from .dashboard_config import value as toml_value

        prepared[f"g{index}_condition"] = toml_value(condition)
        prepared[f"g{index}_channels"] = toml_value(
            list(dict.fromkeys(channel_values))
        )
        if event_values:
            prepared[f"g{index}_events"] = toml_value(list(event_values))
        else:
            # An omitted events list already means every event kind.  Drop a
            # hidden text value so a no-op save does not add an explicit list.
            prepared.pop(f"g{index}_events", None)
    _store_rows({index: _safe_row(row) for index, row in rows.items()})
    if failed:
        abort(400, _SAVE_ERROR)
    return prepared


def _parse_text_condition(text: str, fallback: Any) -> Any:
    if not text.strip():
        return fallback
    try:
        parsed = tomllib.loads("condition = " + text)
    except (ValueError, RecursionError):
        raise ConfigurationError("The condition is not a valid TOML value") from None
    if set(parsed) != {"condition"}:
        raise ConfigurationError("The condition is not a valid TOML value")
    return parsed["condition"]


def _rule_from_form(form, document, current_config, index):
    rules = _document_rules(document)
    if index < 0 or index >= len(rules):
        abort(400, "Unknown rule")
    original = rules[index]
    name = (original.get("name") or "").strip()
    mode = _one_value(form, f"b{index}_mode")
    row = None
    if mode == _MODE_BUILDER:
        posted = _posted_row(form, index)
        row = _safe_row(posted)
        row["errors"] = {}
        result = build_model(posted["join"], posted["uses"], posted["values"])
        if result.model is None:
            row["errors"] = dict(result.errors)
            return None, row, "Check the highlighted criteria."
        row["summary"] = describe(result.model)
        condition = keep_original_condition(original.get("condition"), result.model)
    else:
        text = form.get(f"g{index}_condition", "")
        condition = _parse_text_condition(text, original.get("condition"))
        if mode == _MODE_TEXT:
            row = _safe_row(_posted_row(form, index))
            if text.strip():
                from .dashboard_config import FIELD_METADATA, retained_form_value

                control = {
                    "key": "condition",
                    "kind": "toml",
                    "identity": "watch.rules.condition",
                    "spec": FIELD_METADATA["watch.rules.condition"],
                    "readonly": False,
                }
                safe_text = retained_form_value(control, text, "rules")
                if safe_text is not None:
                    row["condition_text"] = safe_text
    try:
        parsed = parse_condition(condition, path=f"watch.rules[{index}].condition")
    except ConfigurationError:
        message = "The condition is not valid. Check it and try again."
        if row is not None:
            row["errors"] = {BUILD_FIELD_CRITERIA: message}
        return None, row, message
    # Keep the stored provider list, events and other rule settings so the
    # preview evaluates the same rule as production; only the condition and
    # the fields needed for this read-only check differ.
    base = current_config.watch.rules[index]
    rule = dataclasses.replace(
        base,
        name=name or base.name,
        condition=parsed,
    )
    return rule, row, None


def match_preview(form, document, current_config):
    """Return preview data for a read-only rule check, or None to continue."""
    raw_index = form.get("match_rule")
    if not raw_index:
        return None
    if not raw_index.isdigit():
        abort(400, "Unknown rule")
    index = int(raw_index)
    rule, row, error = _rule_from_form(form, document, current_config, index)
    rows: dict[int, dict[str, Any]] = {}
    for other, mode in _builder_fields(form, None).items():
        if other != index:
            rows[other] = _safe_row(_posted_row(form, other))
    if row is not None:
        rows[index] = row
    if error is not None:
        _store_rows(rows)
        return {
            "index": index,
            "error": error,
            "stored": 0,
            "match_count": 0,
            "matches": [],
        }
    _store_rows(rows)
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
        reasons = events[0].reasons if events else ()
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
