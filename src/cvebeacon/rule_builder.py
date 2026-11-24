"""Translate flat watch-rule conditions to and from the visual rule builder.

The builder shows one fixed row per leaf key of ``CONDITION_SCHEMA``. It covers
only the flat shapes in the UX-1d design (section 4.1); every other condition is
opened in text mode with a one-line reason and is never rewritten by the
builder. This module is pure: it reads no file, request or clock, and it never
writes a configuration.
"""

from __future__ import annotations

import copy
import math
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .errors import ConfigurationError
from .watch.rules import (
    CONDITION_SCHEMA,
    CWE_PATTERN,
    MAX_LIST_ITEMS,
    MAX_STRING,
    CVSSCondition,
    Condition,
    parse_condition,
)

USE_NOT_USED = ""
USE_INCLUDE = "include"
USE_EXCLUDE = "exclude"
USE_OPTIONS = (
    (USE_NOT_USED, "Not used"),
    (USE_INCLUDE, "Include"),
    (USE_EXCLUDE, "Exclude (never alert)"),
)
JOINS = ("any", "all")
MATCH_OPTIONS = (
    ("any", "Any one of the included criteria"),
    ("all", "All of the included criteria"),
)
MATCH_HELP = (
    "Excluded criteria always apply on top: if one is true, no alert is sent."
)
EXCLUDE_HELP = "An exclusion only applies when the information is known."

# Fixed reasons shown next to the text mode control. They never contain raw
# setting keys or the submitted value.
REASON_MULTIPLE_KEYS = (
    "This rule uses several criteria in one block, which the form cannot show."
)
REASON_REPEATED = (
    "This rule uses the same criterion more than once, which the form cannot show."
)
REASON_NESTED = "This rule groups criteria in a way the form cannot show."
REASON_QUALIFIED = (
    "This rule sets score limits for particular versions or sources, "
    "which the form cannot show."
)
REASON_COMMA = "A value contains a comma, which the form cannot split reliably."
REASON_UNREADABLE = "This rule uses a condition the form cannot read."
REASONS = (
    REASON_MULTIPLE_KEYS,
    REASON_REPEATED,
    REASON_NESTED,
    REASON_QUALIFIED,
    REASON_COMMA,
    REASON_UNREADABLE,
)

BUILD_FIELD_JOIN = "join"
BUILD_FIELD_CRITERIA = "criteria"
NO_CRITERIA_MESSAGE = "Choose at least one criterion to include."

_SCORE_HELP = (
    "A 0-10 severity score (CVSS). 9 and above is Critical. "
    "CVEs with no score yet never match."
)
_NO_SCORE_HELP = "CVEs with no score yet never match."
_NAME_HELP = (
    "Names must match exactly (capital letters do not matter). "
    "Example: Example Corp, Widget Inc."
)


@dataclass(frozen=True, slots=True)
class Criterion:
    """One fixed builder row, derived from ``CONDITION_SCHEMA``."""

    key: str
    label: str
    kind: str
    choices: tuple[tuple[str, str], ...] = ()
    minimum: float | None = None
    maximum: float | None = None
    step: str | None = None
    help: str = ""


CRITERIA: tuple[Criterion, ...] = (
    Criterion(
        "kev",
        "On a list of flaws known to be exploited",
        "enum",
        choices=(("cisa", "CISA list"), ("eu", "EU list"), ("any", "Either list")),
        help=(
            "KEV lists are published by CISA (US) and the EU. "
            "A flaw on a list is being attacked in the real world."
        ),
    ),
    Criterion(
        "exploitation",
        "Exploitation status",
        "enum",
        choices=(
            ("poc", "Exploit code exists or active"),
            ("active", "Actively exploited"),
        ),
        help="Active means a source reports attacks now.",
    ),
    Criterion(
        "cvss_min",
        "Severity score is at least",
        "number",
        minimum=0.0,
        maximum=10.0,
        step="0.1",
        help=_SCORE_HELP,
    ),
    Criterion(
        "cvss_max",
        "Severity score is at most",
        "number",
        minimum=0.0,
        maximum=10.0,
        step="0.1",
        help=_NO_SCORE_HELP,
    ),
    Criterion(
        "epss_min",
        "Exploitation chance is at least",
        "number",
        minimum=0.0,
        maximum=1.0,
        step="0.01",
        help=(
            "EPSS is the estimated chance of exploitation in the next 30 days. "
            "0.5 means 50%. CVEs with no value yet never match."
        ),
    ),
    Criterion(
        "vendor",
        "Vendor is one of",
        "strings",
        help=_NAME_HELP,
    ),
    Criterion(
        "product",
        "Product is one of",
        "strings",
        help=_NAME_HELP,
    ),
    Criterion(
        "keyword",
        "Description contains",
        "strings",
        help="Any of these words or phrases anywhere in the description.",
    ),
    Criterion(
        "cwe",
        "Weakness type is",
        "cwe",
        help="CWE numbers, for example 79 or CWE-787.",
    ),
    Criterion(
        "cna",
        "Reported by",
        "strings",
        help="The organisation that published the record (its CNA name).",
    ),
    Criterion(
        "status",
        "Record status",
        "enum",
        choices=(("published", "Published"), ("rejected", "Rejected"),
                 ("reserved", "Reserved")),
        help="Rejected and reserved records are skipped unless you choose them here.",
    ),
)
CRITERIA_BY_KEY = {criterion.key: criterion for criterion in CRITERIA}


@dataclass(frozen=True, slots=True)
class Model:
    """A flat rule: one use per criterion and one match mode for includes.

    ``uses`` maps a leaf key to ``("include" | "exclude", value)``. Numbers are
    floats, enums are strings and list leaves are tuples of strings in their
    original order.
    """

    join: str
    uses: Mapping[str, tuple[str, Any]]

    def __post_init__(self) -> None:
        # The match mode only affects two or more included criteria.
        includes = 0
        for entry in self.uses.values():
            try:
                if entry[0] == USE_INCLUDE:
                    includes += 1
            except (IndexError, TypeError):
                continue
        if includes < 2 and self.join == "all":
            object.__setattr__(self, "join", "any")


@dataclass(frozen=True, slots=True)
class ConditionRead:
    """The builder model for a stored condition, or why it is text mode."""

    model: Model | None
    reason: str | None = None

    @property
    def representable(self) -> bool:
        return self.model is not None


@dataclass(frozen=True, slots=True)
class BuildResult:
    """Stage A validation result: a model, or field-keyed fixed messages."""

    model: Model | None
    errors: tuple[tuple[str, str], ...] = ()

    @property
    def ok(self) -> bool:
        return self.model is not None and not self.errors

    def error_for(self, field: str) -> str | None:
        for key, message in self.errors:
            if key == field:
                return message
        return None


def read_condition(raw: Any) -> ConditionRead:
    """Classify a stored condition as a builder model or text mode with a reason."""
    try:
        condition = parse_condition(raw)
    except ConfigurationError:
        return ConditionRead(None, REASON_UNREADABLE)
    model, reason = _model_from_condition(condition)
    return ConditionRead(model, reason)


def to_model(raw: Any) -> Model | None:
    """Return the builder model for a stored condition, or ``None``.

    Use :func:`read_condition` when the text-mode reason is needed too.
    """
    return read_condition(raw).model


def from_model(model: Model) -> dict[str, Any]:
    """Compose the canonical stored condition for a builder model."""
    includes, excludes = _split_uses(model)
    if not includes:
        raise ValueError("a rule needs at least one included criterion")
    include_expression = _combine(includes, model.join)
    if not excludes:
        return include_expression
    if len(excludes) == 1:
        excluded: dict[str, Any] = {"not": _leaf(excludes[0])}
    else:
        excluded = {"not": {"any": [_leaf(item) for item in excludes]}}
    return {"all": [include_expression, excluded]}


def keep_original_condition(
    original: Any, model: Model
) -> dict[str, Any]:
    """Return the condition to save, keeping the stored document when unchanged.

    Reusing the stored table byte-for-byte keeps ``condition_payload`` and
    ``rule_hash`` stable for an unrelated edit (for example a renamed rule), so
    a save does not re-baseline stored alert state.
    """
    current = read_condition(original)
    if (
        current.model is not None
        and current.model == model
        and isinstance(original, dict)
    ):
        return copy.deepcopy(original)
    return from_model(model)


def build_model(
    join: str,
    uses: Mapping[str, str],
    values: Mapping[str, str],
) -> BuildResult:
    """Validate stage A form rows and build the model.

    ``uses`` and ``values`` are keyed by criterion key (the form layer adds its
    own per-rule prefix). Unknown keys raise :class:`ValueError`; that is a
    forged field, not a user error, and the form layer turns it into a 400.
    """
    unknown = (set(uses) | set(values)) - set(CRITERIA_BY_KEY)
    if unknown:
        raise ValueError("unknown criterion " + ", ".join(sorted(unknown)))

    join = join.strip() if isinstance(join, str) else ""
    errors: list[tuple[str, str]] = []
    if join not in JOINS:
        errors.append((BUILD_FIELD_JOIN, "Match: choose one of the options."))

    built: dict[str, tuple[str, Any]] = {}
    chosen_include = False
    for criterion in CRITERIA:
        use = uses.get(criterion.key)
        if use is None:
            use = USE_NOT_USED
        elif isinstance(use, str):
            use = use.strip()
        else:
            use = None
        if use not in (USE_NOT_USED, USE_INCLUDE, USE_EXCLUDE):
            errors.append((criterion.key, _choose_message(criterion)))
            continue
        if use == USE_NOT_USED:
            continue
        chosen_include = chosen_include or use == USE_INCLUDE
        text = values.get(criterion.key, "")
        if not isinstance(text, str):
            text = ""
        value, message = _parse_value(criterion, text)
        if message is not None:
            errors.append((criterion.key, message))
            continue
        built[criterion.key] = (use, value)

    if not chosen_include:
        errors.append((BUILD_FIELD_CRITERIA, NO_CRITERIA_MESSAGE))
    if errors:
        return BuildResult(None, tuple(errors))
    return BuildResult(Model(join, built))


def describe(model: Model) -> str:
    """Describe a model in plain words, never with raw setting keys."""
    includes, excludes = _split_uses(model)
    if not includes:
        return "No criteria are included, so this rule does not alert."
    include_text = [_criterion_text(key, value) for key, value in includes]
    if len(include_text) == 1:
        parts = [f"Alert when: {include_text[0]}."]
    else:
        mode = "ALL" if model.join == "all" else "ANY"
        parts = [f"Alert when {mode} of: " + "; ".join(include_text) + "."]
    if excludes:
        exclude_text = [_criterion_text(key, value) for key, value in excludes]
        if len(exclude_text) == 1:
            parts.append(f"Never alert when: {exclude_text[0]}.")
        else:
            parts.append(
                "Never alert when any of: " + "; ".join(exclude_text) + "."
            )
    return " ".join(parts)


def _model_from_condition(
    condition: Condition,
) -> tuple[Model | None, str | None]:
    if condition.kind == "not":
        return None, REASON_NESTED

    if condition.kind == "all" and len(condition.children) == 2:
        negated = [child for child in condition.children if child.kind == "not"]
        if len(negated) == 1:
            positive = next(
                child for child in condition.children if child.kind != "not"
            )
            includes, join, reason = _flat_group(positive)
            if reason is not None:
                return None, reason
            excluded = negated[0].children[0]
            excludes, reason = _excluded_group(excluded)
            if reason is not None:
                return None, reason
            return _assemble(join, includes, excludes)

    includes, join, reason = _flat_group(condition)
    if reason is not None:
        return None, reason
    return _assemble(join, includes, [])


def _flat_group(
    node: Condition,
) -> tuple[list[tuple[str, Any]], str, str | None]:
    """Read a leaf or an any/all group whose children are single-leaf tables."""
    if node.kind == "leaf":
        key, value, reason = _leaf_entry(node)
        if reason is not None:
            return [], "any", reason
        return [(key, value)], "any", None
    if node.kind in ("any", "all"):
        leaves: list[tuple[str, Any]] = []
        for child in node.children:
            key, value, reason = _leaf_entry(child)
            if reason is not None:
                return [], node.kind, reason
            leaves.append((key, value))
        return leaves, node.kind, None
    return [], "any", REASON_NESTED


def _excluded_group(
    node: Condition,
) -> tuple[list[tuple[str, Any]], str | None]:
    """Read the negated side: one leaf or an any group of single-leaf tables."""
    if node.kind == "leaf":
        key, value, reason = _leaf_entry(node)
        if reason is not None:
            return [], reason
        return [(key, value)], None
    if node.kind == "any":
        leaves: list[tuple[str, Any]] = []
        for child in node.children:
            key, value, reason = _leaf_entry(child)
            if reason is not None:
                return [], reason
            leaves.append((key, value))
        return leaves, None
    return [], REASON_NESTED


def _leaf_entry(node: Condition) -> tuple[str, Any, str | None]:
    if node.kind != "leaf":
        return "", None, REASON_NESTED
    if len(node.leaves) != 1:
        return "", None, REASON_MULTIPLE_KEYS
    key, value = node.leaves[0]
    if key not in CRITERIA_BY_KEY:
        return "", None, REASON_UNREADABLE
    if isinstance(value, CVSSCondition):
        return "", None, REASON_QUALIFIED
    if isinstance(value, tuple) and any("," in item for item in value):
        return "", None, REASON_COMMA
    return key, value, None


def _assemble(
    join: str,
    includes: Iterable[tuple[str, Any]],
    excludes: Iterable[tuple[str, Any]],
) -> tuple[Model | None, str | None]:
    include_rows = list(includes)
    exclude_rows = list(excludes)
    keys = [key for key, _ in include_rows] + [key for key, _ in exclude_rows]
    if len(keys) != len(set(keys)):
        return None, REASON_REPEATED
    if not include_rows:
        return None, REASON_NESTED
    uses = {key: (USE_INCLUDE, value) for key, value in include_rows}
    uses.update({key: (USE_EXCLUDE, value) for key, value in exclude_rows})
    return Model(join, uses), None


def _split_uses(
    model: Model,
) -> tuple[list[tuple[str, Any]], list[tuple[str, Any]]]:
    if model.join not in JOINS:
        raise ValueError("unknown match mode")
    unknown = set(model.uses) - set(CRITERIA_BY_KEY)
    if unknown:
        raise ValueError("unknown criterion " + ", ".join(sorted(unknown)))
    includes: list[tuple[str, Any]] = []
    excludes: list[tuple[str, Any]] = []
    for criterion in CRITERIA:
        entry = model.uses.get(criterion.key)
        if entry is None:
            continue
        try:
            use, value = entry
        except (TypeError, ValueError):
            raise ValueError("invalid builder entry") from None
        if use == USE_INCLUDE:
            includes.append((criterion.key, value))
        elif use == USE_EXCLUDE:
            excludes.append((criterion.key, value))
        else:
            raise ValueError("invalid builder use")
    return includes, excludes


def _combine(rows: list[tuple[str, Any]], join: str) -> dict[str, Any]:
    if len(rows) == 1:
        return _leaf(rows[0])
    return {join: [_leaf(row) for row in rows]}


def _leaf(row: tuple[str, Any]) -> dict[str, Any]:
    key, value = row
    criterion = CRITERIA_BY_KEY[key]
    if criterion.kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("a number criterion needs a number")
        return {key: float(value)}
    if criterion.kind in ("strings", "cwe"):
        if not isinstance(value, (list, tuple)) or not value:
            raise ValueError("a list criterion needs at least one value")
        if not all(isinstance(item, str) for item in value):
            raise ValueError("a list criterion needs text values")
        return {key: list(value)}
    if not isinstance(value, str):
        raise ValueError("an option criterion needs a string")
    if value not in {choice for choice, _ in criterion.choices}:
        raise ValueError("an option criterion needs one of its choices")
    return {key: value}


def _parse_value(
    criterion: Criterion, text: str
) -> tuple[Any, str | None]:
    text = text.strip()
    if criterion.kind == "number":
        return _parse_number(criterion, text)
    if criterion.kind == "enum":
        value = text.casefold()
        if value not in {choice for choice, _ in criterion.choices}:
            return None, _choose_message(criterion)
        return value, None
    items = [part.strip() for part in text.split(",") if part.strip()]
    if not items:
        return None, _list_empty_message(criterion)
    if len(items) > MAX_LIST_ITEMS:
        return None, _list_size_message(criterion)
    if any(len(item) > MAX_STRING for item in items):
        return None, _string_size_message(criterion)
    if criterion.kind == "cwe":
        normalized: list[str] = []
        for item in items:
            match = CWE_PATTERN.fullmatch(item)
            if match is None:
                return None, _cwe_message(criterion)
            normalized.append(f"CWE-{int(match.group(1))}")
        return tuple(_dedupe(normalized)), None
    return tuple(_dedupe(items)), None


def _parse_number(
    criterion: Criterion, text: str
) -> tuple[float | None, str | None]:
    if "_" in text:
        return None, _number_message(criterion)
    try:
        number = float(text)
    except ValueError:
        return None, _number_message(criterion)
    if (
        not math.isfinite(number)
        or criterion.minimum is None
        or criterion.maximum is None
        or not criterion.minimum <= number <= criterion.maximum
    ):
        return None, _number_message(criterion)
    if number == 0:
        # Normalise -0.0 so descriptions never read "at least -0.0".
        number = 0.0
    return number, None


def _dedupe(items: Iterable[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for item in items:
        folded = item.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        output.append(item)
    return output


def _choose_message(criterion: Criterion) -> str:
    return f"{criterion.label}: choose one of the options."


def _number_message(criterion: Criterion) -> str:
    return (
        f"{criterion.label}: enter a number from "
        f"{_number_text(criterion.minimum)} to {_number_text(criterion.maximum)}."
    )


def _list_empty_message(criterion: Criterion) -> str:
    return f"{criterion.label}: enter at least one value, separated by commas."


def _list_size_message(criterion: Criterion) -> str:
    return (
        f"{criterion.label}: enter at most {MAX_LIST_ITEMS} values, "
        "separated by commas."
    )


def _string_size_message(criterion: Criterion) -> str:
    return (
        f"{criterion.label}: each value must be at most "
        f"{MAX_STRING} characters."
    )


def _cwe_message(criterion: Criterion) -> str:
    return f"{criterion.label}: use a CWE number such as 79 or CWE-787."


def _criterion_text(key: str, value: Any) -> str:
    if key == "kev":
        return {
            "cisa": "on the CISA list",
            "eu": "on the EU list",
            "any": "on either known-exploited list",
        }[value]
    if key == "exploitation":
        return {
            "poc": "exploit code exists or is active",
            "active": "actively exploited",
        }[value]
    if key == "cvss_min":
        return f"severity score at least {_display_number(value)}"
    if key == "cvss_max":
        return f"severity score at most {_display_number(value)}"
    if key == "epss_min":
        return f"exploitation chance at least {_display_number(value)}"
    if key == "vendor":
        return _name_text("vendor", value)
    if key == "product":
        return _name_text("product", value)
    if key == "keyword":
        items = list(value)
        if len(items) == 1:
            return f"description contains {items[0]}"
        return "description contains any of " + ", ".join(items)
    if key == "cwe":
        items = list(value)
        if len(items) == 1:
            return f"weakness type is {items[0]}"
        return "weakness type is one of " + ", ".join(items)
    if key == "cna":
        items = list(value)
        if len(items) == 1:
            return f"reported by {items[0]}"
        return "reported by one of " + ", ".join(items)
    if key == "status":
        return f"status is {_choice_label(CRITERIA_BY_KEY[key], value)}"
    raise ValueError(f"unknown criterion {key!r}")


def _name_text(noun: str, value: Any) -> str:
    items = list(value)
    if len(items) == 1:
        return f"{noun} is {items[0]}"
    return f"{noun} is one of " + ", ".join(items)


def _choice_label(criterion: Criterion, value: str) -> str:
    for choice, label in criterion.choices:
        if choice == value:
            return label
    return value


def _number_text(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:g}"


def _display_number(value: Any) -> str:
    """Format a stored score in plain decimal without changing its value."""
    number = float(value)
    if number == 0:
        # Normalise -0.0 so a description never reads "at least -0.0".
        number = 0.0
    return format(Decimal(repr(number)), "f")
