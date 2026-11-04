"""Rule parsing, validation and deterministic alert evaluation."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from ..errors import ConfigurationError
from .records import CVSS_PROVIDERS, WatchView

EVENT_KINDS = (
    "match",
    "kev_added",
    "exploitation_active",
    "severity_increase",
    "epss_increase",
    "nvd_score_added",
    "rejected",
)
DEFAULT_EVENTS = EVENT_KINDS
SEVERITY_BANDS = ("none", "low", "medium", "high", "critical")
EPSS_BAND_LABELS = ("none", "<0.1", "<0.5", "<0.9", ">=0.9")
LEAF_KEYS = (
    "cvss_min",
    "cvss_max",
    "epss_min",
    "kev",
    "exploitation",
    "vendor",
    "product",
    "keyword",
    "cwe",
    "cna",
    "status",
)
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}")
MAX_DEPTH = 4
MAX_LEAVES = 32
MAX_LIST_ITEMS = 100
MAX_STRING = 200


@dataclass(frozen=True, slots=True)
class Condition:
    """One node of a rule condition tree."""

    kind: str
    children: tuple["Condition", ...] = ()
    leaves: tuple[tuple[str, Any], ...] = ()

    def contains_leaf(self, key: str, value: Any | None = None) -> bool:
        if self.kind == "leaf":
            return any(name == key and (value is None or item == value) for name, item in self.leaves)
        return any(child.contains_leaf(key, value) for child in self.children)

    def epss_minima(self) -> tuple[float, ...]:
        if self.kind == "leaf":
            return tuple(
                float(value) for name, value in self.leaves if name == "epss_min"
            )
        output: list[float] = []
        for child in self.children:
            output.extend(child.epss_minima())
        return tuple(output)


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    condition: Condition
    channels: tuple[str, ...]
    events: tuple[str, ...] = DEFAULT_EVENTS
    cvss_providers: tuple[str, ...] = CVSS_PROVIDERS
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class AlertSnapshot:
    cisa_kev: bool
    eu_kev: bool
    exploitation: str
    severity_band: str
    epss_band: str
    nvd_score: bool
    status: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "cisa_kev": self.cisa_kev,
            "eu_kev": self.eu_kev,
            "exploitation": self.exploitation,
            "severity_band": self.severity_band,
            "epss_band": self.epss_band,
            "nvd_score": self.nvd_score,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AlertSnapshot":
        try:
            snapshot = cls(
                cisa_kev=value["cisa_kev"],
                eu_kev=value["eu_kev"],
                exploitation=str(value["exploitation"]),
                severity_band=str(value["severity_band"]),
                epss_band=str(value["epss_band"]),
                nvd_score=value["nvd_score"],
                status=str(value["status"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid alert snapshot") from exc
        if not isinstance(snapshot.cisa_kev, bool) or not isinstance(snapshot.nvd_score, bool):
            raise ValueError("invalid alert snapshot")
        if not isinstance(snapshot.eu_kev, bool):
            raise ValueError("invalid alert snapshot")
        if snapshot.exploitation not in {"none", "poc", "active"}:
            raise ValueError("invalid alert snapshot")
        if snapshot.severity_band not in SEVERITY_BANDS:
            raise ValueError("invalid alert snapshot")
        if snapshot.epss_band not in EPSS_BAND_LABELS:
            raise ValueError("invalid alert snapshot")
        if snapshot.status not in {"published", "rejected"}:
            raise ValueError("invalid alert snapshot")
        return snapshot


@dataclass(frozen=True, slots=True)
class AlertState:
    first_matched_at: str
    snapshot: AlertSnapshot


@dataclass(frozen=True, slots=True)
class AlertEvent:
    rule: str
    cve_id: str
    kind: str
    reasons: tuple[str, ...]


def _fail(path: str, message: str) -> None:
    raise ConfigurationError(f"{path} {message}")


def _number(value: Any, path: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(path, f"must be a number from {minimum:g} to {maximum:g}")
    try:
        number = float(value)
    except OverflowError:
        _fail(path, f"must be a number from {minimum:g} to {maximum:g}")
    if not math.isfinite(number) or not minimum <= number <= maximum:
        _fail(path, f"must be a number from {minimum:g} to {maximum:g}")
    return number


def _enum(value: Any, path: str, allowed: Sequence[str]) -> str:
    if not isinstance(value, str):
        _fail(path, "must be one of " + ", ".join(allowed))
    text = value.strip().casefold()
    if text not in allowed:
        _fail(path, "must be one of " + ", ".join(allowed))
    return text


def _strings(value: Any, path: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(path, "must be a list of strings")
    if not value:
        _fail(path, "must contain at least one item")
    if len(value) > MAX_LIST_ITEMS:
        _fail(path, f"must contain at most {MAX_LIST_ITEMS} items")
    output: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str):
            _fail(f"{path}[{index}]", "must be a string")
        text = item.strip()
        if not text:
            _fail(f"{path}[{index}]", "must not be empty")
        if len(text) > MAX_STRING:
            _fail(f"{path}[{index}]", f"must be at most {MAX_STRING} characters")
        key = text.casefold()
        if key not in seen:
            seen.add(key)
            output.append(text)
    return tuple(output)


def _leaf_value(key: str, value: Any, path: str) -> Any:
    if key in {"cvss_min", "cvss_max"}:
        return _number(value, path, 0.0, 10.0)
    if key == "epss_min":
        return _number(value, path, 0.0, 1.0)
    if key == "kev":
        return _enum(value, path, ("cisa", "eu", "any"))
    if key == "exploitation":
        return _enum(value, path, ("poc", "active"))
    if key in {"vendor", "product", "keyword", "cwe", "cna"}:
        return _strings(value, path)
    if key == "status":
        return _enum(value, path, ("published", "rejected"))
    _fail(path, "is not a known condition key")
    raise AssertionError("unreachable")


def _parse_condition(
    raw: Any,
    path: str,
    *,
    depth: int,
    leaf_count: list[int],
) -> Condition:
    if not isinstance(raw, dict):
        _fail(path, "must be a table")
    keys = set(raw)
    boolean_keys = [key for key in ("all", "any", "not") if key in keys]
    if len(boolean_keys) > 1:
        _fail(path, "must contain exactly one of all, any or not")
    if boolean_keys and keys - {boolean_keys[0]}:
        _fail(path, "cannot mix a boolean key with leaf keys")
    if not keys:
        _fail(path, "must not be empty")
    if boolean_keys:
        key = boolean_keys[0]
        node_depth = depth + 1
        if node_depth > MAX_DEPTH:
            _fail(path, f"exceeds the nesting depth limit of {MAX_DEPTH}")
        if key == "not":
            return Condition(
                "not",
                (_parse_condition(
                    raw[key],
                    f"{path}.not",
                    depth=node_depth,
                    leaf_count=leaf_count,
                ),),
            )
        value = raw[key]
        if not isinstance(value, list):
            _fail(f"{path}.{key}", "must be a list")
        if not value:
            _fail(f"{path}.{key}", "must not be empty")
        children = []
        for index, item in enumerate(value):
            children.append(
                _parse_condition(
                    item,
                    f"{path}.{key}[{index}]",
                    depth=node_depth,
                    leaf_count=leaf_count,
                )
            )
        return Condition(key, tuple(children))
    leaves: list[tuple[str, Any]] = []
    for key in sorted(keys):
        if key not in LEAF_KEYS:
            _fail(path, f"has unknown key {key!r}")
        leaf_count[0] += 1
        if leaf_count[0] > MAX_LEAVES:
            _fail(path, f"exceeds the limit of {MAX_LEAVES} leaves per rule")
        leaves.append((key, _leaf_value(key, raw[key], f"{path}.{key}")))
    return Condition("leaf", (), tuple(leaves))


def parse_condition(raw: Any, *, path: str = "condition") -> Condition:
    return _parse_condition(raw, path, depth=0, leaf_count=[0])


def _rule_events(value: Any, path: str) -> tuple[str, ...]:
    if value is None:
        return DEFAULT_EVENTS
    if not isinstance(value, list):
        _fail(path, "must be a list of event kinds")
    output: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        kind = _enum(item, f"{path}[{index}]", EVENT_KINDS)
        if kind not in seen:
            seen.add(kind)
            output.append(kind)
    return tuple(output)


def _rule_providers(value: Any, path: str) -> tuple[str, ...]:
    if value is None:
        return CVSS_PROVIDERS
    if not isinstance(value, list) or not value:
        _fail(path, "must be a nonempty list of CVSS providers")
    output: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        provider = _enum(item, f"{path}[{index}]", CVSS_PROVIDERS)
        if provider not in seen:
            seen.add(provider)
            output.append(provider)
    return tuple(output)


def _rule_channels(value: Any, path: str) -> tuple[str, ...]:
    if value is None:
        _fail(path, "is required")
    if not isinstance(value, list) or not value:
        _fail(path, "must be a nonempty list of channel names")
    output: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str):
            _fail(f"{path}[{index}]", "must be a string")
        text = item.strip()
        if not text:
            _fail(f"{path}[{index}]", "must not be empty")
        if len(text) > MAX_STRING:
            _fail(f"{path}[{index}]", f"must be at most {MAX_STRING} characters")
        if text not in seen:
            seen.add(text)
            output.append(text)
    return tuple(output)


def parse_rules(raw: Any, *, path: str = "watch.rules") -> tuple[Rule, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        _fail(path, "must be an array of tables")
    rules: list[Rule] = []
    names: dict[str, str] = {}
    for index, item in enumerate(raw):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            _fail(item_path, "must be a table")
        unknown = sorted(set(item) - {
            "name", "enabled", "condition", "channels", "events", "cvss_providers"
        })
        if unknown:
            _fail(item_path, "has unknown key " + ", ".join(repr(key) for key in unknown))
        name = item.get("name")
        if not isinstance(name, str):
            _fail(f"{item_path}.name", "is required")
        name = name.strip()
        if NAME_PATTERN.fullmatch(name) is None:
            _fail(
                f"{item_path}.name",
                "must start with a letter or digit and contain at most 64 "
                "letters, digits, spaces, underscores, dots or hyphens",
            )
        folded = name.casefold()
        if folded in names:
            _fail(item_path, f"duplicate watch rule name {name!r}")
        names[folded] = name
        label = f"watch rule {name!r}"
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            _fail(f"{label} enabled", "must be true or false")
        if "condition" not in item:
            _fail(f"{label} condition", "is required")
        condition = _parse_condition(
            item["condition"], f"{label} condition", depth=0, leaf_count=[0]
        )
        channels = _rule_channels(item.get("channels"), f"{label} channels")
        events = _rule_events(item.get("events"), f"{label} events")
        providers = _rule_providers(
            item.get("cvss_providers"), f"{label} cvss_providers"
        )
        rules.append(Rule(name, condition, channels, events, providers, enabled))
    return tuple(rules)


def _provider_priority(provider: str) -> int:
    try:
        return CVSS_PROVIDERS.index(provider)
    except ValueError:
        return len(CVSS_PROVIDERS)


def highest_cvss(view: WatchView, providers: Sequence[str]) -> Any | None:
    selected = [entry for entry in view.cvss if entry.provider in providers]
    if not selected:
        return None
    return max(
        selected,
        key=lambda entry: (
            entry.score,
            -_provider_priority(entry.provider),
            entry.source,
            entry.version,
        ),
    )


def _severity_band(score: float | None) -> str:
    if score is None or score < 0.1:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def _epss_band(value: float | None) -> str:
    if value is None:
        return "none"
    if value < 0.1:
        return "<0.1"
    if value < 0.5:
        return "<0.5"
    if value < 0.9:
        return "<0.9"
    return ">=0.9"


def snapshot_for(view: WatchView, rule: Rule) -> AlertSnapshot:
    highest = highest_cvss(view, rule.cvss_providers)
    return AlertSnapshot(
        cisa_kev=view.cisa_kev_added is not None,
        eu_kev=view.eu_kev_added is not None,
        exploitation=view.ssvc_exploitation or "none",
        severity_band=_severity_band(highest.score if highest is not None else None),
        epss_band=_epss_band(view.epss),
        nvd_score=any(entry.provider == "nvd" for entry in view.cvss),
        status=view.status,
    )


def _first_match(values: Iterable[str], target: str) -> str | None:
    folded = target.casefold()
    for value in values:
        if value.casefold() == folded:
            return value
    return None


def _keyword_match(values: Iterable[str], description: str | None) -> str | None:
    if not description:
        return None
    folded = description.casefold()
    for value in values:
        if value.casefold() in folded:
            return value
    return None


def _matches_leaf(view: WatchView, key: str, value: Any, rule: Rule) -> tuple[bool, str | None]:
    if key in {"cvss_min", "cvss_max"}:
        highest = highest_cvss(view, rule.cvss_providers)
        if highest is None:
            return False, None
        if key == "cvss_min":
            matched = highest.score >= value
        else:
            matched = highest.score <= value
        return matched, f"cvss {highest.score:g} ({highest.provider})"
    if key == "epss_min":
        if view.epss is None:
            return False, None
        return view.epss >= value, f"epss {view.epss:g}"
    if key == "kev":
        present = []
        if view.cisa_kev_added is not None:
            present.append(("cisa", "kev cisa"))
        if view.eu_kev_added is not None:
            present.append(("eu", "kev eu"))
        selected = [reason for catalog, reason in present if value in ("any", catalog)]
        return bool(selected), selected[0] if selected else None
    if key == "exploitation":
        current = view.ssvc_exploitation or "none"
        matched = current == "active" or (value == "poc" and current == "poc")
        return matched, f"exploitation {current}"
    if key == "vendor":
        found = next(
            (match for name in value if (match := _first_match(view.vendors, name))),
            None,
        )
        return found is not None, f"vendor {found}" if found is not None else None
    if key == "product":
        found = next(
            (match for name in value if (match := _first_match(view.products, name))),
            None,
        )
        return found is not None, f"product {found}" if found is not None else None
    if key == "keyword":
        found = _keyword_match(value, view.description)
        return found is not None, f"keyword {found}" if found is not None else None
    if key == "cwe":
        wanted = {item.casefold() for item in value}
        found = next((item for item in view.cwes if item.casefold() in wanted), None)
        return found is not None, f"cwe {found}" if found is not None else None
    if key == "cna":
        if view.source_identifier is None:
            return False, None
        source = view.source_identifier
        matched = any(source.casefold() == item.casefold() for item in value)
        return matched, f"cna {source}" if matched else None
    if key == "status":
        return view.status == value, f"status {view.status}"
    raise AssertionError(f"unknown condition key {key}")


def evaluate_condition(
    view: WatchView, condition: Condition, rule: Rule
) -> tuple[bool, tuple[str, ...]]:
    """Return whether the condition matches and the true leaves that explain it."""
    if condition.kind == "leaf":
        reasons: list[str] = []
        for key, value in condition.leaves:
            matched, reason = _matches_leaf(view, key, value, rule)
            if not matched:
                return False, ()
            if reason is not None and reason not in reasons:
                reasons.append(reason)
        return True, tuple(reasons)
    if condition.kind == "all":
        reasons: list[str] = []
        for child in condition.children:
            matched, child_reasons = evaluate_condition(view, child, rule)
            if not matched:
                return False, ()
            for reason in child_reasons:
                if reason not in reasons:
                    reasons.append(reason)
        return True, tuple(reasons)
    if condition.kind == "any":
        reasons: list[str] = []
        matched_any = False
        for child in condition.children:
            matched, child_reasons = evaluate_condition(view, child, rule)
            if matched:
                matched_any = True
                for reason in child_reasons:
                    if reason not in reasons:
                        reasons.append(reason)
        return matched_any, tuple(reasons) if matched_any else ()
    if condition.kind == "not":
        matched, _ = evaluate_condition(view, condition.children[0], rule)
        if matched:
            return False, ()
        return True, (f"not {describe_condition(condition.children[0])}",)
    raise AssertionError(f"unknown condition kind {condition.kind}")


def _event(
    view: WatchView, rule: Rule, kind: str, reasons: Sequence[str]
) -> AlertEvent:
    return AlertEvent(rule.name, view.cve_id, kind, tuple(reasons))


def evaluate(
    view: WatchView,
    previous: AlertState | None,
    rule: Rule,
    now: datetime,
) -> tuple[AlertState | None, tuple[AlertEvent, ...]]:
    """Evaluate one rule against one view without reading state or the clock."""
    if not rule.enabled:
        return previous, ()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    timestamp = now.astimezone(timezone.utc).isoformat()
    snapshot = snapshot_for(view, rule)
    if previous is None:
        matched, reasons = evaluate_condition(view, rule.condition, rule)
        if matched and view.status == "rejected" and not rule.condition.contains_leaf(
            "status", "rejected"
        ):
            matched, reasons = False, ()
        if not matched:
            return None, ()
        state = AlertState(timestamp, snapshot)
        if "match" not in rule.events:
            return state, ()
        return state, (_event(view, rule, "match", reasons),)

    events: list[AlertEvent] = []
    old = previous.snapshot
    if "kev_added" in rule.events:
        if not old.cisa_kev and snapshot.cisa_kev:
            events.append(
                _event(view, rule, "kev_added", ("kev cisa false \u2192 true",))
            )
        if not old.eu_kev and snapshot.eu_kev:
            events.append(
                _event(view, rule, "kev_added", ("kev eu false \u2192 true",))
            )
    if (
        "exploitation_active" in rule.events
        and old.exploitation != "active"
        and snapshot.exploitation == "active"
    ):
        events.append(
            _event(
                view,
                rule,
                "exploitation_active",
                (f"exploitation {old.exploitation} \u2192 active",),
            )
        )
    if (
        "severity_increase" in rule.events
        and SEVERITY_BANDS.index(snapshot.severity_band)
        > SEVERITY_BANDS.index(old.severity_band)
    ):
        events.append(
            _event(
                view,
                rule,
                "severity_increase",
                (f"severity {old.severity_band} \u2192 {snapshot.severity_band}",),
            )
        )
    if (
        "epss_increase" in rule.events
        and EPSS_BAND_LABELS.index(snapshot.epss_band) > EPSS_BAND_LABELS.index(old.epss_band)
    ):
        events.append(
            _event(
                view,
                rule,
                "epss_increase",
                (f"epss {old.epss_band} \u2192 {snapshot.epss_band}",),
            )
        )
    if "nvd_score_added" in rule.events and not old.nvd_score and snapshot.nvd_score:
        events.append(
            _event(view, rule, "nvd_score_added", ("nvd score absent \u2192 present",))
        )
    if (
        "rejected" in rule.events
        and old.status != "rejected"
        and snapshot.status == "rejected"
    ):
        events.append(
            _event(view, rule, "rejected", (f"status {old.status} \u2192 rejected",))
        )
    return AlertState(previous.first_matched_at, snapshot), tuple(events)


def _format_number(value: float) -> str:
    return str(float(value))


def _describe_leaf(key: str, value: Any) -> str:
    if key == "cvss_min":
        return f"cvss \u2265 {_format_number(value)}"
    if key == "cvss_max":
        return f"cvss \u2264 {_format_number(value)}"
    if key == "epss_min":
        return f"epss \u2265 {_format_number(value)}"
    if key == "kev":
        return f"kev {value}"
    if key == "exploitation":
        return f"exploitation {value}"
    if key == "vendor":
        return "vendor in [" + ", ".join(value) + "]"
    if key == "product":
        return "product in [" + ", ".join(value) + "]"
    if key == "keyword":
        return "keyword contains [" + ", ".join(value) + "]"
    if key == "cwe":
        return "cwe in [" + ", ".join(value) + "]"
    if key == "cna":
        return "cna in [" + ", ".join(value) + "]"
    if key == "status":
        return f"status = {value}"
    return f"{key} = {value}"


def describe_condition(condition: Condition) -> str:
    if condition.kind == "leaf":
        return " AND ".join(
            _describe_leaf(key, value) for key, value in condition.leaves
        )
    if condition.kind == "all":
        return "(" + " AND ".join(
            describe_condition(child) for child in condition.children
        ) + ")"
    if condition.kind == "any":
        return "(" + " OR ".join(
            describe_condition(child) for child in condition.children
        ) + ")"
    if condition.kind == "not":
        inner = describe_condition(condition.children[0])
        if inner.startswith("(") and inner.endswith(")"):
            return "NOT " + inner
        return f"NOT ({inner})"
    raise AssertionError(f"unknown condition kind {condition.kind}")


def rule_epss_thresholds(rules: Iterable[Rule]) -> tuple[float, ...]:
    values: set[float] = set()
    for rule in rules:
        if rule.enabled:
            values.update(rule.condition.epss_minima())
    return tuple(sorted(values))
