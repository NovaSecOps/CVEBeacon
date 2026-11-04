"""Rule parsing, validation and deterministic alert evaluation."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, replace
from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from ..errors import ConfigurationError
from .records import CVSS_PROVIDERS, WatchView, canonical_json, euvd_datetime

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
CWE_PATTERN = re.compile(r"(?i)^(?:cwe-)?(\d{1,9})$")
MAX_DEPTH = 4
MAX_LEAVES = 32
MAX_LIST_ITEMS = 100
MAX_STRING = 200
OLD_CVES_MODES = ("digest", "alert", "ignore")


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
    old_cves: str = "digest"


@dataclass(frozen=True, slots=True)
class AlertSnapshot:
    cisa_kev: bool
    eu_kev: bool
    exploitation: str
    severity_band: str
    epss_band: str
    nvd_score: bool
    status: str
    max_severity_band: str = "none"
    max_epss_band: str = "none"

    def as_dict(self) -> dict[str, Any]:
        return {
            "cisa_kev": self.cisa_kev,
            "eu_kev": self.eu_kev,
            "exploitation": self.exploitation,
            "severity_band": self.severity_band,
            "epss_band": self.epss_band,
            "nvd_score": self.nvd_score,
            "status": self.status,
            "max_severity_band": self.max_severity_band,
            "max_epss_band": self.max_epss_band,
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
                max_severity_band=str(
                    value.get("max_severity_band", value["severity_band"])
                ),
                max_epss_band=str(value.get("max_epss_band", value["epss_band"])),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
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
        if snapshot.max_severity_band not in SEVERITY_BANDS:
            raise ValueError("invalid alert snapshot")
        if snapshot.max_epss_band not in EPSS_BAND_LABELS:
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
    occurrence: str
    initial: bool = False


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


def _cwe_values(value: Any, path: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(path, "must be a list of CWE identifiers")
    if not value:
        _fail(path, "must contain at least one item")
    if len(value) > MAX_LIST_ITEMS:
        _fail(path, f"must contain at most {MAX_LIST_ITEMS} items")
    output: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if isinstance(item, bool) or not isinstance(item, (str, int)):
            _fail(f"{path}[{index}]", "must be a CWE number or string")
        text = str(item).strip()
        if not text:
            _fail(f"{path}[{index}]", "must not be empty")
        if len(text) > MAX_STRING:
            _fail(f"{path}[{index}]", f"must be at most {MAX_STRING} characters")
        match = CWE_PATTERN.fullmatch(text)
        if match is None:
            _fail(
                f"{path}[{index}]",
                "must be a CWE number such as 79, cwe-79 or CWE-79",
            )
        normalized = f"CWE-{int(match.group(1))}"
        key = normalized.casefold()
        if key not in seen:
            seen.add(key)
            output.append(normalized)
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
    if key == "cwe":
        return _cwe_values(value, path)
    if key in {"vendor", "product", "keyword", "cna"}:
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
    if not output:
        _fail(path, "must contain at least one event kind")
    return tuple(output)


def _rule_old_cves(value: Any, path: str) -> str:
    if value is None:
        return "digest"
    if not isinstance(value, str):
        _fail(path, "must be one of digest, alert, ignore")
    text = value.strip().casefold()
    if text not in OLD_CVES_MODES:
        _fail(path, "must be one of digest, alert, ignore")
    return text


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
            "name", "enabled", "condition", "channels", "events", "cvss_providers",
            "old_cves",
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
        old_cves = _rule_old_cves(item.get("old_cves"), f"{label} old_cves")
        rules.append(
            Rule(
                name=name,
                condition=condition,
                channels=channels,
                events=events,
                cvss_providers=providers,
                enabled=enabled,
                old_cves=old_cves,
            )
        )
    return tuple(rules)


def validate_rule_sources(rules: Iterable[Rule], sources: Iterable[str]) -> None:
    """Reject rules whose only evidence source is not configured."""
    configured = set(sources)
    for rule in rules:
        if rule.condition.contains_leaf("kev", "eu") and "eu_kev" not in configured:
            raise ConfigurationError(
                f"watch rule {rule.name!r} uses kev = \"eu\" but eu_kev "
                "is not in watch.sources"
            )
        if rule.condition.contains_leaf("epss_min") and "epss" not in configured:
            raise ConfigurationError(
                f"watch rule {rule.name!r} uses epss_min but epss "
                "is not in watch.sources"
            )
        if set(rule.cvss_providers) == {"euvd"} and "euvd" not in configured:
            raise ConfigurationError(
                f"watch rule {rule.name!r} selects only the euvd CVSS provider "
                "but euvd is not in watch.sources"
            )


def _provider_priority(provider: str) -> int:
    try:
        return CVSS_PROVIDERS.index(provider)
    except ValueError:
        return len(CVSS_PROVIDERS)


def _provider_best(entries: Iterable[Any]) -> list[Any]:
    """Pick one score per provider, ignoring legacy v2 when a modern score exists."""
    grouped: dict[str, list[Any]] = {}
    for entry in entries:
        grouped.setdefault(entry.provider, []).append(entry)
    output: list[Any] = []
    for provider in sorted(grouped):
        candidates = grouped[provider]
        modern = [entry for entry in candidates if entry.version != "2.0"]
        pool = modern or candidates
        output.append(
            max(
                pool,
                key=lambda entry: (
                    entry.score,
                    entry.source,
                    entry.version,
                    entry.vector or "",
                ),
            )
        )
    return output


def highest_cvss(view: WatchView, providers: Sequence[str]) -> Any | None:
    selected = _provider_best(
        entry for entry in view.cvss if entry.provider in providers
    )
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


def _exploitation_level(view: WatchView) -> str:
    if view.ssvc_exploitation == "active" or view.euvd_exploited_since:
        return "active"
    if view.ssvc_exploitation == "poc":
        return "poc"
    return "none"


def _exploitation_sources(view: WatchView) -> tuple[str, ...]:
    sources: list[str] = []
    if view.ssvc_exploitation in {"poc", "active"}:
        sources.append("cisa-adp")
    if view.euvd_exploited_since:
        sources.append("euvd")
    return tuple(sources)


def snapshot_for(view: WatchView, rule: Rule) -> AlertSnapshot:
    highest = highest_cvss(view, rule.cvss_providers)
    severity_band = _severity_band(highest.score if highest is not None else None)
    epss_band = _epss_band(view.epss)
    return AlertSnapshot(
        cisa_kev=view.cisa_kev_added is not None,
        eu_kev=view.eu_kev_added is not None,
        exploitation=_exploitation_level(view),
        severity_band=severity_band,
        epss_band=epss_band,
        nvd_score=any(entry.provider == "nvd" for entry in view.cvss),
        status=view.status,
        max_severity_band=severity_band,
        max_epss_band=epss_band,
    )


def _date_prefix(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _is_backlog(view: WatchView, backlog_before: date | None) -> bool:
    if backlog_before is None:
        return False
    published = _date_prefix(view.published)
    if published is None or published >= backlog_before:
        return False
    for added in (view.cisa_kev_added, view.eu_kev_added):
        value = _date_prefix(added)
        if value is not None and value >= backlog_before:
            return False
    # EUVD exploitation evidence from inside the window is new, not backlog.
    exploited = _date_prefix(euvd_datetime(view.euvd_exploited_since))
    if exploited is not None and exploited >= backlog_before:
        return False
    return True


def condition_payload(condition: Condition) -> dict[str, Any]:
    if condition.kind == "leaf":
        return {"leaf": [[key, value] for key, value in condition.leaves]}
    if condition.kind == "not":
        return {"not": condition_payload(condition.children[0])}
    return {
        condition.kind: [condition_payload(child) for child in condition.children]
    }


def rule_hash(rule: Rule) -> str:
    """Hash the parts of a rule that define which CVEs and scores it sees."""
    value = {
        "condition": condition_payload(rule.condition),
        "cvss_providers": list(rule.cvss_providers),
    }
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:16]


def providers_hash(rule: Rule) -> str:
    """Hash the CVSS providers alone, since they decide the severity band."""
    value = list(rule.cvss_providers)
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:16]


def rebase_severity(previous: AlertState, view: WatchView, rule: Rule) -> AlertState:
    """Restart the severity marks from the band that the current providers give.

    Used when ``cvss_providers`` changed. The stored marks came from other scores,
    so keeping them would alert on the edit itself or hide a later real rise.
    """
    band = snapshot_for(view, rule).severity_band
    snapshot = replace(previous.snapshot, severity_band=band, max_severity_band=band)
    return AlertState(previous.first_matched_at, snapshot)


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
        return matched, (
            f"cvss {_format_number(highest.score)} v{highest.version} "
            f"({highest.provider})"
        )
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
        if value == "poc":
            current = view.ssvc_exploitation
            if current not in {"poc", "active"}:
                return False, None
            return True, f"exploitation {current} (cisa-adp)"
        current = _exploitation_level(view)
        if current != "active":
            return False, None
        sources = _exploitation_sources(view)
        suffix = f" ({', '.join(sources)})" if sources else ""
        return True, f"exploitation active{suffix}"
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
    view: WatchView,
    rule: Rule,
    kind: str,
    reasons: Sequence[str],
    occurrence: str,
    *,
    initial: bool = False,
) -> AlertEvent:
    return AlertEvent(
        rule.name, view.cve_id, kind, tuple(reasons), occurrence, initial
    )


def _raised_band(current: str, mark: str, labels: Sequence[str]) -> str:
    if labels.index(current) > labels.index(mark):
        return current
    return mark


def evaluate(
    view: WatchView,
    previous: AlertState | None,
    rule: Rule,
    now: datetime,
    *,
    backlog_before: date | None = None,
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
        if matched and view.status == "rejected" and "status rejected" not in reasons:
            matched, reasons = False, ()
        if not matched:
            return None, ()
        state = AlertState(timestamp, snapshot)
        backlog = _is_backlog(view, backlog_before)
        if backlog and rule.old_cves == "ignore":
            return state, ()
        if "match" not in rule.events:
            return state, ()
        return state, (
            _event(
                view,
                rule,
                "match",
                reasons,
                "match",
                initial=backlog and rule.old_cves == "digest",
            ),
        )

    events: list[AlertEvent] = []
    old = previous.snapshot
    if "kev_added" in rule.events:
        if not old.cisa_kev and snapshot.cisa_kev:
            added = _date_prefix(view.cisa_kev_added)
            events.append(
                _event(
                    view,
                    rule,
                    "kev_added",
                    ("kev cisa false -> true",),
                    f"cisa:{added.isoformat() if added else ''}",
                )
            )
        if not old.eu_kev and snapshot.eu_kev:
            added = _date_prefix(view.eu_kev_added)
            events.append(
                _event(
                    view,
                    rule,
                    "kev_added",
                    ("kev eu false -> true",),
                    f"eu:{added.isoformat() if added else ''}",
                )
            )
    if (
        "exploitation_active" in rule.events
        and old.exploitation != "active"
        and snapshot.exploitation == "active"
    ):
        sources = _exploitation_sources(view)
        suffix = f" ({', '.join(sources)})" if sources else ""
        events.append(
            _event(
                view,
                rule,
                "exploitation_active",
                (f"exploitation {old.exploitation} -> active{suffix}",),
                "active",
            )
        )
    max_severity = _raised_band(
        snapshot.severity_band, old.max_severity_band, SEVERITY_BANDS
    )
    if "severity_increase" in rule.events and max_severity != old.max_severity_band:
        events.append(
            _event(
                view,
                rule,
                "severity_increase",
                (
                    f"severity {old.severity_band} -> "
                    f"{snapshot.severity_band}",
                ),
                snapshot.severity_band,
            )
        )
    max_epss = old.max_epss_band
    if not (old.max_epss_band == "none" and snapshot.epss_band == "<0.1"):
        max_epss = _raised_band(
            snapshot.epss_band, old.max_epss_band, EPSS_BAND_LABELS
        )
    if "epss_increase" in rule.events and max_epss != old.max_epss_band:
        events.append(
            _event(
                view,
                rule,
                "epss_increase",
                (f"epss {old.epss_band} -> {snapshot.epss_band}",),
                snapshot.epss_band,
            )
        )
    if "nvd_score_added" in rule.events and not old.nvd_score and snapshot.nvd_score:
        events.append(
            _event(
                view,
                rule,
                "nvd_score_added",
                ("nvd score absent -> present",),
                "nvd",
            )
        )
    if (
        "rejected" in rule.events
        and old.status != "rejected"
        and snapshot.status == "rejected"
    ):
        rejected_on = _date_prefix(view.last_modified)
        events.append(
            _event(
                view,
                rule,
                "rejected",
                (f"status {old.status} -> rejected",),
                f"rejected:{rejected_on.isoformat() if rejected_on else ''}",
            )
        )
    snapshot = replace(
        snapshot,
        max_severity_band=max_severity,
        max_epss_band=max_epss,
    )
    return AlertState(previous.first_matched_at, snapshot), tuple(events)


def _format_number(value: float) -> str:
    return str(float(value))


def _describe_leaf(key: str, value: Any) -> str:
    if key == "cvss_min":
        return f"cvss >= {_format_number(value)}"
    if key == "cvss_max":
        return f"cvss <= {_format_number(value)}"
    if key == "epss_min":
        return f"epss >= {_format_number(value)}"
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


def _describe_any_child(condition: Condition) -> str:
    text = describe_condition(condition)
    if condition.kind == "leaf" and len(condition.leaves) > 1:
        return f"({text})"
    return text


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
            _describe_any_child(child) for child in condition.children
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
