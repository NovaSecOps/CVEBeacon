"""Short, provider-neutral formatting for watch alert messages."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote

from .records import CVSSEntry, DeliveryEvent, WatchView
from .rules import EVENT_KINDS, Rule

NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
CVE_URL = "https://www.cve.org/CVERecord?id={cve_id}"
EUVD_URL = "https://euvd.enisa.europa.eu/vulnerability/{euvd_id}"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
STYLE_PLAIN = "plain"
STYLE_SLACK = "slack"
STYLE_MARKDOWN = "markdown"
STYLE_DISCORD = "discord"
MAX_PARTS = 10
DESCRIPTION_LIMIT = 160
KEV_ACTION_LIMIT = 120
PROVIDER_ORDER = ("cna", "nvd", "cisa-adp", "euvd", "other")
CHANNEL_LIMITS = {
    "smtp": 1_000_000,
    "graph": 1_000_000,
    "teams": 24_000,
    "slack": 3_800,
    "discord": 2_000,
    "telegram": 4_096,
    "matrix": 30_000,
    "ntfy": 4_096,
    "gotify": 32_768,
    "webhook": 32_768,
}
KIND_NAMES = {
    "match": "match",
    "kev_added": "KEV added",
    "exploitation_active": "actively exploited",
    "severity_increase": "severity up",
    "epss_increase": "EPSS up",
    "nvd_score_added": "NVD scored",
    "rejected": "rejected",
}
_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class OutgoingMessage:
    event_ids: tuple[int, ...]
    subject: str
    text: str
    body: str
    initial: bool = False


def style_for(channel_type: str) -> str:
    if channel_type == "slack":
        return STYLE_SLACK
    if channel_type == "discord":
        return STYLE_DISCORD
    if channel_type in {"teams", "matrix"}:
        return STYLE_MARKDOWN
    return STYLE_PLAIN


def _clean(value: Any, limit: int | None = None) -> str:
    text = _WHITESPACE.sub(" ", str(value or "")).strip()
    if limit is not None and len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text


def _escape_slack(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_discord(value: str) -> str:
    value = re.sub(r"([\\*_`~|>\[\]])", r"\\\1", value)
    return value.replace("@", "\\@")


def _dynamic(value: Any, style: str, limit: int | None = None) -> str:
    text = _clean(value, limit)
    if style == STYLE_SLACK:
        return _escape_slack(text)
    if style == STYLE_DISCORD:
        return _escape_discord(text)
    return text


def _link(url: str, label: str, style: str) -> str:
    if style == STYLE_SLACK:
        return f"<{url}|{label}>"
    if style in {STYLE_MARKDOWN, STYLE_DISCORD}:
        return f"[{label}]({url})"
    return url


def _title(value: str, style: str) -> str:
    if style == STYLE_SLACK:
        return f"*{value}*"
    if style in {STYLE_MARKDOWN, STYLE_DISCORD}:
        return f"**{value}**"
    return value


def _best_by_provider(entries: Iterable[CVSSEntry]) -> dict[str, CVSSEntry]:
    grouped: dict[str, list[CVSSEntry]] = {}
    for entry in entries:
        grouped.setdefault(entry.provider, []).append(entry)
    output: dict[str, CVSSEntry] = {}
    for provider, candidates in grouped.items():
        modern = [entry for entry in candidates if entry.version != "2.0"]
        output[provider] = max(
            modern or candidates,
            key=lambda entry: (
                entry.score,
                entry.source,
                entry.version,
                entry.vector or "",
            ),
        )
    return output


def _cna_name(entry: CVSSEntry, view: WatchView) -> str:
    source = _clean(entry.source or view.source_identifier)
    if "@" in source:
        source = source.rsplit("@", 1)[-1]
    if source:
        return source[:60]
    return "CNA"


def _provider_label(provider: str, entry: CVSSEntry, view: WatchView) -> str:
    if provider == "cna":
        return f"CNA: {_cna_name(entry, view)}"
    if provider == "nvd":
        return "NVD"
    if provider == "cisa-adp":
        return "CISA-ADP"
    if provider == "euvd":
        return "EUVD"
    return "Other"


def _cvss_field(view: WatchView, style: str = STYLE_PLAIN) -> str:
    best = _best_by_provider(view.cvss)
    parts: list[str] = []
    for provider in PROVIDER_ORDER:
        entry = best.get(provider)
        if entry is None:
            continue
        label = _dynamic(_provider_label(provider, entry, view), style, 80)
        parts.append(f"CVSS {entry.score:g} ({label})")
    if not parts:
        return "CVSS not scored"
    if "nvd" not in best:
        parts.append("NVD pending")
    return ", ".join(parts)


def _epss_field(view: WatchView) -> str:
    if view.epss is None:
        return "–"
    return f"{view.epss:.2f}"


def _kev_field(view: WatchView) -> str:
    cisa = "✓" if view.cisa_kev_added is not None else "–"
    eu = "✓" if view.eu_kev_added is not None else "–"
    return f"CISA {cisa} EU {eu}"


def _exploitation_field(view: WatchView) -> str:
    if view.ssvc_exploitation == "active" or view.euvd_exploited_since:
        return "active"
    if view.ssvc_exploitation == "poc":
        return "poc"
    return "none"


def _reason_transition(reasons: Sequence[str], prefix: str) -> tuple[str, str] | None:
    for reason in reasons:
        if reason.startswith(prefix) and " -> " in reason:
            old, _, new = reason[len(prefix) :].partition(" -> ")
            if old.strip() and new.strip():
                return old.strip(), new.strip()
    return None


def _kind_label(event: DeliveryEvent, style: str) -> str:
    kind = event.kind
    if kind == "match":
        return "[NEW]"
    if kind == "kev_added":
        catalog = "CISA"
        for reason in event.reasons:
            if "kev eu" in reason:
                catalog = "EU"
            elif "kev cisa" in reason:
                catalog = "CISA"
        return f"[KEV ADDED: {catalog}]"
    if kind == "exploitation_active":
        return "[ACTIVELY EXPLOITED]"
    if kind == "severity_increase":
        transition = _reason_transition(event.reasons, "severity")
        if transition is not None:
            return f"[SEVERITY UP {transition[0]}→{transition[1]}]"
        return "[SEVERITY UP]"
    if kind == "epss_increase":
        previous = event.details.get("previous_epss")
        if isinstance(previous, (int, float)) and event.view.epss is not None:
            return f"[EPSS UP {float(previous):.2f}→{event.view.epss:.2f}]"
        transition = _reason_transition(event.reasons, "epss")
        if transition is not None:
            return f"[EPSS UP {transition[0]}→{transition[1]}]"
        return "[EPSS UP]"
    if kind == "nvd_score_added":
        nvd = _best_by_provider(event.view.cvss).get("nvd")
        if nvd is not None:
            return f"[NVD SCORED {nvd.score:g}]"
        return "[NVD SCORED]"
    if kind == "rejected":
        return "[REJECTED]"
    return f"[{kind.upper()}]"


def _links(event: DeliveryEvent, style: str) -> str:
    view = event.view
    cve_id = quote(str(event.cve_id), safe="-_.")
    values = [
        _link(NVD_URL.format(cve_id=cve_id), "NVD", style),
        _link(CVE_URL.format(cve_id=cve_id), "CVE.org", style),
    ]
    if view.euvd_id:
        euvd_id = quote(str(view.euvd_id), safe="-_.")
        values.append(_link(EUVD_URL.format(euvd_id=euvd_id), "EUVD", style))
    if view.cisa_kev_added is not None or view.eu_kev_added is not None:
        values.append(_link(KEV_URL, "KEV catalog", style))
    return " · ".join(values)


def _event_lines(event: DeliveryEvent, style: str, rule_name: str) -> list[str]:
    label = _kind_label(event, style)
    line = (
        f"{label} {event.cve_id} · {_cvss_field(event.view, style)} · "
        f"EPSS {_epss_field(event.view)} · KEV: {_kev_field(event.view)} · "
        f"Exploitation: {_exploitation_field(event.view)}"
    )
    lines = [line]
    description = _dynamic(event.view.description, style, DESCRIPTION_LIMIT)
    if description:
        lines.append(f"  {description}")
    if event.kind == "kev_added" and event.view.cisa_kev_added is not None:
        extras: list[str] = []
        if event.view.cisa_kev_due:
            extras.append(f"Due {_clean(event.view.cisa_kev_due, 40)}")
        if event.view.cisa_required_action:
            extras.append(
                _dynamic(event.view.cisa_required_action, style, KEV_ACTION_LIMIT)
            )
        if extras:
            lines.append("  " + " · ".join(extras))
    rule = _dynamic(rule_name, style, 80)
    lines.append(f"  Rule: {rule} · {_links(event, style)}")
    return lines


def sort_events(events: Iterable[DeliveryEvent]) -> tuple[DeliveryEvent, ...]:
    def key(event: DeliveryEvent) -> tuple[Any, ...]:
        view = event.view
        urgent = (
            view.cisa_kev_added is not None
            or view.eu_kev_added is not None
            or view.ssvc_exploitation == "active"
            or view.euvd_exploited_since is not None
        )
        best = _best_by_provider(view.cvss)
        score = max((entry.score for entry in best.values()), default=-1.0)
        epss = view.epss if view.epss is not None else -1.0
        return (
            0 if urgent else 1,
            -score,
            -epss,
            event.cve_id,
            event.kind,
            event.event_id,
        )

    return tuple(sorted(events, key=key))


def _counts_phrase(events: Sequence[DeliveryEvent]) -> str:
    counts = Counter(event.kind for event in events)
    parts: list[str] = []
    for kind in EVENT_KINDS:
        count = counts.get(kind, 0)
        if not count:
            continue
        name = KIND_NAMES[kind]
        if kind == "match":
            parts.append(f"{count} new")
        else:
            parts.append(f"{count} {name}")
    return ", ".join(parts) or f"{len(events)} event(s)"


def _rule_label(events: Sequence[DeliveryEvent], names: Mapping[str, str]) -> str:
    rules = {event.rule for event in events}
    if len(rules) == 1:
        folded = next(iter(rules))
        return names.get(folded, folded)
    return f"{len(rules)} rules"


def _display_name(event: DeliveryEvent, names: Mapping[str, str]) -> str:
    return names.get(event.rule, event.rule)


def _run_subject(events: Sequence[DeliveryEvent], names: Mapping[str, str]) -> str:
    return f"CVEBeacon: {_counts_phrase(events)} ({_rule_label(events, names)})"


def _event_subject(event: DeliveryEvent, names: Mapping[str, str]) -> str:
    label = _kind_label(event, STYLE_PLAIN).strip("[]")
    return f"CVEBeacon: [{label}] {event.cve_id}"


def split_message(text: str, limit: int) -> tuple[str, ...]:
    """Split at line boundaries, numbering parts when there is more than one."""
    if limit < 16:
        raise ValueError("message limit is too small")
    if len(text) <= limit:
        return (text,)
    # Reserve the widest part label, ``[10/10] ``, so every numbered part
    # still fits the provider limit.
    usable = limit - 8
    lines = text.splitlines() or [""]
    chunks: list[str] = []
    current: list[str] = []
    used = 0
    for line in lines:
        # A single line must fit; cut it only if the formatter ever makes one
        # longer than the provider limit.
        while len(line) > usable:
            if current:
                chunks.append("\n".join(current))
                current, used = [], 0
            chunks.append(line[: usable - 1] + "…")
            line = line[usable - 1 :]
        extra = len(line) + (1 if current else 0)
        if current and used + extra > usable:
            chunks.append("\n".join(current))
            current, used = [], 0
        current.append(line)
        used += len(line) + (1 if len(current) > 1 else 0)
    if current:
        chunks.append("\n".join(current))
    if len(chunks) == 1:
        return (chunks[0],)
    return tuple(
        f"[{index + 1}/{len(chunks)}] {chunk}" for index, chunk in enumerate(chunks)
    )


def _compose(
    subject: str,
    body: str,
    *,
    style: str,
    chat: bool,
) -> tuple[str, str]:
    if not chat:
        return subject, body
    return f"{_title(subject, style)}\n\n{body}".strip(), body


def _event_body(
    events: Sequence[DeliveryEvent],
    *,
    style: str,
    names: Mapping[str, str],
    limit: int,
    max_items: int | None = None,
) -> str:
    listed = list(events)
    while True:
        shown = listed if max_items is None else listed[:max_items]
        lines: list[str] = []
        for event in shown:
            lines.extend(_event_lines(event, style, _display_name(event, names)))
        omitted = len(listed) - len(shown)
        if omitted:
            lines.append(f"and {omitted} more")
        body = "\n".join(lines)
        if len(split_message(body, limit)) <= MAX_PARTS:
            return body
        if not shown:
            return body
        if max_items is None:
            max_items = len(shown) - 1
        else:
            max_items = max(0, min(max_items, len(shown)) - 1)


def _initial_body(
    events: Sequence[DeliveryEvent],
    *,
    style: str,
    names: Mapping[str, str],
    limit: int,
    max_items: int,
    since: str | None,
) -> str:
    ordered = sort_events(events)
    while True:
        shown = ordered[:max_items]
        counts: dict[str, Counter[str]] = {}
        for event in ordered:
            counts.setdefault(event.rule, Counter())[event.kind] += 1
        lines: list[str] = []
        for rule in sorted(counts):
            parts = [
                f"{count} {KIND_NAMES[kind]}"
                for kind in EVENT_KINDS
                if (count := counts[rule].get(kind, 0))
            ]
            lines.append(f"{_display_name_for(rule, names)}: " + ", ".join(parts))
        lines.append("")
        for event in shown:
            lines.extend(_event_lines(event, style, _display_name(event, names)))
        if len(ordered) > len(shown):
            lines.append(f"and {len(ordered) - len(shown)} more")
        rule_names = sorted({_display_name(event, names) for event in ordered})
        example = rule_names[0] if len(rule_names) == 1 else "X"
        lines.append("")
        lines.append(
            f"Run `cvebeacon watch events --rule {_dynamic(example, style, 80)}` "
            "to list all."
        )
        body = "\n".join(lines)
        if len(split_message(body, limit)) <= MAX_PARTS or not shown:
            return body
        max_items = max(0, len(shown) - 1)


def _display_name_for(folded: str, names: Mapping[str, str]) -> str:
    return names.get(folded, folded)


def _initial_subject(
    events: Sequence[DeliveryEvent], names: Mapping[str, str], since: str | None
) -> str:
    matches = sum(event.kind == "match" for event in events)
    rules = len({event.rule for event in events})
    suffix = f" since {since}" if since else ""
    return (
        f"CVEBeacon initial summary: {matches} matches across {rules} "
        f"rules{suffix}"
    )


def build_messages(
    events: Sequence[DeliveryEvent],
    *,
    channel_type: str,
    grouping: str,
    max_items: int,
    names: Mapping[str, str],
    since: str | None = None,
) -> tuple[OutgoingMessage, ...]:
    """Build the messages one channel should send for the selected events."""
    style = style_for(channel_type)
    limit = CHANNEL_LIMITS.get(channel_type, 32_768)
    chat = channel_type not in {"smtp", "graph", "webhook"}
    body_limit = limit - 300 if chat else limit
    ordered = sort_events(events)
    initial = tuple(event for event in ordered if event.initial)
    normal = tuple(event for event in ordered if not event.initial)
    output: list[OutgoingMessage] = []
    if initial:
        subject = _initial_subject(initial, names, since)
        body = _initial_body(
            initial,
            style=style,
            names=names,
            limit=body_limit,
            max_items=max_items,
            since=since,
        )
        text, body = _compose(subject, body, style=style, chat=chat)
        parts = split_message(text, limit) if chat else (text,)
        for part in parts[:MAX_PARTS]:
            output.append(
                OutgoingMessage(
                    tuple(event.event_id for event in initial),
                    subject,
                    part,
                    body,
                    initial=True,
                )
            )
    if grouping == "event":
        groups = [(event,) for event in normal]
    else:
        groups = [normal] if normal else []
    for group in groups:
        if not group:
            continue
        subject = (
            _event_subject(group[0], names)
            if grouping == "event"
            else _run_subject(group, names)
        )
        body = _event_body(
            group,
            style=style,
            names=names,
            limit=body_limit,
            max_items=None if grouping == "event" else max_items,
        )
        text, body = _compose(subject, body, style=style, chat=chat)
        parts = split_message(text, limit) if chat else (text,)
        for part in parts[:MAX_PARTS]:
            output.append(
                OutgoingMessage(
                    tuple(event.event_id for event in group),
                    subject,
                    part,
                    body,
                )
            )
    return tuple(output)


def webhook_payload(
    events: Sequence[DeliveryEvent], names: Mapping[str, str]
) -> dict[str, Any]:
    """Return the stable version 1 webhook document."""
    output = []
    for event in sort_events(events):
        view = event.view
        output.append(
            {
                "rule": _display_name(event, names),
                "cve_id": event.cve_id,
                "kind": event.kind,
                "reasons": list(event.reasons),
                "initial": bool(event.initial),
                "created_at": event.created_at,
                "view": {
                    "cvss": [
                        {
                            "provider": entry.provider,
                            "source": entry.source,
                            "version": entry.version,
                            "score": entry.score,
                            "vector": entry.vector,
                        }
                        for entry in view.cvss
                    ],
                    "kev": {
                        "cisa": (
                            {
                                "added": view.cisa_kev_added,
                                "due": view.cisa_kev_due,
                                "required_action": view.cisa_required_action,
                            }
                            if view.cisa_kev_added is not None
                            else None
                        ),
                        "eu": (
                            {"added": view.eu_kev_added}
                            if view.eu_kev_added is not None
                            else None
                        ),
                    },
                    "epss": (
                        {
                            "score": view.epss,
                            "percentile": view.epss_percentile,
                            "date": view.epss_date,
                        }
                        if view.epss is not None
                        else None
                    ),
                    "vendors": list(view.vendors),
                    "products": list(view.products),
                    "links": {
                        "nvd": NVD_URL.format(
                            cve_id=quote(str(event.cve_id), safe="-_.")
                        ),
                        "cve": CVE_URL.format(
                            cve_id=quote(str(event.cve_id), safe="-_.")
                        ),
                        "euvd": (
                            EUVD_URL.format(
                                euvd_id=quote(str(view.euvd_id), safe="-_.")
                            )
                            if view.euvd_id
                            else None
                        ),
                    },
                },
            }
        )
    return {"version": 1, "events": output}


def rule_display_names(rules: Iterable[Rule]) -> dict[str, str]:
    return {rule.name.casefold(): rule.name for rule in rules}
