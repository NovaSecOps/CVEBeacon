"""Short, provider-neutral formatting for watch alert messages."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote

from .records import CVSSEntry, DeliveryEvent, InitialDigest, WatchView
from .reported import NOTICE_KINDS, NOTICE_LABELS, format_reported
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
WEBHOOK_VERSION = 2
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
    content: str = ""
    part_index: int = 0
    part_count: int = 1


def style_for(channel_type: str) -> str:
    if channel_type == "slack":
        return STYLE_SLACK
    if channel_type == "discord":
        return STYLE_DISCORD
    if channel_type == "teams":
        return STYLE_MARKDOWN
    return STYLE_PLAIN


def _clean(value: Any, limit: int | None = None) -> str:
    text = _WHITESPACE.sub(" ", str(value or "")).strip()
    if limit is not None and len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text


def _date_text(value: Any) -> str:
    """Return a UTC date as ``YYYY-MM-DD``, or ``unknown`` when it is absent."""
    text = _clean(value)
    if not text:
        return "unknown"
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.date().isoformat()
    except ValueError:
        pass
    try:
        return datetime.strptime(text[:10], "%Y-%m-%d").date().isoformat()
    except ValueError:
        return "unknown"


def date_phrase(published: Any, first_seen: Any) -> str:
    """Return the short publication and first-seen phrase for one CVE."""
    return (
        f"Published {_date_text(published)} · "
        f"first seen {_date_text(first_seen)}"
    )


def _escape_slack(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_markdown(value: str) -> str:
    return re.sub(r"([\\*_`~|>\[\]])", r"\\\1", value)


def _escape_discord(value: str) -> str:
    return _escape_markdown(value).replace("@", "\\@")


def _dynamic(value: Any, style: str, limit: int | None = None) -> str:
    text = _clean(value, limit)
    if style == STYLE_SLACK:
        return _escape_slack(text)
    if style == STYLE_DISCORD:
        return _escape_discord(text)
    if style == STYLE_MARKDOWN:
        return _escape_markdown(text)
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
    if "nvd" not in best and view.status != "rejected":
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
            return f"[SEVERITY UP {transition[0]}->{transition[1]}]"
        return "[SEVERITY UP]"
    if kind == "epss_increase":
        previous = event.details.get("previous_epss")
        current = event.details.get("epss")
        if not isinstance(current, (int, float)):
            current = event.view.epss
        if isinstance(previous, (int, float)) and isinstance(current, (int, float)):
            return f"[EPSS UP {float(previous):.2f}->{float(current):.2f}]"
        transition = _reason_transition(event.reasons, "epss")
        if transition is not None:
            return f"[EPSS UP {transition[0]}->{transition[1]}]"
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


def _group_events(
    events: Iterable[DeliveryEvent], style: str
) -> list[list[DeliveryEvent]]:
    """Merge events that render the same CVE line under the same label."""
    grouped: dict[tuple[str, str], list[DeliveryEvent]] = {}
    for event in events:
        key = (event.cve_id, _kind_label(event, style))
        grouped.setdefault(key, []).append(event)
    return list(grouped.values())


def _event_lines(
    group: Sequence[DeliveryEvent], style: str, names: Mapping[str, str]
) -> list[str]:
    event = group[0]
    label = _kind_label(event, style)
    line = (
        f"{label} {event.cve_id} · {_cvss_field(event.view, style)} · "
        f"EPSS {_epss_field(event.view)} · KEV: {_kev_field(event.view)} · "
        f"Exploitation: {_exploitation_field(event.view)}"
    )
    lines = [
        line,
        f"  {date_phrase(event.view.published, event.view.first_seen)}",
    ]
    description = _dynamic(event.view.description, style, DESCRIPTION_LIMIT)
    if description:
        lines.append(f"  {description}")
    if event.kind == "kev_added" and event.view.cisa_kev_added is not None:
        extras: list[str] = []
        if event.view.cisa_kev_due:
            extras.append(f"Due {_dynamic(event.view.cisa_kev_due, style, 40)}")
        if event.view.cisa_required_action:
            extras.append(
                _dynamic(event.view.cisa_required_action, style, KEV_ACTION_LIMIT)
            )
        if extras:
            lines.append("  " + " · ".join(extras))
    if event.reported is not None:
        lines.append("  " + _dynamic(format_reported(event.reported), style))
    rule_names = sorted({_display_name(item, names) for item in group})
    rules = ", ".join(_dynamic(name, style, 80) for name in rule_names)
    lines.append(f"  Rule: {rules} · {_links(event, style)}")
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


def _counts_phrase(groups: Sequence[Sequence[DeliveryEvent]]) -> str:
    counts = Counter(group[0].kind for group in groups)
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
    return ", ".join(parts) or f"{len(groups)} event(s)"


def _rule_label(events: Sequence[DeliveryEvent], names: Mapping[str, str]) -> str:
    rules = {event.rule for event in events}
    if len(rules) == 1:
        folded = next(iter(rules))
        return names.get(folded, folded)
    return f"{len(rules)} rules"


def _display_name(event: DeliveryEvent, names: Mapping[str, str]) -> str:
    return names.get(event.rule, event.rule)


def _run_subject(events: Sequence[DeliveryEvent], names: Mapping[str, str]) -> str:
    groups = _group_events(sort_events(events), STYLE_PLAIN)
    return f"CVEBeacon: {_counts_phrase(groups)} ({_rule_label(events, names)})"


def _event_subject(event: DeliveryEvent, names: Mapping[str, str]) -> str:
    label = _kind_label(event, STYLE_PLAIN).strip("[]")
    return f"CVEBeacon: [{label}] {event.cve_id}"


def _size(value: str, byte_limit: bool) -> int:
    return len(value.encode("utf-8")) if byte_limit else len(value)


def _head(value: str, size_limit: int, byte_limit: bool) -> str:
    if not byte_limit:
        return value[:size_limit]
    used = 0
    output: list[str] = []
    for character in value:
        width = len(character.encode("utf-8"))
        if used + width > size_limit:
            break
        output.append(character)
        used += width
    return "".join(output)


def split_message(
    text: str, limit: int, *, byte_limit: bool = False
) -> tuple[str, ...]:
    """Split at line boundaries, numbering parts when there is more than one."""
    if limit < 16:
        raise ValueError("message limit is too small")
    if _size(text, byte_limit) <= limit:
        return (text,)
    # Reserve the widest part label, ``[10/10] ``, so every numbered part
    # still fits the provider limit.
    usable = limit - 8
    ellipsis = _size("…", byte_limit)
    lines = text.splitlines() or [""]
    chunks: list[str] = []
    current: list[str] = []
    used = 0
    for line in lines:
        # A single line must fit; cut it only if the formatter ever makes one
        # longer than the provider limit.
        while _size(line, byte_limit) > usable:
            if current:
                chunks.append("\n".join(current))
                current, used = [], 0
            head = _head(line, usable - ellipsis, byte_limit)
            if not head:
                head = line[:1]
            chunks.append(head + "…")
            line = line[len(head) :]
        extra = _size(line, byte_limit) + (1 if current else 0)
        if current and used + extra > usable:
            chunks.append("\n".join(current))
            current, used = [], 0
        current.append(line)
        used += _size(line, byte_limit) + (1 if len(current) > 1 else 0)
    if current:
        chunks.append("\n".join(current))
    if len(chunks) == 1:
        return (chunks[0],)
    return tuple(
        f"[{index + 1}/{len(chunks)}] {chunk}" for index, chunk in enumerate(chunks)
    )


def _partials(
    subject: str,
    body: str,
    *,
    style: str,
    chat: bool,
    limit: int,
    byte_limit: bool,
    title_in_body: bool,
) -> tuple[str, ...]:
    if not chat:
        return (subject,)
    text = f"{_title(subject, style)}\n\n{body}".strip() if title_in_body else body
    return split_message(text, limit, byte_limit=byte_limit)


def _event_body(
    events: Sequence[DeliveryEvent],
    *,
    style: str,
    names: Mapping[str, str],
    limit: int,
    max_items: int | None = None,
    byte_limit: bool = False,
) -> str:
    listed = _group_events(sort_events(events), style)
    while True:
        shown = listed if max_items is None else listed[:max_items]
        lines: list[str] = []
        for group in shown:
            lines.extend(_event_lines(group, style, names))
        omitted = len(listed) - len(shown)
        if omitted:
            lines.append(
                f"and {omitted} more. "
                "Run `cvebeacon watch events` to list all."
            )
        body = "\n".join(lines)
        if len(split_message(body, limit, byte_limit=byte_limit)) <= MAX_PARTS:
            return body
        if not shown:
            return body
        if max_items is None:
            max_items = len(shown) - 1
        else:
            max_items = max(0, min(max_items, len(shown)) - 1)


def _kind_count_name(kind: str, count: int) -> str:
    if kind == "match":
        return "match" if count == 1 else "matches"
    return KIND_NAMES[kind]


def _initial_body(
    events: Sequence[DeliveryEvent],
    *,
    style: str,
    names: Mapping[str, str],
    limit: int,
    max_items: int,
    since: str | None,
    byte_limit: bool = False,
    counts: Sequence[tuple[str, str, int]] | None = None,
    total_cves: int | None = None,
) -> str:
    ordered = sort_events(events)
    groups = _group_events(ordered, style)
    totals: dict[str, Counter[str]] = {}
    if counts is None:
        for event in ordered:
            totals.setdefault(event.rule, Counter())[event.kind] += 1
    else:
        for rule, kind, count in counts:
            totals.setdefault(rule, Counter())[kind] += count
    cves = total_cves if total_cves is not None else len({event.cve_id for event in ordered})
    while True:
        shown = groups[:max_items]
        lines: list[str] = []
        for rule in sorted(totals):
            parts = [
                f"{count} {_kind_count_name(kind, count)}"
                for kind in EVENT_KINDS
                if (count := totals[rule].get(kind, 0))
            ]
            lines.append(f"{_display_name_for(rule, names)}: " + ", ".join(parts))
        lines.append("")
        for group in shown:
            lines.extend(_event_lines(group, style, names))
        shown_cves = len({event.cve_id for group in shown for event in group})
        omitted = max(0, cves - shown_cves)
        if omitted:
            lines.append(
                f"and {omitted} more. "
                "Run `cvebeacon watch events` to list all."
            )
        else:
            rule_names = sorted(
                {_display_name_for(rule, names) for rule in totals}
            )
            lines.append("")
            if rule_names:
                example = rule_names[0]
                if any(character.isspace() for character in example):
                    example = f'"{example}"'
                lines.append(
                    "Run `cvebeacon watch events --rule "
                    f"{_dynamic(example, style, 80)}` to list all."
                )
            else:
                lines.append("Run `cvebeacon watch events` to list all.")
        body = "\n".join(lines)
        if (
            len(split_message(body, limit, byte_limit=byte_limit)) <= MAX_PARTS
            or not shown
        ):
            return body
        max_items = max(0, len(shown) - 1)


def _display_name_for(folded: str, names: Mapping[str, str]) -> str:
    return names.get(folded, folded)


def _initial_subject(cves: int, rules: int, since: str | None) -> str:
    suffix = f" since {since}" if since else ""
    cve_word = "CVE" if cves == 1 else "CVEs"
    rule_word = "rule" if rules == 1 else "rules"
    return (
        f"CVEBeacon initial summary: {cves} {cve_word} across {rules} "
        f"{rule_word}{suffix}"
    )


def _notice_subject(event: DeliveryEvent) -> str:
    label = NOTICE_LABELS.get(event.kind, f"[{event.kind.upper()}]")
    return f"CVEBeacon: {label} {event.cve_id}"


def _notice_text(event: DeliveryEvent, style: str) -> str:
    label = NOTICE_LABELS.get(event.kind, f"[{event.kind.upper()}]")
    by = event.details.get("by")
    by_text = _dynamic(by if isinstance(by, str) else "unknown", style, 100)
    if event.kind == "unreported":
        line = f"{label} {event.cve_id} report withdrawn by {by_text}"
    else:
        line = f"{label} {event.cve_id} reported to clients by {by_text}"
    note = event.details.get("note")
    if isinstance(note, str) and note.strip():
        line += "\n  " + _dynamic(note, style, 500)
    return line


def build_messages(
    events: Sequence[DeliveryEvent],
    *,
    channel_type: str,
    grouping: str,
    max_items: int,
    names: Mapping[str, str],
    since: str | None = None,
    initial: InitialDigest | None = None,
) -> tuple[OutgoingMessage, ...]:
    """Build the messages one channel should send for the selected events."""
    style = style_for(channel_type)
    limit = CHANNEL_LIMITS.get(channel_type, 32_768)
    byte_limit = channel_type in {"ntfy", "matrix", "teams"}
    chat = channel_type not in {"smtp", "graph", "webhook"}
    title_in_body = chat and channel_type not in {"ntfy", "gotify"}
    body_limit = limit - 300 if chat else limit
    ordered = sort_events(events)
    notices = tuple(event for event in ordered if event.kind in NOTICE_KINDS)
    normal = tuple(
        event
        for event in ordered
        if not event.initial and event.kind not in NOTICE_KINDS
    )
    if initial is None:
        selected = tuple(event for event in ordered if event.initial)
        if selected:
            counter: dict[str, Counter[str]] = {}
            for event in selected:
                counter.setdefault(event.rule, Counter())[event.kind] += 1
            initial = InitialDigest(
                selected,
                tuple(
                    sorted(
                        (rule, kind, count)
                        for rule, counts in counter.items()
                        for kind, count in counts.items()
                    )
                ),
                len({event.cve_id for event in selected}),
                len(selected),
            )
    output: list[OutgoingMessage] = []
    if initial is not None and initial.total:
        rules = len({rule for rule, _, _ in initial.counts})
        subject = _initial_subject(initial.cves, rules, since)
        body = _initial_body(
            initial.events,
            style=style,
            names=names,
            limit=body_limit,
            max_items=max_items,
            since=since,
            byte_limit=byte_limit,
            counts=initial.counts,
            total_cves=initial.cves,
        )
        parts = _partials(
            subject,
            body,
            style=style,
            chat=chat,
            limit=limit,
            byte_limit=byte_limit,
            title_in_body=title_in_body,
        )
        for index, part in enumerate(parts[:MAX_PARTS]):
            output.append(
                OutgoingMessage(
                    tuple(event.event_id for event in initial.events),
                    subject,
                    part,
                    body,
                    initial=True,
                    content=part,
                    part_index=index,
                    part_count=len(parts),
                )
            )
    for notice in notices:
        subject = _notice_subject(notice)
        body = _notice_text(notice, style)
        parts = _partials(
            subject,
            body,
            style=style,
            chat=chat,
            limit=limit,
            byte_limit=byte_limit,
            title_in_body=title_in_body,
        )
        for index, part in enumerate(parts[:MAX_PARTS]):
            output.append(
                OutgoingMessage(
                    (notice.event_id,),
                    subject,
                    part,
                    body,
                    content=part,
                    part_index=index,
                    part_count=len(parts),
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
            byte_limit=byte_limit,
        )
        parts = _partials(
            subject,
            body,
            style=style,
            chat=chat,
            limit=limit,
            byte_limit=byte_limit,
            title_in_body=title_in_body,
        )
        for index, part in enumerate(parts[:MAX_PARTS]):
            output.append(
                OutgoingMessage(
                    tuple(event.event_id for event in group),
                    subject,
                    part,
                    body,
                    content=part,
                    part_index=index,
                    part_count=len(parts),
                )
            )
    return tuple(output)


def webhook_payload(
    events: Sequence[DeliveryEvent], names: Mapping[str, str]
) -> dict[str, Any]:
    """Return the stable version 2 webhook document."""
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
                    "published": view.published,
                    "first_seen": view.first_seen,
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
                    "reported": (
                        {
                            "by": event.reported.by,
                            "at": event.reported.at,
                            "note": event.reported.note,
                        }
                        if event.reported is not None
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
                        "kev": KEV_URL,
                    },
                },
            }
        )
        if event.kind in NOTICE_KINDS:
            output[-1]["notice"] = {
                "action": "report" if event.kind == "reported" else "unreport",
                "by": str(event.details.get("by") or "unknown"),
                "note": event.details.get("note"),
            }
    return {"version": WEBHOOK_VERSION, "events": output}


def rule_display_names(rules: Iterable[Rule]) -> dict[str, str]:
    return {rule.name.casefold(): rule.name for rule in rules}
