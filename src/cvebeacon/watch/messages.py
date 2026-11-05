"""Short, provider-neutral formatting for watch alert messages."""

from __future__ import annotations

import html as html_module
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote

from .catalog import DEFAULT_LANGUAGE, catalog_for, translate
from .records import CVSSEntry, DeliveryEvent, InitialDigest, WatchView
from ..clients import (
    ClientImpact,
    ClientImpacts,
    format_affected_clients,
    impacts_for,
)
from .reported import (
    NOTICE_KINDS,
    NOTICE_LABEL_KEYS,
    format_reported,
    format_timestamp,
    identity_label,
)
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
MAX_WEBHOOK_CLIENTS = 50
WEBHOOK_CLIENT_BUDGET = 8_000
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
EMAIL_CHANNELS = ("smtp", "graph")
MESSAGE_TOO_LARGE = "message exceeds the channel size limit"
_WHITESPACE = re.compile(r"\s+")


class MessageTooLarge(Exception):
    """The fixed part of a message cannot fit the channel size limit."""


@dataclass(frozen=True, slots=True)
class OutgoingMessage:
    event_ids: tuple[int, ...]
    subject: str
    text: str
    body: str
    html: str = ""
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


def _date_text(value: Any, catalog: Mapping[str, str]) -> str:
    """Return a UTC date as ``YYYY-MM-DD``, or the unknown label when absent."""
    text = _clean(value)
    if not text:
        return catalog["unknown_date"]
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
        return catalog["unknown_date"]


def date_phrase(
    published: Any, first_seen: Any, language: str = DEFAULT_LANGUAGE
) -> str:
    """Return the short publication and first-seen phrase for one CVE."""
    catalog = catalog_for(language)
    return translate(
        catalog,
        "date_line",
        published=_date_text(published, catalog),
        first_seen=_date_text(first_seen, catalog),
    )


def _escape_slack(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_markdown(value: str) -> str:
    return re.sub(r"([\\*_`~|>\[\]])", r"\\\1", value)


def _escape_discord(value: str) -> str:
    return _escape_markdown(value).replace("@", "\\@")


def _slack_client(value: str) -> str:
    """Render one client label as literal Slack text, not mrkdwn."""
    text = _escape_slack(value).replace("`", "\u02cb")
    return f"`{text}`"


def _teams_client(value: str) -> str:
    """Escape HTML and Markdown tokens that Teams would interpret."""
    return _escape_markdown(html_module.escape(value, quote=True))


def _client_escape(style: str):
    if style == STYLE_SLACK:
        return _slack_client
    if style == STYLE_MARKDOWN:
        return _teams_client
    if style == STYLE_DISCORD:
        return _escape_discord
    return None


def _client_line(
    impacts: ClientImpacts,
    style: str,
    language: str,
) -> str:
    return format_affected_clients(
        impacts,
        language=language,
        limit=10,
        escape=_client_escape(style),
    )


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


def _provider_label(
    provider: str,
    entry: CVSSEntry,
    view: WatchView,
    catalog: Mapping[str, str],
) -> str:
    if provider == "cna":
        return translate(
            catalog, "provider_cna", name=_cna_name(entry, view)
        )
    if provider == "nvd":
        return catalog["provider_nvd"]
    if provider == "cisa-adp":
        return catalog["provider_cisa_adp"]
    if provider == "euvd":
        return catalog["provider_euvd"]
    return catalog["provider_other"]


def _cvss_field(
    view: WatchView,
    style: str = STYLE_PLAIN,
    catalog: Mapping[str, str] | None = None,
) -> str:
    if catalog is None:
        catalog = catalog_for(DEFAULT_LANGUAGE)
    best = _best_by_provider(view.cvss)
    parts: list[str] = []
    for provider in PROVIDER_ORDER:
        entry = best.get(provider)
        if entry is None:
            continue
        label = _dynamic(
            _provider_label(provider, entry, view, catalog), style, 80
        )
        parts.append(
            translate(
                catalog,
                "cvss_score",
                score=f"{entry.score:g}",
                provider=label,
            )
        )
    if not parts:
        return catalog["cvss_not_scored"]
    if "nvd" not in best and view.status != "rejected":
        parts.append(catalog["nvd_pending"])
    return ", ".join(parts)


def _epss_field(view: WatchView) -> str:
    if view.epss is None:
        return "–"
    return f"{view.epss:.2f}"


def _exploitation_value(view: WatchView, catalog: Mapping[str, str]) -> str:
    if view.ssvc_exploitation == "active" or view.euvd_exploited_since:
        return catalog["exploitation_active"]
    if view.ssvc_exploitation == "poc":
        return catalog["exploitation_poc"]
    return catalog["exploitation_none"]


def _reason_transition(reasons: Sequence[str], prefix: str) -> tuple[str, str] | None:
    for reason in reasons:
        if reason.startswith(prefix) and " -> " in reason:
            old, _, new = reason[len(prefix) :].partition(" -> ")
            if old.strip() and new.strip():
                return old.strip(), new.strip()
    return None


def _severity_text(value: str, catalog: Mapping[str, str]) -> str:
    key = f"severity_{value}"
    if key in catalog:
        return catalog[key]
    return value


def _epss_text(value: str, catalog: Mapping[str, str]) -> str:
    if value == "none":
        return catalog["epss_band_none"]
    return value


def _kind_label(
    event: DeliveryEvent, style: str, catalog: Mapping[str, str]
) -> str:
    kind = event.kind
    if kind == "match":
        return catalog["label_match"]
    if kind == "kev_added":
        catalog_name = "CISA"
        for reason in event.reasons:
            if "kev eu" in reason:
                catalog_name = "EU"
            elif "kev cisa" in reason:
                catalog_name = "CISA"
        if catalog_name == "EU":
            catalog_name = catalog["kev_catalog_eu"]
        return translate(
            catalog, "label_kev_added", catalog=catalog_name
        )
    if kind == "exploitation_active":
        return catalog["label_exploited"]
    if kind == "severity_increase":
        transition = _reason_transition(event.reasons, "severity")
        if transition is not None:
            return translate(
                catalog,
                "label_severity_up",
                previous=_severity_text(transition[0], catalog),
                current=_severity_text(transition[1], catalog),
            )
        return catalog["label_severity_up_plain"]
    if kind == "epss_increase":
        previous = event.details.get("previous_epss")
        current = event.details.get("epss")
        if not isinstance(current, (int, float)):
            current = event.view.epss
        if isinstance(previous, (int, float)) and isinstance(current, (int, float)):
            return translate(
                catalog,
                "label_epss_up",
                previous=f"{float(previous):.2f}",
                current=f"{float(current):.2f}",
            )
        transition = _reason_transition(event.reasons, "epss")
        if transition is not None:
            return translate(
                catalog,
                "label_epss_up",
                previous=_epss_text(transition[0], catalog),
                current=_epss_text(transition[1], catalog),
            )
        return catalog["label_epss_up_plain"]
    if kind == "nvd_score_added":
        nvd = _best_by_provider(event.view.cvss).get("nvd")
        if nvd is not None:
            return translate(
                catalog, "label_nvd_scored", score=f"{nvd.score:g}"
            )
        return catalog["label_nvd_scored_plain"]
    if kind == "rejected":
        return catalog["label_rejected"]
    if kind == "reported":
        return catalog["label_reported"]
    if kind == "unreported":
        return catalog["label_unreported"]
    return translate(catalog, "label_unknown", kind=kind.upper())


def _link_pairs(
    event: DeliveryEvent, catalog: Mapping[str, str]
) -> tuple[tuple[str, str], ...]:
    view = event.view
    cve_id = quote(str(event.cve_id), safe="-_.")
    values: list[tuple[str, str]] = [
        (NVD_URL.format(cve_id=cve_id), catalog["link_nvd"]),
        (CVE_URL.format(cve_id=cve_id), catalog["link_cve"]),
    ]
    if view.euvd_id:
        euvd_id = quote(str(view.euvd_id), safe="-_.")
        values.append(
            (EUVD_URL.format(euvd_id=euvd_id), catalog["link_euvd"])
        )
    if view.cisa_kev_added is not None or view.eu_kev_added is not None:
        values.append((KEV_URL, catalog["link_kev"]))
    return tuple(values)


def _links(
    event: DeliveryEvent, style: str, catalog: Mapping[str, str]
) -> str:
    return " · ".join(
        _link(url, label, style) for url, label in _link_pairs(event, catalog)
    )


def _group_events(
    events: Iterable[DeliveryEvent],
    style: str,
    catalog: Mapping[str, str],
) -> list[list[DeliveryEvent]]:
    """Merge events that render the same CVE line under the same label."""
    grouped: dict[tuple[str, str], list[DeliveryEvent]] = {}
    for event in events:
        key = (event.cve_id, _kind_label(event, style, catalog))
        grouped.setdefault(key, []).append(event)
    return list(grouped.values())


@dataclass(frozen=True, slots=True)
class _EventFacts:
    """The facts one CVE block shows, shared by the text and HTML renderers."""

    label: str
    cve_id: str
    cvss: str
    epss: str
    kev: str
    exploitation: str
    published: str
    first_seen: str
    date_line: str
    description: str
    extras: tuple[str, ...]
    client_impacts: ClientImpacts
    language: str
    reported: str
    rules: tuple[str, ...]
    links: tuple[tuple[str, str], ...]


def _event_facts(
    group: Sequence[DeliveryEvent],
    names: Mapping[str, str],
    catalog: Mapping[str, str],
    language: str,
    clients: Mapping[str, ClientImpacts | Sequence[ClientImpact]] | None = None,
) -> _EventFacts:
    event = group[0]
    view = event.view
    published = _date_text(view.published, catalog)
    first_seen = _date_text(view.first_seen, catalog)
    extras: list[str] = []
    if event.kind == "kev_added" and view.cisa_kev_added is not None:
        if view.cisa_kev_due:
            extras.append(
                translate(
                    catalog, "due", date=_clean(view.cisa_kev_due, 40)
                )
            )
        if view.cisa_required_action:
            extras.append(_clean(view.cisa_required_action, KEV_ACTION_LIMIT))
    return _EventFacts(
        label=_kind_label(event, STYLE_PLAIN, catalog),
        cve_id=str(event.cve_id),
        cvss=_cvss_field(view, STYLE_PLAIN, catalog),
        epss=_epss_field(view),
        kev=translate(
            catalog,
            "kev_value",
            cisa="✓" if view.cisa_kev_added is not None else "–",
            eu_name=catalog["kev_catalog_eu"],
            eu="✓" if view.eu_kev_added is not None else "–",
        ),
        exploitation=_exploitation_value(view, catalog),
        published=published,
        first_seen=first_seen,
        date_line=translate(
            catalog, "date_line", published=published, first_seen=first_seen
        ),
        description=_clean(view.description, DESCRIPTION_LIMIT),
        extras=tuple(extras),
        client_impacts=impacts_for(clients, event.cve_id),
        language=language,
        reported=(
            format_reported(event.reported, language)
            if event.reported is not None
            else ""
        ),
        rules=tuple(
            sorted({_display_name(item, names) for item in group})
        ),
        links=_link_pairs(event, catalog),
    )


def _event_summary(
    facts: _EventFacts, style: str, catalog: Mapping[str, str]
) -> str:
    return (
        f"{facts.label} {_dynamic(facts.cve_id, style)} · "
        f"{_dynamic(facts.cvss, style)} · "
        f"{_dynamic(translate(catalog, 'epss_field', score=facts.epss), style)} · "
        f"{_dynamic(translate(catalog, 'kev_field', kev=facts.kev), style)} · "
        f"{_dynamic(translate(catalog, 'exploitation_field', value=facts.exploitation), style)}"
    )


def _event_lines(
    facts: _EventFacts, style: str, catalog: Mapping[str, str]
) -> list[str]:
    lines = [
        _event_summary(facts, style, catalog),
        f"  {_dynamic(facts.date_line, style)}",
    ]
    if facts.description:
        lines.append(f"  {_dynamic(facts.description, style)}")
    if facts.extras:
        lines.append(
            "  " + " · ".join(_dynamic(item, style) for item in facts.extras)
        )
    if facts.client_impacts:
        lines.append(
            "  " + _client_line(facts.client_impacts, style, facts.language)
        )
    if facts.reported:
        lines.append("  " + _dynamic(facts.reported, style))
    rules = ", ".join(_dynamic(name, style, 80) for name in facts.rules)
    links = " · ".join(
        _link(url, label, style) for url, label in facts.links
    )
    lines.append(
        "  "
        + translate(
            catalog,
            "rule_line_plural" if len(facts.rules) > 1 else "rule_line",
            rules=rules,
            links=links,
        )
    )
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


def _counts_phrase(
    groups: Sequence[Sequence[DeliveryEvent]], catalog: Mapping[str, str]
) -> str:
    counts = Counter(group[0].kind for group in groups)
    parts: list[str] = []
    for kind in EVENT_KINDS:
        count = counts.get(kind, 0)
        if not count:
            continue
        suffix = "one" if count == 1 else "other"
        parts.append(
            translate(
                catalog, f"count_{kind}_{suffix}", count=count
            )
        )
    if parts:
        return ", ".join(parts)
    suffix = "one" if len(groups) == 1 else "other"
    return translate(catalog, f"count_events_{suffix}", count=len(groups))


def _rule_label(
    events: Sequence[DeliveryEvent],
    names: Mapping[str, str],
    catalog: Mapping[str, str],
) -> str:
    rules = {event.rule for event in events}
    if len(rules) == 1:
        folded = next(iter(rules))
        return names.get(folded, folded)
    return translate(catalog, "rule_count_other", count=len(rules))


def _display_name(event: DeliveryEvent, names: Mapping[str, str]) -> str:
    return names.get(event.rule, event.rule)


def _run_subject(
    events: Sequence[DeliveryEvent],
    names: Mapping[str, str],
    catalog: Mapping[str, str],
) -> str:
    groups = _group_events(sort_events(events), STYLE_PLAIN, catalog)
    return translate(
        catalog,
        "subject_run",
        counts=_counts_phrase(groups, catalog),
        rules=_rule_label(events, names, catalog),
    )


def _event_subject(
    event: DeliveryEvent, names: Mapping[str, str], catalog: Mapping[str, str]
) -> str:
    label = _kind_label(event, STYLE_PLAIN, catalog)
    return translate(catalog, "subject_event", label=label, cve=event.cve_id)


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


_HTML_FONT = (
    "font-family:Arial,Helvetica,sans-serif;font-size:14px;"
    "line-height:1.5;color:#1b1f24;"
)
_HTML_MUTED = "color:#475467;font-size:12px;"
_HTML_LINK = "color:#0b57d0;text-decoration:underline;"
_HTML_TD = "padding:4px 6px;vertical-align:top;border-bottom:1px solid #e4e7ec;"
_HTML_TH = (
    "padding:6px;text-align:left;border-bottom:2px solid #d0d5dd;"
    "font-size:11px;letter-spacing:0.03em;text-transform:uppercase;"
    "color:#475467;"
)
_HTML_BLOCK = (
    "border:1px solid #d0d5dd;border-left:4px solid #0b57d0;"
    "border-radius:4px;padding:10px 12px;margin:0 0 12px 0;"
    "background-color:#f8fafc;"
)


def _h(value: str) -> str:
    """Escape one dynamic value for HTML text and attribute contexts."""
    return html_module.escape(value, quote=True)


def _html_link(url: str, label: str) -> str:
    return (
        f'<a href="{_h(url)}" style="{_HTML_LINK}" '
        f'rel="noopener noreferrer">{_h(label)}</a>'
    )


def _html_links(facts: _EventFacts) -> str:
    return " · ".join(
        _html_link(url, label) for url, label in facts.links
    )


def _html_document(language: str, subject: str, fragment: str) -> str:
    """Wrap a fragment in a small table-based email document.

    Every style is inline, there are no images, scripts, fonts or remote
    stylesheets, and the layout uses tables only.
    """
    return (
        "<!doctype html>\n"
        f'<html lang="{_h(language)}">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light dark">\n'
        f"<title>{_h(subject)}</title>\n</head>\n"
        '<body style="margin:0;padding:0;background-color:#f2f4f7;">\n'
        '<table role="presentation" width="100%" cellpadding="0" '
        'cellspacing="0" border="0" style="background-color:#f2f4f7;">\n'
        '<tr><td align="center" style="padding:16px;">\n'
        '<table role="presentation" width="100%" cellpadding="0" '
        'cellspacing="0" border="0" style="max-width:720px;'
        'background-color:#ffffff;border:1px solid #d0d5dd;'
        'border-radius:6px;">\n'
        f'<tr><td style="padding:16px 18px;{_HTML_FONT}">\n'
        '<h1 style="font-size:18px;line-height:1.3;margin:0 0 12px 0;">'
        f"{_h(subject)}</h1>\n"
        f"{fragment}\n"
        "</td></tr>\n</table>\n</td></tr>\n</table>\n</body>\n</html>"
    )


def _html_event_block(facts: _EventFacts, catalog: Mapping[str, str]) -> str:
    rows = [
        f'<tr><td style="{_HTML_TD}"><strong>'
        f"{_h(_event_summary(facts, STYLE_PLAIN, catalog))}"
        "</strong></td></tr>",
        f'<tr><td style="{_HTML_TD}{_HTML_MUTED}">'
        f"{_h(facts.date_line)}</td></tr>",
    ]
    if facts.description:
        rows.append(
            f'<tr><td style="{_HTML_TD}">{_h(facts.description)}</td></tr>'
        )
    if facts.extras:
        rows.append(
            f'<tr><td style="{_HTML_TD}{_HTML_MUTED}">'
            f'{_h(" · ".join(facts.extras))}</td></tr>'
        )
    if facts.client_impacts:
        rows.append(
            f'<tr><td style="{_HTML_TD}">'
            f'{_h(format_affected_clients(facts.client_impacts, language=facts.language, limit=10))}</td></tr>'
        )
    if facts.reported:
        rows.append(
            f'<tr><td style="{_HTML_TD}">{_h(facts.reported)}</td></tr>'
        )
    rules = _h(", ".join(facts.rules))
    rule_label = catalog[
        "rule_label_plural" if len(facts.rules) > 1 else "rule_label"
    ]
    rows.append(
        f'<tr><td style="{_HTML_TD}">'
        f'<span style="{_HTML_MUTED}">{_h(rule_label)}:</span> '
        f"{rules} · {_html_links(facts)}</td></tr>"
    )
    return (
        '<table role="presentation" width="100%" cellpadding="0" '
        'cellspacing="0" border="0" '
        f'style="{_HTML_BLOCK}">' + "".join(rows) + "</table>"
    )


def _html_run_fragment(
    facts: Sequence[_EventFacts],
    omitted: int,
    catalog: Mapping[str, str],
) -> str:
    blocks = [_html_event_block(item, catalog) for item in facts]
    if omitted:
        blocks.append(
            f'<p style="margin:8px 0;{_HTML_MUTED}">'
            f'{_h(translate(catalog, "and_more", count=omitted))}</p>'
        )
    return "\n".join(blocks)


def _html_digest_fragment(
    rule_pairs: Sequence[tuple[str, str]],
    facts: Sequence[_EventFacts],
    omitted: int,
    hint: str,
    catalog: Mapping[str, str],
) -> str:
    parts: list[str] = []
    for rule, counts in rule_pairs:
        parts.append(
            '<h2 style="font-size:14px;line-height:1.3;margin:14px 0 2px 0;">'
            f"{_h(rule)}</h2>"
        )
        parts.append(
            f'<p style="margin:0 0 8px 0;{_HTML_MUTED}">{_h(counts)}</p>'
        )
    columns = (
        "html_column_cve",
        "html_column_severity",
        "html_column_epss",
        "html_column_kev",
        "html_column_exploitation",
        "html_column_published",
        "html_column_first_seen",
    )
    header = "".join(
        f'<th scope="col" style="{_HTML_TH}">{_h(catalog[key])}</th>'
        for key in columns
    )
    rows: list[str] = []
    for item in facts:
        cell: list[str] = [
            f"<strong>{_h(item.label)}</strong>",
            _h(item.cve_id),
        ]
        if item.description:
            cell.append(
                f'<span style="{_HTML_MUTED}">{_h(item.description)}</span>'
            )
        if item.extras:
            cell.append(
                f'<span style="{_HTML_MUTED}">'
                f'{_h(" · ".join(item.extras))}</span>'
            )
        if item.client_impacts:
            cell.append(
                f'<span style="{_HTML_MUTED}">'
                f'{_h(format_affected_clients(item.client_impacts, language=item.language, limit=10))}</span>'
            )
        if item.reported:
            cell.append(
                f'<span style="{_HTML_MUTED}">{_h(item.reported)}</span>'
            )
        cell.append(
            f'<span style="{_HTML_MUTED}">'
            f'{_h(catalog["rule_label_plural"] if len(item.rules) > 1 else catalog["rule_label"])}: '
            f'{_h(", ".join(item.rules))}</span>'
        )
        cell.append(
            f'<span style="{_HTML_MUTED}">{_html_links(item)}</span>'
        )
        values = (
            "<br>".join(cell),
            _h(item.cvss),
            _h(item.epss),
            _h(item.kev),
            _h(item.exploitation),
            _h(item.published),
            _h(item.first_seen),
        )
        rows.append(
            "<tr>"
            + "".join(
                f'<td style="{_HTML_TD}">{value}</td>' for value in values
            )
            + "</tr>"
        )
    parts.append(
        '<table width="100%" cellpadding="0" '
        'cellspacing="0" border="0" '
        'style="border-collapse:collapse;width:100%;font-size:12px;">'
        f"<tr>{header}</tr>{''.join(rows)}</table>"
    )
    if omitted:
        parts.append(
            f'<p style="margin:8px 0;{_HTML_MUTED}">'
            f'{_h(translate(catalog, "and_more", count=omitted))}</p>'
        )
    else:
        parts.append(
            f'<p style="margin:8px 0;{_HTML_MUTED}">{_h(hint)}</p>'
        )
    return "\n".join(parts)


def _email_content_fits(
    body: str,
    markup: str,
    *,
    channel_type: str,
    limit: int,
    byte_limit: bool = False,
) -> bool:
    """Return whether the content this email channel sends fits the limit.

    SMTP carries both alternatives in one message, so the decoded sizes are
    counted together. Graph sends only one body; with HTML that body is the
    HTML document, so only the document is counted. A text-only message keeps
    the earlier behavior and is not size-predicated here.
    """
    if not markup:
        return True
    if channel_type == "graph":
        return _size(markup, byte_limit) <= limit
    return _size(body, byte_limit) + _size(markup, byte_limit) <= limit


def _event_body_and_html(
    events: Sequence[DeliveryEvent],
    *,
    style: str,
    names: Mapping[str, str],
    catalog: Mapping[str, str],
    language: str,
    subject: str,
    channel_type: str,
    limit: int,
    max_items: int | None = None,
    byte_limit: bool = False,
    with_html: bool = False,
    clients: Mapping[str, ClientImpacts] | None = None,
) -> tuple[str, str]:
    listed = _group_events(sort_events(events), style, catalog)
    current = max_items
    while True:
        shown = listed if current is None else listed[:current]
        facts = [
            _event_facts(group, names, catalog, language, clients)
            for group in shown
        ]
        lines: list[str] = []
        for item in facts:
            lines.extend(_event_lines(item, style, catalog))
        omitted = len(listed) - len(shown)
        if omitted:
            lines.append(translate(catalog, "and_more", count=omitted))
        body = "\n".join(lines)
        markup = ""
        if with_html:
            markup = _html_document(
                language,
                subject,
                _html_run_fragment(facts, omitted, catalog),
            )
        fits = len(split_message(body, limit, byte_limit=byte_limit)) <= MAX_PARTS
        if with_html and not _email_content_fits(
            body,
            markup,
            channel_type=channel_type,
            limit=limit,
            byte_limit=byte_limit,
        ):
            fits = False
        if fits:
            return body, markup
        if not shown:
            if with_html:
                raise MessageTooLarge(MESSAGE_TOO_LARGE)
            return body, markup
        if current is None:
            current = len(shown) - 1
        else:
            current = max(0, min(current, len(shown)) - 1)


def _rule_count_pairs(
    totals: Mapping[str, Counter[str]],
    names: Mapping[str, str],
    catalog: Mapping[str, str],
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for rule in sorted(totals):
        parts: list[str] = []
        for kind in EVENT_KINDS:
            count = totals[rule].get(kind, 0)
            if not count:
                continue
            suffix = "one" if count == 1 else "other"
            parts.append(
                f"{count} "
                + translate(catalog, f"item_{kind}_{suffix}", count=count)
            )
        pairs.append(
            (_display_name_for(rule, names), ", ".join(parts))
        )
    return pairs


def _digest_hint(
    totals: Mapping[str, Counter[str]],
    names: Mapping[str, str],
    style: str,
    catalog: Mapping[str, str],
) -> str:
    rule_names = sorted(
        {_display_name_for(rule, names) for rule in totals}
    )
    if rule_names:
        example = rule_names[0]
        if any(character.isspace() for character in example):
            example = f'"{example}"'
        return translate(
            catalog,
            "list_all_rule",
            rule=_dynamic(example, style, 80),
        )
    return catalog["list_all"]


def _initial_body_and_html(
    events: Sequence[DeliveryEvent],
    *,
    style: str,
    names: Mapping[str, str],
    catalog: Mapping[str, str],
    language: str,
    subject: str,
    channel_type: str,
    limit: int,
    max_items: int,
    byte_limit: bool = False,
    counts: Sequence[tuple[str, str, int]] | None = None,
    total_cves: int | None = None,
    with_html: bool = False,
    clients: Mapping[str, ClientImpacts] | None = None,
) -> tuple[str, str]:
    ordered = sort_events(events)
    groups = _group_events(ordered, style, catalog)
    totals: dict[str, Counter[str]] = {}
    if counts is None:
        for event in ordered:
            totals.setdefault(event.rule, Counter())[event.kind] += 1
    else:
        for rule, kind, count in counts:
            totals.setdefault(rule, Counter())[kind] += count
    cves = (
        total_cves
        if total_cves is not None
        else len({event.cve_id for event in ordered})
    )
    current = max_items
    while True:
        shown = groups[:current]
        facts = [
            _event_facts(group, names, catalog, language, clients)
            for group in shown
        ]
        rule_pairs = _rule_count_pairs(totals, names, catalog)
        lines = [
            translate(
                catalog,
                "per_rule_line",
                rule=_display_name_for(rule, names),
                counts=counts_text,
            )
            for rule, counts_text in rule_pairs
        ]
        lines.append("")
        for item in facts:
            lines.extend(_event_lines(item, style, catalog))
        shown_cves = len({event.cve_id for group in shown for event in group})
        omitted = max(0, cves - shown_cves)
        hint = _digest_hint(totals, names, style, catalog)
        if omitted:
            lines.append(translate(catalog, "and_more", count=omitted))
        else:
            lines.append("")
            lines.append(hint)
        body = "\n".join(lines)
        markup = ""
        if with_html:
            markup = _html_document(
                language,
                subject,
                _html_digest_fragment(
                    rule_pairs,
                    facts,
                    omitted,
                    _digest_hint(totals, names, STYLE_PLAIN, catalog),
                    catalog,
                ),
            )
        fits = len(split_message(body, limit, byte_limit=byte_limit)) <= MAX_PARTS
        if with_html and not _email_content_fits(
            body,
            markup,
            channel_type=channel_type,
            limit=limit,
            byte_limit=byte_limit,
        ):
            fits = False
        if fits:
            return body, markup
        if not shown:
            if with_html:
                raise MessageTooLarge(MESSAGE_TOO_LARGE)
            return body, markup
        current = max(0, len(shown) - 1)


def _display_name_for(folded: str, names: Mapping[str, str]) -> str:
    return names.get(folded, folded)


def _initial_subject(
    cves: int,
    rules: int,
    since: str | None,
    catalog: Mapping[str, str],
) -> str:
    suffix = (
        translate(catalog, "since_suffix", since=since) if since else ""
    )
    cve_word = translate(
        catalog,
        "cve_word_one" if cves == 1 else "cve_word_other",
    )
    rule_word = translate(
        catalog,
        "rule_word_one" if rules == 1 else "rule_word_other",
    )
    return translate(
        catalog,
        "subject_initial_one" if cves == 1 else "subject_initial",
        cves=cves,
        cve_word=cve_word,
        rules=rules,
        rule_word=rule_word,
        since=suffix,
    )


def _notice_label(
    event: DeliveryEvent, catalog: Mapping[str, str]
) -> str:
    key = NOTICE_LABEL_KEYS.get(event.kind)
    if key is None:
        return translate(catalog, "label_unknown", kind=event.kind.upper())
    return catalog[key]


def _notice_subject(
    event: DeliveryEvent, catalog: Mapping[str, str]
) -> str:
    return translate(
        catalog,
        "subject_notice",
        label=_notice_label(event, catalog),
        cve=event.cve_id,
    )


def _sorted_notices(events: Iterable[DeliveryEvent]) -> tuple[DeliveryEvent, ...]:
    """Notices follow the durable audit order, never alert severity."""
    return tuple(
        sorted(
            (event for event in events if event.kind in NOTICE_KINDS),
            key=lambda event: event.event_id,
        )
    )


def _notice_by(event: DeliveryEvent, catalog: Mapping[str, str]) -> str:
    by = event.details.get("by")
    text = by if isinstance(by, str) and by.strip() else catalog["unknown"]
    username = event.details.get("username")
    if isinstance(username, str) and username.strip():
        text = identity_label(text, username)
    email = event.details.get("email")
    if isinstance(email, str) and email.strip():
        text += f" <{email}>"
    return text


def _notice_text(
    event: DeliveryEvent, style: str, catalog: Mapping[str, str]
) -> str:
    label = _notice_label(event, catalog)
    by_text = _dynamic(_notice_by(event, catalog), style, 450)
    stamp = format_timestamp(event.created_at)
    key = (
        "notice_unreported"
        if event.kind == "unreported"
        else "notice_reported"
    )
    line = translate(
        catalog,
        key,
        label=label,
        cve=event.cve_id,
        by=by_text,
        at=stamp,
    )
    note = event.details.get("note")
    if isinstance(note, str) and note.strip():
        line += "\n  " + _dynamic(note, style, 500)
    return line


def _notice_html(
    event: DeliveryEvent, catalog: Mapping[str, str]
) -> str:
    key = (
        "notice_unreported"
        if event.kind == "unreported"
        else "notice_reported"
    )
    line = translate(
        catalog,
        key,
        label=_notice_label(event, catalog),
        cve=event.cve_id,
        by=_notice_by(event, catalog),
        at=format_timestamp(event.created_at),
    )
    parts = [
        f'<p style="margin:0 0 8px 0;"><strong>{_h(line)}</strong></p>'
    ]
    note = event.details.get("note")
    if isinstance(note, str) and note.strip():
        parts.append(
            f'<p style="margin:0;{_HTML_MUTED}">{_h(_clean(note, 500))}</p>'
        )
    return "\n".join(parts)


def build_messages(
    events: Sequence[DeliveryEvent],
    *,
    channel_type: str,
    grouping: str,
    max_items: int,
    names: Mapping[str, str],
    since: str | None = None,
    initial: InitialDigest | None = None,
    language: str = DEFAULT_LANGUAGE,
    format: str = "text",
    clients: Mapping[str, ClientImpacts] | None = None,
) -> tuple[OutgoingMessage, ...]:
    """Build the messages one channel should send for the selected events.

    ``format`` only adds an HTML alternative for the email channels; every
    other provider keeps its single text body. ``language`` selects the
    message catalog, and the text and HTML renderers always use the same
    facts. ``MessageTooLarge`` is raised when the fixed summary cannot fit
    the channel size limit even with no event rows left.
    """
    catalog = catalog_for(language)
    style = style_for(channel_type)
    limit = CHANNEL_LIMITS.get(channel_type, 32_768)
    byte_limit = channel_type in {"ntfy", "matrix", "teams"}
    chat = channel_type not in {"smtp", "graph", "webhook"}
    title_in_body = chat and channel_type not in {"ntfy", "gotify"}
    body_limit = limit - 300 if chat else limit
    with_html = format == "html" and channel_type in EMAIL_CHANNELS
    ordered = sort_events(events)
    notices = _sorted_notices(ordered)
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
        subject = _initial_subject(initial.cves, rules, since, catalog)
        body, markup = _initial_body_and_html(
            initial.events,
            style=style,
            names=names,
            catalog=catalog,
            language=language,
            subject=subject,
            channel_type=channel_type,
            limit=body_limit,
            max_items=max_items,
            byte_limit=byte_limit,
            counts=initial.counts,
            total_cves=initial.cves,
            with_html=with_html,
            clients=clients,
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
                    html=markup,
                    initial=True,
                    content=part,
                    part_index=index,
                    part_count=len(parts),
                )
            )
    for notice in notices:
        subject = _notice_subject(notice, catalog)
        body = _notice_text(notice, style, catalog)
        markup = (
            _html_document(
                language, subject, _notice_html(notice, catalog)
            )
            if with_html
            else ""
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
                    (notice.event_id,),
                    subject,
                    part,
                    body,
                    html=markup,
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
            _event_subject(group[0], names, catalog)
            if grouping == "event"
            else _run_subject(group, names, catalog)
        )
        body, markup = _event_body_and_html(
            group,
            style=style,
            names=names,
            catalog=catalog,
            language=language,
            subject=subject,
            channel_type=channel_type,
            limit=body_limit,
            max_items=None if grouping == "event" else max_items,
            byte_limit=byte_limit,
            with_html=with_html,
            clients=clients,
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
                    html=markup,
                    content=part,
                    part_index=index,
                    part_count=len(parts),
                )
            )
    return tuple(output)


def test_message(
    language: str = DEFAULT_LANGUAGE,
) -> tuple[str, str]:
    """Return the localized subject and body of a test message."""
    catalog = catalog_for(language)
    return catalog["test_subject"], catalog["test_message"]


def simple_html(language: str, subject: str, body: str) -> str:
    """Render one short paragraph as an HTML email document."""
    fragment = (
        f'<p style="margin:0;{_HTML_FONT}">{_h(body)}</p>'
    )
    return _html_document(language, subject, fragment)


def webhook_payload(
    events: Sequence[DeliveryEvent],
    names: Mapping[str, str],
    clients: Mapping[str, ClientImpacts] | None = None,
) -> dict[str, Any]:
    """Return the stable version 2 webhook document.

    ``affected_clients`` is added only when at least one client is affected, so
    documents without clients stay byte-identical to earlier versions.
    """
    output = []
    alerts = tuple(
        event for event in sort_events(events) if event.kind not in NOTICE_KINDS
    )
    for event in (*alerts, *_sorted_notices(events)):
        view = event.view
        impacts = impacts_for(clients, event.cve_id)
        entry: dict[str, Any] = {
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
                            **(
                                {"username": event.reported.username}
                                if event.reported.username
                                else {}
                            ),
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
        if impacts:
            shown = []
            used = 0
            for item in impacts.clients[:MAX_WEBHOOK_CLIENTS]:
                cost = len(item.name.encode("utf-8")) + 64
                if shown and used + cost > WEBHOOK_CLIENT_BUDGET:
                    break
                shown.append(item)
                used += cost
            if shown:
                entry["affected_clients"] = [
                    {
                        "name": item.name,
                        "assets": item.assets,
                        "status": item.status,
                    }
                    for item in shown
                ]
                omitted = impacts.omitted + len(impacts.clients) - len(shown)
                if omitted:
                    entry["affected_clients_omitted"] = omitted
        output.append(entry)
        if event.kind in NOTICE_KINDS:
            notice = {
                "action": "report" if event.kind == "reported" else "unreport",
                "by": str(event.details.get("by") or "unknown"),
                "note": event.details.get("note"),
            }
            for field in ("username", "email"):
                value = event.details.get(field)
                if isinstance(value, str) and value.strip():
                    notice[field] = value
            output[-1]["notice"] = notice
    return {"version": WEBHOOK_VERSION, "events": output}


def rule_display_names(rules: Iterable[Rule]) -> dict[str, str]:
    return {rule.name.casefold(): rule.name for rule in rules}
