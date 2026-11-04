from __future__ import annotations

import html as html_module
import re
from string import Formatter
from typing import Any

import pytest

from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.catalog import (
    CATALOGS,
    SUPPORTED_LANGUAGES,
    canonical_language,
)
from cvebeacon.watch.messages import (
    CHANNEL_LIMITS,
    DeliveryEvent,
    InitialDigest,
    MessageTooLarge,
    _email_content_fits,
    build_messages,
    webhook_payload,
)
from cvebeacon.watch.records import CVSSEntry, ReportedMark, WatchView

MESSAGE_CHANNELS = (
    "smtp",
    "graph",
    "teams",
    "slack",
    "discord",
    "telegram",
    "matrix",
    "ntfy",
    "gotify",
)
URL_PREFIXES = (
    "https://nvd.nist.gov/vuln/detail/",
    "https://www.cve.org/CVERecord?id=",
    "https://euvd.enisa.europa.eu/vulnerability/",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
)


def view(cve_id: str = "CVE-2026-1234", **overrides: Any) -> WatchView:
    values: dict[str, Any] = {
        "cve_id": cve_id,
        "status": "published",
        "published": "2026-10-30T14:00:00.000",
        "first_seen": "2026-11-04T09:15:00+00:00",
        "description": (
            "Acme Widget before 4.2.1 allows unauthenticated remote code "
            "execution."
        ),
        "source_identifier": "security@acme.example",
        "cvss": (CVSSEntry("cna", "security@acme.example", "3.1", 9.8),),
        "epss": 0.62,
    }
    values.update(overrides)
    return WatchView(**values)


def event(
    kind: str = "match",
    *,
    cve_id: str = "CVE-2026-1234",
    reasons: tuple[str, ...] = ("cvss 9.8 v3.1 (cna)",),
    initial: bool = False,
    details: dict[str, Any] | None = None,
    current: WatchView | None = None,
    event_id: int = 1,
    rule: str = "critical-or-likely",
    reported: ReportedMark | None = None,
) -> DeliveryEvent:
    return DeliveryEvent(
        event_id,
        rule,
        cve_id,
        kind,
        reasons,
        initial,
        "2026-11-03T12:00:00+00:00",
        current or view(cve_id),
        details or {},
        reported=reported,
    )


def message_for(
    item: DeliveryEvent,
    channel: str = "smtp",
    *,
    language: str = "pt-PT",
    format: str = "html",
    names: dict[str, str] | None = None,
):
    return build_messages(
        (item,),
        channel_type=channel,
        grouping="run",
        max_items=20,
        names=names or {item.rule: item.rule},
        language=language,
        format=format,
    )[0]


def placeholders(template: str) -> list[str]:
    return [
        name
        for _, name, _, _ in Formatter().parse(template)
        if name is not None
    ]


def visible_html(markup: str) -> str:
    text = re.sub(r"<[^>]+>", " ", markup)
    return re.sub(r"\s+", " ", html_module.unescape(text)).strip()


def test_supported_languages_are_the_catalog_keys():
    assert SUPPORTED_LANGUAGES == ("en", "pt-PT")
    assert set(CATALOGS) == set(SUPPORTED_LANGUAGES)


def test_catalogs_have_exactly_the_same_keys():
    assert set(CATALOGS["en"]) == set(CATALOGS["pt-PT"])


def test_catalog_placeholders_match_per_key():
    for key in CATALOGS["en"]:
        assert placeholders(CATALOGS["en"][key]) == placeholders(
            CATALOGS["pt-PT"][key]
        ), key


def test_unknown_language_lists_the_supported_values():
    with pytest.raises(ConfigurationError, match="en, pt-PT"):
        canonical_language("pt-BR", label="watch.language")
    with pytest.raises(ConfigurationError, match="en, pt-PT"):
        canonical_language(3, label="watch.language")


def test_language_names_are_case_insensitive():
    assert canonical_language("EN") == "en"
    assert canonical_language("pt-pt") == "pt-PT"


def test_pt_pt_renders_every_message_channel_family():
    for channel in MESSAGE_CHANNELS:
        message = message_for(event(), channel)
        body = (
            message.body
            if channel in {"smtp", "graph"}
            else message.text
        )
        assert "[NOVO]" in body, channel
        assert "Publicado 2026-10-30" in body, channel
        assert "visto pela primeira vez 2026-11-04" in body, channel
        assert "Exploração: nenhuma" in body, channel
        assert "Regra: critical-or-likely" in body, channel
        assert "https://nvd.nist.gov/vuln/detail/CVE-2026-1234" in body, channel


def test_webhook_alert_payload_stays_language_independent():
    item = event()
    payload = webhook_payload((item,), {item.rule: item.rule})
    entry = payload["events"][0]
    assert entry["cve_id"] == "CVE-2026-1234"
    assert entry["kind"] == "match"
    assert entry["rule"] == "critical-or-likely"
    assert "NOVO" not in repr(payload)
    assert "Resumo" not in repr(payload)


def test_pt_pt_alert_header_and_reported_line():
    mark = ReportedMark(
        "CVE-2026-1234", "alice", None, "2026-11-04T12:00:00+00:00"
    )
    message = message_for(event(reported=mark), "smtp", format="text")
    assert "[NOVO] CVE-2026-1234" in message.body
    assert "CVSS 9.8 (CNA: acme.example), NVD pendente" in message.body
    assert "EPSS 0.62" in message.body
    assert "KEV: CISA – EU –" in message.body
    assert (
        "Comunicado aos clientes por alice em 2026-11-04 12:00 UTC"
        in message.body
    )


def test_pt_pt_digest_uses_a_summary_and_per_rule_sections():
    events = (
        event("match", cve_id="CVE-2026-0001", event_id=1, initial=True, rule="alpha"),
        event("match", cve_id="CVE-2026-0002", event_id=2, initial=True, rule="alpha"),
        event(
            "kev_added",
            cve_id="CVE-2026-0003",
            event_id=3,
            initial=True,
            rule="beta",
            reasons=("kev cisa false -> true",),
            current=view("CVE-2026-0003", cisa_kev_added="2026-11-03"),
        ),
    )
    message = build_messages(
        events,
        channel_type="smtp",
        grouping="run",
        max_items=20,
        names={"alpha": "alpha", "beta": "beta"},
        since="2026-10-27",
        language="pt-PT",
        format="html",
    )[0]
    assert message.subject == (
        "Resumo inicial do CVEBeacon: 3 CVEs repartidos por 2 regras desde 2026-10-27"
    )
    assert "alpha: 2 correspondências" in message.body
    assert "beta: 1 adicionado ao KEV" in message.body
    assert "[NOVO] CVE-2026-0001" in message.body
    assert "Publicado 2026-10-30" in message.body
    assert "Execute `cvebeacon watch events --rule alpha`" in message.body
    assert "<h2" in message.html
    assert "Gravidade" in message.html
    assert "Visto pela primeira vez" in message.html


def test_pt_pt_notice_message_and_subject():
    notice = event(
        "reported",
        details={"by": "alice", "note": "Enviado no ticket OPS-42"},
    )
    message = message_for(notice, "slack", format="text")
    assert message.subject == "CVEBeacon: [COMUNICADO] CVE-2026-1234"
    assert (
        "[COMUNICADO] CVE-2026-1234 comunicado aos clientes por alice "
        "em 2026-11-03 12:00 UTC"
    ) in message.text
    assert "Enviado no ticket OPS-42" in message.text


def test_pt_pt_unreported_notice():
    notice = event("unreported", details={"by": "alice"})
    message = message_for(notice, "slack", format="text")
    assert message.subject == "CVEBeacon: [NÃO COMUNICADO] CVE-2026-1234"
    assert (
        "comunicação aos clientes retirada por alice em "
        "2026-11-03 12:00 UTC"
    ) in message.text


def test_html_escapes_dynamic_values():
    description = (
        '<script>alert("x")</script> "><img src=x onerror=alert(1)> '
        "[click](https://evil.test) *bold*"
    )
    message = message_for(
        event(current=view(description=description)), "smtp"
    )
    assert "<script" not in message.html.lower()
    assert "<img" not in message.html.lower()
    assert "&lt;script&gt;" in message.html
    assert "&lt;img" in message.html
    assert "&quot;&gt;" in message.html
    assert "[click](https://evil.test)" in html_module.unescape(message.html)


def test_html_escapes_notice_identity_and_note():
    notice = event(
        "reported",
        details={
            "by": "<b>alice</b>",
            "note": '<img src=x onerror="alert(1)">',
        },
    )
    message = message_for(notice, "smtp")
    assert "<b>alice</b>" not in message.html
    assert "&lt;b&gt;alice&lt;/b&gt;" in message.html
    assert "<img" not in message.html.lower()
    assert "&lt;img" in message.html


def test_html_links_are_known_urls_and_percent_quoted():
    item = event(
        current=view(
            euvd_id='EUVD-2026-1"><script>',
            cisa_kev_added="2026-11-03",
        )
    )
    message = message_for(item, "smtp")
    hrefs = re.findall(r'href="([^"]*)"', message.html)
    assert hrefs
    for href in hrefs:
        assert href.startswith(URL_PREFIXES), href
        assert '"' not in href
    assert "%3Cscript%3E" in message.html
    assert "%22" in message.html


def test_html_has_no_remote_resources_or_scripts():
    message = message_for(event(), "smtp")
    lowered = message.html.lower()
    for tag in ("<script", "<img", "<link", "<iframe", "<object", "<embed"):
        assert tag not in lowered
    for marker in ("@import", "url(", "http://", "<style"):
        assert marker not in lowered


def test_text_and_html_carry_the_same_facts():
    mark = ReportedMark(
        "CVE-2026-1234", "alice", None, "2026-11-04T12:00:00+00:00"
    )
    item = event(
        "kev_added",
        reasons=("kev cisa false -> true",),
        current=view(
            euvd_id="EUVD-2026-1234",
            cisa_kev_added="2026-11-03",
            cisa_kev_due="2026-11-20",
            cisa_required_action="Apply the vendor update.",
            epss=0.62,
        ),
        reported=mark,
    )
    message = message_for(item, "smtp", language="en")
    visible = visible_html(message.html)
    for fact in (
        "[KEV ADDED: CISA] CVE-2026-1234",
        "CVSS 9.8 (CNA: acme.example), NVD pending",
        "EPSS 0.62",
        "KEV: CISA ✓ EU –",
        "Exploitation: none",
        "Published 2026-10-30 · first seen 2026-11-04",
        "Acme Widget before 4.2.1 allows unauthenticated remote code execution.",
        "Due 2026-11-20",
        "Apply the vendor update.",
        "Reported to clients by alice at 2026-11-04 12:00 UTC",
        "Rule: critical-or-likely",
    ):
        assert fact in message.body
        assert fact in visible
    for url in (
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
        "https://www.cve.org/CVERecord?id=CVE-2026-1234",
        "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-1234",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ):
        assert url in message.body
        assert url in message.html


def test_digest_html_has_a_compact_table_with_the_same_facts():
    events = (
        event("match", cve_id="CVE-2026-0001", event_id=1, initial=True),
        event(
            "match",
            cve_id="CVE-2026-0002",
            event_id=2,
            initial=True,
            current=view("CVE-2026-0002", description="Second description."),
        ),
    )
    message = build_messages(
        events,
        channel_type="smtp",
        grouping="run",
        max_items=20,
        names={"critical-or-likely": "critical-or-likely"},
        since="2026-10-27",
        language="en",
        format="html",
    )[0]
    assert "CVEBeacon initial summary: 2 CVEs across 1 rule" in message.subject
    assert "<table" in message.html
    assert '<th scope="col"' in message.html
    assert '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse' not in message.html
    visible = visible_html(message.html)
    for fact in (
        "CVE-2026-0001",
        "CVE-2026-0002",
        "Second description.",
        "Published",
        "First seen",
        "Severity",
        "EPSS",
        "KEV",
        "Exploitation",
        "2 matches",
    ):
        assert fact in visible


def test_html_is_ignored_for_chat_channels():
    message = message_for(event(), "slack")
    assert message.html == ""


def test_email_size_limit_counts_the_sent_body(monkeypatch):
    monkeypatch.setitem(CHANNEL_LIMITS, "smtp", 20_000)
    events = tuple(
        event(
            "match",
            cve_id=f"CVE-2026-{index:04d}",
            event_id=index,
            current=view(
                f"CVE-2026-{index:04d}",
                description="A long vulnerability description " * 20,
            ),
        )
        for index in range(1, 21)
    )
    message = build_messages(
        events,
        channel_type="smtp",
        grouping="run",
        max_items=20,
        names={"critical-or-likely": "critical-or-likely"},
        format="html",
    )[0]
    assert len(message.body) + len(message.html) <= 20_000
    assert message.body.count("[NEW]") == message.html.count("[NEW]")
    assert "and " in message.body


def test_graph_size_limit_counts_only_the_html_body():
    body = "x" * 15_000
    markup = "y" * 5_000
    assert _email_content_fits(
        body,
        markup,
        channel_type="graph",
        limit=10_000,
    )
    assert not _email_content_fits(
        body,
        markup,
        channel_type="smtp",
        limit=10_000,
    )
    assert not _email_content_fits(
        "x" * 15_000,
        "y" * 25_000,
        channel_type="graph",
        limit=20_000,
    )


@pytest.mark.parametrize("channel", ("smtp", "graph"))
def test_oversized_fixed_digest_summary_is_rejected(channel):
    counts = tuple(
        (f"rule-{index:04d}-" + "x" * 50, "match", 1)
        for index in range(7_000)
    )
    digest = InitialDigest(
        (event("match", initial=True),),
        counts,
        1,
        7_000,
    )
    with pytest.raises(MessageTooLarge):
        build_messages(
            (),
            channel_type=channel,
            grouping="run",
            max_items=20,
            names={},
            initial=digest,
            format="html",
        )


@pytest.mark.parametrize(
    ("kind", "kwargs", "expected", "english"),
    (
        ("match", {}, "[NOVO]", "[NEW]"),
        (
            "kev_added",
            {
                "reasons": ("kev cisa false -> true",),
                "current": view(cisa_kev_added="2026-11-03"),
            },
            "[ADICIONADO AO KEV: CISA]",
            "[KEV ADDED",
        ),
        (
            "exploitation_active",
            {
                "reasons": ("exploitation poc -> active (cisa-adp)",),
                "current": view(ssvc_exploitation="active"),
            },
            "[EXPLORADA ATIVAMENTE]",
            "[ACTIVELY EXPLOITED]",
        ),
        (
            "severity_increase",
            {
                "reasons": ("severity high -> critical",),
            },
            "[GRAVIDADE AUMENTOU alta->crítica]",
            "[SEVERITY UP",
        ),
        (
            "epss_increase",
            {
                "reasons": ("epss <0.1 -> <0.5",),
                "details": {"previous_epss": 0.08},
                "current": view(epss=0.61),
            },
            "[EPSS AUMENTOU 0.08->0.61]",
            "[EPSS UP",
        ),
        (
            "nvd_score_added",
            {
                "reasons": ("nvd score absent -> present",),
                "current": view(
                    cvss=(
                        CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.1),
                    )
                ),
            },
            "[PONTUAÇÃO NVD ADICIONADA 9.1]",
            "[NVD SCORED",
        ),
        (
            "rejected",
            {
                "reasons": ("status published -> rejected",),
                "current": view(status="rejected"),
            },
            "[REJEITADO]",
            "[REJECTED]",
        ),
    ),
)
def test_pt_pt_every_event_kind_is_translated(kind, kwargs, expected, english):
    item = event(kind, **kwargs)
    for fmt in ("text", "html"):
        message = message_for(item, "smtp", format=fmt)
        visible = (
            message.body if fmt == "text" else visible_html(message.html)
        )
        assert expected in visible
        assert english not in visible
    subject = build_messages(
        (item,),
        channel_type="smtp",
        grouping="event",
        max_items=20,
        names={item.rule: item.rule},
        language="pt-PT",
        format="text",
    )[0].subject
    assert expected in subject
    assert english not in subject


def test_pt_pt_missing_date_uses_agreement_for_a_date():
    message = message_for(
        event(current=view(published=None)), "smtp", format="text"
    )
    assert "Publicado data desconhecida" in message.body
    assert "Publicado desconhecido" not in message.body


def test_pt_pt_typography_for_dates_and_due_dates():
    item = event(
        "kev_added",
        reasons=("kev cisa false -> true",),
        current=view(
            cisa_kev_added="2026-11-03",
            cisa_kev_due="2026-11-20",
            cisa_required_action="Apply the update.",
        ),
    )
    message = message_for(item, "smtp", format="text")
    assert "Publicado 2026-10-30 · visto pela primeira vez" in message.body
    assert "Prazo: 2026-11-20" in message.body
    assert "Prazo 2026-11-20" not in message.body


def test_pt_pt_singular_initial_summary():
    item = event("match", cve_id="CVE-2026-0001", initial=True, rule="only")
    message = build_messages(
        (item,),
        channel_type="smtp",
        grouping="run",
        max_items=20,
        names={"only": "only"},
        since="2026-10-27",
        language="pt-PT",
        format="text",
    )[0]
    assert message.subject == (
        "Resumo inicial do CVEBeacon: 1 CVE repartido por 1 regra "
        "desde 2026-10-27"
    )


def test_pt_pt_unscored_cvss_wording():
    message = message_for(
        event(current=view(cvss=())), "smtp", format="text"
    )
    assert "Sem pontuação CVSS" in message.body
    assert "não classificada" not in message.body


def test_html_escapes_rule_due_action_and_cna_source():
    item = event(
        "kev_added",
        reasons=("kev cisa false -> true",),
        current=view(
            source_identifier="security@<script>.example",
            cvss=(
                CVSSEntry(
                    "cna", "security@<script>.example", "3.1", 9.8
                ),
            ),
            cisa_kev_added="2026-11-03",
            cisa_kev_due='2026-11-20<script>alert("due")</script>',
            cisa_required_action='"><img src=x onerror="alert(1)">',
        ),
    )
    message = build_messages(
        (item,),
        channel_type="smtp",
        grouping="run",
        max_items=20,
        names={item.rule: '<b onclick="x">rule</b>'},
        language="en",
        format="html",
    )[0]
    lowered = message.html.lower()
    for raw in ("<script", "<img", "<b onclick", "onerror=\"alert(1)\""):
        assert raw not in lowered
    assert "&lt;script&gt;" in message.html
    assert "&lt;img" in message.html
    assert "&lt;b onclick=&quot;x&quot;&gt;rule&lt;/b&gt;" in message.html
    assert "CNA: &lt;script&gt;.example" in message.html


def test_digest_html_escapes_rule_due_action_and_cna_source():
    item = event(
        "kev_added",
        cve_id="CVE-2026-0001",
        event_id=1,
        initial=True,
        rule="hostile rule",
        reasons=("kev cisa false -> true",),
        current=view(
            "CVE-2026-0001",
            source_identifier="security@<script>.example",
            cvss=(
                CVSSEntry(
                    "cna", "security@<script>.example", "3.1", 9.8
                ),
            ),
            cisa_kev_added="2026-11-03",
            cisa_kev_due='2026-11-20<script>alert("due")</script>',
            cisa_required_action='"><img src=x onerror="alert(1)">',
        ),
    )
    message = build_messages(
        (item,),
        channel_type="smtp",
        grouping="run",
        max_items=20,
        names={"hostile rule": '<b onclick="x">hostile rule</b>'},
        since="2026-10-27",
        language="en",
        format="html",
    )[0]
    lowered = message.html.lower()
    for raw in ("<script", "<img", "<b onclick"):
        assert raw not in lowered
    assert "&lt;script&gt;" in message.html
    assert "&lt;img" in message.html
    assert "&lt;b onclick=&quot;x&quot;&gt;hostile rule&lt;/b&gt;" in message.html
    assert "CNA: &lt;script&gt;.example" in message.html
