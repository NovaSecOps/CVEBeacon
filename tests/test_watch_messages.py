from __future__ import annotations

from typing import Any

import pytest

from cvebeacon.watch.messages import (
    DeliveryEvent,
    build_messages,
    split_message,
    webhook_payload,
)
from cvebeacon.watch.records import CVSSEntry, WatchView


def view(cve_id: str = "CVE-2026-1234", **overrides: Any) -> WatchView:
    values: dict[str, Any] = {
        "cve_id": cve_id,
        "status": "published",
        "description": "Acme Widget before 4.2.1 allows unauthenticated remote code execution.",
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
    )


def body_for(item: DeliveryEvent, channel: str = "slack") -> str:
    messages = build_messages(
        (item,),
        channel_type=channel,
        grouping="run",
        max_items=20,
        names={item.rule: item.rule},
        since="2026-10-27",
    )
    return messages[0].text


def test_match_line_follows_the_template():
    text = body_for(event())
    assert "[NEW] CVE-2026-1234" in text
    assert "CVSS 9.8 (CNA: acme.example), NVD pending" in text
    assert "EPSS 0.62" in text
    assert "KEV: CISA – EU –" in text
    assert "Exploitation: none" in text
    assert "Acme Widget before 4.2.1" in text
    assert "Rule: critical-or-likely" in text
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-1234" in text
    assert "https://www.cve.org/CVERecord?id=CVE-2026-1234" in text


def test_kev_added_label_and_detail():
    text = body_for(
        event(
            "kev_added",
            reasons=("kev cisa false -> true",),
            current=view(
                cisa_kev_added="2026-11-03",
                cisa_kev_due="2026-11-20",
                cisa_required_action="Apply the vendor update before the due date.",
            ),
        )
    )
    assert "[KEV ADDED: CISA]" in text
    assert "Due 2026-11-20" in text
    assert "Apply the vendor update before the due date." in text
    assert "KEV: CISA ✓ EU –" in text


@pytest.mark.parametrize(
    "kind,reasons,kwargs,expected",
    [
        ("exploitation_active", ("exploitation poc -> active (cisa-adp)",), {"ssvc_exploitation": "active"}, "[ACTIVELY EXPLOITED]"),
        ("severity_increase", ("severity high -> critical",), {}, "[SEVERITY UP high→critical]"),
        ("epss_increase", ("epss <0.1 -> <0.5",), {}, "[EPSS UP 0.08→0.61]"),
        ("nvd_score_added", ("nvd score absent -> present",), {"cvss": (CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.1),)}, "[NVD SCORED 9.1]"),
        ("rejected", ("status published -> rejected",), {"status": "rejected"}, "[REJECTED]"),
    ],
)
def test_kind_labels(kind, reasons, kwargs, expected):
    current = view(epss=0.61) if kind == "epss_increase" else view(**kwargs)
    details = {"previous_epss": 0.08} if kind == "epss_increase" else {}
    text = body_for(event(kind, reasons=reasons, current=current, details=details))
    assert expected in text


def test_score_labels_name_each_provider():
    current = view(
        cvss=(
            CVSSEntry("cna", "security@acme.example", "3.1", 9.8),
            CVSSEntry("nvd", "nvd@nist.gov", "3.1", 8.0),
            CVSSEntry("cisa-adp", "cisa@example.gov", "3.1", 7.5),
            CVSSEntry("euvd", "enisa", "3.1", 6.0),
            CVSSEntry("other", "someone", "3.1", 5.0),
        )
    )
    text = body_for(event(current=current))
    assert "CVSS 9.8 (CNA: acme.example)" in text
    assert "CVSS 8 (NVD)" in text
    assert "CVSS 7.5 (CISA-ADP)" in text
    assert "CVSS 6 (EUVD)" in text
    assert "CVSS 5 (Other)" in text
    assert "NVD pending" not in text


def test_nvd_pending_is_only_used_when_nvd_has_no_score():
    cna_only = body_for(event())
    assert "NVD pending" in cna_only
    unscored = body_for(event(current=view(cvss=())))
    assert "CVSS not scored" in unscored
    assert "NVD pending" not in unscored


def test_events_are_ordered_by_urgency_then_score_then_epss():
    kev = event(
        "match",
        cve_id="CVE-2026-0001",
        current=view("CVE-2026-0001", cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 1.0),), epss=0.01, cisa_kev_added="2026-11-03"),
        event_id=1,
    )
    high = event(
        "match",
        cve_id="CVE-2026-0002",
        current=view("CVE-2026-0002", cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8),), epss=0.01),
        event_id=2,
    )
    low = event(
        "match",
        cve_id="CVE-2026-0003",
        current=view("CVE-2026-0003", cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 4.0),), epss=0.9),
        event_id=3,
    )
    text = body_for_message_tuple((low, high, kev))
    assert text.index("CVE-2026-0001") < text.index("CVE-2026-0002") < text.index("CVE-2026-0003")


def body_for_message_tuple(events):
    return build_messages(
        events,
        channel_type="slack",
        grouping="run",
        max_items=20,
        names={"critical-or-likely": "critical-or-likely"},
    )[0].text


def test_subject_uses_counts_and_rule():
    events = (
        event("match", cve_id="CVE-2026-0001", event_id=1),
        event("match", cve_id="CVE-2026-0002", event_id=2),
        event("match", cve_id="CVE-2026-0003", event_id=3),
        event("kev_added", cve_id="CVE-2026-0004", event_id=4, reasons=("kev cisa false -> true",), current=view("CVE-2026-0004", cisa_kev_added="2026-11-03")),
    )
    message = build_messages(
        events,
        channel_type="slack",
        grouping="run",
        max_items=20,
        names={"critical-or-likely": "critical-or-likely"},
    )[0]
    assert message.subject == "CVEBeacon: 3 new, 1 KEV added (critical-or-likely)"


def test_event_grouping_uses_an_event_subject():
    item = event("kev_added", reasons=("kev cisa false -> true",), current=view(cisa_kev_added="2026-11-03"))
    message = build_messages(
        (item,),
        channel_type="slack",
        grouping="event",
        max_items=20,
        names={item.rule: item.rule},
    )[0]
    assert message.subject == "CVEBeacon: [KEV ADDED: CISA] CVE-2026-1234"


def test_max_items_adds_a_remainder_line():
    events = tuple(
        event("match", cve_id=f"CVE-2026-{index:04d}", event_id=index)
        for index in range(1, 6)
    )
    text = build_messages(
        events,
        channel_type="slack",
        grouping="run",
        max_items=2,
        names={"critical-or-likely": "critical-or-likely"},
    )[0].text
    assert "and 3 more" in text
    assert text.count("[NEW]") == 2


def test_initial_events_become_one_digest():
    initial = (
        event("match", cve_id="CVE-2026-0001", event_id=1, initial=True, rule="first"),
        event("match", cve_id="CVE-2026-0002", event_id=2, initial=True, rule="second"),
        event("kev_added", cve_id="CVE-2026-0003", event_id=3, initial=True, rule="second", reasons=("kev cisa false -> true",), current=view("CVE-2026-0003", cisa_kev_added="2026-11-03")),
    )
    messages = build_messages(
        initial,
        channel_type="slack",
        grouping="event",
        max_items=20,
        names={"first": "first", "second": "second"},
        since="2026-10-27",
    )
    assert len(messages) == 1
    message = messages[0]
    assert message.initial is True
    assert message.subject == "CVEBeacon initial summary: 2 matches across 2 rules since 2026-10-27"
    assert "first: 1 match" in message.text
    assert "second: 1 match, 1 KEV added" in message.text
    assert "Run `cvebeacon watch events --rule X` to list all." in message.text
    assert len(message.event_ids) == 3


def test_initial_and_normal_events_are_separate_messages():
    events = (
        event("match", cve_id="CVE-2026-0001", event_id=1, initial=True),
        event("kev_added", cve_id="CVE-2026-0002", event_id=2, reasons=("kev cisa false -> true",), current=view("CVE-2026-0002", cisa_kev_added="2026-11-03")),
    )
    messages = build_messages(
        events,
        channel_type="slack",
        grouping="run",
        max_items=20,
        names={"critical-or-likely": "critical-or-likely"},
        since="2026-10-27",
    )
    assert len(messages) == 2
    assert messages[0].initial is True
    assert messages[1].initial is False


def test_description_is_cut_to_160_characters():
    long = "word " * 200
    text = body_for(event(current=view(description=long)))
    description = [line for line in text.splitlines() if line.startswith("  word")][0]
    assert len(description.strip()) <= 160
    assert description.strip().endswith("…")


def test_links_include_euvd_and_kev_catalog():
    text = body_for(event(current=view(euvd_id="EUVD-2026-1234", cisa_kev_added="2026-11-03")))
    assert "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-1234" in text
    assert "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" in text


def test_split_message_never_breaks_a_line():
    lines = [f"line {index:03d} " + "x" * 40 for index in range(20)]
    parts = split_message("\n".join(lines), 100)
    assert len(parts) > 1
    assert all(len(part) <= 100 for part in parts)
    rebuilt = []
    for part in parts:
        assert part.startswith("[")
        _, _, body = part.partition("] ")
        rebuilt.extend(body.splitlines())
    assert rebuilt == lines


def test_long_messages_split_within_provider_limits():
    events = tuple(
        event(
            "match",
            cve_id=f"CVE-2026-{index:04d}",
            event_id=index,
            current=view(
                f"CVE-2026-{index:04d}",
                description=("A long vulnerability description " * 20),
            ),
        )
        for index in range(1, 101)
    )
    for channel, limit in (("discord", 2000), ("telegram", 4096), ("slack", 3800)):
        messages = build_messages(
            events,
            channel_type=channel,
            grouping="run",
            max_items=100,
            names={"critical-or-likely": "critical-or-likely"},
        )
        assert len(messages) <= 10
        assert all(len(message.text) <= limit for message in messages)


def test_discord_escapes_mentions_and_markdown():
    item = event(
        current=view(
            description="@everyone *bold* _italic_ `code` ~~strike~~ <tag>",
            source_identifier="@channel",
        )
    )
    text = body_for(item, "discord")
    assert "\\@everyone" in text
    assert "\\*bold\\*" in text
    assert "\\_italic\\_" in text
    assert "\\`code\\`" in text
    assert "\\~\\~strike\\~\\~" in text


def test_plain_slack_and_markdown_styles_differ():
    item = event()
    slack = body_for(item, "slack")
    teams = body_for(item, "teams")
    assert slack.startswith("*CVEBeacon:")
    assert teams.startswith("**CVEBeacon:")
    assert "<https://nvd.nist.gov" in slack
    assert "[NVD](https://nvd.nist.gov" in teams


def test_webhook_payload_is_stable_and_descriptive():
    item = event(
        current=view(
            euvd_id="EUVD-2026-1234",
            cisa_kev_added="2026-11-03",
            cisa_kev_due="2026-11-20",
            cisa_required_action="Patch",
            epss_percentile=0.91,
            epss_date="2026-11-03",
            vendors=("Acme",),
            products=("Widget",),
        )
    )
    payload = webhook_payload((item,), {item.rule: "critical-or-likely"})
    assert payload["version"] == 1
    entry = payload["events"][0]
    assert entry["rule"] == "critical-or-likely"
    assert entry["cve_id"] == "CVE-2026-1234"
    assert entry["kind"] == "match"
    assert entry["reasons"] == ["cvss 9.8 v3.1 (cna)"]
    assert entry["initial"] is False
    assert entry["created_at"].startswith("2026-11-03")
    view_payload = entry["view"]
    assert view_payload["cvss"][0]["provider"] == "cna"
    assert view_payload["kev"]["cisa"]["due"] == "2026-11-20"
    assert view_payload["epss"]["percentile"] == 0.91
    assert view_payload["vendors"] == ["Acme"]
    assert view_payload["products"] == ["Widget"]
    assert view_payload["links"]["euvd"].endswith("EUVD-2026-1234")
