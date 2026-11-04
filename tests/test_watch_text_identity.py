from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cvebeacon.watch.messages import build_messages, test_message as localized_test_message
from cvebeacon.watch.records import (
    CVSSEntry,
    DeliveryEvent,
    InitialDigest,
    ReportedMark,
    WatchView,
)

FIXTURE = Path(__file__).parent / "fixtures" / "watch_text_identity.json"
CHANNELS = (
    "smtp",
    "graph",
    "teams",
    "slack",
    "discord",
    "telegram",
    "matrix",
    "ntfy",
    "gotify",
    "webhook",
)
CASES = ("normal", "normal_event", "notices", "digest")


def view(cve_id: str = "CVE-2026-1234", **overrides: Any) -> WatchView:
    values: dict[str, Any] = {
        "cve_id": cve_id,
        "status": "published",
        "published": "2026-10-30T14:00:00.000",
        "first_seen": "2026-11-04T09:15:00+00:00",
        "description": "Acme Widget before 4.2.1 allows remote code execution.",
        "source_identifier": "security@acme.example",
        "cvss": (CVSSEntry("cna", "security@acme.example", "3.1", 9.8),),
        "epss": 0.62,
        "euvd_id": "EUVD-2026-1234",
        "cisa_kev_added": "2026-11-03",
        "cisa_kev_due": "2026-11-20",
        "cisa_required_action": "Apply the vendor update.",
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
):
    from cvebeacon.watch.records import DeliveryEvent

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


def inputs(case: str) -> tuple[tuple, dict[str, str], str | None, str]:
    if case == "normal":
        return (
            (event(),),
            {"critical-or-likely": "critical-or-likely"},
            None,
            "run",
        )
    if case == "normal_event":
        return (
            (event(),),
            {"critical-or-likely": "critical-or-likely"},
            None,
            "event",
        )
    if case == "notices":
        return (
            (
                event(
                    "reported",
                    event_id=1,
                    details={
                        "by": "alice",
                        "note": "Sent in ticket OPS-42",
                    },
                ),
                event(
                    "unreported",
                    event_id=2,
                    details={"by": "alice", "note": "Sent in error"},
                ),
            ),
            {"critical-or-likely": "critical-or-likely"},
            None,
            "run",
        )
    if case == "digest":
        return (
            (
                event(
                    "match",
                    cve_id="CVE-2026-0001",
                    event_id=1,
                    initial=True,
                    rule="SOC  rule",
                ),
                event(
                    "kev_added",
                    cve_id="CVE-2026-0001",
                    event_id=2,
                    initial=True,
                    rule="SOC  rule",
                    reasons=("kev cisa false -> true",),
                ),
                event(
                    "match",
                    cve_id="CVE-2026-0002",
                    event_id=3,
                    initial=True,
                    rule="soc_rule",
                ),
            ),
            {"SOC  rule": "SOC  rule", "soc_rule": "soc_rule"},
            "2026-10-27",
            "run",
        )
    raise AssertionError(case)


def rendered(case: str, channel: str, **kwargs: Any) -> list[dict[str, Any]]:
    events, names, since, grouping = inputs(case)
    messages = build_messages(
        events,
        channel_type=channel,
        grouping=grouping,
        max_items=20,
        names=names,
        since=since,
        **kwargs,
    )
    return [
        {
            "subject": message.subject,
            "text": message.text,
            "body": message.body,
            "content": message.content,
            "initial": message.initial,
            "part_index": message.part_index,
            "part_count": message.part_count,
        }
        for message in messages
    ]


def large_slack_messages() -> list[dict[str, Any]]:
    names = [f"rule-{index:04d}-" + "x" * 50 for index in range(1, 501)]
    item = DeliveryEvent(
        1,
        names[0],
        "CVE-2026-1234",
        "match",
        ("cvss 9.8 v3.1 (cna)",),
        True,
        "2026-11-03T12:00:00+00:00",
        view(),
    )
    digest = InitialDigest(
        (item,),
        tuple((name, "match", 1) for name in names),
        1,
        500,
    )
    messages = build_messages(
        (),
        channel_type="slack",
        grouping="run",
        max_items=20,
        names={name: name for name in names},
        since="2026-10-27",
        initial=digest,
    )
    return [
        {
            "subject": message.subject,
            "text": message.text,
            "body": message.body,
            "content": message.content,
            "initial": message.initial,
            "part_index": message.part_index,
            "part_count": message.part_count,
        }
        for message in messages
    ]


@pytest.fixture(scope="module")
def frozen() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("channel", CHANNELS)
def test_default_english_text_is_frozen(frozen, case, channel):
    expected = frozen["cases"][case][channel]
    assert rendered(case, channel) == expected
    assert rendered(case, channel, format="text", language="en") == expected


def test_large_fixed_text_summary_is_frozen(frozen):
    expected = frozen["cases"]["large_slack"]["slack"]
    actual = large_slack_messages()
    assert actual == expected
    assert actual[0]["part_count"] == 10
    assert len(actual[0]["body"]) == 35_054


def test_test_message_is_frozen(frozen):
    expected = frozen["test_message"]
    assert localized_test_message("en") == (
        expected["subject"],
        expected["body"],
    )
