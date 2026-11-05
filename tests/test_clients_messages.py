from __future__ import annotations

import html as html_module
import json
import re
from typing import Any

import pytest

from cvebeacon.clients import ClientImpact
from cvebeacon.watch.messages import (
    CHANNEL_LIMITS,
    DeliveryEvent,
    build_messages,
    webhook_payload,
)
from cvebeacon.watch.records import CVSSEntry, WatchView

CHANNELS = tuple(name for name in CHANNEL_LIMITS if name != "webhook")
EMAIL = {"smtp", "graph"}


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
    }
    values.update(overrides)
    return WatchView(**values)


def event(
    *,
    cve_id: str = "CVE-2026-1234",
    initial: bool = False,
    event_id: int = 1,
    rule: str = "critical-or-likely",
) -> DeliveryEvent:
    return DeliveryEvent(
        event_id,
        rule,
        cve_id,
        "match",
        ("cvss 9.8 v3.1 (cna)",),
        initial,
        "2026-11-03T12:00:00+00:00",
        view(cve_id),
    )


IMPACTS = {
    "CVE-2026-1234": (
        ClientImpact("Acme", 2, "affected"),
        ClientImpact("Globex", 1, "needs_review"),
        ClientImpact("Initech", 1, "affected"),
    )
}


def render(item: DeliveryEvent, channel: str, **kwargs: Any):
    kwargs.setdefault("names", {item.rule: item.rule})
    kwargs.setdefault("max_items", 20)
    return build_messages(
        (item,),
        channel_type=channel,
        grouping="run",
        **kwargs,
    )


def text_for(item: DeliveryEvent, channel: str, **kwargs: Any) -> str:
    message = render(item, channel, **kwargs)[0]
    return message.body if channel in EMAIL else message.text


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize(
    ("language", "expected"),
    (
        ("en", "Affected clients: Acme, Globex (review), Initech"),
        ("pt-PT", "Clientes afetados: Acme, Globex (revisão), Initech"),
    ),
)
def test_every_channel_shows_the_affected_clients_line(
    channel, language, expected
):
    if channel == "slack":
        expected = (
            "Affected clients: `Acme`, `Globex (review)`, `Initech`"
            if language == "en"
            else "Clientes afetados: `Acme`, `Globex (revisão)`, `Initech`"
        )
    text = text_for(event(), channel, language=language, clients=IMPACTS)
    assert expected in text


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("language", ("en", "pt-PT"))
def test_no_clients_keeps_the_message_byte_identical(channel, language):
    item = event()
    baseline = render(item, channel, language=language)
    with_empty = render(item, channel, language=language, clients={})
    assert with_empty == baseline
    text = text_for(item, channel, language=language, clients={})
    assert "Affected clients:" not in text
    assert "Clientes afetados:" not in text


def test_initial_digest_shows_the_affected_clients_line():
    item = event(initial=True)
    message = render(item, "slack", clients=IMPACTS, since="2026-10-27")[0]
    assert message.initial is True
    assert "Affected clients: `Acme`, `Globex (review)`, `Initech`" in message.text


def test_html_email_shows_the_affected_clients_line():
    message = render(
        event(), "smtp", format="html", clients=IMPACTS, language="pt-PT"
    )[0]
    visible = re.sub(
        r"\s+",
        " ",
        html_module.unescape(re.sub(r"<[^>]+>", " ", message.html)),
    )
    assert "Clientes afetados: Acme, Globex (revisão), Initech" in visible


def test_the_clients_line_is_bounded():
    impacts = tuple(
        ClientImpact(f"Client {index:02d} " + "x" * 100, 1, "affected")
        for index in range(1, 51)
    )
    text = text_for(
        event(), "discord", clients={"CVE-2026-1234": impacts}
    )
    assert "Client 10" in text
    assert "Client 11" not in text
    assert "and 40 more" in text


@pytest.mark.parametrize("channel", CHANNELS)
def test_parts_respect_each_channel_limit(channel):
    impacts = tuple(
        ClientImpact(f"Client {index:02d} " + "x" * 100, 1, "affected")
        for index in range(1, 51)
    )
    messages = render(
        event(), channel, clients={"CVE-2026-1234": impacts}
    )
    limit = CHANNEL_LIMITS[channel]
    byte_limit = channel in {"ntfy", "matrix", "teams"}
    for message in messages:
        size = (
            len(message.text.encode("utf-8"))
            if byte_limit
            else len(message.text)
        )
        assert size <= limit


def test_slack_and_discord_escape_client_names():
    impacts = {
        "CVE-2026-1234": (ClientImpact("<Acme & Co>", 1, "affected"),)
    }
    slack = text_for(event(), "slack", clients=impacts)
    assert "`&lt;Acme &amp; Co&gt;`" in slack
    discord = text_for(event(), "discord", clients=impacts)
    assert "<Acme & Co\\>" in discord


def test_teams_and_html_escape_client_names():
    impacts = {
        "CVE-2026-1234": (ClientImpact("<Acme & Co>", 1, "affected"),)
    }
    teams = text_for(event(), "teams", clients=impacts)
    assert "&lt;Acme &amp; Co&gt;" in teams
    assert "<Acme & Co>" not in teams
    message = render(event(), "smtp", format="html", clients=impacts)[0]
    visible = re.sub(r"<[^>]+>", " ", message.html)
    assert "&lt;Acme &amp; Co&gt;" in visible
    assert "<Acme & Co>" not in visible


def test_slack_backtick_cannot_open_a_code_span():
    impacts = {
        "CVE-2026-1234": (ClientImpact("Acme` *Group*", 1, "affected"),)
    }
    slack = text_for(event(), "slack", clients=impacts)
    assert "`Acme\u02cb *Group*`" in slack
    assert "*Group*" in slack


def test_webhook_document_lists_affected_clients():
    payload = webhook_payload(
        (event(),),
        {"critical-or-likely": "critical-or-likely"},
        IMPACTS,
    )
    assert payload["version"] == 2
    assert payload["events"][0]["affected_clients"] == [
        {"name": "Acme", "assets": 2, "status": "affected"},
        {"name": "Globex", "assets": 1, "status": "needs_review"},
        {"name": "Initech", "assets": 1, "status": "affected"},
    ]


def test_webhook_client_list_is_bounded_with_a_count():
    impacts = {
        "CVE-2026-1234": tuple(
            ClientImpact(f"Client {index:03d}", 1, "affected")
            for index in range(1000)
        )
    }
    payload = webhook_payload(
        (event(),),
        {"critical-or-likely": "critical-or-likely"},
        impacts,
    )
    entry = payload["events"][0]
    assert len(entry["affected_clients"]) == 50
    assert entry["affected_clients_omitted"] == 950
    assert len(json.dumps(entry).encode("utf-8")) < 32_768


def test_webhook_document_without_clients_is_unchanged():
    item = event()
    names = {"critical-or-likely": "critical-or-likely"}
    baseline = webhook_payload((item,), names)
    assert webhook_payload((item,), names, {}) == baseline
    assert "affected_clients" not in baseline["events"][0]
