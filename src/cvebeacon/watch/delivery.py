"""Reliable delivery of watch alert messages to configured channels."""

from __future__ import annotations

import hashlib
import json
import smtplib
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import quote

import httpx

from ..config import AppConfig
from ..errors import ConfigurationError
from ..http import HttpClient, HttpResult
from .channels import ChannelConfig, channel_map
from .messages import (
    OutgoingMessage,
    build_messages,
    rule_display_names,
    webhook_payload,
)
from .records import DeliveryEvent
from .store import WatchStore

DELIVERY_BUDGET_SECONDS = 60.0
MAX_MESSAGES_PER_CHANNEL = 10
TEST_MESSAGE = "CVEBeacon test message — no action needed"


class DeliveryFailure(Exception):
    """A channel did not accept a message.

    ``ambiguous`` means the request or SMTP DATA may have reached the provider.
    """

    def __init__(self, category: str, *, ambiguous: bool = False) -> None:
        self.category = category
        self.ambiguous = ambiguous
        super().__init__(category)


@dataclass(frozen=True, slots=True)
class ChannelSummary:
    channel: str
    type: str
    messages: int = 0
    events: int = 0
    failed: int = 0
    ambiguous: int = 0
    ambiguous_total: int = 0
    error: str | None = None
    skipped: bool = False

    @property
    def ok(self) -> bool:
        return not self.failed and not self.ambiguous and self.error is None


@dataclass(frozen=True, slots=True)
class DeliveryReport:
    channels: tuple[ChannelSummary, ...] = ()
    recovered: int = 0

    @property
    def failed(self) -> bool:
        return self.recovered > 0 or any(not channel.ok for channel in self.channels)


@dataclass(frozen=True, slots=True)
class TestOutcome:
    channel: str
    type: str
    ok: bool
    error: str | None = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_channel_line(summary: ChannelSummary) -> str:
    messages = f"{summary.messages} message{'' if summary.messages == 1 else 's'}"
    events = f"{summary.events} event{'' if summary.events == 1 else 's'}"
    line = f"{summary.channel} ({summary.type}): {messages}, {events} sent"
    if summary.failed:
        line += f"; {summary.failed} failed"
    ambiguous = summary.ambiguous_total or summary.ambiguous
    if ambiguous:
        line += f"; {ambiguous} ambiguous"
    if summary.error:
        line += f"; {summary.error}"
    return line


def _http_call(
    http: HttpClient,
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    json_body: Any = None,
    data: Mapping[str, Any] | None = None,
    content: bytes | str | None = None,
    timeout: float,
) -> HttpResult:
    try:
        return http.request_once(
            method,
            url,
            headers=headers,
            json=json_body,
            data=data,
            content=content,
            timeout=timeout,
        )
    except (
        httpx.ConnectError,
        httpx.ConnectTimeout,
        httpx.PoolTimeout,
        httpx.UnsupportedProtocol,
    ):
        raise DeliveryFailure("connection failed") from None
    except (httpx.TimeoutException, httpx.TransportError):
        raise DeliveryFailure("connection interrupted", ambiguous=True) from None
    except ValueError:
        raise DeliveryFailure("invalid request") from None
    except Exception:
        # Unknown third-party transport failures may follow a partial send.
        raise DeliveryFailure("request failed", ambiguous=True) from None


def _json_body(result: HttpResult) -> Any:
    try:
        return json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError):
        return None


def _accepted(result: HttpResult, expected: Iterable[int], category: str) -> None:
    if result.status_code not in set(expected):
        raise DeliveryFailure(f"{category}: HTTP {result.status_code}")


def _secret(channel: ChannelConfig, key: str) -> str:
    reference = channel.secret(key)
    if reference is None:
        raise DeliveryFailure("missing secret")
    try:
        return reference.resolve()
    except ConfigurationError as exc:
        raise DeliveryFailure(str(exc)) from None


def _send_webhook_channel(
    channel: ChannelConfig, message: OutgoingMessage, http: HttpClient, timeout: float
) -> None:
    url = _secret(channel, "webhook_url")
    if channel.type == "teams":
        body = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "wrap": True, "text": message.text}
                        ],
                    },
                }
            ],
        }
        result = _http_call(http, "POST", url, json_body=body, timeout=timeout)
        _accepted(result, (200, 202), "Teams rejected the message")
        return
    if channel.type == "slack":
        result = _http_call(
            http, "POST", url, json_body={"text": message.text}, timeout=timeout
        )
        _accepted(result, (200,), "Slack rejected the message")
        return
    if channel.type == "discord":
        separator = "&" if "?" in url else "?"
        result = _http_call(
            http,
            "POST",
            url + separator + "wait=true",
            json_body={
                "content": message.text,
                "allowed_mentions": {"parse": []},
                "tts": False,
            },
            timeout=timeout,
        )
        _accepted(result, (200, 204), "Discord rejected the message")
        return
    raise DeliveryFailure("unsupported webhook channel")


def _send_telegram(
    channel: ChannelConfig, message: OutgoingMessage, http: HttpClient, timeout: float
) -> None:
    token = _secret(channel, "bot_token")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    result = _http_call(
        http,
        "POST",
        url,
        json_body={
            "chat_id": channel.options["chat_id"],
            "text": message.text,
            "disable_web_page_preview": True,
        },
        timeout=timeout,
    )
    if result.status_code != 200:
        raise DeliveryFailure(f"Telegram rejected the message: HTTP {result.status_code}")
    body = _json_body(result)
    if not isinstance(body, dict) or body.get("ok") is not True:
        raise DeliveryFailure("Telegram rejected the message")


def _send_matrix(
    channel: ChannelConfig, message: OutgoingMessage, http: HttpClient, timeout: float
) -> None:
    token = _secret(channel, "access_token")
    homeserver = str(channel.options["homeserver"])
    room = quote(str(channel.options["room_id"]), safe="")
    headers = {"Authorization": f"Bearer {token}"}
    state_url = (
        f"{homeserver}/_matrix/client/v3/rooms/{room}/state/m.room.encryption"
    )
    try:
        state = http.request_once(
            "GET", state_url, headers=headers, timeout=timeout
        )
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.UnsupportedProtocol):
        raise DeliveryFailure("Matrix encryption check failed") from None
    except (httpx.TimeoutException, httpx.TransportError):
        raise DeliveryFailure("Matrix encryption check failed") from None
    except Exception:
        raise DeliveryFailure("Matrix encryption check failed") from None
    if state.status_code == 200:
        raise DeliveryFailure("Matrix encrypted rooms are not supported")
    if state.status_code == 404:
        body = _json_body(state)
        if not isinstance(body, dict) or body.get("errcode") != "M_NOT_FOUND":
            raise DeliveryFailure("Matrix encryption state is unknown")
    else:
        raise DeliveryFailure(
            f"Matrix encryption check failed: HTTP {state.status_code}"
        )
    transaction = hashlib.sha256(
        (
            "cvebeacon:"
            + channel.name
            + ":"
            + ",".join(str(value) for value in message.event_ids)
        ).encode("utf-8")
    ).hexdigest()[:32]
    send_url = (
        f"{homeserver}/_matrix/client/v3/rooms/{room}/send/"
        f"m.room.message/{transaction}"
    )
    result = _http_call(
        http,
        "PUT",
        send_url,
        headers=headers,
        json_body={
            "msgtype": "m.text",
            "body": message.text,
            "m.mentions": {},
        },
        timeout=timeout,
    )
    if result.status_code != 200:
        raise DeliveryFailure(f"Matrix rejected the message: HTTP {result.status_code}")
    body = _json_body(result)
    if not isinstance(body, dict) or not isinstance(body.get("event_id"), str):
        raise DeliveryFailure("Matrix rejected the message")


def _send_ntfy(
    channel: ChannelConfig, message: OutgoingMessage, http: HttpClient, timeout: float
) -> None:
    token = channel.secret("token")
    headers = {
        "Title": message.subject.encode("ascii", "replace").decode("ascii"),
        "Priority": str(channel.options["priority"]),
    }
    if token is not None:
        try:
            headers["Authorization"] = "Bearer " + token.resolve()
        except ConfigurationError as exc:
            raise DeliveryFailure(str(exc)) from None
    url = f"{channel.options['server']}/{channel.options['topic']}"
    result = _http_call(
        http,
        "POST",
        url,
        headers=headers,
        content=message.text.encode("utf-8"),
        timeout=timeout,
    )
    _accepted(result, (200,), "ntfy rejected the message")


def _send_gotify(
    channel: ChannelConfig, message: OutgoingMessage, http: HttpClient, timeout: float
) -> None:
    token = _secret(channel, "app_token")
    result = _http_call(
        http,
        "POST",
        f"{channel.options['server']}/message",
        headers={"X-Gotify-Key": token},
        json_body={
            "title": message.subject,
            "message": message.text,
            "priority": channel.options["priority"],
        },
        timeout=timeout,
    )
    _accepted(result, (200,), "Gotify rejected the message")


def _send_webhook(
    channel: ChannelConfig,
    events: Sequence[DeliveryEvent],
    http: HttpClient,
    timeout: float,
    names: Mapping[str, str],
) -> None:
    headers: dict[str, str] = {}
    header_name = channel.options.get("header_name")
    if header_name:
        headers[str(header_name)] = _secret(channel, "header_value")
    result = _http_call(
        http,
        "POST",
        str(channel.options["url"]),
        headers=headers,
        json_body=webhook_payload(events, names),
        timeout=timeout,
    )
    if not 200 <= result.status_code < 300:
        raise DeliveryFailure(f"webhook rejected the message: HTTP {result.status_code}")


def _email_message(
    channel: ChannelConfig, message: OutgoingMessage
) -> EmailMessage:
    email = EmailMessage()
    email["Subject"] = message.subject
    email["From"] = str(channel.options["sender"])
    email["To"] = ", ".join(channel.options["to"])
    cc = channel.options.get("cc") or ()
    if cc:
        email["Cc"] = ", ".join(cc)
    email["Date"] = formatdate(localtime=False)
    domain = str(channel.options["sender"]).rsplit("@", 1)[-1]
    email["Message-ID"] = make_msgid(domain=domain or None)
    email.set_content(message.body)
    return email


def _smtp_client(channel: ChannelConfig, timeout: float):
    security = str(channel.options["security"])
    context = ssl.create_default_context()
    host = str(channel.options["host"])
    port = int(channel.options["port"])
    if security == "tls":
        return smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    return smtplib.SMTP(host, port, timeout=timeout)


def _send_smtp(
    channel: ChannelConfig, message: OutgoingMessage, timeout: float
) -> None:
    security = str(channel.options["security"])
    try:
        client = _smtp_client(channel, timeout)
    except (OSError, ssl.SSLError, smtplib.SMTPException):
        raise DeliveryFailure("SMTP connection failed") from None
    try:
        try:
            client.ehlo()
            if security == "starttls":
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            username = channel.options.get("username")
            if username:
                password = _secret(channel, "password")
                client.login(str(username), password)
        except smtplib.SMTPAuthenticationError:
            raise DeliveryFailure("SMTP authentication failed") from None
        except (OSError, ssl.SSLError, smtplib.SMTPException):
            raise DeliveryFailure("SMTP session failed") from None
        try:
            refused = client.send_message(_email_message(channel, message))
        except (
            smtplib.SMTPRecipientsRefused,
            smtplib.SMTPSenderRefused,
            smtplib.SMTPDataError,
            smtplib.SMTPNotSupportedError,
            smtplib.SMTPHeloError,
        ):
            raise DeliveryFailure("SMTP rejected the message") from None
        except (OSError, ssl.SSLError, smtplib.SMTPException, TimeoutError):
            raise DeliveryFailure("SMTP outcome unknown", ambiguous=True) from None
        if refused:
            raise DeliveryFailure(
                "SMTP refused some recipients", ambiguous=True
            )
    finally:
        try:
            client.quit()
        except (OSError, smtplib.SMTPException):
            try:
                client.close()
            except OSError:
                pass


def _graph_token(channel: ChannelConfig, http: HttpClient, timeout: float) -> str:
    tenant = quote(str(channel.options["tenant_id"]), safe="")
    secret = _secret(channel, "client_secret")
    result = _http_call(
        http,
        "POST",
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={
            "client_id": channel.options["client_id"],
            "client_secret": secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=timeout,
    )
    if result.status_code != 200:
        raise DeliveryFailure(f"Graph token request failed: HTTP {result.status_code}")
    body = _json_body(result)
    token = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        raise DeliveryFailure("Graph token response did not contain an access token")
    return token


def _send_graph(
    channel: ChannelConfig, message: OutgoingMessage, http: HttpClient, timeout: float
) -> None:
    try:
        token = _graph_token(channel, http, timeout)
    except DeliveryFailure as exc:
        # No mail has been sent yet, even if the token request was interrupted.
        raise DeliveryFailure(exc.category) from None
    recipients = [
        {"emailAddress": {"address": address}}
        for address in channel.options["to"]
    ]
    message_body: dict[str, Any] = {
        "subject": message.subject,
        "body": {"contentType": "Text", "content": message.body},
        "toRecipients": recipients,
    }
    cc = channel.options.get("cc") or ()
    if cc:
        message_body["ccRecipients"] = [
            {"emailAddress": {"address": address}} for address in cc
        ]
    sender = quote(str(channel.options["sender"]), safe="")
    result = _http_call(
        http,
        "POST",
        f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail",
        headers={"Authorization": f"Bearer {token}"},
        json_body={"message": message_body, "saveToSentItems": False},
        timeout=timeout,
    )
    _accepted(result, (202,), "Graph mail rejected the message")


def _send(
    channel: ChannelConfig,
    message: OutgoingMessage,
    events: Sequence[DeliveryEvent],
    http: HttpClient,
    timeout: float,
    names: Mapping[str, str],
) -> None:
    if channel.type in {"teams", "slack", "discord"}:
        _send_webhook_channel(channel, message, http, timeout)
    elif channel.type == "telegram":
        _send_telegram(channel, message, http, timeout)
    elif channel.type == "matrix":
        _send_matrix(channel, message, http, timeout)
    elif channel.type == "ntfy":
        _send_ntfy(channel, message, http, timeout)
    elif channel.type == "gotify":
        _send_gotify(channel, message, http, timeout)
    elif channel.type == "webhook":
        _send_webhook(channel, events, http, timeout, names)
    elif channel.type == "graph":
        _send_graph(channel, message, http, timeout)
    elif channel.type == "smtp":
        _send_smtp(channel, message, timeout)
    else:
        raise DeliveryFailure("unsupported channel type")


def _group_messages(
    messages: Sequence[OutgoingMessage],
) -> list[list[OutgoingMessage]]:
    groups: list[list[OutgoingMessage]] = []
    for message in messages:
        if groups and groups[-1][0].event_ids == message.event_ids:
            groups[-1].append(message)
        else:
            groups.append([message])
    return groups


def _event_index(events: Sequence[DeliveryEvent]) -> dict[int, DeliveryEvent]:
    return {event.event_id: event for event in events}


def _channel_messages(
    channel: ChannelConfig,
    events: Sequence[DeliveryEvent],
    *,
    names: Mapping[str, str],
    since: str | None,
) -> tuple[OutgoingMessage, ...]:
    return build_messages(
        events,
        channel_type=channel.type,
        grouping=channel.grouping,
        max_items=channel.max_items,
        names=names,
        since=since,
    )


def deliver_pending(
    config: AppConfig,
    store: WatchStore,
    http: HttpClient,
    *,
    channel_names: Iterable[str] | None = None,
    retry_ambiguous: bool = False,
    clock: Callable[[], datetime] = _utc_now,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
    budget_seconds: float = DELIVERY_BUDGET_SECONDS,
) -> DeliveryReport:
    if monotonic is None:
        monotonic = time.monotonic
    if sleep is None:
        sleep = time.sleep
    selected_names = set(channel_names) if channel_names is not None else None
    channels = tuple(
        channel
        for channel in config.watch.channels
        if selected_names is None or channel.name in selected_names
    )
    if selected_names is not None:
        missing = sorted(selected_names - {channel.name for channel in channels})
        if missing:
            raise ConfigurationError(
                "unknown watch channel: " + ", ".join(missing)
            )
    store.initialize()
    recovered = store.recover_sending()
    started = monotonic()
    deadline = started + max(1.0, budget_seconds)
    names = rule_display_names(config.watch.rules)
    metadata = store.metadata()
    since = (
        metadata.get("initial_window_start")
        or metadata.get("initialized_at")
        or ""
    )[:10] or None
    summaries: list[ChannelSummary] = []
    for channel in channels:
        if not channel.enabled:
            summaries.append(
                ChannelSummary(channel.name, channel.type, skipped=True)
            )
            continue
        now = clock()
        include_ambiguous = retry_ambiguous or channel.type == "matrix"
        events = store.delivery_events(
            channel.name,
            catalogs=config.watch.sources,
            now=now,
            include_ambiguous=include_ambiguous,
        )
        if not events:
            summaries.append(ChannelSummary(channel.name, channel.type))
            continue
        batches: list[tuple[DeliveryEvent, ...]] = []
        if include_ambiguous:
            ambiguous_events = tuple(
                event for event in events if event.status == "ambiguous"
            )
            other_events = tuple(
                event for event in events if event.status != "ambiguous"
            )
            if ambiguous_events:
                batches.append(ambiguous_events)
            if other_events:
                batches.append(other_events)
        else:
            batches.append(tuple(events))
        messages_sent = 0
        events_sent = 0
        failed = 0
        ambiguous = 0
        error: str | None = None
        pace_needed = False
        stop_channel = False
        for batch in batches:
            index = _event_index(batch)
            for group in _group_messages(
                _channel_messages(channel, batch, names=names, since=since)
            ):
                if stop_channel or messages_sent >= MAX_MESSAGES_PER_CHANNEL:
                    stop_channel = True
                    break
                if messages_sent + len(group) > MAX_MESSAGES_PER_CHANNEL:
                    break
                if monotonic() >= deadline:
                    break
                interval = channel.min_interval_seconds
                if pace_needed and interval > 0:
                    remaining = deadline - monotonic()
                    if interval > remaining:
                        break
                    sleep(interval)
                event_ids = group[0].event_ids
                covered = [index[value] for value in event_ids if value in index]
                if not covered:
                    continue
                store.mark_delivery(event_ids, channel.name, "sending")
                delivered = 0
                failure: DeliveryFailure | None = None
                for message in group:
                    if pace_needed and interval > 0:
                        remaining = deadline - monotonic()
                        if interval > remaining:
                            failure = DeliveryFailure(
                                "delivery budget exhausted", ambiguous=delivered > 0
                            )
                            break
                        sleep(interval)
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        failure = DeliveryFailure(
                            "delivery budget exhausted", ambiguous=delivered > 0
                        )
                        break
                    timeout = max(0.5, min(channel.timeout_seconds, remaining))
                    try:
                        _send(channel, message, covered, http, timeout, names)
                    except DeliveryFailure as exc:
                        failure = exc
                        if delivered:
                            failure = DeliveryFailure(exc.category, ambiguous=True)
                        break
                    except ConfigurationError as exc:
                        failure = DeliveryFailure(str(exc))
                        break
                    except Exception:
                        failure = DeliveryFailure(
                            "unexpected delivery failure",
                            ambiguous=delivered > 0,
                        )
                        break
                    delivered += 1
                    messages_sent += 1
                    pace_needed = True
                if failure is not None:
                    if failure.ambiguous or delivered:
                        store.mark_delivery(
                            event_ids, channel.name, "ambiguous", error=failure.category
                        )
                        ambiguous += len(event_ids)
                    else:
                        store.mark_delivery(
                            event_ids, channel.name, "failed", error=failure.category
                        )
                        failed += len(event_ids)
                    error = failure.category
                    stop_channel = True
                    break
                store.mark_delivery(event_ids, channel.name, "sent")
                events_sent += len(event_ids)
        summaries.append(
            ChannelSummary(
                channel.name,
                channel.type,
                messages=messages_sent,
                events=events_sent,
                failed=failed,
                ambiguous=ambiguous,
                ambiguous_total=store.delivery_status([channel.name])[0].ambiguous,
                error=error,
            )
        )
    return DeliveryReport(tuple(summaries), recovered)


def send_test(
    config: AppConfig,
    http: HttpClient,
    channel_name: str,
    *,
    clock: Callable[[], datetime] = _utc_now,
    timeout_seconds: float = DELIVERY_BUDGET_SECONDS,
) -> TestOutcome:
    channel = channel_map(config.watch.channels).get(channel_name)
    if channel is None:
        raise ConfigurationError(f"unknown watch channel {channel_name!r}")
    if not channel.enabled:
        return TestOutcome(
            channel.name, channel.type, False, "channel is disabled"
        )
    message = OutgoingMessage(
        (int(clock().timestamp() * 1000),) if channel.type == "matrix" else (),
        "CVEBeacon test message",
        TEST_MESSAGE,
        TEST_MESSAGE,
    )
    try:
        if channel.type == "webhook":
            headers: dict[str, str] = {}
            header_name = channel.options.get("header_name")
            if header_name:
                headers[str(header_name)] = _secret(channel, "header_value")
            result = _http_call(
                http,
                "POST",
                str(channel.options["url"]),
                headers=headers,
                json_body={
                    "version": 1,
                    "test": True,
                    "message": TEST_MESSAGE,
                    "events": [],
                },
                timeout=min(timeout_seconds, channel.timeout_seconds),
            )
            if not 200 <= result.status_code < 300:
                raise DeliveryFailure(
                    f"webhook rejected the message: HTTP {result.status_code}"
                )
        else:
            _send(
                channel,
                message,
                (),
                http,
                min(timeout_seconds, channel.timeout_seconds),
                {},
            )
    except (DeliveryFailure, ConfigurationError) as exc:
        category = exc.category if isinstance(exc, DeliveryFailure) else str(exc)
        return TestOutcome(channel.name, channel.type, False, category)
    except Exception:
        return TestOutcome(
            channel.name, channel.type, False, "unexpected delivery failure"
        )
    return TestOutcome(channel.name, channel.type, True)
