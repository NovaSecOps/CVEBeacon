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
from ..clients import ClientImpacts, affected_clients
from ..errors import ConfigurationError
from ..http import HttpClient, HttpResult
from .channels import ChannelConfig, channel_map, validate_webhook_url
from .messages import (
    CHANNEL_LIMITS,
    EMAIL_CHANNELS,
    MESSAGE_TOO_LARGE,
    WEBHOOK_VERSION,
    MessageTooLarge,
    OutgoingMessage,
    build_messages,
    rule_display_names,
    simple_html,
    test_message,
    webhook_payload,
)
from .records import DeliveryEvent
from .reported import NOTICE_KINDS
from .store import (
    DeliveryStatusRow,
    WatchStore,
)

DELIVERY_BUDGET_SECONDS = 60.0
MAX_MESSAGES_PER_CHANNEL = 10
AUTH_MAX_ATTEMPTS = 3
INITIAL_WEBHOOK_CHUNK = 1000


class DeliveryFailure(Exception):
    """A channel did not accept a message.

    ``ambiguous`` means the request or SMTP DATA may have reached the provider.
    ``attempts_limit`` stops automatic retries earlier than the default cap,
    which keeps repeated authentication failures from locking an account.
    """

    def __init__(
        self,
        category: str,
        *,
        ambiguous: bool = False,
        attempts_limit: int | None = None,
    ) -> None:
        self.category = category
        self.ambiguous = ambiguous
        self.attempts_limit = attempts_limit
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
    given_up: int = 0
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
    if summary.given_up:
        line += (
            f"; {summary.given_up} given up "
            "(run cvebeacon watch notify --retry-failed)"
        )
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
    except (httpx.LocalProtocolError, httpx.InvalidURL):
        # Raised while building the request, before anything leaves the host.
        raise DeliveryFailure("invalid request") from None
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
    try:
        # The secret may have been set after configuration was loaded.
        validate_webhook_url(
            url, channel.type, f"watch channel {channel.name!r} webhook_url"
        )
    except ConfigurationError as exc:
        raise DeliveryFailure(str(exc)) from None
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
                "flags": 4,
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
    if not isinstance(body, dict) or not isinstance(body.get("ok"), bool):
        # The provider answered with its success status, so the message may
        # have arrived even though the confirmation cannot be read.
        raise DeliveryFailure(
            "Telegram confirmation was unreadable", ambiguous=True
        )
    if body["ok"] is not True:
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
            + ",".join(str(value) for value in sorted(message.event_ids))
            + f":{message.part_index}/{message.part_count}"
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
        # A 200 without an event id may still have created the event.
        raise DeliveryFailure("Matrix confirmation was unreadable", ambiguous=True)


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
        content=message.content.encode("utf-8"),
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
            "message": message.content,
            "priority": channel.options["priority"],
        },
        timeout=timeout,
    )
    _accepted(result, (200,), "Gotify rejected the message")


def _webhook_body(
    events: Sequence[DeliveryEvent],
    names: Mapping[str, str],
    clients: Mapping[str, ClientImpacts] | None,
) -> bytes:
    payload = webhook_payload(events, names, clients)
    while True:
        body = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(body) <= CHANNEL_LIMITS["webhook"]:
            return body
        entries = [entry for entry in payload["events"] if entry.get("affected_clients")]
        if not entries:
            # The budget governs only client details. A document without
            # them is sent exactly as before this feature existed.
            return body
        # Reduce details across the document in at most six rounds. Counts
        # survive even if all names must be omitted to fit the request budget.
        cap = max(len(entry["affected_clients"]) for entry in entries) // 2
        for entry in entries:
            details = entry["affected_clients"]
            omitted = len(details) - min(cap, len(details))
            if omitted:
                entry["affected_clients_omitted"] = entry.get("affected_clients_omitted", 0) + omitted
                if cap:
                    entry["affected_clients"] = details[:cap]
                else:
                    del entry["affected_clients"]


def _send_webhook(
    channel: ChannelConfig,
    events: Sequence[DeliveryEvent],
    http: HttpClient,
    timeout: float,
    names: Mapping[str, str],
    clients: Mapping[str, ClientImpacts] | None = None,
) -> None:
    body = _webhook_body(events, names, clients)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    header_name = channel.options.get("header_name")
    if header_name:
        headers[str(header_name)] = _secret(channel, "header_value")
    result = _http_call(
        http,
        "POST",
        str(channel.options["url"]),
        headers=headers,
        content=body,
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
    email["Date"] = formatdate(localtime=False, usegmt=True)
    email["Auto-Submitted"] = "auto-generated"
    domain = str(channel.options["sender"]).rsplit("@", 1)[-1]
    email["Message-ID"] = make_msgid(domain=domain or None)
    # A 7-bit safe body works with relays that do not offer 8BITMIME.
    email.set_content(message.body, cte="quoted-printable")
    if message.html:
        # The plain-text part stays first for clients that prefer it.
        email.add_alternative(
            message.html, subtype="html", cte="quoted-printable"
        )
    return email


class _SmtpDeadline(Exception):
    """The delivery deadline expired between SMTP phases."""


class _TrackedSMTP(smtplib.SMTP):
    data_sent = False

    def data(self, msg):
        self.data_sent = True
        return super().data(msg)


class _TrackedSMTP_SSL(smtplib.SMTP_SSL):
    data_sent = False

    def data(self, msg):
        self.data_sent = True
        return super().data(msg)


def _smtp_client(channel: ChannelConfig, timeout: float):
    security = str(channel.options["security"])
    context = ssl.create_default_context()
    host = str(channel.options["host"])
    port = int(channel.options["port"])
    if security == "tls":
        return _TrackedSMTP_SSL(host, port, timeout=timeout, context=context)
    return _TrackedSMTP(host, port, timeout=timeout)


def _send_smtp(
    channel: ChannelConfig,
    message: OutgoingMessage,
    timeout: float,
    *,
    deadline: float | None = None,
    monotonic: Callable[[], float] | None = None,
) -> None:
    if monotonic is None:
        monotonic = time.monotonic

    def remaining() -> float:
        if deadline is None:
            return timeout
        return deadline - monotonic()

    def phase_timeout() -> float:
        left = remaining()
        if deadline is not None and left <= 0:
            raise _SmtpDeadline
        return max(0.01, min(timeout, left))

    def set_phase_timeout() -> None:
        sock = getattr(client, "sock", None)
        if sock is not None:
            sock.settimeout(phase_timeout())

    security = str(channel.options["security"])
    try:
        client = _smtp_client(channel, phase_timeout())
    except _SmtpDeadline:
        raise DeliveryFailure("delivery budget exhausted") from None
    except ssl.SSLCertVerificationError:
        raise DeliveryFailure("SMTP certificate verification failed") from None
    except (OSError, ssl.SSLError, smtplib.SMTPException):
        raise DeliveryFailure("SMTP connection failed") from None
    try:
        try:
            set_phase_timeout()
            client.ehlo()
            if security == "starttls":
                try:
                    set_phase_timeout()
                    client.starttls(context=ssl.create_default_context())
                except smtplib.SMTPNotSupportedError:
                    raise DeliveryFailure(
                        "server does not offer STARTTLS"
                    ) from None
                set_phase_timeout()
                client.ehlo()
            username = channel.options.get("username")
            if username:
                password = _secret(channel, "password")
                set_phase_timeout()
                client.login(str(username), password)
        except _SmtpDeadline:
            raise DeliveryFailure("delivery budget exhausted") from None
        except DeliveryFailure:
            raise
        except smtplib.SMTPAuthenticationError:
            raise DeliveryFailure(
                "SMTP authentication failed", attempts_limit=AUTH_MAX_ATTEMPTS
            ) from None
        except smtplib.SMTPResponseException:
            raise DeliveryFailure("SMTP rejected the message") from None
        except ssl.SSLCertVerificationError:
            raise DeliveryFailure("SMTP certificate verification failed") from None
        except (OSError, ssl.SSLError, smtplib.SMTPException):
            raise DeliveryFailure("SMTP session failed") from None
        recipients = [
            *channel.options["to"],
            *(channel.options.get("cc") or ()),
            *(channel.options.get("bcc") or ()),
        ]
        try:
            set_phase_timeout()
            refused = client.send_message(
                _email_message(channel, message), to_addrs=recipients
            )
        except _SmtpDeadline:
            raise DeliveryFailure("delivery budget exhausted") from None
        except ssl.SSLCertVerificationError:
            raise DeliveryFailure("SMTP certificate verification failed") from None
        except smtplib.SMTPAuthenticationError:
            raise DeliveryFailure(
                "SMTP authentication failed", attempts_limit=AUTH_MAX_ATTEMPTS
            ) from None
        except (
            smtplib.SMTPRecipientsRefused,
            smtplib.SMTPSenderRefused,
            smtplib.SMTPHeloError,
        ):
            raise DeliveryFailure("SMTP rejected the message") from None
        except smtplib.SMTPResponseException:
            raise DeliveryFailure("SMTP rejected the message") from None
        except (OSError, ssl.SSLError, smtplib.SMTPException, TimeoutError):
            if client.data_sent:
                raise DeliveryFailure("SMTP outcome unknown", ambiguous=True) from None
            raise DeliveryFailure("SMTP session failed") from None
        if refused:
            raise DeliveryFailure(
                "SMTP refused some recipients", ambiguous=True
            )
    finally:
        try:
            set_phase_timeout()
            client.quit()
        except (_SmtpDeadline, OSError, smtplib.SMTPException):
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
    if result.status_code in (401, 403):
        raise DeliveryFailure(
            f"Graph authentication failed: HTTP {result.status_code}",
            attempts_limit=AUTH_MAX_ATTEMPTS,
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
        raise DeliveryFailure(
            exc.category, attempts_limit=exc.attempts_limit
        ) from None
    recipients = [
        {"emailAddress": {"address": address}}
        for address in channel.options["to"]
    ]
    message_body: dict[str, Any] = {
        "subject": message.subject,
        "body": (
            {"contentType": "HTML", "content": message.html}
            if message.html
            else {"contentType": "Text", "content": message.body}
        ),
        "toRecipients": recipients,
    }
    cc = channel.options.get("cc") or ()
    if cc:
        message_body["ccRecipients"] = [
            {"emailAddress": {"address": address}} for address in cc
        ]
    bcc = channel.options.get("bcc") or ()
    if bcc:
        message_body["bccRecipients"] = [
            {"emailAddress": {"address": address}} for address in bcc
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
    if result.status_code in (401, 403):
        raise DeliveryFailure(
            f"Graph authentication failed: HTTP {result.status_code}",
            attempts_limit=AUTH_MAX_ATTEMPTS,
        )
    _accepted(result, (202,), "Graph mail rejected the message")


def _send(
    channel: ChannelConfig,
    message: OutgoingMessage,
    events: Sequence[DeliveryEvent],
    http: HttpClient,
    timeout: float,
    names: Mapping[str, str],
    *,
    clients: Mapping[str, ClientImpacts] | None = None,
    deadline: float | None = None,
    monotonic: Callable[[], float] | None = None,
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
        _send_webhook(channel, events, http, timeout, names, clients)
    elif channel.type == "graph":
        _send_graph(channel, message, http, timeout)
    elif channel.type == "smtp":
        _send_smtp(
            channel,
            message,
            timeout,
            deadline=deadline,
            monotonic=monotonic,
        )
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


def _channel_status(store: WatchStore, name: str) -> DeliveryStatusRow:
    rows = store.delivery_status([name])
    for row in rows:
        if row.channel == name:
            return row
    raise ConfigurationError(f"unknown watch channel {name!r}")


def _channel_messages(
    channel: ChannelConfig,
    events: Sequence[DeliveryEvent],
    *,
    names: Mapping[str, str],
    since: str | None,
    language: str,
    clients: Mapping[str, ClientImpacts] | None = None,
) -> tuple[OutgoingMessage, ...]:
    return build_messages(
        events,
        channel_type=channel.type,
        grouping=channel.grouping,
        max_items=channel.max_items,
        names=names,
        since=since,
        language=language,
        format=channel.format,
        clients=clients,
    )


def deliver_pending(
    config: AppConfig,
    store: WatchStore,
    http: HttpClient,
    *,
    channel_names: Iterable[str] | None = None,
    event_ids: Iterable[int] | None = None,
    retry_ambiguous: bool = False,
    retry_failed: bool = False,
    clock: Callable[[], datetime] = _utc_now,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
    budget_seconds: float = DELIVERY_BUDGET_SECONDS,
) -> DeliveryReport:
    if monotonic is None:
        monotonic = time.monotonic
    if sleep is None:
        sleep = time.sleep
    selected_events: tuple[int, ...] | None = None
    if event_ids is not None:
        selected_events = tuple(sorted({int(value) for value in event_ids}))
        if not selected_events:
            return DeliveryReport()
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
        if retry_failed:
            store.reset_failed(channel.name)
        now = clock()
        include_ambiguous = retry_ambiguous
        messages_sent = 0
        events_sent = 0
        failed = 0
        ambiguous = 0
        error: str | None = None
        pace_needed = False
        stop_channel = False
        interval = channel.min_interval_seconds
        language = channel.language or config.watch.language

        def send_messages(
            messages: Sequence[OutgoingMessage],
            covered: Sequence[DeliveryEvent],
            sent: int,
            pace: bool,
            client_impacts: Mapping[str, ClientImpacts] | None = None,
        ) -> tuple[int, int, DeliveryFailure | None, bool, bool]:
            delivered = 0
            failure: DeliveryFailure | None = None
            expired = False
            for message in messages:
                if delivered and pace and interval > 0:
                    remaining = deadline - monotonic()
                    if interval > remaining:
                        failure = DeliveryFailure(
                            "delivery budget exhausted", ambiguous=True
                        )
                        break
                    sleep(interval)
                    if monotonic() >= deadline:
                        failure = DeliveryFailure(
                            "delivery budget exhausted", ambiguous=True
                        )
                        break
                remaining = deadline - monotonic()
                if remaining <= 0:
                    if delivered == 0:
                        expired = True
                    else:
                        failure = DeliveryFailure(
                            "delivery budget exhausted", ambiguous=True
                        )
                    break
                timeout = max(0.5, min(channel.timeout_seconds, remaining))
                try:
                    _send(
                        channel,
                        message,
                        covered,
                        http,
                        timeout,
                        names,
                        clients=client_impacts,
                        deadline=deadline,
                        monotonic=monotonic,
                    )
                except DeliveryFailure as exc:
                    failure = exc
                    if delivered:
                        failure = DeliveryFailure(
                            exc.category,
                            ambiguous=True,
                            attempts_limit=exc.attempts_limit,
                        )
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
                sent += 1
                pace = True
            return delivered, sent, failure, expired, pace

        if selected_events is None and monotonic() < deadline:
            if channel.type == "webhook":
                # Initial events are JSON documents of at most 1,000 rows.
                while (
                    not stop_channel
                    and messages_sent < MAX_MESSAGES_PER_CHANNEL
                ):
                    if messages_sent and pace_needed and interval > 0:
                        remaining = deadline - monotonic()
                        if interval > remaining:
                            stop_channel = True
                            break
                        sleep(interval)
                        if monotonic() >= deadline:
                            stop_channel = True
                            break
                    if monotonic() >= deadline:
                        stop_channel = True
                        break
                    chunk = store.claim_initial_chunk(
                        channel.name,
                        catalogs=config.watch.sources,
                        now=now,
                        include_ambiguous=include_ambiguous,
                        limit=INITIAL_WEBHOOK_CHUNK,
                    )
                    if not chunk:
                        break
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        store.release_initial(channel.name, now=now)
                        stop_channel = True
                        break
                    timeout = max(0.5, min(channel.timeout_seconds, remaining))
                    failure: DeliveryFailure | None = None
                    try:
                        _send_webhook(
                            channel,
                            chunk,
                            http,
                            timeout,
                            names,
                            affected_clients(
                                config.database_path,
                                (event.cve_id for event in chunk),
                            ),
                        )
                    except DeliveryFailure as exc:
                        failure = exc
                    except ConfigurationError as exc:
                        failure = DeliveryFailure(str(exc))
                    except Exception:
                        failure = DeliveryFailure("unexpected delivery failure")
                    if failure is not None:
                        store.mark_initial_failed(
                            channel.name,
                            now=now,
                            error=failure.category,
                            attempts_limit=failure.attempts_limit,
                            ambiguous=failure.ambiguous,
                        )
                        prior_ambiguous = sum(
                            event.status == "ambiguous" for event in chunk
                        )
                        if failure.ambiguous:
                            ambiguous += len(chunk)
                        else:
                            ambiguous += prior_ambiguous
                            failed += len(chunk) - prior_ambiguous
                        error = failure.category
                        stop_channel = True
                        break
                    store.mark_initial_sent(channel.name, now=now)
                    messages_sent += 1
                    events_sent += len(chunk)
                    pace_needed = True
            else:
                digest = store.claim_initial_digest(
                    channel.name,
                    catalogs=config.watch.sources,
                    now=now,
                    max_items=channel.max_items,
                    include_ambiguous=include_ambiguous,
                )
                if digest is not None:
                    digest_clients = affected_clients(
                        config.database_path,
                        (event.cve_id for event in digest.events),
                    )
                    try:
                        initial_messages = build_messages(
                            (),
                            channel_type=channel.type,
                            grouping=channel.grouping,
                            max_items=channel.max_items,
                            names=names,
                            since=since,
                            initial=digest,
                            language=language,
                            format=channel.format,
                            clients=digest_clients,
                        )
                    except MessageTooLarge:
                        store.mark_initial_failed(
                            channel.name,
                            now=now,
                            error=MESSAGE_TOO_LARGE,
                        )
                        ambiguous += digest.ambiguous
                        failed += digest.total - digest.ambiguous
                        error = MESSAGE_TOO_LARGE
                        stop_channel = True
                    else:
                        if len(initial_messages) > MAX_MESSAGES_PER_CHANNEL:
                            store.release_initial(channel.name, now=now)
                            stop_channel = True
                        else:
                            (
                                delivered,
                                messages_sent,
                                failure,
                                expired,
                                pace_needed,
                            ) = send_messages(
                                initial_messages,
                                digest.events,
                                messages_sent,
                                pace_needed,
                                digest_clients,
                            )
                            if expired:
                                store.release_initial(channel.name, now=now)
                                stop_channel = True
                            elif failure is not None:
                                store.mark_initial_failed(
                                    channel.name,
                                    now=now,
                                    error=failure.category,
                                    attempts_limit=failure.attempts_limit,
                                    ambiguous=failure.ambiguous,
                                )
                                if failure.ambiguous:
                                    ambiguous += digest.total
                                else:
                                    ambiguous += digest.ambiguous
                                    failed += digest.total - digest.ambiguous
                                error = failure.category
                                stop_channel = True
                            elif delivered == len(initial_messages):
                                store.mark_initial_sent(channel.name, now=now)
                                events_sent += digest.total
                            else:
                                store.release_initial(channel.name, now=now)
                                stop_channel = True

        if not stop_channel and monotonic() < deadline:
            events = store.delivery_events(
                channel.name,
                catalogs=config.watch.sources,
                now=now,
                include_ambiguous=include_ambiguous,
                event_ids=selected_events,
            )
            notices = tuple(
                sorted(
                    (
                        event
                        for event in events
                        if event.kind in NOTICE_KINDS
                    ),
                    key=lambda event: event.event_id,
                )
            )
            alerts = tuple(
                event for event in events if event.kind not in NOTICE_KINDS
            )
            batches: list[tuple[DeliveryEvent, ...]] = []
            if notices:
                # Notices are one message each and follow the audit order.
                batches.append(notices)
            if include_ambiguous:
                ambiguous_events = tuple(
                    event for event in alerts if event.status == "ambiguous"
                )
                other_events = tuple(
                    event for event in alerts if event.status != "ambiguous"
                )
                if ambiguous_events:
                    batches.append(ambiguous_events)
                if other_events:
                    batches.append(other_events)
            elif alerts:
                batches.append(alerts)
            for batch in batches:
                index = _event_index(batch)
                batch_clients = affected_clients(
                    config.database_path,
                    (event.cve_id for event in batch),
                )
                claim_statuses = (
                    ("ambiguous",)
                    if batch
                    and all(event.status == "ambiguous" for event in batch)
                    else ("pending", "failed")
                )
                try:
                    channel_messages = _channel_messages(
                        channel,
                        batch,
                        names=names,
                        since=since,
                        language=language,
                        clients=batch_clients,
                    )
                except MessageTooLarge:
                    identifiers = tuple(event.event_id for event in batch)
                    was_ambiguous = any(
                        event.status == "ambiguous" for event in batch
                    )
                    if identifiers and store.claim_delivery(
                        identifiers,
                        channel.name,
                        statuses=claim_statuses,
                    ):
                        if was_ambiguous:
                            store.mark_delivery(
                                identifiers,
                                channel.name,
                                "ambiguous",
                                error=MESSAGE_TOO_LARGE,
                            )
                            ambiguous += len(identifiers)
                        else:
                            store.mark_delivery(
                                identifiers,
                                channel.name,
                                "failed",
                                error=MESSAGE_TOO_LARGE,
                            )
                            failed += len(identifiers)
                    error = MESSAGE_TOO_LARGE
                    stop_channel = True
                    break
                for group in _group_messages(channel_messages):
                    if stop_channel or messages_sent >= MAX_MESSAGES_PER_CHANNEL:
                        stop_channel = True
                        break
                    if messages_sent + len(group) > MAX_MESSAGES_PER_CHANNEL:
                        break
                    if monotonic() >= deadline:
                        break
                    if pace_needed and interval > 0:
                        remaining = deadline - monotonic()
                        if interval > remaining:
                            stop_channel = True
                            break
                        sleep(interval)
                        if monotonic() >= deadline:
                            stop_channel = True
                            break
                    event_ids = group[0].event_ids
                    covered = [index[value] for value in event_ids if value in index]
                    if not covered:
                        continue
                    if (
                        len(event_ids) == 1
                        and covered[0].kind in NOTICE_KINDS
                    ):
                        claim_statuses = (
                            ("ambiguous",)
                            if covered[0].status == "ambiguous"
                            else ("pending", "failed")
                        )
                        claimed = store.claim_notice(
                            event_ids[0],
                            channel.name,
                            statuses=claim_statuses,
                        )
                    else:
                        claim_statuses = (
                            ("ambiguous",)
                            if batch and batch[0].status == "ambiguous"
                            else ("pending", "failed")
                        )
                        claimed = store.claim_delivery(
                            event_ids, channel.name, statuses=claim_statuses
                        )
                    if not claimed:
                        # Another run owns these rows, or an earlier notice
                        # for this CVE and channel is still unresolved.
                        continue
                    (
                        delivered,
                        messages_sent,
                        failure,
                        expired,
                        pace_needed,
                    ) = send_messages(
                        group, covered, messages_sent, pace_needed, batch_clients
                    )
                    if expired:
                        # Nothing left this run: undo the claim without an
                        # attempt or a failure.
                        store.release_delivery(
                            event_ids,
                            channel.name,
                            status=claim_statuses[0],
                        )
                        stop_channel = True
                        break
                    if failure is not None:
                        # A row that was ambiguous before this attempt may
                        # already have been delivered; a later failure cannot
                        # clear that.
                        was_ambiguous = any(
                            event.status == "ambiguous" for event in covered
                        )
                        if failure.ambiguous or delivered or was_ambiguous:
                            store.mark_delivery(
                                event_ids,
                                channel.name,
                                "ambiguous",
                                error=failure.category,
                                attempts_limit=failure.attempts_limit,
                            )
                            ambiguous += len(event_ids)
                        else:
                            store.mark_delivery(
                                event_ids,
                                channel.name,
                                "failed",
                                error=failure.category,
                                attempts_limit=failure.attempts_limit,
                            )
                            failed += len(event_ids)
                        error = failure.category
                        stop_channel = True
                        break
                    store.mark_delivery(event_ids, channel.name, "sent")
                    events_sent += len(event_ids)
        final_status = _channel_status(store, channel.name)
        summaries.append(
            ChannelSummary(
                channel.name,
                channel.type,
                messages=messages_sent,
                events=events_sent,
                failed=failed,
                ambiguous=ambiguous,
                ambiguous_total=final_status.ambiguous,
                given_up=final_status.given_up,
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
    language = channel.language or config.watch.language
    subject, body = test_message(language)
    html = (
        simple_html(language, subject, body)
        if channel.format == "html" and channel.type in EMAIL_CHANNELS
        else ""
    )
    message = OutgoingMessage(
        (int(clock().timestamp() * 1000),) if channel.type == "matrix" else (),
        subject,
        body,
        body,
        html=html,
        content=body,
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
                    "version": WEBHOOK_VERSION,
                    "test": True,
                    "message": body,
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
