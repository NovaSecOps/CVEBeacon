"""Proactive Teams delivery using the public Bot Connector REST protocol."""

from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote, urlsplit
from weakref import WeakKeyDictionary

from ..http import HttpClient, HttpResult
from .channels import ChannelConfig, teams_service_url
from .delivery import AUTH_MAX_ATTEMPTS, DeliveryFailure, _http_call, _json_body, _secret
from .messages import OutgoingMessage, teams_adaptive_card
from .store import WatchStore

AUTHORITY = "https://login.microsoftonline.com"
GRAPH_URL = "https://graph.microsoft.com/v1.0"
BOT_SCOPE = "https://api.botframework.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
# A transport owns its cache: credentials/tokens never enter SQLite or config.
_TOKENS: WeakKeyDictionary = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class RecipientResult:
    recipient: str
    status: str
    error: str | None = None
    attempts_limit: int | None = None
    part_index: int = 0
    destination_index: int = 0


adaptive_card = teams_adaptive_card


def message_key(message: OutgoingMessage) -> str:
    return hashlib.sha256(json.dumps(
        [message.event_ids, message.initial, message.part_index, adaptive_card(message)],
        sort_keys=True, ensure_ascii=True,
    ).encode()).hexdigest()


class _Session:
    def __init__(
        self, channel: ChannelConfig, http: HttpClient, timeout: float,
        deadline: float, monotonic: Callable[[], float], sleep: Callable[[float], None],
    ) -> None:
        self.channel = channel
        self.http = http
        self.timeout = timeout
        self.deadline = deadline
        self.monotonic = monotonic
        self.sleep = sleep
        self._token_errors: dict[str, DeliveryFailure] = {}

    def request(self, method: str, url: str, *, activity: bool = False, scope: str | None = None, **kwargs) -> HttpResult:
        if scope == BOT_SCOPE and kwargs.get("headers", {}).get("Authorization"):
            origin = urlsplit(url)
            teams_service_url(f"{origin.scheme}://{origin.netloc}/", "Teams bot service_url")
        for attempt in range(3):
            remaining = self.deadline - self.monotonic()
            if remaining <= 0:
                raise DeliveryFailure("Teams bot delivery budget exhausted")
            try:
                result = _http_call(
                    self.http, method, url, timeout=min(self.timeout, remaining), **kwargs,
                )
            except DeliveryFailure as exc:
                # Token, lookup and empty conversation creation cannot send a card.
                raise DeliveryFailure(exc.category, ambiguous=activity and exc.ambiguous) from None
            status = result.status_code
            if 200 <= status < 300:
                return result
            if status in (401, 403):
                if status == 401:
                    _TOKENS.pop(self.http, None)
                operation = "Graph user lookup" if scope == GRAPH_SCOPE else "Bot Connector"
                failure = DeliveryFailure(
                    f"Teams bot {operation} authorization failed: HTTP {status}",
                    attempts_limit=AUTH_MAX_ATTEMPTS,
                )
                if status == 401 and scope:
                    self._token_errors[scope] = failure
                raise failure
            if status == 429:
                retry_after = HttpClient._retry_after_value(
                    result.headers.get("retry-after") or result.headers.get("Retry-After"),
                    ceiling=float("inf"),
                )
                delay = retry_after if retry_after is not None else 2 ** attempt
                if attempt < 2 and delay + 0.5 < self.deadline - self.monotonic():
                    self.sleep(delay)
                    continue
                raise DeliveryFailure("Teams bot throttled: HTTP 429", retry_after=delay)
            # No immediate replay of an activity on 5xx or a transport timeout.
            raise DeliveryFailure(f"Teams bot request rejected: HTTP {status}")
        raise DeliveryFailure("Teams bot request failed")

    def token(self, scope: str) -> str:
        if scope in self._token_errors:
            raise self._token_errors[scope]
        secret = _secret(self.channel, "client_secret")
        tenant = self.channel.options["tenant_id"]
        app = self.channel.options["app_id"]
        key = (tenant, app, scope, hashlib.sha256(secret.encode()).digest())
        cache = _TOKENS.setdefault(self.http, {})
        now = self.monotonic()
        if key in cache and now < cache[key][1]:
            return cache[key][0]
        started = now
        try:
            result = self.request(
                "POST", f"{AUTHORITY}/{tenant}/oauth2/v2.0/token",
                scope=scope,
                data={"client_id": app, "client_secret": secret,
                      "scope": scope, "grant_type": "client_credentials"},
            )
        except DeliveryFailure as exc:
            # All destinations share these credentials. Retry next batch, rather
            # than repeating a failed login for every user in the current batch.
            self._token_errors[scope] = exc
            raise
        body = _json_body(result)
        token = body.get("access_token") if isinstance(body, dict) else None
        expiry = body.get("expires_in") if isinstance(body, dict) else None
        if (
            not isinstance(token, str) or not token or len(token) > 16384
            or any(ord(char) <= 32 or ord(char) == 127 for char in token)
            or isinstance(expiry, bool) or not isinstance(expiry, (int, float))
            or not 0 < expiry or not math.isfinite(expiry)
        ):
            failure = DeliveryFailure("Teams bot token response is invalid")
            self._token_errors[scope] = failure
            raise failure
        # Refresh a little early, including unusually short-lived tokens.
        expires = started + min(expiry, 86400) - min(60, expiry / 10)
        if len(cache) >= 32:
            cache.clear()
        cache[key] = (token, expires)
        return token

    def conversation(self, store: WatchStore, recipient: str, service_url: str) -> str:
        tenant = self.channel.options["tenant_id"]
        app = self.channel.options["app_id"]
        existing = store.teams_bot_conversation(tenant, app, recipient, service_url)
        if existing:
            return existing
        object_id = recipient
        if "@" in recipient:
            result = self.request(
                "GET", f"{GRAPH_URL}/users/{quote(recipient, safe='')}?$select=id",
                headers={"Authorization": f"Bearer {self.token(GRAPH_SCOPE)}"}, scope=GRAPH_SCOPE,
            )
            body = _json_body(result)
            try:
                object_id = str(uuid.UUID(body["id"]))
            except (ValueError, TypeError, KeyError, AttributeError):
                raise DeliveryFailure("Teams bot user lookup response is invalid") from None
        result = self.request(
            "POST", service_url + "v3/conversations",
            headers={"Authorization": f"Bearer {self.token(BOT_SCOPE)}"}, scope=BOT_SCOPE,
            json_body={
                "bot": {"id": "28:" + app}, "isGroup": False,
                "members": [{"id": object_id}],
                "channelData": {"tenant": {"id": tenant}},
            },
        )
        body = _json_body(result)
        conversation_id = body.get("id") if isinstance(body, dict) else None
        if (
            not isinstance(conversation_id, str) or not conversation_id
            or len(conversation_id) > 2048
            or any(ord(char) < 32 or ord(char) == 127 for char in conversation_id)
        ):
            raise DeliveryFailure("Teams bot conversation response is invalid")
        store.teams_bot_conversation(tenant, app, recipient, service_url, conversation_id)
        return conversation_id


def send_bot(
    channel: ChannelConfig, message: OutgoingMessage, http: HttpClient,
    timeout: float, store: WatchStore | None, *, deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep, retry_ambiguous: bool = False,
    wall_time: Callable[[], float] = time.time,
) -> tuple[RecipientResult, ...]:
    session = _Session(
        channel, http, timeout, monotonic() + timeout if deadline is None else deadline,
        monotonic, sleep,
    )
    # Parts are individually durable. A later failed part never replays a sent part.
    payload = adaptive_card(message)
    rendered_key = message_key(message)
    destinations = [
        (recipient, None, channel.options["service_url"])
        for recipient in channel.options["recipients"]
    ] + [
        ("conversation:" + conversation_id, conversation_id, service_url)
        for conversation_id, service_url in channel.options["conversation_references"]
    ]
    # Revalidate before any token request, including programmatic channel configs.
    destinations = [(recipient, conversation_id, teams_service_url(service_url, "Teams bot service_url"))
                    for recipient, conversation_id, service_url in destinations]
    results = []
    for destination_index, (recipient, conversation_id, service_url) in enumerate(destinations):
        destination_key = hashlib.sha256(json.dumps([recipient, service_url]).encode()).hexdigest()
        key = (channel.name, channel.options["tenant_id"], channel.options["app_id"],
               destination_key, rendered_key)
        # Channel tests deliberately send a fresh labelled card every time.
        durable = bool(message.event_ids) or message.initial
        was_ambiguous = False
        if durable:
            status = store.claim_teams_bot_recipient(
                key, retry_ambiguous=retry_ambiguous, now=wall_time(),
            )
            was_ambiguous = status == "retrying_ambiguous"
            if status not in {"sending", "retrying_ambiguous"}:
                results.append(RecipientResult(
                    recipient, status,
                    None if status == "sent" else "Teams bot recipient requires retry" if status == "ambiguous"
                    else "Teams bot recipient is waiting for Retry-After",
                    part_index=message.part_index, destination_index=destination_index,
                ))
                continue
        activity_started = False
        try:
            conversation_id = conversation_id or session.conversation(store, recipient, service_url)
            token = session.token(BOT_SCOPE)
            activity_started = True
            session.request(
                "POST", service_url + "v3/conversations/" + quote(conversation_id, safe="") + "/activities",
                headers={"Authorization": f"Bearer {token}"}, scope=BOT_SCOPE,
                json_body=payload, activity=True,
            )
            if durable:
                store.finish_teams_bot_recipient(key, "sent")
        except DeliveryFailure as exc:
            status = "ambiguous" if exc.ambiguous or was_ambiguous else "failed"
            if durable:
                try:
                    store.finish_teams_bot_recipient(
                        key, status, error=exc.category,
                        not_before=wall_time() + exc.retry_after if exc.retry_after else 0,
                    )
                except Exception:
                    # Leave the claimed row for crash recovery if storage is unavailable.
                    results.append(RecipientResult(
                        recipient, "ambiguous" if activity_started or was_ambiguous else "failed",
                        "Teams bot delivery state could not be saved", part_index=message.part_index,
                        destination_index=destination_index,
                    ))
                    continue
            results.append(RecipientResult(recipient, status, exc.category, exc.attempts_limit, message.part_index, destination_index))
        except Exception:
            status = "ambiguous" if activity_started or was_ambiguous else "failed"
            if durable:
                try:
                    store.finish_teams_bot_recipient(key, status, error="Teams bot delivery interrupted")
                except Exception:
                    pass  # The sending row remains durable and will recover as ambiguous.
            results.append(RecipientResult(
                recipient, status, "Teams bot delivery interrupted", part_index=message.part_index,
                destination_index=destination_index,
            ))
        else:
            results.append(RecipientResult(recipient, "sent", part_index=message.part_index, destination_index=destination_index))
    return tuple(results)
