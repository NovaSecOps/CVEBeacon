"""Proactive Teams delivery using the public Bot Connector REST protocol."""

from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote
from weakref import WeakKeyDictionary

from ..http import HttpClient, HttpResult
from .channels import ChannelConfig
from .delivery import AUTH_MAX_ATTEMPTS, DeliveryFailure, _http_call, _json_body, _secret
from .messages import OutgoingMessage
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


def adaptive_card(message: OutgoingMessage) -> dict:
    """Use the same card structure as the existing Workflow channel."""
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard", "version": "1.4",
                "body": [{"type": "TextBlock", "wrap": True, "text": message.text}],
            },
        }],
    }


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

    def request(self, method: str, url: str, *, activity: bool = False, **kwargs) -> HttpResult:
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
                raise DeliveryFailure(
                    f"Teams bot authorization failed: HTTP {status}",
                    attempts_limit=AUTH_MAX_ATTEMPTS,
                )
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
            or not 0 < expiry <= 86400 or not math.isfinite(expiry)
        ):
            failure = DeliveryFailure("Teams bot token response is invalid")
            self._token_errors[scope] = failure
            raise failure
        # Refresh a little early, including unusually short-lived tokens.
        expires = started + expiry - min(60, expiry / 10)
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
                headers={"Authorization": f"Bearer {self.token(GRAPH_SCOPE)}"},
            )
            body = _json_body(result)
            try:
                object_id = str(uuid.UUID(body["id"]))
            except (ValueError, TypeError, KeyError, AttributeError):
                raise DeliveryFailure("Teams bot user lookup response is invalid") from None
        result = self.request(
            "POST", service_url + "v3/conversations",
            headers={"Authorization": f"Bearer {self.token(BOT_SCOPE)}"},
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
    timeout: float, store: WatchStore, *, deadline: float | None = None,
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
    message_key = hashlib.sha256(json.dumps(
        [message.event_ids, message.initial, message.part_index, payload],
        sort_keys=True, ensure_ascii=True,
    ).encode()).hexdigest()
    destinations = [
        (recipient, None, channel.options["service_url"])
        for recipient in channel.options["recipients"]
    ] + [
        ("conversation:" + conversation_id, conversation_id, service_url)
        for conversation_id, service_url in channel.options["conversation_references"]
    ]
    results = []
    for recipient, conversation_id, service_url in destinations:
        destination_key = hashlib.sha256(json.dumps([recipient, service_url]).encode()).hexdigest()
        key = (channel.name, channel.options["tenant_id"], channel.options["app_id"],
               destination_key, message_key)
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
                    recipient, "failed" if status == "deferred" else status,
                    None if status == "sent" else "Teams bot recipient requires retry" if status == "ambiguous"
                    else "Teams bot recipient is waiting for Retry-After",
                ))
                continue
        try:
            conversation_id = conversation_id or session.conversation(store, recipient, service_url)
            session.request(
                "POST", service_url + "v3/conversations/" + quote(conversation_id, safe="") + "/activities",
                headers={"Authorization": f"Bearer {session.token(BOT_SCOPE)}"},
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
                    results.append(RecipientResult(recipient, "ambiguous", "Teams bot delivery state could not be saved"))
                    continue
            results.append(RecipientResult(recipient, status, exc.category, exc.attempts_limit))
        except Exception:
            # A storage failure after an accepted send must never permit a replay.
            if durable:
                try:
                    store.finish_teams_bot_recipient(key, "ambiguous", error="Teams bot delivery interrupted")
                except Exception:
                    pass  # The sending row remains durable and will recover as ambiguous.
            results.append(RecipientResult(recipient, "ambiguous", "Teams bot delivery interrupted"))
        else:
            results.append(RecipientResult(recipient, "sent"))
    return tuple(results)
