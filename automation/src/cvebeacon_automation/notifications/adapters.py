"""Reviewed text-only provider protocols and finite channel configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
import math
from pathlib import Path
import re
from urllib.parse import quote, urlsplit

from cvebeacon_extensions.contract import decode_json, json_bytes
from ..common import AutomationError, Secret, digest, identifier
from ..config import boolean, keys, number
from ..http import HTTPS, TransportError, endpoint


MAX_RESPONSE = 65536
MAX_REQUEST = 32768
COMMON = {"id", "provider", "enabled", "timeout_seconds", "max_attempts", "batch_size", "max_parts",
          "min_interval_seconds", "retry_base_seconds", "retry_max_seconds"}
SPECIFIC = {"telegram": {"token", "chat_id", "message_thread_id"}, "discord": {"webhook"},
            "slack": {"webhook"}, "matrix": {"token", "homeserver", "room_id"}}


@dataclass(frozen=True, repr=False)
class Channel:
    id: str
    provider: str
    secret: Secret = field(repr=False)
    options: dict = field(repr=False)
    enabled: bool = True
    timeout: int = 15
    max_attempts: int = 5
    batch_size: int = 64
    max_parts: int = 8
    interval: int = 1
    retry_base: int = 30
    retry_max: int = 3600

    def __repr__(self):
        return "Channel(<configured>)"


def validate_channels(items: tuple[dict, ...], base: Path) -> tuple[Channel, ...]:
    if not isinstance(items, tuple) or len(items) > 32:
        raise AutomationError("invalid_notification_channels")
    result, seen = [], set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("provider"), str) or item["provider"] not in SPECIFIC:
            raise AutomationError("unsupported_notification_provider")
        provider = item["provider"]
        keys(item, COMMON | SPECIFIC[provider])
        name = identifier(item.get("id"), "channel_id")
        if name.casefold() in seen:
            raise AutomationError("duplicate_notification_channel")
        seen.add(name.casefold())
        secret_value = item.get("webhook" if provider in {"slack", "discord"} else "token")
        if isinstance(secret_value, dict) and "file" in secret_value and (not isinstance(secret_value["file"], str)
                or len(secret_value["file"]) > 4096 or any(ord(c) < 32 for c in secret_value["file"])):
            raise AutomationError("invalid_secret_reference")
        secret = Secret.parse(secret_value, base)
        options = {}
        if provider == "telegram":
            chat = item.get("chat_id")
            if type(chat) is int and -(2**52) < chat < 2**52 and chat != 0:
                options["chat_id"] = chat
            elif isinstance(chat, str) and (re.fullmatch(r"-?[1-9][0-9]{0,15}", chat)
                    or re.fullmatch(r"@[A-Za-z][A-Za-z0-9_]{3,63}", chat)):
                options["chat_id"] = chat
            else:
                raise AutomationError("invalid_telegram_chat")
            if "message_thread_id" in item:
                options["message_thread_id"] = number(item["message_thread_id"], 1, 2**31 - 1)
        elif provider == "matrix":
            home = item.get("homeserver")
            target = endpoint(home)
            if target.path != "/" or urlsplit(home).query:
                raise AutomationError("invalid_matrix_homeserver")
            room = item.get("room_id")
            if (not isinstance(room, str) or not room.startswith("!") or ":" not in room
                    or len(room) > 255 or any(ord(c) <= 32 or ord(c) >= 127 for c in room)
                    or any(c in room for c in "/?#\\")):
                raise AutomationError("invalid_matrix_room")
            options.update(homeserver=home.rstrip("/"), room_id=room)
        retry_base = number(item.get("retry_base_seconds", 30), 1, 3600)
        retry_max = number(item.get("retry_max_seconds", 3600), 1, 86400)
        if retry_max < retry_base:
            raise AutomationError("invalid_notification_backoff")
        interval = number(item.get("min_interval_seconds", 3 if provider == "telegram" else 1), 1, 86400)
        if provider == "telegram" and interval < 3:
            raise AutomationError("telegram_group_pacing")
        result.append(Channel(name, provider, secret, options, boolean(item.get("enabled", True)),
                              number(item.get("timeout_seconds", 15), 1, 30), number(item.get("max_attempts", 5), 1, 10),
                              number(item.get("batch_size", 64), 1, 256), number(item.get("max_parts", 8), 1, 16),
                              interval, retry_base, retry_max))
    return tuple(result)


@dataclass(frozen=True)
class Outcome:
    state: str
    error: str = ""
    delay: float = 0
    provider_wide: bool = False


def _seconds(value):
    # No Boolean, NaN/Infinity, scientific-notation or huge untrusted integer parsing.
    if isinstance(value, str) and len(value) <= 24 and re.fullmatch(r"[0-9]{1,12}(?:\.[0-9]{1,6})?", value):
        value = float(value)
    if type(value) is int and 0 <= value <= 10**12:
        return float(value)
    if type(value) is float and math.isfinite(value) and 0 <= value <= 10**12:
        return float(value)
    return None


def retry_delay(headers, payload, provider, timestamp):
    values = []
    hint = headers.get("retry-after")
    parsed = _seconds(hint)
    if parsed is None and isinstance(hint, str) and len(hint) <= 80:
        try:
            date = parsedate_to_datetime(hint)
            if date.tzinfo is not None:
                parsed = max(0, date.timestamp() - timestamp)
        except (ValueError, TypeError, OverflowError):
            pass
    if parsed is not None:
        values.append(parsed)
    if isinstance(payload, dict):
        hint = None
        if provider == "telegram" and isinstance(payload.get("parameters"), dict):
            hint = _seconds(payload["parameters"].get("retry_after"))
        if provider == "discord":
            hint = _seconds(payload.get("retry_after"))
        if provider == "matrix":
            raw = _seconds(payload.get("retry_after_ms"))
            hint = raw / 1000 if raw is not None else None
        if hint is not None:
            values.append(hint)
    return max(values, default=0)


def _json(body):
    try:
        if not isinstance(body, bytes) or len(body) > MAX_RESPONSE:
            return None
        value = decode_json(body)
        return value if isinstance(value, dict) else None
    except (ValueError, UnicodeError, RecursionError):
        return None


@dataclass(frozen=True, repr=False)
class BoundChannel:
    channel: Channel
    url: str = field(repr=False)
    token: str = field(default="", repr=False)
    destination: str = ""
    replay_scope: str = field(default="", repr=False)

    def __repr__(self):
        return "BoundChannel(<resolved>)"

    def send(self, text, transaction, *, transport_factory=HTTPS, timestamp=0, timeout=None):
        provider = self.channel.provider
        client = transport_factory(self.url, timeout=min(self.channel.timeout, timeout or self.channel.timeout),
                                   max_body=MAX_REQUEST, max_response=MAX_RESPONSE)
        headers = {"Content-Type": "application/json"}
        if provider == "matrix":
            headers["Authorization"] = "Bearer " + self.token
            path = self.url + "/_matrix/client/v3/rooms/" + quote(self.channel.options["room_id"], safe="")
            # A GET outcome cannot make the later POST/PUT ambiguous: it has not been sent.
            try:
                checked = client.request("GET", path + "/state/m.room.encryption", headers=headers)
                data = _json(checked.body)
            except (TransportError, OSError, ValueError):
                return Outcome("retryable", "matrix_encryption_check_failed")
            if checked.status == 200:
                return Outcome("permanent", "matrix_encrypted_room_unsupported")
            if checked.status == 429:
                return Outcome("retryable", "rate_limited", retry_delay(checked.headers, data, provider, timestamp))
            if checked.status == 408 or 500 <= checked.status < 600:
                return Outcome("retryable", "matrix_encryption_check_failed")
            if checked.status != 404 or not data or data.get("errcode") != "M_NOT_FOUND":
                return Outcome("permanent", "matrix_encryption_state_unknown")
            url = path + "/send/m.room.message/" + quote(transaction, safe="")
            method, payload = "PUT", {"body": text, "msgtype": "m.text", "m.mentions": {}}
        elif provider == "telegram":
            url, method = self.url, "POST"
            payload = {**self.channel.options, "text": text, "link_preview_options": {"is_disabled": True}}
        elif provider == "discord":
            url, method = self.url + "?wait=true", "POST"
            # Do not assume nonce/enforce_nonce on the separate webhook route.
            escaped = re.sub(r"([\\*_`~|>\[\]])", r"\\\1", text)
            payload = {"content": escaped, "allowed_mentions": {"parse": []}, "tts": False}
        else:
            url, method = self.url, "POST"
            fallback = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            payload = {"text": fallback, "blocks": [{"type": "section", "text": {"type": "plain_text", "text": text, "emoji": False}}]}
        try:
            result = client.request(method, url, headers=headers, body=json_bytes(payload))
        except TransportError as exc:
            return Outcome("retryable" if provider == "matrix" or not exc.transmitted else "ambiguous", "transport_failure")
        except (OSError, ValueError):
            # Unknown third-party/injected transport exception may follow a partial send.
            return Outcome("retryable" if provider == "matrix" else "ambiguous", "transport_failure")
        data = _json(result.body)
        limited = result.status == 429 or (provider == "telegram" and data and data.get("ok") is False and data.get("error_code") == 429)
        limited |= provider == "matrix" and data is not None and data.get("errcode") == "M_LIMIT_EXCEEDED"
        if limited:
            wide = provider in {"telegram", "slack"} or (provider == "discord" and
                    ((data and data.get("global") is True) or result.headers.get("x-ratelimit-global", "").lower() == "true"
                     or result.headers.get("x-ratelimit-scope") == "global"))
            return Outcome("retryable", "rate_limited", retry_delay(result.headers, data, provider, timestamp), bool(wide))
        if 400 <= result.status < 500 and result.status != 408:
            return Outcome("permanent", "provider_rejected")
        if result.status == 200:
            accepted = False
            if provider == "slack":
                accepted = isinstance(result.body, bytes) and len(result.body) < 32 and result.body.strip() == b"ok"
            elif provider == "telegram":
                accepted = bool(data and data.get("ok") is True and isinstance(data.get("result"), dict)
                                and type(data["result"].get("message_id")) is int)
            elif provider == "discord":
                accepted = bool(data and isinstance(data.get("id"), str) and re.fullmatch(r"[0-9]{1,20}", data["id"]))
            elif provider == "matrix":
                accepted = bool(data and isinstance(data.get("event_id"), str) and data["event_id"].startswith("$")
                                and len(data["event_id"].encode("utf-8")) <= 255)
            if accepted:
                cooldown = 0
                if provider == "discord" and result.headers.get("x-ratelimit-remaining") == "0":
                    cooldown = _seconds(result.headers.get("x-ratelimit-reset-after")) or 0
                return Outcome("accepted", delay=cooldown)
        if provider == "telegram" and data and data.get("ok") is False and data.get("error_code") in {400, 401, 403, 404}:
            return Outcome("permanent", "provider_rejected")
        return Outcome("retryable" if provider == "matrix" and (result.status >= 500 or result.status == 408 or 200 <= result.status < 300)
                       else "ambiguous", "provider_outcome_unknown")


def bind(channel: Channel) -> BoundChannel:
    value = channel.secret.resolve()
    if channel.provider == "telegram":
        if not re.fullmatch(r"[1-9][0-9]{0,19}:[A-Za-z0-9_-]{16,256}", value):
            raise AutomationError("invalid_telegram_token")
        url = "https://api.telegram.org/bot" + value + "/sendMessage"
        identity_options = dict(channel.options)
        chat = identity_options["chat_id"]
        if type(chat) is int or re.fullmatch(r"-?[1-9][0-9]{0,15}", chat):
            identity_options["chat_id"] = str(chat)
        identity = ["telegram", value.split(":", 1)[0], identity_options]
        token = ""
    elif channel.provider in {"discord", "slack"}:
        target = endpoint(value)
        expected = "discord.com" if channel.provider == "discord" else "hooks.slack.com"
        pattern = (r"/api(?:/v10)?/webhooks/([1-9][0-9]{0,19})/([A-Za-z0-9_.-]{16,256})" if channel.provider == "discord"
                   else r"/services/(T[A-Z0-9]{1,64})/(B[A-Z0-9]{1,64})/([A-Za-z0-9]{16,128})")
        match = re.fullmatch(pattern, target.path)
        if target.host != expected or target.port != 443 or not match or urlsplit(value).query:
            raise AutomationError("invalid_notification_webhook")
        if channel.provider == "discord":
            url = "https://discord.com/api/v10/webhooks/" + match[1] + "/" + match[2]
            identity = ["discord", match[1]]
        else:
            url, identity = value, ["slack", match[1], match[2]]
        token = ""
    else:
        url, token = channel.options["homeserver"], value
        identity = ["matrix", endpoint(url).origin, channel.options["room_id"]]
    # A refreshed token can represent the same Matrix device, but a new login can
    # represent a different one. Without verifying device identity, changed tokens
    # cannot automatically replay an already attempted transaction safely.
    replay_scope = digest(token.encode("ascii")) if channel.provider == "matrix" else ""
    return BoundChannel(channel, url, token, digest(json_bytes(identity)), replay_scope)


def split_message(text: str, channel: Channel) -> tuple[str, ...]:
    if not isinstance(text, str) or len(text) > 32768 or any(0xD800 <= ord(c) <= 0xDFFF for c in text):
        raise AutomationError("notification_text_limit")
    # Reserve room for part labels, Discord escaping and Slack's plain_text block cap.
    limit = 900 if channel.provider == "discord" else 2400 if channel.provider == "slack" else 3800
    chunks, current, used = [], [], 0
    for character in text:
        weight = 2 if ord(character) > 0xFFFF else 1
        if used + weight > limit:
            chunks.append("".join(current))
            current, used = [], 0
        current.append(character)
        used += weight
    if current:
        chunks.append("".join(current))
    if not chunks or len(chunks) > channel.max_parts:
        raise AutomationError("notification_parts_limit")
    return tuple((f"[{index + 1}/{len(chunks)}] " if len(chunks) > 1 else "") + part for index, part in enumerate(chunks))
