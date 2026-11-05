"""Watch alert channel configuration and secret references."""

from __future__ import annotations

import logging
import math
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from ..errors import ConfigurationError
from .catalog import canonical_language
from .rules import Rule

LOG = logging.getLogger("cvebeacon")

CHANNEL_TYPES = (
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
GROUPING_MODES = ("run", "event")
CHANNEL_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
ENV_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
TOPIC_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
CHAT_ID_PATTERN = re.compile(r"-?[1-9][0-9]{0,15}")
CHAT_NAME_PATTERN = re.compile(r"@[A-Za-z][A-Za-z0-9_]{3,63}")
HEADER_PATTERN = re.compile(r"[A-Za-z0-9-]{1,100}")
SECRET_FILE_LIMIT = 16 * 1024
COMMON_KEYS = {
    "type",
    "enabled",
    "grouping",
    "max_items",
    "min_interval_seconds",
    "timeout_seconds",
    "allow_insecure",
    "notify_reported",
    "language",
}
TYPE_KEYS = {
    "smtp": {
        "host",
        "port",
        "security",
        "username",
        "password_env",
        "password_file",
        "from",
        "to",
        "cc",
        "bcc",
        "format",
    },
    "graph": {
        "tenant_id",
        "client_id",
        "client_secret_env",
        "client_secret_file",
        "sender",
        "to",
        "cc",
        "bcc",
        "format",
    },
    "teams": {"webhook_url_env", "webhook_url_file"},
    "slack": {"webhook_url_env", "webhook_url_file"},
    "discord": {"webhook_url_env", "webhook_url_file"},
    "telegram": {"bot_token_env", "bot_token_file", "chat_id"},
    "matrix": {"homeserver", "room_id", "access_token_env", "access_token_file"},
    "ntfy": {"server", "topic", "token_env", "token_file", "priority"},
    "gotify": {"server", "app_token_env", "app_token_file", "priority"},
    "webhook": {
        "url",
        "url_env",
        "url_file",
        "header_name",
        "header_value_env",
        "header_value_file",
    },
}
SMTP_SECURITY = ("starttls", "tls", "none")
MESSAGE_FORMATS = ("text", "html")


def _fail(label: str, message: str) -> None:
    raise ConfigurationError(f"{label} {message}")


@dataclass(frozen=True, slots=True)
class SecretRef:
    """A secret named by an environment variable or a protected file."""

    label: str
    env: str | None = None
    file: Path | None = None

    def __repr__(self) -> str:
        return f"SecretRef({self.label!r})"

    def peek(self) -> str | None:
        """Return the secret when it is already readable, without raising."""
        if self.env:
            value = os.environ.get(self.env)
            if value is not None and value.strip():
                return value.strip()
        if self.file is not None:
            try:
                return self.file.read_text(encoding="utf-8").strip() or None
            except (OSError, UnicodeError):
                return None
        return None

    def resolve(self) -> str:
        value = self.peek()
        if value:
            return value
        named_env = (
            self.env
            if self.env is not None and ENV_NAME_PATTERN.fullmatch(self.env)
            else None
        )
        if named_env is not None and self.file is not None:
            raise ConfigurationError(
                f"{self.label} is not set (environment variable {named_env} "
                f"and its file are empty or unreadable)"
            )
        if named_env is not None:
            raise ConfigurationError(
                f"{self.label} is not set (environment variable {named_env})"
            )
        if self.env is not None and self.file is not None:
            raise ConfigurationError(
                f"{self.label} is not set (its environment variable and file "
                "are empty or unreadable)"
            )
        if self.env is not None:
            raise ConfigurationError(f"{self.label} is not set")
        raise ConfigurationError(f"{self.label} is empty or unreadable")


@dataclass(frozen=True, slots=True)
class ChannelConfig:
    name: str
    type: str
    enabled: bool = True
    grouping: str = "run"
    max_items: int = 20
    min_interval_seconds: float = 0.0
    timeout_seconds: float = 30.0
    notify_reported: bool = False
    format: str = "text"
    language: str | None = None
    options: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @property
    def label(self) -> str:
        return f"watch channel {self.name!r}"

    def secret(self, key: str) -> SecretRef | None:
        value = self.options.get(key)
        return value if isinstance(value, SecretRef) else None


def _table(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(label, "must be a table")
    return value


def _string(
    table: Mapping[str, Any],
    key: str,
    label: str,
    *,
    required: bool = False,
    maximum: int = 1000,
) -> str | None:
    value = table.get(key)
    if value is None:
        if required:
            _fail(f"{label} {key}", "is required")
        return None
    if not isinstance(value, str):
        _fail(f"{label} {key}", "must be a string")
    text = value.strip()
    if not text:
        if required:
            _fail(f"{label} {key}", "must not be empty")
        return None
    if len(text) > maximum:
        _fail(f"{label} {key}", f"must be at most {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        _fail(f"{label} {key}", "must not contain control characters")
    return text


def _boolean(table: Mapping[str, Any], key: str, label: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        _fail(f"{label} {key}", "must be true or false")
    return value


def _integer(
    table: Mapping[str, Any],
    key: str,
    label: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{label} {key}", f"must be an integer from {minimum} to {maximum}")
    if not minimum <= value <= maximum:
        _fail(f"{label} {key}", f"must be an integer from {minimum} to {maximum}")
    return value


def _number(
    table: Mapping[str, Any],
    key: str,
    label: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{label} {key}", f"must be a number from {minimum:g} to {maximum:g}")
    try:
        number = float(value)
    except OverflowError:
        _fail(f"{label} {key}", f"must be a number from {minimum:g} to {maximum:g}")
    if not math.isfinite(number) or not minimum <= number <= maximum:
        _fail(f"{label} {key}", f"must be a number from {minimum:g} to {maximum:g}")
    return number


def _string_list(
    table: Mapping[str, Any],
    key: str,
    label: str,
    *,
    required: bool = False,
    maximum: int = 100,
) -> tuple[str, ...]:
    value = table.get(key)
    if value is None:
        if required:
            _fail(f"{label} {key}", "is required")
        return ()
    if not isinstance(value, list):
        _fail(f"{label} {key}", "must be a list of strings")
    if required and not value:
        _fail(f"{label} {key}", "must contain at least one item")
    if len(value) > maximum:
        _fail(f"{label} {key}", f"must contain at most {maximum} items")
    output: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            _fail(f"{label} {key}[{index}]", "must be a nonempty string")
        text = item.strip()
        if len(text) > 320 or any(ord(character) < 32 for character in text):
            _fail(f"{label} {key}[{index}]", "is not a valid address")
        if text not in output:
            output.append(text)
    return tuple(output)


def _email_addresses(
    table: Mapping[str, Any], key: str, label: str, *, required: bool
) -> tuple[str, ...]:
    values = _string_list(table, key, label, required=required)
    for index, value in enumerate(values):
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            _fail(f"{label} {key}[{index}]", "is not a valid email address")
    return values


def _protected_file(path: Path, label: str) -> None:
    try:
        details = path.stat()
    except OSError:
        _fail(label, "file cannot be read")
    if not path.is_file():
        _fail(label, "file cannot be read")
    if details.st_size > SECRET_FILE_LIMIT:
        _fail(label, f"file must be at most {SECRET_FILE_LIMIT} bytes")
    if os.name == "posix" and stat.S_IMODE(details.st_mode) & 0o077:
        _fail(label, "file must not be group or other accessible")


def _secret(
    table: Mapping[str, Any],
    env_key: str,
    file_key: str,
    label: str,
    base: Path,
    *,
    required: bool,
) -> SecretRef | None:
    env_name = _string(table, env_key, label, maximum=200)
    if env_name is not None and ENV_NAME_PATTERN.fullmatch(env_name) is None:
        # Never repeat the value: a pasted secret must not reach logs or errors.
        _fail(f"{label} {env_key}", "must be an environment variable name")
    file_value = _string(table, file_key, label, maximum=4096)
    if env_name is None and file_value is None:
        if required:
            _fail(label, f"requires {env_key} or {file_key}")
        return None
    path: Path | None = None
    if file_value is not None:
        path = Path(file_value).expanduser()
        if not path.is_absolute():
            path = base / path
        path = path.resolve()
        _protected_file(path, f"{label} {file_key}")
    return SecretRef(label, env_name, path)


def _https_url(value: str, label: str, *, allow_http: bool = False) -> None:
    try:
        parts = urlsplit(value)
    except ValueError:
        _fail(label, "is not a valid URL")
    allowed = {"https", "http"} if allow_http else {"https"}
    if (
        parts.scheme not in allowed
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        _fail(label, "must be an HTTPS URL" if not allow_http else "must be an HTTP or HTTPS URL")


def _validate_webhook_host(value: str, channel_type: str, label: str) -> None:
    _https_url(value, label)
    parts = urlsplit(value)
    if channel_type == "slack":
        if parts.hostname != "hooks.slack.com" or not parts.path.startswith("/services/"):
            _fail(label, "must be an https://hooks.slack.com/services/... URL")
        if parts.query or parts.fragment:
            _fail(label, "must not contain a query or fragment")
    elif channel_type == "discord":
        if parts.hostname not in {"discord.com", "discordapp.com"}:
            _fail(label, "must be a Discord webhook URL")
        if not re.match(r"/api(?:/v10)?/webhooks/", parts.path):
            _fail(label, "must be an https://discord.com/api/webhooks/... URL")
        if parts.query or parts.fragment:
            _fail(label, "must not contain a query or fragment")


def _matrix_homeserver(value: str, label: str) -> None:
    _https_url(value, label)
    parts = urlsplit(value)
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        _fail(label, "must be an HTTPS origin without a path, query or fragment")


def _common(table: Mapping[str, Any], label: str, channel_type: str) -> dict[str, Any]:
    enabled = _boolean(table, "enabled", label, True)
    grouping = _string(table, "grouping", label, maximum=20) or "run"
    grouping = grouping.casefold()
    if grouping not in GROUPING_MODES:
        _fail(f"{label} grouping", "must be run or event")
    max_items = _integer(table, "max_items", label, 20, 1, 100)
    timeout = _number(table, "timeout_seconds", label, 30.0, 1.0, 300.0)
    default_interval = 3.0 if channel_type == "telegram" else 0.0
    interval = _number(
        table, "min_interval_seconds", label, default_interval, 0.0, 3600.0
    )
    if channel_type == "telegram" and interval < 3.0:
        _fail(f"{label} min_interval_seconds", "must be at least 3 for Telegram")
    language: str | None = None
    if "language" in table:
        language = _string(table, "language", label, maximum=20)
        if language is None:
            _fail(f"{label} language", "must not be empty")
        language = canonical_language(language, label=f"{label} language")
    if "format" in table:
        message_format = _string(table, "format", label, maximum=20)
        if message_format is None:
            _fail(f"{label} format", "must not be empty")
    else:
        message_format = "text"
    message_format = message_format.casefold()
    if message_format not in MESSAGE_FORMATS:
        _fail(f"{label} format", "must be text or html")
    return {
        "enabled": enabled,
        "grouping": grouping,
        "max_items": max_items,
        "timeout_seconds": timeout,
        "min_interval_seconds": interval,
        "allow_insecure": _boolean(table, "allow_insecure", label, False),
        "notify_reported": _boolean(table, "notify_reported", label, False),
        "format": message_format,
        "language": language,
    }


def _parse_smtp(
    table: Mapping[str, Any], label: str, base: Path, common: dict[str, Any]
) -> dict[str, Any]:
    host = _string(table, "host", label, required=True, maximum=253)
    security = (_string(table, "security", label, maximum=20) or "starttls").casefold()
    if security not in SMTP_SECURITY:
        _fail(f"{label} security", "must be starttls, tls or none")
    default_port = {"starttls": 587, "tls": 465, "none": 25}[security]
    port = _integer(table, "port", label, default_port, 1, 65535)
    allow_insecure = bool(common["allow_insecure"])
    if security == "none" and not allow_insecure:
        _fail(f"{label} security", "none requires allow_insecure = true")
    if security == "none":
        LOG.warning("%s uses SMTP without TLS; enable starttls or tls", label)
    username = _string(table, "username", label, maximum=320)
    password = _secret(
        table, "password_env", "password_file", f"{label} password", base, required=False
    )
    sender = _string(table, "from", label, required=True, maximum=320)
    recipients = _email_addresses(table, "to", label, required=True)
    cc = _email_addresses(table, "cc", label, required=False)
    bcc = _email_addresses(table, "bcc", label, required=False)
    return {
        **common,
        "host": host,
        "port": port,
        "security": security,
        "username": username,
        "password": password,
        "sender": sender,
        "to": recipients,
        "cc": cc,
        "bcc": bcc,
    }


def _parse_graph(
    table: Mapping[str, Any], label: str, base: Path, common: dict[str, Any]
) -> dict[str, Any]:
    return {
        **common,
        "tenant_id": _string(table, "tenant_id", label, required=True, maximum=200),
        "client_id": _string(table, "client_id", label, required=True, maximum=200),
        "client_secret": _secret(
            table,
            "client_secret_env",
            "client_secret_file",
            f"{label} client_secret",
            base,
            required=True,
        ),
        "sender": _string(table, "sender", label, required=True, maximum=320),
        "to": _email_addresses(table, "to", label, required=True),
        "cc": _email_addresses(table, "cc", label, required=False),
        "bcc": _email_addresses(table, "bcc", label, required=False),
    }


def _parse_webhook_channel(
    table: Mapping[str, Any],
    label: str,
    base: Path,
    common: dict[str, Any],
    channel_type: str,
) -> dict[str, Any]:
    secret = _secret(
        table,
        "webhook_url_env",
        "webhook_url_file",
        f"{label} webhook_url",
        base,
        required=True,
    )
    value = secret.peek() if secret is not None else None
    if value is not None:
        _validate_webhook_host(value, channel_type, f"{label} webhook_url")
    return {**common, "webhook_url": secret}


def _parse_telegram(
    table: Mapping[str, Any], label: str, base: Path, common: dict[str, Any]
) -> dict[str, Any]:
    token = _secret(
        table, "bot_token_env", "bot_token_file", f"{label} bot_token", base, required=True
    )
    raw_chat = table.get("chat_id")
    if isinstance(raw_chat, bool):
        _fail(f"{label} chat_id", "must be a chat id or channel name")
    if isinstance(raw_chat, int):
        if raw_chat == 0 or not -(2**52) < raw_chat < 2**52:
            _fail(f"{label} chat_id", "must be a chat id or channel name")
        chat_id = str(raw_chat)
    elif isinstance(raw_chat, str):
        text = raw_chat.strip()
        if not (CHAT_ID_PATTERN.fullmatch(text) or CHAT_NAME_PATTERN.fullmatch(text)):
            _fail(f"{label} chat_id", "must be a chat id or channel name")
        chat_id = text
    else:
        _fail(f"{label} chat_id", "must be a chat id or channel name")
    return {**common, "bot_token": token, "chat_id": chat_id}


def _parse_matrix(
    table: Mapping[str, Any], label: str, base: Path, common: dict[str, Any]
) -> dict[str, Any]:
    homeserver = _string(table, "homeserver", label, required=True, maximum=2000)
    _matrix_homeserver(homeserver, f"{label} homeserver")
    room_id = _string(table, "room_id", label, required=True, maximum=255)
    if (
        not room_id.startswith("!")
        or ":" not in room_id
        or any(ord(character) <= 32 or ord(character) >= 127 for character in room_id)
        or any(character in room_id for character in "/?#\\")
    ):
        _fail(f"{label} room_id", "must be a Matrix room id such as !room:example.org")
    token = _secret(
        table,
        "access_token_env",
        "access_token_file",
        f"{label} access_token",
        base,
        required=True,
    )
    return {
        **common,
        "homeserver": homeserver.rstrip("/"),
        "room_id": room_id,
        "access_token": token,
    }


def _parse_ntfy(
    table: Mapping[str, Any], label: str, base: Path, common: dict[str, Any]
) -> dict[str, Any]:
    server = (
        _string(table, "server", label, maximum=2000) or "https://ntfy.sh"
    ).rstrip("/")
    _https_url(server, f"{label} server", allow_http=bool(common["allow_insecure"]))
    topic = _string(table, "topic", label, required=True, maximum=64)
    if TOPIC_PATTERN.fullmatch(topic) is None:
        _fail(f"{label} topic", "must contain only letters, digits, underscores or hyphens")
    token = _secret(
        table, "token_env", "token_file", f"{label} token", base, required=False
    )
    return {
        **common,
        "server": server,
        "topic": topic,
        "token": token,
        "priority": _integer(table, "priority", label, 3, 1, 5),
    }


def _parse_gotify(
    table: Mapping[str, Any], label: str, base: Path, common: dict[str, Any]
) -> dict[str, Any]:
    server = (_string(table, "server", label, required=True, maximum=2000) or "").rstrip("/")
    _https_url(server, f"{label} server")
    token = _secret(
        table,
        "app_token_env",
        "app_token_file",
        f"{label} app_token",
        base,
        required=True,
    )
    return {
        **common,
        "server": server,
        "app_token": token,
        "priority": _integer(table, "priority", label, 5, -2, 10),
    }


def _parse_webhook(
    table: Mapping[str, Any], label: str, base: Path, common: dict[str, Any]
) -> dict[str, Any]:
    url = _string(table, "url", label, maximum=4000)
    url_secret = _secret(
        table,
        "url_env",
        "url_file",
        f"{label} url",
        base,
        required=False,
    )
    if url is not None and url_secret is not None:
        _fail(f"{label} url", "must be given as url or url_env/url_file, not both")
    if url is None and url_secret is None:
        _fail(f"{label} url", "requires url, url_env or url_file")
    target = url if url is not None else url_secret.peek()
    if target is not None:
        _https_url(target, f"{label} url", allow_http=bool(common["allow_insecure"]))
    header_name = _string(table, "header_name", label, maximum=100)
    header_value = _secret(
        table,
        "header_value_env",
        "header_value_file",
        f"{label} header_value",
        base,
        required=False,
    )
    if header_name is not None:
        if HEADER_PATTERN.fullmatch(header_name) is None:
            _fail(f"{label} header_name", "must be an HTTP header name")
        if header_value is None:
            _fail(f"{label} header_name", "requires header_value_env or header_value_file")
    elif header_value is not None:
        _fail(f"{label} header_value_env", "requires header_name")
    return {
        **common,
        "url": url if url is not None else url_secret,
        "header_name": header_name,
        "header_value": header_value,
    }


def parse_channels(raw: Any, *, base: Path) -> tuple[ChannelConfig, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        raise ConfigurationError("watch.channels must be a table")
    output: list[ChannelConfig] = []
    seen: set[str] = set()
    for name, value in raw.items():
        if CHANNEL_NAME_PATTERN.fullmatch(name) is None:
            _fail(
                "watch channel name",
                f"{name!r} must start with a letter or digit and contain at most "
                "64 letters, digits, underscores, dots or hyphens",
            )
        folded = name.casefold()
        if folded in seen:
            _fail(f"watch channel {name!r}", "is a duplicate name")
        seen.add(folded)
        label = f"watch channel {name!r}"
        table = _table(value, label)
        channel_type = (_string(table, "type", label, required=True, maximum=20) or "").casefold()
        if channel_type not in CHANNEL_TYPES:
            _fail(f"{label} type", "must be one of " + ", ".join(CHANNEL_TYPES))
        unknown = sorted(set(table) - COMMON_KEYS - TYPE_KEYS[channel_type])
        if unknown:
            _fail(label, "has unknown key " + ", ".join(repr(key) for key in unknown))
        common = _common(table, label, channel_type)
        if channel_type == "smtp":
            options = _parse_smtp(table, label, base, common)
        elif channel_type == "graph":
            options = _parse_graph(table, label, base, common)
        elif channel_type in {"teams", "slack", "discord"}:
            options = _parse_webhook_channel(
                table, label, base, common, channel_type
            )
        elif channel_type == "telegram":
            options = _parse_telegram(table, label, base, common)
        elif channel_type == "matrix":
            options = _parse_matrix(table, label, base, common)
        elif channel_type == "ntfy":
            options = _parse_ntfy(table, label, base, common)
        elif channel_type == "gotify":
            options = _parse_gotify(table, label, base, common)
        else:
            options = _parse_webhook(table, label, base, common)
        output.append(
            ChannelConfig(
                name=name,
                type=channel_type,
                enabled=bool(options["enabled"]),
                grouping=str(options["grouping"]),
                max_items=int(options["max_items"]),
                min_interval_seconds=float(options["min_interval_seconds"]),
                timeout_seconds=float(options["timeout_seconds"]),
                notify_reported=bool(options["notify_reported"]),
                format=str(options["format"]),
                language=options["language"],
                options=options,
            )
        )
    return tuple(output)


def validate_rule_channels(rules: Iterable[Rule], channels: Iterable[ChannelConfig]) -> None:
    configured = {channel.name for channel in channels}
    for rule in rules:
        for channel in rule.channels:
            if channel not in configured:
                raise ConfigurationError(
                    f"watch rule {rule.name!r} references channel {channel!r} "
                    "which is not configured in watch.channels"
                )


def channel_map(channels: Iterable[ChannelConfig]) -> dict[str, ChannelConfig]:
    return {channel.name: channel for channel in channels}


def validate_webhook_url(value: str, channel_type: str, label: str) -> None:
    """Re-check a webhook URL after its secret was resolved at send time."""
    _validate_webhook_host(value, channel_type, label)
