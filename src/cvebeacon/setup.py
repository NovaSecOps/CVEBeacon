"""Interactive configuration wizard."""

from __future__ import annotations

import getpass
import json
import os
import platform
import re
import shlex
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import InventoryConfig, load_config
from .errors import CVEBeaconError, ConfigurationError, SchedulingError
from .http import HttpClient
from .inventory import load_inventory
from .scheduling import default_command, describe, install, make_plan, parse_times
from .watch.channels import (
    CHANNEL_NAME_PATTERN,
    CHANNEL_TYPES,
    CHAT_ID_PATTERN,
    CHAT_NAME_PATTERN,
    ENV_NAME_PATTERN,
    HEADER_PATTERN,
    TOPIC_PATTERN,
)
from .watch import delivery as watch_delivery
from .watch.rules import NAME_PATTERN

SOURCE_INFO = (
    ("nvd", "NVD CVE records, CVSS scores and CPE products (required)"),
    ("euvd", "ENISA EU vulnerability records and exploitation dates"),
    ("cisa_kev", "CISA Known Exploited Vulnerabilities catalog"),
    ("eu_kev", "ENISA EU KEV catalog"),
    ("epss", "FIRST EPSS exploit-probability scores"),
)
CHANNEL_INFO = (
    ("smtp", "email over SMTP"),
    ("graph", "Microsoft 365 Graph mail"),
    ("teams", "Microsoft Teams webhook"),
    ("slack", "Slack webhook"),
    ("discord", "Discord webhook"),
    ("telegram", "Telegram bot"),
    ("matrix", "Matrix room"),
    ("ntfy", "ntfy topic"),
    ("gotify", "Gotify server"),
    ("webhook", "generic JSON webhook"),
)
RULE_PRESETS = (
    ("critical", "CVSS at least 9.0"),
    ("likely-exploited", "EPSS at least 0.5"),
    ("kev-any", "any CISA or EU KEV entry"),
    ("kev-and-severe", "KEV and (CVSS at least 8.0 or EPSS at least 0.3)"),
    ("actively-exploited", "active exploitation evidence"),
    ("custom", "enter your own thresholds"),
)
CHANNEL_ENV_DEFAULTS = {
    "teams": "CVEBEACON_TEAMS_WEBHOOK_URL",
    "slack": "CVEBEACON_SLACK_WEBHOOK_URL",
    "discord": "CVEBEACON_DISCORD_WEBHOOK_URL",
    "telegram": "CVEBEACON_TELEGRAM_BOT_TOKEN",
    "matrix": "CVEBEACON_MATRIX_ACCESS_TOKEN",
    "gotify": "CVEBEACON_GOTIFY_TOKEN",
    "ntfy": "CVEBEACON_NTFY_TOKEN",
    "webhook": "CVEBEACON_HOOK_SECRET",
}


class SetupCancelled(Exception):
    """The user interrupted the wizard."""


@dataclass
class SecretChoice:
    env: str | None = None
    file: str | None = None
    value: str | None = field(default=None, repr=False)


@dataclass
class NvdKey:
    kind: str = "skip"
    env: str = "NVD_API_KEY"
    file: str | None = None
    value: str | None = field(default=None, repr=False)


@dataclass
class ChannelDraft:
    name: str
    kind: str
    values: dict[str, Any] = field(default_factory=dict)
    secret_fields: list[tuple[str, SecretChoice]] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RuleDraft:
    name: str
    condition: dict[str, Any]
    old_cves: str
    channels: tuple[str, ...] = ()


@dataclass(frozen=True)
class InventoryChoice:
    path: str
    format: str


@dataclass(frozen=True)
class WatchSettings:
    sources: tuple[str, ...]
    initial: str
    backfill_days: int


def send_test(config, http, channel_name):
    """Indirection so tests and callers can replace the delivery path."""
    return watch_delivery.send_test(config, http, channel_name)


def _one_line(value: object) -> str:
    return " ".join(str(value).split())


def _ask_line(label: str, default: str | None) -> str:
    shown = f" [{default}]" if default is not None else " []"
    try:
        return input(f"{label}{shown}: ").strip()
    except (EOFError, KeyboardInterrupt):
        raise SetupCancelled from None


def _ask_text(label: str, default: str = "", *, required: bool = False) -> str:
    while True:
        value = _ask_line(label, default)
        if not value:
            value = default
        if required and not value:
            print(f"{label} is required.")
            continue
        return value


def _ask_validated(label: str, default: str, validator) -> str:
    while True:
        value = _ask_text(label, default, required=True)
        try:
            return validator(value)
        except (ValueError, CVEBeaconError) as exc:
            print(_one_line(exc))


def _ask_bool(label: str, default: bool) -> bool:
    shown = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            answer = input(f"{label} {shown}: ").strip().casefold()
        except (EOFError, KeyboardInterrupt):
            raise SetupCancelled from None
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def _ask_choice(label: str, options: tuple[str, ...], default: str) -> str:
    shown = "/".join(options)
    while True:
        value = _ask_text(f"{label} ({shown})", default, required=True).casefold()
        if value in options:
            return value
        print(f"Choose one of: {shown}.")


def _ask_number(label: str, default: float, minimum: float, maximum: float) -> float:
    while True:
        value = _ask_text(label, f"{default:g}", required=True)
        try:
            number = float(value)
        except ValueError:
            print(f"Enter a number from {minimum:g} to {maximum:g}.")
            continue
        if not minimum <= number <= maximum:
            print(f"Enter a number from {minimum:g} to {maximum:g}.")
            continue
        return number


def _ask_optional_number(label: str, minimum: float, maximum: float) -> float | None:
    while True:
        value = _ask_text(label, "", required=False)
        if not value:
            return None
        try:
            number = float(value)
        except ValueError:
            print(f"Enter a number from {minimum:g} to {maximum:g}, or leave it blank.")
            continue
        if not minimum <= number <= maximum:
            print(f"Enter a number from {minimum:g} to {maximum:g}, or leave it blank.")
            continue
        return number


def _ask_int(label: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        value = _ask_text(label, str(default), required=True)
        try:
            number = int(value)
        except ValueError:
            print(f"Enter a whole number from {minimum} to {maximum}.")
            continue
        if not minimum <= number <= maximum:
            print(f"Enter a whole number from {minimum} to {maximum}.")
            continue
        return number


def _ask_list(
    label: str,
    default: str,
    *,
    validator=None,
    required: bool = True,
) -> list[str]:
    while True:
        value = _ask_text(label, default, required=required)
        items = [item.strip() for item in value.split(",") if item.strip()]
        if required and not items:
            print(f"{label} is required.")
            continue
        if not items:
            return []
        try:
            for item in items:
                if validator is not None:
                    validator(item)
        except ValueError as exc:
            print(_one_line(exc))
            continue
        output: list[str] = []
        for item in items:
            if item not in output:
                output.append(item)
        return output


def _validate_email(value: str) -> str:
    text = value.strip()
    if "@" not in text or text.startswith("@") or text.endswith("@"):
        raise ValueError(f"{text!r} is not a valid email address.")
    return text


def _validate_https_url(value: str) -> str:
    text = value.strip()
    if not text.startswith("https://") or len(text) <= len("https://"):
        raise ValueError("Enter an HTTPS URL.")
    return text


def _validate_env_name(value: str) -> str:
    text = value.strip()
    if ENV_NAME_PATTERN.fullmatch(text) is None:
        raise ValueError("Use an environment variable name such as CVEBEACON_SMTP_PASSWORD.")
    return text


def _validate_channel_name(value: str, existing: list[str]) -> str:
    text = value.strip()
    if CHANNEL_NAME_PATTERN.fullmatch(text) is None:
        raise ValueError(
            "Channel names start with a letter or digit and use at most 64 letters, "
            "digits, underscores, dots or hyphens."
        )
    if text.casefold() in {item.casefold() for item in existing}:
        raise ValueError(f"Channel name {text!r} is already used.")
    return text


def _validate_rule_name(value: str, existing: set[str]) -> str:
    text = value.strip()
    if NAME_PATTERN.fullmatch(text) is None:
        raise ValueError(
            "Rule names start with a letter or digit and use at most 64 letters, "
            "digits, spaces, underscores, dots or hyphens."
        )
    if text.casefold() in existing:
        raise ValueError(f"Rule name {text!r} is already used.")
    return text


def _stored_path(value: str, base: Path) -> tuple[str, Path]:
    path = Path(value).expanduser()
    resolved = (path if path.is_absolute() else base / path).resolve()
    try:
        relative = Path(os.path.relpath(resolved, base.resolve()))
    except ValueError:
        return resolved.as_posix(), resolved
    return relative.as_posix(), resolved


def _infer_format(path: Path) -> str:
    return {
        "csv": "csv",
        "xlsx": "xlsx",
        "json": "json",
        "yaml": "yaml",
        "yml": "yaml",
    }.get(path.suffix.casefold().lstrip("."), "auto")


def _ask_mode() -> str:
    print("Mode:")
    print("  inventory - scan a component inventory")
    print("  watch     - monitor CVE changes and send alerts")
    print("  both      - scan an inventory and monitor CVE changes")
    return _ask_choice("Mode", ("inventory", "watch", "both"), "watch")


def _ask_inventory(base: Path) -> InventoryChoice:
    while True:
        raw = _ask_text("Inventory file path", "inventory.csv", required=True)
        stored, resolved = _stored_path(raw, base)
        default_format = _infer_format(resolved)
        inventory_format = _ask_choice(
            "Inventory format", ("auto", "csv", "xlsx", "json", "yaml"), default_format
        )
        try:
            assets = load_inventory(
                InventoryConfig(path=resolved, format=inventory_format)
            )
        except CVEBeaconError as exc:
            print(f"Inventory error: {_one_line(exc)}")
            if not _ask_bool("Choose another inventory file?", True):
                return InventoryChoice(stored, inventory_format)
            continue
        print(f"Inventory: {len(assets)} asset(s).")
        return InventoryChoice(stored, inventory_format)


def _ask_sources() -> tuple[str, ...]:
    print("Watch sources:")
    for name, description in SOURCE_INFO:
        suffix = " (always enabled)" if name == "nvd" else ""
        print(f"  {name}: {description}{suffix}")
    enabled = ["nvd"]
    for name, _description in SOURCE_INFO[1:]:
        if _ask_bool(f"Enable {name.upper()}?", True):
            enabled.append(name)
    if "epss" not in enabled:
        print("Warning: EPSS is disabled; epss_min rules will be unavailable.")
    return tuple(enabled)


def _ask_watch_settings() -> WatchSettings:
    sources = _ask_sources()
    initial = _ask_choice(
        "First run history", ("baseline", "backfill", "full"), "baseline"
    )
    backfill_days = 7
    if initial == "backfill":
        backfill_days = _ask_int("Backfill days", 7, 1, 120)
    elif initial == "full":
        print(
            "Full history downloads many years of NVD and EUVD data; expect "
            "several hours and a large download. The first watch sync asks again."
        )
    return WatchSettings(sources, initial, backfill_days)


def _ask_nvd_key(base: Path) -> NvdKey:
    print("An NVD API key is optional; it raises the request limit and speeds up syncs.")
    choice = _ask_choice("NVD API key", ("skip", "env", "file"), "skip")
    if choice == "env":
        name = _ask_validated(
            "NVD API key environment variable", "NVD_API_KEY", _validate_env_name
        )
        return NvdKey("env", env=name)
    if choice == "file":
        value = _ask_secret_value("NVD API key")
        stored = _secret_relative(base, "nvd", "api-key")
        return NvdKey("file", file=stored, value=value)
    return NvdKey()


def _ask_rule_selection(epss_enabled: bool) -> list[int]:
    print("Rules:")
    for index, (name, description) in enumerate(RULE_PRESETS, start=1):
        print(f"  {index}. {name}: {description}")
    while True:
        raw = _ask_text("Rule numbers (comma-separated)", "1", required=True)
        try:
            selected = sorted({int(part.strip()) for part in raw.split(",") if part.strip()})
        except ValueError:
            print("Choose numbers from 1 to 6.")
            continue
        if not selected or any(not 1 <= value <= len(RULE_PRESETS) for value in selected):
            print("Choose numbers from 1 to 6.")
            continue
        if not epss_enabled and any(value in {2, 4} for value in selected):
            print("Those rules use EPSS, which is disabled. Choose another rule or enable EPSS.")
            continue
        return selected


def _custom_condition(epss_enabled: bool) -> dict[str, Any]:
    while True:
        cvss = _ask_optional_number("CVSS minimum (blank for none)", 0.0, 10.0)
        epss = _ask_optional_number("EPSS minimum (blank for none)", 0.0, 1.0)
        if epss is not None and not epss_enabled:
            print("EPSS is disabled; leave the EPSS minimum blank or enable EPSS.")
            continue
        combination = "and"
        if cvss is not None and epss is not None:
            combination = _ask_choice("Combine CVSS and EPSS", ("and", "or"), "and")
        kev = _ask_bool("Require a KEV entry?", False)
        leaves: list[dict[str, Any]] = []
        if cvss is not None:
            leaves.append({"cvss_min": cvss})
        if epss is not None:
            leaves.append({"epss_min": epss})
        if not leaves and not kev:
            print("Choose at least one condition.")
            continue
        if len(leaves) == 2:
            condition: dict[str, Any] = (
                {"all": leaves} if combination == "and" else {"any": leaves}
            )
        elif leaves:
            condition = leaves[0]
        else:
            condition = {}
        if kev:
            condition = (
                {"all": [condition, {"kev": "any"}]}
                if condition
                else {"kev": "any"}
            )
        return condition


def _preset_condition(index: int, epss_enabled: bool) -> dict[str, Any]:
    if index == 1:
        return {"cvss_min": _ask_number("CVSS minimum", 9.0, 0.0, 10.0)}
    if index == 2:
        return {"epss_min": _ask_number("EPSS minimum", 0.5, 0.0, 1.0)}
    if index == 3:
        return {"kev": "any"}
    if index == 4:
        cvss = _ask_number("CVSS minimum", 8.0, 0.0, 10.0)
        epss = _ask_number("EPSS minimum", 0.3, 0.0, 1.0)
        return {
            "all": [
                {"kev": "any"},
                {"any": [{"cvss_min": cvss}, {"epss_min": epss}]},
            ]
        }
    if index == 5:
        return {"exploitation": "active"}
    return _custom_condition(epss_enabled)


def _ask_rules(settings: WatchSettings) -> list[RuleDraft]:
    epss_enabled = "epss" in settings.sources
    selected = _ask_rule_selection(epss_enabled)
    rules: list[RuleDraft] = []
    used: set[str] = set()
    for index in selected:
        preset_name = RULE_PRESETS[index - 1][0]
        condition = _preset_condition(index, epss_enabled)
        name = _ask_validated(
            "Rule name", preset_name, lambda value: _validate_rule_name(value, used)
        )
        used.add(name.casefold())
        vendors = _ask_list(
            "Vendor filter (comma-separated, blank for none)", "", required=False
        )
        if vendors:
            condition = {"all": [condition, {"vendor": vendors}]}
        old_cves = _ask_choice(
            "Old CVEs", ("digest", "alert", "ignore"), "digest"
        )
        rules.append(RuleDraft(name, condition, old_cves))
    return rules


def _ask_channel_type() -> str:
    print("Channel types:")
    for index, (name, description) in enumerate(CHANNEL_INFO, start=1):
        print(f"  {index}. {name}: {description}")
    while True:
        value = _ask_text("Channel type", "smtp", required=True).casefold()
        if value.isdigit() and 1 <= int(value) <= len(CHANNEL_INFO):
            return CHANNEL_INFO[int(value) - 1][0]
        if value in CHANNEL_TYPES:
            return value
        print("Choose a channel type from the list.")


def _ask_secret_value(label: str) -> str:
    while True:
        try:
            value = getpass.getpass(f"{label} []: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise SetupCancelled from None
        if value:
            return value
        print(f"{label} is required.")


def _secret_relative(base: Path, channel: str, field_name: str) -> str:
    directory = base / "secrets" if os.name == "posix" else base
    filename = re.sub(r"[^A-Za-z0-9_.-]", "-", f"{channel}-{field_name}")
    path = directory / filename
    try:
        relative = path.relative_to(base)
    except ValueError:
        relative = path
    return relative.as_posix()


def _ask_secret_choice(
    base: Path,
    channel: str,
    field_name: str,
    default_env: str,
    *,
    required: bool = True,
) -> SecretChoice | None:
    if not required and not _ask_bool(f"Use a {field_name.replace('_', ' ')}?", False):
        return None
    method = _ask_choice(
        f"Store the {field_name.replace('_', ' ')} in", ("env", "file"), "env"
    )
    if method == "env":
        name = _ask_validated(
            "Environment variable name", default_env, _validate_env_name
        )
        return SecretChoice(env=name)
    value = _ask_secret_value(f"Secret value for {channel} {field_name}")
    return SecretChoice(file=_secret_relative(base, channel, field_name), value=value)


def _common_comments(kind: str, *, allow_insecure: bool = False) -> list[str]:
    interval = 3 if kind == "telegram" else 0
    return [
        '# grouping = "run"',
        "# max_items = 20",
        f"# min_interval_seconds = {interval}",
        "# timeout_seconds = 30",
        f"# allow_insecure = {str(allow_insecure).lower()}",
    ]


def _ask_smtp(base: Path, name: str) -> ChannelDraft:
    preset = _ask_choice(
        "Email preset",
        ("gmail", "m365-smtp", "m365-graph", "custom"),
        "gmail",
    )
    if preset == "m365-graph":
        return _ask_graph(base, name)
    if preset == "gmail":
        host, port, security = "smtp.gmail.com", 587, "starttls"
        print("Gmail needs an app password for SMTP authentication.")
    elif preset == "m365-smtp":
        host, port, security = "smtp.office365.com", 587, "starttls"
        print(
            "Microsoft 365 SMTP requires SMTP AUTH on the mailbox; use the Graph "
            "preset if it is disabled."
        )
    else:
        host = _ask_text("SMTP host", "smtp.example.com", required=True)
        port = _ask_int("SMTP port", 587, 1, 65535)
        security = _ask_choice("SMTP security", ("starttls", "tls", "none"), "starttls")
    sender = _ask_validated("From address", "alerts@example.com", _validate_email)
    recipients = _ask_list("To addresses", "security@example.com", validator=_validate_email)
    username = _ask_text(
        "SMTP username (use - for no authentication)", sender, required=False
    )
    if username == "-":
        username = ""
    draft = ChannelDraft(
        name,
        "smtp",
        {
            "type": "smtp",
            "host": host,
            "port": port,
            "security": security,
        },
    )
    if username:
        draft.values["username"] = username
        choice = _ask_secret_choice(
            base, name, "password", "CVEBEACON_SMTP_PASSWORD"
        )
        if choice is not None:
            draft.secret_fields.append(("password", choice))
    else:
        draft.comments.append('# password_env = "CVEBEACON_SMTP_PASSWORD"')
    draft.values["from"] = sender
    draft.values["to"] = recipients
    if security == "none":
        draft.values["allow_insecure"] = True
        print("Warning: SMTP without TLS sends credentials and alerts in clear text.")
    draft.comments.extend(['# cc = []', '# bcc = []'])
    draft.comments.extend(_common_comments("smtp", allow_insecure=security == "none"))
    return draft


def _ask_graph(base: Path, name: str) -> ChannelDraft:
    tenant = _ask_text("Microsoft Graph tenant ID", "", required=True)
    client = _ask_text("Microsoft Graph client ID", "", required=True)
    sender = _ask_validated("From address", "alerts@example.com", _validate_email)
    recipients = _ask_list("To addresses", "security@example.com", validator=_validate_email)
    draft = ChannelDraft(
        name,
        "graph",
        {
            "type": "graph",
            "tenant_id": tenant,
            "client_id": client,
            "sender": sender,
            "to": recipients,
        },
    )
    choice = _ask_secret_choice(
        base, name, "client_secret", "CVEBEACON_GRAPH_CLIENT_SECRET"
    )
    if choice is not None:
        draft.secret_fields.append(("client_secret", choice))
    draft.comments.extend(['# cc = []', '# bcc = []'])
    draft.comments.extend(_common_comments("graph"))
    return draft


def _ask_webhook_channel(base: Path, name: str, kind: str) -> ChannelDraft:
    choice = _ask_secret_choice(
        base, name, "webhook_url", CHANNEL_ENV_DEFAULTS[kind]
    )
    draft = ChannelDraft(name, kind, {"type": kind})
    if choice is not None:
        draft.secret_fields.append(("webhook_url", choice))
    draft.comments.extend(_common_comments(kind))
    return draft


def _ask_telegram(base: Path, name: str) -> ChannelDraft:
    while True:
        chat_id = _ask_text("Telegram chat id or @channel", "-1001234567890", required=True)
        if CHAT_ID_PATTERN.fullmatch(chat_id) or CHAT_NAME_PATTERN.fullmatch(chat_id):
            break
        print("Use a numeric chat id or a name such as @my_channel.")
    draft = ChannelDraft(name, "telegram", {"type": "telegram", "chat_id": chat_id})
    choice = _ask_secret_choice(
        base, name, "bot_token", CHANNEL_ENV_DEFAULTS["telegram"]
    )
    if choice is not None:
        draft.secret_fields.append(("bot_token", choice))
    draft.comments.extend(_common_comments("telegram"))
    return draft


def _ask_matrix(base: Path, name: str) -> ChannelDraft:
    homeserver = _ask_validated(
        "Matrix homeserver", "https://matrix.example.org", _validate_https_url
    ).rstrip("/")
    while True:
        room = _ask_text("Matrix room id", "!room:example.org", required=True)
        if room.startswith("!") and ":" in room:
            break
        print("Use a room id such as !room:example.org.")
    draft = ChannelDraft(
        name,
        "matrix",
        {"type": "matrix", "homeserver": homeserver, "room_id": room},
    )
    choice = _ask_secret_choice(
        base, name, "access_token", CHANNEL_ENV_DEFAULTS["matrix"]
    )
    if choice is not None:
        draft.secret_fields.append(("access_token", choice))
    draft.comments.extend(_common_comments("matrix"))
    return draft


def _ask_ntfy(base: Path, name: str) -> ChannelDraft:
    server = _ask_validated("ntfy server", "https://ntfy.sh", _validate_https_url).rstrip("/")
    while True:
        topic = _ask_text("ntfy topic", "cvebeacon-alerts", required=True)
        if TOPIC_PATTERN.fullmatch(topic):
            break
        print("Use only letters, digits, underscores or hyphens for the topic.")
    draft = ChannelDraft(
        name, "ntfy", {"type": "ntfy", "server": server, "topic": topic}
    )
    token = _ask_secret_choice(
        base, name, "token", CHANNEL_ENV_DEFAULTS["ntfy"], required=False
    )
    if token is not None:
        draft.secret_fields.append(("token", token))
    else:
        draft.comments.append('# token_env = "CVEBEACON_NTFY_TOKEN"')
    draft.comments.extend(["# priority = 3", *_common_comments("ntfy")])
    return draft


def _ask_gotify(base: Path, name: str) -> ChannelDraft:
    server = _ask_validated(
        "Gotify server", "https://gotify.example.org", _validate_https_url
    ).rstrip("/")
    draft = ChannelDraft(name, "gotify", {"type": "gotify", "server": server})
    choice = _ask_secret_choice(
        base, name, "app_token", CHANNEL_ENV_DEFAULTS["gotify"]
    )
    if choice is not None:
        draft.secret_fields.append(("app_token", choice))
    draft.comments.extend(["# priority = 5", *_common_comments("gotify")])
    return draft


def _ask_webhook(base: Path, name: str) -> ChannelDraft:
    url = _ask_validated("Webhook URL", "https://example.org/cvebeacon", _validate_https_url)
    while True:
        header = _ask_text("Header name (blank for none)", "", required=False)
        if not header or HEADER_PATTERN.fullmatch(header) is not None:
            break
        print("Enter a valid HTTP header name.")
    draft = ChannelDraft(name, "webhook", {"type": "webhook", "url": url})
    if header:
        draft.values["header_name"] = header
        choice = _ask_secret_choice(
            base, name, "header_value", CHANNEL_ENV_DEFAULTS["webhook"]
        )
        if choice is not None:
            draft.secret_fields.append(("header_value", choice))
    else:
        draft.comments.extend(
            ['# header_name = "X-Auth"', '# header_value_env = "CVEBEACON_HOOK_SECRET"']
        )
    draft.comments.extend(_common_comments("webhook"))
    return draft


def _ask_channel(base: Path, name: str) -> ChannelDraft:
    kind = _ask_channel_type()
    if kind == "smtp":
        return _ask_smtp(base, name)
    if kind == "graph":
        return _ask_graph(base, name)
    if kind in {"teams", "slack", "discord"}:
        return _ask_webhook_channel(base, name, kind)
    if kind == "telegram":
        return _ask_telegram(base, name)
    if kind == "matrix":
        return _ask_matrix(base, name)
    if kind == "ntfy":
        return _ask_ntfy(base, name)
    if kind == "gotify":
        return _ask_gotify(base, name)
    return _ask_webhook(base, name)


def _ask_channels(base: Path) -> list[ChannelDraft]:
    channels: list[ChannelDraft] = []
    while True:
        default_name = "alerts" if not channels else f"alerts-{len(channels) + 1}"
        name = _ask_validated(
            "Channel name",
            default_name,
            lambda value: _validate_channel_name(value, [item.name for item in channels]),
        )
        channels.append(_ask_channel(base, name))
        if not _ask_bool("Add another channel?", False):
            return channels


def _assign_channels(rules: list[RuleDraft], channels: list[ChannelDraft]) -> None:
    names = [channel.name for channel in channels]
    default = names[0] if len(names) == 1 else "all"
    for index, rule in enumerate(rules):
        while True:
            value = _ask_text(
                f'Channels for rule "{rule.name}" (comma-separated or all)',
                default,
                required=True,
            )
            if value.casefold() == "all":
                selected = names
            else:
                selected = [item.strip() for item in value.split(",") if item.strip()]
                missing = [item for item in selected if item not in names]
                if missing:
                    print("Unknown channel: " + ", ".join(missing))
                    continue
                if not selected:
                    print("Choose at least one channel.")
                    continue
            rules[index] = RuleDraft(
                rule.name, rule.condition, rule.old_cves, tuple(dict.fromkeys(selected))
            )
            break


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_key(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]+", value):
        return value
    return _toml_string(value)


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _toml_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return _inline_table(value)
    raise TypeError(f"cannot write {type(value).__name__} to TOML")


def _inline_table(value: dict[str, Any]) -> str:
    parts = [f"{_toml_key(key)} = {_toml_value(value[key])}" for key in sorted(value)]
    return "{ " + ", ".join(parts) + " }"


def _render_channel(channel: ChannelDraft) -> str:
    lines = [f"[watch.channels.{_toml_key(channel.name)}]"]
    lines.extend(f"{key} = {_toml_value(value)}" for key, value in channel.values.items())
    for base_key, choice in channel.secret_fields:
        if choice.env is not None:
            lines.append(f"{base_key}_env = {_toml_string(choice.env)}")
        if choice.file is not None:
            lines.append(f"{base_key}_file = {_toml_string(choice.file)}")
    if channel.comments:
        lines.append("")
        lines.append("# Optional settings:")
        lines.extend(channel.comments)
    return "\n".join(lines)


def _render_rule(rule: RuleDraft) -> str:
    return "\n".join(
        [
            "[[watch.rules]]",
            f"name = {_toml_string(rule.name)}",
            f"condition = {_toml_value(rule.condition)}",
            f"channels = {_toml_value(list(rule.channels))}",
            f"old_cves = {_toml_string(rule.old_cves)}",
        ]
    )


def _render_config(
    *,
    now: datetime,
    inventory: InventoryChoice | None,
    watch: WatchSettings | None,
    rules: list[RuleDraft],
    channels: list[ChannelDraft],
    nvd_key: NvdKey,
) -> str:
    lines = [
        f"# Generated by cvebeacon setup on {now.strftime('%Y-%m-%d')}.",
        "# Review the paths and secret references before the first run.",
        "",
    ]
    if inventory is not None:
        lines.extend(
            [
                "# Inventory file, format and column names. See docs/USER_GUIDE.md.",
                "[inventory]",
                f"path = {_toml_string(inventory.path)}",
                f"format = {_toml_string(inventory.format)}",
                "",
            ]
        )
    lines.extend(
        [
            "# Local monitoring state. See docs/USER_GUIDE.md.",
            "[state]",
            'database = ".cvebeacon/state.db"',
            "",
            "# Report output directory. See docs/USER_GUIDE.md.",
            "[output]",
            'directory = "reports"',
            "",
            "# HTTP timeouts, retries and pacing. See docs/DEVELOPMENT.md.",
            "[http]",
            "connect_timeout = 10",
            "read_timeout = 30",
            "retries = 3",
            "backoff_seconds = 1",
            "",
            "# Public vulnerability sources. See docs/SOURCES.md.",
            "[sources]",
        ]
    )
    if nvd_key.kind == "env":
        lines.append(f"nvd_api_key_env = {_toml_string(nvd_key.env)}")
    elif nvd_key.kind == "file" and nvd_key.file is not None:
        lines.append(f"nvd_api_key_file = {_toml_string(nvd_key.file)}")
    else:
        lines.append('# nvd_api_key_env = "NVD_API_KEY"')
    lines.append("")
    if watch is not None:
        lines.extend(
            [
                "# Watch mode keeps CVE history and evaluates alert rules. See docs/WATCH.md.",
                "[watch]",
                "enabled = true",
                'database = "cvebeacon-watch.db"',
                f"sources = {_toml_value(list(watch.sources))}",
                f"initial = {_toml_string(watch.initial)}",
                f"backfill_days = {watch.backfill_days}",
                "overlap_minutes = 15",
                "",
            ]
        )
        for channel in channels:
            lines.extend(
                [
                    "# Alert delivery channel. See docs/WATCH.md.",
                    _render_channel(channel),
                    "",
                ]
            )
        for rule in rules:
            lines.extend(
                [
                    "# Alert rule. See docs/WATCH.md.",
                    _render_rule(rule),
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def _secret_paths(
    base: Path,
    channels: list[ChannelDraft],
    nvd_key: NvdKey,
) -> list[tuple[Path, str]]:
    output: list[tuple[Path, str]] = []
    for channel in channels:
        for base_key, choice in channel.secret_fields:
            if choice.file is not None and choice.value is not None:
                path = (base / choice.file).resolve()
                output.append((path, choice.value))
    if nvd_key.file is not None and nvd_key.value is not None:
        output.append(((base / nvd_key.file).resolve(), nvd_key.value))
    return output


def _write_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if os.name == "posix":
            os.chmod(path, 0o600)
    if os.name == "nt":
        print("Note: restrict the secrets files with NTFS permissions.")


def _write_config(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        load_config(name)
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise


def _backup(path: Path, now: datetime) -> Path:
    stamp = now.strftime("%Y%m%dT%H%M%S")
    candidate = path.with_name(f"{path.name}.bak-{stamp}")
    counter = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.bak-{stamp}-{counter}")
        counter += 1
    shutil.copy2(path, candidate)
    return candidate


def _offer_test_send(path: Path) -> None:
    if not _ask_bool("Send a test message to each channel now?", False):
        return
    config = load_config(path)
    with HttpClient(config.http) as http:
        for channel in config.watch.channels:
            try:
                outcome = send_test(config, http, channel.name)
            except CVEBeaconError as exc:
                print(f"{channel.name} ({channel.type}): test message failed; {_one_line(exc)}")
                continue
            if outcome.ok:
                print(f"{outcome.channel} ({outcome.type}): test message sent")
            else:
                suffix = f"; {outcome.error}" if outcome.error else ""
                print(
                    f"{outcome.channel} ({outcome.type}): test message failed{suffix}"
                )


def _ask_schedule_command(*, inventory: bool, watch: bool) -> str:
    options: list[str] = []
    if inventory:
        options.append("scan")
    if watch:
        options.append("watch")
    if inventory and watch:
        options.append("both")
    default = default_command(inventory=inventory, watch=watch)
    return _ask_choice("Scheduled command", tuple(options), default)


def _offer_schedule(
    path: Path,
    *,
    inventory: bool,
    watch: bool,
) -> None:
    kind = _ask_choice("Schedule type", ("times", "interval"), "times")
    if kind == "times":
        while True:
            value = _ask_text("Times (comma-separated HH:MM)", "07:00,19:00", required=True)
            try:
                times = parse_times(value)
                break
            except SchedulingError as exc:
                print(_one_line(exc))
        every: int | None = None
        later = ["--times", ",".join(times)]
    else:
        while True:
            every = _ask_int("Interval in hours", 4, 2, 24)
            if platform.system().casefold() == "linux" and 24 % every:
                print("Linux intervals must divide 24: choose 2, 3, 4, 6, 8, 12 or 24.")
                continue
            break
        times = ()
        later = ["--every", str(every)]
    command = _ask_schedule_command(inventory=inventory, watch=watch)
    try:
        plan = make_plan(
            path,
            every,
            times=times if kind == "times" else None,
            command=command,
        )
    except SchedulingError as exc:
        print(f"Scheduling is unavailable: {_one_line(exc)}")
        return
    print(describe(plan))
    if _ask_bool("Install this schedule now?", False):
        try:
            install(plan)
        except (SchedulingError, OSError) as exc:
            print(f"Schedule installation failed: {_one_line(exc)}")
        else:
            print("Schedule installed.")
        return
    print("Schedule not installed. Install it later with:")
    print(
        "  "
        + shlex.join(
            [
                "cvebeacon",
                "--config",
                str(path),
                "schedule",
                "install",
                *later,
                "--command",
                command,
            ]
        )
    )


def _next_commands(path: Path, *, inventory: bool, watch: WatchSettings | None) -> list[str]:
    base = ["cvebeacon", "--config", str(path)]
    commands: list[str] = []
    if watch is not None:
        commands.append(shlex.join([*base, "watch", "sync"]))
        if watch.initial in {"backfill", "full"}:
            commands.append(shlex.join([*base, "watch", "evaluate", "--all", "--yes"]))
        commands.append(shlex.join([*base, "watch", "run"]))
    if inventory:
        commands.append(shlex.join([*base, "scan"]))
    return commands


def run_setup(
    config_path: str | Path = "cvebeacon.toml",
    *,
    force: bool = False,
    now: datetime | None = None,
) -> int:
    path = Path(config_path).expanduser().resolve()
    stamp = now or datetime.now()
    try:
        backup_pending = False
        if path.exists():
            if path.is_dir():
                print(f"error: configuration path is a directory: {path}", file=sys.stderr)
                return 2
            if not force and not _ask_bool(
                f"{path} already exists; overwrite it?", False
            ):
                print("cancelled")
                return 1
            backup_pending = True
        mode = _ask_mode()
        inventory = _ask_inventory(path.parent) if mode in {"inventory", "both"} else None
        watch = _ask_watch_settings() if mode in {"watch", "both"} else None
        nvd_key = _ask_nvd_key(path.parent)
        rules = _ask_rules(watch) if watch is not None else []
        channels = _ask_channels(path.parent) if watch is not None else []
        if watch is not None:
            _assign_channels(rules, channels)
        text = _render_config(
            now=stamp,
            inventory=inventory,
            watch=watch,
            rules=rules,
            channels=channels,
            nvd_key=nvd_key,
        )
        if backup_pending:
            try:
                backup = _backup(path, stamp)
            except OSError as exc:
                print(f"error: cannot back up the existing configuration: {exc}", file=sys.stderr)
                return 2
            print(f"Backup: {backup}")
        for secret_path, value in _secret_paths(path.parent, channels, nvd_key):
            try:
                _write_secret(secret_path, value)
            except OSError as exc:
                print(f"error: cannot write secret file: {exc}", file=sys.stderr)
                return 2
        try:
            _write_config(path, text)
        except (ConfigurationError, OSError) as exc:
            print(f"error: {_one_line(exc)}", file=sys.stderr)
            return 2
        print(f"Configuration written: {path}")
        if watch is not None:
            _offer_test_send(path)
        _offer_schedule(
            path,
            inventory=inventory is not None,
            watch=watch is not None,
        )
        secret_files = any(choice.file for channel in channels for _, choice in channel.secret_fields)
        secret_files = secret_files or nvd_key.file is not None
        print("")
        print(f"Configuration: {path}")
        if secret_files:
            secret_directory = path.parent / "secrets" if os.name == "posix" else path.parent
            print(f"Secrets: {secret_directory}")
        print("Next steps:")
        for command in _next_commands(
            path, inventory=inventory is not None, watch=watch
        ):
            print(f"  {command}")
        return 0
    except SetupCancelled:
        print("cancelled")
        return 1
