"""Interactive configuration wizard."""

from __future__ import annotations

import getpass
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
    validate_webhook_url,
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
SOURCE_LABELS = {"cisa_kev": "CISA KEV", "eu_kev": "EU KEV"}
SECRET_LABELS = {
    ("smtp", "password"): "SMTP password",
    ("graph", "client_secret"): "Microsoft Graph client secret",
    ("teams", "webhook_url"): "Teams webhook URL",
    ("slack", "webhook_url"): "Slack webhook URL",
    ("discord", "webhook_url"): "Discord webhook URL",
    ("telegram", "bot_token"): "Telegram bot token",
    ("matrix", "access_token"): "Matrix access token",
    ("ntfy", "token"): "ntfy access token",
    ("gotify", "app_token"): "Gotify app token",
    ("webhook", "header_value"): "Webhook header value",
}


class SetupCancelled(Exception):
    """The user interrupted the wizard."""


class _AnswerHistory:
    """Replays earlier answers as defaults when the user edits them."""

    def __init__(self) -> None:
        self._values: dict[tuple[str, int], str] = {}
        self._positions: dict[str, int] = {}

    def reset(self) -> None:
        self._values = {}
        self._positions = {}

    def new_pass(self) -> None:
        self._positions = {}

    def previous(self, label: str, default: str) -> str:
        index = self._positions.get(label, 0)
        return self._values.get((label, index), default)

    def remember(self, label: str, value: str) -> None:
        index = self._positions.get(label, 0)
        self._values[(label, index)] = value
        self._positions[label] = index + 1


ANSWERS = _AnswerHistory()


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
    previous = ANSWERS.previous(label, default or "")
    shown = f" [{previous}]" if previous else ""
    try:
        value = input(f"{label}{shown}: ").strip()
    except (EOFError, KeyboardInterrupt):
        raise SetupCancelled from None
    return value or previous


def _ask_text(
    label: str,
    default: str = "",
    *,
    required: bool = False,
    validator=None,
) -> str:
    while True:
        value = _ask_line(label, default)
        if not value:
            value = default
        if required and not value:
            print(f"{label} is required.")
            continue
        if validator is not None:
            try:
                value = validator(value)
            except (ValueError, CVEBeaconError) as exc:
                print(_one_line(exc))
                continue
        ANSWERS.remember(label, value)
        return value


def _ask_validated(label: str, default: str, validator) -> str:
    return _ask_text(label, default, required=True, validator=validator)


def _ask_bool(label: str, default: bool) -> bool:
    remembered = ANSWERS.previous(label, "")
    if remembered.casefold() in {"y", "yes", "n", "no"}:
        default = remembered.casefold() in {"y", "yes"}
    shown = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            answer = input(f"{label} {shown}: ").strip().casefold()
        except (EOFError, KeyboardInterrupt):
            raise SetupCancelled from None
        if not answer:
            ANSWERS.remember(label, "y" if default else "n")
            return default
        if answer in {"y", "yes"}:
            ANSWERS.remember(label, "y")
            return True
        if answer in {"n", "no"}:
            ANSWERS.remember(label, "n")
            return False
        print("Please answer yes or no.")


def _ask_choice(label: str, options: tuple[str, ...], default: str) -> str:
    shown = "/".join(options)

    def validate(value: str) -> str:
        folded = value.casefold()
        if folded not in options:
            raise ValueError(f"Choose one of: {shown}.")
        return folded

    return _ask_text(
        f"{label} ({shown})", default, required=True, validator=validate
    )


def _ask_number(label: str, default: float, minimum: float, maximum: float) -> float:
    message = f"Enter a number from {minimum:g} to {maximum:g}."

    def validate(value: str) -> str:
        try:
            number = float(value)
        except ValueError:
            raise ValueError(message) from None
        if not minimum <= number <= maximum:
            raise ValueError(message)
        return f"{number:g}"

    return float(_ask_text(label, f"{default:g}", required=True, validator=validate))


def _ask_optional_number(
    label: str, minimum: float, maximum: float, *, validator=None
) -> float | None:
    message = f"Enter a number from {minimum:g} to {maximum:g}, or leave it blank."

    def validate(value: str) -> str:
        if not value:
            return ""
        try:
            number = float(value)
        except ValueError:
            raise ValueError(message) from None
        if not minimum <= number <= maximum:
            raise ValueError(message)
        if validator is not None:
            validator(number)
        return f"{number:g}"

    value = _ask_text(label, "", required=False, validator=validate)
    return float(value) if value else None


def _ask_int(
    label: str,
    default: int,
    minimum: int,
    maximum: int,
    *,
    validator=None,
) -> int:
    message = f"Enter a whole number from {minimum} to {maximum}."

    def validate(value: str) -> str:
        try:
            number = int(value)
        except ValueError:
            raise ValueError(message) from None
        if not minimum <= number <= maximum:
            raise ValueError(message)
        if validator is not None:
            validator(number)
        return str(number)

    return int(_ask_text(label, str(default), required=True, validator=validate))


def _ask_list(
    label: str,
    default: str,
    *,
    validator=None,
    required: bool = True,
) -> list[str]:
    def validate(value: str) -> str:
        items = [item.strip() for item in value.split(",") if item.strip()]
        if required and not items:
            raise ValueError(f"{label} is required.")
        if validator is not None:
            for item in items:
                validator(item)
        return value

    value = _ask_text(
        label, default, required=required, validator=validate
    )
    items = [item.strip() for item in value.split(",") if item.strip()]
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
    try:
        parts = urlsplit(text)
    except ValueError:
        raise ValueError("Enter an HTTPS URL.") from None
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValueError("Enter an HTTPS URL.")
    return text


def _validate_matrix_homeserver(value: str) -> str:
    text = _validate_https_url(value).rstrip("/")
    parts = urlsplit(text)
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("Enter an HTTPS origin without a path, query or fragment.")
    return text


def _validate_telegram_chat(value: str) -> str:
    text = value.strip()
    if CHAT_ID_PATTERN.fullmatch(text) is None and CHAT_NAME_PATTERN.fullmatch(text) is None:
        raise ValueError("Use a numeric chat id or a name such as @my_channel.")
    return text


def _validate_matrix_room(value: str) -> str:
    text = value.strip()
    if (
        not text.startswith("!")
        or ":" not in text
        or any(ord(character) <= 32 or ord(character) >= 127 for character in text)
        or any(character in text for character in "/?#\\")
    ):
        raise ValueError("Use a room id such as !room:example.org.")
    return text


def _validate_webhook(value: str, kind: str) -> str:
    text = value.strip()
    try:
        validate_webhook_url(
            text, kind, SECRET_LABELS.get((kind, "webhook_url"), "webhook URL")
        )
    except CVEBeaconError as exc:
        raise ValueError(_one_line(exc)) from None
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
        label = SOURCE_LABELS.get(name, name.upper())
        suffix = " (always enabled)" if name == "nvd" else ""
        print(f"  {label}: {description}{suffix}")
    enabled = ["nvd"]
    for name, _description in SOURCE_INFO[1:]:
        label = SOURCE_LABELS.get(name, name.upper())
        if _ask_bool(f"Enable {label}?", True):
            enabled.append(name)
    if "epss" not in enabled:
        print("Warning: EPSS is disabled; epss_min rules will be unavailable.")
    return tuple(enabled)


def _ask_watch_settings() -> WatchSettings:
    sources = _ask_sources()
    print("First run history:")
    print("  baseline - no history; alerts start from now")
    print("  backfill - download the last N days and evaluate them")
    print("  full     - download all available history; this can take hours")
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
        print(
            f"Set {name} in the environment of the account that runs CVEBeacon "
            "(including its scheduler)."
        )
        return NvdKey("env", env=name)
    if choice == "file":
        value = _ask_secret_value("NVD API key")
        stored = _secret_relative(base, "nvd", "api-key")
        return NvdKey("file", file=stored, value=value)
    return NvdKey()


def _warn_rule_sources(
    index: int, sources: tuple[str, ...], warned: set[str]
) -> None:
    enabled = set(sources)
    if (
        index in {3, 4}
        and "kev" not in warned
        and not ({"cisa_kev", "eu_kev"} & enabled)
    ):
        print(
            "Warning: CISA KEV and EU KEV are disabled; KEV rules will not match."
        )
        warned.add("kev")
    if index == 5 and "euvd" not in warned and "euvd" not in enabled:
        print(
            "Warning: EUVD is disabled; actively-exploited rules will rely on "
            "NVD SSVC only."
        )
        warned.add("euvd")


def _ask_rule_selection(sources: tuple[str, ...]) -> list[int]:
    epss_enabled = "epss" in sources
    print("Rules:")
    for index, (name, description) in enumerate(RULE_PRESETS, start=1):
        print(f"  {index}. {name}: {description}")

    def validate(value: str) -> str:
        try:
            selected = {
                int(part.strip()) for part in value.split(",") if part.strip()
            }
        except ValueError:
            raise ValueError("Choose numbers from 1 to 6.") from None
        if not selected or any(
            not 1 <= number <= len(RULE_PRESETS) for number in selected
        ):
            raise ValueError("Choose numbers from 1 to 6.")
        if not epss_enabled and any(number in {2, 4} for number in selected):
            raise ValueError(
                "Those rules use EPSS, which is disabled. Choose another rule "
                "or enable EPSS."
            )
        return value

    raw = _ask_text(
        "Rule numbers (comma-separated)", "1", required=True, validator=validate
    )
    selected = sorted(
        {int(part.strip()) for part in raw.split(",") if part.strip()}
    )
    warned: set[str] = set()
    for index in selected:
        _warn_rule_sources(index, sources, warned)
    return selected


def _custom_condition(sources: tuple[str, ...]) -> dict[str, Any]:
    enabled = set(sources)

    def validate_epss(number: float) -> None:
        if "epss" not in enabled:
            raise ValueError(
                "EPSS is disabled; leave the EPSS minimum blank or enable EPSS."
            )

    while True:
        cvss = _ask_optional_number("CVSS minimum (blank for none)", 0.0, 10.0)
        epss = _ask_optional_number(
            "EPSS minimum (blank for none)", 0.0, 1.0, validator=validate_epss
        )
        combination = "and"
        if cvss is not None and epss is not None:
            combination = _ask_choice("Combine CVSS and EPSS", ("and", "or"), "and")
        kev = _ask_bool("Require a KEV entry?", False)
        if kev and not ({"cisa_kev", "eu_kev"} & enabled):
            print(
                "Warning: CISA KEV and EU KEV are disabled; this condition will "
                "not match."
            )
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


def _preset_condition(index: int, sources: tuple[str, ...]) -> dict[str, Any]:
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
    return _custom_condition(sources)


def _ask_rules(settings: WatchSettings) -> list[RuleDraft]:
    selected = _ask_rule_selection(settings.sources)
    rules: list[RuleDraft] = []
    used: set[str] = set()
    for index in selected:
        preset_name = RULE_PRESETS[index - 1][0]
        condition = _preset_condition(index, settings.sources)
        name = _ask_validated(
            "Rule name", preset_name, lambda value: _validate_rule_name(value, used)
        )
        used.add(name.casefold())
        vendors = _ask_list(
            "Vendor filter (comma-separated, blank for none)", "", required=False
        )
        if vendors:
            condition = {"all": [condition, {"vendor": vendors}]}
        print(
            "Old CVEs: digest sends a summary, alert sends each one, ignore "
            "leaves them out."
        )
        old_cves = _ask_choice(
            "Old CVEs", ("digest", "alert", "ignore"), "digest"
        )
        rules.append(RuleDraft(name, condition, old_cves))
    return rules


def _ask_channel_type() -> str:
    print("Channel types:")
    for index, (name, description) in enumerate(CHANNEL_INFO, start=1):
        print(f"  {index}. {name}: {description}")

    def validate(value: str) -> str:
        folded = value.casefold()
        if folded.isdigit() and 1 <= int(folded) <= len(CHANNEL_INFO):
            return CHANNEL_INFO[int(folded) - 1][0]
        if folded in CHANNEL_TYPES:
            return folded
        raise ValueError("Choose a channel type from the list.")

    return _ask_text("Channel type", "smtp", required=True, validator=validate)


def _ask_secret_value(label: str, validator=None) -> str:
    while True:
        try:
            value = getpass.getpass(f"{label}: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise SetupCancelled from None
        if not value:
            print(f"{label} is required.")
            continue
        if validator is not None:
            try:
                return validator(value)
            except (ValueError, CVEBeaconError) as exc:
                print(_one_line(exc))
                continue
        return value


def _secret_relative(base: Path, channel: str, field_name: str) -> str:
    directory = base / "secrets"
    filename = re.sub(r"[^A-Za-z0-9_.-]", "-", f"{channel}-{field_name}")
    path = directory / filename
    try:
        relative = path.relative_to(base)
    except ValueError:
        relative = path
    return relative.as_posix()


def _secret_label(kind: str, field_name: str) -> str:
    return SECRET_LABELS.get(
        (kind, field_name), field_name.replace("_", " ").capitalize()
    )


def _ask_secret_choice(
    base: Path,
    channel: str,
    field_name: str,
    default_env: str,
    *,
    kind: str,
    required: bool = True,
    validator=None,
) -> SecretChoice | None:
    label = _secret_label(kind, field_name)
    article = "an" if label.casefold().startswith("ntfy") else "a"
    if not required and not _ask_bool(f"Use {article} {label}?", False):
        return None
    method = _ask_choice(f"Store the {label} in", ("env", "file"), "env")
    if method == "env":
        name = _ask_validated(
            "Environment variable name", default_env, _validate_env_name
        )
        print(
            f"Set {name} in the environment of the account that runs CVEBeacon "
            "(including its scheduler)."
        )
        return SecretChoice(env=name)
    value = _ask_secret_value(label, validator)
    return SecretChoice(file=_secret_relative(base, channel, field_name), value=value)


def _common_comments(kind: str, *, allow_insecure: bool = False) -> list[str]:
    interval = 3 if kind == "telegram" else 0
    comments = [
        '# grouping = "run"',
        "# max_items = 20",
        f"# min_interval_seconds = {interval}",
        "# timeout_seconds = 30",
    ]
    if not allow_insecure:
        comments.append("# allow_insecure = false")
    return comments


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
        host = _ask_text("SMTP host (e.g. smtp.example.com)", "", required=True)
        security = _ask_choice("SMTP security", ("starttls", "tls", "none"), "starttls")
        default_port = {"starttls": 587, "tls": 465, "none": 25}[security]
        port = _ask_int("SMTP port", default_port, 1, 65535)
    sender = _ask_validated(
        "From address (e.g. alerts@example.com)", "", _validate_email
    )
    recipients = _ask_list(
        "To addresses (e.g. security@example.com)", "", validator=_validate_email
    )
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
            base,
            name,
            "password",
            "CVEBEACON_SMTP_PASSWORD",
            kind="smtp",
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
    draft.comments.extend(
        _common_comments("smtp", allow_insecure=security == "none")
    )
    return draft


def _ask_graph(base: Path, name: str) -> ChannelDraft:
    tenant = _ask_text("Microsoft Graph tenant ID", "", required=True)
    client = _ask_text("Microsoft Graph client ID", "", required=True)
    sender = _ask_validated(
        "From address (e.g. alerts@example.com)", "", _validate_email
    )
    recipients = _ask_list(
        "To addresses (e.g. security@example.com)", "", validator=_validate_email
    )
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
        base,
        name,
        "client_secret",
        "CVEBEACON_GRAPH_CLIENT_SECRET",
        kind="graph",
    )
    if choice is not None:
        draft.secret_fields.append(("client_secret", choice))
    draft.comments.extend(['# cc = []', '# bcc = []'])
    draft.comments.extend(_common_comments("graph"))
    return draft


def _ask_webhook_channel(base: Path, name: str, kind: str) -> ChannelDraft:
    choice = _ask_secret_choice(
        base,
        name,
        "webhook_url",
        CHANNEL_ENV_DEFAULTS[kind],
        kind=kind,
        validator=lambda value: _validate_webhook(value, kind),
    )
    draft = ChannelDraft(name, kind, {"type": kind})
    if choice is not None:
        draft.secret_fields.append(("webhook_url", choice))
    draft.comments.extend(_common_comments(kind))
    return draft


def _ask_telegram(base: Path, name: str) -> ChannelDraft:
    chat_id = _ask_validated(
        "Telegram chat id or @channel (e.g. -1001234567890)",
        "",
        _validate_telegram_chat,
    )
    draft = ChannelDraft(name, "telegram", {"type": "telegram", "chat_id": chat_id})
    choice = _ask_secret_choice(
        base,
        name,
        "bot_token",
        CHANNEL_ENV_DEFAULTS["telegram"],
        kind="telegram",
    )
    if choice is not None:
        draft.secret_fields.append(("bot_token", choice))
    draft.comments.extend(_common_comments("telegram"))
    return draft


def _ask_matrix(base: Path, name: str) -> ChannelDraft:
    homeserver = _ask_validated(
        "Matrix homeserver (e.g. https://matrix.example.org)",
        "",
        _validate_matrix_homeserver,
    )
    room = _ask_validated(
        "Matrix room id (e.g. !room:example.org)", "", _validate_matrix_room
    )
    draft = ChannelDraft(
        name,
        "matrix",
        {"type": "matrix", "homeserver": homeserver, "room_id": room},
    )
    choice = _ask_secret_choice(
        base,
        name,
        "access_token",
        CHANNEL_ENV_DEFAULTS["matrix"],
        kind="matrix",
    )
    if choice is not None:
        draft.secret_fields.append(("access_token", choice))
    draft.comments.extend(_common_comments("matrix"))
    return draft


def _ask_ntfy(base: Path, name: str) -> ChannelDraft:
    print(
        "ntfy.sh topics are public unless protected; use a token or self-host "
        "for private alerts."
    )
    server = _ask_validated(
        "ntfy server", "https://ntfy.sh", _validate_https_url
    ).rstrip("/")
    suggested = "cvebeacon-" + secrets.token_urlsafe(9)

    def validate(value: str) -> str:
        if TOPIC_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "Use only letters, digits, underscores or hyphens for the topic."
            )
        return value

    topic = _ask_text("ntfy topic", suggested, required=True, validator=validate)
    draft = ChannelDraft(
        name, "ntfy", {"type": "ntfy", "server": server, "topic": topic}
    )
    token = _ask_secret_choice(
        base,
        name,
        "token",
        CHANNEL_ENV_DEFAULTS["ntfy"],
        kind="ntfy",
        required=False,
    )
    if token is not None:
        draft.secret_fields.append(("token", token))
    else:
        draft.comments.append('# token_env = "CVEBEACON_NTFY_TOKEN"')
    draft.comments.extend(["# priority = 3", *_common_comments("ntfy")])
    return draft


def _ask_gotify(base: Path, name: str) -> ChannelDraft:
    server = _ask_validated(
        "Gotify server (e.g. https://gotify.example.org)", "", _validate_https_url
    ).rstrip("/")
    draft = ChannelDraft(name, "gotify", {"type": "gotify", "server": server})
    choice = _ask_secret_choice(
        base,
        name,
        "app_token",
        CHANNEL_ENV_DEFAULTS["gotify"],
        kind="gotify",
    )
    if choice is not None:
        draft.secret_fields.append(("app_token", choice))
    draft.comments.extend(["# priority = 5", *_common_comments("gotify")])
    return draft


def _ask_webhook(base: Path, name: str) -> ChannelDraft:
    url = _ask_validated(
        "Webhook URL (e.g. https://example.org/cvebeacon)",
        "",
        _validate_https_url,
    )
    def validate_header(value: str) -> str:
        if value and HEADER_PATTERN.fullmatch(value) is None:
            raise ValueError("Enter a valid HTTP header name.")
        return value

    header = _ask_text(
        "Header name (blank for none)", "", required=False, validator=validate_header
    )
    draft = ChannelDraft(name, "webhook", {"type": "webhook", "url": url})
    if header:
        draft.values["header_name"] = header
        choice = _ask_secret_choice(
            base,
            name,
            "header_value",
            CHANNEL_ENV_DEFAULTS["webhook"],
            kind="webhook",
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
        def validate(value: str) -> str:
            if value.casefold() == "all":
                return value
            selected = [item.strip() for item in value.split(",") if item.strip()]
            missing = [item for item in selected if item not in names]
            if missing:
                raise ValueError("Unknown channel: " + ", ".join(missing))
            if not selected:
                raise ValueError("Choose at least one channel.")
            return value

        value = _ask_text(
            f'Channels for rule "{rule.name}" (comma-separated or all)',
            default,
            required=True,
            validator=validate,
        )
        if value.casefold() == "all":
            selected = names
        else:
            selected = [item.strip() for item in value.split(",") if item.strip()]
        rules[index] = RuleDraft(
            rule.name, rule.condition, rule.old_cves, tuple(dict.fromkeys(selected))
        )


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


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


def _render_channel(channel: ChannelDraft, *, secret_root: Path | None = None) -> str:
    lines = [f"[watch.channels.{_toml_key(channel.name)}]"]
    lines.extend(f"{key} = {_toml_value(value)}" for key, value in channel.values.items())
    for base_key, choice in channel.secret_fields:
        if choice.env is not None:
            lines.append(f"{base_key}_env = {_toml_string(choice.env)}")
        if choice.file is not None:
            path = (
                (secret_root / choice.file).as_posix()
                if secret_root is not None
                else choice.file
            )
            lines.append(f"{base_key}_file = {_toml_string(path)}")
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
    secret_root: Path | None = None,
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
        path = (
            (secret_root / nvd_key.file).as_posix()
            if secret_root is not None
            else nvd_key.file
        )
        lines.append(f"nvd_api_key_file = {_toml_string(path)}")
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
                    _render_channel(channel, secret_root=secret_root),
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
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.name == "posix":
            os.chmod(path, 0o600)


def _write_config(path: Path, text: str) -> Path:
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
        return Path(name)
    except BaseException:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise


def _backup_path(path: Path, now: datetime) -> Path:
    stamp = now.strftime("%Y%m%dT%H%M%S")
    candidate = path.with_name(f"{path.name}.bak-{stamp}")
    counter = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.bak-{stamp}-{counter}")
        counter += 1
    return candidate


def _backup(path: Path, now: datetime) -> Path:
    candidate = _backup_path(path, now)
    shutil.copy2(path, candidate)
    return candidate


def _backup_secret(path: Path, now: datetime) -> Path:
    candidate = _backup_path(path, now)
    _write_secret(candidate, path.read_bytes().decode("utf-8"))
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
    if len(options) == 1:
        print(f"Scheduled command: {options[0]}")
        return options[0]
    return _ask_choice("Scheduled command", tuple(options), default)


def _offer_schedule(
    path: Path,
    *,
    inventory: bool,
    watch: bool,
) -> None:
    kind = _ask_choice("Schedule type", ("times", "interval"), "times")
    if kind == "times":
        def validate_times(value: str) -> str:
            parse_times(value)
            return value

        value = _ask_text(
            "Times (comma-separated HH:MM)",
            "07:00,19:00",
            required=True,
            validator=validate_times,
        )
        times = parse_times(value)
        every: int | None = None
        later = ["--times", ",".join(times)]
    else:
        def validate_interval(value: int) -> None:
            if platform.system().casefold() == "linux" and 24 % value:
                raise ValueError(
                    "Linux intervals must divide 24: choose 2, 3, 4, 6, 8, 12 or 24."
                )

        every = _ask_int("Interval in hours", 4, 2, 24, validator=validate_interval)
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
    ANSWERS.reset()
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
        while True:
            ANSWERS.new_pass()
            mode = _ask_mode()
            inventory = (
                _ask_inventory(path.parent) if mode in {"inventory", "both"} else None
            )
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
            secrets_to_write = _secret_paths(path.parent, channels, nvd_key)
            try:
                validation_root = Path(
                    tempfile.mkdtemp(prefix=".cvebeacon-secrets-", dir=path.parent)
                )
            except OSError as exc:
                print(f"error: cannot write secret file: {exc}", file=sys.stderr)
                return 2
            try:
                for secret_path, value in secrets_to_write:
                    relative = secret_path.relative_to(path.parent)
                    _write_secret(validation_root / relative, value)
                validation_text = _render_config(
                    now=stamp,
                    inventory=inventory,
                    watch=watch,
                    rules=rules,
                    channels=channels,
                    nvd_key=nvd_key,
                    secret_root=validation_root,
                )
                try:
                    temporary = _write_config(path, validation_text)
                except ConfigurationError as exc:
                    print(f"error: {_one_line(exc)}", file=sys.stderr)
                    if _ask_bool("Edit answers again?", True):
                        continue
                    print("cancelled")
                    return 2
                except OSError as exc:
                    print(
                        f"error: cannot write the configuration: {exc}",
                        file=sys.stderr,
                    )
                    return 2
            except OSError as exc:
                print(f"error: cannot write secret file: {exc}", file=sys.stderr)
                return 2
            finally:
                shutil.rmtree(validation_root, ignore_errors=True)
            break
        if backup_pending:
            try:
                backup = _backup(path, stamp)
            except OSError as exc:
                temporary.unlink(missing_ok=True)
                print(
                    f"error: cannot back up the existing configuration: {exc}",
                    file=sys.stderr,
                )
                return 2
            print(f"Backup: {backup}")
        try:
            for secret_path, value in secrets_to_write:
                if secret_path.exists():
                    print(f"Backup: {_backup_secret(secret_path, stamp)}")
                _write_secret(secret_path, value)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            print(f"error: cannot write secret file: {exc}", file=sys.stderr)
            return 2
        try:
            final = _write_config(path, text)
        except (ConfigurationError, OSError) as exc:
            temporary.unlink(missing_ok=True)
            print(f"error: {_one_line(exc)}", file=sys.stderr)
            return 2
        try:
            os.replace(final, path)
        except OSError as exc:
            final.unlink(missing_ok=True)
            temporary.unlink(missing_ok=True)
            print(f"error: cannot write the configuration: {exc}", file=sys.stderr)
            return 2
        temporary.unlink(missing_ok=True)
        if os.name == "nt" and secrets_to_write:
            print("Note: restrict the secrets directory with NTFS permissions.")
        print(f"Configuration written: {path}")
        try:
            if watch is not None:
                _offer_test_send(path)
            _offer_schedule(
                path,
                inventory=inventory is not None,
                watch=watch is not None,
            )
        except (SetupCancelled, KeyboardInterrupt):
            print(f"Configuration saved: {path}")
        secret_files = bool(secrets_to_write)
        print("")
        print(f"Configuration: {path}")
        if secret_files:
            print(f"Secrets: {path.parent / 'secrets'}")
        print("Next steps:")
        for command in _next_commands(
            path, inventory=inventory is not None, watch=watch
        ):
            print(f"  {command}")
        return 0
    except SetupCancelled:
        print("cancelled")
        return 1
