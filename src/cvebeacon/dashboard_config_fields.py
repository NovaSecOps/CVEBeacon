"""Presentation metadata checked against the configuration validators."""

from dataclasses import dataclass
from pathlib import Path

from .config import WATCH_INITIAL_MODES, WATCH_SOURCES, INVENTORY_FORMATS
from .watch.catalog import SUPPORTED_LANGUAGES
from .watch.channels import CHANNEL_TYPES, GROUPING_MODES, MESSAGE_FORMATS, SMTP_SECURITY, SMTP_DEFAULT_PORTS, TEAMS_BOT_FORMATS
from .watch.records import CVSS_PROVIDERS
from .watch.reported import IDENTITY_MODES
from .watch.rules import EVENT_KINDS, OLD_CVES_MODES


@dataclass(frozen=True)
class FieldMetadata:
    kind: str
    default: object = None
    choices: tuple = ()
    required: bool = False
    help: str = ""
    example: object = "example"
    minimum: float | None = None
    maximum: float | None = None
    step: str = "1"
    item_choices: tuple = ()
    requirement: str = ""
    minimum_exclusive: bool = False


ENUMS = {
    "watch.initial": WATCH_INITIAL_MODES,
    "watch.language": SUPPORTED_LANGUAGES,
    "watch.reporting.identity": IDENTITY_MODES,
    "inventory.format": INVENTORY_FORMATS,
    "watch.rules.old_cves": OLD_CVES_MODES,
    "channel.type": CHANNEL_TYPES,
    "channel.grouping": GROUPING_MODES,
    "channel.format": MESSAGE_FORMATS,
    "channel.security": SMTP_SECURITY,
    "channel.language": SUPPORTED_LANGUAGES,
}
LIST_ENUMS = {"watch.sources": WATCH_SOURCES, "watch.rules.events": EVENT_KINDS,
              "watch.rules.cvss_providers": CVSS_PROVIDERS}
# None means there is no upper bound in the loader.
BOUNDS = {
    "http.connect_timeout": (0, None, "any"),
    "http.read_timeout": (0, None, "any"),
    "http.backoff_seconds": (0, None, "any"),
    "http.retries": (0, 10, "1"),
    "sources.minimum_request_interval": (0, None, "any"),
    "inventory.header_row": (1, None, "1"),
    "watch.backfill_days": (1, 120, "1"),
    "watch.overlap_minutes": (0, 1440, "1"),
    "dashboard.session_lifetime_seconds": (60, 86400, "1"),
    "dashboard.session_idle_seconds": (60, 86400, "1"),
    "backup.retention_days": (1, 3650, "1"),
    "backup.keep_min": (0, 1000, "1"),
    "channel.port": (1, 65535, "1"),
    "channel.max_items": (1, 100, "1"),
    "channel.timeout_seconds": (1, 300, "any"),
    "channel.min_interval_seconds": (0, 3600, "any"),
}
CHANNEL_DEFAULTS = {"allow_insecure": False, "security": "starttls", "port": SMTP_DEFAULT_PORTS["starttls"],
                    "cc": (), "bcc": (),
                    "server": "https://ntfy.sh"}
CHANNEL_REQUIRED = {
    "smtp": {"host", "from", "to"},
    "graph": {"tenant_id", "client_id", "sender", "to"},
    "teams_bot": {"tenant_id", "app_id", "client_secret_file"},
    "telegram": {"chat_id"}, "matrix": {"homeserver", "room_id"},
    "ntfy": {"topic"}, "gotify": {"server"},
}
HELP = {
    "initial": "First-run handling: baseline records existing CVEs silently; backfill covers recent days; full covers all stored CVEs.",
    "old_cves": "Handle older CVEs as a digest, individual alerts, or ignore them.",
    "format": "Choose the input or message format.",
    "security": "SMTP transport security. Unencrypted SMTP also requires allow_insecure.",
    "grouping": "Group notifications per run or per event.",
    "priority": "Notification priority; higher numbers are more urgent.",
    "condition": "TOML condition table. Combine leaves with any, all or not; see the valid leaves below.",
    "identity": "Who may record reporting: open, registered users, or authenticated users.",
    "enabled": "Enable this section or row.",
    "allow_insecure": "Allow unencrypted transport only on a trusted connection.",
    "notify_reported": "Include CVEs already marked as reported.",
    "language": "Language used for delivered messages.",
    "sources": "TOML array of source names; nvd is required.",
    "channels": "TOML array of existing channel names.",
    "events": "TOML array of event triggers.",
    "cvss_providers": "TOML array of accepted score providers.",
    "columns": "TOML table mapping inventory field names to input column names.",
    "managed": "Include current client inventories saved from the dashboard.",
    "to": "Comma-separated email addresses or a TOML array. Spaces and duplicate addresses are removed.",
    "cc": "Optional copy recipients, separated by commas or entered as a TOML array.",
    "bcc": "Optional hidden-copy recipients, separated by commas or entered as a TOML array.",
    "recipients": "Comma-separated email addresses or a TOML array.",
    "session_lifetime_seconds": "Absolute session lifetime in seconds.",
    "session_idle_seconds": "End sessions after this many seconds without a request.",
    "secure_cookie": "Send session cookies only over HTTPS.",
    "port": "SMTP port. The default follows security: starttls 587, tls 465, none 25.",
    "database": "Database location. Only administrators may change filesystem paths.",
    "directory": "Report output directory. Only administrators may change filesystem paths.",
    "path": "Inventory input path. You can leave it blank when watch mode or another inventory source is available.",
}
EXAMPLES = {"condition": {"kev": "cisa"}, "channels": ["email"],
            "events": ["match"], "cvss_providers": ["nvd"], "sources": ["nvd"],
            "columns": {"asset_id": "asset_id"}, "host": "smtp.example.com",
            "from": "alerts@example.com", "sender": "alerts@example.com",
            "to": "alerts@example.com, security@example.com", "cc": "copy@example.com",
            "bcc": "copy@example.com", "recipients": "alerts@example.com",
            "name": "example", "cpe": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"}


def metadata(path, key, default, kind, *, channel_type=None):
    identity = f"{'channel' if channel_type else path}.{key}"
    choices = ENUMS.get(identity, ())
    required = (path == "watch.rules" and key in {"name", "condition", "channels"}
                or path == "product_mappings"
                or channel_type is not None and key in {"name", "type", *CHANNEL_REQUIRED.get(channel_type, ())})
    requirement = ""
    if path == "inventory" and key == "path":
        requirement = "required when there is no other inventory source or watch mode"
    if path == "notifications.email" and key in {"sender", "recipients"}:
        requirement = "required when email notifications are enabled"
    if channel_type and key.endswith(("_env", "_file")):
        if channel_type in {"graph", "teams", "slack", "discord", "telegram", "matrix", "gotify"} or channel_type == "webhook" and key.startswith("url_"):
            requirement = "one of the paired environment or file references is required"
    if channel_type:
        default = CHANNEL_DEFAULTS.get(key, default)
        if key == "server" and channel_type != "ntfy":
            default = None
        if key == "priority":
            choices = tuple(range(1, 6)) if channel_type == "ntfy" else tuple(range(-2, 11))
            default = 3 if channel_type == "ntfy" else 5
        if channel_type == "teams_bot" and key == "format":
            choices = TEAMS_BOT_FORMATS
            default = "adaptive_card"
        elif channel_type == "teams_bot" and key in {"recipients", "conversation_references"}:
            default = ()
        elif channel_type == "teams_bot" and key == "service_url":
            default = "https://smba.trafficmanager.net/teams/"
    if isinstance(default, Path):
        default = str(default)
    if isinstance(default, tuple):
        default = list(default)
    minimum, maximum, step = BOUNDS.get(identity, (None, None, "1"))
    if channel_type == "telegram" and key == "min_interval_seconds":
        minimum = 3
    if key in {"to", "cc", "bcc", "recipients"}:
        kind = "addresses"
    if channel_type == "teams_bot" and key == "recipients":
        # Bot recipients are object IDs or UPNs, not only email addresses.
        kind = "toml"
    if choices:
        kind = "enum"
    help_text = HELP.get(key, "")
    if path == "dashboard" and key.endswith("_env"):
        help_text = "Environment variable name, never its secret contents. Dashboard changes require an administrator."
    elif path == "backup" and key == "directory":
        help_text = "Backup directory. Defaults to the backups directory beside the state database. Only administrators may change filesystem paths."
    elif path == "backup" and key == "compress":
        help_text = "Compress dashboard downloads. Stored backups stay as plain files."
    elif path == "backup" and key == "retention_days":
        help_text = "Delete backups older than this many days, keeping the retained minimum."
    elif path == "backup" and key == "keep_min":
        help_text = "Never delete the newest this many backups, even when they are past retention."
    elif key.endswith("_env"):
        help_text = "Environment variable name, never its secret contents. Changing references requires manage_secrets."
    elif key.endswith("_file"):
        help_text = "Protected secret file reference. Path changes require an administrator; contents are never displayed."
    elif key.endswith("_enabled"):
        help_text = "Enable this vulnerability source."
    elif not help_text:
        help_text = ("Number of seconds." if key.endswith(("_seconds", "_timeout"))
                     else "Enter " + key.replace("_", " ") + " as " + ("a TOML value." if kind == "toml" else "plain text."))
    minimum_exclusive = identity in {"http.connect_timeout", "http.read_timeout", "http.backoff_seconds", "sources.minimum_request_interval"}
    if minimum_exclusive:
        help_text += " Must be greater than zero."
    if identity == "notifications.email.recipients":
        help_text = "Legacy recipient names or addresses, separated by commas or entered as a TOML array. Existing ordering and duplicates are retained."
    example = EXAMPLES.get(key, choices[0] if choices else default if default is not None else "example")
    if path == "backup" and key == "directory":
        example = "backups"
    if key.endswith("_env"):
        example = "EXAMPLE_SECRET"
    elif key.endswith("_file"):
        example = "secrets/channel.txt"
    return FieldMetadata(kind, default, choices, bool(required), help_text, example,
                         minimum, maximum, step, LIST_ENUMS.get(identity, ()), requirement, minimum_exclusive)
