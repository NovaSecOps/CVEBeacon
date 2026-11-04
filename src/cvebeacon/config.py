"""Small TOML configuration model."""

from __future__ import annotations

import os
import math
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .watch.channels import ChannelConfig, parse_channels, validate_rule_channels
from .watch.rules import Rule, parse_rules, validate_rule_sources

CANONICAL_FIELDS = ("asset_id", "vendor", "product", "version")
OPTIONAL_FIELDS = ("category", "system_id", "ecosystem", "purl", "cpe", "repository", "commit")
WATCH_SOURCES = ("nvd", "euvd", "cisa_kev", "eu_kev", "epss")
WATCH_INITIAL_MODES = ("baseline", "backfill", "full")
WATCH_SETTINGS = {
    "enabled",
    "database",
    "sources",
    "initial",
    "backfill_days",
    "overlap_minutes",
    "rules",
    "channels",
}


def _resolve(base: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()


@dataclass(frozen=True, slots=True)
class InventoryConfig:
    path: Path
    format: str = "auto"
    worksheet: str | None = None
    header_row: int = 1
    records_path: str | None = None
    delimiter: str = ","
    encoding: str = "utf-8-sig"
    columns: dict[str, str] = field(
        default_factory=lambda: {name: name for name in CANONICAL_FIELDS}
    )


@dataclass(frozen=True, slots=True)
class HttpConfig:
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    retries: int = 3
    backoff_seconds: float = 1.0
    user_agent: str = "CVEBeacon/0.1"


@dataclass(frozen=True, slots=True)
class SourceConfig:
    osv_enabled: bool = True
    nvd_enabled: bool = True
    cve_enabled: bool = True
    euvd_enabled: bool = True
    cisa_kev_enabled: bool = True
    eu_kev_enabled: bool = True
    epss_enabled: bool = True
    nvd_api_key_env: str = "NVD_API_KEY"
    nvd_api_key_file: Path | None = None
    minimum_request_interval: float = 6.0


@dataclass(frozen=True, slots=True)
class ProductMapping:
    vendor: str
    product: str
    cpe: str


@dataclass(frozen=True, slots=True)
class TeamsConfig:
    enabled: bool = False
    webhook_env: str = "CVEBEACON_TEAMS_WEBHOOK_URL"


@dataclass(frozen=True, slots=True)
class EmailConfig:
    enabled: bool = False
    tenant_id_env: str = "CVEBEACON_M365_TENANT_ID"
    client_id_env: str = "CVEBEACON_M365_CLIENT_ID"
    client_secret_env: str = "CVEBEACON_M365_CLIENT_SECRET"
    sender: str = ""
    recipients: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DashboardConfig:
    password_hash_env: str = "CVEBEACON_DASHBOARD_PASSWORD_HASH"
    session_lifetime_seconds: int = 3600
    secure_cookie: bool = False


@dataclass(frozen=True, slots=True)
class WatchConfig:
    enabled: bool = False
    database: Path = Path("cvebeacon-watch.db")
    sources: tuple[str, ...] = WATCH_SOURCES
    initial: str = "baseline"
    backfill_days: int = 7
    overlap_minutes: int = 15
    rules: tuple[Rule, ...] = ()
    channels: tuple[ChannelConfig, ...] = ()


@dataclass(frozen=True, slots=True)
class AppConfig:
    config_path: Path
    inventory: InventoryConfig | None
    database_path: Path
    output_dir: Path
    http: HttpConfig = field(default_factory=HttpConfig)
    sources: SourceConfig = field(default_factory=SourceConfig)
    product_mappings: tuple[ProductMapping, ...] = ()
    teams: TeamsConfig = field(default_factory=TeamsConfig)
    email: EmailConfig = field(default_factory=EmailConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    watch: WatchConfig = field(default_factory=WatchConfig)

    def secret(self, env_name: str, *, required: bool = False) -> str | None:
        value = os.environ.get(env_name)
        if required and not value:
            raise ConfigurationError(f"required environment variable is not set: {env_name}")
        return value

    def nvd_api_key(self) -> str | None:
        value = self.secret(self.sources.nvd_api_key_env)
        if value and value.strip():
            return value.strip()
        path = self.sources.nvd_api_key_file
        if path is None:
            return None
        try:
            return path.read_text(encoding="utf-8").strip() or None
        except (OSError, UnicodeError):
            return None


def _table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigurationError(f"[{key}] must be a table")
    return value


def _positive_number(value: Any, name: str, *, minimum: float = 0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{name} must be a number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ConfigurationError(f"{name} must be greater than {minimum}") from exc
    if not math.isfinite(number) or number <= minimum:
        raise ConfigurationError(f"{name} must be greater than {minimum}")
    return number


def _boolean(table: dict[str, Any], key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigurationError(f"{key} must be true or false")
    return value


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).expanduser().resolve()
    try:
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigurationError(f"configuration file not found: {config_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigurationError(f"invalid TOML in {config_path}: {exc}") from exc
    except OSError as exc:
        raise ConfigurationError(f"cannot read configuration {config_path}: {exc}") from exc

    base = config_path.parent
    watch_data = _table(data, "watch")
    unknown_watch = sorted(set(watch_data) - WATCH_SETTINGS)
    if unknown_watch:
        raise ConfigurationError("unknown watch setting: " + ", ".join(unknown_watch))
    watch_enabled = _boolean(watch_data, "enabled", False)
    raw_watch_sources = watch_data.get("sources", list(WATCH_SOURCES))
    if not isinstance(raw_watch_sources, list) or not all(
        isinstance(value, str) and value.strip() for value in raw_watch_sources
    ):
        raise ConfigurationError("watch.sources must be a list of source names")
    watch_sources = tuple(dict.fromkeys(value.strip().casefold() for value in raw_watch_sources))
    unknown_sources = sorted(set(watch_sources) - set(WATCH_SOURCES))
    if unknown_sources:
        raise ConfigurationError("unknown watch source: " + ", ".join(unknown_sources))
    if "nvd" not in watch_sources:
        raise ConfigurationError("watch.sources must include nvd")
    watch_initial = str(watch_data.get("initial", "baseline")).strip().casefold()
    if watch_initial not in WATCH_INITIAL_MODES:
        raise ConfigurationError("watch.initial must be baseline, backfill, or full")
    watch_database = watch_data.get("database", "cvebeacon-watch.db")
    if not isinstance(watch_database, str) or not watch_database.strip():
        raise ConfigurationError("watch.database must be a nonempty path")
    watch_rules = parse_rules(watch_data.get("rules"))
    validate_rule_sources(watch_rules, watch_sources)
    watch_channels = parse_channels(watch_data.get("channels"), base=base)
    validate_rule_channels(watch_rules, watch_channels)

    inv = _table(data, "inventory")
    inventory_config: InventoryConfig | None = None
    if inv.get("path"):
        columns = inv.get("columns", {name: name for name in CANONICAL_FIELDS})
        if not isinstance(columns, dict):
            raise ConfigurationError("inventory.columns must be a table")
        missing = [name for name in columns if name in CANONICAL_FIELDS + OPTIONAL_FIELDS and not columns.get(name)]
        if not columns.get("asset_id"):
            missing.append("asset_id")
        if missing:
            raise ConfigurationError(
                "inventory.columns is missing mappings for: " + ", ".join(missing)
            )
        header_row = inv.get("header_row", 1)
        if not isinstance(header_row, int) or isinstance(header_row, bool) or header_row < 1:
            raise ConfigurationError("inventory.header_row must be an integer of at least 1")
        delimiter = inv.get("delimiter", ",")
        if not isinstance(delimiter, str) or len(delimiter) != 1:
            raise ConfigurationError("inventory.delimiter must be one character")
        inventory_format = str(inv.get("format", "auto")).casefold().lstrip(".")
        if inventory_format == "yml":
            inventory_format = "yaml"
        if inventory_format not in {"auto", "xlsx", "csv", "json", "yaml"}:
            raise ConfigurationError("inventory.format must be auto, xlsx, csv, json, or yaml")
        inventory_config = InventoryConfig(
            path=_resolve(base, inv["path"]),
            format=inventory_format,
            worksheet=inv.get("worksheet"),
            header_row=header_row,
            records_path=inv.get("records_path"),
            delimiter=delimiter,
            encoding=str(inv.get("encoding", "utf-8-sig")),
            columns={name: str(value) for name, value in columns.items() if name in CANONICAL_FIELDS + OPTIONAL_FIELDS},
        )
    elif not watch_enabled:
        raise ConfigurationError("inventory.path is required")

    state = _table(data, "state")
    output = _table(data, "output")
    http_data = _table(data, "http")
    source_data = _table(data, "sources")
    dashboard_data = _table(data, "dashboard")
    if set(dashboard_data) - {"password_hash_env", "session_lifetime_seconds", "secure_cookie"}:
        raise ConfigurationError("unknown dashboard setting; supply the password hash only through its environment variable")
    hash_env = dashboard_data.get("password_hash_env", "CVEBEACON_DASHBOARD_PASSWORD_HASH")
    if not isinstance(hash_env, str) or not hash_env.strip():
        raise ConfigurationError("dashboard.password_hash_env must be a nonempty environment variable name")
    lifetime = dashboard_data.get("session_lifetime_seconds", 3600)
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or not 60 <= lifetime <= 86400:
        raise ConfigurationError("dashboard.session_lifetime_seconds must be an integer from 60 to 86400")
    notification_data = _table(data, "notifications")
    teams_data = notification_data.get("teams", {})
    email_data = notification_data.get("email", {})
    if not isinstance(teams_data, dict) or not isinstance(email_data, dict):
        raise ConfigurationError("notification channel settings must be tables")
    teams_enabled = _boolean(teams_data, "enabled", False)
    email_enabled = _boolean(email_data, "enabled", False)

    retries = http_data.get("retries", 3)
    if not isinstance(retries, int) or isinstance(retries, bool) or not 0 <= retries <= 10:
        raise ConfigurationError("http.retries must be an integer from 0 to 10")
    user_agent = str(http_data.get("user_agent", "CVEBeacon/0.1")).strip()
    if not user_agent:
        raise ConfigurationError("http.user_agent cannot be blank")
    nvd_api_key_env = source_data.get("nvd_api_key_env", "NVD_API_KEY")
    if not isinstance(nvd_api_key_env, str) or not nvd_api_key_env.strip():
        raise ConfigurationError("sources.nvd_api_key_env cannot be blank")
    raw_nvd_key_file = source_data.get("nvd_api_key_file")
    nvd_api_key_file: Path | None = None
    if raw_nvd_key_file is not None:
        if not isinstance(raw_nvd_key_file, str) or not raw_nvd_key_file.strip():
            raise ConfigurationError("sources.nvd_api_key_file must be a nonempty path")
        nvd_api_key_file = _resolve(base, raw_nvd_key_file.strip())
        try:
            details = nvd_api_key_file.stat()
        except OSError as exc:
            raise ConfigurationError(
                f"sources.nvd_api_key_file cannot be read: {nvd_api_key_file}"
            ) from exc
        if not nvd_api_key_file.is_file():
            raise ConfigurationError(
                f"sources.nvd_api_key_file must be a file: {nvd_api_key_file}"
            )
        if details.st_size > 16 * 1024:
            raise ConfigurationError("sources.nvd_api_key_file must be at most 16384 bytes")
        if os.name == "posix" and stat.S_IMODE(details.st_mode) & 0o077:
            raise ConfigurationError(
                "sources.nvd_api_key_file must not be group or other accessible"
            )
    raw_recipients = email_data.get("recipients", [])
    if not isinstance(raw_recipients, list) or not all(
        isinstance(value, str) and value.strip() for value in raw_recipients
    ):
        raise ConfigurationError("notifications.email.recipients must be a list of strings")
    sender = str(email_data.get("sender", "")).strip()
    if email_enabled and (not sender or not raw_recipients):
        raise ConfigurationError("enabled email notifications require sender and at least one recipient")
    env_values = {
        "notifications.teams.webhook_env": teams_data.get("webhook_env", "CVEBEACON_TEAMS_WEBHOOK_URL"),
        "notifications.email.tenant_id_env": email_data.get("tenant_id_env", "CVEBEACON_M365_TENANT_ID"),
        "notifications.email.client_id_env": email_data.get("client_id_env", "CVEBEACON_M365_CLIENT_ID"),
        "notifications.email.client_secret_env": email_data.get("client_secret_env", "CVEBEACON_M365_CLIENT_SECRET"),
    }
    if any(not isinstance(value, str) or not value.strip() for value in env_values.values()):
        raise ConfigurationError("notification credential environment-variable names cannot be blank")

    mappings: list[ProductMapping] = []
    mapping_keys: set[tuple[str, str]] = set()
    raw_mappings = data.get("product_mappings", [])
    if not isinstance(raw_mappings, list):
        raise ConfigurationError("product_mappings must be an array of tables")
    for index, item in enumerate(raw_mappings, start=1):
        if not isinstance(item, dict) or not all(item.get(k) for k in ("vendor", "product", "cpe")):
            raise ConfigurationError(
                f"product_mappings entry {index} requires vendor, product, and cpe"
            )
        vendor, product, cpe = item["vendor"].strip(), item["product"].strip(), item["cpe"].strip()
        key = (vendor.casefold(), product.casefold())
        if key in mapping_keys:
            raise ConfigurationError(f"duplicate product_mappings entry for {vendor} / {product}")
        if not cpe.startswith("cpe:2.3:"):
            raise ConfigurationError(f"product_mappings entry {index} must use a CPE 2.3 name")
        mapping_keys.add(key)
        mappings.append(ProductMapping(vendor, product, cpe))

    return AppConfig(
        config_path=config_path,
        inventory=inventory_config,
        database_path=_resolve(base, state.get("database", ".cvebeacon/state.db")),
        output_dir=_resolve(base, output.get("directory", "reports")),
        http=HttpConfig(
            connect_timeout=_positive_number(
                http_data.get("connect_timeout", 10), "http.connect_timeout"
            ),
            read_timeout=_positive_number(
                http_data.get("read_timeout", 30), "http.read_timeout"
            ),
            retries=retries,
            backoff_seconds=_positive_number(
                http_data.get("backoff_seconds", 1), "http.backoff_seconds"
            ),
            user_agent=user_agent,
        ),
        sources=SourceConfig(
            osv_enabled=_boolean(source_data, "osv_enabled", True),
            nvd_enabled=_boolean(source_data, "nvd_enabled", True),
            cve_enabled=_boolean(source_data, "cve_enabled", True),
            euvd_enabled=_boolean(source_data, "euvd_enabled", True),
            cisa_kev_enabled=_boolean(source_data, "cisa_kev_enabled", True),
            eu_kev_enabled=_boolean(source_data, "eu_kev_enabled", True),
            epss_enabled=_boolean(source_data, "epss_enabled", True),
            nvd_api_key_env=nvd_api_key_env.strip(),
            nvd_api_key_file=nvd_api_key_file,
            minimum_request_interval=_positive_number(
                source_data.get("minimum_request_interval", 6),
                "sources.minimum_request_interval",
            ),
        ),
        product_mappings=tuple(mappings),
        dashboard=DashboardConfig(hash_env.strip(), lifetime, _boolean(dashboard_data, "secure_cookie", False)),
        teams=TeamsConfig(
            enabled=teams_enabled,
            webhook_env=str(
                teams_data.get("webhook_env", "CVEBEACON_TEAMS_WEBHOOK_URL")
            ),
        ),
        email=EmailConfig(
            enabled=email_enabled,
            tenant_id_env=str(
                email_data.get("tenant_id_env", "CVEBEACON_M365_TENANT_ID")
            ),
            client_id_env=str(
                email_data.get("client_id_env", "CVEBEACON_M365_CLIENT_ID")
            ),
            client_secret_env=str(
                email_data.get("client_secret_env", "CVEBEACON_M365_CLIENT_SECRET")
            ),
            sender=sender,
            recipients=tuple(value.strip() for value in raw_recipients),
        ),
        watch=WatchConfig(
            enabled=watch_enabled,
            database=_resolve(base, watch_database.strip()),
            sources=watch_sources,
            initial=watch_initial,
            backfill_days=_bounded_int(
                watch_data.get("backfill_days", 7), "watch.backfill_days", 1, 120
            ),
            overlap_minutes=_bounded_int(
                watch_data.get("overlap_minutes", 15), "watch.overlap_minutes", 0, 1440
            ),
            rules=watch_rules,
            channels=watch_channels,
        ),
    )
