"""Small TOML configuration model."""

from __future__ import annotations

import os
import math
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigurationError

CANONICAL_FIELDS = ("asset_id", "vendor", "product", "version")


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
    nvd_enabled: bool = True
    cve_enabled: bool = True
    euvd_enabled: bool = True
    cisa_kev_enabled: bool = True
    eu_kev_enabled: bool = True
    epss_enabled: bool = True
    nvd_api_key_env: str = "NVD_API_KEY"
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
class AppConfig:
    config_path: Path
    inventory: InventoryConfig
    database_path: Path
    output_dir: Path
    http: HttpConfig = field(default_factory=HttpConfig)
    sources: SourceConfig = field(default_factory=SourceConfig)
    product_mappings: tuple[ProductMapping, ...] = ()
    teams: TeamsConfig = field(default_factory=TeamsConfig)
    email: EmailConfig = field(default_factory=EmailConfig)

    def secret(self, env_name: str, *, required: bool = False) -> str | None:
        value = os.environ.get(env_name)
        if required and not value:
            raise ConfigurationError(f"required environment variable is not set: {env_name}")
        return value


def _table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigurationError(f"[{key}] must be a table")
    return value


def _positive_number(value: Any, name: str, *, minimum: float = 0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{name} must be a number")
    number = float(value)
    if not math.isfinite(number) or number <= minimum:
        raise ConfigurationError(f"{name} must be greater than {minimum}")
    return number


def _boolean(table: dict[str, Any], key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigurationError(f"{key} must be true or false")
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
    inv = _table(data, "inventory")
    if not inv.get("path"):
        raise ConfigurationError("inventory.path is required")
    columns = inv.get("columns", {name: name for name in CANONICAL_FIELDS})
    if not isinstance(columns, dict):
        raise ConfigurationError("inventory.columns must be a table")
    missing = [name for name in CANONICAL_FIELDS if not columns.get(name)]
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

    state = _table(data, "state")
    output = _table(data, "output")
    http_data = _table(data, "http")
    source_data = _table(data, "sources")
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
        inventory=InventoryConfig(
            path=_resolve(base, inv["path"]),
            format=inventory_format,
            worksheet=inv.get("worksheet"),
            header_row=header_row,
            records_path=inv.get("records_path"),
            delimiter=delimiter,
            encoding=str(inv.get("encoding", "utf-8-sig")),
            columns={name: str(columns[name]) for name in CANONICAL_FIELDS},
        ),
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
            nvd_enabled=_boolean(source_data, "nvd_enabled", True),
            cve_enabled=_boolean(source_data, "cve_enabled", True),
            euvd_enabled=_boolean(source_data, "euvd_enabled", True),
            cisa_kev_enabled=_boolean(source_data, "cisa_kev_enabled", True),
            eu_kev_enabled=_boolean(source_data, "eu_kev_enabled", True),
            epss_enabled=_boolean(source_data, "epss_enabled", True),
            nvd_api_key_env=nvd_api_key_env.strip(),
            minimum_request_interval=_positive_number(
                source_data.get("minimum_request_interval", 6),
                "sources.minimum_request_interval",
            ),
        ),
        product_mappings=tuple(mappings),
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
    )
