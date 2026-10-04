"""Strict versioned TOML; examples contain references, never credentials."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib

from cvebeacon_extensions.contract import read_bytes
from .common import AutomationError, identifier


def keys(value, allowed):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise AutomationError("unknown_configuration_setting")
    return value


def number(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise AutomationError("invalid_configuration_bound")
    return value


def boolean(value):
    if type(value) is not bool:
        raise AutomationError("invalid_configuration_boolean")
    return value


def path(base: Path, value) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise AutomationError("invalid_configuration_path")
    return Path(os.path.abspath(base / value))


def tables(value, maximum=128):
    if not isinstance(value, list) or len(value) > maximum or not all(isinstance(item, dict) for item in value):
        raise AutomationError("invalid_configuration_list")
    return value


@dataclass(frozen=True)
class Source:
    id: str
    kind: str = "snapshot"
    required: bool = True
    max_age_seconds: int = 86400
    allow_partial: bool = False
    snapshot: Path | None = None
    options: dict = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class Config:
    config_path: Path
    state_dir: Path
    staging_dir: Path
    inventory_path: Path
    core_config: Path
    sources: tuple[Source, ...]
    core_timeout: int = 600
    core_env: tuple[str, ...] = ()
    notifications: tuple[dict, ...] = field(default=(), repr=False)
    registries: tuple[dict, ...] = field(default=(), repr=False)
    discovery: tuple[dict, ...] = field(default=(), repr=False)
    operations: dict = field(default_factory=dict)


def input_paths(config: Config) -> set[Path]:
    """Explicit configured inputs, including credential files, without reading them."""
    base = config.config_path.parent
    result = {config.config_path, config.core_config}
    for source in config.sources:
        if source.snapshot:
            result.update({source.snapshot, source.snapshot.with_name(source.snapshot.name + ".manifest.json")})
        for key in (("observations",) if source.kind == "kubernetes" else ("key", "known_hosts") if source.kind == "ssh" else ()):
            if key in source.options:
                result.add(path(base, source.options[key]))
    def files(value):
        if isinstance(value, dict):
            if set(value) == {"file"}:
                result.add(path(base, value["file"]))
            for child in value.values():
                files(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                files(child)
    files((config.notifications, config.registries))
    for registry in config.registries:
        if "ca_file" in registry:
            result.add(path(base, registry["ca_file"]))
    return result


def load_config(filename: str | Path) -> Config:
    filename = Path(os.path.abspath(filename))
    base = filename.parent
    try:
        data = tomllib.loads(read_bytes(filename, 1024 * 1024).decode("utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise AutomationError("configuration_unreadable") from None
    keys(data, {"automation", "sources", "notifications", "registries", "discovery", "operations"})
    settings = keys(data.get("automation", {}), {"version", "state_dir", "staging_dir", "inventory_path", "core_config", "core_timeout", "core_env"})
    if type(settings.get("version")) is not int or settings["version"] != 1:
        raise AutomationError("unsupported_configuration_version")
    state = path(base, settings.get("state_dir", "automation-state"))
    staging = path(base, settings.get("staging_dir", "staging"))
    inventory = path(base, settings.get("inventory_path", "merged.json"))
    core = path(base, settings.get("core_config"))
    output_pair = {inventory, inventory.with_name(inventory.name + ".manifest.json")}
    if state == staging or output_pair & {core, filename} or state in (core, filename, inventory) or staging in (core, filename, inventory):
        raise AutomationError("configuration_path_collision")
    env = settings.get("core_env", [])
    import re
    if not isinstance(env, list) or len(env) > 32 or any(not isinstance(item, str) or not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", item) for item in env):
        raise AutomationError("invalid_core_environment")
    sources, seen = [], set()
    for item in tables(data.get("sources", [])):
        keys(item, {"id", "kind", "required", "max_age_seconds", "allow_partial", "snapshot", "options"})
        name = identifier(item.get("id"), "source_id")
        if name.casefold() in seen:
            raise AutomationError("duplicate_source_id")
        seen.add(name.casefold())
        kind = item.get("kind", "snapshot")
        if kind not in {"snapshot", "upload", "ssh", "registry", "kubernetes"}:
            raise AutomationError("unsupported_source_kind")
        snapshot = path(base, item["snapshot"]) if "snapshot" in item else None
        input_pair = {snapshot, snapshot.with_name(snapshot.name + ".manifest.json")} if snapshot else set()
        if (kind == "snapshot") != (snapshot is not None) or input_pair & (output_pair | {core, filename}):
            raise AutomationError("invalid_source_snapshot")
        options = item.get("options", {})
        if not isinstance(options, dict) or (kind in {"snapshot", "upload"} and options):
            raise AutomationError("invalid_source_options")
        sources.append(Source(name, kind, boolean(item.get("required", True)), number(item.get("max_age_seconds", 86400), 1, 31536000),
                              boolean(item.get("allow_partial", False)), snapshot, options))
    notifications = tuple(tables(data.get("notifications", []), 32))
    registries = tuple(tables(data.get("registries", []), 32))
    discovery = tuple(tables(data.get("discovery", []), 16))
    operations = keys(data.get("operations", {}), {"enabled", "interval_seconds", "failures", "recovery", "discovery"})
    if operations:
        boolean(operations.get("enabled", False))
        number(operations.get("interval_seconds", 86400), 60, 604800)
        for flag in ("failures", "recovery", "discovery"):
            boolean(operations.get(flag, False))
    # Explicit adapters validate their own finite schemas before any network IO.
    if notifications:
        from .notifications.adapters import validate_channels
        validate_channels(notifications, base)
    if registries:
        from .registry.client import validate_registries
        validate_registries(registries, base)
    for source in sources:
        if source.kind == "ssh":
            from .remote.ssh import validate_options
            validate_options(source.options, base)
        if source.kind in {"registry", "kubernetes"}:
            from .registry.acquire import validate_source
            validate_source(source, registries)
    if discovery:
        from .discovery.nmap import validate_jobs
        validate_jobs(discovery)
    def secret_names(value):
        if isinstance(value, dict):
            if set(value) == {"env"}:
                yield value["env"]
            for nested in value.values():
                yield from secret_names(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                yield from secret_names(nested)
    if set(env) & set(secret_names((notifications, registries))):
        raise AutomationError("integration_credential_in_core_environment")
    result = Config(filename, state, staging, inventory, core, tuple(sources), number(settings.get("core_timeout", 600), 5, 3600),
                    tuple(env), notifications, registries, discovery, operations)
    owned = output_pair | {state / name for name in ("health.json", "automation.lock", "notifications.lock", "notification-ledger.sqlite3")}
    owned.update(state / ("collection-" + source.id + ".json") for source in sources)
    if owned & input_paths(result):
        raise AutomationError("configuration_path_collision")
    return result
