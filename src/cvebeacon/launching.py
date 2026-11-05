"""Launch the same installed command without searching a working directory."""

from dataclasses import fields, is_dataclass
from collections.abc import Mapping
import os
import sys


def command_prefix() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-I", "-u", "-m", "cvebeacon"]


def child_environment(config) -> dict[str, str]:
    # Runtime locations, TLS trust and proxy settings are needed by the CLI.
    names = {
        "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
        "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "LANG", "LC_ALL",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "no_proxy",
    }

    def references(value):
        if is_dataclass(value):
            for field in fields(value):
                item = getattr(value, field.name)
                if (field.name.endswith("_env") or field.name == "env") and isinstance(item, str):
                    names.add(item)
                else:
                    references(item)
        elif isinstance(value, Mapping):
            for item in value.values():
                references(item)
        elif isinstance(value, (tuple, list)):
            for item in value:
                references(item)

    for part in (config.sources, config.teams, config.email, config.watch):
        references(part)
    if os.name == "nt":
        names = {name.upper() for name in names}
    environment = {key: value for key, value in os.environ.items() if key in names or key.upper() in names}
    environment["PYTHONUNBUFFERED"] = "1"
    return environment
