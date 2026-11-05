"""Private client allowlists and fixed companion commands; no network transport."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

from .errors import ConfigurationError
from .identity import validate_client_name
from .launching import child_environment
from .private_storage import private_directory, private_file
from .publication import replace_file
from .web_inventory import decode_json, read_bytes

COMPANION_NOTICE = "Web detection requires the optional Extensions package. Install it to enable these actions."


def companion_available():
    return not getattr(sys, "frozen", False) and importlib.util.find_spec("cvebeacon_extensions") is not None


def require_companion():
    if not companion_available():
        raise ConfigurationError(COMPANION_NOTICE)


def client_label(value):
    try:
        result = validate_client_name(value)
        if not result.strip():
            raise ValueError("client must be nonempty")
        return result
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc


def client_key(client):
    return hashlib.sha256(client_label(client).strip().casefold().encode("utf-8")).hexdigest()


def directories(config):
    data = config.database_path.parent
    assets, inventory = data / "web-assets", data / "web-inventory"
    for directory in (assets, inventory):
        private_directory(directory, owner_only=True)
    return assets, inventory


def paths(config, client):
    assets, inventory = directories(config)
    key = client_key(client)
    return assets / f"{key}.json", inventory / f"{key}.json"


def read_allowlist(path, client):
    try:
        data = read_bytes(path)
    except FileNotFoundError:
        return {"client": client_label(client), "assets": []}, "new"
    document = decode_json(data)
    if (not isinstance(document, dict) or set(document) - {"client", "assets", "ca_bundle"}
            or client_key(document.get("client")) != client_key(client)
            or not isinstance(document.get("assets"), list)
            or len(document["assets"]) > 1000
            or any(not isinstance(row, dict) for row in document["assets"])):
        raise ConfigurationError("Invalid saved web allowlist; review the local file")
    return document, hashlib.sha256(data).hexdigest()


def temporary_json(directory, document):
    return temporary_bytes(directory, (json.dumps(document, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8"))


def temporary_bytes(directory, data):
    path = directory / (".web-assets-" + secrets.token_hex(16) + ".tmp")
    descriptor = private_file(path, create=True, exclusive=True)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def companion_command(client, assets, output, *, plan=False):
    require_companion()
    label = client_label(client)
    client_arguments = ["--client=" + label] if label.startswith("-") else ["--client", label]
    return [sys.executable, "-I", "-u", "-m", "cvebeacon_extensions", "web", "detect",
            *client_arguments, "--assets", str(assets), "--output", str(output),
            "--source-id", "web-" + client_key(client), "--allow-partial", *(["--plan"] if plan else [])]


def validate_allowlist(config, path, document):
    # The companion's plan path calls the TD-1 validator and performs no DNS or IO to targets.
    require_companion()
    temporary = temporary_json(path.parent, document)
    try:
        if not document["assets"]:
            return  # Removing the last entry leaves a non-runnable, empty client record.
        result = subprocess.run(
            companion_command(document["client"], temporary, path.parent / ".validation-output", plan=True),
            stdin=subprocess.DEVNULL, capture_output=True, timeout=30, env=child_environment(config),
        )
        if result.returncode:
            error = result.stderr.decode("utf-8", "replace")[:1024].strip()
            raise ConfigurationError(error or "The companion refused the allowlist")
    except subprocess.TimeoutExpired as exc:
        raise ConfigurationError("Allowlist validation timed out") from exc
    finally:
        temporary.unlink(missing_ok=True)


def save_allowlist(path, document):
    replace_bytes(path, (json.dumps(document, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8"))


def replace_bytes(path, data):
    # Check an existing destination too; replacement must never hide a linked or public file.
    if path.exists() or path.is_symlink():
        read_bytes(path)
    temporary = temporary_bytes(path.parent, data)
    try:
        replace_file(temporary, path)
        if os.name == "posix":
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def run_detection(config, client, *, plan=False):
    assets, output = paths(config, client)
    document, _ = read_allowlist(assets, client)
    if not document["assets"]:
        raise ConfigurationError("Save an attested web asset before running detection")
    # The parent CLI holds the shared scan lock throughout the child process.
    code = subprocess.call(companion_command(document["client"], assets, output, plan=plan),
                           stdin=subprocess.DEVNULL, env=child_environment(config))
    if not plan and code == 0:
        output.with_name(output.name + ".removed").unlink(missing_ok=True)
    return code
