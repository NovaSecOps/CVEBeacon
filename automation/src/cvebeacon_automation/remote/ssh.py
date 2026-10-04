"""Strict system OpenSSH, stdin-only probe, and unchanged v1 normalization."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile

from cvebeacon_extensions.contract import (ExtensionError, MAX_BYTES, decode_json, json_bytes,
    manifest_path, read_bytes, write_snapshot)
from cvebeacon_extensions.hosts import linux_inventory

from ..common import AutomationError, atomic, digest, directory, identifier, now, regular
from ..config import number
from ..process import run
from ..staging import publish
from .executables import executable
from .probe import REMOTE_COMMAND, script

OPTIONS = {"host", "user", "port", "known_hosts", "key", "timeout", "backend", "package_namespace"}


def _file_path(value, base: Path) -> Path:
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value) or any(c in value for c in '%$"\x7f'):
        raise AutomationError("invalid_ssh_path")
    return Path(os.path.abspath(base / value))


def validate_options(options, base: Path) -> dict:
    """Only typed configuration is normalized here; key material is never read."""
    if not isinstance(options, dict) or set(options) - OPTIONS:
        raise AutomationError("invalid_ssh_options")
    host, user = options.get("host"), options.get("user")
    if not isinstance(host, str) or not host or len(host) > 253 or "%" in host:
        raise AutomationError("invalid_ssh_host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host) or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in host.split(".")):
            raise AutomationError("invalid_ssh_host") from None
    else:
        if address.is_unspecified or address.is_multicast:
            raise AutomationError("invalid_ssh_host")
        host = str(address)
    if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", user):
        raise AutomationError("invalid_ssh_user")
    backend = options.get("backend", "auto")
    if not isinstance(backend, str) or backend not in {"auto", "dpkg", "rpm"}:
        raise AutomationError("invalid_ssh_backend")
    namespace = options.get("package_namespace")
    if namespace is not None and (not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", namespace)):
        raise AutomationError("invalid_ssh_package_namespace")
    return dict(host=host, user=user, port=number(options.get("port", 22), 1, 65535),
        known_hosts=_file_path(options.get("known_hosts"), base), key=_file_path(options.get("key"), base),
        timeout=number(options.get("timeout", 60), 5, 300), backend=backend, package_namespace=namespace)


def _regular_path(path: Path):
    # Ancestors are administrator controlled, but cannot redirect the supplied path.
    try:
        for item in (path, *path.parents):
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise AutomationError("unsafe_ssh_path")
        regular(path)
    except OSError:
        raise AutomationError("ssh_file_unavailable") from None


def argv(options: dict) -> list[str]:
    _regular_path(options["key"])
    _regular_path(options["known_hosts"])
    if os.name == "posix":
        if options["key"].stat().st_mode & 0o077:
            raise AutomationError("ssh_key_permissions")
        if options["known_hosts"].stat().st_mode & 0o022:
            raise AutomationError("ssh_known_hosts_permissions")
    settings = ["BatchMode=yes", "StrictHostKeyChecking=yes", "NoHostAuthenticationForLocalhost=no",
        'UserKnownHostsFile="' + options["known_hosts"].as_posix() + '"', "GlobalKnownHostsFile=none",
        "UpdateHostKeys=no", "VerifyHostKeyDNS=no", "CheckHostIP=no", "IdentitiesOnly=yes", "IdentityAgent=none",
        "PreferredAuthentications=publickey", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
        "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes", "PermitLocalCommand=no", "ProxyCommand=none",
        "ProxyJump=none", "KnownHostsCommand=none", "ControlPath=none", "ControlMaster=no", "ControlPersist=no",
        "ConnectionAttempts=1", "ConnectTimeout=" + str(min(15, options["timeout"])), "ServerAliveInterval=10",
        "ServerAliveCountMax=2", "LogLevel=ERROR"]
    result = [executable("ssh"), "-F", "none", "-T", "-a", "-x"]
    for setting in settings:
        result.append("-o" + setting)
    result.extend(["-i", options["key"].as_posix(), "-p", str(options["port"]), "-l", options["user"],
        options["host"], REMOTE_COMMAND])
    return result


def collect_ssh(config, source) -> dict:
    identifier(source.id, "source_id")
    options = validate_options(source.options, config.config_path.parent)
    command = argv(options)
    observed_at = now()
    directory(config.state_dir)
    with tempfile.TemporaryDirectory(prefix=".ssh-", dir=config.state_dir) as temporary:
        home = Path(temporary)
        code, output = run(command, timeout=options["timeout"], limit=MAX_BYTES, input=script(options["backend"]),
            cwd=home, environment={name: str(home) for name in ("HOME", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA")})
        if code != 0:
            # Never include stderr, hostname, key path, command, or remote payload in an error.
            raise AutomationError("ssh_collection_failed")
        try:
            data = decode_json(output)
            if not isinstance(data, dict) or set(data) != {"version", "backend", "os_release", "packages"} or type(data["version"]) is not int or data["version"] != 1:
                raise AutomationError("ssh_probe_protocol_invalid")
            if not isinstance(data["backend"], str) or data["backend"] not in {"dpkg", "rpm"} or options["backend"] != "auto" and data["backend"] != options["backend"]:
                raise AutomationError("ssh_probe_backend_mismatch")
            if not isinstance(data["os_release"], str) or not isinstance(data["packages"], str):
                raise AutomationError("ssh_probe_protocol_invalid")
            rows, reviews = linux_inventory(data["os_release"], data["packages"], backend=data["backend"],
                source_id=source.id, package_namespace=options["package_namespace"])
            if not rows:
                raise AutomationError("ssh_no_valid_inventory")
            candidate = home / "inventory.json"
            write_snapshot(candidate, rows, source_id=source.id, collector="automation-ssh-v1",
                observed_at=observed_at, omissions=["review-required"] if reviews else [])
            inventory = read_bytes(candidate)
            manifest = read_bytes(manifest_path(candidate), 65536)
            generation = digest(inventory + b"\x00" + manifest)
            review_folder = directory(directory(config.state_dir / "remote") / source.id)
            review_file = review_folder / (generation + ".review.json")
            review_bytes = json_bytes(dict(version=1, source_id=source.id, reviews=reviews))
            if len(review_bytes) > MAX_BYTES:
                raise AutomationError("ssh_review_limit")
            if review_file.exists() or review_file.is_symlink():
                regular(review_file)
                if read_bytes(review_file) != review_bytes:
                    raise AutomationError("ssh_review_conflict")
            else:
                atomic(review_file, review_bytes)
            result = publish(config.staging_dir, source.id, inventory, manifest, max_age_seconds=source.max_age_seconds)
        except ExtensionError:
            raise AutomationError("ssh_observations_invalid") from None
    return {**result, "observations": len(rows), "review_required": len(reviews)}


def collect_winrm(*args, **kwargs):
    """No unvalidated WinRM transport can silently be enabled by configuration."""
    raise AutomationError("winrm_disabled_no_validated_secure_backend")
