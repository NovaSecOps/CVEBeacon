"""Signed release checks and the administrator-owned native update transaction.

The web process can write only a tiny request. Policy, executable code, verified
wheels, backups and the transaction journal belong to the administrator.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from email.parser import BytesParser
import errno
import hashlib
import ipaddress
from importlib.metadata import version as installed_version
import json
import logging
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.parse import quote, urlsplit
import uuid
import zipfile

import httpx

from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.requirements import Requirement
from packaging.version import InvalidVersion, Version

from .config import HttpConfig, UPDATE_STATUS_DIR, UpdateConfig, load_config
from .errors import CVEBeaconError
from .http import HttpClient
from .locking import LOCK_NAME, RunInProgress, RunLock
from .private_storage import private_directory, private_file
from .release_repository import valid_repository
from .update_transaction import JOURNAL, read_record

LOG = logging.getLogger(__name__)
REQUEST = "update-request.json"
STATUS = "update-status.json"
CHECK_STATUS = "update-check-status.json"
REQUEST_STATUS = "update-request-status.json"
ATTEMPT_STATUS = "update-attempt-status.json"
MAX_STATUS = 131072
MAX_NOTES = 65536
MAX_LEGACY_STATUS = 12 * MAX_NOTES + 8192
ADVISORY_FORMAT = "cvebeacon-update-advisory-v1"
ADVISORY_FILES = {STATUS, CHECK_STATUS, REQUEST_STATUS, ATTEMPT_STATUS}
ADVISORY_MARKER = ".cvebeacon-advisory-v1"
ADVISORY_MARKER_BYTES = b"CVEBeacon update advisory\n"
_JSON_TOKENS = re.compile(r'\\.|["{}\[\]]', re.DOTALL)
MAX_REQUEST = 1024
MAX_ASSETS = 256
MAX_ARTIFACT = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
PACKAGES = ("cvebeacon", "cvebeacon-extensions", "cvebeacon-automation")
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
OPERATION_ERRORS = (CVEBeaconError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError)


class UpdateError(CVEBeaconError):
    def __init__(self, message, *, reason_code=None):
        super().__init__(message)
        self.reason_code = reason_code


class ConfigLock(RunLock):
    """Share the dashboard editor's flock without changing its private mode."""
    def _open(self):
        private_directory(self.path.parent)
        return private_file(self.path, create=True)


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_warning(message):
    try:
        LOG.warning(message)
    except Exception:
        pass  # Logging must never interrupt state recovery.


REASON_STEPS = {
    "preflight": "preflight-failed",
    "check": "check-failed",
    "verify": "verify-artifact",
    "probe": "probe-unhealthy",
    "quiesce": "quiesce-failed",
    "lock": "lock-failed",
    "freeze": "freeze-failed",
    "backup": "backup-failed",
    "install": "install-failed",
    "migrate": "migrate-failed",
    "switch": "switch-failed",
    "start": "start-failed",
    "doctor": "doctor-failed",
    "recovery": "recovery-incomplete",
    "adopt": "adopt-failed",
    "finalize-timers": "finalize-timers-failed",
    "finalize-archive": "finalize-archive-failed",
    "finalize-cleanup": "finalize-cleanup-failed",
}
REASON_CODES = frozenset(REASON_STEPS.values()) | frozenset({
    "preflight-crontab-unreadable",
    "preflight-managed-crontab",
    "check-network",
    "verify-signature",
    "backup-database-busy",
    "request-invalid",
    "request-claim-failed",
    "policy-invalid",
    "version-invalid",
    "update-failed",
})


def release_version(value):
    if not isinstance(value, str) or len(value) > 96 or not re.fullmatch(r"[0-9][A-Za-z0-9.!+_-]*", value):
        raise UpdateError("invalid release version")
    try:
        result = Version(value)
    except InvalidVersion:
        raise UpdateError("invalid release version") from None
    if str(result) != value:
        raise UpdateError("use the canonical PEP 440 release version")
    return result


def diagnostic_version(value):
    try:
        release_version(value)
    except UpdateError:
        return None
    return value


def diagnostic_reason(value):
    return value if isinstance(value, str) and value in REASON_CODES else None


def diagnostic_result(target, result, *, reason=None):
    entry = {"version": diagnostic_version(target), "result": result,
             "time": datetime.now(timezone.utc).isoformat(timespec="microseconds")}
    if code := diagnostic_reason(reason):
        entry["reason"] = code
    return entry


def _json(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8-sig")
        depth, quoted = 0, False
        for match in _JSON_TOKENS.finditer(raw):
            token = match[0]
            if token == '"':
                quoted = not quoted
            elif not quoted and token in ("{", "["):
                depth += 1
                if depth > 32:
                    raise ValueError("JSON exceeds the nesting limit")
            elif not quoted and token in ("}", "]"):
                depth -= 1
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, RecursionError, MemoryError):
        raise UpdateError("invalid update JSON") from None


def read_bounded(path, limit):
    fd = private_file(Path(path), readonly=True, owner_only=False)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise UpdateError("update file exceeds the size limit")
    return raw


def atomic_json(path, value, *, mode=0o644, advisory=False):
    """Replace a file through an anchored parent; never follow its old inode."""
    path = Path(path)
    if platform.system() == "Windows":
        # Check-only Windows installs still persist their advisory status.
        from .publication import replace_file
        private_directory(path.parent)
        temporary = path.with_name(".update-" + uuid.uuid4().hex)
        try:
            occupied = _previous_advisory(path) if advisory else None
            fd = private_file(temporary, create=True, exclusive=True)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=True)
                stream.flush()
                os.fsync(stream.fileno())
            if advisory and occupied is None:
                os.rename(temporary, path)  # Windows rename fails if the name is now occupied.
            else:
                if advisory and _previous_advisory(path) != occupied:
                    raise UpdateError("update status destination changed")
                replace_file(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = ".update-" + uuid.uuid4().hex
    try:
        if advisory:
            import fcntl
            details = os.fstat(parent)
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o750:
                raise UpdateError("invalid update status directory")
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            marker = os.open(ADVISORY_MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(marker, "rb") as stream:
                if (not stat.S_ISREG(os.fstat(stream.fileno()).st_mode)
                        or stream.read(64) != ADVISORY_MARKER_BYTES):
                    raise UpdateError("unrecognized update status directory")
            # Use the open directory for both inspection and publication.
            occupied = _previous_advisory(path.name, parent=parent)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            json.dump(value, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        if advisory and occupied is None:
            os.link(name, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(name, dir_fd=parent)
        else:
            if advisory and _previous_advisory(path.name, parent=parent) != occupied:
                raise UpdateError("update status destination changed")
            os.rename(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def _advisory_value(value, filename):
    if (isinstance(value, dict) and set(value) == {"format", "kind", "value"}
            and value["format"] == ADVISORY_FORMAT and value["kind"] == filename
            and isinstance(value["value"], dict)):
        return value["value"]
    raise UpdateError("unrecognized update status file")


def _previous_advisory(path, *, parent=None):
    try:
        if parent is None:
            fd = private_file(path, readonly=True, owner_only=True)
        else:
            details = os.stat(path, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise UpdateError("occupied update status destination")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if parent is not None and (
            (info.st_dev, info.st_ino) != (details.st_dev, details.st_ino)
            or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o022
        ):
            raise UpdateError("occupied update status destination")
        raw = stream.read(MAX_STATUS + 1)
    if len(raw) > MAX_STATUS:
        raise UpdateError("update file exceeds the size limit")
    _advisory_value(_json(raw), Path(path).name)
    return info.st_dev, info.st_ino


def read_request(path):
    value = _json(read_bounded(path, MAX_REQUEST))
    if not isinstance(value, dict) or set(value) != {"version", "user", "time"}:
        raise UpdateError("invalid update request fields")
    release_version(value["version"])
    if not isinstance(value["user"], str) or not re.fullmatch(r"[\w.@-]{1,128}", value["user"], re.ASCII):
        raise UpdateError("invalid update request user")
    if not isinstance(value["time"], str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", value["time"]):
        raise UpdateError("invalid update request time")
    try:
        datetime.fromisoformat(value["time"])
    except ValueError:
        raise UpdateError("invalid update request time") from None
    return value["version"]  # No identity, path or privilege comes from this file.


def request_update(config, target, proof, users):
    if not config.update.enabled:
        raise UpdateError("updates are disabled")
    release_version(target)
    with users.transaction() as db:
        actor = users.require_admin_in(db, proof)
        request = {"version": target, "user": actor.username, "time": stamp()}
        users._append_audit(db, "update_request:" + target, actor.username, request["time"], actor=actor.username)
    # Authorization and its audit are durable before the path unit can run.
    path, _ = control_paths(config.config_path)
    try:
        private_directory(path.parent)
        atomic_json(path, request, mode=0o600)
    except OSError:
        raise UpdateError("cannot publish the update request") from None


def control_paths(config_path):
    """Runtime and privileged commands share the resolved config directory."""
    directory = Path(config_path).parent.resolve()
    return directory / REQUEST, directory / STATUS


def _read_status_file(path, *, legacy=False, limit=MAX_STATUS):
    try:
        value = _json(read_bounded(path, limit))
        if not legacy:
            return _advisory_value(value, path.name)
        return value if isinstance(value, dict) else {}
    except (OSError, CVEBeaconError):
        return {}


def status_time(entry, key="time"):
    try:
        value = entry[key]
        if not isinstance(value, str) or len(value) > 40:
            return None
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (KeyError, ValueError, OverflowError):
        return None


EARLIEST = datetime.min.replace(tzinfo=timezone.utc)
OUTCOMES = frozenset({
    "adopted", "busy", "recovered; request again", "recovery-refused", "refused",
    "refused; administrator review required", "rollback-failed", "rolled-back", "up-to-date", "updated",
})
LEGACY_WARNINGS = frozenset({
    "completed update recovery could not verify the selected release",
    "update committed; run update recover to finish finalization",
    "update committed; temporary-file cleanup needs administrator review",
})


def _outcome(entry):
    if not isinstance(entry, dict) or not isinstance(entry.get("result"), str) or entry["result"] not in OUTCOMES:
        return {}
    value = {"result": entry["result"], "version": diagnostic_version(entry.get("version"))}
    if status_time(entry) is not None:
        value["time"] = entry["time"]
    for key in ("reason", "recovery_reason", "finalization_reason"):
        if code := diagnostic_reason(entry.get(key)):
            value[key] = code
    warning = entry.get("warning")
    if isinstance(warning, str) and warning in LEGACY_WARNINGS:
        value["warning"] = warning
    return value


def _status_roots(config):
    return tuple(dict.fromkeys((control_paths(config.config_path)[1].parent, config.watch.database.parent)))


def read_status(config):
    # Order by validated event time. On a tie prefer the new format, then the
    # config directory, then a dedicated record over one embedded in a mirror.
    checks, outcomes = [], {}
    for priority, root in enumerate(_status_roots(config)):
        for modern in (False, True):
            directory = root / UPDATE_STATUS_DIR if modern else root
            tie = (modern, -priority)
            for filename in (STATUS, CHECK_STATUS, REQUEST_STATUS, ATTEMPT_STATUS):
                if priority and filename not in (STATUS, CHECK_STATUS):
                    continue  # Only a portable release check uses the fallback.
                limit = MAX_LEGACY_STATUS if not modern and filename == STATUS else MAX_STATUS
                value = _read_status_file(directory / filename, legacy=not modern, limit=limit)
                if not value:
                    continue
                if filename in (STATUS, CHECK_STATUS):
                    checked = _check_fields(value)
                    if checked:
                        updated = _outcome(value.get("last_update"))
                        check_time = status_time(checked, "last_check") or EARLIEST
                        if updated.get("result") == "updated" and "available" in checked:
                            check_time = max(check_time, status_time(updated) or EARLIEST)
                        checks.append(((check_time, *tie, filename == CHECK_STATUS), checked))
                    if filename == CHECK_STATUS:
                        continue
                    entries = ((key, value.get(key)) for key in ("last_update", "last_request", "last_attempt"))
                else:
                    entries = (("last_request" if filename == REQUEST_STATUS else "last_attempt", value),)
                for key, entry in entries:
                    if outcome := _outcome(entry):
                        when = status_time(outcome)
                        rank = (when is not None, when or EARLIEST, *tie, filename != STATUS)
                        if key not in outcomes or rank > outcomes[key][0]:
                            outcomes[key] = rank, outcome
    state = dict(max(checks, key=lambda item: item[0])[1]) if checks else {}
    state.update({key: outcome for key, (_, outcome) in outcomes.items()})
    return state


def _check_fields(state):
    fields = {key: diagnostic_version(state[key]) for key in ("current", "available") if key in state}
    notes, checked = state.get("notes"), state.get("last_check")
    if isinstance(notes, str):
        fields["notes"] = notes[:MAX_NOTES]
    if isinstance(checked, str) and len(checked) <= 40:
        fields["last_check"] = checked
    return fields


def _advisory_directory(data):
    path = data / UPDATE_STATUS_DIR
    private_directory(data)
    if os.name == "nt":
        try:
            path.lstat()
        except FileNotFoundError:
            created = True
        else:
            created = False
        private_directory(path, owner_only=True)
    else:
        try:
            path.mkdir(mode=0o750)
        except FileExistsError:
            created = False
        else:
            created = True
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            details = os.fstat(fd)
            if details.st_uid != os.geteuid():
                raise UpdateError("invalid update status owner")
            if created:
                os.fchmod(fd, 0o750)
            elif stat.S_IMODE(details.st_mode) != 0o750:
                raise UpdateError("invalid update status directory mode")
        finally:
            os.close(fd)
    marker = path / ADVISORY_MARKER
    if created:
        with os.fdopen(private_file(marker, create=True, exclusive=True), "wb") as stream:
            stream.write(ADVISORY_MARKER_BYTES)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            sync_directory(path)
            sync_directory(data)
    elif read_bounded(marker, 64) != ADVISORY_MARKER_BYTES:
        raise UpdateError("unrecognized update status directory")
    return path


def _publish_status(path, state):
    if path.name not in ADVISORY_FILES:
        raise UpdateError("invalid update status name")
    state = dict(state)
    envelope = {"format": ADVISORY_FORMAT, "kind": path.name, "value": state}
    notes = state.get("notes")
    if isinstance(notes, str):
        # Match atomic_json's ASCII representation, including surrogate pairs.
        low, high = 0, min(len(notes), MAX_NOTES)
        state["notes"] = notes[:high]
        if len(json.dumps(envelope, ensure_ascii=True)) > MAX_STATUS:
            while low < high:
                middle = (low + high + 1) // 2
                state["notes"] = notes[:middle]
                if len(json.dumps(envelope, ensure_ascii=True)) <= MAX_STATUS:
                    low = middle
                else:
                    high = middle - 1
            state["notes"] = notes[:low]
    atomic_json(path, envelope, mode=0o640, advisory=True)


def _publish_advisory(policy, filename, entry):
    try:
        with _service_credentials(policy):
            load_config(policy.config, allow_state_only=True)
            directory = _advisory_directory(policy.data)
            path = directory / filename
            if filename == STATUS:
                entry = {**_check_fields(_read_status_file(path)), **entry}
            _publish_status(path, entry)
    except (OSError, CVEBeaconError, RuntimeError):
        log_warning("update advisory status is unavailable")


def unsupported_reason():
    if platform.system() != "Linux" or getattr(__import__("sys"), "frozen", False):
        return "Check only: use the native Windows upgrade instructions in docs/UPGRADING.md."
    if Path("/.dockerenv").exists() or os.environ.get("KUBERNETES_SERVICE_HOST") or os.environ.get("CVEBEACON_CONTAINER"):
        return "Check only: use docs/CONTAINERS.md or docs/KUBERNETES.md to upgrade the deployment."
    return None


def validate_wheel(path):
    """No-index alone does not prohibit URL requirements in wheel metadata."""
    try:
        package, version, _, _ = parse_wheel_filename(path.name)
        with zipfile.ZipFile(path) as archive:
            # Only the top-level dist-info describes this wheel; vendored
            # packages may carry their own nested dist-info directories.
            entries = [entry for entry in archive.infolist()
                       if entry.filename.count("/") == 1 and entry.filename.endswith(".dist-info/METADATA")]
            if len(entries) != 1 or entries[0].file_size > 1024 * 1024:
                raise UpdateError("invalid wheel metadata")
            with archive.open(entries[0]) as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise UpdateError("wheel metadata exceeds the size limit")
            metadata = BytesParser().parsebytes(raw)
            if canonicalize_name(metadata.get("Name", "")) != package or Version(metadata.get("Version", "")) != version:
                raise UpdateError("wheel identity differs from its filename")
            for requirement in metadata.get_all("Requires-Dist", []):
                if Requirement(requirement).url:
                    raise UpdateError("direct URL wheel dependencies are forbidden")
    except (zipfile.BadZipFile, ValueError, KeyError, OSError):
        raise UpdateError("invalid release wheel metadata") from None


@dataclass(frozen=True)
class Release:
    version: str
    notes: str
    assets: tuple[str, ...]


class Releases:
    """One anonymous API request per check; URLs never contain local identity."""
    def __init__(self, settings, http):
        self.settings, self.http = settings, http
        if not valid_repository(settings.repository):
            raise UpdateError("invalid release repository")

    def _api(self, target):
        suffix = "/tags/v" + quote(target, safe="") if target else "?per_page=30"
        return "https://api.github.com/repos/" + self.settings.repository + "/releases" + suffix

    def _request(self, url, limit, *, api=False):
        headers = {"User-Agent": "CVEBeacon-release-check"}
        if api:
            headers["Accept"] = "application/vnd.github+json"
        try:
            result = self.http.request_once("GET", url, body_limit=limit + 1, headers=headers, timeout=60)
        except (httpx.HTTPError, ValueError, OSError):
            raise UpdateError("release request failed", reason_code="check-network") from None
        if len(result.body) > limit:
            raise UpdateError("release response exceeds the size limit")
        return result

    def check(self, current, target=None):
        if not self.settings.enabled:
            return None
        if target:
            release_version(target)
        reply = self._request(self._api(target), 512 * 1024, api=True)
        if reply.status_code != 200:
            raise UpdateError("release API check failed")
        payload = _json(reply.body)
        rows = [payload] if target else payload
        if not isinstance(rows, list) or len(rows) > 30:
            raise UpdateError("invalid release API response")
        candidates = []
        for row in rows:
            if not isinstance(row, dict) or row.get("draft") is not False:
                continue
            tag = row.get("tag_name", "")
            if not isinstance(tag, str) or not tag.startswith("v"):
                continue
            try:
                parsed = release_version(tag[1:])
            except UpdateError:
                continue
            if parsed <= Version(current) or (target and str(parsed) != target):
                continue
            if (row.get("prerelease") is not False or parsed.is_prerelease or parsed.is_devrelease) and not self.settings.allow_prereleases:
                continue
            assets = row.get("assets")
            if not isinstance(assets, list) or not 3 <= len(assets) <= MAX_ASSETS:
                raise UpdateError("release has no signed artifact set")
            names = tuple(item.get("name") if isinstance(item, dict) else None for item in assets)
            if any(not isinstance(n, str) or len(n) > 200 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", n) for n in names):
                raise UpdateError("invalid release artifact name")
            if len(set(names)) != len(names) or not {"SHA256SUMS", "SHA256SUMS.sig"} <= set(names):
                raise UpdateError("release is unsigned or has duplicate artifacts")
            notes = row.get("body") or ""
            if not isinstance(notes, str) or len(notes) > MAX_NOTES:
                raise UpdateError("release notes exceed the size limit")
            candidates.append(Release(str(parsed), notes, names))
        if not candidates:
            if target:
                raise UpdateError("release must be newer, published and permitted by policy")
            return None
        return max(candidates, key=lambda item: Version(item.version))

    def download(self, release, name, destination, limit):
        url = f"https://github.com/{self.settings.repository}/releases/download/v{release.version}/{name}"
        # GitHub serves release bodies through a short-lived HTTPS redirect.
        for _ in range(4):
            reply = self._request(url, limit)
            if reply.status_code == 200:
                destination.write_bytes(reply.body)
                return len(reply.body)
            if reply.status_code not in {301, 302, 303, 307, 308}:
                break
            url = reply.headers.get("location", "")
            try:
                parsed = urlsplit(url)
                allowed = (parsed.scheme == "https" and parsed.hostname in {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
                           and not parsed.username and not parsed.password and parsed.port in {None, 443})
            except ValueError:
                allowed = False
            if not allowed:
                raise UpdateError("unsafe release asset redirect")
        raise UpdateError("release artifact download failed")

    def verify(self, release, directory, signers):
        if shutil.which("ssh-keygen", path=SAFE_ENV["PATH"]) is None:
            raise UpdateError("ssh-keygen is required to verify releases; update refused", reason_code="verify-signature")
        directory = Path(directory)
        for name, cap in (("SHA256SUMS", 65536), ("SHA256SUMS.sig", 16384)):
            self.download(release, name, directory / name, cap)
        checksums = (directory / "SHA256SUMS").read_bytes()
        result = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "cvebeacon-release",
                                 "-n", "cvebeacon-release", "-s", str(directory / "SHA256SUMS.sig")],
                                input=checksums, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30, env=SAFE_ENV, cwd="/")
        if result.returncode:
            raise UpdateError("release signature verification failed", reason_code="verify-signature")
        hashes = {}
        try:
            lines = checksums.decode("ascii", errors="strict").splitlines()
        except UnicodeError:
            raise UpdateError("invalid signed checksum manifest") from None
        for line in lines:
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.+-]{0,199})", line)
            if not match or match[2] in hashes:
                raise UpdateError("invalid signed checksum manifest")
            hashes[match[2]] = match[1]
        if set(hashes) != set(release.assets) - {"SHA256SUMS", "SHA256SUMS.sig"}:
            raise UpdateError("signed manifest does not match the release artifacts")
        total = 0
        for name, digest in hashes.items():
            total += self.download(release, name, directory / name, min(MAX_ARTIFACT, MAX_TOTAL - total))
            with (directory / name).open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            if actual != digest:
                raise UpdateError("release artifact checksum mismatch")
        wheels = []
        for name in hashes:
            if name.endswith(".whl"):
                try:
                    package, version, _, _ = parse_wheel_filename(name)
                except ValueError:
                    raise UpdateError("invalid release wheel filename") from None
                if package in {canonicalize_name(n) for n in PACKAGES} and version != Version(release.version):
                    raise UpdateError("release package version differs from its tag")
                validate_wheel(directory / name)
                wheels.append(name)
        if not any(parse_wheel_filename(name)[0] == "cvebeacon" for name in wheels):
            raise UpdateError("release has no core wheel")
        return tuple(wheels)


def check(config, *, daily=False, http=None):
    if not config.update.enabled or (daily and not config.update.daily):
        return read_status(config)
    state = read_status(config)
    if daily and state.get("last_check"):
        try:
            if (datetime.now(timezone.utc) - datetime.fromisoformat(state["last_check"])).total_seconds() < 86400:
                return state
        except (ValueError, TypeError):
            pass
    with ExitStack() as stack:
        transport = http or stack.enter_context(HttpClient(HttpConfig(retries=0)))
        release = Releases(config.update, transport).check(installed_version("cvebeacon"))
    checked = {"current": installed_version("cvebeacon"), "available": release.version if release else None,
               "notes": release.notes if release else "",
               "last_check": datetime.now(timezone.utc).isoformat(timespec="microseconds")}
    if getattr(os, "geteuid", lambda: -1)() != 0:
        for root in _status_roots(config):
            try:
                directory = _advisory_directory(root)
            except PermissionError:
                continue  # A check-only config mount may be read-only.
            except OSError as exc:
                if exc.errno == errno.EROFS:
                    continue
                break
            except CVEBeaconError:
                break
            try:
                _publish_status(directory / CHECK_STATUS, checked)
            except (OSError, CVEBeaconError):
                pass  # Advisory publication cannot fail a successful release check.
            break
    return {**state, **checked}


def protected(path, *, directory=False):
    """All policy and code ancestors must be root-owned and non-writable."""
    path = Path(path).absolute()
    for candidate in (path, *path.parents):
        info = candidate.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise UpdateError("administrator-owned policy and installation paths are required")
        if candidate != path or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise UpdateError("invalid protected directory")
        elif not stat.S_ISREG(info.st_mode):
            raise UpdateError("invalid protected file")
    return path


def protected_tree(path):
    path = Path(path).resolve(strict=True)
    protected(path, directory=True)
    for parent, directories, files in os.walk(path, followlinks=False):
        for name in directories + files:
            entry = Path(parent) / name
            if entry.is_symlink() and entry.is_dir() and not entry.resolve(strict=True).is_relative_to(path):
                raise UpdateError("code directory links must stay inside the virtual environment")
            protected(entry.resolve(strict=True), directory=entry.is_dir())


def service_account(login):
    import pwd
    if not isinstance(login, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", login):
        raise UpdateError("invalid service account name")
    account = pwd.getpwnam(login)
    if account.pw_uid == 0:
        raise UpdateError("the service account must be unprivileged")
    return account


def service_data(config, *, uid):
    """Validate the directory independently of the config file's contents."""
    data = Path(config).parent
    protected(data.parent, directory=True)
    info = data.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid == 0 or info.st_uid != uid
            or info.st_mode & 0o022 or info.st_mode & 0o700 != 0o700):
        raise UpdateError("data must be a real directory writable only by its service account")
    return data


@contextmanager
def _service_credentials(policy):
    # Only the privileged one-shot updater switches effective credentials.
    if os.geteuid() != 0:
        yield
        return
    account = policy._account
    if account is None or policy.config.parent != policy.data:
        raise UpdateError("validated service credentials are required")
    service_data(policy.config, uid=account.pw_uid)
    groups, gid = os.getgroups(), os.getegid()
    try:
        os.setgroups([])
        os.setegid(account.pw_gid)
        os.seteuid(account.pw_uid)
        yield
    finally:
        os.seteuid(0)
        os.setegid(gid)
        os.setgroups(groups)


@dataclass(frozen=True)
class Policy:
    prefix: Path
    config: Path
    data: Path
    user: str
    repository: str = "NovaSecOps/CVEBeacon"
    allow_prereleases: bool = False
    signers: Path = Path(__file__).with_name("release-allowed-signers")
    units: tuple[str, ...] = ("cvebeacon.timer", "cvebeacon.service", "cvebeacon-dashboard.service")
    probe: str = "http://127.0.0.1:8787/healthz"
    retention: int = 7
    wait_seconds: int = 86400
    dashboard_unit: str = "cvebeacon-dashboard.service"
    _account: object = field(init=False, default=None, repr=False, compare=False)

    @classmethod
    def read(cls, path):
        if os.geteuid() != 0:
            raise UpdateError("apply and adopt require an administrator; run with sudo")
        protected(path)
        value = tomllib.loads(read_bounded(path, 16384).decode("utf-8"))
        if value.pop("enabled", False) is not True:
            raise UpdateError("updates are disabled in administrator policy")
        allowed = {entry.name for entry in fields(cls) if entry.init}
        if set(value) - allowed or not {"prefix", "config", "data", "user"} <= set(value):
            raise UpdateError("invalid administrator update policy fields")
        for key in ("prefix", "config", "data", "signers"):
            if key in value:
                if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
                    raise UpdateError("policy paths must be absolute")
                value[key] = Path(value[key])
        if "units" in value:
            if not isinstance(value["units"], list) or len(value["units"]) > 32:
                raise UpdateError("invalid update units")
            value["units"] = tuple(value["units"])
        policy = cls(**value)
        if not isinstance(policy.allow_prereleases, bool) or not valid_repository(policy.repository):
            raise UpdateError("invalid release policy")
        for key, lo, hi in (("retention", 1, 100), ("wait_seconds", 1, 86400)):
            if type(getattr(policy, key)) is not int or not lo <= getattr(policy, key) <= hi:
                raise UpdateError("invalid update policy limit")
        if not policy.units or len(set(policy.units)) != len(policy.units) or any(not isinstance(u, str) or not re.fullmatch(r"cvebeacon[\w@.-]*\.(service|timer)", u) or u.startswith("cvebeacon-update") for u in policy.units):
            raise UpdateError("invalid update unit name")
        if policy.dashboard_unit not in policy.units or not policy.dashboard_unit.endswith(".service"):
            raise UpdateError("the explicit dashboard unit must be included in units")
        parsed = urlsplit(policy.probe)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.username or parsed.password or parsed.path != "/healthz" or parsed.query or parsed.fragment:
            raise UpdateError("health probe must use the loopback /healthz endpoint")
        protected(policy.prefix, directory=True)
        protected(policy.signers)
        # Data and runtime config may be service-owned; never execute either.
        account = service_account(policy.user)
        if policy.config.parent != policy.data or policy.config.name == UPDATE_STATUS_DIR:
            raise UpdateError("runtime config must be directly inside the data directory")
        service_data(policy.config, uid=account.pw_uid)
        if policy.data.is_relative_to(policy.prefix):
            raise UpdateError("data must be separate from code")
        object.__setattr__(policy, "_account", account)
        try:
            pending = read_record(policy.prefix)
        except OPERATION_ERRORS:
            raise UpdateError("the update journal requires administrator recovery",
                              reason_code="recovery-incomplete") from None
        if pending is not None and pending.get("config") == str(policy.config.parent.resolve() / policy.config.name):
            return policy  # Recovery may need to replace a missing or corrupt runtime config.
        info = policy.config.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in {0, account.pw_uid} or info.st_mode & 0o022:
            raise UpdateError("runtime config must be a regular administrator- or service-owned file")
        return policy


def switch(prefix, target):
    """The link is replaced atomically, never removed before replacement."""
    prefix, target = Path(prefix), Path(target)
    if target.parent != prefix / "releases" or target.is_symlink() or not target.is_dir():
        raise UpdateError("invalid release switch target")
    name = prefix / (".current-" + uuid.uuid4().hex)
    try:
        name.symlink_to(target.relative_to(prefix), target_is_directory=True)
        os.replace(name, prefix / "current")
        fd = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        name.unlink(missing_ok=True)


class Native:
    """Small OS boundary; tests replace this with local fakes."""
    def __init__(self, policy):
        self.policy = policy
        self.account = policy._account or service_account(policy.user)

    def run(self, args, *, service=False, timeout=600, accepted=(0,), completed=False, env=SAFE_ENV, **kwargs):
        options = {}
        if service and os.geteuid() == 0:
            options.update(user=self.account.pw_uid, group=self.account.pw_gid, extra_groups=())
        result = subprocess.run([str(a) for a in args], env=env, cwd="/", stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, umask=0o022, **options, **kwargs)
        if result.returncode not in accepted:
            raise UpdateError("update subprocess failed (details withheld); inspect the transaction journal")
        return result if completed else result.stdout

    def active(self, unit):
        result = subprocess.run(["systemctl", "show", "--property=ActiveState", "--value", unit], env=SAFE_ENV,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        if result.returncode or result.stdout.strip() not in {b"active", b"activating", b"reloading", b"deactivating", b"inactive", b"failed"}:
            raise UpdateError("cannot determine update unit state")
        return result.stdout.strip() not in {b"inactive", b"failed"}

    def stop(self, units):
        # Stop timers first. A oneshot sync is allowed to finish, never SIGTERM'd.
        timers = [u for u in units if u.endswith(".timer")]
        if timers:
            self.run(["systemctl", "stop", *timers])
        deadline = time.monotonic() + self.policy.wait_seconds
        while any(self.active(u) for u in units if u.endswith(".service") and u != self.policy.dashboard_unit):
            if time.monotonic() >= deadline:
                raise UpdateError("timed out waiting for running services; no process was killed")
            time.sleep(1)

    def freeze(self, units):
        # Only after all run locks are held: systemd also stops dashboard children.
        dashboards = [u for u in units if u == self.policy.dashboard_unit]
        if dashboards:
            self.run(["systemctl", "stop", *dashboards])

    def start(self, units):
        # Timers resume only after commit and after releasing resource locks.
        selected = [u for u in units if u.endswith(".timer") or u == self.policy.dashboard_unit]
        if selected:
            self.run(["systemctl", "start", *selected])

    def inventory(self, venv):
        code = "import importlib.metadata as m,json; ds=list(m.distributions()); assert not any(json.loads(d.read_text('direct_url.json') or '{}').get('dir_info',{}).get('editable') for d in ds), 'editable installs cannot be adopted'; print(json.dumps({d.metadata['Name'].lower():d.version for d in ds}))"
        return _json(self.run([venv / "bin/python", "-I", "-c", code], service=True))

    def service_access(self, venv):
        code = "import os,sys; assert os.access(sys.argv[1],os.R_OK|os.X_OK); open(sys.argv[2],'rb').read(1)"
        self.run([venv / "bin/python", "-I", "-c", code, venv / "bin/cvebeacon", self.policy.config], service=True)
        self.run([venv / "bin/cvebeacon", "--help"], service=True)

    def directory_access(self, venv, directories):
        code = "import os,sys; assert all(os.access(p,os.R_OK|os.X_OK) and not os.access(p,os.W_OK) for p in sys.argv[1:])"
        self.run([venv / "bin/python", "-I", "-c", code, *directories], service=True)

    def managed_cron(self):
        if shutil.which("crontab", path=SAFE_ENV["PATH"]) is None:
            return
        login = self.policy.user
        try:
            account = service_account(login)
            if (account.pw_uid, account.pw_gid) != (self.account.pw_uid, self.account.pw_gid):
                raise UpdateError("service account identity changed")
            # Keep root credentials and use the exact login approved by policy.
            result = self.run(["crontab", "-l", "-u", login], accepted=(0, 1), completed=True,
                              env={**SAFE_ENV, "LC_ALL": "C"})
            if result.returncode != 0:
                diagnostic = b"no crontab for " + login.encode("ascii")
                stdout, stderr = result.stdout.removesuffix(b"\n"), result.stderr.removesuffix(b"\n")
                if result.returncode == 1 and (stdout, stderr) in {(b"", diagnostic), (diagnostic, b"")}:
                    return
                raise UpdateError("unexpected crontab diagnostic")
        except OPERATION_ERRORS:
            raise UpdateError("cannot verify the service account's managed crontab",
                              reason_code="preflight-crontab-unreadable") from None
        if b"# BEGIN CVEBEACON MANAGED" in result.stdout:
            raise UpdateError("remove the service account's managed cron schedule before adopting or applying updates",
                              reason_code="preflight-managed-crontab")

    def preflight(self, venv):
        self.service_access(venv)
        self.managed_cron()
        paths = self.lock_paths(venv / "bin/python")
        # Probe using the same credentials and checked lock implementations as
        # the transaction. Contention is allowed; inaccessible storage is not.
        code = """import os,sys,tempfile
from pathlib import Path
from cvebeacon.updater import ConfigLock
from cvebeacon.locking import RunLock
from cvebeacon.private_storage import private_directory
for directory in {Path(p).parent for p in sys.argv[1:]}:
    private_directory(directory)
    fd, path = tempfile.mkstemp(prefix='.update-preflight-', dir=directory)
    os.close(fd)
    os.unlink(path)
ConfigLock(sys.argv[1]).probe()
for path in sys.argv[2:]:
    RunLock(path).probe()
"""
        self.run([venv / "bin/python", "-I", "-c", code,
                  self.policy.config.with_name(".config-" + self.policy.config.name + ".lock"), *paths],
                 service=True, timeout=None)

    def lock_paths(self, python, backup=None, manifest_hash=None):
        action = "recovery-paths" if backup else "paths"
        arguments = [python, "-I", "-m", "cvebeacon.update_state", action, self.policy.config, self.policy.data, backup or "-"]
        raw = self.run([*arguments, *([manifest_hash] if manifest_hash else [])], service=True, timeout=None)
        paths = _json(raw)
        if not isinstance(paths, list) or len(paths) > 20000 or any(not isinstance(p, str) or not Path(p).is_relative_to(self.policy.data) or Path(p).name != LOCK_NAME for p in paths):
            raise UpdateError("invalid run lock paths")
        return tuple(Path(p) for p in paths)

    def acquire_lock(self, lock):
        # Opening storage with service credentials prevents privileged writes
        # through a raced data-directory entry. Only this one-shot CLI calls it.
        with _service_credentials(self.policy):
            return lock.acquire()

    def install(self, venv, artifacts, packages, target, *, python=None):
        self.run([python or sys.executable, "-I", "-S", "-m", "venv", venv])
        self.run([venv / "bin/python", "-I", "-m", "pip", "--isolated", "install", "--no-index", "--only-binary=:all:",
                  "--find-links", artifacts, *[name + "==" + target for name in packages]])
        self.run([venv / "bin/python", "-I", "-m", "pip", "--isolated", "check"])

    def command(self, release, command):
        options = ["--allow-watch-only", "--local-state"] if command == "doctor" else []
        return self.run([release / ".venv/bin/cvebeacon", "--config", self.policy.config, command, *options], service=True, timeout=None)

    def state(self, python, action, backup, manifest_hash=None):
        # SQLite and config I/O runs with service privileges, even on rollback.
        result = self.run([python, "-I", "-m", "cvebeacon.update_state", action, self.policy.config, self.policy.data, backup,
                           *([manifest_hash] if manifest_hash else [])], service=True, timeout=None,
                          accepted=(0, 75), completed=True)
        if result is not None and result.returncode == 75:
            if action == "backup":
                raise UpdateError("database remained busy during backup (details withheld)",
                                  reason_code="backup-database-busy")
            raise UpdateError("database remained busy during recovery (details withheld)",
                              reason_code="recovery-incomplete")
        return result.stdout if result is not None else None

    def backup_directory(self, path):
        path.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(path, self.account.pw_uid, self.account.pw_gid)
        sync_directory(path.parent)

    def dashboard_pid(self, *, timeout):
        raw = self.run(["systemctl", "show", self.policy.dashboard_unit, "--property=ActiveState,MainPID,ExecStart"],
                       timeout=timeout)
        values = dict(line.split("=", 1) for line in raw.decode("utf-8").splitlines() if "=" in line)
        match = re.search(r"(?:^|[ {])path=([^ ;}]+)\s*;", values.get("ExecStart", ""))
        executable = str(self.policy.prefix / "current/.venv/bin/cvebeacon")
        if (values.get("ActiveState") != "active" or not values.get("MainPID", "").isdigit()
                or int(values["MainPID"]) <= 0 or not match or match[1] != executable):
            raise UpdateError("the configured dashboard unit must run the current executable")
        return int(values["MainPID"])

    @staticmethod
    def process_start(pid):
        # The comm field may contain spaces or parentheses. Field 22 is the
        # start time in clock ticks since boot, after the closing parenthesis.
        fields = Path(f"/proc/{pid}/stat").read_bytes().rpartition(b")")[2].split()
        if len(fields) < 20:
            raise UpdateError("cannot determine the dashboard process start time")
        return int(fields[19])

    def listener_sockets(self, pid):
        """Find matching listening socket inodes held by the unit's process."""
        listeners = set()
        sockets = set()
        for path in Path(f"/proc/{pid}/fd").iterdir():
            try:
                link = os.readlink(path)
            except FileNotFoundError:
                continue  # A process may close an unrelated fd during inspection.
            if link.startswith("socket:["):
                sockets.add(link[8:-1])
        endpoint = urlsplit(self.policy.probe)
        address = ipaddress.ip_address(endpoint.hostname)
        port = endpoint.port or 80
        for protocol in (("tcp",) if address.version == 4 else ("tcp6",)):
            try:
                rows = Path(f"/proc/{pid}/net/{protocol}").read_text().splitlines()[1:]
            except FileNotFoundError:
                continue
            for line in rows:
                fields = line.split()
                if len(fields) < 10 or fields[3] != "0A" or fields[9] not in sockets:
                    continue
                encoded, local_port = fields[1].split(":")
                # proc encodes each 32-bit address word in host byte order.
                packed = b"".join(int(encoded[i:i + 8], 16).to_bytes(4, sys.byteorder) for i in range(0, len(encoded), 8))
                bound = ipaddress.ip_address(packed)
                if int(local_port, 16) == port and (bound == address or bound.is_unspecified):
                    listeners.add(fields[9])
        return listeners

    def owns_listener(self, pid):
        return bool(self.listener_sockets(pid))

    def probe(self, expected_version=None):
        expected_version = expected_version or (self.policy.prefix / "current").resolve().name
        deadline = time.monotonic() + 120

        def timeout():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpdateError("dashboard health probe deadline elapsed")
            return min(2, remaining)

        delay = 0.5
        while time.monotonic() < deadline:
            try:
                pid = self.dashboard_pid(timeout=timeout())
                started = self.process_start(pid)
                listeners = self.listener_sockets(pid)
                if listeners:
                    # A new client prevents an attempt from reusing a socket
                    # connected to a previously observed process.
                    with httpx.Client(trust_env=False) as client, HttpClient(HttpConfig(retries=0), client=client) as http:
                        result = http.request_once("GET", self.policy.probe, body_limit=1024, timeout=timeout())
                    if (result.status_code == 200
                            and _json(result.body) == {"status": "ok", "version": expected_version, "pid": pid}
                            and self.dashboard_pid(timeout=timeout()) == pid
                            and listeners & self.listener_sockets(pid)
                            and self.process_start(pid) == started
                            and time.monotonic() < deadline):
                        return
            except (OSError, ValueError, CVEBeaconError, subprocess.SubprocessError, httpx.HTTPError):
                pass
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 16)
        raise UpdateError("dashboard loopback health probe failed", reason_code="probe-unhealthy")


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def release_directory(path, *, mode=0o755):
    path.mkdir(mode=mode, exist_ok=True)
    protected(path, directory=True)
    # mkdir's mode is filtered by the administrator's umask. These dedicated
    # code/layout directories need explicit traversal, including after retry.
    path.chmod(mode)
    return path


def sync_tree(path):
    """Persist installed bytes and entries, without following directory links."""
    def failed(error):
        raise error
    for parent, _, files in os.walk(path, topdown=False, followlinks=False, onerror=failed):
        for name in files:
            entry = Path(parent) / name
            if entry.is_symlink():
                continue  # Its containing directory persists the link itself.
            descriptor = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise UpdateError("invalid installed release file")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        sync_directory(parent)
    sync_directory(Path(path).parent)


def consume_request(config_path):
    request, _ = control_paths(config_path)
    claimed = request.with_name(".claimed-update-" + uuid.uuid4().hex)
    try:
        os.rename(request, claimed)
    except FileNotFoundError:
        return None
    except OSError:
        raise UpdateError("cannot claim the update request", reason_code="request-claim-failed") from None
    try:
        try:
            return read_request(claimed)
        except (OSError, CVEBeaconError):
            raise UpdateError("invalid update request", reason_code="request-invalid") from None
    finally:
        try:
            claimed.unlink(missing_ok=True)
        except OSError:
            # The watched name is already consumed. Leave quarantined input
            # alone if it cannot be removed with service credentials.
            log_warning("claimed update request could not be removed")


class Updater:
    def __init__(self, policy, native=None, releases=None):
        self.policy = policy
        self.native = native or Native(policy)
        self.releases = releases
        self.events = []
        self.record = None
        self.failure_step = None
        self.failure_reason = None

    def event(self, step, result="ok", *, reason=None):
        entry = {"time": stamp(), "step": step, "result": result,
                 "version": diagnostic_version(getattr(self, "target", None))}
        if code := diagnostic_reason(reason):
            entry["reason"] = code
        self.events.append(entry)
        try:
            LOG.info("update %s: %s", step, result)
        except Exception:
            pass
        try:
            import fcntl
            fd = private_file(self.policy.prefix / "update-audit.jsonl", create=True)
            with os.fdopen(fd, "ab") as stream:
                fcntl.fcntl(stream.fileno(), fcntl.F_SETFL, os.O_APPEND)
                stream.write(json.dumps(entry).encode("ascii") + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, CVEBeaconError):
            log_warning("update audit is unavailable")

    @staticmethod
    def _reason_code(step, error):
        return diagnostic_reason(getattr(error, "reason_code", None)) or REASON_STEPS.get(step, "update-failed")

    def _record_failure(self, step, error):
        reason = self._reason_code(step, error)
        self.failure_reason = reason
        self.event(step, "failed", reason=reason)
        return reason

    def current(self):
        link = self.policy.prefix / "current"
        if not link.is_symlink():
            raise UpdateError("adopt the versioned layout before applying updates")
        target = link.resolve(strict=True)
        if target.parent != self.policy.prefix / "releases":
            raise UpdateError("current link is outside the release layout")
        release_version(target.name)
        protected(target, directory=True)
        return target

    def _checkpoint(self, phase, *, record=None, **fields):
        record = {**(self.record if record is None else record), **fields, "phase": phase}
        atomic_json(self.policy.prefix / JOURNAL, record, mode=0o644)
        self.record = record

    def _begin(self, old, target, active, *, kind="apply"):
        if read_record(self.policy.prefix) is not None:
            raise UpdateError("finish recovery before beginning another update")
        self.record = {"format": 1, "id": uuid.uuid4().hex, "kind": kind,
                       "old": old, "new": target, "active": list(active),
                       "config": str(self.policy.config.parent.resolve() / self.policy.config.name), "data": str(self.policy.data.resolve()),
                       "user": self.policy.user, "dashboard_unit": self.policy.dashboard_unit,
                       "backup": None if kind == "adopt" else datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex,
                       "snapshot_ready": False, "time": stamp()}
        self._checkpoint("adopting" if kind == "adopt" else "quiescing")

    def _validate_recovery(self, record):
        p = self.policy
        if (record.get("config") != str(p.config.parent.resolve() / p.config.name) or record.get("data") != str(p.data.resolve())
                or record.get("user") != p.user or record.get("dashboard_unit") != p.dashboard_unit
                or not isinstance(record.get("active"), list) or not set(record["active"]) <= set(p.units)):
            raise UpdateError("restore the original administrator policy before recovering this transaction")
        self.record = record
        self.target, self.previous_version = record["new"], record["old"]
        reason = diagnostic_reason(record.get("failure_reason"))
        self.failure_reason = reason if reason != "recovery-incomplete" else None

    @contextmanager
    def _locks(self, record, *, completed=False):
        p = self.policy
        locks = []
        deadline = time.monotonic() + p.wait_seconds
        def acquire(lock):
            locks.append(lock)
            while not self.native.acquire_lock(lock):
                if time.monotonic() >= deadline:
                    raise UpdateError("timed out waiting for the run lock; no process was killed")
                time.sleep(0.1)
        try:
            acquire(ConfigLock(p.config.with_name(".config-" + p.config.name + ".lock"), command="update"))
            backup = p.prefix / "backups" / record["backup"] if record["snapshot_ready"] else None
            python = p.prefix / "releases" / record["old"] / ".venv/bin/python"
            paths = set()
            if completed:
                selected = record["new"] if record["result"] == "updated" else record["old"]
                release = self.current()
                if release.name != selected:
                    raise UpdateError("completed transaction does not match the selected release")
                protected_tree(release / ".venv")
                paths.update(self.native.lock_paths(release / ".venv/bin/python"))
            if backup:
                paths.update(self.native.lock_paths(python, backup=backup,
                                                    manifest_hash=record.get("manifest_sha256")))
            elif not completed:
                paths.update(self.native.lock_paths(python))
            for path in sorted(paths):
                acquire(RunLock(path, command="update"))
            yield release if completed else None
        finally:
            for lock in reversed(locks):
                lock.release()

    def _archive(self):
        # Keep the active entry until the completed copy and its name are
        # durable. Recovery of a complete record never restores old databases.
        archive = release_directory(self.policy.prefix / "transactions")
        self.native.directory_access(self.policy.prefix / "current/.venv", (archive,))
        sync_directory(self.policy.prefix)
        atomic_json(archive / (self.record["id"] + ".json"), self.record)
        sync_directory(archive)
        active = self.policy.prefix / JOURNAL
        active.unlink()
        try:
            sync_directory(self.policy.prefix)
        except OSError:
            # The archive is already durable. Retain an explicit retry entry
            # when removal durability is uncertain, without changing outcome.
            atomic_json(active, self.record)
            raise

    def _finish(self, result):
        record = dict(self.record)
        if record.get("failure_reason") == "recovery-incomplete":
            record.pop("failure_reason")  # Clear the legacy recovery-only marker.
        self._checkpoint("complete", record=record, result=result)

    def _completed_result(self, record, *, warning=None, recovery_reason=None, finalization_reason=None):
        result = record["result"]
        selected = record["new"] if result == "updated" else record["old"]
        self._result(selected, result, warning=warning, recovery_reason=recovery_reason,
                     finalization_reason=finalization_reason)
        return {"result": result, "version": selected, **({"warning": warning} if warning else {})}

    def _finalize(self):
        step = "finalize-timers"
        try:
            self._resume_timers(self.record)
            step = "finalize-archive"
            self._archive()
        except OPERATION_ERRORS:
            reason = REASON_STEPS[step]
            self.event(step, "failed", reason=reason)
            warning = "update committed; run update recover to finish finalization"
            log_warning(warning)
            outcome = self._completed_result(self.record, warning=warning, finalization_reason=reason)
        else:
            outcome = self._completed_result(self.record)
        self._retain_best_effort()
        return outcome

    def _resume_timers(self, record):
        timers = tuple(unit for unit in record["active"] if unit.endswith(".timer"))
        if timers:
            self.native.start(timers)

    def _update_lock(self, command, *, requested=False):
        lock = RunLock(self.policy.prefix / "update.lock", command=command)
        try:
            if lock.acquire():
                return lock
            raise RunInProgress(lock.holder)
        except OPERATION_ERRORS as exc:
            busy = requested and isinstance(exc, RunInProgress)
            result = "busy" if busy else "refused" if command == "update" else "recovery-refused"
            entry = diagnostic_result(self.target, result, reason="lock-failed")
            self.failure_reason = "lock-failed"
            self.event("request_busy" if busy else "lock", "refused" if busy else "failed", reason="lock-failed")
            _publish_advisory(self.policy, REQUEST_STATUS if requested else ATTEMPT_STATUS, entry)
            raise

    def _read_pending(self, *, result):
        try:
            return read_record(self.policy.prefix)
        except OPERATION_ERRORS:
            reason = "recovery-incomplete"
            self.event("recovery", "failed", reason=reason)
            if self.record and self.record.get("phase") == "complete":
                self._completed_result(self.record, recovery_reason=reason)
            else:
                self._result(self.target, result, reason=reason)
            self.failure_reason = reason
            raise UpdateError("update recovery remains incomplete; inspect the active recovery record") from None

    def apply(self, target=None, *, from_request=False, _requested=False):
        requested = from_request or _requested
        self.target = None
        self.record = self.failure_step = self.failure_reason = None
        self.checked = {}
        if from_request:
            try:
                if target is not None:
                    raise UpdateError("--version and --from-request are mutually exclusive", reason_code="request-invalid")
                with _service_credentials(self.policy):
                    target = consume_request(self.policy.config)
            except OPERATION_ERRORS as exc:
                reason = self._reason_code("request", exc)
                if reason == "update-failed":
                    reason = "request-claim-failed"
                self.failure_reason = reason
                self.event("request_refused", "failed", reason=reason)
                self._request_result(None, "refused", reason=reason)
                raise
            if target is None:
                return {"result": "no-request"}
        if target is not None and diagnostic_version(target) is None:
            self.failure_reason = "version-invalid"
            self.event("version", "failed", reason=self.failure_reason)
            filename = REQUEST_STATUS if requested else ATTEMPT_STATUS
            _publish_advisory(self.policy, filename,
                              diagnostic_result(None, "refused", reason=self.failure_reason))
            raise UpdateError("invalid or noncanonical release version", reason_code=self.failure_reason)
        self.target = target
        try:
            lock = self._update_lock("update", requested=requested)
        except RunInProgress:
            if requested:
                return {"result": "busy", "version": target}
            raise
        try:
            pending = self._read_pending(result="refused")
            result = self._recover(pending) if pending else self._apply_or_restore(target)
        except OPERATION_ERRORS:
            if requested:
                reason = self.failure_reason or "update-failed"
                self.event("request_refused", "failed", reason=reason)
                self._request_result(target, "refused", reason=reason)
            raise
        else:
            if requested:
                self._request_result(target, "recovered; request again" if pending else result["result"])
            return result
        finally:
            lock.release()

    def _apply_or_restore(self, target):
        try:
            return self._apply(target)
        except BaseException as exc:
            # An atomic replacement can succeed before its directory fsync
            # raises. Recover from the observed record, including commit.
            pending = self._read_pending(result="rollback-failed" if self.record else "refused")
            if pending:
                if pending["phase"] != "complete":
                    reason = self._record_failure(self.failure_step or "recovery", exc)
                    pending = {**pending, "failure_reason": reason}
                    try:
                        self._checkpoint(pending["phase"], record=pending)
                    except OSError:
                        log_warning("update failure reason could not be saved in the recovery record")
                result = self._recover(pending)
                if result["result"] == "updated":
                    return result
                raise UpdateError("update failed; previous release and state restored") from None
            if self.record and self.record["phase"] == "complete":
                reason = REASON_STEPS["finalize-cleanup"]
                self.event("finalize-cleanup", "failed", reason=reason)
                warning = "update committed; temporary-file cleanup needs administrator review"
                return self._completed_result(self.record, warning=warning, finalization_reason=reason)
            reason = self._record_failure(self.failure_step or "recovery", exc)
            self._result(target, "refused", reason=reason)
            raise

    def _apply(self, target):
        p = self.policy
        self.failure_step = "preflight"
        old = self.current()
        protected_tree(old / ".venv")
        self.native.preflight(old / ".venv")
        packages = self.native.inventory(old / ".venv")
        if packages.get("cvebeacon") != old.name:
            raise UpdateError("installed version differs from the current release directory")
        self.previous_version = old.name
        settings = UpdateConfig(True, False, p.repository, p.allow_prereleases)
        with ExitStack() as stack:
            remote = self.releases or Releases(settings, stack.enter_context(HttpClient(HttpConfig(retries=0))))
            self.failure_step = "check"
            release = remote.check(old.name, target)
            self.target = release.version if release else old.name
            self.checked = {"last_check": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                            "available": release.version if release else None, "notes": release.notes if release else ""}
            self.event("check")
            if release is None:
                self._result(old.name, "up-to-date")
                return {"result": "up-to-date", "version": old.name}
            release_version(release.version)
            if Version(release.version) <= Version(old.name):
                raise UpdateError("release must be strictly newer")
            destination = p.prefix / "releases" / release.version
            if destination.exists() or destination.is_symlink():
                raise UpdateError("release directory already exists; inspect or remove the failed install locally")
            artifacts = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix=".verified-", dir=p.prefix)))
            self.failure_step = "verify"
            remote.verify(release, artifacts, p.signers)
            self.event("verify")
            self.failure_step = "quiesce"
            active = tuple(unit for unit in p.units if self.native.active(unit))
            if p.dashboard_unit not in active:
                raise UpdateError("the configured dashboard must be running before applying an update")
            self.failure_step = "probe"
            self.native.probe(old.name)
            self.failure_step = "quiesce"
            self._begin(old.name, release.version, active)
            self.native.stop(p.units)
            self.event("quiesce")
            self.failure_step = "lock"
            with self._locks(self.record):
                self.event("lock")
                self.failure_step = "freeze"
                self.native.freeze(p.units)
                self.event("freeze")
                self.failure_step = "backup"
                self._checkpoint("snapshot")
                backup_root = release_directory(p.prefix / "backups", mode=0o711)
                backup = backup_root / self.record["backup"]
                self.native.backup_directory(backup)
                self.native.state(old / ".venv/bin/python", "backup", backup)
                manifest_hash = hashlib.sha256(read_bounded(backup / "manifest.json", 8 * 1024 * 1024)).hexdigest()
                self._checkpoint("installing", snapshot_ready=True, manifest_sha256=manifest_hash)
                self.event("backup")
                self.failure_step = "install"
                release_directory(destination)
                self.native.install(destination / ".venv", artifacts, [name for name in PACKAGES if name in packages], release.version, python=old / ".venv/bin/python")
                protected_tree(destination / ".venv")
                self.native.directory_access(destination / ".venv", (destination.parent, destination))
                self.native.service_access(destination / ".venv")
                sync_tree(destination)
                self.event("install")
                self.failure_step = "migrate"
                self._checkpoint("migrating")
                self.native.command(destination, "migrate")
                self.event("migrate")
                self.failure_step = "switch"
                self._checkpoint("switching")
                switch(p.prefix, destination)
                self.event("switch")
                self.failure_step = "start"
                self._checkpoint("health")
                self.native.start((p.dashboard_unit,))
                self.event("start")
                self.failure_step = "doctor"
                self.native.command(destination, "doctor")
                self.failure_step = "probe"
                self.native.probe(release.version)
                self.event("health")
                self._finish("updated")
            return self._finalize()

    def recover(self):
        self.target = None
        self.record = self.failure_step = self.failure_reason = None
        self.checked = {}
        lock = self._update_lock("recover")
        try:
            pending = self._read_pending(result="recovery-refused")
            return self._recover(pending) if pending else {"result": "no-recovery-required"}
        finally:
            lock.release()

    @contextmanager
    def _recovery_dashboard(self):
        unit = (self.policy.dashboard_unit,)
        try:
            self.failure_step = "start"
            self.native.start(unit)
            yield
        except BaseException:
            # Start can partially succeed before it raises. The caller still
            # holds the resource locks while we stop this attempt's dashboard.
            try:
                self.native.freeze(unit)
            except OPERATION_ERRORS:
                self.event("freeze", "failed", reason="freeze-failed")
            raise

    def _recover(self, record):
        self.failure_step = "recovery"
        try:
            self._validate_recovery(record)
            if record["kind"] == "adopt":
                self.failure_step = "adopt"
                return self._complete_adopt()
            p = self.policy
            old = p.prefix / "releases" / record["old"]
            self.failure_step = "recovery"
            protected(old, directory=True)
            protected_tree(old / ".venv")
            self.failure_step = "quiesce"
            self.native.stop(p.units)
            self.failure_step = "lock"
            completed = record["phase"] == "complete"
            with self._locks(record, completed=completed) as release:
                self.failure_step = "freeze"
                self.native.freeze(p.units)
                if completed:
                    selected = release.name
                else:
                    self.failure_step = "recovery"
                    try:
                        self._checkpoint("restoring")
                    except OSError:
                        log_warning("recovery is using the last durable transaction record")
                    errors = []
                    try:
                        if (p.prefix / "current").resolve() != old:
                            switch(p.prefix, old)
                        sync_directory(p.prefix)
                    except OSError as exc:
                        errors.append(exc)
                    if record["snapshot_ready"]:
                        backup = p.prefix / "backups" / record["backup"]
                        try:
                            self.native.state(old / ".venv/bin/python", "restore", backup, record["manifest_sha256"])
                            self.native.state(old / ".venv/bin/python", "verify_restore", backup, record["manifest_sha256"])
                        except BaseException as exc:
                            errors.append(exc)
                    if errors:
                        raise UpdateError("restoration is incomplete")
                    self._checkpoint("rollback-health")
                    selected, release = record["old"], old
                with self._recovery_dashboard():
                    self.failure_step = "doctor"
                    self.native.command(release, "doctor")
                    self.failure_step = "probe"
                    self.native.probe(selected)
                    self.failure_step = "recovery"
                    if self.current().name != selected:
                        raise UpdateError("restored release selection could not be verified")
                    self.event("rollback")
                    self._finish(record["result"] if record["phase"] == "complete" else "rolled-back")
            return self._finalize()
        except BaseException as exc:
            reason = self._reason_code(self.failure_step, exc)
            self.event(self.failure_step, "failed", reason=reason)
            self.event("rollback", "failed", reason="recovery-incomplete")
            try:
                observed = read_record(self.policy.prefix)
            except OPERATION_ERRORS:
                observed = None
            if observed and observed["id"] == record["id"] and observed["phase"] == "complete":
                record = observed  # Completion may have replaced the journal before fsync failed.
            if record["phase"] == "complete":
                warning = "completed update recovery could not verify the selected release"
                self._completed_result(record, warning=warning, recovery_reason=reason)
                self.failure_reason = "recovery-incomplete"
                raise UpdateError("completed update verification remains incomplete; inspect the active recovery record") from None
            self._result(record["new"], "rollback-failed", reason=self.failure_reason or "recovery-incomplete",
                         recovery_reason=reason)
            self.failure_reason = "recovery-incomplete"
            raise UpdateError("update recovery remains incomplete; writers are blocked until recovery succeeds") from None

    def _request_result(self, target, result, *, reason=None):
        _publish_advisory(self.policy, REQUEST_STATUS, diagnostic_result(target, result, reason=reason))

    def _result(self, target, result, *, warning=None, reason=None, recovery_reason=None, finalization_reason=None):
        value = diagnostic_result(target, result, reason=reason or self.failure_reason)
        if warning:
            value["warning"] = warning
        if code := diagnostic_reason(recovery_reason):
            value["recovery_reason"] = code
        if code := diagnostic_reason(finalization_reason):
            value["finalization_reason"] = code
        try:
            atomic_json(self.policy.prefix / "update-result.json", value, mode=0o600)
        except OSError:
            log_warning("update result mirror is unavailable; retain the transaction record")
        status = {**getattr(self, "checked", {}), "last_update": value,
                  "current": diagnostic_version(target if result == "updated" else getattr(self, "previous_version", None))}
        if result == "updated":
            status["available"] = None
        _publish_advisory(self.policy, STATUS, status)

    def _retain_best_effort(self):
        try:
            self._retain()
        except (OSError, CVEBeaconError):
            log_warning("backup retention needs administrator review")

    def _retain(self):
        root = self.policy.prefix / "backups"
        if not root.exists() and not root.is_symlink():
            return
        protected(root, directory=True)
        pinned = self.record.get("backup") if self.record else None
        backups = sorted((path for path in root.iterdir() if path.is_dir() and not path.is_symlink()), reverse=True)
        for path in backups[self.policy.retention:]:
            if path.name != pinned:
                shutil.rmtree(path)

    def _complete_adopt(self):
        p = self.policy
        venv = p.prefix / ".venv"
        protected_tree(venv)
        self.native.preflight(venv)
        releases = release_directory(p.prefix / "releases")
        destination = release_directory(releases / self.record["old"])
        self.native.directory_access(venv, (releases, destination))
        link = destination / ".venv"
        if not link.is_symlink():
            link.symlink_to(venv, target_is_directory=True)
        if link.resolve() != venv:
            raise UpdateError("adopted virtual environment does not match its original path")
        sync_tree(venv)
        sync_tree(destination)
        if not (p.prefix / "current").is_symlink() or (p.prefix / "current").resolve() != destination:
            switch(p.prefix, destination)
        self.native.service_access(p.prefix / "current/.venv")
        self.event("adopt")
        self._finish("adopted")
        return self._finalize()

    def adopt(self):
        p = self.policy
        with RunLock(p.prefix / "update.lock", command="adopt"):
            pending = read_record(p.prefix)
            if pending:
                return self._recover(pending)
            if (p.prefix / "current").exists() or (p.prefix / "current").is_symlink():
                raise UpdateError("installation already has a current link")
            venv = p.prefix / ".venv"
            protected_tree(venv)
            self.native.preflight(venv)
            current = self.native.inventory(venv).get("cvebeacon", "")
            release_version(current)
            self._begin(current, current, (), kind="adopt")
            return self._complete_adopt()


def _suspend_requests(reason):
    log_warning("update request watcher waiting for administrator: " + reason)
    try:
        subprocess.run(["systemctl", "stop", "cvebeacon-update.path"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10, env=SAFE_ENV, cwd="/")
    except (OSError, subprocess.SubprocessError):
        # The unit's start limit bounds repeated failures if the stop fails.
        return 2
    return 0


def _cli(args, config=None):
    action = args.update_command
    if action == "guard":
        from .update_transaction import ensure_ready
        ensure_ready(args.role)
        return 0
    if action == "check":
        config = config or load_config(args.config)
        result = check(config, daily=args.daily)
        if unsupported_reason():
            result = {**result, "notice": unsupported_reason()}
        print(json.dumps(result, indent=2))
        return 0
    reason = unsupported_reason()
    if reason:
        raise UpdateError(reason)
    requested = action == "apply" and args.from_request
    try:
        policy = Policy.read(args.policy)
        if requested and Path(args.config) != policy.config:
            raise UpdateError("request config must match the administrator policy")
    except OPERATION_ERRORS as exc:
        if os.geteuid() != 0:
            raise
        reason = "recovery-incomplete" if getattr(exc, "reason_code", None) == "recovery-incomplete" else "policy-invalid"
        if requested:
            return _suspend_requests(reason)
        log_warning("update refused: " + reason)
        raise UpdateError("administrator update policy or journal requires review", reason_code=reason) from None
    updater = Updater(policy)
    if action == "adopt":
        result = updater.adopt()
    elif action == "recover":
        result = updater.recover()
    else:
        try:
            result = updater.apply(args.version, from_request=requested)
        except OPERATION_ERRORS:
            if not requested:
                raise
            if updater.failure_reason == "request-claim-failed":
                return _suspend_requests(updater.failure_reason)
            return 0

    print(json.dumps(result, indent=2))
    return 0


def cli(args, config=None):
    try:
        return _cli(args, config)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        raise UpdateError("update operation failed safely; inspect the administrator journal and policy") from None
