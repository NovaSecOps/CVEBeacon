"""Signed release checks and the administrator-owned native update transaction.

The web process can write only a tiny request. Policy, executable code, verified
wheels, backups and the transaction journal belong to the administrator.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
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

from .config import HttpConfig, UpdateConfig, load_config
from .errors import CVEBeaconError
from .http import HttpClient
from .locking import LOCK_NAME, RunLock
from .private_storage import private_directory, private_file

LOG = logging.getLogger(__name__)
REQUEST = "update-request.json"
STATUS = "update-status.json"
MAX_REQUEST = 1024
MAX_ASSETS = 256
MAX_ARTIFACT = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
PACKAGES = ("cvebeacon", "cvebeacon-extensions", "cvebeacon-automation")
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


class UpdateError(CVEBeaconError):
    pass


class ConfigLock(RunLock):
    """Share the dashboard editor's flock without changing its private mode."""
    def _open(self):
        private_directory(self.path.parent)
        return private_file(self.path, create=True)


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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


def _json(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise UpdateError("invalid update JSON") from None


def read_bounded(path, limit):
    fd = private_file(Path(path), readonly=True, owner_only=False)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise UpdateError("update file exceeds the size limit")
    return raw


def atomic_json(path, value, *, mode=0o644):
    """Replace a file through an anchored parent; never follow its old inode."""
    path = Path(path)
    if platform.system() == "Windows":
        # Check-only Windows installs still persist their advisory status.
        from .publication import replace_file
        private_directory(path.parent)
        temporary = path.with_name(".update-" + uuid.uuid4().hex)
        try:
            fd = private_file(temporary, create=True, exclusive=True)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=True)
                stream.flush()
                os.fsync(stream.fileno())
            replace_file(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = ".update-" + uuid.uuid4().hex
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


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
    atomic_json(config.watch.database.parent / REQUEST, request, mode=0o600)


def read_status(config):
    try:
        value = _json(read_bounded(config.watch.database.parent / STATUS, 131072))
        return value if isinstance(value, dict) else {}
    except (OSError, CVEBeaconError):
        return {}


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
            entries = [entry for entry in archive.infolist() if entry.filename.endswith(".dist-info/METADATA")]
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
        if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", settings.repository):
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
            raise UpdateError("release request failed") from None
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
            if not isinstance(notes, str) or len(notes) > 65536:
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
            raise UpdateError("ssh-keygen is required to verify releases; update refused")
        directory = Path(directory)
        for name, cap in (("SHA256SUMS", 65536), ("SHA256SUMS.sig", 16384)):
            self.download(release, name, directory / name, cap)
        checksums = (directory / "SHA256SUMS").read_bytes()
        result = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "cvebeacon-release",
                                 "-n", "cvebeacon-release", "-s", str(directory / "SHA256SUMS.sig")],
                                input=checksums, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30, env=SAFE_ENV, cwd="/")
        if result.returncode:
            raise UpdateError("release signature verification failed")
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
    private_directory(config.watch.database.parent)
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
    state.update(current=installed_version("cvebeacon"), available=release.version if release else None,
                 notes=release.notes if release else "", last_check=stamp())
    atomic_json(config.watch.database.parent / STATUS, state)
    return state


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

    @classmethod
    def read(cls, path):
        if os.geteuid() != 0:
            raise UpdateError("apply and adopt require an administrator; run with sudo")
        protected(path)
        value = tomllib.loads(read_bounded(path, 16384).decode("utf-8"))
        if value.pop("enabled", False) is not True:
            raise UpdateError("updates are disabled in administrator policy")
        allowed = set(cls.__dataclass_fields__)
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
        if not isinstance(policy.allow_prereleases, bool) or not isinstance(policy.repository, str) or not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", policy.repository):
            raise UpdateError("invalid release policy")
        for key, lo, hi in (("retention", 1, 100), ("wait_seconds", 1, 86400)):
            if type(getattr(policy, key)) is not int or not lo <= getattr(policy, key) <= hi:
                raise UpdateError("invalid update policy limit")
        if not policy.units or len(set(policy.units)) != len(policy.units) or any(not isinstance(u, str) or not re.fullmatch(r"cvebeacon[\w@.-]*\.(service|timer)", u) or u.startswith("cvebeacon-update") for u in policy.units):
            raise UpdateError("invalid update unit name")
        parsed = urlsplit(policy.probe)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.username or parsed.password or parsed.path != "/healthz" or parsed.query or parsed.fragment:
            raise UpdateError("health probe must use the loopback /healthz endpoint")
        protected(policy.prefix, directory=True)
        protected(policy.signers)
        # Data and runtime config may be service-owned; never execute either.
        import pwd
        if not isinstance(policy.user, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", policy.user):
            raise UpdateError("invalid service account name")
        account = pwd.getpwnam(policy.user)
        if account.pw_uid == 0:
            raise UpdateError("the service account must be unprivileged")
        if policy.data.is_symlink() or not policy.data.is_dir() or policy.data.stat().st_uid != account.pw_uid:
            raise UpdateError("data must be a real service-owned directory")
        protected(policy.data.parent, directory=True)
        if policy.data.is_relative_to(policy.prefix) or policy.data.stat().st_mode & 0o022:
            raise UpdateError("data must be separate from code and writable only by its service account")
        if policy.config.parent != policy.data:
            raise UpdateError("runtime config must be directly inside the data directory")
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
        import pwd
        self.account = pwd.getpwnam(policy.user)

    def run(self, args, *, service=False, **kwargs):
        options = {}
        if service and os.geteuid() == 0:
            options.update(user=self.account.pw_uid, group=self.account.pw_gid, extra_groups=())
        result = subprocess.run([str(a) for a in args], env=SAFE_ENV, cwd="/", stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, umask=0o022, **options, **kwargs)
        if result.returncode:
            raise UpdateError("update subprocess failed (details withheld); inspect the transaction journal")
        return result.stdout

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
        while any(self.active(u) for u in units if u.endswith(".service") and "dashboard" not in u):
            if time.monotonic() >= deadline:
                raise UpdateError("timed out waiting for running services; no process was killed")
            time.sleep(1)

    def freeze(self, units):
        # Only after all run locks are held: systemd also stops dashboard children.
        dashboards = [u for u in units if "dashboard" in u]
        if dashboards:
            self.run(["systemctl", "stop", *dashboards])

    def start(self, units):
        # Starting a timer is safe while the resource locks are held. Do not
        # synchronously launch oneshot work that needs those same locks.
        selected = [u for u in units if u.endswith(".timer") or "dashboard" in u]
        if selected:
            self.run(["systemctl", "start", *selected])

    def inventory(self, venv):
        code = "import importlib.metadata as m,json; ds=list(m.distributions()); assert not any(json.loads(d.read_text('direct_url.json') or '{}').get('dir_info',{}).get('editable') for d in ds), 'editable installs cannot be adopted'; print(json.dumps({d.metadata['Name'].lower():d.version for d in ds}))"
        return _json(self.run([venv / "bin/python", "-I", "-c", code]))

    def lock_paths(self, python):
        raw = self.run([python, "-I", "-m", "cvebeacon.update_state", "paths", self.policy.config, self.policy.data, "-"], service=True)
        paths = _json(raw)
        if not isinstance(paths, list) or len(paths) > 20000 or any(not isinstance(p, str) or not Path(p).is_relative_to(self.policy.data) or Path(p).name != LOCK_NAME for p in paths):
            raise UpdateError("invalid run lock paths")
        return tuple(Path(p) for p in paths)

    def acquire_lock(self, lock):
        # Opening storage with service credentials prevents privileged writes
        # through a raced data-directory entry. Only this one-shot CLI calls it.
        if os.geteuid() != 0:
            return lock.acquire()
        groups, gid = os.getgroups(), os.getegid()
        try:
            os.setgroups([])
            os.setegid(self.account.pw_gid)
            os.seteuid(self.account.pw_uid)
            return lock.acquire()
        finally:
            os.seteuid(0)
            os.setegid(gid)
            os.setgroups(groups)

    def install(self, venv, artifacts, packages, target):
        self.run(["/usr/bin/python3", "-I", "-m", "venv", venv])
        self.run([venv / "bin/python", "-I", "-m", "pip", "--isolated", "install", "--no-index", "--only-binary=:all:",
                  "--find-links", artifacts, *[name + "==" + target for name in packages]])
        self.run([venv / "bin/python", "-I", "-m", "pip", "--isolated", "check"])

    def command(self, release, command):
        options = ["--allow-watch-only"] if command == "doctor" else []
        return self.run([release / ".venv/bin/cvebeacon", "--config", self.policy.config, command, *options], service=True)

    def state(self, python, action, backup):
        # SQLite and config I/O runs with service privileges, even on rollback.
        self.run([python, "-I", "-m", "cvebeacon.update_state", action, self.policy.config, self.policy.data, backup], service=True)

    def backup_directory(self, path):
        path.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(path, self.account.pw_uid, self.account.pw_gid)

    def probe(self):
        with HttpClient(HttpConfig(retries=0)) as http:
            deadline = time.monotonic() + 30
            while True:
                try:
                    result = http.request_once("GET", self.policy.probe, body_limit=1024, timeout=2)
                    if result.status_code == 200 and _json(result.body) == {"status": "ok"}:
                        return
                except (OSError, ValueError, CVEBeaconError, httpx.HTTPError):
                    pass
                if time.monotonic() >= deadline:
                    raise UpdateError("dashboard loopback health probe failed")
                time.sleep(0.5)


class Updater:
    def __init__(self, policy, native=None, releases=None):
        self.policy = policy
        self.native = native or Native(policy)
        self.releases = releases
        self.events = []

    def event(self, step, result="ok"):
        entry = {"time": stamp(), "step": step, "result": result, "version": getattr(self, "target", None)}
        self.events.append(entry)
        LOG.info("update %s: %s", step, result)
        atomic_json(self.policy.prefix / "update-journal.json", {"events": self.events}, mode=0o600)
        fd = private_file(self.policy.prefix / "update-audit.jsonl", create=True)
        with os.fdopen(fd, "ab") as stream:
            stream.write(json.dumps(entry).encode("ascii") + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

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

    def apply(self, target=None, *, from_request=False):
        with RunLock(self.policy.prefix / "update.lock", command="update"):
            self.recorded = False
            try:
                return self._apply(target, from_request=from_request)
            except BaseException:
                if not self.recorded:
                    self.event("refuse", "failed")
                    self._result(None, "refused")
                raise

    def _apply(self, target=None, *, from_request=False):
        p = self.policy
        if from_request:
            if target:
                raise UpdateError("--version and --from-request are mutually exclusive")
            # The request is consumed before work so a failure cannot loop
            # under a PathExists unit. Every check below runs again.
            try:
                target = read_request(p.data / REQUEST)
            finally:
                (p.data / REQUEST).unlink(missing_ok=True)
        old = self.current()
        protected_tree(old / ".venv")
        packages = self.native.inventory(old / ".venv")
        current = packages.get("cvebeacon")
        if current != old.name:
            raise UpdateError("installed version differs from the current release directory")
        self.previous_version = current
        settings = UpdateConfig(True, False, p.repository, p.allow_prereleases)
        with ExitStack() as stack:
            remote = self.releases or Releases(settings, stack.enter_context(HttpClient(HttpConfig(retries=0))))
            release = remote.check(current, target)
            self.target = release.version if release else current
            self.checked = {"last_check": stamp(), "available": release.version if release else None,
                            "notes": release.notes if release else ""}
            self.event("check")
            if release is None:
                self._result(current, "up-to-date")
                return {"result": "up-to-date", "version": current}
            release_version(release.version)
            if Version(release.version) <= Version(current):
                raise UpdateError("release must be strictly newer")
            destination = p.prefix / "releases" / release.version
            if destination.exists() or destination.is_symlink():
                raise UpdateError("release directory already exists; inspect or remove the failed install locally")
            artifacts = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix=".verified-", dir=p.prefix)))
            remote.verify(release, artifacts, p.signers)
            self.event("verify")
            active = tuple(u for u in p.units if self.native.active(u))
            locks = []
            backup = None
            switched = False
            try:
                self.native.stop(p.units)
                self.event("quiesce")
                deadline = time.monotonic() + p.wait_seconds
                def wait_for(lock):
                    while not self.native.acquire_lock(lock):
                        if time.monotonic() >= deadline:
                            raise UpdateError("timed out waiting for the run lock; no process was killed")
                        time.sleep(0.1)
                config_lock = ConfigLock(p.config.with_name(".config-" + p.config.name + ".lock"), command="update")
                locks.append(config_lock)
                wait_for(config_lock)
                # Freeze configuration paths before discovering resource locks.
                locks.extend(RunLock(path, command="update") for path in self.native.lock_paths(old / ".venv/bin/python"))
                for lock in locks[1:]:
                    wait_for(lock)
                self.event("lock")
                self.native.freeze(p.units)
                self.event("freeze")
                backup_root = p.prefix / "backups"
                backup_root.mkdir(mode=0o711, exist_ok=True)
                protected(backup_root, directory=True)
                backup = backup_root / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex)
                self.native.backup_directory(backup)
                self.native.state(old / ".venv/bin/python", "backup", backup)
                self.event("backup")
                destination.mkdir(mode=0o755)
                self.native.install(destination / ".venv", artifacts, [n for n in PACKAGES if n in packages], release.version)
                protected_tree(destination / ".venv")
                self.event("install")
                self.native.command(destination, "migrate")
                self.event("migrate")
                switch(p.prefix, destination)
                switched = True
                self.event("switch")
                self.native.start(active)
                self.event("start")
                self.native.command(destination, "doctor")
                self.native.probe()
                self.event("health")
            except BaseException:
                self.event("failure", "failed")
                try:
                    # Quiesce a partially started new dashboard before state restore.
                    self.native.stop(p.units)
                    if backup is not None:
                        self.native.freeze(p.units)
                    if switched:
                        switch(p.prefix, old)
                    if backup and (backup / "manifest.json").is_file():
                        self.native.state(old / ".venv/bin/python", "restore", backup)
                    self.native.start(active)
                    self.event("rollback")
                    self._result(release.version, "rolled-back")
                    self._retain()
                except BaseException:
                    self.event("rollback", "failed")
                    self._result(release.version, "rollback-failed")
                    raise UpdateError("update failed and rollback needs administrator recovery") from None
                raise UpdateError("update failed; previous release and state restored") from None
            finally:
                for lock in reversed(locks):
                    lock.release()
            self._result(release.version, "updated")
            self._retain()
            return {"result": "updated", "version": release.version}

    def _result(self, target, result):
        self.recorded = True
        value = {"version": target, "result": result, "time": stamp()}
        # Administrator journal is authoritative; dashboard status is advisory.
        atomic_json(self.policy.prefix / "update-result.json", value, mode=0o600)
        try:
            status = _json(read_bounded(self.policy.data / STATUS, 131072))
        except (OSError, CVEBeaconError):
            status = {}
        if not isinstance(status, dict):
            status = {}
        status.update(getattr(self, "checked", {}))
        status["last_update"] = value
        status["current"] = target if result == "updated" else getattr(self, "previous_version", None)
        if result == "updated":
            status["available"] = None
        atomic_json(self.policy.data / STATUS, status)

    def _retain(self):
        root = self.policy.prefix / "backups"
        if not root.exists() and not root.is_symlink():
            return
        protected(root, directory=True)
        backups = sorted((p for p in root.iterdir() if p.is_dir() and not p.is_symlink()), reverse=True)
        for path in backups[self.policy.retention:]:
            shutil.rmtree(path)

    def adopt(self):
        p = self.policy
        with RunLock(p.prefix / "update.lock", command="adopt"):
            if (p.prefix / "current").exists() or (p.prefix / "current").is_symlink():
                raise UpdateError("installation already has a current link")
            venv = p.prefix / ".venv"
            protected_tree(venv)
            packages = self.native.inventory(venv)
            current = packages.get("cvebeacon", "")
            release_version(current)
            releases = p.prefix / "releases"
            releases.mkdir(mode=0o755, exist_ok=True)
            protected(releases, directory=True)
            destination = releases / current
            destination.mkdir(mode=0o755)
            # Keeping the original path preserves absolute venv script shebangs.
            (destination / ".venv").symlink_to(venv, target_is_directory=True)
            switch(p.prefix, destination)
            self.event("adopt")
            return {"result": "adopted", "version": current}


def _cli(args, config=None):
    action = args.update_command
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
    policy = Policy.read(args.policy)
    updater = Updater(policy)
    result = updater.adopt() if action == "adopt" else updater.apply(args.version, from_request=args.from_request)
    print(json.dumps(result, indent=2))
    return 0


def cli(args, config=None):
    try:
        return _cli(args, config)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        raise UpdateError("update operation failed safely; inspect the administrator journal and policy") from None
