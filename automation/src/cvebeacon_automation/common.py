"""Small bounded IO primitives and process-local secret references."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

from cvebeacon_extensions.contract import decode_json, json_bytes, read_bytes


class AutomationError(ValueError):
    """Only fixed safe categories cross the CLI/health boundary."""

    def __init__(self, category: str):
        self.category = category
        super().__init__(category)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def identifier(value, name="identifier") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", value):
        raise AutomationError("invalid_" + name)
    if value.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))} or value.endswith("."):
        raise AutomationError("invalid_" + name)
    return value


def directory(path: Path) -> Path:
    """Parents are administrator controlled; reject redirected leaf directories."""
    path.mkdir(parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400 or path.is_symlink():
        raise AutomationError("unsafe_directory")
    return path


def regular(path: Path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info, "st_file_attributes", 0) & 0x400:
        raise AutomationError("unsafe_file")


def atomic(path: Path, data: bytes):
    if len(data) > 48 * 1024 * 1024:
        raise AutomationError("output_too_large")
    directory(path.parent)
    if path.exists() or path.is_symlink():
        regular(path)
    fd, temporary = tempfile.mkstemp(prefix=".auto-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path: Path, value):
    atomic(path, json_bytes(value))


def read_json(path: Path, limit=1024 * 1024):
    return decode_json(read_bytes(path, limit))


def publish_pair(path: Path, inventory: bytes, manifest: bytes):
    """Preflight both sides; restore prior bytes on ordinary publication failure.

    An abrupt crash remains fail-closed under the v1 hash contract. Callers keep
    immutable generations for recovery and serialize all cooperating readers.
    """
    side = path.with_name(path.name + ".manifest.json")
    previous = []
    for destination, limit in ((path, 32 * 1024 * 1024), (side, 65536)):
        if destination.exists() or destination.is_symlink():
            regular(destination)
            previous.append(read_bytes(destination, limit))
        else:
            previous.append(None)
    atomic(path, inventory)
    try:
        atomic(side, manifest)
    except BaseException:
        # A failed second side must not erase the last known good first side.
        if previous[0] is not None:
            atomic(path, previous[0])
        else:
            path.unlink(missing_ok=True)  # Only the file just created by this call.
        raise


@contextmanager
def lock(path: Path):
    """OS advisory lock survives file reuse and releases on process death."""
    directory(path.parent)
    if path.exists() or path.is_symlink():
        regular(path)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    acquired = False
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AutomationError("unsafe_lock")
        if os.name == "nt":
            import msvcrt
            if not info.st_size:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise AutomationError("locked") from None
        else:
            import fcntl
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise AutomationError("locked") from None
        acquired = True
        yield
    finally:
        if acquired:
            if os.name == "nt":
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@dataclass(frozen=True, repr=False)
class Secret:
    env: str | None = None
    file: Path | None = None

    @classmethod
    def parse(cls, value, base: Path) -> Secret:
        if not isinstance(value, dict) or set(value) not in ({"env"}, {"file"}):
            raise AutomationError("invalid_secret_reference")
        if "env" in value:
            if not isinstance(value["env"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value["env"]):
                raise AutomationError("invalid_secret_reference")
            return cls(env=value["env"])
        if not isinstance(value["file"], str) or not value["file"]:
            raise AutomationError("invalid_secret_reference")
        return cls(file=Path(os.path.abspath(base / value["file"])))

    def resolve(self) -> str:
        try:
            if self.file:
                regular(self.file)
                if os.name == "posix" and self.file.stat().st_mode & 0o077:
                    raise AutomationError("secret_file_permissions")
                value = read_bytes(self.file, 16384).decode("utf-8").strip()
            else:
                value = os.environ.get(self.env or "", "")
        except (OSError, UnicodeError):
            raise AutomationError("secret_unavailable") from None
        if not value or len(value) > 16384 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise AutomationError("secret_unavailable")
        return value

    def __repr__(self):
        return "Secret(<reference>)"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
