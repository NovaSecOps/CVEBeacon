"""Checked private files for operation locks, history and logs."""

from __future__ import annotations

import os
from pathlib import Path
import stat

from .errors import StateError
from .watch.directories import ensure_private_directory


def private_directory(path: Path) -> None:
    if os.name == "nt":
        from .windows_private import private_directory as windows_directory
        windows_directory(path)
        return
    existing = path.absolute()
    while not existing.exists() and not existing.is_symlink():
        existing = existing.parent
    _check_directory_chain(existing)
    ensure_private_directory(path)
    _check_directory_chain(path)


def _check_directory_chain(path: Path) -> None:
    current = path.absolute()
    while True:
        details = current.lstat()
        mode = stat.S_IMODE(details.st_mode)
        if not stat.S_ISDIR(details.st_mode):
            raise StateError("operation storage directory must not be a symlink")
        if mode & 0o002 and not mode & stat.S_ISVTX:
            raise StateError(
                "operation storage directory must not be world-writable without "
                f"the sticky bit: {current}; chmod o-w {current} or chmod +t {current}"
            )
        if current.parent == current:
            break
        current = current.parent


def validate_file(descriptor: int, path: Path) -> os.stat_result:
    details = os.fstat(descriptor)
    current = path.lstat()
    if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
            or not stat.S_ISREG(current.st_mode)
            or getattr(current, "st_file_attributes", 0) & 0x400
            or (current.st_dev, current.st_ino) != (details.st_dev, details.st_ino)):
        raise StateError("operation storage must be a regular file without links")
    if os.name == "posix":
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise StateError("operation storage file must be owner-only")
    else:
        from .windows_private import validate_handle
        import msvcrt
        validate_handle(msvcrt.get_osfhandle(descriptor))
    return details


def private_file(path: Path, *, create: bool = False, exclusive: bool = False,
                 readonly: bool = False) -> int:
    """Open without following links; new files are private before first use."""
    try:
        current = path.lstat()
    except FileNotFoundError:
        pass
    else:
        # Reject links before opening too: closing any descriptor of a live
        # SQLite inode would release this process's POSIX record locks.
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise StateError("operation storage must be a regular file without links")
    if os.name == "nt":
        from .windows_private import open_file
        descriptor = open_file(path, create=create, exclusive=exclusive, readonly=readonly)
    else:
        flags = (os.O_RDONLY if readonly else os.O_RDWR) | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            descriptor = os.open(path, flags | (os.O_CREAT | os.O_EXCL if create else 0), 0o600)
            created = create
        except FileExistsError:
            if exclusive:
                raise
            descriptor = os.open(path, flags)
            created = False
    try:
        if os.name == "posix" and created:
            os.fchmod(descriptor, 0o600)
        validate_file(descriptor, path)
        return descriptor
    except BaseException:
        if os.name == "posix":
            from .watch.users import _retain_database_descriptor
            details = os.fstat(descriptor)
            if _retain_database_descriptor(descriptor, (details.st_dev, details.st_ino), None):
                raise
        os.close(descriptor)
        raise
