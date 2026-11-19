"""Durable SQLite snapshot primitives shared by update and backup.

The updater and the administrator backup command must agree on consistency,
integrity checks and durable replacement. Keeping one implementation here
prevents the two paths from drifting apart.
"""

from __future__ import annotations

import hashlib
import os
from contextlib import closing
from pathlib import Path
import sqlite3

from .errors import CVEBeaconError


class SnapshotError(CVEBeaconError):
    pass


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_file(path):
    with Path(path).open("rb") as stream:
        os.fsync(stream.fileno())


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def logical_digest(path):
    result = hashlib.sha256()
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SnapshotError("SQLite integrity check failed")
        for line in db.iterdump():
            result.update(line.encode("utf-8"))
            result.update(b"\n")
    return result.hexdigest()


def copy_sqlite(source, destination):
    """Take one consistent online copy, then verify and persist it."""
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=30)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
            if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise SnapshotError("SQLite snapshot integrity check failed")
    Path(destination).chmod(0o600)
    sync_file(destination)
