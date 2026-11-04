"""Create private data directories without depending on the process umask."""

from __future__ import annotations

import os
from pathlib import Path


def ensure_private_directory(path: Path) -> Path:
    """Create missing directory levels with mode 0700 on POSIX."""
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    for item in reversed(missing):
        try:
            item.mkdir(mode=0o700)
        except FileExistsError:
            if not item.is_dir():
                raise
        if os.name == "posix":
            os.chmod(item, 0o700)
    return path
