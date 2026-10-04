"""Select external tools only from administrator-controlled installation paths."""

from __future__ import annotations

import os
from pathlib import Path
import shutil

from ..common import AutomationError, regular


def executable(name: str) -> str:
    if name not in {"ssh", "nmap"}:
        raise AutomationError("unsupported_external_tool")
    paths = [item for item in os.defpath.split(os.pathsep) if item and Path(item).is_absolute()]
    if os.name == "nt":
        system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        if system.is_absolute():
            paths[:0] = [str(system / "System32" / "OpenSSH")]
        if name == "nmap":
            for variable in ("ProgramFiles", "ProgramFiles(x86)"):
                root = Path(os.environ.get(variable, ""))
                if root.is_absolute():
                    paths.append(str(root / "Nmap"))
    else:
        paths.append("/usr/local/bin")
    # Never inherit PATH or search '.', a relative directory, or an uploaded file.
    selected = shutil.which(name, path=os.pathsep.join(dict.fromkeys(paths)))
    if not selected or not Path(selected).is_absolute():
        raise AutomationError(name + "_unavailable")
    try:
        regular(Path(selected))
    except OSError:
        raise AutomationError(name + "_unavailable") from None
    return selected
