#!/usr/bin/env python3
"""Update the pinned Retire.js signatures for maintainers.

This script is never called by the scanner. Run it only when intentionally
updating the bundled signatures to a reviewed upstream commit.
"""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.request import Request, urlopen


_REPOSITORY = "RetireJS/retire.js"
_FILES = ("jsrepository-master.json", "LICENSE.md")
_MAX_BYTES = 16 * 1024 * 1024
_DATA = (Path(__file__).resolve().parents[1]
         / "extensions/src/cvebeacon_extensions/data/retirejs")


def _download(commit: str, filename: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{_REPOSITORY}/{commit}/{filename}"
    request = Request(url, headers={"User-Agent": "CVEBeacon-maintainer"})
    with urlopen(request, timeout=30) as response:
        payload = response.read(_MAX_BYTES + 1)
    if len(payload) > _MAX_BYTES:
        raise ValueError(f"{filename} exceeds the {_MAX_BYTES}-byte limit")
    return payload


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".retirejs-",
                                         delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def update(commit: str, *, destination: Path = _DATA, download=None,
           bundled_date: str | None = None) -> str:
    """Download pinned files, validate them, and return the JSON SHA-256."""
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-fA-F]{40}", commit) is None:
        raise ValueError("commit must be a full 40-character hexadecimal id")
    commit = commit.lower()
    fetch = download or _download
    payloads = {filename: fetch(commit, filename) for filename in _FILES}
    try:
        document = json.loads(payloads["jsrepository-master.json"].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Retire.js signature file is not valid UTF-8 JSON") from exc
    if (not isinstance(document, dict) or not document
            or any(not isinstance(key, str) or not isinstance(value, dict)
                   for key, value in document.items())):
        raise ValueError("Retire.js signature JSON has an unexpected structure")
    license_text = payloads["LICENSE.md"].decode("utf-8", errors="strict")
    if "Apache License" not in license_text or "Version 2.0" not in license_text:
        raise ValueError("Retire.js license file is not Apache-2.0")
    digest = hashlib.sha256(payloads["jsrepository-master.json"]).hexdigest()
    source = (
        "# Retire.js signatures\n\n"
        f"- Repository: `{_REPOSITORY}`\n"
        f"- Commit: `{commit}`\n"
        "- File: `jsrepository-master.json`\n"
        f"- SHA-256: `{digest}`\n"
        f"- Date bundled: `{bundled_date or date.today().isoformat()}`\n"
        "- License: Apache-2.0; see `LICENSE.md`.\n\n"
        "The scanner evaluates only supported passive URI, filename, file-content "
        "and SHA-1 extractors. It does not use vulnerability entries or execute "
        "JavaScript. The bundled signatures are never downloaded at runtime.\n"
    ).encode("utf-8")
    for filename, payload in payloads.items():
        _atomic_write(Path(destination) / filename, payload)
    _atomic_write(Path(destination) / "SOURCE.md", source)
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commit", help="full RetireJS/retire.js commit id")
    args = parser.parse_args(argv)
    try:
        digest = update(args.commit)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Updated Retire.js signatures ({digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
