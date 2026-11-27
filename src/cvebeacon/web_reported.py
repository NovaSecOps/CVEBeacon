"""Per-client "reported" marks for detected web technologies.

The file sits next to the saved review (``<output>.reported.json``) and is private. It holds
one mark per product asset ID: the version(s) shown when it was marked, when, by whom, and an
optional note. Reading is strict; a file that does not validate yields no marks.
"""

from __future__ import annotations

import json
import re
import unicodedata

from .web_inventory import decode_json

SUFFIX = ".reported.json"
MAX_MARKS = 20_000
MAX_NOTE = 200
MAX_VERSION = 100
MAX_BY = 100
MAX_PICKS = 2000
ASSET_ID = re.compile(r"web-[0-9a-f]{16,64}\Z")
INVALID = ("The saved report marks could not be read, so none are shown. "
           "Removing all sites and results for this client clears them.")


def marks_path(output):
    return output.with_name(output.name + SUFFIX)


def _clean(value, limit):
    return (isinstance(value, str) and len(value) <= limit
            and not any(unicodedata.category(char) in {"Cc", "Cs", "Cf", "Zl", "Zp"} for char in value))


def shown_version(item):
    """The version text a mark records and later compares against."""
    versions = [version.strip() for version in item.get("versions", []) if version.strip()]
    return ", ".join(versions)[:MAX_VERSION]


def parse(data, client_key_of, client):
    """Return the marks stored in ``data`` or raise ValueError."""
    document = decode_json(data)
    if (not isinstance(document, dict) or set(document) != {"client", "marks"}
            or not isinstance(document["client"], str)
            or client_key_of(document["client"]) != client_key_of(client)
            or not isinstance(document["marks"], dict) or len(document["marks"]) > MAX_MARKS):
        raise ValueError("invalid report marks")
    for asset_id, mark in document["marks"].items():
        if (not isinstance(asset_id, str) or ASSET_ID.fullmatch(asset_id) is None
                or not isinstance(mark, dict) or set(mark) != {"version", "reported_at", "by", "note"}
                or not _clean(mark["version"], MAX_VERSION) or not _clean(mark["note"], MAX_NOTE)
                or not _clean(mark["by"], MAX_BY) or not _clean(mark["reported_at"], 64)):
            raise ValueError("invalid report mark")
    return document["marks"]


def encode(client, marks):
    return json.dumps({"client": client, "marks": marks}, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
