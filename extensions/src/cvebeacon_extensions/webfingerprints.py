"""Bounded reader for operator-supplied Wappalyzer-format fingerprints.

The package deliberately contains no upstream fingerprint collection. This
module only reads a collection supplied by the operator and evaluates its
passive patterns against data already present on a :class:`webrules.Page`.
"""

from __future__ import annotations

from collections import Counter, deque
from contextlib import ExitStack
from dataclasses import dataclass, field
from html.parser import HTMLParser
from itertools import islice
import json
import os
from pathlib import Path
import re
import stat
import time
from types import MappingProxyType
from typing import Iterable, Mapping

from cvebeacon.sources.nvd import split_cpe23

from . import webrules


MAX_TECHNOLOGY_FILES = 20_000
MAX_DIRECTORY_ENTRIES = 50_000
MAX_TECHNOLOGIES_PER_FILE = 2_048
MAX_FILE_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_TOTAL_FINGERPRINT_BYTES = 64 * 1024 * 1024
MAX_PATTERNS_PER_TECHNOLOGY = 512
MAX_TOTAL_PATTERNS = 100_000
MAX_STRING_LENGTH = 4096
MAX_REGEX_LENGTH = 2048
MAX_EVALUATION_SECONDS = 20.0
RELATION_FINALIZATION_RESERVE_SECONDS = 0.05
MAX_HTML_LENGTH = 4 * 1024 * 1024
MAX_TEXT_LENGTH = 1024 * 1024
MAX_RESOURCE_LENGTH = 4 * 1024 * 1024
MAX_ROBOTS_LENGTH = 1024 * 1024
MAX_PAGE_RESOURCES = 300
MAX_RESOURCE_BYTES_PER_PAGE = 96 * 1024 * 1024
MAX_DOM_NODES = 50_000
MAX_DOM_TEXT_CACHE_BYTES = 4 * 1024 * 1024
MAX_DOM_TEXT_WORK = 16 * 1024 * 1024
HTML_PARSE_CHUNK = 16 * 1024
MAX_VERSION_CAPTURE_LENGTH = 64
MAX_META_TAGS = 4096
MAX_SCRIPT_URLS = 16_384
MAX_EVIDENCE_PER_DETECTION = 64
EVIDENCE_EXCERPT_LENGTH = 160
MAX_LITERAL_HITS_PER_PATTERN = 64

SUPPORTED_KINDS = frozenset({
    "headers", "cookies", "meta", "scriptSrc", "scripts", "css", "html",
    "text", "url", "robots", "dom",
})
UNSUPPORTED_KINDS = frozenset({"js", "xhr", "dns", "certIssuer", "probe"})
_ALL_KINDS = SUPPORTED_KINDS | UNSUPPORTED_KINDS
_KNOWN_FIELDS = _ALL_KINDS | frozenset({
    "cats", "description", "website", "icon", "pricing", "saas", "oss", "cpe",
    "implies", "excludes", "requires", "requiresCategory", "groups",
})
EVIDENCE_KIND_MAP = MappingProxyType({
    "headers": "header", "cookies": "cookie", "meta": "meta",
    "scriptSrc": "url", "scripts": "script", "css": "style", "html": "html",
    "text": "text", "url": "url", "robots": "robots", "dom": "dom",
})
_VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
})
_JS_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
_COOKIE_HEADERS = frozenset({"set-cookie", "cookie"})
_SENSITIVE_HEADERS = _COOKIE_HEADERS | {"authorization", "proxy-authorization"}
_WINDOWS = os.name == "nt"
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
_OPEN_FLAGS |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


@dataclass(frozen=True, slots=True)
class FingerprintStats:
    technologies_loaded: int = 0
    skipped_technologies: tuple[tuple[str, int], ...] = ()
    skipped_patterns: tuple[tuple[str, int], ...] = ()
    unsupported_kinds: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class DetectionStats:
    technologies_loaded: int
    skipped_patterns: tuple[tuple[str, int], ...]
    unsupported_kinds: tuple[tuple[str, int], ...]
    stopped_at_time_limit: int = 0
    patterns_evaluated: int = 0
    truncated: bool = False


class DetectionResults(tuple):
    """Tuple-compatible detections with immutable per-page run statistics."""

    def __new__(cls, detections: Iterable[object], stats: DetectionStats):
        value = super().__new__(cls, tuple(detections))
        value.stats = stats
        return value


@dataclass(frozen=True, slots=True)
class _DOMTest:
    regex: re.Pattern[str]
    version: str | None = None
    confidence: int = 100


@dataclass(frozen=True, slots=True)
class _SelectorAttribute:
    name: str
    operator: str = ""
    value: str = ""


@dataclass(frozen=True, slots=True)
class _Selector:
    tag: str = ""
    identifier: str = ""
    classes: tuple[str, ...] = ()
    attributes: tuple[_SelectorAttribute, ...] = ()


@dataclass(frozen=True, slots=True)
class _Pattern:
    index: int
    kind: str
    source: str
    regex: re.Pattern[str] | None
    selector_regex: re.Pattern[str] | None = None
    version: str | None = None
    confidence: int = 100
    literal: str = ""
    prefix: str = ""
    selector: _Selector | None = None
    dom_exists: bool = True
    dom_attributes: tuple[tuple[str, tuple[_DOMTest, ...]], ...] = ()
    dom_text: tuple[_DOMTest, ...] = ()


@dataclass(frozen=True, slots=True)
class _Relationship:
    target: str
    confidence: int = 100


@dataclass(frozen=True, slots=True)
class _Technology:
    name: str
    cpe: str
    vendor: str
    product: str
    category: str
    category_ids: tuple[str, ...]
    pattern_ids: tuple[int, ...]
    implies: tuple[_Relationship, ...] = ()
    excludes: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    requires_categories: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _LiteralIndex:
    transitions: tuple[Mapping[str, int], ...]
    failures: tuple[int, ...]
    outputs: tuple[tuple[int, ...], ...]
    literal_lengths: Mapping[int, int]

    def find(self, text: str, deadline: float, clock, on_truncated) -> tuple[dict[int, set[int]], bool]:
        candidates: dict[int, set[int]] = {}
        positions_are_exact = text.isascii()
        truncated = False
        folded = _fold_for_index(text)
        state = 0
        for position, char in enumerate(folded):
            while state and char not in self.transitions[state]:
                state = self.failures[state]
            state = self.transitions[state].get(char, 0)
            if self.outputs[state]:
                for pattern_id in self.outputs[state]:
                    found = candidates.setdefault(pattern_id, set())
                    if positions_are_exact:
                        if len(found) < MAX_LITERAL_HITS_PER_PATTERN:
                            found.add(position - self.literal_lengths[pattern_id] + 1)
                        else:
                            truncated = True
            if position and position % 65_536 == 0 and clock() >= deadline:
                return candidates, True
        if truncated:
            on_truncated()
        return candidates, clock() >= deadline


@dataclass(frozen=True, slots=True)
class Fingerprints:
    directory: Path
    technologies: tuple[_Technology, ...]
    patterns: tuple[_Pattern, ...]
    categories: Mapping[str, str]
    groups: Mapping[str, str]
    stats: FingerprintStats
    literal_indexes: Mapping[str, _LiteralIndex]
    no_literal: Mapping[str, tuple[int, ...]]

    @property
    def technology_count(self) -> int:
        return len(self.technologies)

    @property
    def load_error(self) -> bool:
        return any(reason in {"fingerprint directory unavailable", "untrusted fingerprint layout"}
                   for reason, _ in self.stats.skipped_technologies)

    @property
    def incomplete(self) -> bool:
        """True when a supported file could not be read or trusted, so coverage is partial."""
        return any(reason in INCOMPLETE_LOAD_REASONS for reason, _ in self.stats.skipped_technologies)


def _freeze_counts(counter: Counter[str]) -> tuple[tuple[str, int], ...]:
    return tuple(sorted((key, value) for key, value in counter.items() if value))


def _cpe_identity(cpe: str, name: str) -> tuple[str, str]:
    if cpe:
        parts = split_cpe23(cpe)
        if len(parts) == 11 and parts[1] not in {"", "*", "-"} and parts[2] not in {"", "*", "-"}:
            return parts[1].casefold(), parts[2].casefold()
    slug = re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_") or "unknown"
    return slug, slug


def _category_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()
    aliases = {
        "cms": "cms", "content management systems": "cms",
        "web servers": "web-server", "web server": "web-server",
        "reverse proxy": "reverse-proxy", "reverse proxies": "reverse-proxy",
        "application servers": "application-server", "application server": "application-server",
        "programming languages": "language", "languages": "language",
        "javascript libraries": "js-library", "javascript library": "js-library",
        "javascript frameworks": "framework", "web frameworks": "framework",
        "frameworks": "framework", "framework": "framework",
        "cdn": "edge", "content delivery network": "edge", "content delivery networks": "edge",
        "paas": "hosted-platform", "hosting": "hosted-platform", "hosted platforms": "hosted-platform",
        "dev tools": "ops-tool", "developer tools": "ops-tool", "analytics": "analytics",
        "tag managers": "analytics",
        "ui frameworks": "css-library", "font scripts": "css-library",
        "javascript graphics": "js-library", "maps": "js-library",
        "rich text editors": "js-library", "video players": "js-library",
        "static site generator": "framework",
        "operating systems": "application", "databases": "application",
        "ecommerce": "application", "email": "application", "widgets": "application",
    }
    result = aliases.get(normalized, normalized.replace(" ", "-"))
    return result if result in webrules.CATEGORIES else "application"


def _category_id(value: object) -> str:
    if type(value) is int:
        return str(value)
    if isinstance(value, str) and len(value) <= 32 and not _contains_invalid_unicode(value):
        return value
    raise ValueError("invalid category id")


def _object_pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _stat_stamp(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns, getattr(info, "st_file_attributes", 0),
    )


def _contains_invalid_unicode(value: object) -> bool:
    if isinstance(value, str):
        return any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    if isinstance(value, dict):
        return any(_contains_invalid_unicode(key) or _contains_invalid_unicode(item)
                   for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_invalid_unicode(item) for item in value)
    return False


class _FingerprintFileChanged(OSError):
    pass


def _is_reparse_point(info: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & flag)


def _safe_directory_info(info: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not _is_reparse_point(info)
        and (_WINDOWS or not (info.st_mode & stat.S_IWOTH))
    )


def _safe_file_info(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not _is_reparse_point(info)
        and (_WINDOWS or not (info.st_mode & stat.S_IWOTH))
    )


def _open_windows(path: Path, *, directory: bool) -> int:
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create_file.restype = wintypes.HANDLE
    close_handle = kernel.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    # Pin each directory in the chain against rename or removal by omitting
    # FILE_SHARE_DELETE. OPEN_REPARSE_POINT opens a link itself for inspection.
    access = 0x81 if directory else 0x80000000  # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, or GENERIC_READ
    sharing = 0x3  # FILE_SHARE_READ | FILE_SHARE_WRITE
    flags = 0x00200000  # FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= 0x02000000  # FILE_FLAG_BACKUP_SEMANTICS
    handle = create_file(str(path), access, sharing, None, 3, flags, None)  # OPEN_EXISTING
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        get_info = kernel.GetFileInformationByHandleEx
        get_info.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
        get_info.restype = wintypes.BOOL
        attributes_and_tag = (wintypes.DWORD * 2)()
        if not get_info(handle, 9, ctypes.byref(attributes_and_tag), ctypes.sizeof(attributes_and_tag)):
            raise ctypes.WinError(ctypes.get_last_error())  # FileAttributeTagInfo
        if attributes_and_tag[0] & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError("untrusted fingerprint layout")
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        close_handle(handle)
        raise


@dataclass(frozen=True, slots=True)
class _DirectoryHandle:
    path: Path
    descriptor: int

    def stat(self, name: str) -> os.stat_result:
        if _WINDOWS:
            return (self.path / name).lstat()
        return os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)

    def open(self, name: str, *, directory: bool = False) -> int:
        if _WINDOWS:
            return _open_windows(self.path / name, directory=directory)
        flags = _OPEN_FLAGS | (getattr(os, "O_DIRECTORY", 0) if directory else 0)
        return os.open(name, flags, dir_fd=self.descriptor)

    def entries(self):
        return os.scandir(self.path if _WINDOWS else self.descriptor)


def _open_directory(stack: ExitStack, parent: _DirectoryHandle | None, name: str) -> _DirectoryHandle:
    path = parent.path / name if parent is not None else Path(name)
    checked = parent.stat(name) if parent is not None else path.lstat()
    if not stat.S_ISDIR(checked.st_mode) or _is_reparse_point(checked):
        raise PermissionError("untrusted fingerprint layout")
    if parent is not None:
        descriptor = parent.open(name, directory=True)
    elif _WINDOWS:
        descriptor = _open_windows(path, directory=True)
    else:
        descriptor = os.open(path, _OPEN_FLAGS | getattr(os, "O_DIRECTORY", 0))
    stack.callback(os.close, descriptor)
    opened = os.fstat(descriptor)
    if (not stat.S_ISDIR(opened.st_mode) or _is_reparse_point(opened)
            or (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino)):
        raise PermissionError("untrusted fingerprint layout")
    return _DirectoryHandle(path, descriptor)


def _read_json_file(directory: _DirectoryHandle, name: str, limit: int, expected_stamp: tuple[int, ...]) -> object:
    checked = directory.stat(name)
    checked_stamp = _stat_stamp(checked)
    if checked_stamp != expected_stamp:
        raise _FingerprintFileChanged("fingerprint file changed during loading")
    if not _safe_file_info(checked):
        raise PermissionError("untrusted fingerprint file")
    if checked.st_size > limit:
        raise OverflowError("file too large")

    descriptor = directory.open(name)
    try:
        opened = os.fstat(descriptor)
        if (
            not _safe_file_info(opened)
            or _stat_stamp(opened) != checked_stamp
        ):
            raise _FingerprintFileChanged("fingerprint file changed while opening")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(limit + 1)
            after_read = os.fstat(stream.fileno())
            if _stat_stamp(after_read) != checked_stamp:
                raise _FingerprintFileChanged("fingerprint file changed while reading")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > limit:
        raise OverflowError("file too large")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs_no_duplicates)


def _category_map(root: _DirectoryHandle, skipped: Counter[str], expected_stamp=None) -> dict[str, str]:
    if expected_stamp is None:
        skipped["categories file unavailable"] += 1
        return {}
    try:
        if len(expected_stamp) != 7:
            raise OSError("invalid checked category file")
        if expected_stamp[3] > MAX_METADATA_BYTES:
            skipped["categories file too large"] += 1
            return {}
        payload = _read_json_file(root, "categories.json", MAX_METADATA_BYTES, expected_stamp)
    except FileNotFoundError:
        skipped["categories file unavailable"] += 1
        return {}
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, OverflowError, RecursionError):
        skipped["malformed categories file"] += 1
        return {}
    result: dict[str, str] = {}
    entries: Iterable[tuple[object, object]]
    if isinstance(payload, dict):
        entries = payload.items()
    elif isinstance(payload, list):
        entries = ((entry.get("id"), entry) for entry in payload if isinstance(entry, dict))
    else:
        skipped["malformed categories file"] += 1
        return {}
    for identifier, entry in entries:
        try:
            key = _category_id(identifier)
            if isinstance(entry, str):
                name = entry
            elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
                name = entry["name"]
            else:
                raise ValueError("invalid category")
            if not name or len(name) > MAX_STRING_LENGTH or _contains_invalid_unicode(name):
                raise ValueError("invalid category name")
            result[key] = _category_name(name)
        except ValueError:
            skipped["malformed category entry"] += 1
    return result


@dataclass(frozen=True, slots=True)
class _DirectorySnapshot:
    root: _DirectoryHandle
    technologies_dir: _DirectoryHandle
    files: tuple[tuple[str, tuple[int, ...]], ...]
    metadata: tuple[tuple[str, tuple[int, ...] | None], ...]
    overflow_files: int
    truncated: bool
    key: tuple


def _snapshot_directory(directory: Path, stack: ExitStack) -> _DirectorySnapshot:
    """Open and inspect only the supported layout through verified handles."""
    requested = Path(os.path.abspath(os.fspath(directory.expanduser())))
    requested_handle = None
    parent = None
    for component in requested.parts:
        parent = requested_handle
        requested_handle = _open_directory(stack, parent, component)
    if requested_handle is None:
        raise FileNotFoundError("fingerprint directory unavailable")

    root = requested_handle
    try:
        technologies = _open_directory(stack, root, "technologies")
    except FileNotFoundError:
        if requested.name != "technologies" or parent is None:
            raise
        technologies = requested_handle
        root = parent
    root_info = os.fstat(root.descriptor)
    technologies_info = os.fstat(technologies.descriptor)
    if not _safe_directory_info(root_info) or not _safe_directory_info(technologies_info):
        raise PermissionError("untrusted fingerprint layout")

    files = []
    truncated = False
    with technologies.entries() as entries:
        for position, entry in enumerate(entries):
            if position >= MAX_DIRECTORY_ENTRIES:
                truncated = True
                break
            if not entry.name.endswith(".json"):
                continue
            try:
                stamp = _stat_stamp(technologies.stat(entry.name))
            except OSError:
                stamp = ()
            files.append((entry.name, stamp))
    files.sort(key=lambda item: item[0])
    overflow_files = max(0, len(files) - MAX_TECHNOLOGY_FILES)
    files_tuple = tuple(files[:MAX_TECHNOLOGY_FILES])

    metadata = []
    for filename in ("categories.json", "groups.json"):
        try:
            stamp = _stat_stamp(root.stat(filename))
        except FileNotFoundError:
            stamp = None
        except OSError:
            stamp = ()
        metadata.append((filename, stamp))
    metadata_tuple = tuple(metadata)
    key = (
        str(root.path), str(technologies.path), _stat_stamp(root_info), _stat_stamp(technologies_info),
        files_tuple, metadata_tuple, overflow_files, truncated,
    )
    return _DirectorySnapshot(root, technologies, files_tuple, metadata_tuple, overflow_files, truncated, key)


def _parse_js_flags(source: str) -> tuple[str, int]:
    value = source
    flags = re.IGNORECASE
    # A slash-delimited JavaScript literal is accepted when its trailing flags
    # are known. A normal URL-like or slash-containing pattern stays untouched.
    if value.startswith("/"):
        end = -1
        escaped = False
        in_class = False
        for index in range(1, len(value)):
            char = value[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "[":
                in_class = True
            elif char == "]":
                in_class = False
            elif char == "/" and not in_class:
                end = index
        if end > 0 and re.fullmatch(r"[A-Za-z]*", value[end + 1:]):
            specified = value[end + 1:]
            allowed = set("imsu")
            if len(set(specified)) != len(specified) or any(flag not in allowed for flag in specified):
                raise ValueError("unsupported JavaScript regular-expression flags")
            flags = re.NOFLAG
            for flag in specified:
                flags |= _JS_FLAGS.get(flag, re.NOFLAG)
            value = value[1:end]
    # JavaScript named captures and backreferences use a different spelling.
    value = re.sub(r"\(\?<([A-Za-z_$][\w$]*)>", r"(?P<\1>", value)
    value = re.sub(r"\\k<([A-Za-z_$][\w$]*)>", r"(?P=\1)", value)
    value = re.sub(r"\\u\{([0-9A-Fa-f]{1,6})\}", lambda match: _unicode_escape(match.group(1)), value)
    if re.search(r"\\[pP]\{", value):
        raise ValueError("unsupported Unicode property escape")
    return value, flags


def _unicode_escape(hex_value: str) -> str:
    codepoint = int(hex_value, 16)
    if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
        raise ValueError("invalid Unicode escape")
    return "\\U" + f"{codepoint:08x}"


def _unsafe_regex(source: str) -> bool:
    """Reject backtracking shapes that cannot be bounded by deadline checks."""
    def parse(position: int, stop_at_group: bool = False):
        has_alternative = False
        has_unbounded = False
        previous_unbounded = False
        unsafe = False
        while position < len(source):
            char = source[position]
            if stop_at_group and char == ")":
                return has_alternative, has_unbounded, unsafe, position + 1
            if char == "|":
                has_alternative = True
                previous_unbounded = False
                position += 1
                continue

            atom_alternative = False
            atom_unbounded = False
            if char == "\\":
                if position + 1 >= len(source):
                    position += 1
                    continue
                escaped = source[position + 1]
                if escaped.isdigit() and escaped != "0":
                    unsafe = True
                elif escaped == "k" and position + 2 < len(source) and source[position + 2] == "<":
                    unsafe = True
                position += 2
            elif char == "[":
                position += 1
                escaped = False
                while position < len(source):
                    current = source[position]
                    position += 1
                    if escaped:
                        escaped = False
                    elif current == "\\":
                        escaped = True
                    elif current == "]":
                        break
            elif char == "(":
                position += 1
                if source.startswith("?P=", position):
                    unsafe = True
                    close = source.find(")", position + 3)
                    position = len(source) if close < 0 else close + 1
                    continue
                if source.startswith("?:", position):
                    position += 2
                elif source.startswith(("?=", "?!"), position):
                    position += 2
                elif source.startswith(("?<=", "?<!"), position):
                    position += 3
                elif source.startswith("?P<", position):
                    close = source.find(">", position + 3)
                    if close < 0:
                        return False, False, True, len(source)
                    position = close + 1
                elif source.startswith("?<", position):
                    close = source.find(">", position + 2)
                    if close < 0:
                        return False, False, True, len(source)
                    position = close + 1
                elif source.startswith("?", position):
                    colon = source.find(":", position + 1)
                    if colon < 0:
                        return False, False, True, len(source)
                    position = colon + 1
                atom_alternative, atom_unbounded, nested_unsafe, position = parse(position, True)
                unsafe = unsafe or nested_unsafe
            else:
                position += 1

            quantifier_unbounded = False
            quantifier_max = 1
            if position < len(source) and source[position] in "*+?":
                quantifier = source[position]
                quantifier_unbounded = quantifier in "*+"
                quantifier_max = None if quantifier_unbounded else 1
                position += 1
            elif position < len(source) and source[position] == "{":
                end = source.find("}", position + 1)
                if end >= 0:
                    spec = source[position + 1:end]
                    match = re.fullmatch(r"(\d+)(?:,(\d*))?", spec)
                    if match:
                        if "," in spec and not match.group(2):
                            quantifier_unbounded = True
                            quantifier_max = None
                        else:
                            quantifier_max = int(match.group(2) or match.group(1))
                            if quantifier_max > 256:
                                unsafe = True
                        position = end + 1
            if position < len(source) and source[position] == "?":
                position += 1

            if quantifier_unbounded:
                if previous_unbounded or atom_unbounded or atom_alternative:
                    unsafe = True
                has_unbounded = True
                previous_unbounded = True
            else:
                if atom_unbounded and quantifier_max and quantifier_max > 1:
                    unsafe = True
                if atom_alternative and quantifier_max and quantifier_max > 1:
                    unsafe = True
                previous_unbounded = False
        return has_alternative, has_unbounded, unsafe, position

    _, _, unsafe, _ = parse(0)
    return unsafe


def _rewrite_safe_regex(source: str) -> str:
    """Collapse redundant wildcards and nested repeats when matching is unchanged."""
    def collapse(match):
        atom, inner, outer = match.groups()
        return atom + ("+" if inner == outer == "+" else "*")

    value = re.sub(r"\(\?:([A-Za-z0-9])([+*])\)([+*])", collapse, source)
    wildcard_literal = re.fullmatch(r"\.\*([A-Za-z0-9_:/-]{2,})\.\*", value)
    if wildcard_literal:
        return wildcard_literal.group(1)
    return value


def _compile_regex(source: str) -> tuple[re.Pattern[str], str]:
    if len(source) > MAX_REGEX_LENGTH:
        raise ValueError("regular expression too long")
    translated, flags = _parse_js_flags(source)
    translated = _rewrite_safe_regex(translated)
    if _unsafe_regex(translated):
        raise ValueError("unsafe regular expression")
    return re.compile(translated, flags), translated


_TAG_MARKER = re.compile(r"\\;(version|confidence):", re.IGNORECASE)


def _split_pattern_tags(source: str) -> tuple[str, str | None, int]:
    markers = list(_TAG_MARKER.finditer(source))
    if not markers:
        return source, None, 100
    regex_source = source[:markers[0].start()]
    version = None
    confidence = 100
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(source)
        content = source[marker.end():end]
        if marker.group(1).casefold() == "version":
            version = content
        else:
            if not re.fullmatch(r"\d{1,3}", content) or not 0 <= int(content) <= 100:
                raise ValueError("invalid confidence tag")
            confidence = int(content)
    return regex_source, version, confidence


def _required_literal(regex_source: str) -> str:
    """Find a conservative literal guaranteed to occur in every match."""
    try:
        translated, _ = _parse_js_flags(regex_source)
    except ValueError:
        return ""

    def parse_expression(position: int, stop_at_group: bool = False):
        branches = []
        sequence = []
        literal = []

        def flush():
            if literal:
                sequence.append(("lit", "".join(literal)))
                literal.clear()

        while position < len(translated):
            char = translated[position]
            if stop_at_group and char == ")":
                break
            if char == "|":
                flush()
                branches.append(sequence)
                sequence = []
                position += 1
                continue
            atom_type = "other"
            atom_value = ""
            if char == "\\":
                if position + 1 >= len(translated):
                    position += 1
                    continue
                escape = translated[position + 1]
                if escape in r".^$*+?{}[]\|()/-":
                    atom_type, atom_value = "lit", escape
                    position += 2
                elif escape == "x" and position + 3 < len(translated):
                    token = translated[position + 2:position + 4]
                    if re.fullmatch(r"[0-9A-Fa-f]{2}", token):
                        atom_type, atom_value = "lit", chr(int(token, 16))
                        position += 4
                    else:
                        position += 2
                elif escape == "u" and position + 5 < len(translated):
                    token = translated[position + 2:position + 6]
                    if re.fullmatch(r"[0-9A-Fa-f]{4}", token):
                        atom_type, atom_value = "lit", chr(int(token, 16))
                        position += 6
                    else:
                        position += 2
                else:
                    position += 2
            elif char == "[":
                position += 1
                escaped_class = False
                while position < len(translated):
                    current = translated[position]
                    position += 1
                    if escaped_class:
                        escaped_class = False
                    elif current == "\\":
                        escaped_class = True
                    elif current == "]":
                        break
            elif char == "(":
                position += 1
                assertion = False
                if translated.startswith("?:", position):
                    position += 2
                elif translated.startswith(("?=", "?!", "?<=", "?<!"), position):
                    assertion = True
                    position += 2 if translated.startswith(("?=", "?!"), position) else 3
                elif translated.startswith("?P<", position):
                    closing = translated.find(">", position + 3)
                    if closing < 0:
                        assertion = True
                    else:
                        position = closing + 1
                else:
                    assertion = True
                child, position = parse_expression(position, True)
                if position < len(translated) and translated[position] == ")":
                    position += 1
                if not assertion:
                    atom_type = "group"
                    atom_value = child
            elif char in ".^$":
                position += 1
            else:
                atom_type, atom_value = "lit", char
                position += 1

            # Consume one quantifier. A zero-minimum repeat contributes no
            # required text; a positive-minimum repeat retains its literal.
            minimum = 1
            if position < len(translated) and translated[position] in "?*+":
                quantifier = translated[position]
                minimum = 0 if quantifier in "?*" else 1
                position += 1
            elif position < len(translated) and translated[position] == "{":
                close = translated.find("}", position + 1)
                if close >= 0 and re.fullmatch(r"\d+(?:,\d*)?", translated[position + 1:close]):
                    minimum = int(translated[position + 1:close].split(",", 1)[0])
                    position = close + 1
            if position < len(translated) and translated[position] == "?":
                position += 1
            if minimum == 0:
                flush()
                sequence.append(("other", ""))
            elif atom_type == "lit":
                literal.append(atom_value)
            elif atom_type == "group":
                flush()
                child_literal = atom_value
                if child_literal:
                    sequence.append(("lit", child_literal))
                else:
                    sequence.append(("other", ""))
            else:
                flush()
                sequence.append(("other", ""))
        flush()
        branches.append(sequence)
        candidates = []
        for branch in branches:
            candidates.extend(value for kind, value in branch if kind == "lit" and len(value) >= 2)
            for left, right in zip(branch, branch[1:]):
                if left[0] == right[0] == "lit":
                    candidates.append(left[1] + right[1])
        if len(branches) == 1:
            return max(candidates, key=len, default=""), position
        common = set(candidates)
        for branch in branches:
            branch_candidates = {value for kind, value in branch if kind == "lit" and len(value) >= 2}
            common.intersection_update(branch_candidates)
        return max(common, key=len, default=""), position

    value, _ = parse_expression(0)
    return _fold_for_index(value) if len(value) >= 2 else ""


def _leading_literal(regex_source: str) -> str:
    """Return a fixed literal prefix, if the expression has one."""
    value, _ = _parse_js_flags(regex_source)
    if value.startswith("^"):
        value = value[1:]
    result = []
    position = 0
    while position < len(value):
        char = value[position]
        if char == "\\" and position + 1 < len(value):
            escaped = value[position + 1]
            if escaped in r".^$*+?{}[]\|()/-":
                result.append(escaped)
                position += 2
                continue
            if escaped == "x" and position + 3 < len(value) and re.fullmatch(r"[0-9A-Fa-f]{2}", value[position + 2:position + 4]):
                result.append(chr(int(value[position + 2:position + 4], 16)))
                position += 4
                continue
            if escaped == "u" and position + 5 < len(value) and re.fullmatch(r"[0-9A-Fa-f]{4}", value[position + 2:position + 6]):
                result.append(chr(int(value[position + 2:position + 6], 16)))
                position += 6
                continue
            break
        if char in ".^$*+?{}[]()|":
            break
        result.append(char)
        position += 1
    return _fold_for_index("".join(result)) if len(result) >= 3 else ""


def _fold_for_index(value: str) -> str:
    # Python's IGNORECASE also equates dotless i with i; normalize it here so
    # the literal prefilter cannot suppress a regex match on that character.
    return value.casefold().replace("ı", "i")


def _build_literal_index(patterns: tuple[_Pattern, ...], kind: str) -> tuple[_LiteralIndex | None, tuple[int, ...]]:
    transitions: list[dict[str, int]] = [{}]
    failures = [0]
    outputs: list[list[int]] = [[]]
    literal_lengths: dict[int, int] = {}
    no_literal = []
    for pattern in patterns:
        if pattern.kind != kind:
            continue
        if not pattern.literal or len(pattern.literal) < 3 or pattern.regex is None:
            no_literal.append(pattern.index)
            continue
        state = 0
        for char in pattern.literal:
            next_state = transitions[state].get(char)
            if next_state is None:
                next_state = len(transitions)
                transitions[state][char] = next_state
                transitions.append({})
                failures.append(0)
                outputs.append([])
            state = next_state
        outputs[state].append(pattern.index)
        literal_lengths[pattern.index] = len(pattern.literal)
    if len(transitions) == 1:
        return None, tuple(no_literal)
    queue = deque()
    for state in transitions[0].values():
        queue.append(state)
    while queue:
        state = queue.popleft()
        for char, next_state in transitions[state].items():
            queue.append(next_state)
            failure = failures[state]
            while failure and char not in transitions[failure]:
                failure = failures[failure]
            failures[next_state] = transitions[failure].get(char, 0)
            outputs[next_state].extend(outputs[failures[next_state]])
    frozen = _LiteralIndex(
        tuple(MappingProxyType(dict(edges)) for edges in transitions),
        tuple(failures),
        tuple(tuple(sorted(set(items))) for items in outputs),
        MappingProxyType(literal_lengths),
    )
    return frozen, tuple(no_literal)


def _string(value: object, *, allow_empty: bool = True) -> str:
    if (
        not isinstance(value, str) or len(value) > MAX_STRING_LENGTH
        or (not value and not allow_empty) or _contains_invalid_unicode(value)
    ):
        raise ValueError("invalid bounded string")
    return value


def _valid_technology_name(value: object) -> bool:
    # The rules module owns the shared name contract that the dashboard enforces.
    validate_name = (getattr(webrules, "valid_detection_name", None)
                     or getattr(webrules, "valid_technology_name", None))
    if validate_name is not None:
        return validate_name(value)
    scalar = getattr(webrules, "is_scalar_text", None) or getattr(webrules, "_is_scalar_text")
    return isinstance(value, str) and bool(value.strip()) and scalar(value, 256)


def _pattern_values(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (_string(value),)
    if isinstance(value, list) and len(value) <= MAX_PATTERNS_PER_TECHNOLOGY:
        return tuple(_string(item) for item in value)
    raise ValueError("invalid pattern value")


def _pattern_size(value: object) -> int:
    if isinstance(value, str):
        return 1
    if isinstance(value, dict):
        return sum(_pattern_size(item) for item in value.values())
    if isinstance(value, list):
        return sum(_pattern_size(item) for item in value)
    return 1


def _compile_pattern(index: int, kind: str, source: str, skipped: Counter[str], selector_regex=None):
    try:
        body, version, confidence = _split_pattern_tags(source)
        regex, translated = _compile_regex(body)
        if version is not None:
            _validate_version_template(version)
        literal = _required_literal(translated)
        prefix = _leading_literal(translated)
    except (re.error, ValueError, OverflowError, RecursionError):
        skipped["invalid or unsafe regular expression"] += 1
        return None
    return _Pattern(index, kind, source, regex, selector_regex, version, confidence,
                    literal, prefix)


def _validate_version_template(template: str) -> None:
    _string(template)
    pieces = _ternary(template)
    for piece in pieces:
        probe = re.sub(r"\\\d+", "x", piece)
        probe = re.sub(r"\\k<[A-Za-z_$][\w$]*>", "x", probe)
        if not probe or not re.search(r"[.^$*+?{}\[\]()]", probe):
            continue
        translated, flags = _parse_js_flags(probe)
        if _unsafe_regex(translated):
            raise ValueError("unsafe version regular expression")
        re.compile(translated, flags)


def _ternary(template: str) -> tuple[str, ...]:
    match = re.fullmatch(r"\\(\d+|[A-Za-z_$][\w$]*)\?([^:]*):(.*)", template, re.DOTALL)
    if match:
        return match.group(2), match.group(3)
    return (template,)


def _dom_selector(source: str) -> _Selector:
    if not source or len(source) > 512:
        raise ValueError("invalid selector length")
    position = 0
    tag = ""
    identifier = ""
    classes = []
    attributes = []
    token = re.compile(
        r"(?P<tag>[A-Za-z][A-Za-z0-9-]*)|(?P<id>#[A-Za-z0-9_-]+)|"
        r"(?P<class>\.[A-Za-z0-9_-]+)|"
        r"\[(?P<attr>[A-Za-z_][A-Za-z0-9_.:-]*)(?:(?P<op>\*=|\^=|\$=|=)"
        r"(?P<value>\"[^\"]{0,256}\"|'[^']{0,256}'|[^\]\s]{1,256}))?\]"
    )
    while position < len(source):
        match = token.match(source, position)
        if not match:
            raise ValueError("unsupported DOM selector")
        if match.group("tag"):
            if tag:
                raise ValueError("multiple tag selectors")
            tag = match.group("tag").casefold()
        elif match.group("id"):
            if identifier:
                raise ValueError("multiple id selectors")
            identifier = match.group("id")[1:]
        elif match.group("class"):
            classes.append(match.group("class")[1:])
        else:
            value = match.group("value") or ""
            if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
                value = value[1:-1]
            attributes.append(_SelectorAttribute(match.group("attr").casefold(), match.group("op") or "", value))
        position = match.end()
    if not any((tag, identifier, classes, attributes)):
        raise ValueError("empty DOM selector")
    return _Selector(tag, identifier, tuple(classes), tuple(attributes))


def _dom_pattern(index: int, selector_source: str, descriptor: object, skipped: Counter[str]):
    try:
        selector = _dom_selector(selector_source)
    except ValueError:
        skipped["unsupported DOM selector"] += 1
        return None
    if not isinstance(descriptor, dict) or any(key not in {"exists", "attributes", "text", "properties"} for key in descriptor):
        skipped["malformed DOM pattern"] += 1
        return None
    if "properties" in descriptor:
        skipped["DOM properties require a JavaScript runtime"] += 1
        return None
    if "exists" in descriptor:
        exists = descriptor["exists"]
        if isinstance(exists, str):
            try:
                _string(exists)
            except ValueError:
                skipped["malformed DOM pattern"] += 1
                return None
        elif exists is not True:
            skipped["unsupported DOM exists condition"] += 1
            return None
    attributes = []
    text = []
    try:
        raw_attributes = descriptor.get("attributes", {})
        if not isinstance(raw_attributes, dict) or len(raw_attributes) > 32:
            raise ValueError("invalid DOM attributes")
        for name, raw_patterns in raw_attributes.items():
            name = _string(name, allow_empty=False).casefold()
            tests = []
            for raw in _pattern_values(raw_patterns):
                body, version, confidence = _split_pattern_tags(raw)
                regex, _ = _compile_regex(body)
                if version is not None:
                    _validate_version_template(version)
                tests.append(_DOMTest(regex, version, confidence))
            attributes.append((name, tuple(tests)))
        raw_text = descriptor.get("text")
        if raw_text is not None:
            for raw in _pattern_values(raw_text):
                body, version, confidence = _split_pattern_tags(raw)
                regex, _ = _compile_regex(body)
                if version is not None:
                    _validate_version_template(version)
                text.append(_DOMTest(regex, version, confidence))
    except (ValueError, re.error, OverflowError):
        skipped["invalid DOM condition"] += 1
        return None
    pattern = _Pattern(index, "dom", selector_source, None, selector=selector,
                       dom_exists=True, dom_attributes=tuple(attributes), dom_text=tuple(text))
    return pattern


def _relation_values(value: object) -> tuple[object, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and len(value) <= MAX_PATTERNS_PER_TECHNOLOGY:
        return tuple(value)
    raise ValueError("invalid relationship value")


def _parse_relationships(data: dict, skipped: Counter[str]):
    implies = []
    excludes = []
    requires = []
    requires_categories = []
    for raw in _relation_values(data.get("implies", [])):
        try:
            target, _, confidence = _split_pattern_tags(_string(raw, allow_empty=False))
            if not _valid_technology_name(target):
                raise ValueError("invalid implied technology")
            implies.append(_Relationship(target.strip(), confidence))
        except ValueError:
            skipped["malformed implies relationship"] += 1
    for field, destination in (("excludes", excludes), ("requires", requires)):
        for raw in _relation_values(data.get(field, [])):
            try:
                target, _, _ = _split_pattern_tags(_string(raw, allow_empty=False))
                if not _valid_technology_name(target):
                    raise ValueError("invalid relationship")
                destination.append(target.strip().casefold())
            except ValueError:
                skipped[f"malformed {field} relationship"] += 1
    for raw in _relation_values(data.get("requiresCategory", [])):
        try:
            requires_categories.append(_category_id(raw))
        except ValueError:
            skipped["malformed requiresCategory relationship"] += 1
    return tuple(implies), tuple(excludes), tuple(requires), tuple(requires_categories)


def _patterns_for_technology(data: dict, base_index: int, skipped: Counter[str], unsupported: Counter[str]):
    output: list[_Pattern] = []
    count = sum(_pattern_size(data.get(kind)) for kind in SUPPORTED_KINDS | UNSUPPORTED_KINDS if kind in data)
    if count > MAX_PATTERNS_PER_TECHNOLOGY:
        raise ValueError("too many patterns in technology")
    for kind in sorted(UNSUPPORTED_KINDS):
        if kind in data:
            unsupported[kind] += max(1, _pattern_size(data[kind]))
            skipped[f"unsupported kind: {kind}"] += max(1, _pattern_size(data[kind]))
    for kind in sorted(SUPPORTED_KINDS):
        if kind not in data:
            continue
        raw = data[kind]
        if kind in {"headers", "meta"}:
            if not isinstance(raw, dict) or len(raw) > MAX_PATTERNS_PER_TECHNOLOGY:
                skipped["malformed pattern collection"] += 1
                continue
            for selector_source, values in raw.items():
                try:
                    selector_source = _string(selector_source, allow_empty=False)
                    selector_regex, _ = _compile_regex(selector_source)
                    patterns = _pattern_values(values)
                except (ValueError, re.error):
                    skipped["malformed pattern selector"] += 1
                    continue
                for source in patterns:
                    pattern = _compile_pattern(base_index + len(output), kind, source, skipped, selector_regex)
                    if pattern is not None:
                        output.append(pattern)
        elif kind == "cookies":
            if isinstance(raw, dict):
                if len(raw) > MAX_PATTERNS_PER_TECHNOLOGY:
                    skipped["malformed pattern collection"] += 1
                    continue
                sources = raw.keys()
            elif isinstance(raw, list):
                sources = raw
            else:
                skipped["malformed pattern collection"] += 1
                continue
            for source in sources:
                try:
                    source = _string(source, allow_empty=False)
                except ValueError:
                    skipped["malformed pattern string"] += 1
                    continue
                pattern = _compile_pattern(base_index + len(output), kind, source, skipped)
                if pattern is not None:
                    output.append(pattern)
        elif kind == "dom":
            if isinstance(raw, list):
                if len(raw) > MAX_PATTERNS_PER_TECHNOLOGY:
                    skipped["malformed DOM collection"] += 1
                    continue
                entries = ((selector, {"exists": True}) for selector in raw)
            elif isinstance(raw, dict) and len(raw) <= MAX_PATTERNS_PER_TECHNOLOGY:
                entries = raw.items()
            else:
                skipped["malformed DOM collection"] += 1
                continue
            for selector_source, descriptor in entries:
                try:
                    selector_source = _string(selector_source, allow_empty=False)
                except ValueError:
                    skipped["unsupported DOM selector"] += 1
                    continue
                pattern = _dom_pattern(base_index + len(output), selector_source, descriptor, skipped)
                if pattern is not None:
                    output.append(pattern)
        else:
            try:
                sources = _pattern_values(raw)
            except ValueError:
                skipped["malformed pattern collection"] += 1
                continue
            for source in sources:
                pattern = _compile_pattern(base_index + len(output), kind, source, skipped)
                if pattern is not None:
                    output.append(pattern)
    return tuple(output)


def _load_groups(root: _DirectoryHandle, skipped: Counter[str], expected_stamp=None) -> dict[str, str]:
    if expected_stamp is None:
        return {}
    try:
        if len(expected_stamp) != 7:
            raise OSError("invalid checked groups file")
        if expected_stamp[3] > MAX_METADATA_BYTES:
            skipped["malformed groups file"] += 1
            return {}
        payload = _read_json_file(root, "groups.json", MAX_METADATA_BYTES, expected_stamp)
        if not isinstance(payload, (dict, list)):
            skipped["malformed groups file"] += 1
            return {}
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, OverflowError, RecursionError):
        skipped["malformed groups file"] += 1
        return {}
    entries = payload.items() if isinstance(payload, dict) else enumerate(payload)
    result = {}
    for identifier, entry in entries:
        try:
            key = _category_id(identifier)
            if isinstance(entry, str):
                name = entry
            elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
                name = entry["name"]
            else:
                raise ValueError("invalid group")
            if not name or len(name) > MAX_STRING_LENGTH or _contains_invalid_unicode(name):
                raise ValueError("invalid group name")
            result[key] = name
        except ValueError:
            skipped["malformed group entry"] += 1
    return result


def _load_uncached(snapshot: _DirectorySnapshot) -> Fingerprints:
    skipped_technologies: Counter[str] = Counter()
    skipped_patterns: Counter[str] = Counter()
    unsupported_kinds: Counter[str] = Counter()
    root = snapshot.root
    technologies_dir = snapshot.technologies_dir
    metadata_stamps = dict(snapshot.metadata)
    categories = _category_map(root, skipped_technologies, metadata_stamps.get("categories.json"))
    groups = _load_groups(root, skipped_technologies, metadata_stamps.get("groups.json"))
    if snapshot.overflow_files:
        skipped_technologies["technology file count limit"] += snapshot.overflow_files
    if snapshot.truncated:
        skipped_technologies["directory entry limit"] += 1
    technologies: list[_Technology] = []
    patterns: list[_Pattern] = []
    bytes_seen = 0
    for filename, expected_stamp in snapshot.files:
        try:
            if not expected_stamp:
                skipped_technologies["technology file unavailable"] += 1
                continue
            info = technologies_dir.stat(filename)
            if not _safe_file_info(info):
                skipped_technologies["technology file is not a regular file"] += 1
                continue
            if _stat_stamp(info) != expected_stamp:
                skipped_technologies["technology file changed during loading"] += 1
                continue
            file_size = info.st_size
            if file_size > MAX_FILE_BYTES:
                skipped_technologies["technology file too large"] += 1
                continue
            if bytes_seen + file_size > MAX_TOTAL_FINGERPRINT_BYTES:
                skipped_technologies["total fingerprint byte limit"] += 1
                continue
            bytes_seen += file_size
            payload = _read_json_file(technologies_dir, filename, MAX_FILE_BYTES, expected_stamp)
            if isinstance(payload, dict) and len(payload) > MAX_TECHNOLOGIES_PER_FILE:
                skipped_technologies["technologies per file limit"] += 1
                continue
            if not isinstance(payload, dict) or not payload:
                skipped_technologies["malformed technology file"] += 1
                continue
            for name, data in payload.items():
                try:
                    if _contains_invalid_unicode(name) or _contains_invalid_unicode(data):
                        skipped_technologies["invalid Unicode scalar value"] += 1
                        continue
                    if not _valid_technology_name(name) or not isinstance(data, dict):
                        raise ValueError("malformed technology shape")
                    if any(field not in _KNOWN_FIELDS for field in data):
                        raise ValueError("unknown technology field")
                    if "cats" not in data or not isinstance(data["cats"], list) or len(data["cats"]) > 64:
                        raise ValueError("malformed technology categories")
                    category_ids = tuple(_category_id(value) for value in data["cats"])
                    cpe = data.get("cpe", "")
                    if not isinstance(cpe, str) or len(cpe) > MAX_STRING_LENGTH:
                        raise ValueError("malformed technology CPE")
                    if cpe:
                        try:
                            fields = split_cpe23(cpe)
                            invalid_cpe = (
                                len(fields) != 11 or fields[0] not in {"a", "o", "h"}
                                or fields[1] in {"", "*", "-"} or fields[2] in {"", "*", "-"}
                            )
                            if not invalid_cpe:
                                webrules._validated_cpe(cpe)
                            else:
                                cpe = ""
                        except (TypeError, ValueError):
                            # CPE is optional identity metadata; an unsupported
                            # or non-product-specific value never blocks detection.
                            cpe = ""
                    for field in ("description", "website", "icon", "pricing"):
                        if field not in data:
                            continue
                        value = data[field]
                        if isinstance(value, str):
                            _string(value)
                        elif isinstance(value, list) and len(value) <= 64:
                            for item in value:
                                _string(item)
                        else:
                            raise ValueError("malformed technology metadata")
                    if any(field in data and type(data[field]) is not bool for field in ("saas", "oss")):
                        raise ValueError("malformed technology metadata")
                    if "groups" in data:
                        if not isinstance(data["groups"], list) or len(data["groups"]) > 64:
                            raise ValueError("malformed technology groups")
                        for group in data["groups"]:
                            _category_id(group)
                    potential_patterns = sum(
                        _pattern_size(data[kind]) for kind in _ALL_KINDS if kind in data
                    )
                    if potential_patterns > MAX_PATTERNS_PER_TECHNOLOGY:
                        skipped_technologies["technology pattern count limit"] += 1
                        continue
                    if potential_patterns > MAX_TOTAL_PATTERNS - len(patterns):
                        skipped_technologies["total pattern limit"] += 1
                        continue
                    local_patterns = _patterns_for_technology(data, len(patterns), skipped_patterns, unsupported_kinds)
                    if len(patterns) + len(local_patterns) > MAX_TOTAL_PATTERNS:
                        skipped_technologies["total pattern limit"] += 1
                        continue
                    vendor, product = _cpe_identity(cpe, name)
                    category_names = tuple(dict.fromkeys(
                        categories[identifier] for identifier in category_ids if identifier in categories
                    )) or ("application",)
                    category = category_names[0]
                    relationships = _parse_relationships(data, skipped_patterns)
                    patterns.extend(local_patterns)
                    technologies.append(_Technology(name, cpe, vendor, product, category, category_ids,
                                                     tuple(pattern.index for pattern in local_patterns), *relationships,
                                                     category_names))
                except (ValueError, TypeError, OverflowError, RecursionError):
                    skipped_technologies["malformed technology"] += 1
        except OverflowError:
            skipped_technologies["technology file too large"] += 1
        except _FingerprintFileChanged:
            skipped_technologies["technology file changed during loading"] += 1
        except FileNotFoundError:
            skipped_technologies["technology file unavailable"] += 1
        except (UnicodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
            skipped_technologies["malformed technology file"] += 1
        except OSError:
            skipped_technologies["technology file unavailable or untrusted"] += 1
    index_map = {}
    no_literal = {}
    pattern_tuple = tuple(patterns)
    for kind in sorted(SUPPORTED_KINDS - {"dom"}):
        index, no_literal_patterns = _build_literal_index(pattern_tuple, kind)
        if index is not None:
            index_map[kind] = index
        no_literal[kind] = no_literal_patterns
    stats = FingerprintStats(len(technologies), _freeze_counts(skipped_technologies),
                             _freeze_counts(skipped_patterns), _freeze_counts(unsupported_kinds))
    return Fingerprints(root.path, tuple(technologies), pattern_tuple, MappingProxyType(dict(categories)),
                        MappingProxyType(dict(groups)), stats, MappingProxyType(index_map),
                        MappingProxyType(no_literal))


# Reasons that mean a supported file was not read as published. A malformed file
# is a property of the collection itself and does not make every scan partial.
INCOMPLETE_LOAD_REASONS = frozenset({
    "fingerprint directory unavailable", "untrusted fingerprint layout",
    "technology file changed during loading", "technology file unavailable",
    "technology file unavailable or untrusted", "categories file unavailable",
    "fingerprint collections are not supported on this platform",
    "directory entry limit", "technology file count limit", "technology file too large",
    "total fingerprint byte limit", "technologies per file limit", "technology pattern count limit",
    "total pattern limit", "categories file too large", "technology file is not a regular file",
})
_LOAD_CACHE: dict[tuple, Fingerprints] = {}
_LOAD_CACHE_ORDER: deque[tuple] = deque()
_LOAD_CACHE_LIMIT = 8


def _collections_supported() -> bool:
    """External collections are read on POSIX systems only for now."""
    return os.name != "nt"


def load_fingerprints(directory: Path) -> Fingerprints:
    """Load and cache a bounded operator-supplied fingerprint directory.

    ``directory`` may point at the published ``src`` directory or directly at
    its ``technologies`` child. Malformed files and patterns are counted and
    skipped so an optional collection cannot abort a scan.

    External collections are read on POSIX systems only for now; on Windows the
    load reports that the platform is not supported and the scan is partial.
    The operator must restrict write access to the collection and its directories.
    """
    if not _collections_supported():
        # The trust checks rely on POSIX directory handles and no-follow opens.
        stats = FingerprintStats(skipped_technologies=(
            ("fingerprint collections are not supported on this platform", 1),))
        return Fingerprints(Path(directory), (), (), MappingProxyType({}), MappingProxyType({}), stats,
                            MappingProxyType({}), MappingProxyType({}))
    with ExitStack() as stack:
        try:
            snapshot = _snapshot_directory(Path(directory), stack)
        except (OSError, RuntimeError, ValueError) as error:
            reason = ("untrusted fingerprint layout" if isinstance(error, PermissionError)
                      else "fingerprint directory unavailable")
            stats = FingerprintStats(skipped_technologies=((reason, 1),))
            return Fingerprints(Path(directory), (), (), MappingProxyType({}), MappingProxyType({}), stats,
                                MappingProxyType({}), MappingProxyType({}))
        cached = _LOAD_CACHE.get(snapshot.key)
        if cached is not None:
            return cached
        loaded = _load_uncached(snapshot)
    if loaded.incomplete:
        # A transient read or trust failure must not be remembered as the complete collection.
        return loaded
    _LOAD_CACHE[snapshot.key] = loaded
    _LOAD_CACHE_ORDER.append(snapshot.key)
    while len(_LOAD_CACHE_ORDER) > _LOAD_CACHE_LIMIT:
        oldest = _LOAD_CACHE_ORDER.popleft()
        _LOAD_CACHE.pop(oldest, None)
    return loaded


@dataclass(slots=True)
class _Node:
    tag: str
    attributes: dict[str, str]
    parent: int | None
    children: list[int]
    text: list[str]


class _AnalysisStopped(Exception):
    pass


class _PageParser(HTMLParser):
    def __init__(self, html: str, *, deadline: float = float("inf"), clock=time.monotonic):
        super().__init__(convert_charrefs=True)
        self.deadline = deadline
        self.clock = clock
        self.nodes: list[_Node] = []
        self.stack: list[int] = []
        self.meta: list[tuple[str, str]] = []
        self.script_urls: list[str] = []
        self.inline_scripts: list[str] = []
        self.inline_styles: list[str] = []
        self.visible_text: list[str] = []
        self.visible_text_length = 0
        self.capture_tag = ""
        self.capture_text: list[str] = []
        self.capture_length = 0
        self.truncated = False
        self.html = self.bound_text(html, MAX_HTML_LENGTH)
        self.id_index: dict[str, list[int]] = {}
        self.class_index: dict[str, list[int]] = {}
        self.tag_index: dict[str, list[int]] = {}
        self.attribute_index: dict[str, list[int]] = {}
        self._node_text_cache: dict[int, str] = {}
        self._node_text_cache_bytes = 0
        self._node_text_work_remaining = MAX_DOM_TEXT_WORK
        try:
            for offset in range(0, len(self.html), HTML_PARSE_CHUNK):
                self.check_deadline()
                self.feed(self.html[offset:offset + HTML_PARSE_CHUNK])
            self.check_deadline()
            self.close()
        except _AnalysisStopped:
            raise
        except Exception:
            # HTMLParser is intentionally lenient; malformed pages simply
            # contribute the bounded prefix that was parsed successfully.
            self.mark_truncated()

    def mark_truncated(self) -> None:
        self.truncated = True

    def bound_text(self, value: object, limit: int) -> str:
        return _bounded_text(value, limit, self.mark_truncated)

    def bound_items(self, values, limit):
        for index, value in enumerate(islice(values, limit + 1)):
            if index == limit:
                self.mark_truncated()
                break
            yield value

    def check_deadline(self) -> None:
        if self.clock() >= self.deadline:
            raise _AnalysisStopped

    def handle_starttag(self, tag: str, attrs):
        self.check_deadline()
        tag = tag.casefold()
        values = {str(name).casefold(): "" if value is None else str(value) for name, value in attrs}
        if tag == "meta":
            name = values.get("name") or values.get("property") or values.get("http-equiv")
            if name and "content" in values:
                if len(self.meta) < MAX_META_TAGS:
                    self.meta.append((name, values["content"]))
                else:
                    self.mark_truncated()
        if tag == "script" and values.get("src"):
            if len(self.script_urls) < MAX_SCRIPT_URLS:
                self.script_urls.append(values["src"])
            else:
                self.mark_truncated()
        if tag in {"script", "style"}:
            self.capture_tag = tag
            self.capture_text = []
            self.capture_length = 0
        if len(self.nodes) >= MAX_DOM_NODES:
            self.mark_truncated()
            return
        parent = self.stack[-1] if self.stack else None
        index = len(self.nodes)
        node = _Node(tag, values, parent, [], [])
        self.nodes.append(node)
        if parent is not None:
            self.nodes[parent].children.append(index)
        self.tag_index.setdefault(tag, []).append(index)
        if "id" in values:
            self.id_index.setdefault(values["id"], []).append(index)
        for class_name in values.get("class", "").split():
            self.class_index.setdefault(class_name, []).append(index)
        for name in values:
            self.attribute_index.setdefault(name, []).append(index)
        if tag not in _VOID_TAGS:
            self.stack.append(index)

    def handle_endtag(self, tag: str):
        self.check_deadline()
        tag = tag.casefold()
        if self.capture_tag == tag:
            content = "".join(self.capture_text)
            if tag == "script":
                self.inline_scripts.append(content)
            elif tag == "style":
                self.inline_styles.append(content)
            self.capture_tag = ""
            self.capture_text = []
            self.capture_length = 0
        for position in range(len(self.stack) - 1, -1, -1):
            if position % 256 == 0:
                self.check_deadline()
            if self.nodes[self.stack[position]].tag == tag:
                del self.stack[position:]
                break

    def handle_data(self, data: str):
        self.check_deadline()
        if self.capture_tag:
            chunk = self.bound_text(data, MAX_RESOURCE_LENGTH - self.capture_length)
            if chunk:
                self.capture_text.append(chunk)
                self.capture_length += len(chunk)
        if self.stack:
            self.nodes[self.stack[-1]].text.append(data)
        if not self.capture_tag:
            chunk = self.bound_text(data, MAX_TEXT_LENGTH - self.visible_text_length)
            if chunk:
                self.visible_text.append(chunk)
                self.visible_text_length += len(chunk)

    def _charge_text_work(self, amount: int) -> None:
        # Count traversed nodes and text characters, including repeated cache hits.
        if amount > self._node_text_work_remaining:
            raise _AnalysisStopped
        self._node_text_work_remaining -= amount

    def node_text(self, index: int) -> str:
        self.check_deadline()
        cached = self._node_text_cache.get(index)
        if cached is not None:
            self._charge_text_work(len(cached) + 1)
            return cached
        output = []
        pending = [index]
        total = 0
        while pending and total < MAX_TEXT_LENGTH:
            self.check_deadline()
            self._charge_text_work(1)
            current = pending.pop()
            node = self.nodes[current]
            for part in node.text:
                self.check_deadline()
                size = min(len(part), MAX_TEXT_LENGTH - total)
                self._charge_text_work(size)
                output.append(part[:size])
                total += size
                if total >= MAX_TEXT_LENGTH:
                    break
            pending.extend(reversed(node.children))
        if total == MAX_TEXT_LENGTH:
            self.mark_truncated()
        value = "".join(output)
        byte_length = len(value.encode("utf-8", errors="replace"))
        if self._node_text_cache_bytes + byte_length <= MAX_DOM_TEXT_CACHE_BYTES:
            self._node_text_cache[index] = value
            self._node_text_cache_bytes += byte_length
        return value


@dataclass(frozen=True, slots=True)
class _Source:
    value: str
    source: str
    selector: str = ""


def _resource_source(resource: webrules.Resource) -> str:
    url = getattr(resource, "url", "")
    return url if isinstance(url, str) and url else "page"


def _bounded_text(value: object, limit: int, on_truncated) -> str:
    if not isinstance(value, str):
        return ""
    if len(value) > limit:
        on_truncated()
    return value[:limit]


def _page_sources(page: webrules.Page, page_url: str, *, deadline: float, clock):
    parser = _PageParser(getattr(page, "html", ""), deadline=deadline, clock=clock)
    if getattr(page, "truncated", False):
        parser.mark_truncated()
    sources: dict[str, list[_Source]] = {kind: [] for kind in SUPPORTED_KINDS}
    for name, values in getattr(page, "headers", {}).items():
        if not isinstance(name, str):
            continue
        name = name.casefold()
        if name in _COOKIE_HEADERS:
            continue
        for value in parser.bound_items(values, 64):
            sources["headers"].append(_Source(parser.bound_text(value, 16_384), f"header:{name}", name))
    for name, content in parser.meta:
        sources["meta"].append(_Source(parser.bound_text(content, 16_384), "page", name))
    for cookie in parser.bound_items(getattr(page, "cookie_names", ()), 4096):
        if isinstance(cookie, str):
            sources["cookies"].append(_Source(parser.bound_text(cookie, 256), f"cookie:{cookie}"))
    for url in parser.script_urls:
        sources["scriptSrc"].append(_Source(parser.bound_text(url, 4096), "page"))
    resource_budget = MAX_RESOURCE_BYTES_PER_PAGE
    for resource in parser.bound_items(getattr(page, "resources", ()), MAX_PAGE_RESOURCES):
        parser.check_deadline()
        kind = getattr(resource, "kind", "")
        source = _resource_source(resource)
        url = parser.bound_text(getattr(resource, "url", ""), 4096)
        resource_text = getattr(resource, "text", "")
        per_resource_limit = MAX_ROBOTS_LENGTH if kind == "robots" else MAX_RESOURCE_LENGTH
        available = min(per_resource_limit, resource_budget)
        bounded_resource = parser.bound_text(resource_text, available)
        resource_budget -= len(bounded_resource)
        if kind == "script":
            if url:
                sources["scriptSrc"].append(_Source(url, source))
            sources["scripts"].append(_Source(bounded_resource, source))
        elif kind in {"style", "css"}:
            sources["css"].append(_Source(bounded_resource, source))
        elif kind == "robots":
            sources["robots"].append(_Source(bounded_resource, source))
    sources["scripts"].extend(_Source(value, "page") for value in parser.inline_scripts)
    sources["css"].extend(_Source(value, "page") for value in parser.inline_styles)
    sources["html"].append(_Source(parser.html, "page"))
    sources["text"].append(_Source("".join(parser.visible_text), "page"))
    sources["url"].append(_Source(parser.bound_text(page_url, 4096), "page"))
    return sources, parser


def _selector_candidates(selector: _Selector, parser: _PageParser) -> Iterable[int]:
    candidates = None
    if selector.identifier:
        candidates = parser.id_index.get(selector.identifier, [])
    for class_name in selector.classes:
        values = parser.class_index.get(class_name, [])
        if candidates is None or len(values) < len(candidates):
            candidates = values
    if selector.tag:
        values = parser.tag_index.get(selector.tag, [])
        if candidates is None or len(values) < len(candidates):
            candidates = values
    for attribute in selector.attributes:
        values = parser.attribute_index.get(attribute.name, [])
        if candidates is None or len(values) < len(candidates):
            candidates = values
    if candidates is None:
        return range(len(parser.nodes))
    return candidates


def _selector_matches(selector: _Selector, node: _Node) -> bool:
    if selector.tag and node.tag != selector.tag:
        return False
    if selector.identifier and node.attributes.get("id") != selector.identifier:
        return False
    if selector.classes:
        classes = set(node.attributes.get("class", "").split())
        if any(class_name not in classes for class_name in selector.classes):
            return False
    for attribute in selector.attributes:
        if attribute.name not in node.attributes:
            return False
        if not attribute.operator:
            continue
        value = node.attributes[attribute.name]
        if attribute.operator == "=" and value != attribute.value:
            return False
        if attribute.operator == "*=" and attribute.value not in value:
            return False
        if attribute.operator == "^=" and not value.startswith(attribute.value):
            return False
        if attribute.operator == "$=" and not value.endswith(attribute.value):
            return False
    return True


_VERSION_REFERENCE = re.compile(r"\\(?:(\d+)|k<([A-Za-z_$][\w$]*)>)")


def _group_span(match: re.Match[str], key: str | int) -> tuple[int, int]:
    try:
        return match.span(key)
    except (IndexError, OverflowError):
        return -1, -1


def _bounded_capture(match: re.Match[str], key: str | int) -> str:
    start, end = _group_span(match, key)
    if end - start > MAX_VERSION_CAPTURE_LENGTH:
        raise ValueError("version capture too long")
    return match.string[start:end] if start >= 0 else ""


def _reference_key(reference: re.Match[str]) -> str | int:
    return int(reference[1]) if reference[1] is not None else reference[2]


def _expand_version_reference(template: str, match: re.Match[str]) -> tuple[str, bool]:
    conditional = re.fullmatch(r"\\(\d+|[A-Za-z_$][\w$]*)\?([^:]*):(.*)", template, re.DOTALL)
    literal_value = False
    if conditional:
        group_key = conditional[1]
        start, end = _group_span(match, int(group_key) if group_key.isdigit() else group_key)
        template = conditional[2] if end > start else conditional[3]
        literal_value = (
            len(template) <= MAX_VERSION_CAPTURE_LENGTH and bool(webrules.normalize_version(template))
        ) or not re.search(r"[\\.^$*+?{}\[\]()|]", template)
    pure_reference = _VERSION_REFERENCE.fullmatch(template)
    if pure_reference:
        return _bounded_capture(match, _reference_key(pure_reference)), True

    chunks = []
    previous = 0
    remaining = MAX_REGEX_LENGTH
    for reference in _VERSION_REFERENCE.finditer(template):
        literal_size = reference.start() - previous
        if literal_size > remaining:
            raise ValueError("version expression too long")
        escaped = re.escape(_bounded_capture(match, _reference_key(reference)))
        remaining -= literal_size + len(escaped)
        if remaining < 0:
            raise ValueError("version expression too long")
        chunks.extend((template[previous:reference.start()], escaped))
        previous = reference.end()
    if len(template) - previous > remaining:
        raise ValueError("version expression too long")
    chunks.append(template[previous:])
    return "".join(chunks), literal_value


def _version_from(pattern: _Pattern | _DOMTest, value: str, matched: re.Match[str]) -> str:
    template = pattern.version
    if not template:
        return ""
    try:
        expanded, is_literal = _expand_version_reference(template, matched)
        if is_literal:
            candidate = expanded
        else:
            if not expanded:
                return ""
            translated, flags = _parse_js_flags(expanded)
            version_regex = re.compile(translated, flags)
            version_match = version_regex.search(value)
            if not version_match:
                return ""
            candidate = _bounded_capture(version_match, 1 if version_match.lastindex else 0)
        if len(candidate) > MAX_VERSION_CAPTURE_LENGTH or _contains_invalid_unicode(candidate):
            return ""
        return webrules.normalize_version(candidate)
    except (re.error, ValueError, IndexError):
        return ""


def _excerpt(value: str, start: int) -> str:
    begin = max(0, start - 40)
    return value[begin:begin + EVIDENCE_EXCERPT_LENGTH]


def _pattern_evidence(pattern: _Pattern, source: _Source, match: re.Match[str]):
    kind = EVIDENCE_KIND_MAP.get(pattern.kind, pattern.kind)
    if pattern.kind == "headers" and source.selector in _SENSITIVE_HEADERS:
        return "", (kind, source.source, source.source)
    version = _version_from(pattern, source.value, match)
    return version, (kind, source.source, _excerpt(source.value, match.start()))


@dataclass(slots=True)
class _DOMMatches:
    accepted: bool = False
    confidence: int = 100
    versions: set[str] = field(default_factory=set)
    excerpts: list[str] = field(default_factory=list)


def _dom_condition(alternatives: tuple[_DOMTest, ...], value: str, parser: _PageParser):
    for test in alternatives:
        parser.check_deadline()
        match = test.regex.search(value)
        if match is not None:
            parser.check_deadline()
            return test.confidence, _version_from(test, value, match), _excerpt(value, match.start())
    return None


def _dom_node_matches(pattern: _Pattern, selector: _Selector, parser: _PageParser, node_index: int):
    node = parser.nodes[node_index]
    if not _selector_matches(selector, node):
        return None
    conditions = []
    for name, alternatives in pattern.dom_attributes:
        value = node.attributes.get(name)
        if value is None:
            return None
        condition = _dom_condition(alternatives, value, parser)
        if condition is None:
            return None
        conditions.append(condition)
    if pattern.dom_text:
        condition = _dom_condition(pattern.dom_text, parser.node_text(node_index), parser)
        if condition is None:
            return None
        conditions.append(condition)
    return conditions


def _dom_matches(pattern: _Pattern, parser: _PageParser) -> tuple[_DOMMatches, bool]:
    matched = _DOMMatches()
    selector = pattern.selector
    if selector is None:
        return matched, False
    try:
        for node_index in _selector_candidates(selector, parser):
            parser.check_deadline()
            conditions = _dom_node_matches(pattern, selector, parser, node_index)
            if conditions is None:
                continue
            matched.accepted = True
            for confidence, version, excerpt in conditions:
                matched.confidence = min(matched.confidence, confidence)
                if version and len(matched.versions) < MAX_EVIDENCE_PER_DETECTION:
                    matched.versions.add(version)
                if len(matched.excerpts) < MAX_EVIDENCE_PER_DETECTION and excerpt not in matched.excerpts:
                    matched.excerpts.append(excerpt)
    except _AnalysisStopped:
        return matched, True
    return matched, False


@dataclass(slots=True)
class _DetectionRecord:
    technology: _Technology
    confidence: int
    versions: set[str]
    evidence_types: set[str]
    evidence: list[tuple[str, str, str]]
    implied_by: set[str]
    direct: bool


def _detect_category(technology: _Technology) -> str:
    return technology.category if technology.category in webrules.CATEGORIES else "application"


def _make_detection(record: _DetectionRecord):
    technology = record.technology
    if record.confidence >= 100:
        confidence = "high"
    elif record.confidence >= 50:
        confidence = "medium"
    else:
        confidence = "low"
    evidence_values = ()
    evidence_type = getattr(webrules, "Evidence", None)
    detection_fields = getattr(webrules.Detection, "__dataclass_fields__", {})
    if evidence_type is not None and "evidence" in detection_fields:
        built = []
        for kind, source, excerpt in record.evidence[:MAX_EVIDENCE_PER_DETECTION]:
            try:
                built.append(evidence_type(kind, source, excerpt))
            except (TypeError, ValueError):
                continue
        evidence_values = tuple(built)
    kwargs = {
        "vendor": technology.vendor,
        "product": technology.product,
        "category": _detect_category(technology),
        "categories": technology.categories or (_detect_category(technology),),
        "cpe": technology.cpe,
        "confidence": confidence,
        "versions": tuple(sorted(record.versions)),
        "evidence_types": tuple(sorted(record.evidence_types)),
        "name": technology.name,
        "ecosystem": "",
        "package": "",
        "implied_by": tuple(sorted(record.implied_by)),
        "name_only": not technology.cpe,
    }
    if "evidence" in detection_fields:
        kwargs["evidence"] = evidence_values
    return webrules.Detection(**{key: value for key, value in kwargs.items() if key in detection_fields})


def _technology_key(technology: _Technology) -> tuple[str, str]:
    return technology.name.casefold(), technology.cpe


def _merge_direct_record(records: dict[tuple[str, str], _DetectionRecord], technology: _Technology,
                         confidence: int, version: str, evidence):
    key = _technology_key(technology)
    record = records.get(key)
    if record is None:
        record = _DetectionRecord(technology, confidence, set(), set(), [], set(), True)
        records[key] = record
    record.confidence = max(record.confidence, confidence)
    if version:
        record.versions.add(version)
    record.evidence_types.add(evidence[0])
    if evidence not in record.evidence and len(record.evidence) < MAX_EVIDENCE_PER_DETECTION:
        record.evidence.append(evidence)


def _candidate_patterns(fingerprints: Fingerprints, kind: str, source: _Source,
                        deadline: float, clock, on_truncated) -> tuple[tuple[int, ...], bool, Mapping[int, set[int]]]:
    index = fingerprints.literal_indexes.get(kind)
    no_literal = fingerprints.no_literal.get(kind, ())
    if index is None:
        return no_literal, clock() >= deadline, MappingProxyType({})
    if len(source.value) <= 16_384:
        folded = _fold_for_index(source.value)
        found = []
        no_literal_set = set(no_literal)
        for pattern in fingerprints.patterns:
            if clock() >= deadline:
                return tuple(found), True, MappingProxyType({})
            if pattern.kind == kind and pattern.index in no_literal_set:
                found.append(pattern.index)
            elif pattern.kind == kind and pattern.literal and pattern.literal in folded:
                found.append(pattern.index)
        return tuple(found), clock() >= deadline, MappingProxyType({})
    positions, expired = index.find(source.value, deadline, clock, on_truncated)
    candidates = set(positions)
    candidates.update(no_literal)
    return tuple(candidates), expired, MappingProxyType(positions)


def _category_ids_available(records: Mapping[tuple[str, str], _DetectionRecord]) -> set[str]:
    return {identifier for record in records.values() for identifier in record.technology.category_ids}


def _resolve_relationships(fingerprints: Fingerprints, direct: dict[tuple[str, str], _DetectionRecord],
                           known_exclusions: set[str], deadline: float, clock, on_truncated):
    by_name: dict[str, _Technology | None] = {}
    for technology in fingerprints.technologies:
        if clock() >= deadline:
            return direct, True
        key = _technology_key(technology)
        previous = by_name.setdefault(key[0], technology)
        if previous is not None and _technology_key(previous) != key:
            by_name[key[0]] = None  # A name alone cannot select between distinct CPEs.
    working_direct = dict(direct)
    expansion_limit = min(10_000, len(fingerprints.technologies) * 8 + 1)
    for _ in range(len(direct) + 1):
        if clock() >= deadline:
            return direct, True
        records = dict(working_direct)
        pending = deque((record.technology, record.confidence, record.technology.name, 0)
                        for record in working_direct.values())
        best_implied: dict[tuple[str, str], int] = {}
        expansions = 0
        while pending and expansions < expansion_limit:
            if clock() >= deadline:
                return direct, True
            source, source_confidence, origin, depth = pending.popleft()
            if depth >= 32:
                if source.implies:
                    on_truncated()
                continue
            for relation in source.implies:
                if clock() >= deadline:
                    return direct, True
                technology = by_name.get(relation.target.casefold())
                if technology is None:
                    continue
                target_key = _technology_key(technology)
                if target_key in direct:
                    continue
                confidence = min(source_confidence, relation.confidence)
                record = records.get(target_key)
                if record is None:
                    record = _DetectionRecord(technology, confidence, set(), {"implied"}, [], {origin}, False)
                    records[target_key] = record
                    known_exclusions.update(technology.excludes)
                else:
                    record.confidence = max(record.confidence, confidence)
                    record.implied_by.add(origin)
                previous = best_implied.get(target_key, -1)
                if confidence > previous:
                    best_implied[target_key] = confidence
                    pending.append((technology, confidence, technology.name, depth + 1))
                else:
                    record.implied_by.add(origin)
            expansions += 1
        if pending:
            return direct, True

        excluded_names = set()
        for record in records.values():
            if clock() >= deadline:
                return direct, True
            excluded_names.update(record.technology.excludes)
        records = {key: record for key, record in records.items() if key[0] not in excluded_names}
        changed = True
        while changed:
            changed = False
            active_names = {name for name, _ in records}
            categories = _category_ids_available(records)
            for key, record in tuple(records.items()):
                if clock() >= deadline:
                    return direct, True
                if any(required not in active_names for required in record.technology.requires) or any(
                    required not in categories for required in record.technology.requires_categories
                ):
                    records.pop(key, None)
                    changed = True
        surviving_direct = {key: record for key, record in working_direct.items() if key in records}
        if surviving_direct.keys() == working_direct.keys():
            return records, False
        working_direct = surviving_direct
    return working_direct, True


class ExternalSession:
    """Accumulate direct matches for one site under its caller's deadline."""

    def __init__(self, fingerprints: Fingerprints, *, deadline: float, clock=time.monotonic):
        self.fingerprints = fingerprints
        self.deadline = deadline
        self.clock = clock
        self._direct: dict[tuple[str, str], _DetectionRecord] = {}
        self._known_exclusions: set[str] = set()
        self._by_index = {pattern.index: pattern for pattern in fingerprints.patterns}
        self._technology_by_index = {
            pattern_id: technology
            for technology in fingerprints.technologies
            for pattern_id in technology.pattern_ids
        }
        self._patterns_evaluated = 0
        self._stopped = False
        self._truncated = False
        self._result = None

    def _mark_truncated(self) -> None:
        self._truncated = True

    def _expired(self) -> bool:
        if self._stopped or self.clock() >= self.deadline:
            self._stopped = True
            return True
        return False

    def _record_direct(self, technology: _Technology, confidence: int, version: str, evidence) -> None:
        if _technology_key(technology) not in self._direct:
            self._known_exclusions.update(technology.excludes)
        _merge_direct_record(self._direct, technology, confidence, version, evidence)

    def _match_sources(self, sources: Mapping[str, Iterable[_Source]]) -> None:
        for kind in ("headers", "cookies", "meta", "scriptSrc", "scripts", "css", "html", "text", "url", "robots"):
            for source in sources.get(kind, ()):
                if self._expired():
                    return
                candidate_ids, expired, literal_positions = _candidate_patterns(
                    self.fingerprints, kind, source, self.deadline, self.clock, self._mark_truncated
                )
                if expired:
                    self._stopped = True
                    return
                for pattern_id in candidate_ids:
                    if self._expired():
                        return
                    pattern = self._by_index.get(pattern_id)
                    technology = self._technology_by_index.get(pattern_id)
                    if pattern is None or technology is None or pattern.regex is None:
                        continue
                    if kind in {"headers", "meta"}:
                        if pattern.selector_regex is None or not pattern.selector_regex.fullmatch(source.selector):
                            continue
                    self._patterns_evaluated += 1
                    positions = literal_positions.get(pattern_id, ())
                    if positions and pattern.prefix and pattern.literal.startswith(pattern.prefix):
                        matches = (
                            match for position in sorted(positions)
                            if not self._expired()
                            and (match := pattern.regex.match(source.value, position)) is not None
                        )
                    else:
                        match = pattern.regex.search(source.value)
                        matches = (match,) if match else ()
                    for match in matches:
                        if self._expired():
                            return
                        version, evidence = _pattern_evidence(pattern, source, match)
                        self._record_direct(technology, pattern.confidence, version, evidence)

    def _match_dom(self, parser: _PageParser) -> None:
        for technology in self.fingerprints.technologies:
            for pattern_id in technology.pattern_ids:
                if self._expired():
                    return
                pattern = self._by_index[pattern_id]
                if pattern.kind != "dom":
                    continue
                self._patterns_evaluated += 1
                matched, expired = _dom_matches(pattern, parser)
                if matched.accepted:
                    base_evidence = ("dom", "page", pattern.source[:EVIDENCE_EXCERPT_LENGTH])
                    self._record_direct(technology, matched.confidence, "", base_evidence)
                    record = self._direct[_technology_key(technology)]
                    for version in sorted(matched.versions):
                        if len(record.versions) >= MAX_EVIDENCE_PER_DETECTION:
                            break
                        record.versions.add(version)
                    for excerpt in matched.excerpts:
                        item = ("dom", "page", excerpt)
                        if len(record.evidence) >= MAX_EVIDENCE_PER_DETECTION:
                            break
                        if item not in record.evidence:
                            record.evidence.append(item)
                if expired:
                    self._stopped = True
                    return

    def add_page(self, page: webrules.Page, page_url: str) -> None:
        if self._result is not None or self._expired():
            return
        try:
            sources, parser = _page_sources(page, page_url, deadline=self.deadline, clock=self.clock)
        except _AnalysisStopped:
            self._stopped = True
            return
        self._match_sources(sources)
        if not self._stopped:
            self._match_dom(parser)
        self._truncated |= parser.truncated

    def add_resource(self, resource: webrules.Resource) -> None:
        if self._result is not None or self._expired():
            return
        kind = getattr(resource, "kind", "")
        source = _resource_source(resource)
        url = _bounded_text(getattr(resource, "url", ""), 4096, self._mark_truncated)
        value = getattr(resource, "text", "")
        if kind == "robots":
            sources = {"robots": (_Source(_bounded_text(value, MAX_ROBOTS_LENGTH, self._mark_truncated), source),)}
        elif kind == "script":
            sources = {
                "scriptSrc": (_Source(url, source),) if url else (),
                "scripts": (_Source(_bounded_text(value, MAX_RESOURCE_LENGTH, self._mark_truncated), source),),
            }
        elif kind in {"style", "css"}:
            sources = {"css": (_Source(_bounded_text(value, MAX_RESOURCE_LENGTH, self._mark_truncated), source),)}
        else:
            return
        self._match_sources(sources)

    def _partial_records(self) -> dict[tuple[str, str], _DetectionRecord]:
        return {
            key: record for key, record in self._direct.items()
            if key[0] not in self._known_exclusions
            and not record.technology.requires and not record.technology.requires_categories
        }

    def finish(self) -> tuple[tuple[webrules.Detection, ...], dict]:
        if self._result is not None:
            detections, stats = self._result
            return detections, dict(stats)
        if self._expired():
            resolved = self._partial_records()
        else:
            resolved, relation_stopped = _resolve_relationships(
                self.fingerprints, self._direct, self._known_exclusions,
                self.deadline - RELATION_FINALIZATION_RESERVE_SECONDS, self.clock, self._mark_truncated,
            )
            if relation_stopped:
                self._stopped = True
                resolved = self._partial_records()
        detections = tuple(
            _make_detection(record)
            for _, record in sorted(resolved.items(), key=lambda item: item[0])
        )
        stats = {
            "technologies_loaded": self.fingerprints.stats.technologies_loaded,
            "skipped_patterns": self.fingerprints.stats.skipped_patterns,
            "unsupported_kinds": self.fingerprints.stats.unsupported_kinds,
            "stopped": self._stopped,
            "truncated": self._truncated,
            "patterns_evaluated": self._patterns_evaluated,
        }
        self._result = (detections, stats)
        return detections, dict(stats)


def detect_external(page: webrules.Page, fingerprints: Fingerprints, *, page_url: str = "") -> tuple[webrules.Detection, ...]:
    """Evaluate one page through a one-shot external fingerprint session."""
    clock = time.monotonic
    session = ExternalSession(fingerprints, deadline=clock() + MAX_EVALUATION_SECONDS, clock=clock)
    session.add_page(page, page_url)
    detections, stats = session.finish()
    return DetectionResults(
        detections,
        DetectionStats(
            stats["technologies_loaded"], stats["skipped_patterns"], stats["unsupported_kinds"],
            int(stats["stopped"]), stats["patterns_evaluated"], stats["truncated"],
        ),
    )
