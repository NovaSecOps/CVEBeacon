"""Bounded reader for operator-supplied Wappalyzer-format fingerprints.

The package deliberately contains no upstream fingerprint collection. This
module only reads a collection supplied by the operator and evaluates its
passive patterns against data already present on a :class:`webrules.Page`.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from html.parser import HTMLParser
import json
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
MAX_FILE_BYTES = 256 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_TOTAL_FINGERPRINT_BYTES = 128 * 1024 * 1024
MAX_PATTERNS_PER_TECHNOLOGY = 512
MAX_TOTAL_PATTERNS = 100_000
MAX_STRING_LENGTH = 4096
MAX_REGEX_LENGTH = 2048
MAX_EVALUATION_SECONDS = 20.0
MAX_HTML_LENGTH = 4 * 1024 * 1024
MAX_TEXT_LENGTH = 1024 * 1024
MAX_RESOURCE_LENGTH = 4 * 1024 * 1024
MAX_ROBOTS_LENGTH = 1024 * 1024
MAX_PAGE_RESOURCES = 300
MAX_RESOURCE_BYTES_PER_PAGE = 96 * 1024 * 1024
MAX_DOM_NODES = 50_000
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
    "cats", "description", "website", "icon", "pricing", "saas", "cpe",
    "implies", "excludes", "requires", "requiresCategory", "groups",
})
_VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
})
_JS_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


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


@dataclass(frozen=True, slots=True)
class _LiteralIndex:
    transitions: tuple[Mapping[str, int], ...]
    failures: tuple[int, ...]
    outputs: tuple[tuple[int, ...], ...]
    anchor_regex: re.Pattern[str] | None
    literal_lengths: Mapping[int, int]

    def find(self, text: str, deadline: float) -> tuple[dict[int, set[int]], bool]:
        candidates: dict[int, set[int]] = {}
        positions_are_exact = text.isascii()
        folded = _fold_for_index(text)
        if self.anchor_regex is None:
            state = 0
            for position, char in enumerate(folded):
                while state and char not in self.transitions[state]:
                    state = self.failures[state]
                state = self.transitions[state].get(char, 0)
                if self.outputs[state]:
                    for pattern_id in self.outputs[state]:
                        found = candidates.setdefault(pattern_id, set())
                        if positions_are_exact and len(found) < MAX_LITERAL_HITS_PER_PATTERN:
                            found.add(position - self.literal_lengths[pattern_id] + 1)
                if position and position % 65_536 == 0 and time.monotonic() >= deadline:
                    return candidates, True
            return candidates, time.monotonic() >= deadline

        visits = 0
        saturated_states: set[int] = set()
        for anchor in self.anchor_regex.finditer(folded):
            state = 0
            position = anchor.start()
            while position < len(folded):
                char = folded[position]
                next_state = self.transitions[state].get(char)
                if next_state is None:
                    break
                state = next_state
                if self.outputs[state] and state not in saturated_states:
                    for pattern_id in self.outputs[state]:
                        positions = candidates.setdefault(pattern_id, set())
                        if positions_are_exact and len(positions) < MAX_LITERAL_HITS_PER_PATTERN:
                            positions.add(position - self.literal_lengths[pattern_id] + 1)
                    if self.outputs[state] and all(
                        len(candidates.get(pattern_id, ())) >= MAX_LITERAL_HITS_PER_PATTERN
                        for pattern_id in self.outputs[state]
                    ):
                        saturated_states.add(state)
                position += 1
            visits += 1
            if visits % 1024 == 0 and time.monotonic() >= deadline:
                return candidates, True
        return candidates, time.monotonic() >= deadline


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
        "application servers": "application-server", "application server": "application-server",
        "programming languages": "language", "languages": "language",
        "javascript libraries": "js-library", "javascript library": "js-library",
        "javascript frameworks": "framework", "web frameworks": "framework",
        "frameworks": "framework", "framework": "framework",
        "cdn": "edge", "content delivery network": "edge", "content delivery networks": "edge",
        "paas": "hosted-platform", "hosting": "hosted-platform", "hosted platforms": "hosted-platform",
        "dev tools": "ops-tool", "developer tools": "ops-tool", "analytics": "ops-tool",
        "operating systems": "application", "databases": "application",
        "ecommerce": "application", "email": "application", "widgets": "application",
    }
    result = aliases.get(normalized, normalized.replace(" ", "-"))
    return result if result in webrules.CATEGORIES else "application"


def _category_id(value: object) -> str:
    if type(value) is int:
        return str(value)
    if isinstance(value, str) and len(value) <= 32:
        return value
    raise ValueError("invalid category id")


def _object_pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_json_file(path: Path, limit: int) -> object:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise OverflowError("file too large")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs_no_duplicates)


def _category_map(root: Path, skipped: Counter[str]) -> dict[str, str]:
    path = root / "categories.json"
    try:
        if path.is_symlink() or not path.is_file():
            skipped["categories file unavailable"] += 1
            return {}
        if path.stat().st_size > MAX_METADATA_BYTES:
            skipped["categories file too large"] += 1
            return {}
        payload = _read_json_file(path, MAX_METADATA_BYTES)
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
            if not name or len(name) > MAX_STRING_LENGTH:
                raise ValueError("invalid category name")
            result[key] = _category_name(name)
        except ValueError:
            skipped["malformed category entry"] += 1
    return result


def _snapshot_directory(directory: Path):
    """Return the normalized layout and a bounded cache key."""
    try:
        requested = directory.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not requested.is_dir():
        return None
    child = requested / "technologies"
    if child.is_dir():
        root, technologies = requested, child
    else:
        technologies, root = requested, requested.parent
    try:
        entries = []
        truncated = False
        for position, entry in enumerate(technologies.iterdir()):
            if position >= MAX_DIRECTORY_ENTRIES:
                truncated = True
                break
            if entry.name.endswith(".json"):
                try:
                    info = entry.lstat()
                    stamp = (info.st_mtime_ns, info.st_size, getattr(info, "st_ino", 0), stat.S_ISLNK(info.st_mode))
                except OSError:
                    stamp = (-1, -1, 0, False)
                entries.append((entry.name, stamp))
        entries.sort(key=lambda item: item[0])
    except OSError:
        return None
    overflow_files = max(0, len(entries) - MAX_TECHNOLOGY_FILES)
    entries = entries[:MAX_TECHNOLOGY_FILES]
    if root == technologies:
        metadata_root = root.parent
    else:
        metadata_root = root
    metadata = []
    for filename in ("categories.json", "groups.json"):
        path = metadata_root / filename
        try:
            info = path.lstat()
            stamp = (info.st_mtime_ns, info.st_size, getattr(info, "st_ino", 0), stat.S_ISLNK(info.st_mode))
        except OSError:
            stamp = (-1, -1, 0, False)
        metadata.append((filename, stamp))
    key = (str(root), str(technologies), tuple(entries), tuple(metadata), overflow_files, truncated)
    return root, technologies, metadata_root, tuple(item[0] for item in entries), overflow_files, truncated, key


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
    """Reject common unbounded nested-backtracking forms before compilation."""
    # Repeated groups containing alternatives or an inner unbounded repeat are
    # conservatively skipped. Bounded repeats such as (?:\.\d+){0,3} remain
    # usable because their outer work is finite.
    stack: list[list[bool]] = []
    escaped = False
    in_class = False
    for index, char in enumerate(source):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "[":
            in_class = True
            continue
        if char == "]" and in_class:
            in_class = False
            continue
        if in_class:
            continue
        if char == "(":
            stack.append([False, 0])
            continue
        if char == "|" and stack:
            stack[-1][0] = True
            continue
        if char in "+*" and stack:
            stack[-1][1] += 1
        if char == ")" and stack:
            has_alternative, inner_repeats = stack.pop()
            if stack and inner_repeats:
                stack[-1][1] += inner_repeats
            tail = source[index + 1:index + 3]
            if tail.startswith(("+", "*")) and (has_alternative or inner_repeats):
                return True
    return False


def _compile_regex(source: str) -> tuple[re.Pattern[str], str]:
    if len(source) > MAX_REGEX_LENGTH:
        raise ValueError("regular expression too long")
    translated, flags = _parse_js_flags(source)
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
    anchors = sorted({pattern.literal[:3] for pattern in patterns
                      if pattern.kind == kind and pattern.literal and len(pattern.literal) >= 3
                      and pattern.regex is not None})
    anchor_regex = None
    if anchors and len(anchors) <= 50_000:
        anchor_regex = re.compile("(?=(?:" + "|".join(re.escape(anchor) for anchor in anchors) + "))")
    frozen = _LiteralIndex(
        tuple(MappingProxyType(dict(edges)) for edges in transitions),
        tuple(failures),
        tuple(tuple(sorted(set(items))) for items in outputs),
        anchor_regex,
        MappingProxyType(literal_lengths),
    )
    return frozen, tuple(no_literal)


def _string(value: object, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or len(value) > MAX_STRING_LENGTH or (not value and not allow_empty):
        raise ValueError("invalid bounded string")
    return value


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
    if "exists" in descriptor and descriptor["exists"] is not True:
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
            if not target.strip() or len(target) > 256:
                raise ValueError("invalid implied technology")
            implies.append(_Relationship(target.strip(), confidence))
        except ValueError:
            skipped["malformed implies relationship"] += 1
    for field, destination in (("excludes", excludes), ("requires", requires)):
        for raw in _relation_values(data.get(field, [])):
            try:
                target, _, _ = _split_pattern_tags(_string(raw, allow_empty=False))
                if not target.strip() or len(target) > 256:
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
            if not isinstance(raw, dict) or len(raw) > MAX_PATTERNS_PER_TECHNOLOGY:
                skipped["malformed DOM collection"] += 1
                continue
            for selector_source, descriptor in raw.items():
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


def _load_groups(root: Path, skipped: Counter[str]) -> dict[str, str]:
    path = root / "groups.json"
    try:
        if not path.exists():
            return {}
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES:
            skipped["malformed groups file"] += 1
            return {}
        payload = _read_json_file(path, MAX_METADATA_BYTES)
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
            if not name or len(name) > MAX_STRING_LENGTH:
                raise ValueError("invalid group name")
            result[key] = name
        except ValueError:
            skipped["malformed group entry"] += 1
    return result


def _load_uncached(root: Path, technologies_dir: Path, metadata_root: Path,
                   names: tuple[str, ...], overflow_files: int, truncated: bool) -> Fingerprints:
    skipped_technologies: Counter[str] = Counter()
    skipped_patterns: Counter[str] = Counter()
    unsupported_kinds: Counter[str] = Counter()
    categories = _category_map(metadata_root, skipped_technologies)
    groups = _load_groups(metadata_root, skipped_technologies)
    if overflow_files:
        skipped_technologies["technology file count limit"] += overflow_files
    if truncated:
        skipped_technologies["directory entry limit"] += 1
    technologies: list[_Technology] = []
    patterns: list[_Pattern] = []
    bytes_seen = 0
    for filename in names:
        path = technologies_dir / filename
        try:
            if path.is_symlink() or not path.is_file():
                skipped_technologies["technology file is not a regular file"] += 1
                continue
            file_size = path.stat().st_size
            if file_size > MAX_FILE_BYTES:
                skipped_technologies["technology file too large"] += 1
                continue
            if bytes_seen + file_size > MAX_TOTAL_FINGERPRINT_BYTES:
                skipped_technologies["total fingerprint byte limit"] += 1
                continue
            bytes_seen += file_size
            payload = _read_json_file(path, MAX_FILE_BYTES)
            if not isinstance(payload, dict) or len(payload) != 1:
                raise ValueError("technology file must contain one name")
            name, data = next(iter(payload.items()))
            if not isinstance(name, str) or not name or len(name) > 256 or not isinstance(data, dict):
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
                fields = split_cpe23(cpe)
                if (
                    len(fields) != 11 or fields[0] not in {"a", "o", "h"}
                    or fields[1] in {"", "*", "-"} or fields[2] in {"", "*", "-"}
                    or fields[3] != "*"
                ):
                    raise ValueError("malformed technology CPE")
                webrules._validated_cpe(cpe)
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
            if "saas" in data and type(data["saas"]) is not bool:
                raise ValueError("malformed technology metadata")
            if "groups" in data:
                if not isinstance(data["groups"], list) or len(data["groups"]) > 64:
                    raise ValueError("malformed technology groups")
                for group in data["groups"]:
                    _category_id(group)
            potential_patterns = sum(
                _pattern_size(data[kind]) for kind in SUPPORTED_KINDS if kind in data
            )
            if potential_patterns > MAX_TOTAL_PATTERNS - len(patterns):
                skipped_technologies["total pattern limit"] += 1
                continue
            local_patterns = _patterns_for_technology(data, len(patterns), skipped_patterns, unsupported_kinds)
            if len(patterns) + len(local_patterns) > MAX_TOTAL_PATTERNS:
                skipped_technologies["total pattern limit"] += 1
                continue
            vendor, product = _cpe_identity(cpe, name)
            category = next((categories[identifier] for identifier in category_ids if identifier in categories), "application")
            relationships = _parse_relationships(data, skipped_patterns)
            patterns.extend(local_patterns)
            technologies.append(_Technology(name, cpe, vendor, product, category, category_ids,
                                             tuple(pattern.index for pattern in local_patterns), *relationships))
        except OverflowError:
            skipped_technologies["technology file too large"] += 1
        except FileNotFoundError:
            skipped_technologies["technology file unavailable"] += 1
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
            skipped_technologies["malformed technology"] += 1
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
    return Fingerprints(root, tuple(technologies), pattern_tuple, MappingProxyType(dict(categories)),
                        MappingProxyType(dict(groups)), stats, MappingProxyType(index_map),
                        MappingProxyType(no_literal))


_LOAD_CACHE: dict[tuple, Fingerprints] = {}
_LOAD_CACHE_ORDER: deque[tuple] = deque()
_LOAD_CACHE_LIMIT = 8


def load_fingerprints(directory: Path) -> Fingerprints:
    """Load and cache a bounded operator-supplied fingerprint directory.

    ``directory`` may point at the published ``src`` directory or directly at
    its ``technologies`` child. Malformed files and patterns are counted and
    skipped so an optional collection cannot abort a scan.
    """
    snapshot = _snapshot_directory(Path(directory))
    if snapshot is None:
        stats = FingerprintStats(skipped_technologies=(("fingerprint directory unavailable", 1),))
        return Fingerprints(Path(directory), (), (), MappingProxyType({}), MappingProxyType({}), stats,
                            MappingProxyType({}), MappingProxyType({}))
    root, technologies_dir, metadata_root, names, overflow_files, truncated, key = snapshot
    cached = _LOAD_CACHE.get(key)
    if cached is not None:
        return cached
    loaded = _load_uncached(root, technologies_dir, metadata_root, names, overflow_files, truncated)
    _LOAD_CACHE[key] = loaded
    _LOAD_CACHE_ORDER.append(key)
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


class _PageParser(HTMLParser):
    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.nodes: list[_Node] = []
        self.stack: list[int] = []
        self.meta: list[tuple[str, str, str]] = []
        self.script_urls: list[tuple[str, str]] = []
        self.inline_scripts: list[tuple[str, str]] = []
        self.inline_styles: list[tuple[str, str]] = []
        self.visible_text: list[str] = []
        self.visible_text_length = 0
        self.capture_tag = ""
        self.capture_text: list[str] = []
        self.capture_length = 0
        self.html = html[:MAX_HTML_LENGTH]
        self.id_index: dict[str, list[int]] = {}
        self.class_index: dict[str, list[int]] = {}
        self.tag_index: dict[str, list[int]] = {}
        self.attribute_index: dict[str, list[int]] = {}
        self._node_text_cache: dict[int, str] = {}
        try:
            self.feed(self.html)
            self.close()
        except Exception:
            # HTMLParser is intentionally lenient; malformed pages simply
            # contribute the bounded prefix that was parsed successfully.
            pass

    def handle_starttag(self, tag: str, attrs):
        tag = tag.casefold()
        values = {str(name).casefold(): "" if value is None else str(value) for name, value in attrs}
        if tag == "meta" and len(self.meta) < MAX_META_TAGS:
            name = values.get("name") or values.get("property") or values.get("http-equiv")
            if name and "content" in values:
                self.meta.append((name, values["content"], f"meta:{name}"))
        if tag == "script" and len(self.script_urls) < MAX_SCRIPT_URLS and values.get("src"):
            self.script_urls.append((values["src"], values["src"]))
        if tag in {"script", "style"}:
            self.capture_tag = tag
            self.capture_text = []
            self.capture_length = 0
        if len(self.nodes) >= MAX_DOM_NODES:
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
        tag = tag.casefold()
        if self.capture_tag == tag:
            content = "".join(self.capture_text)
            if tag == "script":
                self.inline_scripts.append((content, "inline script"))
            elif tag == "style":
                self.inline_styles.append((content, "inline style"))
            self.capture_tag = ""
            self.capture_text = []
            self.capture_length = 0
        for position in range(len(self.stack) - 1, -1, -1):
            if self.nodes[self.stack[position]].tag == tag:
                del self.stack[position:]
                break

    def handle_data(self, data: str):
        if self.capture_tag and self.capture_length < MAX_RESOURCE_LENGTH:
            remaining = MAX_RESOURCE_LENGTH - self.capture_length
            chunk = data[:remaining]
            self.capture_text.append(chunk)
            self.capture_length += len(chunk)
        if self.stack:
            self.nodes[self.stack[-1]].text.append(data)
        if not self.capture_tag and self.visible_text_length < MAX_TEXT_LENGTH:
            chunk = data[:MAX_TEXT_LENGTH - self.visible_text_length]
            self.visible_text.append(chunk)
            self.visible_text_length += len(chunk)

    def node_text(self, index: int) -> str:
        cached = self._node_text_cache.get(index)
        if cached is not None:
            return cached
        output = []
        pending = [index]
        total = 0
        while pending and total < MAX_TEXT_LENGTH:
            current = pending.pop()
            node = self.nodes[current]
            for part in node.text:
                chunk = part[:MAX_TEXT_LENGTH - total]
                output.append(chunk)
                total += len(chunk)
                if total >= MAX_TEXT_LENGTH:
                    break
            pending.extend(reversed(node.children))
        value = "".join(output)
        self._node_text_cache[index] = value
        return value


@dataclass(frozen=True, slots=True)
class _Source:
    value: str
    source: str
    selector: str = ""


def _bounded_text(value: object, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _page_sources(page: webrules.Page, page_url: str):
    html = _bounded_text(getattr(page, "html", ""), MAX_HTML_LENGTH)
    parser = _PageParser(html)
    sources: dict[str, list[_Source]] = {kind: [] for kind in SUPPORTED_KINDS}
    for name, values in getattr(page, "headers", {}).items():
        if not isinstance(name, str):
            continue
        for value in tuple(values)[:64]:
            sources["headers"].append(_Source(_bounded_text(value, 16_384), f"header:{name}", name.casefold()))
    for name, content, source in parser.meta:
        sources["meta"].append(_Source(_bounded_text(content, 16_384), source, name))
    cookie_names = tuple(getattr(page, "cookie_names", ()))[:4096]
    for cookie in cookie_names:
        if isinstance(cookie, str):
            sources["cookies"].append(_Source(cookie[:256], f"cookie:{cookie[:128]}"))
    for url, source in parser.script_urls:
        sources["scriptSrc"].append(_Source(url[:4096], source[:512]))
    resources = tuple(getattr(page, "resources", ()))[:MAX_PAGE_RESOURCES]
    resource_budget = MAX_RESOURCE_BYTES_PER_PAGE
    for resource in resources:
        kind = getattr(resource, "kind", "")
        url = _bounded_text(getattr(resource, "url", ""), 4096)
        resource_text = getattr(resource, "text", "")
        per_resource_limit = MAX_ROBOTS_LENGTH if kind == "robots" else MAX_RESOURCE_LENGTH
        available = min(per_resource_limit, resource_budget)
        bounded_resource = _bounded_text(resource_text, available)
        resource_budget -= len(bounded_resource)
        if kind == "script":
            if url:
                sources["scriptSrc"].append(_Source(url, url))
            sources["scripts"].append(_Source(bounded_resource, url or "script resource"))
        elif kind in {"style", "css"}:
            sources["css"].append(_Source(bounded_resource, url or "style resource"))
        elif kind == "robots":
            sources["robots"].append(_Source(bounded_resource, url or "robots resource"))
    sources["scripts"].extend(_Source(value, source) for value, source in parser.inline_scripts)
    sources["css"].extend(_Source(value, source) for value, source in parser.inline_styles)
    sources["html"].append(_Source(parser.html, "page HTML"))
    sources["text"].append(_Source("".join(parser.visible_text)[:MAX_TEXT_LENGTH], "page text"))
    sources["url"].append(_Source(_bounded_text(page_url, 4096), "page URL"))
    return sources, parser


def _selector_candidates(selector: _Selector, parser: _PageParser) -> tuple[int, ...]:
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
        return tuple(range(len(parser.nodes)))
    return tuple(candidates)


def _selector_matches(selector: _Selector, node: _Node) -> bool:
    if selector.tag and node.tag != selector.tag:
        return False
    if selector.identifier and node.attributes.get("id") != selector.identifier:
        return False
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


def _expand_version_reference(template: str, match: re.Match[str]) -> tuple[str, bool]:
    conditional = re.fullmatch(r"\\(\d+|[A-Za-z_$][\w$]*)\?([^:]*):(.*)", template, re.DOTALL)
    literal_value = False
    if conditional:
        group_key = conditional.group(1)
        try:
            group_value = match.group(int(group_key)) if group_key.isdigit() else match.group(group_key)
        except (IndexError, KeyError):
            group_value = None
        template = conditional.group(2) if group_value else conditional.group(3)
        literal_value = bool(webrules.normalize_version(template)) or not bool(
            re.search(r"[\\.^$*+?{}\[\]()|]", template)
        )
    pure_numeric = re.fullmatch(r"\\(\d+)", template)
    if pure_numeric:
        try:
            return match.group(int(pure_numeric.group(1))) or "", True
        except IndexError:
            return "", True
    pure_named = re.fullmatch(r"\\k<([A-Za-z_$][\w$]*)>", template)
    if pure_named:
        try:
            return match.group(pure_named.group(1)) or "", True
        except (IndexError, KeyError):
            return "", True

    def numeric_reference(reference):
        try:
            value = match.group(int(reference.group(1))) or ""
        except IndexError:
            value = ""
        return re.escape(value)

    def named_reference(reference):
        try:
            value = match.group(reference.group(1)) or ""
        except (IndexError, KeyError):
            value = ""
        return re.escape(value)

    template = re.sub(r"\\(\d+)", numeric_reference, template)
    template = re.sub(r"\\k<([A-Za-z_$][\w$]*)>", named_reference, template)
    return template, literal_value


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
            candidate = version_match.group(1) if version_match.lastindex else version_match.group(0)
        return webrules.normalize_version(candidate)
    except (re.error, ValueError, IndexError):
        return ""


def _pattern_evidence(pattern: _Pattern, value: str, match: re.Match[str], source: str):
    version = _version_from(pattern, value, match)
    start = match.start()
    excerpt = value[max(0, start - 40):start + EVIDENCE_EXCERPT_LENGTH]
    return version, (pattern.kind, source[:512], excerpt[:EVIDENCE_EXCERPT_LENGTH])


def _dom_matches(pattern: _Pattern, parser: _PageParser, deadline: float):
    if pattern.selector is None:
        return (), False
    matches = []
    for count, node_index in enumerate(_selector_candidates(pattern.selector, parser)):
        if count and count % 1024 == 0 and time.monotonic() >= deadline:
            return tuple(matches), True
        node = parser.nodes[node_index]
        if not _selector_matches(pattern.selector, node):
            continue
        matched_tests: list[tuple[_DOMTest, str, re.Match[str], str]] = []
        accepted = True
        for name, alternatives in pattern.dom_attributes:
            value = node.attributes.get(name)
            if value is None:
                accepted = False
                break
            found = next(((test, test.regex.search(value)) for test in alternatives if test.regex.search(value)), None)
            if found is None:
                accepted = False
                break
            matched_tests.append((found[0], value, found[1], f"dom attribute:{name}"))
        if not accepted:
            continue
        if pattern.dom_text:
            value = parser.node_text(node_index)
            found = next(((test, test.regex.search(value)) for test in pattern.dom_text if test.regex.search(value)), None)
            if found is None:
                continue
            matched_tests.append((found[0], value, found[1], "dom text"))
        matches.append((matched_tests, pattern.source))
    return tuple(matches), False


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
        "cpe": technology.cpe,
        "confidence": confidence,
        "versions": tuple(sorted(record.versions)),
        "evidence_types": tuple(sorted(record.evidence_types)),
        "name": technology.name,
        "ecosystem": "",
        "package": "",
        "implied_by": tuple(sorted(record.implied_by)),
    }
    if "evidence" in detection_fields:
        kwargs["evidence"] = evidence_values
    return webrules.Detection(**{key: value for key, value in kwargs.items() if key in detection_fields})


def _merge_direct_record(records: dict[str, _DetectionRecord], technology: _Technology,
                         confidence: int, version: str, evidence):
    key = technology.name.casefold()
    record = records.get(key)
    if record is None:
        record = _DetectionRecord(technology, confidence, set(), set(), [], set(), True)
        records[key] = record
    record.confidence = max(record.confidence, confidence)
    if version:
        record.versions.add(version)
    record.evidence_types.add(evidence[0])
    if len(record.evidence) < MAX_EVIDENCE_PER_DETECTION:
        record.evidence.append(evidence)


def _candidate_patterns(fingerprints: Fingerprints, kind: str, source: _Source,
                        deadline: float) -> tuple[tuple[int, ...], bool, Mapping[int, set[int]]]:
    index = fingerprints.literal_indexes.get(kind)
    no_literal = fingerprints.no_literal.get(kind, ())
    if index is None:
        return no_literal, time.monotonic() >= deadline, MappingProxyType({})
    if len(source.value) <= 16_384:
        folded = _fold_for_index(source.value)
        found = []
        no_literal_set = set(no_literal)
        for pattern in fingerprints.patterns:
            if pattern.kind == kind and pattern.index in no_literal_set:
                found.append(pattern.index)
            elif pattern.kind == kind and pattern.literal and pattern.literal in folded:
                found.append(pattern.index)
        return tuple(found), time.monotonic() >= deadline, MappingProxyType({})
    positions, expired = index.find(source.value, deadline)
    candidates = set(positions)
    candidates.update(no_literal)
    return tuple(candidates), expired, MappingProxyType(positions)


def _category_ids_available(records: Mapping[str, _DetectionRecord]) -> set[str]:
    return {identifier for record in records.values() for identifier in record.technology.category_ids}


def _resolve_relationships(fingerprints: Fingerprints, direct: dict[str, _DetectionRecord],
                           deadline: float):
    records = dict(direct)
    by_name = {technology.name.casefold(): technology for technology in fingerprints.technologies}
    pending = [(record.technology, record.confidence, record.technology.name, 0)
               for record in direct.values()]
    best_implied: dict[str, int] = {}
    expansions = 0
    while pending and expansions < min(10_000, len(fingerprints.technologies) * 8 + 1):
        if time.monotonic() >= deadline:
            return records, True
        source, source_confidence, origin, depth = pending.pop(0)
        if depth >= 32:
            continue
        for relation in source.implies:
            target_key = relation.target.casefold()
            technology = by_name.get(target_key)
            if technology is None or target_key in direct:
                continue
            confidence = min(source_confidence, relation.confidence)
            record = records.get(target_key)
            if record is None:
                record = _DetectionRecord(technology, confidence, set(), {"implied"}, [], {origin}, False)
                records[target_key] = record
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

    active_names = set(records)
    excluded = set()
    for key, record in records.items():
        excluded.update(target for target in record.technology.excludes if target in active_names)
    for key in excluded:
        records.pop(key, None)
    changed = True
    while changed:
        changed = False
        active_names = set(records)
        categories = _category_ids_available(records)
        for key, record in tuple(records.items()):
            if any(required not in active_names for required in record.technology.requires) or any(
                required not in categories for required in record.technology.requires_categories
            ):
                records.pop(key, None)
                changed = True
    return records, False


def detect_external(page: webrules.Page, fingerprints: Fingerprints, *, page_url: str = "") -> tuple[webrules.Detection, ...]:
    """Evaluate passive fingerprint kinds on a fetched page, within 20 seconds."""
    started = time.monotonic()
    deadline = started + MAX_EVALUATION_SECONDS
    sources, parser = _page_sources(page, page_url)
    direct: dict[str, _DetectionRecord] = {}
    by_index = {pattern.index: pattern for pattern in fingerprints.patterns}
    technology_by_index = {}
    for technology in fingerprints.technologies:
        for pattern_id in technology.pattern_ids:
            technology_by_index[pattern_id] = technology
    patterns_evaluated = 0
    stopped = False

    for kind in ("headers", "cookies", "meta", "scriptSrc", "scripts", "css", "html", "text", "url", "robots"):
        kind_sources = sources.get(kind, ())
        for source in kind_sources:
            candidate_ids, expired, literal_positions = _candidate_patterns(fingerprints, kind, source, deadline)
            if expired:
                stopped = True
                break
            for pattern_id in candidate_ids:
                if time.monotonic() >= deadline:
                    stopped = True
                    break
                pattern = by_index.get(pattern_id)
                technology = technology_by_index.get(pattern_id)
                if pattern is None or technology is None or pattern.regex is None:
                    continue
                if kind in {"headers", "meta"}:
                    if pattern.selector_regex is None or not pattern.selector_regex.fullmatch(source.selector):
                        continue
                patterns_evaluated += 1
                positions = literal_positions.get(pattern_id, ())
                if positions and pattern.prefix and pattern.literal.startswith(pattern.prefix):
                    matches = tuple(
                        match for position in sorted(positions)
                        if (match := pattern.regex.match(source.value, position)) is not None
                    )
                else:
                    match = pattern.regex.search(source.value)
                    matches = (match,) if match else ()
                if not matches:
                    continue
                for match in matches:
                    version, evidence = _pattern_evidence(pattern, source.value, match, source.source)
                    _merge_direct_record(direct, technology, pattern.confidence, version, evidence)
            if stopped:
                break
        if stopped:
            break

    if not stopped:
        for technology in fingerprints.technologies:
            for pattern_id in technology.pattern_ids:
                pattern = by_index[pattern_id]
                if pattern.kind != "dom":
                    continue
                if time.monotonic() >= deadline:
                    stopped = True
                    break
                patterns_evaluated += 1
                dom_matches, expired = _dom_matches(pattern, parser, deadline)
                if expired:
                    stopped = True
                    break
                if not dom_matches:
                    continue
                confidence = 100
                versions = set()
                evidence = []
                for tests, selector in dom_matches:
                    for test, value, match, source_name in tests:
                        confidence = min(confidence, test.confidence)
                        version = _version_from(test, value, match)
                        if version:
                            versions.add(version)
                        if len(evidence) < MAX_EVIDENCE_PER_DETECTION:
                            start = match.start()
                            excerpt = value[max(0, start - 40):start + EVIDENCE_EXCERPT_LENGTH]
                            evidence.append(("dom", f"{source_name}:{selector}"[:512], excerpt[:EVIDENCE_EXCERPT_LENGTH]))
                for version in versions or {""}:
                    _merge_direct_record(direct, technology, confidence, version, ("dom", f"dom:{pattern.source}", pattern.source))
                # Preserve bounded condition-specific evidence and the selector.
                record = direct[technology.name.casefold()]
                for item in evidence:
                    if len(record.evidence) < MAX_EVIDENCE_PER_DETECTION:
                        record.evidence.append(item)
            if stopped:
                break

    resolved, relation_timed_out = _resolve_relationships(fingerprints, direct, deadline)
    stopped = stopped or relation_timed_out
    detections = tuple(
        _make_detection(record)
        for _, record in sorted(resolved.items(), key=lambda item: item[0])
    )
    stats = DetectionStats(
        fingerprints.stats.technologies_loaded,
        fingerprints.stats.skipped_patterns,
        fingerprints.stats.unsupported_kinds,
        1 if stopped else 0,
        patterns_evaluated,
    )
    return DetectionResults(detections, stats)
