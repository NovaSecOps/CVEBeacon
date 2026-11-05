"""Render on-demand CVE statements from text or Word templates.

The statement is built from the same stored view that alert messages use.  It
never queries a source: the CVE must already exist in the watch database.
"""

from __future__ import annotations

import io
import os
import re
import stat
import struct
import tempfile
import zipfile
import zlib
from bisect import bisect_right
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from string import Template
from typing import Any, Mapping, Sequence
from urllib.parse import quote
from xml.parsers import expat
from xml.sax.saxutils import escape

from ..clients import ClientImpact, format_client_names
from ..errors import CVEBeaconError
from .messages import CVE_URL, EUVD_URL, NVD_URL, PROVIDER_ORDER
from .records import CVSS_PROVIDERS, CVSSEntry, ReportedMark, WatchView
from .rules import highest_cvss
from .store import WatchStore

MISSING = "not available"
NOT_REPORTED = "not reported"
MAX_TEMPLATE_BYTES = 20 * 1024 * 1024
MAX_MEMBER_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_RENDERED_BYTES = 50 * 1024 * 1024
MAX_ZIP_MEMBERS = 10_000
MAX_XML_DEPTH = 256
MAX_XML_SPANS = 100_000
MAX_XML_BYTES = 8 * 1024 * 1024
MAX_PACKAGE_XML_BYTES = 32 * 1024 * 1024
MAX_ELEMENT_ATTRIBUTES = 8192
MAX_ELEMENT_ATTRIBUTE_BYTES = 256 * 1024
MAX_PART_ATTRIBUTES = 50_000
MAX_PART_ATTRIBUTE_BYTES = 1024 * 1024
MAX_PACKAGE_ATTRIBUTES = 100_000
MAX_PACKAGE_ATTRIBUTE_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_XML_SPANS = 200_000
MAX_NAMESPACE_URI_BYTES = 256
MAX_PART_EXPANDED_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_EXPANDED_BYTES = 32 * 1024 * 1024
MAX_UNKNOWN_NAMES = 128
MAX_UNKNOWN_NAME_BYTES = 16 * 1024
_NS_SEPARATOR = "\x1f"
_ZIP_ERRORS = (
    zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError,
    NotImplementedError, RuntimeError, EOFError, zlib.error, struct.error,
)
WORDPROCESSING_NS = (
    "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
)

FIELD_NAMES = (
    "cve_id",
    "title",
    "description",
    "published",
    "published_date",
    "first_seen",
    "first_seen_date",
    "last_modified",
    "last_modified_date",
    "status",
    "cvss_max",
    "cvss_max_provider",
    "cvss_max_version",
    "cvss_max_vector",
    "cvss_all",
    "severity",
    "epss",
    "epss_percentile",
    "epss_date",
    "kev",
    "kev_date_added",
    "kev_due_date",
    "kev_required_action",
    "eu_kev",
    "ssvc_exploitation",
    "cwes",
    "affected_products",
    "affected_clients",
    "references",
    "nvd_url",
    "cve_org_url",
    "euvd_id",
    "euvd_url",
    "generated_at",
    "reported",
    "reported_by",
    "reported_at",
)

_TEXT_SUFFIXES = (".md", ".txt")
_DOCX_SUFFIX = ".docx"
_PLACEHOLDER = Template("").pattern
_PART_NAME = re.compile(
    r"^word/(?:document|header[0-9]+|footer[0-9]+)\.xml$"
)
_INVALID_XML = re.compile(
    "[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]"
)


def _text(value: Any) -> str:
    return MISSING if value is None or str(value).strip() == "" else str(value)


def _generated_at(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _utc_date(value: str | None) -> str:
    if not value:
        return MISSING
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).date().isoformat()
    except (ValueError, OverflowError):
        return MISSING


def _cna_name(entry: CVSSEntry, view: WatchView) -> str:
    source = " ".join((entry.source or view.source_identifier or "").split())
    if "@" in source:
        source = source.rsplit("@", 1)[-1]
    return source[:60] or "CNA"


def _provider_label(provider: str, entry: CVSSEntry, view: WatchView) -> str:
    if provider == "cna":
        return f"CNA: {_cna_name(entry, view)}"
    if provider == "nvd":
        return "NVD"
    if provider == "cisa-adp":
        return "CISA-ADP"
    if provider == "euvd":
        return "EUVD"
    return "Other"


def _severity(score: float | None) -> str | None:
    if score is None or score < 0.1:
        return None
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def _products(view: WatchView) -> str:
    if view.products and len(view.vendors) == 1:
        return "\n".join(f"{view.vendors[0]} {product}" for product in view.products)
    if view.products:
        return "\n".join(view.products)
    return "\n".join(view.vendors)


def _reported_marks(mark: ReportedMark | None) -> tuple[str, str, str]:
    """Render the current stored reported-to-clients mark."""
    if mark is None:
        return NOT_REPORTED, NOT_REPORTED, NOT_REPORTED
    return "yes", mark.by, mark.at


def build_fields(
    view: WatchView, *, first_seen: str | None, generated_at: datetime,
    reported_mark: ReportedMark | None = None,
    client_impacts: Sequence[ClientImpact] = (),
) -> dict[str, str]:
    """Derive every statement field from one stored watch view."""
    highest = highest_cvss(view, CVSS_PROVIDERS)
    provider = highest.provider if highest is not None else None
    score = highest.score if highest is not None else None
    cvss_lines = [
        f"{entry.score:g} v{entry.version} "
        f"({_provider_label(name, entry, view)})"
        for name in PROVIDER_ORDER
        if (entry := highest_cvss(view, (name,))) is not None
    ]
    kev_added = view.cisa_kev_added or view.eu_kev_added
    reported, reported_by, reported_at = _reported_marks(reported_mark)
    cve_id = quote(str(view.cve_id), safe="-_.")
    euvd_id = quote(str(view.euvd_id), safe="-_.") if view.euvd_id else None
    values = {
        "cve_id": view.cve_id,
        "title": MISSING,
        "description": _text(view.description),
        "published": _text(view.published),
        "published_date": _utc_date(view.published),
        "first_seen": _text(first_seen),
        "first_seen_date": _utc_date(first_seen),
        "last_modified": _text(view.last_modified),
        "last_modified_date": _utc_date(view.last_modified),
        "status": view.status,
        "cvss_max": f"{score:g}" if score is not None else MISSING,
        "cvss_max_provider": (
            _provider_label(provider, highest, view) if highest is not None else MISSING
        ),
        "cvss_max_version": _text(highest.version) if highest is not None else MISSING,
        "cvss_max_vector": _text(highest.vector) if highest is not None else MISSING,
        "cvss_all": "\n".join(cvss_lines) or MISSING,
        "severity": _severity(score) or MISSING,
        "epss": f"{view.epss:.5f}" if view.epss is not None else MISSING,
        "epss_percentile": (
            f"{view.epss_percentile:.5f}"
            if view.epss_percentile is not None
            else MISSING
        ),
        "epss_date": _text(view.epss_date),
        "kev": "yes" if kev_added is not None else "no",
        "kev_date_added": _text(kev_added),
        "kev_due_date": _text(view.cisa_kev_due),
        "kev_required_action": _text(view.cisa_required_action),
        "eu_kev": "yes" if view.eu_kev_added is not None else "no",
        "ssvc_exploitation": _text(view.ssvc_exploitation),
        "cwes": ", ".join(view.cwes) or MISSING,
        "affected_products": _products(view) or MISSING,
        "affected_clients": format_client_names(
            client_impacts, language="en"
        )
        or MISSING,
        "references": "\n".join(reference.url for reference in view.references)
        or MISSING,
        "nvd_url": NVD_URL.format(cve_id=cve_id),
        "cve_org_url": CVE_URL.format(cve_id=cve_id),
        "euvd_id": _text(view.euvd_id),
        "euvd_url": EUVD_URL.format(euvd_id=euvd_id) if euvd_id else MISSING,
        "generated_at": _generated_at(generated_at),
        "reported": reported,
        "reported_by": reported_by,
        "reported_at": reported_at,
    }
    return {name: values[name] for name in FIELD_NAMES}


def _values(fields: Mapping[str, str]) -> dict[str, str]:
    missing = [name for name in FIELD_NAMES if name not in fields]
    if missing:
        raise CVEBeaconError(
            "statement fields are incomplete: " + ", ".join(missing)
        )
    return {name: str(fields[name]) for name in FIELD_NAMES}


def _rendered_too_large() -> CVEBeaconError:
    return CVEBeaconError(
        f"rendered statement is larger than {MAX_RENDERED_BYTES} bytes"
    )


def _invalid_placeholder() -> CVEBeaconError:
    return CVEBeaconError(
        "invalid statement placeholder syntax: '$' must be followed by a name, "
        "a braced name, or another '$' (write '$$' for a literal dollar sign)"
    )


def _unknown_error(names: set[str]) -> CVEBeaconError:
    listed = ", ".join("${" + name + "}" for name in sorted(names))
    return CVEBeaconError(f"unknown statement placeholder(s): {listed}")


def _check_text(text: str, unknown: set[str], budget: _XMLBudget | None = None) -> None:
    budget = budget if budget is not None else _XMLBudget()
    for count, match in enumerate(_PLACEHOLDER.finditer(text), 1):
        budget.placeholders += 1
        if count > MAX_XML_SPANS or budget.placeholders > MAX_XML_SPANS:
            raise _xml_limit("placeholder")
        if match.group("invalid") is not None:
            raise _invalid_placeholder()
        group = "named" if match.start("named") >= 0 else "braced"
        start, end = match.span(group)
        if start < 0:
            continue
        # Template identifiers are ASCII. Check their length before copying.
        if end - start > MAX_UNKNOWN_NAME_BYTES:
            raise _xml_limit("unknown placeholder name byte")
        name = text[start:end]
        if name not in FIELD_NAMES and name not in unknown:
            if (len(unknown) >= MAX_UNKNOWN_NAMES
                or budget.unknown_bytes + len(name) > MAX_UNKNOWN_NAME_BYTES):
                raise _xml_limit("unknown placeholder diagnostic")
            budget.unknown_bytes += len(name)
            unknown.add(name)


def check_template_text(text: str) -> None:
    """Reject unknown or malformed placeholders in a complete text template."""
    unknown: set[str] = set()
    _check_text(text, unknown)
    if unknown:
        raise _unknown_error(unknown)


def render_text(template: str, fields: Mapping[str, str]) -> str:
    """Fill a Markdown or plain-text statement template."""
    check_template_text(template)
    values = _values(fields)
    pieces: list[str] = []
    total = 0
    cursor = 0

    def add(value: str) -> None:
        nonlocal total
        total += len(value.encode("utf-8"))
        if total > MAX_RENDERED_BYTES:
            raise _rendered_too_large()
        pieces.append(value)

    for match in _PLACEHOLDER.finditer(template):
        add(template[cursor : match.start()])
        if match.group("escaped") is not None:
            add("$")
        else:
            name = match.group("named") or match.group("braced")
            add(values[str(name)])
        cursor = match.end()
    add(template[cursor:])
    return "".join(pieces)


def _xml_encoding(data: bytes) -> str:
    if data.startswith((b"\xff\xfe\0\0", b"\0\0\xfe\xff", b"\0\0\0<", b"<\0\0\0")):
        raise CVEBeaconError("statement template XML encoding must be UTF-8 or UTF-16")
    if data.startswith((b"\xff\xfe", b"<\0")):
        return "utf-16-le"
    if data.startswith((b"\xfe\xff", b"\0<")):
        return "utf-16-be"
    return "utf-8"


def _tag_end(data: bytes, start: int, encoding: str) -> int:
    """Find the end of an already validated tag without interpreting attributes."""
    width = 1 if encoding == "utf-8" else 2
    quote_char = b""
    quotes = ("'".encode(encoding), '"'.encode(encoding))
    close = ">".encode(encoding)
    for index in range(start, len(data), width):
        char = data[index:index + width]
        if quote_char:
            if char == quote_char:
                quote_char = b""
        elif char in quotes:
            quote_char = char
        elif char == close:
            return index + width
    raise CVEBeaconError("statement template XML is malformed")


@dataclass(slots=True)
class _XMLBudget:
    records: int = 0
    attributes: int = 0
    attribute_bytes: int = 0
    xml_bytes: int = 0
    expanded_bytes: int = 0
    placeholders: int = 0
    unknown_bytes: int = 0


def _xml_limit(resource: str) -> CVEBeaconError:
    return CVEBeaconError(f"statement template {resource} limit exceeded")


def _utf8_width(char: str) -> int:
    value = ord(char)
    return 1 if value < 128 else 2 if value < 2048 else 3 if value < 65536 else 4


def _preflight_xml(data: bytes, encoding: str, budget: _XMLBudget, name: str) -> None:
    """Conservatively budget lexical markup before Expat allocates its tables.

    This is only an allocation guard. Expat still owns syntax, entities and
    namespace validation. A whole-part upper bound avoids another scope parser.
    """
    if len(data) > MAX_XML_BYTES or budget.xml_bytes + len(data) > MAX_PACKAGE_XML_BYTES:
        raise _xml_limit("input byte")
    budget.xml_bytes += len(data)
    try:
        xml = data.decode(encoding)
    except UnicodeError as exc:
        raise CVEBeaconError("statement template XML encoding must be UTF-8 or UTF-16") from exc
    elements = attributes = attribute_bytes = name_bytes = names = 0
    # Include the implicit xml namespace. Every name is conservatively charged
    # against the longest namespace spelling, even when it is unqualified.
    longest_uri = 36
    def check_names() -> None:
        expanded = name_bytes + names * (longest_uri + 2)
        if (expanded > MAX_PART_EXPANDED_BYTES
            or budget.expanded_bytes + expanded > MAX_PACKAGE_EXPANDED_BYTES):
            raise _xml_limit("expanded name byte")

    index = 0
    while (start := xml.find("<", index)) >= 0:
        for opening, closing in (("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>")):
            if xml.startswith(opening, start):
                end = xml.find(closing, start + len(opening))
                index = len(xml) if end < 0 else end + len(closing)
                break
        else:
            if xml.startswith("<!", start):
                raise CVEBeaconError(f"statement template part {name} declares a DTD or XML entities")
            if xml.startswith("</", start):
                end = xml.find(">", start)
                index = len(xml) if end < 0 else end + 1
                continue
            index = start + 1
            elements += 1
            names += 2  # start and end callbacks
            check_names()
            while index < len(xml) and xml[index] not in " \t\r\n" and xml[index] not in "/>":
                name_bytes += _utf8_width(xml[index]) * 2
                check_names()
                index += 1
            element_attributes = element_bytes = uri_bytes = 0
            quote_char = ""
            namespace_value = False
            token_start = token_end = index
            while index < len(xml):
                char = xml[index]
                if not quote_char and char == ">":
                    index += 1
                    break
                width = _utf8_width(char)
                element_bytes += width if encoding == "utf-8" else 2 if ord(char) <= 65535 else 4
                if (element_bytes > MAX_ELEMENT_ATTRIBUTE_BYTES
                    or attribute_bytes + element_bytes > MAX_PART_ATTRIBUTE_BYTES
                    or budget.attribute_bytes + attribute_bytes + element_bytes > MAX_PACKAGE_ATTRIBUTE_BYTES):
                    raise _xml_limit("attribute byte")
                if quote_char:
                    if char == quote_char:
                        quote_char = ""
                    elif namespace_value:
                        uri_bytes += width
                        if uri_bytes > MAX_NAMESPACE_URI_BYTES:
                            raise _xml_limit("namespace URI byte")
                        if uri_bytes > longest_uri:
                            longest_uri = uri_bytes
                            check_names()
                elif char in "\"'":
                    quote_char = char
                    uri_bytes = 0
                    token_start = token_end = index + 1
                elif char == "=":
                    element_attributes += 1
                    attr_name = xml[token_start:token_end]
                    namespace_value = attr_name == "xmlns" or attr_name.startswith("xmlns:")
                    names += 1
                    name_bytes += sum(_utf8_width(c) for c in attr_name)
                    token_start = token_end = index + 1
                    check_names()
                    if (element_attributes > MAX_ELEMENT_ATTRIBUTES
                        or attributes + element_attributes > MAX_PART_ATTRIBUTES
                        or budget.attributes + attributes + element_attributes > MAX_PACKAGE_ATTRIBUTES):
                        raise _xml_limit("attribute count")
                elif char not in " \t\r\n":
                    if token_end != index:
                        token_start = index
                    token_end = index + 1
                index += 1
            attributes += element_attributes
            attribute_bytes += element_bytes
            records = elements + attributes
            if records > MAX_XML_SPANS or budget.records + records > MAX_PACKAGE_XML_SPANS:
                raise _xml_limit("span")
            check_names()
            continue
        continue
    budget.records += elements + attributes
    budget.attributes += attributes
    budget.attribute_bytes += attribute_bytes
    budget.expanded_bytes += name_bytes + names * (longest_uri + 2)


@dataclass(slots=True)
class _TextSpan:
    start: int
    end: int
    opening: str
    closing: str
    line_break: str
    text: str


_Scan = tuple[list[_TextSpan], list[list[int]], str]


def _parse_xml(
    data: bytes, name: str, *, collect: bool = False, budget: _XMLBudget | None = None
) -> _Scan:
    """Validate XML and optionally retain text byte spans by innermost paragraph."""
    encoding = _xml_encoding(data)
    _preflight_xml(data, encoding, budget if budget is not None else _XMLBudget(), name)
    parser = expat.ParserCreate(namespace_separator=_NS_SEPARATOR, intern=None)
    parser.namespace_prefixes = True
    parser.buffer_text = True
    parser.buffer_size = 64 * 1024
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    spans: list[_TextSpan] = []
    groups: list[list[int]] = []
    paragraphs: list[int] = []
    depth = 0
    declarations: set[str] = set()
    active: _TextSpan | None = None
    text = io.StringIO()

    def reject(*args):
        raise CVEBeaconError(
            f"statement template part {name} declares a DTD or XML entities"
        )

    def declaration(version, declared, standalone):
        if declared and declared.lower() not in ("utf-8", "utf-16", "utf-16le", "utf-16be"):
            raise CVEBeaconError("statement template XML encoding must be UTF-8 or UTF-16")

    def namespace(prefix, uri):
        declarations.add(prefix or "")

    def start(tag, attrs):
        nonlocal depth, active, text
        depth += 1
        if depth > MAX_XML_DEPTH:
            raise _xml_limit("depth")
        if not collect:
            declarations.clear()
            return
        if active is not None:
            raise CVEBeaconError("statement template XML is malformed: nested text element")
        parts = tag.split(_NS_SEPARATOR)
        local = parts[1] if len(parts) > 1 and parts[0] == WORDPROCESSING_NS else ""
        if local == "p":
            paragraphs.append(len(groups))
            groups.append([])
        elif local == "t":
            if not paragraphs:
                raise CVEBeaconError("statement template XML is malformed: text outside a paragraph")
            offset = parser.CurrentByteIndex
            end = _tag_end(data, offset, encoding)
            opening = data[offset:end].decode(encoding)
            if not opening.endswith("/>"):
                prefix = parts[2] if len(parts) == 3 else ""
                qname = f"{prefix}:t" if prefix else "t"
                # A declaration on t ceases to apply to its generated sibling br.
                binding = (f' xmlns:{prefix}="{WORDPROCESSING_NS}"' if prefix
                           else f' xmlns="{WORDPROCESSING_NS}"') if prefix in declarations else ""
                br = f'<{prefix + ":" if prefix else ""}br{binding}/>'
                active = _TextSpan(offset, end, opening, f"</{qname}>", br, "")
                text = io.StringIO()
                groups[paragraphs[-1]].append(len(spans))
                spans.append(active)
                space = _NS_SEPARATOR.join(("http://www.w3.org/XML/1998/namespace", "space", "xml"))
                if space not in attrs:
                    active.opening = opening[:-1] + ' xml:space="preserve">'
        declarations.clear()

    def end(tag):
        nonlocal depth, active
        if active is not None:
            active.end = _tag_end(data, parser.CurrentByteIndex, encoding)
            active.text = text.getvalue()
            if not active.text:
                spans.pop()
                groups[paragraphs[-1]].pop()
            active = None
        if (collect and tag.startswith(WORDPROCESSING_NS + _NS_SEPARATOR + "p")
            and tag.split(_NS_SEPARATOR)[1] == "p"):
            paragraphs.pop()
        depth -= 1

    def characters(value):
        if active is not None:
            text.write(value)

    parser.XmlDeclHandler = declaration
    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.StartNamespaceDeclHandler = namespace
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    if collect:
        parser.CharacterDataHandler = characters
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise CVEBeaconError(f"statement template part {name} XML is malformed") from exc
    except (LookupError, ValueError) as exc:
        raise CVEBeaconError("statement template XML encoding must be UTF-8 or UTF-16") from exc
    finally:
        # Break parser/callback cycles so the current part is released promptly.
        parser.StartElementHandler = parser.EndElementHandler = None
        parser.CharacterDataHandler = None
    return spans, groups, encoding


def _append_literal(
    fragments: list[list[str]],
    texts: Sequence[str],
    starts: Sequence[int],
    joined: str,
    start: int,
    end: int,
) -> None:
    if start >= end:
        return
    index = bisect_right(starts, start) - 1
    while start < end:
        stop = min(end, starts[index] + len(texts[index]))
        fragments[index].append(joined[start:stop])
        start = stop
        index += 1


def _substitute_group(
    joined: str, texts: Sequence[str], values: Mapping[str, str]
) -> list[list[str]]:
    starts: list[int] = []
    total = 0
    for text in texts:
        starts.append(total)
        total += len(text)
    fragments: list[list[str]] = [[] for _ in texts]
    cursor = 0
    for count, match in enumerate(_PLACEHOLDER.finditer(joined), 1):
        if count > MAX_XML_SPANS:
            raise CVEBeaconError("statement template placeholder limit exceeded")
        _append_literal(fragments, texts, starts, joined, cursor, match.start())
        replacement = "$" if match.group("escaped") is not None else values[
            str(match.group("named") or match.group("braced"))
        ]
        fragments[bisect_right(starts, match.start()) - 1].append(replacement)
        cursor = match.end()
    _append_literal(fragments, texts, starts, joined, cursor, len(joined))
    return fragments


def _serialized_text(
    span: _TextSpan, fragments: Sequence[str], encoding: str, budget: int
) -> bytes:
    """Count all escaped bytes and repeated markup before constructing a span."""
    opening = span.opening.encode(encoding)
    closing = span.closing.encode(encoding)
    separator = (span.closing + span.line_break + span.opening).encode(encoding)
    size = len(opening) + len(closing)
    if size > budget:
        raise _rendered_too_large()
    for fragment in fragments:
        value = _INVALID_XML.sub("", fragment.replace("\r\n", "\n").replace("\r", "\n"))
        size += len(value.encode(encoding))
        escapes = value.count("&") * 4 + value.count("<") * 3 + value.count(">") * 3
        size += escapes * (1 if encoding == "utf-8" else 2)
        size += value.count("\n") * (len(separator) - len("\n".encode(encoding)))
        if size > budget:
            raise _rendered_too_large()
    output = io.BytesIO()
    output.write(opening)
    for fragment in fragments:
        value = _INVALID_XML.sub("", fragment.replace("\r\n", "\n").replace("\r", "\n"))
        for index, line in enumerate(value.split("\n")):
            if index:
                output.write(separator)
            output.write(escape(line).encode(encoding))
    output.write(closing)
    return output.getvalue()


def _render_part(raw: bytes, scan: _Scan, values: Mapping[str, str], budget: int) -> bytes:
    spans, groups, encoding = scan
    updates: dict[int, bytes] = {}
    size = len(raw)
    for group in groups:
        texts = [spans[index].text for index in group]
        paragraph = "".join(texts)
        if "$" not in paragraph:
            continue
        for index, fragments in zip(group, _substitute_group(paragraph, texts, values)):
            span = spans[index]
            if (not fragments and not span.text) or fragments == [span.text]:
                continue
            available = min(MAX_MEMBER_BYTES, budget) - size + span.end - span.start
            replacement = _serialized_text(span, fragments, encoding, available)
            size += len(replacement) - (span.end - span.start)
            updates[index] = replacement
    if size > min(MAX_MEMBER_BYTES, budget):
        raise _rendered_too_large()
    if not updates:
        return raw
    output = io.BytesIO()
    cursor = 0
    for index, span in enumerate(spans):
        if index in updates:
            output.write(memoryview(raw)[cursor:span.start])
            output.write(updates[index])
            cursor = span.end
    output.write(memoryview(raw)[cursor:])
    return output.getvalue()


def _check_members(infos: Sequence[zipfile.ZipInfo]) -> None:
    total = 0
    for info in infos:
        if info.flag_bits & 0x1:
            raise CVEBeaconError("encrypted .docx templates are not supported")
        if info.file_size > MAX_MEMBER_BYTES:
            raise CVEBeaconError(
                "statement template contains a member larger than "
                f"{MAX_MEMBER_BYTES} bytes"
            )
        if info.compress_size > info.file_size * 2 + 1024:
            raise CVEBeaconError(
                "statement template contains an invalid member size"
            )
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise CVEBeaconError(
                f"statement template expands to more than {MAX_TOTAL_BYTES} bytes"
            )


def _read_member(source: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Verify complete stored/DEFLATE streams without ZipExtFile's size truncation."""
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise CVEBeaconError("statement template uses unsupported compression")
    try:
        # Let zipfile validate local headers, names, flags and overlapping entries.
        # Read the compressed stream directly: ZipExtFile trusts file_size and
        # can silently truncate a stream with a forged size and matching CRC.
        with source.open(info):
            position = source.fp.tell()
        source.fp.seek(position)
        decoder = (
            zlib.decompressobj(-15)
            if info.compress_type == zipfile.ZIP_DEFLATED else None
        )
        output = io.BytesIO()
        crc = count = 0
        remaining = info.compress_size
        while remaining:
            chunk = source.fp.read(min(64 * 1024, remaining))
            if not chunk:
                raise zipfile.BadZipFile("incomplete compressed stream")
            remaining -= len(chunk)
            if decoder:
                chunk = decoder.decompress(
                    chunk, min(info.file_size, MAX_MEMBER_BYTES) - count + 1
                )
            count += len(chunk)
            if count > min(info.file_size, MAX_MEMBER_BYTES):
                raise zipfile.BadZipFile("invalid member size")
            crc = zlib.crc32(chunk, crc)
            output.write(chunk)
            if decoder and (decoder.unconsumed_tail or decoder.unused_data):
                raise zipfile.BadZipFile("inconsistent compressed stream")
        if count != info.file_size or crc != info.CRC or (decoder and not decoder.eof):
            raise zipfile.BadZipFile("inconsistent member")
        return output.getvalue()
    except _ZIP_ERRORS as exc:
        raise CVEBeaconError("statement template contains an unreadable member") from exc


def _process_xml_part(
    data: bytes, name: str, values: Mapping[str, str], budget: _XMLBudget,
    unknown: set[str], remaining: int,
) -> bytes:
    collect = bool(_PART_NAME.fullmatch(name))
    scan = _parse_xml(data, name, collect=collect, budget=budget)
    if not collect:
        return data
    spans, groups, _ = scan
    for group in groups:
        _check_text("".join(spans[index].text for index in group), unknown, budget)
    return data if unknown else _render_part(data, scan, values, remaining)


def _check_zip_directory(template: bytes) -> None:
    """Bound directory records before ZipFile allocates its member tables."""
    # Reuse the stdlib's classic/ZIP64 end-record decoder, which allocates no
    # ZipInfo objects. Walk fixed headers too: declared entry counts can lie.
    end = zipfile._EndRecData(io.BytesIO(template))
    if end is None:
        raise zipfile.BadZipFile("missing end record")
    if end[zipfile._ECD_ENTRIES_TOTAL] > MAX_ZIP_MEMBERS:
        raise _xml_limit("member count")
    directory_end = end[zipfile._ECD_LOCATION]
    if (end[zipfile._ECD_SIGNATURE] == zipfile.stringEndArchive64
        and template[directory_end:directory_end + 4] != zipfile.stringEndArchive64):
        # Older supported Python versions leave LOCATION at the classic EOCD.
        directory_end -= zipfile.sizeEndCentDir64 + zipfile.sizeEndCentDir64Locator
    position = directory_end - end[zipfile._ECD_SIZE]
    if position < 0 or directory_end > len(template):
        raise zipfile.BadZipFile("invalid directory bounds")
    count = 0
    while position < directory_end:
        if position + 46 > directory_end or template[position:position + 4] != b"PK\x01\x02":
            raise zipfile.BadZipFile("invalid directory record")
        count += 1
        if count > MAX_ZIP_MEMBERS:
            raise _xml_limit("member count")
        name, extra, comment = struct.unpack_from("<HHH", template, position + 28)
        position += 46 + name + extra + comment
    if position != directory_end or count != end[zipfile._ECD_ENTRIES_TOTAL]:
        raise zipfile.BadZipFile("inconsistent directory records")


@contextmanager
def _output_archive(output: io.BytesIO):
    try:
        with zipfile.ZipFile(output, "w") as target:
            yield target
    except _ZIP_ERRORS as exc:
        raise CVEBeaconError("could not write statement document") from exc


def render_docx(template: bytes, fields: Mapping[str, str]) -> bytes:
    """Fill placeholders in a .docx template and return the new document bytes."""
    try:
        return _render_docx(template, fields)
    except _ZIP_ERRORS as exc:
        raise CVEBeaconError("statement template is not a readable .docx file") from exc


def _render_docx(template: bytes, fields: Mapping[str, str]) -> bytes:
    if len(template) > MAX_TEMPLATE_BYTES:
        raise CVEBeaconError(f"statement template is larger than {MAX_TEMPLATE_BYTES} bytes")
    values = _values(fields)
    _check_zip_directory(template)
    with zipfile.ZipFile(io.BytesIO(template)) as source:
        infos = source.infolist()
        names = {info.filename for info in infos}
        if len(names) != len(infos):
            raise CVEBeaconError("statement template contains duplicate package members")
        if "[Content_Types].xml" not in names or "word/document.xml" not in names:
            raise CVEBeaconError("statement template is not a Word document")
        _check_members(infos)
        budget = _XMLBudget()
        unknown: set[str] = set()
        output = io.BytesIO()
        written = rendered = 0
        with _output_archive(output) as target:
            target.comment = source.comment
            for info in sorted(infos, key=lambda info: info.filename != "[Content_Types].xml"):
                if written + info.file_size > MAX_TOTAL_BYTES:
                    raise CVEBeaconError(f"statement template expands to more than {MAX_TOTAL_BYTES} bytes")
                is_xml = info.filename.casefold().endswith((".xml", ".rels"))
                if is_xml and (info.file_size > MAX_XML_BYTES
                               or budget.xml_bytes + info.file_size > MAX_PACKAGE_XML_BYTES):
                    raise _xml_limit("input byte")
                data = _read_member(source, info)
                if is_xml:
                    data = _process_xml_part(
                        data, info.filename, values, budget, unknown,
                        min(MAX_RENDERED_BYTES - rendered, MAX_TOTAL_BYTES - written),
                    )
                    if _PART_NAME.fullmatch(info.filename):
                        rendered += len(data)
                        if rendered > MAX_RENDERED_BYTES:
                            raise _rendered_too_large()
                written += len(data)
                target.writestr(info, data)
                del data
            if unknown:
                raise _unknown_error(unknown)
        return output.getvalue()


def default_template_text() -> str:
    """Load the built-in Markdown template from the installed package."""
    try:
        text = (
            resources.files("cvebeacon.watch")
            .joinpath("templates", "statement.md")
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise CVEBeaconError(
            "the built-in statement template is missing from this installation"
        ) from exc
    if len(text.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        raise CVEBeaconError(
            f"statement template is larger than {MAX_TEMPLATE_BYTES} bytes"
        )
    return text


def template_kind(path: Path) -> str:
    suffix = path.suffix.casefold()
    if suffix in _TEXT_SUFFIXES:
        return "text"
    if suffix == _DOCX_SUFFIX:
        return "docx"
    raise CVEBeaconError(
        f"unsupported statement template type {suffix or '(none)'}; "
        "use .md, .txt or .docx"
    )


def _output_path(path: Path, kind: str) -> Path:
    suffix = path.suffix.casefold()
    allowed = _TEXT_SUFFIXES if kind == "text" else (_DOCX_SUFFIX,)
    if suffix not in allowed:
        expected = " or ".join(allowed)
        raise CVEBeaconError(
            f"output extension {suffix or '(none)'} does not match the template; "
            f"use {expected}"
        )
    return path


def _read_template(path: Path) -> bytes:
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise CVEBeaconError(f"could not read statement template: {path}") from exc
    if not stat.S_ISREG(mode):
        raise CVEBeaconError("statement template must be a regular file")
    try:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        )
    except OSError as exc:
        raise CVEBeaconError(f"could not read statement template: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise CVEBeaconError("statement template must be a regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(MAX_TEMPLATE_BYTES + 1)
    except OSError as exc:
        raise CVEBeaconError(f"could not read statement template: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > MAX_TEMPLATE_BYTES:
        raise CVEBeaconError(
            f"statement template is larger than {MAX_TEMPLATE_BYTES} bytes"
        )
    return data


def _overwrite_error(path: Path) -> CVEBeaconError:
    return CVEBeaconError(
        f"refusing to overwrite existing statement: {path} (pass --force)"
    )


def _atomic_write(path: Path, data: bytes, *, force: bool) -> None:
    if os.path.lexists(path) and not force:
        raise _overwrite_error(path)
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        if force:
            os.replace(temporary, path)
            temporary = None
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise _overwrite_error(path) from exc
            except OSError as exc:
                raise CVEBeaconError(
                    "could not publish the statement without replacing an "
                    f"existing file: {path}"
                ) from exc
            os.unlink(temporary)
            temporary = None
    except OSError as exc:
        raise CVEBeaconError(f"could not write statement: {path}") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def write_statement(
    store: WatchStore,
    cve_id: str,
    *,
    catalogs: Sequence[str],
    template: str | Path | None,
    out: str | Path,
    force: bool = False,
    now: datetime | None = None,
    client_impacts: Sequence[ClientImpact] = (),
) -> Path:
    """Render one stored CVE into ``out`` and return the written path."""
    template_path = Path(template).expanduser() if template else None
    kind = template_kind(template_path) if template_path else "text"
    output = _output_path(Path(out).expanduser(), kind)
    view = store.view(cve_id, catalogs=catalogs)
    if view is None:
        raise CVEBeaconError(
            f"{cve_id} is not in the watch database; run 'cvebeacon watch sync' first"
        )
    fields = build_fields(
        view,
        first_seen=view.first_seen,
        reported_mark=store.reported_marks((view.cve_id,)).get(view.cve_id),
        generated_at=now or datetime.now(timezone.utc),
        client_impacts=client_impacts,
    )
    if template_path is None:
        result = render_text(default_template_text(), fields).encode("utf-8")
    else:
        data = _read_template(template_path)
        if kind == "text":
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise CVEBeaconError(
                    "statement template is not valid UTF-8 text"
                ) from exc
            result = render_text(text, fields).encode("utf-8")
        else:
            result = render_docx(data, fields)
    _atomic_write(output, result, force=force)
    return output
