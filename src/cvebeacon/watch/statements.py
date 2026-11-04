"""Render on-demand CVE statements from text or Word templates.

The statement is built from the same stored view that alert messages use.  It
never queries a source: the CVE must already exist in the watch database.
"""

from __future__ import annotations

import io
import os
import re
import stat
import tempfile
import zipfile
import zlib
from bisect import bisect_right
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from string import Template
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote
from xml.etree import ElementTree
from xml.sax.saxutils import escape

from ..errors import CVEBeaconError
from .messages import CVE_URL, EUVD_URL, NVD_URL, PROVIDER_ORDER
from .records import CVSS_PROVIDERS, CVSSEntry, WatchView
from .rules import highest_cvss
from .store import WatchStore

MISSING = "not available"
NOT_REPORTED = "not reported"
MAX_TEMPLATE_BYTES = 20 * 1024 * 1024
MAX_MEMBER_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_RENDERED_BYTES = 50 * 1024 * 1024
WORDPROCESSING_NS = (
    "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
)

FIELD_NAMES = (
    "cve_id",
    "title",
    "description",
    "published",
    "first_seen",
    "last_modified",
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
_ENTITY = re.compile(r"&(#[0-9]+|#x[0-9A-Fa-f]+|amp|lt|gt|quot|apos);")
_NAMED_ENTITIES = {
    "amp": "&",
    "lt": "<",
    "gt": ">",
    "quot": '"',
    "apos": "'",
}
_ATTRIBUTE = re.compile(r"""([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")


def _text(value: Any) -> str:
    return MISSING if value is None or str(value).strip() == "" else str(value)


def _generated_at(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


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


def _reported_marks(view: WatchView) -> tuple[str, str, str]:
    """Return the reported-to-clients mark for one CVE.

    The watch database does not store this mark yet, so every statement renders
    ``not reported``.  Keep this lookup as the single wiring point for when the
    mark is stored.
    """
    return NOT_REPORTED, NOT_REPORTED, NOT_REPORTED


def build_fields(
    view: WatchView, *, first_seen: str | None, generated_at: datetime
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
    reported, reported_by, reported_at = _reported_marks(view)
    cve_id = quote(str(view.cve_id), safe="-_.")
    euvd_id = quote(str(view.euvd_id), safe="-_.") if view.euvd_id else None
    values = {
        "cve_id": view.cve_id,
        "title": MISSING,
        "description": _text(view.description),
        "published": _text(view.published),
        "first_seen": _text(first_seen),
        "last_modified": _text(view.last_modified),
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


def _unknown_error(names: Iterable[str]) -> CVEBeaconError:
    listed = ", ".join("${" + name + "}" for name in sorted(set(names)))
    return CVEBeaconError(f"unknown statement placeholder(s): {listed}")


def _check_text(text: str, unknown: set[str]) -> None:
    for match in _PLACEHOLDER.finditer(text):
        if match.group("invalid") is not None:
            raise _invalid_placeholder()
        name = match.group("named") or match.group("braced")
        if name is not None and name not in FIELD_NAMES:
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


def _xml_unescape(raw: str) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in _NAMED_ENTITIES:
            return _NAMED_ENTITIES[name]
        base = 16 if name.startswith("#x") else 10
        digits = name[2:] if base == 16 else name[1:]
        try:
            value = chr(int(digits, base))
        except (ValueError, OverflowError) as exc:
            raise CVEBeaconError(
                "statement template contains an invalid character reference"
            ) from exc
        return value

    value = _ENTITY.sub(replace, raw)
    position = 0
    while True:
        amp = raw.find("&", position)
        if amp < 0:
            break
        match = _ENTITY.match(raw, amp)
        if match is None:
            raise CVEBeaconError(
                "statement template contains an invalid XML entity reference"
            )
        position = match.end()
    return value


def _xml_escape(value: str) -> str:
    return escape(_INVALID_XML.sub("", value))


def _normalized_lines(value: str) -> list[str]:
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return value.split("\n")


def _text_element(qname: str, attrs: str, value: str) -> str:
    if "xml:space" not in attrs:
        attrs += ' xml:space="preserve"'
    lines = [_xml_escape(line) for line in _normalized_lines(value)]
    if len(lines) == 1:
        return f"<{qname}{attrs}>{lines[0]}</{qname}>"
    prefix = qname.split(":", 1)[0] + ":" if ":" in qname else ""
    separator = f"</{qname}><{prefix}br/><{qname}{attrs}>"
    return f"<{qname}{attrs}>" + separator.join(lines) + f"</{qname}>"


def _tag_end(xml: str, start: int) -> int:
    quote_char = ""
    index = start
    while index < len(xml):
        char = xml[index]
        if quote_char:
            if char == quote_char:
                quote_char = ""
        elif char in "\"'":
            quote_char = char
        elif char == ">":
            return index
        index += 1
    return -1


def _name_end(body: str) -> int:
    for index, char in enumerate(body):
        if char.isspace() or char == "/":
            return index
    return len(body)


def _namespace_declarations(attrs: str) -> dict[str, str]:
    declarations: dict[str, str] = {}
    for match in _ATTRIBUTE.finditer(attrs):
        name = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        if name == "xmlns":
            declarations[""] = _xml_unescape(value)
        elif name.startswith("xmlns:"):
            declarations[name[6:]] = _xml_unescape(value)
    return declarations


def _malformed(detail: str) -> CVEBeaconError:
    return CVEBeaconError(f"statement template XML is malformed: {detail}")


@dataclass(frozen=True, slots=True)
class _TextSpan:
    start: int
    end: int
    qname: str
    attrs: str
    text: str


def _scan_part(xml: str) -> tuple[tuple[_TextSpan, ...], tuple[tuple[int, ...], ...]]:
    """Scan one XML part once and return text spans grouped by paragraph.

    The scan understands comments, CDATA, processing instructions, namespace
    prefixes and nested paragraphs.  A text element is attached to its
    innermost paragraph, so placeholders cannot span two paragraphs.
    """
    spans: list[_TextSpan] = []
    groups: list[list[int]] = []
    stack: list[tuple[str, bool]] = []
    namespaces: list[dict[str, str]] = [{"xml": "http://www.w3.org/XML/1998/namespace"}]
    paragraphs: list[int] = []
    index = 0
    while index < len(xml):
        start = xml.find("<", index)
        if start < 0:
            break
        if xml.startswith("<!--", start):
            end = xml.find("-->", start + 4)
            if end < 0:
                raise _malformed("unclosed comment")
            index = end + 3
            continue
        if xml.startswith("<![CDATA[", start):
            end = xml.find("]]>", start + 9)
            if end < 0:
                raise _malformed("unclosed CDATA section")
            index = end + 3
            continue
        if xml.startswith("<?", start):
            end = xml.find("?>", start + 2)
            if end < 0:
                raise _malformed("unclosed processing instruction")
            index = end + 2
            continue
        if xml.startswith("<!DOCTYPE", start) or xml.startswith("<!ENTITY", start):
            raise CVEBeaconError(
                "statement template must not declare a DTD or XML entities"
            )
        if xml.startswith("<!", start):
            raise _malformed("unsupported declaration")
        if xml.startswith("</", start):
            end = xml.find(">", start + 2)
            if end < 0:
                raise _malformed("unclosed closing tag")
            qname = xml[start + 2 : end].strip()
            if not stack or stack[-1][0] != qname:
                raise _malformed("unexpected or mismatched closing tag")
            _, is_paragraph = stack.pop()
            namespaces.pop()
            if is_paragraph:
                paragraphs.pop()
            index = end + 1
            continue
        end = _tag_end(xml, start + 1)
        if end < 0:
            raise _malformed("unclosed opening tag")
        body = xml[start + 1 : end]
        self_closing = body.rstrip().endswith("/")
        if self_closing:
            body = body.rstrip()[:-1]
        name_end = _name_end(body)
        qname = body[:name_end]
        if not qname:
            raise _malformed("empty element name")
        attrs = body[name_end:]
        prefix, local = (
            qname.split(":", 1) if ":" in qname else ("", qname)
        )
        declarations = _namespace_declarations(attrs)
        scope = namespaces[-1]
        if declarations:
            scope = dict(scope)
            scope.update(declarations)
        uri = scope.get(prefix, "") if prefix else scope.get("", "")
        is_paragraph = uri == WORDPROCESSING_NS and local == "p"
        is_text = uri == WORDPROCESSING_NS and local == "t"
        if is_text:
            if self_closing:
                index = end + 1
                continue
            if not paragraphs:
                raise _malformed("text outside a paragraph")
            close = xml.find("<", end + 1)
            if close < 0 or not xml.startswith("</", close):
                raise _malformed("a text element contains nested markup")
            close_end = _tag_end(xml, close + 2)
            if close_end < 0 or xml[close + 2 : close_end].strip() != qname:
                raise _malformed("mismatched text element")
            spans.append(
                _TextSpan(
                    start,
                    close_end + 1,
                    qname,
                    attrs,
                    _xml_unescape(xml[end + 1 : close]),
                )
            )
            groups[paragraphs[-1]].append(len(spans) - 1)
            index = close_end + 1
            continue
        if not self_closing:
            if is_paragraph:
                groups.append([])
                paragraphs.append(len(groups) - 1)
            stack.append((qname, is_paragraph))
            namespaces.append(scope)
        index = end + 1
    if stack:
        raise _malformed("unclosed element")
    return tuple(spans), tuple(tuple(group) for group in groups)


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
    joined: str,
    texts: Sequence[str],
    values: Mapping[str, str],
    budget: int,
) -> tuple[list[str], int]:
    starts: list[int] = []
    total = 0
    for text in texts:
        starts.append(total)
        total += len(text)
    fragments: list[list[str]] = [[] for _ in texts]
    expansion = 0
    cursor = 0
    for match in _PLACEHOLDER.finditer(joined):
        _append_literal(fragments, texts, starts, joined, cursor, match.start())
        if match.group("invalid") is not None:
            raise _invalid_placeholder()
        if match.group("escaped") is not None:
            replacement = "$"
        else:
            name = match.group("named") or match.group("braced")
            replacement = values[str(name)]
        expansion += len(replacement.encode("utf-8"))
        if expansion > budget:
            raise _rendered_too_large()
        fragments[bisect_right(starts, match.start()) - 1].append(replacement)
        cursor = match.end()
    _append_literal(fragments, texts, starts, joined, cursor, len(joined))
    return ["".join(parts) for parts in fragments], expansion


def _paragraph_texts(
    spans: Sequence[_TextSpan], groups: Sequence[Sequence[int]]
) -> tuple[str, ...]:
    return tuple("".join(spans[index].text for index in group) for group in groups)


def _render_scanned(
    raw: str,
    spans: Sequence[_TextSpan],
    groups: Sequence[Sequence[int]],
    paragraphs: Sequence[str],
    values: Mapping[str, str],
    budget: int,
) -> tuple[str, int]:
    texts = [span.text for span in spans]
    updates: list[str | None] = [None] * len(spans)
    expansion = 0
    for group, paragraph in zip(groups, paragraphs):
        if "$" not in paragraph:
            continue
        new_texts, used = _substitute_group(
            paragraph,
            [texts[index] for index in group],
            values,
            budget - expansion,
        )
        expansion += used
        for index, new in zip(group, new_texts):
            if new != texts[index]:
                updates[index] = new
    if all(update is None for update in updates):
        return raw, expansion
    pieces: list[str] = []
    cursor = 0
    for span, update in zip(spans, updates):
        pieces.append(raw[cursor : span.start])
        if update is None:
            pieces.append(raw[span.start : span.end])
        else:
            pieces.append(_text_element(span.qname, span.attrs, update))
        cursor = span.end
    pieces.append(raw[cursor:])
    result = "".join(pieces)
    if len(result.encode("utf-8")) > MAX_MEMBER_BYTES:
        raise _rendered_too_large()
    return result, expansion


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
        if info.compress_size > info.file_size + 1024:
            raise CVEBeaconError(
                "statement template contains an invalid member size"
            )
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise CVEBeaconError(
                f"statement template expands to more than {MAX_TOTAL_BYTES} bytes"
            )


def _read_member(source: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.file_size > MAX_MEMBER_BYTES:
        raise CVEBeaconError(
            "statement template contains a member larger than "
            f"{MAX_MEMBER_BYTES} bytes"
        )
    try:
        with source.open(info) as handle:
            data = handle.read(MAX_MEMBER_BYTES + 1)
    except (
        zipfile.BadZipFile,
        OSError,
        NotImplementedError,
        RuntimeError,
        EOFError,
        zlib.error,
    ) as exc:
        raise CVEBeaconError(
            "statement template contains an unreadable member"
        ) from exc
    if len(data) > MAX_MEMBER_BYTES:
        raise CVEBeaconError(
            "statement template contains a member larger than "
            f"{MAX_MEMBER_BYTES} bytes"
        )
    return data


def _reject_declarations(data: bytes, name: str) -> None:
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise CVEBeaconError(
            f"statement template part {name} declares a DTD or XML entities"
        )


def render_docx(template: bytes, fields: Mapping[str, str]) -> bytes:
    """Fill placeholders in a .docx template and return the new document bytes."""
    if len(template) > MAX_TEMPLATE_BYTES:
        raise CVEBeaconError(
            f"statement template is larger than {MAX_TEMPLATE_BYTES} bytes"
        )
    values = _values(fields)
    try:
        source = zipfile.ZipFile(io.BytesIO(template))
    except (zipfile.BadZipFile, OSError) as exc:
        raise CVEBeaconError("statement template is not a readable .docx file") from exc
    with source:
        infos = source.infolist()
        names = {info.filename for info in infos}
        if "[Content_Types].xml" not in names or "word/document.xml" not in names:
            raise CVEBeaconError("statement template is not a Word document")
        _check_members(infos)
        processed: dict[str, str] = {}
        scanned_total = 0
        for info in infos:
            if not (info.filename.endswith(".xml") or info.filename.endswith(".rels")):
                continue
            data = _read_member(source, info)
            scanned_total += len(data)
            if scanned_total > MAX_TOTAL_BYTES:
                raise CVEBeaconError(
                    f"statement template expands to more than {MAX_TOTAL_BYTES} bytes"
                )
            _reject_declarations(data, info.filename)
            if _PART_NAME.match(info.filename):
                try:
                    processed[info.filename] = data.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise CVEBeaconError(
                        "statement template contains an unreadable "
                        "WordprocessingML part"
                    ) from exc
        rendered: dict[str, bytes] = {}
        scans = {
            name: _scan_part(raw) for name, raw in processed.items()
        }
        unknown: set[str] = set()
        paragraphs_by_part: dict[str, tuple[str, ...]] = {}
        for name, (spans, groups) in scans.items():
            paragraphs = _paragraph_texts(spans, groups)
            paragraphs_by_part[name] = paragraphs
            for paragraph in paragraphs:
                if "$" in paragraph:
                    _check_text(paragraph, unknown)
        if unknown:
            raise _unknown_error(unknown)
        expansion = 0
        for name, raw in processed.items():
            spans, groups = scans[name]
            result, used = _render_scanned(
                raw,
                spans,
                groups,
                paragraphs_by_part[name],
                values,
                MAX_RENDERED_BYTES - expansion,
            )
            expansion += used
            data = result.encode("utf-8")
            try:
                ElementTree.fromstring(data)
            except ElementTree.ParseError as exc:
                raise CVEBeaconError(
                    f"generated statement part {name} is not well-formed XML"
                ) from exc
            rendered[name] = data
        output = io.BytesIO()
        written = 0
        with zipfile.ZipFile(output, "w") as target:
            target.comment = source.comment
            ordered = sorted(
                infos, key=lambda info: info.filename != "[Content_Types].xml"
            )
            for info in ordered:
                data = rendered.get(info.filename)
                if data is None:
                    data = _read_member(source, info)
                written += len(data)
                if written > MAX_TOTAL_BYTES:
                    raise CVEBeaconError(
                        "statement template expands to more than "
                        f"{MAX_TOTAL_BYTES} bytes"
                    )
                target.writestr(info, data)
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
        first_seen=store.first_seen(cve_id),
        generated_at=now or datetime.now(timezone.utc),
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
