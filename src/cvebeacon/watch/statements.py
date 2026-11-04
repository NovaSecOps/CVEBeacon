"""Render on-demand CVE statements from text or Word templates.

The statement is built from the same stored view that alert messages use.  It
never queries a source: the CVE must already exist in the watch database.
"""

from __future__ import annotations

import io
import os
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from string import Template
from typing import Any, Iterable, Mapping, Sequence
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
_PARAGRAPH = re.compile(r"<w:p(?:\s[^>]*)?>.*?</w:p>", re.DOTALL)
_TEXT_ELEMENT = re.compile(
    r"<w:t(?P<attrs>\s[^>]*)?>(?P<text>.*?)</w:t>", re.DOTALL
)
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
        "nvd_url": NVD_URL.format(cve_id=view.cve_id),
        "cve_org_url": CVE_URL.format(cve_id=view.cve_id),
        "euvd_id": _text(view.euvd_id),
        "euvd_url": (
            EUVD_URL.format(euvd_id=view.euvd_id) if view.euvd_id else MISSING
        ),
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


def _invalid_placeholder() -> CVEBeaconError:
    return CVEBeaconError(
        "invalid statement placeholder syntax: '$' must be followed by a name, "
        "a braced name, or another '$'"
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
    return Template(template).substitute(_values(fields))


def _xml_unescape(raw: str) -> str:
    try:
        value = ElementTree.fromstring(f"<t>{raw}</t>").text
    except ElementTree.ParseError as exc:
        raise CVEBeaconError(
            "statement template contains malformed WordprocessingML text"
        ) from exc
    return value or ""


def _xml_escape(value: str) -> str:
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return escape(_INVALID_XML.sub("", value))


def _text_element(attrs: str, value: str) -> str:
    if "xml:space" not in attrs:
        attrs += ' xml:space="preserve"'
    lines = [_xml_escape(line) for line in value.split("\n")]
    if len(lines) == 1:
        return f"<w:t{attrs}>{lines[0]}</w:t>"
    separator = "</w:t><w:br/><w:t" + attrs + ">"
    return f"<w:t{attrs}>" + separator.join(lines) + "</w:t>"


def _append_literal(
    pieces: list[tuple[int, str]],
    joined: str,
    owners: Sequence[int],
    start: int,
    end: int,
) -> None:
    index = start
    while index < end:
        slot = owners[index]
        stop = index
        while stop < end and owners[stop] == slot:
            stop += 1
        pieces.append((slot, joined[index:stop]))
        index = stop


def _substitute_runs(
    joined: str,
    owners: Sequence[int],
    values: Mapping[str, str],
    slots: int,
) -> list[str]:
    pieces: list[tuple[int, str]] = []
    cursor = 0
    for match in _PLACEHOLDER.finditer(joined):
        _append_literal(pieces, joined, owners, cursor, match.start())
        if match.group("invalid") is not None:
            raise _invalid_placeholder()
        if match.group("escaped") is not None:
            replacement = "$"
        else:
            name = match.group("named") or match.group("braced")
            replacement = values[str(name)]
        pieces.append((owners[match.start()], replacement))
        cursor = match.end()
    _append_literal(pieces, joined, owners, cursor, len(joined))
    output = [""] * slots
    for slot, value in pieces:
        output[slot] += value
    return output


def _paragraph_texts(raw: str) -> Iterable[str]:
    for paragraph in _PARAGRAPH.finditer(raw):
        texts = [
            _xml_unescape(match.group("text"))
            for match in _TEXT_ELEMENT.finditer(paragraph.group(0))
        ]
        if texts:
            yield "".join(texts)


def _render_paragraph(paragraph: str, values: Mapping[str, str]) -> str:
    matches = list(_TEXT_ELEMENT.finditer(paragraph))
    if not matches:
        return paragraph
    texts = [_xml_unescape(match.group("text")) for match in matches]
    joined = "".join(texts)
    if "$" not in joined:
        return paragraph
    owners = [index for index, text in enumerate(texts) for _ in text]
    updated = _substitute_runs(joined, owners, values, len(texts))
    if updated == texts:
        return paragraph
    pieces: list[str] = []
    cursor = 0
    for match, old, new in zip(matches, texts, updated):
        pieces.append(paragraph[cursor : match.start()])
        if new == old:
            pieces.append(match.group(0))
        else:
            pieces.append(_text_element(match.group("attrs") or "", new))
        cursor = match.end()
    pieces.append(paragraph[cursor:])
    return "".join(pieces)


def _render_part(raw: str, values: Mapping[str, str]) -> str:
    def render(match: re.Match[str]) -> str:
        paragraph = match.group(0)
        return _render_paragraph(paragraph, values) if "$" in paragraph else paragraph

    return _PARAGRAPH.sub(render, raw)


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
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise CVEBeaconError(
                f"statement template expands to more than {MAX_TOTAL_BYTES} bytes"
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
        decoded: dict[str, str] = {}
        for info in infos:
            if not _PART_NAME.match(info.filename):
                continue
            try:
                decoded[info.filename] = source.read(info).decode("utf-8")
            except (
                UnicodeDecodeError,
                zipfile.BadZipFile,
                OSError,
                NotImplementedError,
                RuntimeError,
            ) as exc:
                raise CVEBeaconError(
                    "statement template contains an unreadable WordprocessingML part"
                ) from exc
        unknown: set[str] = set()
        for raw in decoded.values():
            for joined in _paragraph_texts(raw):
                _check_text(joined, unknown)
        if unknown:
            raise _unknown_error(unknown)
        rendered = {
            name: _render_part(raw, values).encode("utf-8")
            for name, raw in decoded.items()
        }
        for name, data in rendered.items():
            try:
                ElementTree.fromstring(data)
            except ElementTree.ParseError as exc:
                raise CVEBeaconError(
                    f"generated statement part {name} is not well-formed XML"
                ) from exc
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as target:
            target.comment = source.comment
            ordered = sorted(
                infos, key=lambda info: info.filename != "[Content_Types].xml"
            )
            for info in ordered:
                data = rendered.get(info.filename)
                if data is None:
                    try:
                        data = source.read(info)
                    except (
                        zipfile.BadZipFile,
                        OSError,
                        NotImplementedError,
                        RuntimeError,
                    ) as exc:
                        raise CVEBeaconError(
                            "statement template contains an unreadable member"
                        ) from exc
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
        if path.stat().st_size > MAX_TEMPLATE_BYTES:
            raise CVEBeaconError(
                f"statement template is larger than {MAX_TEMPLATE_BYTES} bytes"
            )
        data = path.read_bytes()
    except OSError as exc:
        raise CVEBeaconError(f"could not read statement template: {path}") from exc
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
    if path.exists() and not force:
        raise _overwrite_error(path)
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        if path.exists() and not force:
            raise _overwrite_error(path)
        os.replace(temporary, path)
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
