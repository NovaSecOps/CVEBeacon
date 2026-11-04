from __future__ import annotations

import base64
import io
import json
import os
import random
import re
import struct
import subprocess
import sys
import time
import zipfile
import zlib
from datetime import date
from pathlib import Path
from string import Template
from xml.sax.saxutils import escape
from xml.etree import ElementTree

import pytest
from watch_support import NOW, write_config

from cvebeacon import cli
from cvebeacon.errors import CVEBeaconError
from cvebeacon.watch import statements
from cvebeacon.watch.records import (
    CVSSEntry,
    EUVDUpdate,
    KEVFields,
    Product,
    Reference,
    WatchRecord,
    WatchView,
)
from cvebeacon.watch.statements import (
    FIELD_NAMES,
    MISSING,
    NOT_REPORTED,
    build_fields,
    default_template_text,
    render_docx,
    render_text,
)
from cvebeacon.watch.store import WatchStore

SOURCES = ("nvd", "euvd", "cisa_kev", "eu_kev", "epss")
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    "</Types>"
)
STYLES = (
    b'<w:styles xmlns:w="'
    + W.encode()
    + b'"><w:docDefaults><w:rPrDefault/></w:docDefaults></w:styles>'
)


def full_record(identifier: str = "CVE-2026-0001") -> WatchRecord:
    return WatchRecord(
        cve_id=identifier,
        status="published",
        published="2026-10-28T10:00:00.000",
        last_modified="2026-11-03T08:30:00.000",
        description=(
            "Acme Widget before 4.2.1 allows unauthenticated remote code execution."
        ),
        source_identifier="security@acme.example",
        cvss=(
            CVSSEntry(
                "nvd",
                "nvd@nist.gov",
                "3.1",
                9.8,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CRITICAL",
            ),
            CVSSEntry("cna", "security@acme.example", "3.1", 8.1),
        ),
        cwes=("CWE-79", "CWE-89"),
        products=(Product("acme", "widget"),),
        references=(
            Reference("https://example.invalid/patch"),
            Reference("https://example.invalid/advisory", ("VENDOR",)),
        ),
        ssvc_exploitation="active",
    )


def populate(store: WatchStore, identifier: str = "CVE-2026-0001") -> WatchStore:
    store.upsert_nvd([full_record(identifier)])
    store.replace_euvd_items(
        [
            EUVDUpdate(
                (identifier,),
                "EUVD-2026-0001",
                "2026-10-30",
                CVSSEntry("euvd", "euvd", "3.1", 7.5),
                "2026-11-01",
                (Product("acme", "gadget"),),
            )
        ],
        catalogs=SOURCES,
    )
    store.replace_kev(
        "cisa",
        {
            identifier: KEVFields(
                "2026-11-01", "2026-11-20", "Apply the vendor update.", "Known"
            )
        },
        catalogs=SOURCES,
    )
    store.replace_kev(
        "eu", {identifier: KEVFields("2026-11-02")}, catalogs=SOURCES
    )
    store.replace_epss(
        [(identifier, 0.62214, 0.95421, date(2026, 11, 3))]
    )
    return store


def full_store(tmp_path: Path) -> WatchStore:
    return populate(WatchStore(tmp_path / "watch.db", clock=lambda: NOW))


def fields_for(store: WatchStore, identifier: str = "CVE-2026-0001") -> dict[str, str]:
    view = store.view(identifier, catalogs=SOURCES)
    assert view is not None
    return build_fields(
        view, first_seen=view.first_seen, generated_at=NOW,
        reported_mark=store.reported_marks((identifier,)).get(identifier),
    )


def all_fields() -> dict[str, str]:
    values = {name: f"value-{name}" for name in FIELD_NAMES}
    values.update(
        {
            "cve_id": "CVE-2026-0001",
            "status": "published",
            "severity": "critical",
            "description": 'Acme <widget> & "gadget"',
            "references": "https://a.example/x\nhttps://b.example/y",
            "generated_at": "2026-11-04T14:00:00+00:00",
        }
    )
    return values


def docx_zip(
    document: str,
    *,
    header: str | None = None,
    footer: str | None = None,
    styles: bytes = STYLES,
    core: bytes = b"<core/>",
    content_types_last: bool = False,
    compression: int = zipfile.ZIP_STORED,
    extra: dict[str, bytes] | None = None,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        members = [
            ("_rels/.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'),
            ("word/document.xml", document),
        ]
        if header is not None:
            members.append(("word/header1.xml", header))
        if footer is not None:
            members.append(("word/footer1.xml", footer))
        members.extend(
            [
                ("word/styles.xml", styles),
                ("docProps/core.xml", core),
            ]
        )
        members.extend((extra or {}).items())
        if content_types_last:
            members.append(("[Content_Types].xml", CONTENT_TYPES))
        else:
            members.insert(0, ("[Content_Types].xml", CONTENT_TYPES))
        for name, value in members:
            archive.writestr(name, value)
    return output.getvalue()


def docx_bytes(
    document: str,
    *,
    header: str | None = None,
    footer: str | None = None,
    styles: bytes = STYLES,
    core: bytes = b"<core/>",
    content_types_last: bool = False,
    compression: int = zipfile.ZIP_STORED,
) -> bytes:
    body = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<w:document xmlns:w="{W}"><w:body>{document}</w:body></w:document>'
    )
    return docx_zip(
        body,
        header=header,
        footer=footer,
        styles=styles,
        core=core,
        content_types_last=content_types_last,
        compression=compression,
    )


def paragraph_texts(xml: bytes) -> list[str]:
    root = ElementTree.fromstring(xml)
    return [
        "".join(element.text or "" for element in paragraph.iter(f"{{{W}}}t"))
        for paragraph in root.iter(f"{{{W}}}p")
    ]


def part(zip_data: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(zip_data)) as archive:
        return archive.read(name)


def local_data_offset(zip_data: bytes, name: str) -> int:
    position = 0
    while True:
        position = zip_data.find(b"PK\x03\x04", position)
        assert position >= 0
        name_length, extra_length = struct.unpack_from("<HH", zip_data, position + 26)
        filename = zip_data[position + 30 : position + 30 + name_length]
        if filename == name.encode():
            return position + 30 + name_length + extra_length
        position += 4


def corrupt_deflate(zip_data: bytes, name: str) -> bytes:
    data = bytearray(zip_data)
    data[local_data_offset(data, name)] = 0x07
    return bytes(data)


def patch_central_size(
    zip_data: bytes, name: str, size: int | None = None,
    *, compressed_size: int | None = None,
) -> bytes:
    data = bytearray(zip_data)
    position = 0
    while True:
        position = data.find(b"PK\x01\x02", position)
        assert position >= 0
        name_length = struct.unpack_from("<H", data, position + 28)[0]
        filename = data[position + 46 : position + 46 + name_length]
        if filename == name.encode():
            if size is not None:
                struct.pack_into("<I", data, position + 24, size)
                struct.pack_into("<I", data, position + 16, zlib.crc32(b"\0" * size))
            if compressed_size is not None:
                struct.pack_into("<I", data, position + 20, compressed_size)
            return bytes(data)
        position += 4


def test_fields_cover_the_documented_names(tmp_path):
    store = full_store(tmp_path)
    fields = fields_for(store)
    assert tuple(fields) == FIELD_NAMES
    assert fields["cve_id"] == "CVE-2026-0001"
    assert fields["title"] == MISSING
    assert fields["description"].startswith("Acme Widget before 4.2.1")
    assert fields["published"] == "2026-10-28T10:00:00.000"
    assert fields["first_seen"] == "2026-11-03T12:00:00+00:00"
    assert fields["last_modified"] == "2026-11-03T08:30:00.000"
    assert fields["status"] == "published"
    assert fields["cvss_max"] == "9.8"
    assert fields["cvss_max_provider"] == "NVD"
    assert fields["cvss_max_version"] == "3.1"
    assert fields["cvss_max_vector"].startswith("CVSS:3.1/AV:N")
    assert fields["cvss_all"] == "8.1 v3.1 (CNA: acme.example)\n9.8 v3.1 (NVD)\n7.5 v3.1 (EUVD)"
    assert fields["severity"] == "critical"
    assert fields["epss"] == "0.62214"
    assert fields["epss_percentile"] == "0.95421"
    assert fields["epss_date"] == "2026-11-03"
    assert fields["kev"] == "yes"
    assert fields["kev_date_added"] == "2026-11-01"
    assert fields["kev_due_date"] == "2026-11-20"
    assert fields["kev_required_action"] == "Apply the vendor update."
    assert fields["eu_kev"] == "yes"
    assert fields["ssvc_exploitation"] == "active"
    assert fields["cwes"] == "CWE-79, CWE-89"
    assert fields["affected_products"] == "acme gadget\nacme widget"
    assert fields["references"] == (
        "https://example.invalid/advisory\nhttps://example.invalid/patch"
    )
    assert fields["nvd_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    assert fields["cve_org_url"] == "https://www.cve.org/CVERecord?id=CVE-2026-0001"
    assert fields["euvd_id"] == "EUVD-2026-0001"
    assert fields["euvd_url"] == (
        "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-0001"
    )
    assert fields["generated_at"] == "2026-11-03T12:00:00+00:00"
    assert fields["reported"] == NOT_REPORTED
    assert fields["reported_by"] == NOT_REPORTED
    assert fields["reported_at"] == NOT_REPORTED


def test_missing_values_use_the_defined_text(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([WatchRecord(cve_id="CVE-2026-0002", status="published")])
    fields = fields_for(store, "CVE-2026-0002")
    for name in (
        "title",
        "description",
        "published",
        "last_modified",
        "cvss_max",
        "cvss_max_provider",
        "cvss_max_version",
        "cvss_max_vector",
        "cvss_all",
        "severity",
        "epss",
        "epss_percentile",
        "epss_date",
        "kev_date_added",
        "kev_due_date",
        "kev_required_action",
        "ssvc_exploitation",
        "cwes",
        "affected_products",
        "references",
        "euvd_id",
        "euvd_url",
    ):
        assert fields[name] == MISSING, name
    assert fields["kev"] == "no"
    assert fields["eu_kev"] == "no"
    assert fields["status"] == "published"
    assert fields["nvd_url"].endswith("CVE-2026-0002")
    assert fields["cve_org_url"].endswith("CVE-2026-0002")
    assert fields["reported"] == NOT_REPORTED


def test_markdown_fills_every_field_and_escapes_dollar():
    fields = all_fields()
    template = "\n".join(f"{name}: ${{{name}}}" for name in FIELD_NAMES)
    rendered = render_text(template + "\nprice: $$5", fields)
    assert "${" not in rendered
    for name in FIELD_NAMES:
        assert f"{name}: {fields[name]}" in rendered
    assert "price: $5" in rendered


def test_unknown_placeholders_are_listed(tmp_path):
    fields = all_fields()
    with pytest.raises(CVEBeaconError) as caught:
        render_text("${cve_id} ${nope} ${also_missing}", fields)
    message = str(caught.value)
    assert "${nope}" in message
    assert "${also_missing}" in message


def test_malformed_placeholder_is_rejected():
    with pytest.raises(CVEBeaconError) as caught:
        render_text("bad $ placeholder", all_fields())
    message = str(caught.value)
    assert "invalid statement placeholder" in message
    assert "write '$$'" in message


def test_default_markdown_statement_renders_from_the_cli(tmp_path, capsys):
    config = write_config(
        tmp_path, sources=SOURCES, extra=""
    )
    populate(WatchStore(config.watch.database, clock=lambda: NOW))
    out = tmp_path / "statement.md"
    assert (
        cli.main(
            [
                "--config",
                str(config.config_path),
                "watch",
                "statement",
                "CVE-2026-0001",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    text = out.read_text(encoding="utf-8")
    assert "# CVE statement: CVE-2026-0001" in text
    assert "**Title:** not available" in text
    assert "Highest CVSS: 9.8 (version 3.1, NVD)" in text
    assert "9.8 v3.1 (NVD)" in text
    assert "EPSS: 0.62214 (percentile 0.95421, score date 2026-11-03)" in text
    assert "Known exploited: yes" in text
    assert "acme gadget" in text
    assert "https://example.invalid/advisory" in text
    assert "Reported to clients: not reported" in text
    assert "${" not in text
    assert re.search(r"Generated \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", text)
    assert capsys.readouterr().out.strip() == str(out)


def test_missing_cve_exits_two(tmp_path, capsys):
    config = write_config(tmp_path, sources=("nvd",))
    out = tmp_path / "statement.md"
    assert (
        cli.main(
            [
                "--config",
                str(config.config_path),
                "watch",
                "statement",
                "CVE-2099-0001",
                "--out",
                str(out),
            ]
        )
        == 2
    )
    assert "not in the watch database" in capsys.readouterr().err
    assert not out.exists()


def test_overwrite_is_refused_without_force(tmp_path):
    config = write_config(tmp_path, sources=("nvd",))
    populate(WatchStore(config.watch.database, clock=lambda: NOW))
    out = tmp_path / "statement.md"
    out.write_text("keep me", encoding="utf-8")
    base = [
        "--config",
        str(config.config_path),
        "watch",
        "statement",
        "CVE-2026-0001",
        "--out",
        str(out),
    ]
    assert cli.main(base) == 2
    assert out.read_text(encoding="utf-8") == "keep me"
    assert cli.main([*base, "--force"]) == 0
    assert out.read_text(encoding="utf-8").startswith("# CVE statement")
    assert not list(tmp_path.glob(".statement.md.*.tmp"))


def test_oversized_text_template_is_refused(tmp_path, monkeypatch):
    config = write_config(tmp_path, sources=("nvd",))
    populate(WatchStore(config.watch.database, clock=lambda: NOW))
    template = tmp_path / "template.md"
    template.write_text("x" * 32, encoding="utf-8")
    monkeypatch.setattr(statements, "MAX_TEMPLATE_BYTES", 10)
    out = tmp_path / "statement.md"
    assert (
        cli.main(
            [
                "--config",
                str(config.config_path),
                "watch",
                "statement",
                "CVE-2026-0001",
                "--template",
                str(template),
                "--out",
                str(out),
            ]
        )
        == 2
    )
    assert not out.exists()


def test_output_extension_must_match_the_template(tmp_path):
    config = write_config(tmp_path, sources=("nvd",))
    populate(WatchStore(config.watch.database, clock=lambda: NOW))
    template = tmp_path / "template.md"
    template.write_text("${cve_id}", encoding="utf-8")
    out = tmp_path / "statement.docx"
    assert (
        cli.main(
            [
                "--config",
                str(config.config_path),
                "watch",
                "statement",
                "CVE-2026-0001",
                "--template",
                str(template),
                "--out",
                str(out),
            ]
        )
        == 2
    )
    assert not out.exists()


def test_packaged_default_template_loads():
    text = default_template_text()
    assert text.startswith("# CVE statement: ${cve_id}")
    assert "${generated_at}" in text


def test_docx_replaces_placeholders_split_across_runs():
    document = (
        "<w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Client ${cve</w:t></w:r>"
        "<w:r><w:rPr><w:i/></w:rPr><w:t>_id}</w:t></w:r>"
        '<w:r><w:t xml:space="preserve"> end</w:t></w:r></w:p>'
    )
    result = render_docx(docx_bytes(document), all_fields())
    assert paragraph_texts(part(result, "word/document.xml")) == [
        "Client CVE-2026-0001 end"
    ]
    raw = part(result, "word/document.xml").decode("utf-8")
    assert '<w:rPr><w:b/></w:rPr><w:t xml:space="preserve">Client CVE-2026-0001</w:t>' in raw


def test_docx_replaces_header_footer_and_table_cell_placeholders():
    document = (
        "<w:tbl><w:tr><w:tc><w:p><w:r><w:t>${severity}</w:t></w:r></w:p>"
        "</w:tc></w:tr></w:tbl>"
    )
    header = f'<w:hdr xmlns:w="{W}"><w:p><w:r><w:t>${{cve_id}}</w:t></w:r></w:p></w:hdr>'
    footer = f'<w:ftr xmlns:w="{W}"><w:p><w:r><w:t>${{status}}</w:t></w:r></w:p></w:ftr>'
    result = render_docx(
        docx_bytes(document, header=header, footer=footer), all_fields()
    )
    assert paragraph_texts(part(result, "word/document.xml")) == ["critical"]
    assert paragraph_texts(part(result, "word/header1.xml")) == ["CVE-2026-0001"]
    assert paragraph_texts(part(result, "word/footer1.xml")) == ["published"]


def test_docx_multiline_values_become_breaks():
    result = render_docx(
        docx_bytes("<w:p><w:r><w:t>${references}</w:t></w:r></w:p>"),
        all_fields(),
    )
    raw = part(result, "word/document.xml").decode("utf-8")
    assert raw.count("<w:br/>") == 1
    assert paragraph_texts(part(result, "word/document.xml")) == [
        "https://a.example/xhttps://b.example/y"
    ]
    assert (
        '<w:t xml:space="preserve">https://a.example/x</w:t>'
        '<w:br/><w:t xml:space="preserve">https://b.example/y</w:t>'
    ) in raw


def test_docx_escapes_xml_special_characters():
    result = render_docx(
        docx_bytes("<w:p><w:r><w:t>${description}</w:t></w:r></w:p>"),
        all_fields(),
    )
    raw = part(result, "word/document.xml").decode("utf-8")
    assert "&lt;widget&gt;" in raw
    assert "&amp;" in raw
    assert paragraph_texts(part(result, "word/document.xml")) == [
        'Acme <widget> & "gadget"'
    ]


def test_docx_keeps_other_members_and_content_types_first():
    untouched = (
        '<w:p w:rsidR="00A1"><w:pPr><w:jc w:val="center"/></w:pPr>'
        '<w:r><w:t xml:space="preserve">A &#38; B</w:t></w:r></w:p>'
    )
    result = render_docx(
        docx_bytes(
            "<w:p><w:r><w:t>${cve_id}</w:t></w:r></w:p>" + untouched,
            content_types_last=True,
        ),
        all_fields(),
    )
    with zipfile.ZipFile(io.BytesIO(result)) as archive:
        names = archive.namelist()
        assert names[0] == "[Content_Types].xml"
        assert archive.read("word/styles.xml") == STYLES
        assert archive.read("docProps/core.xml") == b"<core/>"
        assert untouched.encode("utf-8") in archive.read("word/document.xml")
        for name in names:
            if name.endswith(".xml") or name.endswith(".rels"):
                ElementTree.fromstring(archive.read(name))


def test_docx_unknown_placeholder_lists_every_name():
    document = (
        "<w:p><w:r><w:t>${cve_id} ${nope}</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>${other}</w:t></w:r></w:p>"
    )
    header = f'<w:hdr xmlns:w="{W}"><w:p><w:r><w:t>${{in_header}}</w:t></w:r></w:p></w:hdr>'
    with pytest.raises(CVEBeaconError) as caught:
        render_docx(docx_bytes(document, header=header), all_fields())
    message = str(caught.value)
    assert "${nope}" in message
    assert "${other}" in message
    assert "${in_header}" in message


def test_docx_dollar_escape_and_unknown_extension(tmp_path):
    result = render_docx(
        docx_bytes("<w:p><w:r><w:t>$$5 ${cve_id}</w:t></w:r></w:p>"),
        all_fields(),
    )
    assert paragraph_texts(part(result, "word/document.xml")) == ["$5 CVE-2026-0001"]
    template = tmp_path / "template.rtf"
    template.write_text("${cve_id}", encoding="utf-8")
    with pytest.raises(CVEBeaconError, match="unsupported statement template type"):
        statements.template_kind(template)


def test_docx_member_size_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(statements, "MAX_MEMBER_BYTES", 10)
    with pytest.raises(CVEBeaconError, match="member larger"):
        render_docx(
            docx_bytes("<w:p><w:r><w:t>${cve_id}</w:t></w:r></w:p>"),
            all_fields(),
        )


def test_docx_cli_writes_a_docx(tmp_path):
    config = write_config(tmp_path, sources=("nvd",))
    populate(WatchStore(config.watch.database, clock=lambda: NOW))
    template = tmp_path / "template.docx"
    template.write_bytes(
        docx_bytes("<w:p><w:r><w:t>${cve_id}</w:t></w:r></w:p>")
    )
    out = tmp_path / "statement.docx"
    assert (
        cli.main(
            [
                "--config",
                str(config.config_path),
                "watch",
                "statement",
                "CVE-2026-0001",
                "--template",
                str(template),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert paragraph_texts(part(out.read_bytes(), "word/document.xml")) == [
        "CVE-2026-0001"
    ]


def test_docx_ignores_paragraph_tokens_inside_comments():
    document = "<!--" + "<w:p>" * 20_000 + "-->"
    header = (
        f'<w:hdr xmlns:w="{W}"><w:p><w:r>'
        "<w:t>${cve_id}</w:t></w:r></w:p></w:hdr>"
    )
    started = time.monotonic()
    result = render_docx(docx_bytes(document, header=header), all_fields())
    assert time.monotonic() - started < 5
    assert paragraph_texts(part(result, "word/header1.xml")) == [
        "CVE-2026-0001"
    ]


def test_docx_many_placeholders_in_one_run_stay_linear():
    fields = all_fields()
    fields["description"] = "x" * 1000
    document = (
        "<w:p><w:r><w:t>"
        + "${description}" * 10_000
        + "</w:t></w:r></w:p>"
    )
    started = time.monotonic()
    result = render_docx(docx_bytes(document), fields)
    assert time.monotonic() - started < 5
    raw = part(result, "word/document.xml")
    assert raw.count(b"x" * 1000) == 10_000


def test_docx_rejects_malformed_input():
    with pytest.raises(CVEBeaconError, match="malformed"):
        render_docx(
            docx_bytes("<w:p><w:r><w:t>${cve_id}</w:t>"), all_fields()
        )
    with pytest.raises(CVEBeaconError, match="malformed"):
        render_docx(docx_bytes("<!-- ${cve_id}"), all_fields())


def test_docx_rejects_doctype_and_entities_in_every_xml_member():
    document = (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE w:document [<!ENTITY a "b">]>'
        f'<w:document xmlns:w="{W}"><w:body><w:p>'
        "<w:instrText>&a;</w:instrText>"
        "</w:p></w:body></w:document>"
    )
    with pytest.raises(CVEBeaconError, match="DTD or XML entities"):
        render_docx(docx_zip(document), all_fields())
    styles = b'<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>'
    with pytest.raises(CVEBeaconError, match="word/styles.xml"):
        render_docx(
            docx_bytes(
                "<w:p><w:r><w:t>${cve_id}</w:t></w:r></w:p>",
                styles=styles,
            ),
            all_fields(),
        )


def test_docx_rejects_a_lying_member_size():
    template = docx_bytes(
        "<w:p><w:r><w:t>${cve_id}</w:t></w:r></w:p>",
        styles=b"\0" * 2_000_000,
        compression=zipfile.ZIP_DEFLATED,
    )
    with pytest.raises(CVEBeaconError, match="invalid member size"):
        render_docx(
            patch_central_size(template, "word/styles.xml", 1), all_fields()
        )


def test_docx_rejects_corrupt_deflate_in_processed_and_untouched_members():
    template = docx_zip(
        f'<w:document xmlns:w="{W}"><w:body><w:p><w:r>'
        "<w:t>${cve_id}</w:t></w:r></w:p></w:body></w:document>",
        compression=zipfile.ZIP_DEFLATED,
        extra={"word/media/image1.png": b"\0" * 4096},
    )
    for member in (
        "word/document.xml",
        "word/styles.xml",
        "word/media/image1.png",
    ):
        with pytest.raises(CVEBeaconError, match="unreadable member"):
            render_docx(corrupt_deflate(template, member), all_fields())


def test_docx_corrupt_deflate_exits_two_from_the_cli(tmp_path, capsys):
    config = write_config(tmp_path, sources=("nvd",))
    populate(WatchStore(config.watch.database, clock=lambda: NOW))
    template = tmp_path / "template.docx"
    template.write_bytes(
        corrupt_deflate(
            docx_bytes(
                "<w:p><w:r><w:t>${cve_id}</w:t></w:r></w:p>",
                compression=zipfile.ZIP_DEFLATED,
            ),
            "word/document.xml",
        )
    )
    out = tmp_path / "statement.docx"
    assert (
        cli.main(
            [
                "--config",
                str(config.config_path),
                "watch",
                "statement",
                "CVE-2026-0001",
                "--template",
                str(template),
                "--out",
                str(out),
            ]
        )
        == 2
    )
    assert "unreadable member" in capsys.readouterr().err
    assert not out.exists()


def test_atomic_write_refuses_a_racing_creation(tmp_path, monkeypatch):
    out = tmp_path / "statement.md"
    real_link = os.link

    def racing_link(src, dst):
        Path(dst).write_text("raced", encoding="utf-8")
        return real_link(src, dst)

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(CVEBeaconError, match="refusing to overwrite"):
        statements._atomic_write(out, b"new", force=False)
    assert out.read_text(encoding="utf-8") == "raced"
    assert not list(tmp_path.glob(".statement.md.*.tmp"))


@pytest.mark.skipif(os.name != "posix", reason="symlink behavior")
def test_atomic_write_does_not_replace_a_dangling_symlink(tmp_path):
    out = tmp_path / "statement.md"
    out.symlink_to(tmp_path / "missing.md")
    with pytest.raises(CVEBeaconError, match="refusing to overwrite"):
        statements._atomic_write(out, b"new", force=False)
    assert out.is_symlink()
    assert not (tmp_path / "missing.md").exists()


@pytest.mark.skipif(
    os.name != "posix" or not Path("/dev/zero").exists(),
    reason="special files",
)
def test_template_reader_rejects_special_files(tmp_path):
    zero = tmp_path / "zero.md"
    zero.symlink_to("/dev/zero")
    with pytest.raises(CVEBeaconError, match="regular file"):
        statements._read_template(zero)
    fifo = tmp_path / "fifo.md"
    try:
        os.mkfifo(fifo)
    except OSError:
        pytest.skip("named pipes are not available")
    with pytest.raises(CVEBeaconError, match="regular file"):
        statements._read_template(fifo)


def test_rendered_output_is_bounded(monkeypatch):
    monkeypatch.setattr(statements, "MAX_RENDERED_BYTES", 100)
    fields = all_fields()
    fields["description"] = "x" * 100
    with pytest.raises(CVEBeaconError, match="rendered statement is larger"):
        render_text("${description}${description}", fields)
    with pytest.raises(CVEBeaconError, match="rendered statement is larger"):
        render_docx(
            docx_bytes(
                "<w:p><w:r><w:t>${description}${description}</w:t></w:r></w:p>"
            ),
            fields,
        )


def test_rendered_output_error_exits_two_from_the_cli(tmp_path, monkeypatch):
    config = write_config(tmp_path, sources=("nvd",))
    populate(WatchStore(config.watch.database, clock=lambda: NOW))
    template = tmp_path / "template.md"
    template.write_text("${description}${description}", encoding="utf-8")
    monkeypatch.setattr(statements, "MAX_RENDERED_BYTES", 100)
    out = tmp_path / "statement.md"
    assert (
        cli.main(
            [
                "--config",
                str(config.config_path),
                "watch",
                "statement",
                "CVE-2026-0001",
                "--template",
                str(template),
                "--out",
                str(out),
            ]
        )
        == 2
    )
    assert not out.exists()


def test_docx_replaces_nested_paragraph_placeholders():
    document = (
        "<w:p><w:r><w:t>${severity}</w:t></w:r>"
        "<w:r><w:txbxContent><w:p><w:r><w:t>${cve_id}</w:t></w:r>"
        "</w:p></w:txbxContent></w:r>"
        "<w:r><w:t> tail ${status}</w:t></w:r></w:p>"
    )
    result = render_docx(docx_bytes(document), all_fields())
    root = ElementTree.fromstring(part(result, "word/document.xml"))
    texts = [node.text or "" for node in root.iter(f"{{{W}}}t")]
    assert "critical" in texts
    assert "CVE-2026-0001" in texts
    assert " tail published" in texts
    assert not any("${" in text for text in texts)


def test_docx_does_not_join_placeholders_across_paragraphs():
    document = (
        "<w:p><w:r><w:t>${cve</w:t></w:r>"
        "<w:r><w:txbxContent><w:p><w:r><w:t>_id}</w:t></w:r>"
        "</w:p></w:txbxContent></w:r></w:p>"
    )
    with pytest.raises(CVEBeaconError, match="invalid statement placeholder"):
        render_docx(docx_bytes(document), all_fields())


@pytest.mark.parametrize(
    "document",
    [
        (
            f'<w2:document xmlns:w2="{W}"><w2:body><w2:p><w2:r>'
            "<w2:t>${cve_id}</w2:t></w2:r></w2:p></w2:body></w2:document>"
        ),
        (
            f'<document xmlns="{W}"><body><p><r>'
            "<t>${cve_id}</t></r></p></body></document>"
        ),
    ],
)
def test_docx_handles_alternate_namespace_prefixes(document):
    result = render_docx(docx_zip(document), all_fields())
    raw = part(result, "word/document.xml")
    assert b"CVE-2026-0001" in raw
    assert b"${" not in raw


def test_docx_normalizes_mixed_line_endings():
    fields = all_fields()
    fields["references"] = "one\r\ntwo\rthree\nfour"
    result = render_docx(
        docx_bytes("<w:p><w:r><w:t>${references}</w:t></w:r></w:p>"),
        fields,
    )
    raw = part(result, "word/document.xml").decode("utf-8")
    assert raw.count("<w:br/>") == 3
    assert "\r" not in raw


def test_url_fields_percent_quote_identifiers():
    view = WatchView(
        cve_id="CVE-2026-1) odd",
        status="published",
        euvd_id="EUVD-1 )",
    )
    fields = build_fields(view, first_seen=None, generated_at=NOW)
    assert fields["nvd_url"] == (
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1%29%20odd"
    )
    assert fields["cve_org_url"] == (
        "https://www.cve.org/CVERecord?id=CVE-2026-1%29%20odd"
    )
    assert fields["euvd_url"] == (
        "https://euvd.enisa.europa.eu/vulnerability/EUVD-1%20%29"
    )
    assert fields["euvd_id"] == "EUVD-1 )"


def test_docx_bare_dollar_error_mentions_doubling():
    with pytest.raises(CVEBeaconError) as caught:
        render_docx(
            docx_bytes("<w:p><w:r><w:t>Budget $5 ${cve_id}</w:t></w:r></w:p>"),
            all_fields(),
        )
    assert "write '$$'" in str(caught.value)


def bounded_render(template: bytes, fields=None, *, expect_error=True) -> dict:
    """Keep adversarial regressions inside a time and address-space bound."""
    script = '''
import base64, json, sys, time
try:
    import resource
except ImportError:
    resource = None
if resource:
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
from cvebeacon.errors import CVEBeaconError
from cvebeacon.watch.statements import render_docx
request = json.load(sys.stdin)
started = time.monotonic()
try:
    render_docx(base64.b64decode(request["template"]), request["fields"])
except CVEBeaconError as exc:
    error = str(exc)
else:
    error = None
peak = None
if sys.platform == "linux":
    from pathlib import Path
    peak = int(next(line.split()[1] for line in Path("/proc/self/status").read_text().splitlines()
                    if line.startswith("VmHWM:")))
print(json.dumps({"error": error, "seconds": time.monotonic() - started, "peak_kib": peak}))
'''
    completed = subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps({
            "template": base64.b64encode(template).decode("ascii"),
            "fields": fields or all_fields(),
        }),
        capture_output=True, text=True, timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert (result["error"] is not None) == expect_error
    assert result["seconds"] < 10
    if sys.platform == "linux":
        assert result["peak_kib"] < 128 * 1024
    return result


@pytest.mark.parametrize("suffix", ["></other>", '="unterminated'])
def test_docx_bounds_malformed_attribute_work(suffix):
    result = bounded_render(docx_bytes("<other " + "a" * 16_000 + suffix))
    assert "malformed" in result["error"]


def test_docx_bounds_unique_namespace_depth():
    body = "".join(f'<n xmlns:p{i}="urn:{i}">' for i in range(5000))
    result = bounded_render(docx_bytes(body + "</n>" * 5000))
    assert "limit" in result["error"]


@pytest.mark.parametrize("value", ["X" + "\n" * 999, "&" * 1000])
def test_docx_bounds_serialized_replacements(value):
    fields = all_fields()
    fields["description"] = value
    count = 2000 if "\n" in value else 11_000
    result = bounded_render(docx_bytes(
        "<w:p><w:r><w:t>" + "${description}" * count + "</w:t></w:r></w:p>"
    ), fields)
    assert "rendered statement is larger" in result["error"]


@pytest.mark.parametrize("text_tag", [
    f'<x:t xmlns:x="{W}">',
    f'<t xmlns="{W}">',
])
@pytest.mark.parametrize("outer_binding", ["", ' xmlns:x="urn:other"'])
def test_docx_break_namespace_survives_local_text_binding(text_tag, outer_binding):
    close = "</x:t>" if text_tag.startswith("<x:") else "</t>"
    document = (f'<w:document xmlns:w="{W}"{outer_binding}><w:body><w:p><w:r>'
                + text_tag + "${references}" + close
                + "</w:r></w:p></w:body></w:document>")
    fields = all_fields()
    fields["references"] = "one\ntwo"
    root = ElementTree.fromstring(part(render_docx(docx_zip(document), fields), "word/document.xml"))
    run = root.find(f".//{{{W}}}r")
    assert [node.tag for node in run] == [f"{{{W}}}t", f"{{{W}}}br", f"{{{W}}}t"]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"])
def test_docx_preserves_supported_encoding_and_untouched_bytes(encoding):
    declaration = "UTF-8" if encoding.startswith("utf-8") else "UTF-16"
    untouched = '<w:p odd="&gt;"><w:r><w:t><![CDATA[café & <]]></w:t></w:r></w:p>'
    document = (f'<?xml version="1.0" encoding="{declaration}"?>'
                f'<w:document xmlns:w="{W}"><w:body>{untouched}'
                '<w:p><w:r><w:t>${description}</w:t></w:r></w:p></w:body></w:document>')
    raw = document.encode(encoding)
    fields = all_fields()
    fields["description"] = "café ☃"
    output = part(render_docx(docx_zip(raw), fields), "word/document.xml")
    assert paragraph_texts(output) == ["café & <", "café ☃"]
    assert untouched in output.decode(encoding)
    codec = "utf-8" if encoding == "utf-8-sig" else "utf-16-le" if encoding == "utf-16" else encoding
    assert untouched.encode(codec) in output
    assert output.startswith(raw[:raw.index("<w:document".encode(codec))])


@pytest.mark.parametrize("encoding", ["ISO-8859-1", "not-a-real-encoding", "UTF-32", "UTF-7"])
def test_docx_rejects_unsupported_encoding_clearly(encoding):
    document = (f'<?xml version="1.0" encoding="{encoding}"?>'
                f'<w:document xmlns:w="{W}"><w:p><w:r><w:t>${{description}}</w:t>'
                '</w:r></w:p></w:document>')
    fields = all_fields()
    fields["description"] = "café"
    result = bounded_render(docx_zip(document), fields)
    assert "encoding" in result["error"]


@pytest.mark.parametrize("content", [
    "<![CDATA[${cve_id}]]>",
    "${cve<!-- split -->_id}",
    "${cve<?test value?>_id}",
    "&#36;{cve_id}",
])
def test_docx_logical_text_includes_cdata_and_ignores_comments_and_pis(content):
    result = render_docx(docx_bytes(f"<w:p><w:r><w:t>{content}</w:t></w:r></w:p>"), all_fields())
    assert paragraph_texts(part(result, "word/document.xml")) == ["CVE-2026-0001"]


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_docx_rejects_adjusted_size_lie_without_truncating(method):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=method) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("word/document.xml", f'<w:document xmlns:w="{W}"/>')
        with archive.open("word/media/image.png", "w") as member:
            for _ in range(64 if method == zipfile.ZIP_DEFLATED else 2):
                member.write(b"\0" * 1024**2)
    template = output.getvalue()
    with zipfile.ZipFile(io.BytesIO(template)) as archive:
        declared = archive.getinfo("word/media/image.png").compress_size // 2
    result = bounded_render(patch_central_size(template, "word/media/image.png", declared))
    assert "member" in result["error"]


@pytest.mark.parametrize("invalid", ["&#0;", "&#xD800;", "\x01", "&unknown;"])
@pytest.mark.parametrize("prefix", ["", "${cve_id} "])
def test_docx_rejects_invalid_original_xml_even_when_replacing(invalid, prefix):
    with pytest.raises(CVEBeaconError, match="malformed"):
        render_docx(docx_bytes(f"<w:p><w:r><w:t>{prefix}{invalid}</w:t></w:r></w:p>"), all_fields())


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("member", ["word/styles.xml", "_rels/custom.rels"])
def test_docx_rejects_encoded_dtd_in_untouched_xml(encoding, member):
    declaration = "UTF-8" if encoding == "utf-8" else "UTF-16"
    raw = (f'<?xml version="1.0" encoding="{declaration}"?>'
           '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///nonexistent">]><x>&e;</x>').encode(encoding)
    with pytest.raises(CVEBeaconError, match="DTD or XML entities"):
        template = docx_zip(f'<w:document xmlns:w="{W}"/>', styles=raw) if member == "word/styles.xml" else docx_zip(f'<w:document xmlns:w="{W}"/>', extra={member: raw})
        render_docx(template, all_fields())


def test_docx_randomized_split_runs_match_string_template():
    rng = random.Random(20261104)
    fields = all_fields()
    fields["description"] = "A & B < C\nnext café"
    tokens = ["${cve_id}", "$severity", "${description}", "$$", "$${unknown}", "café & < >", " tail "]
    for _ in range(500):
        text = " ".join(rng.choices(tokens, k=rng.randint(1, 15)))
        splits = sorted({0, len(text), *(rng.randrange(len(text) + 1) for _ in range(20))})
        runs = "".join('<w:r><w:rPr><w:b/></w:rPr><w:t>' + escape(text[a:b]) + '</w:t></w:r>'
                       for a, b in zip(splits, splits[1:]))
        root = ElementTree.fromstring(part(render_docx(docx_bytes(f"<w:p>{runs}</w:p>"), fields), "word/document.xml"))
        actual = "".join("\n" if node.tag == f"{{{W}}}br" else node.text or ""
                         for node in root.iter() if node.tag in (f"{{{W}}}t", f"{{{W}}}br"))
        assert actual == Template(text).substitute(fields)
        assert all(run.find(f"{{{W}}}rPr/{{{W}}}b") is not None for run in root.iter(f"{{{W}}}r"))


def test_docx_bounds_namespace_work_for_flat_siblings():
    declarations = " ".join(f'xmlns:p{i}="urn:{i}"' for i in range(5000))
    siblings = '<n xmlns:local="urn:local"/>' * 30_000
    document = f'<w:document xmlns:w="{W}" {declarations}>{siblings}</w:document>'
    bounded_render(docx_zip(document), expect_error=False)


def test_docx_bounds_element_count():
    bounded_render(docx_bytes("<n/>" * 100_001))


@pytest.mark.parametrize("location", ["document", "styles"])
def test_docx_resource_limits_also_cover_empty_elements_and_namespaces(monkeypatch, location):
    monkeypatch.setattr(statements, "MAX_XML_SPANS", 32)
    body = "<n/>" * 33
    template = docx_bytes(body) if location == "document" else docx_bytes("", styles=f"<s>{body}</s>".encode())
    with pytest.raises(CVEBeaconError, match="span limit"):
        render_docx(template, all_fields())
    namespaces = " ".join(f'xmlns:p{i}="urn:{i}"' for i in range(33))
    with pytest.raises(CVEBeaconError, match="span limit"):
        render_docx(docx_bytes(f"<n {namespaces}/>"), all_fields())


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_docx_counts_literal_escaping_and_repeated_attributes_before_allocation(monkeypatch, encoding):
    # The short replacement is harmless; literal newlines repeat large t attributes.
    document = (f'<?xml version="1.0" encoding="{"UTF-8" if encoding == "utf-8" else "UTF-16"}"?>'
                f'<w:document xmlns:w="{W}"><w:p><w:r>'
                f'<w:t odd="{"x" * 1000}">${{cve_id}}' + "\n" * 100
                + '</w:t></w:r></w:p></w:document>').encode(encoding)
    monkeypatch.setattr(statements, "MAX_RENDERED_BYTES", 16_000)
    with pytest.raises(CVEBeaconError, match="rendered statement is larger"):
        render_docx(docx_zip(document), all_fields())


def test_docx_rejects_incomplete_deflate_stream():
    # Keep the declared CRC/size unchanged; only stream completion is inconsistent.
    template = docx_bytes("<w:p/>", compression=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(io.BytesIO(template)) as archive:
        info = archive.getinfo("word/document.xml")
    truncated = patch_central_size(
        template, info.filename, compressed_size=info.compress_size - 1,
    )
    with pytest.raises(CVEBeaconError, match="unreadable member"):
        render_docx(truncated, all_fields())


def test_docx_bounds_substitution_fragment_count():
    bounded_render(docx_bytes("<w:p><w:r><w:t>" + "$$" * 100_001 + "</w:t></w:r></w:p>"))


def test_docx_refuses_duplicate_package_members():
    with pytest.warns(UserWarning, match="Duplicate name"):
        template = docx_zip(
            f'<w:document xmlns:w="{W}"/>',
            extra={"word/document.xml": f'<w:document xmlns:w="{W}"/>'},
        )
    with pytest.raises(CVEBeaconError, match="duplicate"):
        render_docx(template, all_fields())


@pytest.mark.parametrize("member", ["word/styles.xml", "word/document.xml"])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_docx_bounds_attribute_tables_before_parsing(member, encoding):
    attrs = " ".join(f'a{i}=""' for i in range(100_000))
    raw = f'<x {attrs}/>'.encode(encoding)
    template = docx_zip(raw) if member.endswith("document.xml") else docx_zip(
        f'<w:document xmlns:w="{W}"/>', styles=raw,
    )
    result = bounded_render(template)
    assert "limit" in result["error"]


@pytest.mark.parametrize("kind", ["element_bytes", "part_count", "part_bytes", "package_count", "package_bytes"])
def test_docx_checks_attribute_budgets_before_parser_allocation(monkeypatch, kind):
    # Valid lexical input, but the parser must never see a table above the limit.
    body = '<x a="' + "q" * 200 + '"/>' if kind.endswith("bytes") else '<x a="" b=""/>' * 20
    extra = {}
    if kind.startswith("package"):
        extra = {"word/header1.xml": f"<h>{body}</h>", "word/footer1.xml": f"<h>{body}</h>"}
    limit = "MAX_" + {
        "element_bytes": "ELEMENT_ATTRIBUTE_BYTES", "part_count": "PART_ATTRIBUTES",
        "part_bytes": "PART_ATTRIBUTE_BYTES", "package_count": "PACKAGE_ATTRIBUTES",
        "package_bytes": "PACKAGE_ATTRIBUTE_BYTES",
    }[kind]
    monkeypatch.setattr(statements, limit, 300 if kind == "package_bytes" else 100 if kind.endswith("bytes") else 50 if kind.startswith("package") else 30, raising=False)
    with pytest.raises(CVEBeaconError, match="attribute.*limit"):
        render_docx(docx_bytes(body, ) if not extra else docx_zip(
            f'<w:document xmlns:w="{W}"/>', extra=extra,
        ), all_fields())


def test_docx_releases_parts_and_applies_a_global_record_budget():
    header = f'<w:hdr xmlns:w="{W}"><w:p><w:r>' + '<w:t/>' * 99_000 + '</w:r></w:p></w:hdr>'
    extra = {f"word/header{i}.xml": header for i in range(1, 9)}
    result = bounded_render(docx_zip(
        f'<w:document xmlns:w="{W}"/>', extra=extra, compression=zipfile.ZIP_DEFLATED,
    ))
    assert "limit" in result["error"]


def test_docx_retains_only_the_current_part_scan(monkeypatch):
    import gc
    import tracemalloc
    header = f'<w:hdr xmlns:w="{W}"><w:p><w:r>' + '<w:t>x</w:t>' * 25_000 + '</w:r></w:p></w:hdr>'
    template = docx_zip(f'<w:document xmlns:w="{W}"/>', extra={
        f"word/header{i}.xml": header for i in range(1, 7)
    }, compression=zipfile.ZIP_DEFLATED)
    gc.collect()
    tracemalloc.start()
    try:
        render_docx(template, all_fields())
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 32 * 1024**2


def corrupt_container(template: bytes, kind: str) -> bytes:
    data = bytearray(template)
    central = data.index(b"PK\x01\x02")
    if kind == "offset":
        end = data.rindex(b"PK\x05\x06")
        offset = struct.unpack_from("<I", data, end + 16)[0]
        struct.pack_into("<I", data, end + 16, offset + 20_000)
    elif kind == "version":
        struct.pack_into("<H", data, central + 6, 151)
    else:
        flags = struct.unpack_from("<H", data, central + 8)[0]
        struct.pack_into("<H", data, central + 8, flags | 0x800)
        data[central + 46] = 0xff
    return bytes(data)


@pytest.mark.parametrize("kind", ["offset", "version", "filename"])
def test_docx_sanitizes_corrupt_container_errors(kind):
    result = bounded_render(corrupt_container(docx_bytes("<w:p/>"), kind))
    assert "statement template" in result["error"]
    assert not any(word in result["error"] for word in ("seek", "15.1", "codec"))


@pytest.mark.parametrize("failure", [ValueError, NotImplementedError, UnicodeDecodeError, struct.error, zlib.error, RuntimeError, EOFError, zipfile.LargeZipFile])
def test_docx_sanitizes_all_container_open_errors(monkeypatch, failure):
    template = docx_bytes("<w:p/>")
    error = failure("utf-8", b"\xff", 0, 1, "invalid") if failure is UnicodeDecodeError else failure("private details")
    def broken(*args, **kwargs):
        raise error
    monkeypatch.setattr(zipfile, "ZipFile", broken)
    with pytest.raises(CVEBeaconError, match="not a readable .docx") as caught:
        render_docx(template, all_fields())
    assert "private details" not in str(caught.value)


@pytest.mark.parametrize("distinct", [False, True])
@pytest.mark.parametrize("location", ["element", "attribute"])
def test_docx_bounds_namespace_expansion_before_allocation(distinct, location):
    uri = "urn:" + "x" * 32_000
    if location == "element":
        body = "".join(f'<x:n{i if distinct else 0}/>' for i in range(16_000))
    else:
        body = '<n ' + " ".join(f'x:a{i}=""' for i in range(8000)) + '/>'
    styles = f'<s xmlns:x="{uri}">{body}</s>'.encode()
    result = bounded_render(docx_zip(f'<w:document xmlns:w="{W}"/>', styles=styles))
    assert "limit" in result["error"]


@pytest.mark.parametrize("distinct", [False, True])
def test_docx_bounds_cumulative_expanded_name_bytes(monkeypatch, distinct):
    body = '<s xmlns:x="urn:long-binding">' + "".join(
        f'<x:n{i if distinct else 0} x:attr=""/>' for i in range(200)
    ) + '</s>'
    monkeypatch.setattr(statements, "MAX_PART_EXPANDED_BYTES", 1024, raising=False)
    def forbidden(*args, **kwargs):
        pytest.fail("expanded-name budget must be checked before creating the parser")
    monkeypatch.setattr(statements.expat, "ParserCreate", forbidden)
    with pytest.raises(CVEBeaconError, match="expanded.*limit"):
        statements._parse_xml(body.encode(), "styles.xml")


@pytest.mark.parametrize("location", ["paragraph", "parts", "long_name"])
def test_docx_bounds_unknown_diagnostic_storage(location):
    if location == "long_name":
        text = "${" + "a" * 200_000 + "}"
        template = docx_bytes(f'<w:p><w:r><w:t>{text}</w:t></w:r></w:p>')
    elif location == "paragraph":
        text = "".join(f'${{unknown{i}}}' for i in range(300_000))
        template = docx_bytes(f'<w:p><w:r><w:t>{text}</w:t></w:r></w:p>')
    else:
        extra = {f"word/header{i}.xml": f'<w:hdr xmlns:w="{W}">' + "".join(
            f'<w:p><w:r><w:t>${{unknown{i}_{j}}}</w:t></w:r></w:p>' for j in range(100)
        ) + '</w:hdr>' for i in range(8)}
        template = docx_zip(f'<w:document xmlns:w="{W}"/>', extra=extra)
    result = bounded_render(template)
    assert "limit" in result["error"]
    assert len(result["error"]) < 256


def test_docx_initial_check_applies_placeholder_limit(monkeypatch):
    monkeypatch.setattr(statements, "MAX_XML_SPANS", 20)
    text = "${unknown}" * 21
    with pytest.raises(CVEBeaconError, match="placeholder.*limit"):
        render_docx(docx_bytes(f'<w:p><w:r><w:t>{text}</w:t></w:r></w:p>'), all_fields())


def test_docx_accepts_namespace_uri_with_pipe():
    raw = b'<s xmlns:x="urn:a|b"><x:a/></s>'
    output = render_docx(docx_bytes("<w:p/>", styles=raw), all_fields())
    assert part(output, "word/styles.xml") == raw


@pytest.mark.parametrize("timestamp,expected", [
    ("2026-11-04T00:30:00+02:00", "2026-11-03"),
    ("2026-11-03T23:30:00-02:00", "2026-11-04"),
    ("2026-11-04T12:34:56Z", "2026-11-04"),
    ("2026-11-04T12:34:56.123", "2026-11-04"),
    ("2026-11-04", "2026-11-04"), (None, MISSING), ("invalid", MISSING),
])
def test_statement_date_fields_are_utc_and_preserve_timestamps(timestamp, expected):
    fields = build_fields(WatchView(cve_id="CVE-2026-1234", status="published", published=timestamp, last_modified=timestamp), first_seen=timestamp, generated_at=NOW)
    for name in ("published", "first_seen", "last_modified"):
        assert fields[name + "_date"] == expected
        assert fields[name] == (timestamp or MISSING)


def test_default_statement_uses_utc_date_fields(tmp_path):
    fields = fields_for(full_store(tmp_path))
    text = render_text(default_template_text(), fields)
    assert "- Published: 2026-10-28\n" in text
    assert "- First seen: 2026-11-03\n" in text
    assert "- Last modified: 2026-11-03\n" in text


def test_bounded_render_ignores_inherited_high_water_mark():
    script = '''
import sys
sys.path.insert(0, "tests")
import test_watch_statements as t
allocation = bytearray(160 * 1024**2)
del allocation
t.bounded_render(t.docx_bytes("<w:p/>"), expect_error=False)
'''
    completed = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=15)
    assert completed.returncode == 0, completed.stderr


def test_docx_bounds_aggregate_unknown_name_bytes():
    extra = {f"word/header{i}.xml": f'<w:hdr xmlns:w="{W}">' + "".join(
        '<w:p><w:r><w:t>${unknown_' + str(i) + '_' + str(j) + '_' + 'x' * 400 + '}</w:t></w:r></w:p>'
        for j in range(20)
    ) + '</w:hdr>' for i in range(4)}
    result = bounded_render(docx_zip(f'<w:document xmlns:w="{W}"/>', extra=extra))
    assert "diagnostic limit" in result["error"]


@pytest.mark.parametrize("kind", ["offset", "version", "filename"])
def test_corrupt_container_exits_two_and_preserves_output(tmp_path, capsys, kind):
    config = write_config(tmp_path, sources=("nvd",))
    populate(WatchStore(config.watch.database, clock=lambda: NOW))
    template = tmp_path / "bad.docx"
    template.write_bytes(corrupt_container(docx_bytes("<w:p/>"), kind))
    out = tmp_path / "statement.docx"
    out.write_bytes(b"old")
    assert cli.main([
        "--config", str(config.config_path), "watch", "statement", "CVE-2026-0001",
        "--template", str(template), "--out", str(out), "--force",
    ]) == 2
    error = capsys.readouterr().err
    assert "statement template" in error
    assert "Traceback" not in error
    assert out.read_bytes() == b"old"


def test_docx_applies_package_expanded_name_budget_before_next_parser(monkeypatch):
    raw = b'<s xmlns:x="urn:small"><x:a x:b=""/></s>'
    budget = statements._XMLBudget()
    statements._parse_xml(raw, "first.xml", budget=budget)
    monkeypatch.setattr(statements, "MAX_PACKAGE_EXPANDED_BYTES", budget.expanded_bytes + 1)
    def forbidden(*args, **kwargs):
        pytest.fail("package name budget must be checked before the next parser")
    monkeypatch.setattr(statements.expat, "ParserCreate", forbidden)
    with pytest.raises(CVEBeaconError, match="expanded.*limit"):
        statements._parse_xml(raw, "second.xml", budget=budget)


def test_docx_counts_short_namespace_expansion_before_allocation():
    styles = '<s xmlns:x="urn:' + 'u' * 252 + '">' + ''.join(
        f'<x:n{i}/>' for i in range(40_000)
    ) + '</s>'
    result = bounded_render(docx_bytes("<w:p/>", styles=styles.encode()))
    assert "expanded name byte limit" in result["error"]


@pytest.mark.parametrize("kind", ["count", "bytes"])
def test_attribute_guard_runs_before_parser_creation(monkeypatch, kind):
    monkeypatch.setattr(statements, "MAX_ELEMENT_ATTRIBUTES", 4)
    monkeypatch.setattr(statements, "MAX_ELEMENT_ATTRIBUTE_BYTES", 100)
    raw = b'<s a="" b="" c="" d="" e=""/>' if kind == "count" else b'<s a="' + b'x' * 101 + b'"/>'
    def forbidden(*args, **kwargs):
        pytest.fail("attribute budget must be checked before Expat allocates")
    monkeypatch.setattr(statements.expat, "ParserCreate", forbidden)
    with pytest.raises(CVEBeaconError, match="attribute.*limit"):
        statements._parse_xml(raw, "styles.xml")


def test_xml_input_budget_runs_before_member_decompression(monkeypatch):
    template = docx_zip('<x>' + 'z' * 1000 + '</x>')
    monkeypatch.setattr(statements, "MAX_XML_BYTES", 700)
    original = statements._read_member
    def reader(source, info):
        assert info.filename != "word/document.xml", "oversized XML was decompressed"
        return original(source, info)
    monkeypatch.setattr(statements, "_read_member", reader)
    with pytest.raises(CVEBeaconError, match="input byte limit"):
        render_docx(template, all_fields())


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("name_size,delimiters", [(8000, 8000), (128000, 8192)], ids=["balanced", "long_name"])
def test_docx_bounds_repeated_attribute_delimiters(encoding, name_size, delimiters):
    raw = ('<s ' + 'a' * name_size + '=' * delimiters + '/>').encode(encoding)
    result = bounded_render(docx_bytes('', styles=raw, compression=zipfile.ZIP_DEFLATED))
    assert result["seconds"] < 1.0


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_preflight_accounts_for_each_name_token_once(monkeypatch, encoding):
    raw = ('<s ' + 'a' * 4000 + '=' * 4000 + '/>').encode(encoding)
    width = statements._utf8_width
    calls = 0
    def counted(char):
        nonlocal calls
        calls += 1
        assert calls <= 3 * len(raw), "the same name was rescanned"
        return width(char)
    monkeypatch.setattr(statements, "_utf8_width", counted)
    with pytest.raises(CVEBeaconError):
        statements._parse_xml(raw, "styles.xml")


def test_preflight_applies_name_budget_inside_opening_tag(monkeypatch):
    monkeypatch.setattr(statements, "MAX_PART_EXPANDED_BYTES", 80)
    width = statements._utf8_width
    calls = 0
    def counted(char):
        nonlocal calls
        calls += 1
        assert calls < 100, "expanded-name limit was deferred until the tag ended"
        return width(char)
    monkeypatch.setattr(statements, "_utf8_width", counted)
    with pytest.raises(CVEBeaconError, match="expanded name.*limit"):
        statements._parse_xml(b'<s a="' + b'x' * 100_000 + b'"/>', "styles.xml")


def zip64_directory(template: bytes) -> bytes:
    end = template.rindex(b"PK\x05\x06")
    count = struct.unpack_from("<H", template, end + 10)[0]
    size, offset = struct.unpack_from("<II", template, end + 12)
    record = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, size, offset)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, end, 1)
    footer = bytearray(template[end:])
    struct.pack_into("<HHII", footer, 8, 0xffff, 0xffff, 0xffffffff, 0xffffffff)
    return template[:end] + record + locator + footer


@pytest.mark.parametrize("zip64", [False, True])
@pytest.mark.parametrize("lie", [False, True])
def test_docx_bounds_member_count_before_directory_allocation(zip64, lie):
    template = docx_zip(f'<w:document xmlns:w="{W}"/>', extra={
        f"media/{i}.bin": b"" for i in range(10_001)
    })
    if zip64:
        template = zip64_directory(template)
    if lie:
        data = bytearray(template)
        if zip64:
            end = data.rindex(b"PK\x06\x06")
            struct.pack_into("<QQ", data, end + 24, 1, 1)
        else:
            end = data.rindex(b"PK\x05\x06")
            struct.pack_into("<HH", data, end + 8, 1, 1)
        template = bytes(data)
    result = bounded_render(template)
    assert "member count limit" in result["error"]
    assert result["seconds"] < 1.0


def test_member_count_limit_precedes_zipfile_constructor(monkeypatch):
    template = docx_zip(f'<w:document xmlns:w="{W}"/>', extra={f"{i}.bin": b"" for i in range(20)})
    monkeypatch.setattr(statements, "MAX_ZIP_MEMBERS", 10, raising=False)
    def forbidden(*args, **kwargs):
        pytest.fail("ZipFile constructed directory metadata before the count check")
    monkeypatch.setattr(zipfile, "ZipFile", forbidden)
    with pytest.raises(CVEBeaconError, match="member count limit"):
        render_docx(template, all_fields())


@pytest.mark.parametrize("zip64", [False, True])
@pytest.mark.parametrize("prefix", [b"", b"prefix-data"])
def test_zip_directory_preflight_accepts_comments_and_prefixes(zip64, prefix):
    template = docx_bytes('<w:p><w:r><w:t>${cve_id}</w:t></w:r></w:p>')
    if zip64:
        template = zip64_directory(template)
    data = bytearray(template)
    end = data.rindex(b"PK\x05\x06")
    comment = b"package comment"
    struct.pack_into("<H", data, end + 20, len(comment))
    result = render_docx(prefix + bytes(data) + comment, all_fields())
    assert paragraph_texts(part(result, "word/document.xml")) == ["CVE-2026-0001"]
    with zipfile.ZipFile(io.BytesIO(result)) as archive:
        assert archive.comment == comment


@pytest.mark.parametrize("failure", [ValueError, OSError, struct.error, zlib.error])
def test_output_zip_close_errors_are_labeled_and_bounded(monkeypatch, failure):
    import tracemalloc
    real_zip = zipfile.ZipFile
    template = docx_bytes('<w:p/>')
    class BrokenClose(real_zip):
        def close(self):
            fail = self.mode == "w" and self.fp is not None
            super().close()
            if fail:
                raise failure("private output failure")
    monkeypatch.setattr(zipfile, "ZipFile", BrokenClose)
    tracemalloc.start()
    started = time.monotonic()
    try:
        with pytest.raises(CVEBeaconError, match="could not write statement") as caught:
            render_docx(template, all_fields())
        assert "private output failure" not in str(caught.value)
        assert tracemalloc.get_traced_memory()[1] < 8 * 1024**2
        assert time.monotonic() - started < 1.0
    finally:
        tracemalloc.stop()


def test_cli_memory_backstop_has_a_clean_exit_under_a_hard_limit():
    script = '''
import json, sys
from pathlib import Path
try:
    import resource
except ImportError:
    resource = None
from cvebeacon import cli
if resource:
    resource.setrlimit(resource.RLIMIT_AS, (96 * 1024**2, 96 * 1024**2))
def exhaust(args):
    if resource:
        bytearray(128 * 1024**2)
    raise MemoryError("private allocation details")
cli.run = exhaust
code = cli.main(["watch", "statement", "CVE-2026-0001", "--out", "unused.md"])
peak = None
if sys.platform == "linux":
    peak = int(next(line.split()[1] for line in Path("/proc/self/status").read_text().splitlines() if line.startswith("VmHWM:")))
print(json.dumps({"code": code, "peak": peak}))
'''
    completed = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=5)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["code"] == 2
    assert "not enough memory" in completed.stderr
    assert "Traceback" not in completed.stderr
    assert "private allocation details" not in completed.stderr
    if result["peak"] is not None:
        assert result["peak"] < 64 * 1024


@pytest.mark.parametrize("kind", ["matches", "unknowns"])
def test_text_template_limits_are_bounded_and_have_neutral_errors(kind):
    import tracemalloc
    text = '${description}' * 100_001 if kind == 'matches' else ''.join(f'${{unknown{i}}}' for i in range(300_000))
    tracemalloc.start()
    started = time.monotonic()
    try:
        with pytest.raises(CVEBeaconError, match="limit") as caught:
            render_text(text, all_fields())
        assert "XML" not in str(caught.value)
        assert tracemalloc.get_traced_memory()[1] < 8 * 1024**2
        assert time.monotonic() - started < 3
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("failure", [ValueError, MemoryError])
def test_statement_output_close_failure_keeps_existing_file(tmp_path, capsys, monkeypatch, failure):
    import tracemalloc
    config = write_config(tmp_path, sources=("nvd",))
    populate(WatchStore(config.watch.database, clock=lambda: NOW))
    template = tmp_path / "template.docx"
    template.write_bytes(docx_bytes('<w:p/>'))
    out = tmp_path / "statement.docx"
    out.write_bytes(b"old")
    real_zip = zipfile.ZipFile
    class BrokenClose(real_zip):
        def close(self):
            fail = self.mode == 'w' and self.fp is not None
            super().close()
            if fail:
                raise failure('private close details')
    monkeypatch.setattr(zipfile, 'ZipFile', BrokenClose)
    started = time.monotonic()
    tracemalloc.start()
    try:
        assert cli.main([
            '--config', str(config.config_path), 'watch', 'statement', 'CVE-2026-0001',
            '--template', str(template), '--out', str(out), '--force',
        ]) == 2
        # Include the bounded 20 MiB template-reader buffer.
        assert tracemalloc.get_traced_memory()[1] < 32 * 1024**2
        assert time.monotonic() - started < 1.0
    finally:
        tracemalloc.stop()
    error = capsys.readouterr().err
    assert ('not enough memory' if failure is MemoryError else 'could not write statement') in error
    assert 'private close details' not in error
    assert 'Traceback' not in error
    assert out.read_bytes() == b'old'


@pytest.mark.parametrize('prefix', [b'', b'prefix'])
def test_member_count_guard_handles_legacy_zip64_end_location(monkeypatch, prefix):
    template = prefix + zip64_directory(docx_bytes('<w:p/>'))
    original = zipfile._EndRecData
    def legacy(handle):
        end = original(handle)
        end[zipfile._ECD_LOCATION] = template.rindex(b'PK\x05\x06')
        return end
    monkeypatch.setattr(zipfile, '_EndRecData', legacy)
    statements._check_zip_directory(template)


def test_member_count_accepts_exact_limit_and_rejects_one_more(monkeypatch):
    template = docx_bytes('<w:p/>')
    with zipfile.ZipFile(io.BytesIO(template)) as archive:
        count = len(archive.infolist())
    monkeypatch.setattr(statements, 'MAX_ZIP_MEMBERS', count)
    render_docx(template, all_fields())
    monkeypatch.setattr(statements, 'MAX_ZIP_MEMBERS', count - 1)
    with pytest.raises(CVEBeaconError, match='member count limit'):
        render_docx(template, all_fields())


def test_statement_uses_current_report_mark_after_rebase(tmp_path, capsys):
    config = write_config(tmp_path, sources=("nvd",))
    store = populate(WatchStore(config.watch.database, clock=lambda: NOW))
    out = tmp_path / 'statement.md'
    arguments = ['--config', str(config.config_path), 'watch', 'statement', 'CVE-2026-0001', '--out', str(out), '--force']
    assert cli.main(arguments) == 0
    assert 'Reported to clients: not reported' in out.read_text()
    mark = store.report_cve('CVE-2026-0001', by='operator@example.invalid').entry
    assert cli.main(arguments) == 0
    text = out.read_text()
    assert 'Reported to clients: yes' in text
    assert 'Reported by: operator@example.invalid' in text
    assert f'Reported at: {mark.at}' in text
    store.unreport_cve('CVE-2026-0001', by='operator@example.invalid')
    assert cli.main(arguments) == 0
    text = out.read_text()
    assert 'Reported to clients: not reported' in text
    assert 'Reported by: not reported' in text
    assert 'Reported at: not reported' in text
    capsys.readouterr()


def test_statement_reads_first_seen_from_the_stored_view(tmp_path, monkeypatch):
    from dataclasses import replace
    store = full_store(tmp_path)
    view = replace(store.view('CVE-2026-0001', catalogs=SOURCES), first_seen='2026-11-04T00:30:00+02:00')
    monkeypatch.setattr(store, 'view', lambda *args, **kwargs: view)
    def forbidden(*args, **kwargs):
        pytest.fail('statement queried a second first-seen snapshot')
    monkeypatch.setattr(store, 'first_seen', forbidden, raising=False)
    template = tmp_path / 'template.md'
    template.write_text('${first_seen}|${first_seen_date}')
    out = tmp_path / 'statement.md'
    statements.write_statement(store, view.cve_id, catalogs=SOURCES, template=template, out=out, now=NOW)
    assert out.read_text() == '2026-11-04T00:30:00+02:00|2026-11-03'
