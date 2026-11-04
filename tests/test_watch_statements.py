from __future__ import annotations

import io
import re
import zipfile
from datetime import date
from pathlib import Path
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
        view, first_seen=store.first_seen(identifier), generated_at=NOW
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


def docx_bytes(
    document: str,
    *,
    header: str | None = None,
    footer: str | None = None,
    styles: bytes = STYLES,
    core: bytes = b"<core/>",
) -> bytes:
    body = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<w:document xmlns:w="{W}"><w:body>{document}</w:body></w:document>'
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr(
            "_rels/.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
        )
        archive.writestr("word/document.xml", body)
        if header is not None:
            archive.writestr("word/header1.xml", header)
        if footer is not None:
            archive.writestr("word/footer1.xml", footer)
        archive.writestr("word/styles.xml", styles)
        archive.writestr("docProps/core.xml", core)
    return output.getvalue()


def paragraph_texts(xml: bytes) -> list[str]:
    root = ElementTree.fromstring(xml)
    return [
        "".join(element.text or "" for element in paragraph.iter(f"{{{W}}}t"))
        for paragraph in root.iter(f"{{{W}}}p")
    ]


def part(zip_data: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(zip_data)) as archive:
        return archive.read(name)


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
    with pytest.raises(CVEBeaconError, match="invalid statement placeholder"):
        render_text("bad $ placeholder", all_fields())


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
    result = render_docx(
        docx_bytes("<w:p><w:r><w:t>${cve_id}</w:t></w:r></w:p>"),
        all_fields(),
    )
    with zipfile.ZipFile(io.BytesIO(result)) as archive:
        names = archive.namelist()
        assert names[0] == "[Content_Types].xml"
        assert archive.read("word/styles.xml") == STYLES
        assert archive.read("docProps/core.xml") == b"<core/>"
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
