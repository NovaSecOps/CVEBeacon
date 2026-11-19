"""Bound workbook input and inspect raw package parts before opening Excel files."""

import re
import struct
from xml.parsers import expat
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

from .errors import InventoryValidationError, ValidationIssue

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 32 * 1024 * 1024
MAX_PART_BYTES = 16 * 1024 * 1024
MAX_DIRECTORY_BYTES = 2 * 1024 * 1024
MAX_PARTS = 1024
MAX_XML_NODES = 2_000_000
MAX_WORKSHEET_CELLS = 1_000_000
DECLARATION = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
COORDINATE = re.compile(r"([A-Z]{1,3})([1-9][0-9]{0,6})")
XML_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def _reject(message):
    raise InventoryValidationError([ValidationIssue(message)])


def _check_directory(stream):
    size = stream.seek(0, 2)
    if size > MAX_ARCHIVE_BYTES:
        _reject("The workbook exceeds the file size limit.")
    tail_size = min(size, 65535 + 22)
    stream.seek(size - tail_size)
    tail = stream.read(tail_size)
    start = tail.rfind(b"PK\x05\x06")
    if start < 0 or len(tail) - start < 22:
        _reject("The workbook is not a complete Excel file.")
    disk, directory_disk, disk_entries, entries, length, offset, comment = struct.unpack_from(
        "<4H2IH", tail, start + 4
    )
    if (disk or directory_disk or disk_entries != entries or entries > MAX_PARTS
            or length > MAX_DIRECTORY_BYTES or start + 22 + comment != len(tail)
            or length + offset > size - tail_size + start):
        _reject("The workbook has too many parts or an invalid directory.")
    stream.seek(0)


def _column_number(text):
    number = 0
    for char in text:
        number = number * 26 + ord(char) - ord("A") + 1
    return number


def _check_xml(raw, budget, row_limit, column_limit, *, use_dimensions):
    parser = expat.ParserCreate(namespace_separator="}")
    worksheet = False
    depth = row = column = 0

    def start(name, attrs):
        nonlocal worksheet, depth, row, column
        depth += 1
        budget[0] -= 1
        if depth > 64 or budget[0] < 0:
            _reject("The workbook XML is too complex.")
        if depth == 1:
            worksheet = name == XML_NS + "worksheet"
        if not worksheet:
            return
        if use_dimensions and name == XML_NS + "dimension":
            positions = attrs.get("ref", "").split(":")
            first, last = COORDINATE.fullmatch(positions[0]), COORDINATE.fullmatch(positions[-1])
            if not first or not last or len(positions) > 2:
                _reject("The workbook has an invalid worksheet range.")
            width = _column_number(last[1]) - _column_number(first[1]) + 1
            height = int(last[2]) - int(first[2]) + 1
            if (width < 1 or height < 1 or width * height > MAX_WORKSHEET_CELLS
                    or int(last[2]) > row_limit or _column_number(last[1]) > column_limit):
                _reject("The workbook worksheet range exceeds the size limit.")
        if name == XML_NS + "row":
            index = attrs.get("r")
            if index is not None and (not index.isascii() or not index.isdecimal() or len(index) > 7):
                _reject("The workbook has an invalid row number.")
            next_row = int(index) if index is not None else row + 1
            if not row < next_row <= row_limit:
                _reject("The workbook exceeds the row limit or has rows out of order.")
            row, column = next_row, 0
        if name == XML_NS + "c":
            budget[1] -= 1
            if budget[1] < 0:
                _reject("The workbook has too many cells.")
            index = attrs.get("r")
            match = COORDINATE.fullmatch(index) if index is not None else None
            if index is not None and (match is None or int(match[2]) != row):
                _reject("The workbook has an invalid cell position.")
            next_column = _column_number(match[1]) if match else column + 1
            if not column < next_column <= column_limit:
                _reject("The workbook exceeds the column limit or has cells out of order.")
            column = next_column

    def end(_):
        nonlocal depth
        depth -= 1

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    # Defense in depth for encodings recognized by the XML parser.
    parser.StartDoctypeDeclHandler = lambda *_: _reject("XML declarations for document types or entities are not allowed.")
    parser.EntityDeclHandler = parser.StartDoctypeDeclHandler
    try:
        parser.Parse(raw, True)
    except (expat.ExpatError, LookupError, ValueError):
        _reject("An XML part in the workbook is invalid.")


def check_workbook(stream, *, row_limit=1_048_576, column_limit=16_384, use_dimensions=True):
    _check_directory(stream)
    budget = [MAX_XML_NODES, MAX_WORKSHEET_CELLS]
    total = 0
    with ZipFile(stream) as archive:
        entries = archive.infolist()
        if (len(entries) > MAX_PARTS or len({entry.filename for entry in entries}) != len(entries)
                or sum(entry.file_size for entry in entries) > MAX_EXPANDED_BYTES):
            _reject("The workbook exceeds the total expanded size or part limit.")
        for entry in entries:
            if entry.flag_bits & 1:
                _reject("The workbook is encrypted.")
            if entry.compress_type not in {ZIP_STORED, ZIP_DEFLATED}:
                _reject("The workbook uses an unsupported compression method.")
            if entry.file_size > MAX_PART_BYTES:
                _reject("A workbook part exceeds the expanded size limit.")
            with archive.open(entry) as part:
                limit = min(MAX_PART_BYTES, MAX_EXPANDED_BYTES - total)
                raw = part.read(limit + 1)
            total += len(raw)
            if len(raw) > limit or len(raw) != entry.file_size:
                _reject("The workbook exceeds the expanded size limit.")
            # Inspect every part, including relationship and custom-named parts.
            # Removing NUL padding recognizes ASCII markup in UTF-16/UTF-32.
            if DECLARATION.search(raw.replace(b"\x00", b"")):
                _reject("XML declarations for document types or entities are not allowed.")
            if (entry.filename.lower().endswith((".xml", ".rels"))
                    or raw.lstrip(b"\xef\xbb\xbf\xff\xfe\x00 \t\r\n").startswith(b"<")):
                _check_xml(raw, budget, row_limit, column_limit, use_dimensions=use_dimensions)
    stream.seek(0)
