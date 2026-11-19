"""Parse and validate a private upload before publishing canonical inventory."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.etree.ElementTree import ParseError
from zipfile import BadZipFile

from .config import CANONICAL_FIELDS, OPTIONAL_FIELDS, InventoryConfig
from .errors import ConfigurationError, InventoryValidationError
from .identity import identity_conflict
from .inventory import (
    FORMULA, MAX_CONTRACT_ROWS, MAX_CONTRACT_TEXT, PREVIEW_COLUMN_LIMIT, _validate_rows, decode_inventory_yaml, inventory_rows,
)
from .models import Asset
from .web_inventory import decode_json

FIELDS = tuple(field for field in CANONICAL_FIELDS + OPTIONAL_FIELDS if field != "client")
FIELD_LABELS = {
    "asset_id": "Asset ID", "vendor": "Vendor", "product": "Product", "version": "Version",
    "category": "Category", "system_id": "System ID", "ecosystem": "Package ecosystem",
    "purl": "Package URL (PURL)", "cpe": "CPE", "repository": "Repository", "commit": "Commit",
}
EXACT_IDENTITY_FIELDS = ("purl", "cpe", "ecosystem", "commit")
ROWS_PER_PAGE = 50
MAX_CELLS = 1_000_000
MAX_LOGICAL_TEXT = 16 * 1024 * 1024


def decode_upload_records(text, kind):
    root = decode_json(text.encode("utf-8"), max_items=MAX_CELLS + MAX_CONTRACT_ROWS) if kind == "json" else decode_inventory_yaml(text)
    if isinstance(root, dict):
        lists = [value for value in root.values() if isinstance(value, list)]
        if len(lists) == 1:
            return lists[0]
    return root


@dataclass(slots=True)
class Preview:
    headers: tuple[str, ...]
    mapping: dict[str, str]
    sample: list
    validation: list
    assets: list[Asset]
    errors: int
    warnings: int
    page: int
    pages: int
    first_error: tuple[int, int] | None


UPLOAD_PARSE_MESSAGES = {
    "configured records value must be a list": "Upload a list of inventory rows or a document containing one list.",
}

# Only messages generated from known input structure are safe for display.
SAFE_PARSE_ERRORS = frozenset({
    "CSV has no header row", "CSV header contains duplicate column names",
    "CSV header contains a blank column name", "CSV header contains too many columns",
    "CSV row has more fields than its header", "a CSV line is too long",
    "header row contains a blank column name", "header row contains duplicate column names",
    "a cell is missing a column name", "the worksheet is too large",
    "the worksheet has too many columns",
    "YAML aliases are not supported. Use a separate value for each field.",
    "The YAML is too complex. Split it into smaller files.",
    "YAML merge keys are not supported. Use a separate value for each field.",
    "The YAML contains duplicate field names.",
})


def read_upload(data, suffix):
    with TemporaryDirectory(prefix="cvebeacon-upload-") as directory:
        path = Path(directory) / ("inventory" + suffix)
        path.write_bytes(data)
        try:
            rows = []
            cells = text_length = 0
            for location, row in inventory_rows(InventoryConfig(path), unmapped=True):
                if len(rows) == MAX_CONTRACT_ROWS:
                    raise ConfigurationError("Upload at most 100,000 rows at a time.")
                if isinstance(row, Mapping):
                    if len(row) > PREVIEW_COLUMN_LIMIT:
                        raise ConfigurationError("Upload at most 256 columns at a time.")
                    cells += len(row)
                    if cells > MAX_CELLS:
                        raise ConfigurationError("This file has too many cells. Split it into smaller uploads.")
                    text_length += sum(len(value) for value in row.values() if isinstance(value, str))
                    if text_length > MAX_LOGICAL_TEXT:
                        raise ConfigurationError("This file contains too much text. Split it into smaller uploads.")
                rows.append((int(location.removeprefix("row ")), row))
            return rows
        except InventoryValidationError as exc:
            issue = exc.issues[0]
            if issue.message in UPLOAD_PARSE_MESSAGES:
                raise ConfigurationError(UPLOAD_PARSE_MESSAGES[issue.message]) from None
            if issue.message in SAFE_PARSE_ERRORS or issue.message.startswith(("The workbook ", "A workbook ", "An XML part ", "XML declarations ")):
                raise ConfigurationError(issue.message.capitalize() if issue.message.islower() else issue.message) from None
            raise ConfigurationError(_unreadable_message()) from None
        except (OSError, ValueError, KeyError, TypeError, IndexError,
                OverflowError, RecursionError, ParseError, BadZipFile) as exc:
            raise ConfigurationError(_unreadable_message()) from exc


def _unreadable_message():
    return ("The file could not be read. Check that it opens and has a header row for "
            "CSV or Excel, or one list of records for JSON or YAML.")


def _display(value):
    if value is FORMULA:
        return "Formula"
    if isinstance(value, (dict, list, set)):
        return "Structured value"
    if value is None:
        return ""
    text = str(value)
    excerpt = text[:120].encode("utf-8", errors="replace").decode("utf-8")
    return excerpt if len(text) <= 120 else excerpt + "…"


def _row_result(row, mapping, client, seen, number):
    if not isinstance(row, Mapping):
        return None, "Error", "This row must contain named fields."
    selected = {field: row.get(header) for field, header in mapping.items() if header}
    if not any(value is not None and value != "" for value in row.values()):
        return None, "Warning", "Blank row will be skipped."
    for field, value in selected.items():
        if value is FORMULA:
            return None, "Error", f"{FIELD_LABELS[field]} uses a formula. Paste its value as text."
        if value is not None and not isinstance(value, str):
            return None, "Error", f"{FIELD_LABELS[field]} must be stored as text."
        if value and (len(value) > MAX_CONTRACT_TEXT or any(0xD800 <= ord(char) <= 0xDFFF for char in value)):
            return None, "Error", f"{FIELD_LABELS[field]} contains unsupported text or is too long."
    required = ("asset_id",) if any(selected.get(key) for key in EXACT_IDENTITY_FIELDS) else CANONICAL_FIELDS
    for field in required:
        if not (selected.get(field) or "").strip():
            return None, "Error", f"{FIELD_LABELS[field]} is missing. Check the column mapping and this row."
    try:
        asset, = _validate_rows(((None, {**selected, "client": client}),), {})
    except InventoryValidationError as exc:
        for issue in exc.issues:
            if issue.message.startswith("blank required field: "):
                field = issue.message.removeprefix("blank required field: ")
                return None, "Error", f"{FIELD_LABELS[field]} is missing."
        return None, "Error", (
            "The row contains invalid text or inconsistent product details. "
            "Check the version and any package, CPE or repository values."
        )
    if identity_conflict(asset):
        return None, "Error", "Choose one identity type for the row, such as a package URL or a CPE."
    if any(len(value) > MAX_CONTRACT_TEXT for value in asdict(asset).values()):
        return None, "Error", "A value is too long after normalization."
    key = asset.asset_id.casefold()
    if key in seen:
        return None, "Error", f"Asset ID is already used in row {seen[key]}. Give each asset a unique ID."
    seen[key] = number
    if not asset.version and not asset.commit:
        return asset, "Warning", "Version is missing. Some findings may require review."
    return asset, "OK", "Ready to import."


def preview_upload(data, suffix, client, choices=None, *, page=1):
    rows = read_upload(data, suffix)
    headers = {}
    for _, row in rows:
        if isinstance(row, Mapping):
            for header in row:
                if (not isinstance(header, str) or not header.strip() or len(header) > 256
                        or any(0xD800 <= ord(char) <= 0xDFFF for char in header)):
                    raise ConfigurationError("Give each column a text name before uploading.")
                headers[header] = None
                if len(headers) > PREVIEW_COLUMN_LIMIT:
                    raise ConfigurationError("Upload at most 256 columns at a time.")
    columns = tuple(headers)
    casefold = suffix in {".csv", ".xlsx"}
    if casefold:
        lookup = {header.casefold(): header for header in columns}
        mapping = {
            field: lookup.get(field, lookup.get(field.replace("_", " "), ""))
            for field in FIELDS
        }
    else:
        mapping = {field: field if field in headers else "" for field in FIELDS}
    if choices is not None:
        for field, choice in choices.items():
            if choice == "":
                mapping[field] = ""
            elif not choice.isascii() or not choice.isdecimal() or not 0 <= int(choice) < len(columns):
                raise ConfigurationError("Select a column from the list.")
            else:
                mapping[field] = columns[int(choice)]
    pages = max(1, (len(rows) + ROWS_PER_PAGE - 1) // ROWS_PER_PAGE)
    page = min(page, pages)
    first = (page - 1) * ROWS_PER_PAGE
    assets, validation, sample, seen = [], [], [], {}
    errors = warnings = 0
    first_error = None
    for index, (number, row) in enumerate(rows):
        asset, status, message = _row_result(row, mapping, client, seen, number)
        if status == "Error" and first_error is None:
            first_error = number, index // ROWS_PER_PAGE + 1
        errors += status == "Error"
        warnings += status == "Warning"
        if asset is not None:
            assets.append(asset)
        if index < 10:
            sample.append((number, [_display(row.get(header)) if isinstance(row, Mapping) else "" for header in columns]))
        if first <= index < first + ROWS_PER_PAGE:
            validation.append((number, status, message))
    return Preview(columns, mapping, sample, validation, assets, errors, warnings, page, pages, first_error)
