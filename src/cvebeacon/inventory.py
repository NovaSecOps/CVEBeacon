"""Inventory inspection, loading, normalization, and validation."""

from __future__ import annotations

import csv
import json
import unicodedata
from zipfile import BadZipFile
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from datetime import date, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

import yaml
from openpyxl import load_workbook
from openpyxl.utils.exceptions import InvalidFileException

from .config import CANONICAL_FIELDS, OPTIONAL_FIELDS, InventoryConfig
from .identity import normalize_asset
from .errors import InventoryValidationError, ValidationIssue
from .models import Asset
from .xlsx_safety import MAX_ARCHIVE_BYTES, check_workbook

SUPPORTED_FORMATS = {"xlsx", "csv", "json", "yaml"}
PREVIEW_COLUMN_LIMIT = 256
MAX_CONTRACT_ROWS = 100_000
MAX_CONTRACT_TEXT = 8192
FORMULA = object()


def detect_format(path: Path, configured: str = "auto") -> str:
    if configured != "auto":
        value = configured.casefold().lstrip(".")
        if value == "yml":
            value = "yaml"
        if value not in SUPPORTED_FORMATS:
            raise InventoryValidationError(
                [ValidationIssue(f"unsupported inventory format: {configured}")]
            )
        return value
    suffix = path.suffix.casefold().lstrip(".")
    if suffix == "yml":
        suffix = "yaml"
    if suffix not in SUPPORTED_FORMATS:
        raise InventoryValidationError(
            [ValidationIssue(f"cannot detect inventory format from extension: {path.suffix}")]
        )
    return suffix


def _cell_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)


def _normalized(value: Any) -> str:
    text = unicodedata.normalize("NFKC", _cell_text(value)).strip()
    if "\x00" in text:
        raise ValueError("contains a null character")
    return text


def _resolve_records(root: Any, path: str | None) -> Any:
    current = root
    if path:
        for component in path.split("."):
            if not component:
                raise KeyError("records path contains an empty component")
            if not isinstance(current, Mapping) or component not in current:
                raise KeyError(f"records path component not found: {component}")
            current = current[component]
    return current


def _validate_rows(rows: Iterable[tuple[str, Mapping[str, Any]]], columns: Mapping[str, str]) -> list[Asset]:
    issues: list[ValidationIssue] = []
    assets: list[Asset] = []
    seen_ids: dict[str, str] = {}
    for location, row in rows:
        if not isinstance(row, Mapping):
            issues.append(ValidationIssue("record must be an object", location))
            continue
        values: dict[str, str] = {}
        mapped = {name: columns.get(name, name) for name in CANONICAL_FIELDS + OPTIONAL_FIELDS}
        advanced = any(row.get(mapped[name]) for name in ("purl", "cpe", "ecosystem", "commit"))
        required = ("asset_id",) if advanced else CANONICAL_FIELDS
        if any(mapped[name] not in row for name in required):
            issues.append(ValidationIssue("record is missing mapped fields", location))
            continue
        row_has_value = False
        for canonical in CANONICAL_FIELDS + OPTIONAL_FIELDS:
            source_name = mapped[canonical]
            raw = row.get(source_name)
            if raw not in (None, ""):
                row_has_value = True
            try:
                if raw is not None and not isinstance(raw, str):
                    raise ValueError("must be text; numeric, date, boolean and compound values cannot preserve inventory spelling")
                # Exact package identifiers must not undergo compatibility
                # Unicode normalization (which can change registry identity).
                values[canonical] = _normalized(raw) if canonical in {"asset_id", "category", "system_id", "client"} or (not advanced and canonical in {"vendor", "product"}) else (raw or "").strip()
                if "\x00" in values[canonical]:
                    raise ValueError("contains a null character")
            except (TypeError, ValueError) as exc:
                issues.append(
                    ValidationIssue(f"{canonical} cannot be normalized: {exc}", location)
                )
                values[canonical] = ""
        if not row_has_value:
            continue
        try:
            asset = normalize_asset(Asset(**values))
        except ValueError as exc:
            issues.append(ValidationIssue(str(exc), location))
            continue
        duplicate_key = values["asset_id"].casefold()
        if duplicate_key in seen_ids:
            issues.append(
                ValidationIssue(
                    f"duplicate asset_id; first seen at {seen_ids[duplicate_key]}", location
                )
            )
            continue
        seen_ids[duplicate_key] = location
        assets.append(asset)
    if issues:
        raise InventoryValidationError(issues)
    if not assets:
        raise InventoryValidationError([ValidationIssue("inventory contains no valid records")])
    return assets


@contextmanager
def _open_workbook(path, *, data_only=False, upload=False, header_row=1):
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_ARCHIVE_BYTES + 1)
        with BytesIO(raw) as stream:
            limits = ({"row_limit": MAX_CONTRACT_ROWS + header_row, "column_limit": PREVIEW_COLUMN_LIMIT}
                      if upload else {})
            check_workbook(stream, use_dimensions=not upload, **limits)
            workbook = load_workbook(stream, read_only=True, data_only=data_only, keep_links=False)
            try:
                yield workbook
            finally:
                workbook.close()
    except (OSError, ValueError, BadZipFile, InvalidFileException, KeyError, IndexError, SyntaxError, RuntimeError) as exc:
        raise InventoryValidationError([ValidationIssue("The workbook could not be read.")]) from exc


def _xlsx_rows(config: InventoryConfig, *, unmapped: bool = False) -> Iterable[tuple[str, Mapping[str, Any]]]:
    with _open_workbook(config.path, upload=unmapped, header_row=config.header_row) as workbook:
        if config.worksheet:
            if config.worksheet not in workbook.sheetnames:
                raise InventoryValidationError(
                    [ValidationIssue(f"worksheet not found: {config.worksheet}")]
                )
            worksheet = workbook[config.worksheet]
        else:
            worksheet = workbook[workbook.sheetnames[0]]
        if unmapped:
            if ((worksheet.max_column or 0) > PREVIEW_COLUMN_LIMIT
                    or (worksheet.max_row or 0) > MAX_CONTRACT_ROWS + config.header_row):
                raise InventoryValidationError([ValidationIssue("the worksheet is too large")])
            # Derive rows from actual cells, rather than trusting the advertised
            # used range to include all of the inventory.
            worksheet.reset_dimensions()
        header_cells = next(
            worksheet.iter_rows(
                min_row=config.header_row, max_row=config.header_row, values_only=True
            ),
            None,
        )
        if header_cells is None:
            raise InventoryValidationError(
                [ValidationIssue(f"header row {config.header_row} does not exist")]
            )
        headers = [_normalized(value) for value in header_cells]
        if unmapped and len(headers) > PREVIEW_COLUMN_LIMIT:
            raise InventoryValidationError([ValidationIssue("the worksheet has too many columns")])
        if any(not value for value in headers):
            raise InventoryValidationError(
                [ValidationIssue("header row contains a blank column name")]
            )
        if len({value.casefold() for value in headers}) != len(headers):
            raise InventoryValidationError(
                [ValidationIssue("header row contains duplicate column names")]
            )
        header_lookup = {name.casefold(): name for name in headers}
        mapped = {name: config.columns.get(name, name) for name in CANONICAL_FIELDS + OPTIONAL_FIELDS}
        required = ("asset_id",) if any(mapped[name].casefold() in header_lookup for name in ("purl", "cpe", "ecosystem", "commit")) else CANONICAL_FIELDS
        missing = [mapped[name] for name in required if mapped[name].casefold() not in header_lookup]
        if missing and not unmapped:
            raise InventoryValidationError(
                [ValidationIssue("mapped columns not found: " + ", ".join(missing))]
            )
        for row_number, values in enumerate(
            worksheet.iter_rows(min_row=config.header_row + 1),
            start=config.header_row + 1,
        ):
            if unmapped:
                if len(values) > len(headers) and any(cell.value is not None for cell in values[len(headers):]):
                    raise InventoryValidationError([ValidationIssue("a cell is missing a column name", f"row {row_number}")])
                yield f"row {row_number}", {
                    name: FORMULA if cell.data_type == "f" else cell.value
                    for name, cell in zip(headers, values)
                }
                continue
            raw_cells = dict(zip(headers, values))
            if any(raw_cells[header_lookup[name.casefold()]].data_type == "f" for name in mapped.values() if name.casefold() in header_lookup):
                raise InventoryValidationError([ValidationIssue("mapped inventory cells must contain text, not formulas", f"row {row_number}")])
            raw = {name: cell.value for name, cell in raw_cells.items()}
            yield f"sheet {worksheet.title!r}, row {row_number}", {
                configured: raw.get(header_lookup[configured.casefold()])
                for configured in mapped.values() if configured.casefold() in header_lookup
            }


def _upload_csv_lines(handle):
    while line := handle.readline(2 * 1024 * 1024 + 1):
        if len(line) > 2 * 1024 * 1024:
            raise InventoryValidationError([ValidationIssue("a CSV line is too long")])
        yield line


def _csv_rows(config: InventoryConfig, *, unmapped: bool = False) -> Iterable[tuple[str, Mapping[str, Any]]]:
    try:
        handle = config.path.open("r", encoding=config.encoding, newline="")
    except (OSError, LookupError) as exc:
        raise InventoryValidationError([ValidationIssue(f"cannot read CSV: {exc}")]) from exc
    with handle:
        try:
            reader = csv.reader(_upload_csv_lines(handle) if unmapped else handle, delimiter=config.delimiter, strict=True)
            fieldnames = next(reader, None)
            if not fieldnames:
                raise InventoryValidationError([ValidationIssue("CSV has no header row")])
            headers = [_normalized(value) for value in fieldnames]
            if unmapped and any(not name for name in headers):
                raise InventoryValidationError([ValidationIssue("CSV header contains a blank column name")])
            if unmapped and len(headers) > PREVIEW_COLUMN_LIMIT:
                raise InventoryValidationError([ValidationIssue("CSV header contains too many columns")])
            if len({value.casefold() for value in headers}) != len(headers):
                raise InventoryValidationError(
                    [ValidationIssue("CSV header contains duplicate column names")]
                )
            header_lookup = {name.casefold(): name for name in headers}
            mapped = {name: config.columns.get(name, name) for name in CANONICAL_FIELDS + OPTIONAL_FIELDS}
            required = ("asset_id",) if any(mapped[name].casefold() in header_lookup for name in ("purl", "cpe", "ecosystem", "commit")) else CANONICAL_FIELDS
            missing = [mapped[name] for name in required if mapped[name].casefold() not in header_lookup]
            if missing and not unmapped:
                raise InventoryValidationError(
                    [ValidationIssue("mapped columns not found: " + ", ".join(missing))]
                )
            while True:
                row_number = reader.line_num + 1
                values = next(reader, None)
                if values is None:
                    break
                if not values:
                    continue
                if len(values) > len(headers):
                    raise InventoryValidationError([ValidationIssue("CSV row has more fields than its header", f"row {row_number}")])
                row = dict(zip(headers, values))
                if unmapped:
                    yield f"row {row_number}", row
                    continue
                yield f"row {row_number}", {
                    configured: row.get(header_lookup[configured.casefold()])
                    for configured in mapped.values() if configured.casefold() in header_lookup
                }
        except csv.Error:
            raise InventoryValidationError(
                [ValidationIssue(f"malformed CSV near line {reader.line_num}")]
            ) from None


class BoundedYAMLLoader(yaml.SafeLoader):
    """Limit YAML parsing before the constructor allocates a large object tree."""

    depth = 0
    nodes = 0

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise InventoryValidationError([ValidationIssue("YAML aliases are not supported. Use a separate value for each field.")])
        if self.depth >= 32 or self.nodes >= 1_000_000:
            raise InventoryValidationError([ValidationIssue("The YAML is too complex. Split it into smaller files.")])
        self.depth += 1
        self.nodes += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        # YAML merges can expand a small file into a very large mapping.
        if any(key.tag == "tag:yaml.org,2002:merge" for key, _ in node.value):
            raise InventoryValidationError([ValidationIssue("YAML merge keys are not supported. Use a separate value for each field.")])
        mapping = super().construct_mapping(node, deep=deep)
        if len(mapping) != len(node.value):
            raise InventoryValidationError([ValidationIssue("The YAML contains duplicate field names.")])
        return mapping


def decode_inventory_yaml(text):
    return yaml.load(text, Loader=BoundedYAMLLoader)


def _structured_error(kind: str, error: BaseException) -> str:
    """Return a parser diagnostic without source text or parser excerpts."""
    if isinstance(error, json.JSONDecodeError):
        return f"cannot read JSON inventory near line {error.lineno}"
    if isinstance(error, yaml.YAMLError):
        mark = getattr(error, "problem_mark", None)
        if mark is not None:
            return f"cannot read YAML inventory near line {mark.line + 1}"
        return "cannot read YAML inventory"
    return f"cannot read {kind.upper()} inventory"


def _structured_rows(config: InventoryConfig, kind: str, *, unmapped: bool = False) -> Iterable[tuple[str, Mapping[str, Any]]]:
    try:
        text = config.path.read_text(encoding=config.encoding)
        if unmapped:
            from .inventory_preview import decode_upload_records
            root = decode_upload_records(text, kind)
        else:
            root = json.loads(text) if kind == "json" else decode_inventory_yaml(text)
        records = _resolve_records(root, config.records_path)
    except (OSError, LookupError, json.JSONDecodeError, yaml.YAMLError, KeyError) as exc:
        raise InventoryValidationError([ValidationIssue(_structured_error(kind, exc))]) from exc
    if not isinstance(records, list):
        location = config.records_path or "document root"
        raise InventoryValidationError(
            [ValidationIssue("configured records value must be a list", location)]
        )
    for index, record in enumerate(records):
        yield (f"row {index + 1}" if unmapped else f"record {index}"), record


def validate_records(records: Iterable[Mapping[str, Any]]) -> list[Asset]:
    """Validate canonical inventory records with the same rules as file input.

    This public boundary performs no IO, discovery, applicability or state writes.
    """
    return _validate_rows(((f"record {index}", row) for index, row in enumerate(records)), {})


def load_inventory(config: InventoryConfig, *, snapshot_directory: Path | None = None,
                   managed_warnings: list[str] | None = None, managed_candidate=None) -> list[Asset]:
    assets = _validate_rows(inventory_rows(config), config.columns) if config.path is not None else []
    if config.web_snapshots:
        if snapshot_directory is None:
            raise InventoryValidationError([ValidationIssue("web snapshots require the data directory")])
        from .web_inventory import append_snapshots
        assets = append_snapshots(assets, snapshot_directory)
    if config.managed_directory is not None:
        from .managed_inventory import append_managed_inventory
        assets = append_managed_inventory(
            assets, config.managed_directory, configured=config.path, users_path=config.managed_users_path,
            warnings=managed_warnings, candidate=managed_candidate,
        )
    if not assets:
        raise InventoryValidationError([ValidationIssue("inventory contains no valid records")])
    return assets


def inventory_rows(config: InventoryConfig, *, unmapped: bool = False):
    kind = detect_format(config.path, config.format)
    if kind == "xlsx":
        return _xlsx_rows(config, unmapped=unmapped)
    if kind == "csv":
        return _csv_rows(config, unmapped=unmapped)
    return _structured_rows(config, kind, unmapped=unmapped)


def inspect_inventory(path: str | Path, *, header_row: int = 1, encoding: str = "utf-8-sig", delimiter: str = ",") -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    kind = detect_format(source)
    if kind == "xlsx":
        with _open_workbook(source, data_only=True) as workbook:
            sheets: list[dict[str, Any]] = []
            for worksheet in workbook.worksheets:
                headers = next(
                    worksheet.iter_rows(
                        min_row=header_row, max_row=header_row, values_only=True
                    ),
                    (),
                )
                sheets.append(
                    {
                        "name": worksheet.title,
                        "headers": [_cell_text(value).strip() for value in headers],
                        "max_row": worksheet.max_row,
                        "max_column": worksheet.max_column,
                    }
                )
            return {"path": str(source), "format": kind, "sheets": sheets}
    if kind == "csv":
        try:
            with source.open("r", encoding=encoding, newline="") as handle:
                reader = csv.reader(handle, delimiter=delimiter)
                headers = next(reader, [])
                sample = [row for _, row in zip(range(3), reader)]
        except (OSError, LookupError, csv.Error):
            raise InventoryValidationError([ValidationIssue("cannot read CSV inventory")]) from None
        return {"path": str(source), "format": kind, "headers": headers, "sample_rows": sample}
    try:
        text = source.read_text(encoding=encoding)
        root = json.loads(text) if kind == "json" else decode_inventory_yaml(text)
    except (OSError, LookupError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise InventoryValidationError([ValidationIssue(_structured_error(kind, exc))]) from exc
    result: dict[str, Any] = {"path": str(source), "format": kind, "root_type": type(root).__name__}
    if isinstance(root, list):
        result["record_count"] = len(root)
        if root and isinstance(root[0], Mapping):
            result["first_record_fields"] = list(root[0].keys())
    elif isinstance(root, Mapping):
        result["top_level_keys"] = list(root.keys())
        result["list_keys"] = [key for key, value in root.items() if isinstance(value, list)]
    return result
