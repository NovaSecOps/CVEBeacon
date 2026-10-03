"""Deterministic merging without state or applicability access."""

from pathlib import Path

from cvebeacon.identity import PURL_ECOSYSTEMS, name_key, package_name, parse_purl, purl_string
from cvebeacon.sources.nvd import split_cpe23

from .contract import (MAX_BYTES, MAX_RECORDS, ExtensionError, canonical_records, json_bytes,
                       label, read_snapshot, timestamp, write_snapshot)


def _slot(row):
    # Without explicit system grouping, distinct asset IDs can be distinct hosts.
    if not row["system_id"]:
        return None
    if row["purl"]:
        purl = parse_purl(row["purl"])
        ecosystem = PURL_ECOSYSTEMS.get(purl.type)
        if ecosystem and not purl.qualifiers and not purl.subpath:
            return (row["system_id"], ecosystem, name_key(ecosystem, package_name(purl)))
        return (row["system_id"], "purl", purl_string(purl._replace(version=None)))
    if row["ecosystem"]:
        return (row["system_id"], row["ecosystem"], name_key(row["ecosystem"], row["product"]))
    if row["cpe"]:
        fields = list(split_cpe23(row["cpe"]))
        fields[3] = ""
        return (row["system_id"], "cpe", *fields)
    if row["repository"] and row["commit"]:
        return (row["system_id"], "repository", row["repository"])
    return None


def merge_snapshots(paths: list[Path], output: Path, *, source_id: str,
                    expected_sources: list[str] | None = None, max_age_seconds: int = 86400,
                    allow_partial: bool = False) -> dict:
    if not paths:
        raise ExtensionError("at least one snapshot is required")
    label(source_id)
    expected = {label(value) for value in expected_sources or []}
    if len({Path(path).resolve() for path in paths}) != len(paths):
        raise ExtensionError("duplicate input path")
    output_paths = {Path(output).resolve(), Path(str(output) + ".manifest.json").resolve()}
    for path in paths:
        if output_paths & {Path(path).resolve(), Path(str(path) + ".manifest.json").resolve()}:
            raise ExtensionError("output must not overwrite an input snapshot")
    sources = set()
    omissions = set()
    rows = {}
    slots = {}
    observed = []
    retained_bytes = 3
    for path in paths:
        # Explicit partial mode only tolerates missing files and
        # declared partial results. Corruption/conflicts must never be ignored.
        try:
            snapshot = read_snapshot(Path(path), max_age_seconds=max_age_seconds, allow_partial=allow_partial)
        except FileNotFoundError:
            if not allow_partial:
                raise ExtensionError("required snapshot or manifest is missing") from None
            omissions.add("missing-input")
            continue
        source = snapshot.manifest["source_id"]
        if source in sources:
            raise ExtensionError("duplicate source_id; choose one snapshot per source")
        sources.add(source)
        omissions.update(snapshot.manifest["omissions"])
        observed.append(timestamp(snapshot.manifest["observed_at"]))
        for row in snapshot.records:
            key = row["asset_id"].casefold()
            if key in rows:
                if rows[key] != row:
                    raise ExtensionError("conflicting asset_id across snapshots")
                continue  # Exact duplicate content is deliberately coalesced.
            if len(rows) >= MAX_RECORDS:
                raise ExtensionError("merged inventory exceeds record limit")
            retained_bytes += len(json_bytes(row)) + 2 * (len(row) + 2) + 1
            if retained_bytes > MAX_BYTES:
                raise ExtensionError("merged inventory exceeds size limit")
            slot = _slot(row)
            if slot is not None and slot in slots and slots[slot] != row:
                raise ExtensionError("conflicting strong identity in the same system/component slot")
            if slot is not None:
                slots[slot] = row
            rows[key] = row
    missing = expected - sources
    if missing and not allow_partial:
        raise ExtensionError("missing required sources: " + ", ".join(sorted(missing)))
    omissions.update(missing)
    final = canonical_records(list(rows.values()))
    return write_snapshot(output, final, source_id=source_id, collector="merge",
                          observed_at=min(observed).isoformat(), omissions=sorted(omissions))
