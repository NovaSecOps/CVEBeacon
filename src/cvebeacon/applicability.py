"""Conservative product/version applicability evaluation."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version

from .models import Applicability, Asset, Evidence


def identity_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in text if character.isalnum())


def same_identity(left: str, right: str) -> bool:
    return bool(left and right and identity_text(left) == identity_text(right))


@dataclass(frozen=True, slots=True)
class Decision:
    state: Applicability
    reason: str


def _compare_versions(left: str, right: str, scheme: str) -> int | None:
    if scheme.casefold() not in {"semver", "python"}:
        return None
    try:
        a, b = Version(left), Version(right)
    except InvalidVersion:
        return None
    return (a > b) - (a < b)


def _version_entry(asset_version: str, entry: dict[str, Any]) -> bool | None:
    start = str(entry.get("version") or "").strip()
    scheme = str(entry.get("versionType") or "").strip()
    less_than = entry.get("lessThan")
    less_equal = entry.get("lessThanOrEqual")
    if less_than is None and less_equal is None and start == "*":
        return True
    if less_than is None and less_equal is None:
        return asset_version.casefold() == start.casefold()
    if start not in {"0", "*"}:
        lower = _compare_versions(asset_version, start, scheme)
        if lower is None:
            return None
        if lower < 0:
            return False
    endpoint = less_than if less_than is not None else less_equal
    if str(endpoint) == "*":
        return True
    upper = _compare_versions(asset_version, str(endpoint), scheme)
    if upper is None:
        return None
    return upper < 0 if less_than is not None else upper <= 0


def _entry_status(asset_version: str, entry: dict[str, Any]) -> str | None:
    status = str(entry.get("status") or "unknown").casefold()
    changes = entry.get("changes") or []
    if not changes:
        return status
    scheme = str(entry.get("versionType") or "")
    ordered: list[tuple[Version, str]] = []
    try:
        parsed_asset = Version(asset_version) if scheme.casefold() in {"semver", "python"} else None
        if parsed_asset is None:
            return None
        for change in changes:
            ordered.append((Version(str(change["at"])), str(change.get("status") or "unknown").casefold()))
    except (InvalidVersion, KeyError, TypeError):
        return None
    for threshold, changed_status in sorted(ordered):
        if parsed_asset >= threshold:
            status = changed_status
    return status


def evaluate_cve_evidence(asset: Asset, evidence: Evidence) -> Decision:
    affected = evidence.details.get("affected")
    if not isinstance(affected, list):
        return Decision(Applicability.NEEDS_REVIEW, "source has no structured affected-product evidence")
    matched_product = False
    uncertain_version = False
    explicit_states: list[str] = []
    for product in affected:
        if not isinstance(product, dict):
            continue
        vendor = str(product.get("vendor") or "")
        name = str(product.get("product") or "")
        if not (same_identity(asset.vendor, vendor) and same_identity(asset.product, name)):
            continue
        matched_product = True
        versions = product.get("versions") or []
        matched_version = False
        for entry in versions:
            if not isinstance(entry, dict):
                continue
            match = _version_entry(asset.version, entry)
            if match is None:
                uncertain_version = True
            elif match:
                matched_version = True
                status = _entry_status(asset.version, entry)
                if status is None:
                    uncertain_version = True
                else:
                    explicit_states.append(status)
        if not matched_version and not uncertain_version and product.get("defaultStatus"):
            explicit_states.append(str(product["defaultStatus"]).casefold())
    states = set(explicit_states)
    if "affected" in states and "unaffected" in states:
        return Decision(Applicability.NEEDS_REVIEW, "official record contains conflicting version statuses")
    if states.intersection({"affected", "unaffected"}) and uncertain_version:
        return Decision(Applicability.NEEDS_REVIEW, "explicit evidence overlaps version semantics that cannot be compared safely")
    if "affected" in states:
        return Decision(Applicability.AFFECTED, "official record explicitly covers this product version")
    if "unaffected" in states:
        return Decision(Applicability.NOT_AFFECTED, "official record explicitly excludes this product version")
    if matched_product and uncertain_version:
        return Decision(Applicability.NEEDS_REVIEW, "product matches but its version scheme cannot be compared safely")
    if matched_product:
        return Decision(Applicability.NEEDS_REVIEW, "product matches but version coverage is not explicit")
    return Decision(Applicability.COVERAGE_UNKNOWN, "official record does not identify this exact product")


def exact_cpe_version(cpe: str, version: str) -> str:
    """Return a 2.3 CPE with its version field replaced and conservatively escaped."""
    if not cpe.startswith("cpe:2.3:"):
        raise ValueError("configured CPE must be a complete CPE 2.3 name")
    parts: list[str] = []
    current: list[str] = []
    escaped_field = False
    for character in cpe[8:]:
        if escaped_field:
            current.extend(("\\", character)); escaped_field = False
        elif character == "\\":
            escaped_field = True
        elif character == ":":
            parts.append("".join(current)); current = []
        else:
            current.append(character)
    if escaped_field:
        current.append("\\")
    parts.append("".join(current))
    if len(parts) != 11:
        raise ValueError("configured CPE must be a complete CPE 2.3 name")
    escaped = re.sub(r"([\\:?!*])", r"\\\1", version.strip())
    parts[3] = escaped
    parts[4:] = ["*"] * 7
    return "cpe:2.3:" + ":".join(parts)
