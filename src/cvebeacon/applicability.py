"""Conservative product/version applicability evaluation."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any

from packaging.version import InvalidVersion, Version

from .models import Applicability, Asset, Evidence


def identity_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(text.split())


def same_identity(left: str, right: str) -> bool:
    return bool(identity_text(left) and identity_text(left) == identity_text(right))


@dataclass(frozen=True, slots=True)
class Decision:
    state: Applicability
    reason: str
    conflict: bool = False


def known_version(value: str) -> bool:
    return bool(value.strip()) and not any(char in value for char in "*?<>=") and value.strip().casefold() not in {"-", "unknown", "n/a", "na", "latest", "all"}


def _semver(value: str):
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", value)
    if not match:
        return None
    prerelease = match[4].split(".") if match[4] else []
    if any(item.isdigit() and len(item) > 1 and item.startswith("0") for item in prerelease):
        return None
    return tuple(int(match[i]) for i in (1, 2, 3)), prerelease


def _compare_versions(left: str, right: str, scheme: str) -> int | None:
    if scheme.casefold() == "semver":
        a, b = _semver(left), _semver(right)
        if a is None or b is None:
            return None
        if a[0] != b[0]:
            return (a[0] > b[0]) - (a[0] < b[0])
        if not a[1] or not b[1]:
            return (not a[1]) - (not b[1])
        for x, y in zip(a[1], b[1]):
            if x == y:
                continue
            if x.isdigit() and y.isdigit():
                return (int(x) > int(y)) - (int(x) < int(y))
            if x.isdigit() != y.isdigit():
                return -1 if x.isdigit() else 1
            return (x > y) - (x < y)
        return (len(a[1]) > len(b[1])) - (len(a[1]) < len(b[1]))
    if scheme.casefold() != "python":
        return None
    try:
        a, b = Version(left), Version(right)
    except InvalidVersion:
        return None
    return (a > b) - (a < b)


def _version_entry(asset_version: str, entry: dict[str, Any]) -> bool | None:
    if any(key in entry and not isinstance(entry[key], str) for key in ("version", "versionType", "lessThan", "lessThanOrEqual", "status")):
        return None
    start = str(entry.get("version") or "").strip()
    scheme = str(entry.get("versionType") or "").strip()
    less_than = entry.get("lessThan")
    less_equal = entry.get("lessThanOrEqual")
    if not start or entry.get("status") not in {"affected", "unaffected", "unknown"}:
        return None
    if less_than is not None and less_equal is not None:
        return None
    if less_than is None and less_equal is None and start == "*":
        return True
    if less_than is None and less_equal is None:
        if asset_version == start:
            return True
        comparison = _compare_versions(asset_version, start, scheme)
        if scheme.casefold() in {"semver", "python"}:
            return comparison == 0 if comparison is not None else None
        if any(char in start for char in "*?<>="):
            return None
        return False
    if _compare_versions(asset_version, asset_version, scheme) is None:
        return None
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
    if not isinstance(changes, list) or any(not isinstance(change, dict) or not isinstance(change.get("at"), str) for change in changes):
        return None
    if any(_compare_versions(asset_version, change["at"], scheme) is None for change in changes):
        return None
    for change in changes:
        if any(_compare_versions(change["at"], other["at"], scheme) == 0 and change.get("status") != other.get("status") for other in changes):
            return None
    ordered = sorted(changes, key=cmp_to_key(lambda a, b: _compare_versions(a["at"], b["at"], scheme)))
    for change in ordered:
        if _compare_versions(asset_version, change["at"], scheme) >= 0:
            status = str(change.get("status") or "unknown").casefold()
    return status


def evaluate_cve_evidence(asset: Asset, evidence: Evidence) -> Decision:
    if not known_version(asset.version):
        return Decision(Applicability.NEEDS_REVIEW, "inventory version is missing or unknown")
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
        if any(product.get(key) for key in ("platforms", "modules", "programFiles", "programRoutines")):
            uncertain_version = True
            continue
        versions = product.get("versions") or []
        if not isinstance(versions, list):
            uncertain_version = True
            continue
        matched_version = False
        for entry in versions:
            if not isinstance(entry, dict):
                uncertain_version = True
                continue
            match = _version_entry(asset.version, entry)
            if match is None:
                uncertain_version = True
            elif match:
                matched_version = True
                status = _entry_status(asset.version, entry)
                if status not in {"affected", "unaffected"}:
                    uncertain_version = True
                else:
                    explicit_states.append(status)
        if not matched_version and not uncertain_version and product.get("defaultStatus"):
            explicit_states.append(str(product["defaultStatus"]).casefold())
    states = set(explicit_states)
    if "affected" in states and "unaffected" in states:
        return Decision(Applicability.NEEDS_REVIEW, "official record contains conflicting version statuses", conflict=True)
    if states.intersection({"affected", "unaffected"}) and uncertain_version:
        return Decision(Applicability.NEEDS_REVIEW, "explicit evidence overlaps version semantics that cannot be compared safely", conflict=True)
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
    if not known_version(version) or any(ord(char) < 32 for char in version):
        raise ValueError("an exact known version is required for CPE lookup")
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
    if escaped_field or len(parts) != 11 or any(not part for part in parts) or parts[0] not in {"a", "h", "o"} or parts[1] in {"*", "-"} or parts[2] in {"*", "-"}:
        raise ValueError("configured CPE must be a complete CPE 2.3 name")
    escaped = re.sub(r"([^A-Za-z0-9._-])", r"\\\1", version.strip())
    parts[3] = escaped
    return "cpe:2.3:" + ":".join(parts)


def evaluate_nvd_evidence(cpe: str, evidence: Evidence) -> Decision:
    """Use API version matching only for unconditional product configurations.

    The API filter identifies a vulnerable CPE match, not satisfaction of an
    entire deployment's AND/negated/platform conditions. Inventory lacks those.
    """
    from .sources.nvd import split_cpe23

    target = split_cpe23(cpe, keep_escapes=True)
    configurations = evidence.details.get("configurations")
    unresolved = Decision(Applicability.NEEDS_REVIEW, "NVD discovery requires review of configuration or platform conditions")
    if len(target) != 11 or not isinstance(configurations, list) or not configurations:
        return unresolved
    matched = False

    def visit(node):
        nonlocal matched
        if not isinstance(node, dict) or node.get("negate") or node.get("operator", "OR") != "OR":
            return False
        children = node.get("nodes", [])
        matches = node.get("cpeMatch", [])
        if not isinstance(children, list) or not isinstance(matches, list) or not (children or matches):
            return False
        for entry in matches:
            if not isinstance(entry, dict) or entry.get("vulnerable") is not True:
                return False
            criteria = split_cpe23(str(entry.get("criteria", "")), keep_escapes=True)
            if len(criteria) != 11:
                return False
            if tuple(x.casefold() for x in criteria[:3]) != tuple(x.casefold() for x in target[:3]):
                continue
            for wanted, actual in zip(criteria[4:], target[4:]):
                if wanted != "*" and (actual == "*" or wanted.casefold() != actual.casefold()):
                    return False
            matched = True
        return all(visit(child) for child in children)

    if all(visit(config) for config in configurations) and matched:
        return Decision(Applicability.AFFECTED, "NVD exact-version filter matched an unconditional vulnerable product configuration")
    return unresolved
