"""Offline structural checks for exported STIX 2.1 bundles."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

_ID = re.compile(
    r"^([a-z0-9-]+)--"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)
_CUSTOM = re.compile(r"^x_cvebeacon_[a-z0-9_]+$")
_RELATIONSHIP = re.compile(r"^[a-z0-9-]+$")
_TYPES = {
    "bundle",
    "identity",
    "relationship",
    "report",
    "software",
    "vulnerability",
}
_SDO_OR_SRO = {"identity", "relationship", "report", "vulnerability"}


def _timestamp(value: Any) -> datetime:
    assert isinstance(value, str) and value.endswith("Z"), value
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    assert parsed.tzinfo is not None
    assert value == parsed.isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    return parsed


def _identifier(value: Any, expected_type: str) -> str:
    assert isinstance(value, str), value
    match = _ID.fullmatch(value)
    assert match is not None, value
    assert match.group(1) == expected_type, value
    assert uuid.UUID(match.group(2)).version == 5, value
    return value


def validate_bundle(bundle: dict[str, Any]) -> None:
    """Assert the required properties, references, and ID forms of a bundle."""
    assert isinstance(bundle, dict)
    assert bundle["type"] == "bundle"
    assert set(bundle) == {"type", "id", "objects"}
    _identifier(bundle["id"], "bundle")
    objects = bundle["objects"]
    assert isinstance(objects, list)
    by_id: dict[str, dict[str, Any]] = {}
    for value in objects:
        assert isinstance(value, dict)
        assert value["type"] in _TYPES - {"bundle"}
        _identifier(value["id"], value["type"])
        assert value["id"] not in by_id
        by_id[value["id"]] = value
        for key in value:
            if key.startswith("x_"):
                assert _CUSTOM.fullmatch(key), key
        if value["type"] in _SDO_OR_SRO:
            assert value["spec_version"] == "2.1"
            created = _timestamp(value["created"])
            modified = _timestamp(value["modified"])
            assert created <= modified
        elif value["type"] == "software":
            assert value.get("spec_version") in {None, "2.1"}

    for value in objects:
        kind = value["type"]
        if kind == "vulnerability":
            assert isinstance(value.get("name"), str) and value["name"]
            references = value["external_references"]
            assert isinstance(references, list) and references
            for reference in references:
                assert isinstance(reference["source_name"], str)
                assert reference["source_name"]
            if value["name"].startswith("CVE-"):
                by_source = {
                    reference["source_name"]: reference
                    for reference in references
                }
                assert by_source["cve"]["external_id"] == value["name"]
                assert by_source["cve"]["url"].endswith(value["name"])
                assert by_source["nvd"]["external_id"] == value["name"]
            assert value["x_cvebeacon_applicability"] in {
                "affected",
                "needs_review",
            }
            assert isinstance(value["x_cvebeacon_sources"], list)
            _timestamp(value["x_cvebeacon_first_seen"])
        elif kind == "software":
            assert isinstance(value["name"], str) and value["name"]
            for name in ("cpe", "vendor", "version"):
                if name in value:
                    assert isinstance(value[name], str) and value[name]
        elif kind == "relationship":
            assert _RELATIONSHIP.fullmatch(value["relationship_type"])
            assert value["relationship_type"] == "has"
            assert value["source_ref"] in by_id
            assert value["target_ref"] in by_id
            assert by_id[value["source_ref"]]["type"] == "software"
            assert by_id[value["target_ref"]]["type"] == "vulnerability"
            assert value["x_cvebeacon_applicability"] in {
                "affected",
                "needs_review",
            }
            _timestamp(value["x_cvebeacon_first_seen"])
        elif kind == "identity":
            assert isinstance(value["name"], str) and value["name"]
            assert isinstance(value["identity_class"], str)
        elif kind == "report":
            assert isinstance(value["name"], str) and value["name"]
            _timestamp(value["published"])
            references = value["object_refs"]
            assert isinstance(references, list) and references
            for reference in references:
                assert reference in by_id
                assert reference != value["id"]
