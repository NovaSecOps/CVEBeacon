"""Conservative local package extraction, not general SBOM conformance validation."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
from pathlib import Path

from cvebeacon.inventory import validate_records
from cvebeacon.identity import identity_conflict, parse_purl, purl_string

from .contract import (ExtensionError, MAX_RECORDS, MAX_TEXT, _atomic, canonical_records,
                       decode_json, json_bytes, label, read_bytes, write_snapshot)

SPDX3_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"


def text(value, field: str, *, required=False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or len(value) > MAX_TEXT or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ExtensionError(f"{field} must be bounded text without control characters")
    if required and not value:
        raise ExtensionError(f"{field} is required")
    return value


def objects(value, field: str) -> list[dict]:
    if not isinstance(value, list) or len(value) > MAX_RECORDS or any(not isinstance(item, dict) for item in value):
        raise ExtensionError(f"{field} must be a bounded list of objects")
    return value


def stable_id(source: str, slot: str) -> str:
    # Version is excluded by callers so ordinary upgrades retain component IDs.
    value = json_bytes([label(source), slot])
    return "component-" + hashlib.sha256(value).hexdigest()[:32]


def _single(values: list[str], field: str) -> str:
    unique = set(values) - {""}
    if len(unique) > 1:
        raise ExtensionError(f"conflicting explicit {field} identities")
    return next(iter(unique), "")


def _cdx(document: dict):
    if document.get("bomFormat") != "CycloneDX" or text(document.get("specVersion"), "specVersion") not in {"1.4", "1.5", "1.6", "1.7"}:
        raise ExtensionError("supported CycloneDX JSON versions are 1.4–1.7")
    stack = [(item, "") for item in reversed(objects(document.get("components", []), "components"))]
    metadata = document.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ExtensionError("metadata must be an object")
    if "component" in metadata:
        if not isinstance(metadata["component"], dict):
            raise ExtensionError("metadata.component must be an object")
        stack.append((metadata["component"], ""))
    count = 0
    while stack:
        item, inherited = stack.pop()
        count += 1
        if count > MAX_RECORDS:
            raise ExtensionError("too many components")
        scope = text(item.get("scope", "required"), "scope")
        if scope not in {"required", "optional", "excluded"}:
            raise ExtensionError("unsupported component scope")
        if type(item.get("isExternal", False)) is not bool:
            raise ExtensionError("isExternal must be boolean")
        if "versionRange" in item:
            text(item["versionRange"], "versionRange", required=True)
            if not item.get("isExternal") or "version" in item:
                raise ExtensionError("versionRange requires an external component without version")
        unsupported = inherited or ("external-component" if item.get("isExternal") else
                                    "not-runtime-component" if scope != "required" else "")
        stack.extend((child, unsupported) for child in reversed(objects(item.get("components", []), "nested components")))
        yield dict(ref=text(item.get("bom-ref"), "bom-ref"), name=text(item.get("name"), "name", required=True),
                   version=text(item.get("version"), "version"), purl=text(item.get("purl"), "purl"),
                   cpe=text(item.get("cpe"), "cpe"), unsupported=unsupported)


def _spdx2(document: dict):
    if text(document.get("spdxVersion"), "spdxVersion") not in {"SPDX-2.2", "SPDX-2.3"}:
        raise ExtensionError("supported SPDX 2 JSON versions are 2.2 and 2.3")
    for item in objects(document.get("packages"), "packages"):
        purls, cpes, unsupported = [], [], ""
        for ref in objects(item.get("externalRefs", []), "externalRefs"):
            category = text(ref.get("referenceCategory"), "referenceCategory", required=True)
            kind = text(ref.get("referenceType"), "referenceType", required=True)
            locator = text(ref.get("referenceLocator"), "referenceLocator", required=True)
            if category == "PACKAGE-MANAGER" and kind == "purl":
                purls.append(locator)
            elif category == "SECURITY" and kind == "cpe23Type":
                cpes.append(locator)
            elif category == "SECURITY" and kind == "cpe22Type":
                unsupported = "unsupported-cpe22"
        yield dict(ref=text(item.get("SPDXID"), "SPDXID", required=True), name=text(item.get("name"), "name", required=True),
                   version=text(item.get("versionInfo"), "versionInfo"), purl=_single(purls, "PURL"),
                   cpe=_single(cpes, "CPE"), unsupported=unsupported)


def _spdx3(document: dict):
    if document.get("@context") != SPDX3_CONTEXT:
        raise ExtensionError("only the official SPDX 3.0.1 compact JSON-LD context is supported")
    nodes = objects(document.get("@graph"), "@graph")
    identities = {}
    creation_ids = set()
    # No remote contexts, external nodes or arbitrary JSON-LD expansion.
    stack = [document]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            allowed = {"@context", "@graph"} if item is document else {"@id"}
            if any(key.startswith("@") and key not in allowed for key in item):
                raise ExtensionError("unsupported or nested JSON-LD keywords")
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    for node in nodes:
        if "spdxId" in node and "@id" in node:
            raise ExtensionError("ambiguous SPDX graph ID aliases")
        identifier = text(node.get("spdxId") or node.get("@id"), "graph ID", required=True)
        if identifier in identities:
            raise ExtensionError("duplicate SPDX graph ID")
        identities[identifier] = node
        kind = text(node.get("type"), "type", required=True)
        if kind == "CreationInfo":
            if node.get("specVersion") != "3.0.1":
                raise ExtensionError("SPDX CreationInfo must specify 3.0.1")
            creation_ids.add(identifier)
    if not creation_ids:
        raise ExtensionError("SPDX 3.0.1 CreationInfo is required")
    for item in nodes:
        if item["type"] != "software_Package":
            continue
        text(item.get("spdxId"), "package spdxId", required=True)
        creation = text(item.get("creationInfo"), "package creationInfo", required=True)
        if creation not in creation_ids:
            raise ExtensionError("package creationInfo must reference a local 3.0.1 CreationInfo")
        purls = [text(item.get("software_packageUrl"), "software_packageUrl")]
        cpes, unsupported = [], ""
        for ref in objects(item.get("externalIdentifier", []), "externalIdentifier"):
            if ref.get("type") != "ExternalIdentifier":
                raise ExtensionError("externalIdentifier must have type ExternalIdentifier")
            kind = text(ref.get("externalIdentifierType"), "externalIdentifierType", required=True)
            locator = text(ref.get("identifier"), "identifier", required=True)
            if kind == "packageUrl":
                purls.append(locator)
            elif kind == "cpe23":
                cpes.append(locator)
            elif kind == "cpe22":
                unsupported = "unsupported-cpe22"
        yield dict(ref=item.get("spdxId", ""), name=text(item.get("name"), "name", required=True),
                   version=text(item.get("software_packageVersion"), "software_packageVersion"),
                   purl=_single(purls, "PURL"), cpe=_single(cpes, "CPE"), unsupported=unsupported)


def extract_sbom(document: dict, *, source_id: str, format: str = "auto") -> tuple[list[dict], list[dict]]:
    label(source_id)
    if not isinstance(document, dict):
        raise ExtensionError("SBOM root must be an object")
    if format == "auto":
        format = "cyclonedx" if document.get("bomFormat") == "CycloneDX" else "spdx" if "spdxVersion" in document or "@context" in document else "unknown"
    if format == "cyclonedx":
        items = _cdx(document)
    elif format == "spdx":
        items = _spdx2(document) if "spdxVersion" in document else _spdx3(document)
    else:
        raise ExtensionError("unrecognized SBOM format")
    refs, rows, reviews = {}, {}, []
    for item in items:
        ref = item.pop("ref")
        if ref:
            if ref in refs and refs[ref] != item:
                raise ExtensionError("conflicting reuse of SBOM component identifier")
            refs[ref] = item
        if item["unsupported"]:
            reviews.append(dict(name=item["name"], version=item["version"], reason=item["unsupported"]))
            continue
        if not item["purl"] and not item["cpe"]:
            reviews.append(dict(name=item["name"], version=item["version"], reason="no-explicit-package-identity"))
            continue
        # SBOM display names need not equal registry-qualified names. Let core
        # derive product/vendor from explicit identities rather than guessing.
        value = dict(asset_id="candidate", version=item["version"], purl=item["purl"], cpe=item["cpe"],
                     system_id=source_id, category="sbom")
        asset = validate_records([value])[0]
        if identity_conflict(asset):
            raise ExtensionError("PURL and CPE require review; equivalence is not established")
        if not asset.version:
            reviews.append(dict(name=item["name"], version="", reason="no-installed-version"))
            continue
        if asset.purl:
            purl = parse_purl(asset.purl)
            slot = purl_string(purl._replace(version=None))
        else:
            from cvebeacon.sources.nvd import split_cpe23
            parts = list(split_cpe23(asset.cpe))
            parts[3] = ""
            slot = "cpe:" + repr(parts)
        row = asdict(asset)
        row["asset_id"] = stable_id(source_id, slot)
        if row["asset_id"] in rows and rows[row["asset_id"]] != row:
            raise ExtensionError("multiple versions in one component slot need separate inventory instance grouping")
        rows[row["asset_id"]] = row
    return (canonical_records(list(rows.values())) if rows else [],
            sorted(reviews, key=lambda item: (item["name"], item["version"], item["reason"])))


def import_sbom(path: Path, output: Path, *, source_id: str, format: str = "auto") -> dict:
    if Path(path).resolve() in {Path(output).resolve(), Path(str(output)+".manifest.json").resolve(), Path(str(output)+".review.json").resolve()}:
        raise ExtensionError("output must not overwrite input SBOM")
    rows, reviews = extract_sbom(decode_json(read_bytes(path)), source_id=source_id, format=format)
    # Discovery review contains only explicitly selected component names and
    # versions, never arbitrary properties, supplier contacts, VEX or findings.
    review_data = json_bytes(dict(source_id=source_id, reviews=reviews))
    from .contract import MAX_BYTES
    if len(review_data) > MAX_BYTES:
        raise ExtensionError("review output exceeds size limit")
    if not rows:
        _atomic(Path(str(output) + ".review.json"), review_data)
        raise ExtensionError("no components with explicit identity and version; review output written")
    # Preflight the review destination so a bad link cannot cause partial publication.
    review_path = Path(str(output) + ".review.json")
    if review_path.exists() or review_path.is_symlink():
        from .contract import _regular
        _regular(review_path)
    _atomic(review_path, review_data)
    return write_snapshot(output, rows, source_id=source_id, collector="sbom",
                          omissions=["review-required"] if reviews else [])
