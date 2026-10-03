import copy
import json
import hashlib
from pathlib import Path

import pytest

from cvebeacon.config import InventoryConfig
from cvebeacon.errors import InventoryValidationError
from cvebeacon.inventory import load_inventory
from cvebeacon_extensions.contract import ExtensionError, decode_json, read_snapshot
from cvebeacon_extensions.sbom import SPDX3_CONTEXT, extract_sbom, import_sbom
from cvebeacon_extensions.cli import main


def cdx(components=None, version="1.7"):
    return dict(bomFormat="CycloneDX", specVersion=version, components=components if components is not None else [dict(name="display name", purl="pkg:pypi/example@1", version="1")])


def spdx2(packages=None, version="SPDX-2.3"):
    return dict(spdxVersion=version, packages=packages if packages is not None else [dict(SPDXID="SPDXRef-example", name="example", versionInfo="1", externalRefs=[dict(referenceCategory="PACKAGE-MANAGER", referenceType="purl", referenceLocator="pkg:pypi/example@1")])])


def spdx3():
    return {"@context": SPDX3_CONTEXT, "@graph": [
        {"@id": "_:creation", "type": "CreationInfo", "specVersion": "3.0.1"},
        {"spdxId": "urn:example:pkg", "type": "software_Package", "name": "example", "creationInfo": "_:creation",
         "software_packageVersion": "1", "software_packageUrl": "pkg:pypi/example@1"}]}


@pytest.mark.parametrize("document", [cdx(version=v) for v in ["1.4", "1.5", "1.6", "1.7"]] + [spdx2(version=v) for v in ["SPDX-2.2", "SPDX-2.3"]] + [spdx3()])
def test_supported_formats_roundtrip_core(tmp_path, document):
    source, output = tmp_path / "sbom.json", tmp_path / "inventory.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    manifest = import_sbom(source, output, source_id="build-a")
    assert manifest["status"] == "success"
    assert len(read_snapshot(output).records) == 1
    asset = load_inventory(InventoryConfig(output))[0]
    assert asset.purl == "pkg:pypi/example@1"
    assert asset.product == "example"
    assert source.read_text(encoding="utf-8") == json.dumps(document)


def test_nested_unicode_qualifiers_metadata_and_duplicate_components():
    component = dict(name="snowman ☃", version="1", purl="pkg:generic/%E2%98%83@1?arch=arm64", **{"bom-ref": "snow"})
    document = cdx([dict(name="assembly", components=[component, copy.deepcopy(component)])])
    document["metadata"] = dict(component=dict(name="root", purl="pkg:npm/root@2"), tools=dict(components=[dict(name="tool", purl="pkg:pypi/should-not-import@1")]))
    rows, reviews = extract_sbom(document, source_id="build")
    assert len(rows) == 2 and len(reviews) == 1
    assert any("arch=arm64" in row["purl"] for row in rows)
    assert not any("should-not-import" in row["purl"] for row in rows)


def test_upgrade_stability_and_source_separation():
    old, _ = extract_sbom(cdx(), source_id="host-a")
    new, _ = extract_sbom(cdx([dict(name="example", purl="pkg:pypi/example@2")]), source_id="host-a")
    other, _ = extract_sbom(cdx(), source_id="host-b")
    assert old[0]["asset_id"] == new[0]["asset_id"] != other[0]["asset_id"]


@pytest.mark.parametrize("components", [
    [dict(name="example", purl="pkg:pypi/example@1", version="2")],
    [dict(name="example", purl="pkg:pypi/example@1", cpe="cpe:2.3:a:acme:example:1:*:*:*:*:*:*:*")],
    [dict(name="example", purl="pkg:pypi/example%ZZ@1")],
    [dict(name="example", purl="pkg:pypi/example@1"), dict(name="example", purl="pkg:pypi/example@2")],
    [dict(name="a", purl="pkg:pypi/a@1", **{"bom-ref":"same"}), dict(name="b", purl="pkg:pypi/b@1", **{"bom-ref":"same"})],
    [dict(name="example", version=1, purl="pkg:pypi/example@1")],
    [dict(name="example", components={})],
])
def test_malformed_conflicting_documents_fail_before_output(tmp_path, components):
    source, output = tmp_path / "sbom.json", tmp_path / "out.json"
    source.write_text(json.dumps(cdx(components)))
    with pytest.raises((ExtensionError, InventoryValidationError)):
        import_sbom(source, output, source_id="build")
    assert not output.exists()


def test_missing_identity_version_are_review_not_invented(tmp_path):
    source, output = tmp_path / "sbom.json", tmp_path / "out.json"
    source.write_text(json.dumps(cdx([dict(name="example", purl="pkg:pypi/example"), dict(name="arbitrary-npm-name", version="1"), dict(name="good", purl="pkg:pypi/good@1")])))
    assert import_sbom(source, output, source_id="build")["status"] == "partial"
    with pytest.raises(ExtensionError, match="partial"):
        read_snapshot(output)
    assert len(read_snapshot(output, allow_partial=True).records) == 1
    reviews = json.loads((tmp_path / "out.json.review.json").read_bytes())["reviews"]
    assert {row["reason"] for row in reviews} == {"no-explicit-package-identity", "no-installed-version"}


def test_no_eligible_component_never_refreshes_inventory(tmp_path):
    source, output = tmp_path / "sbom.json", tmp_path / "out.json"
    source.write_text(json.dumps(cdx()))
    import_sbom(source, output, source_id="build")
    before = output.read_bytes()
    source.write_text(json.dumps(cdx([dict(name="weak", version="1")])) )
    assert main(["sbom", "import", str(source), "--output", str(output), "--source-id", "build"]) == 2
    assert output.read_bytes() == before


def test_spdx_arbitrary_refs_supplier_and_findings_are_not_identity():
    document = spdx2([dict(SPDXID="SPDXRef-a", name="weak", versionInfo="1", supplier="Person: Sensitive Contact", externalRefs=[dict(referenceCategory="OTHER", referenceType="advisory", referenceLocator="pkg:pypi/example@1")])])
    document["vulnerabilities"] = [{"id":"CVE-2026-1234", "state":"affected"}]
    rows, reviews = extract_sbom(document, source_id="build")
    assert rows == [] and len(reviews) == 1
    assert "Sensitive" not in json.dumps(reviews)
    document["packages"][0]["externalRefs"][0] = dict(referenceCategory="SECURITY", referenceType="cpe22Type", referenceLocator="cpe:/a:example:example:1")
    assert extract_sbom(document, source_id="build")[1][0]["reason"] == "unsupported-cpe22"


@pytest.mark.parametrize("mutation", ["context", "nested-context", "duplicate-id", "version", "expanded", "no-creation"])
def test_spdx3_restricted_context_and_graph(mutation):
    document = spdx3()
    if mutation == "context": document["@context"] = "https://untrusted.invalid/context"
    if mutation == "nested-context": document["@graph"][1]["@context"] = {"software_packageUrl":"untrusted"}
    if mutation == "duplicate-id": document["@graph"].append(copy.deepcopy(document["@graph"][1]))
    if mutation == "version": document["@graph"][0]["specVersion"] = "3.1"
    if mutation == "expanded": document["@graph"][1]["type"] = ["https://spdx.org/rdf/3.0.1/terms/Software/Package"]
    if mutation == "no-creation": document["@graph"].pop(0)
    with pytest.raises(ExtensionError):
        extract_sbom(document, source_id="build")


def test_spdx3_typed_external_identifiers_and_conflicts():
    document = spdx3()
    item = document["@graph"][1]
    item.pop("software_packageUrl")
    item["externalIdentifier"] = [dict(type="ExternalIdentifier", externalIdentifierType="packageUrl", identifier="pkg:pypi/example@1")]
    assert extract_sbom(document, source_id="build")[0][0]["purl"] == "pkg:pypi/example@1"
    item["externalIdentifier"].append(dict(type="ExternalIdentifier", externalIdentifierType="packageUrl", identifier="pkg:pypi/different@1"))
    with pytest.raises(ExtensionError, match="conflicting"):
        extract_sbom(document, source_id="build")


def test_unknown_versions_and_path_overwrite(tmp_path):
    with pytest.raises(ExtensionError): extract_sbom(cdx(version="1.3"), source_id="build")
    with pytest.raises(ExtensionError): extract_sbom(spdx2(version="SPDX-3.0"), source_id="build")
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(cdx()))
    with pytest.raises(ExtensionError, match="overwrite"):
        import_sbom(path, path, source_id="build")


@pytest.mark.parametrize("flags", [dict(isExternal=True), dict(scope="excluded"), dict(scope="optional")])
def test_cyclonedx_environment_requirements_are_not_installed_components(flags):
    document = cdx([dict(name="parent", purl="pkg:pypi/parent@1", components=[dict(name="child", purl="pkg:pypi/child@1")], **flags)])
    rows, reviews = extract_sbom(document, source_id="build")
    assert not rows and len(reviews) == 2


@pytest.mark.parametrize("document", [cdx(version=[]), spdx2(version={}), cdx([dict(name="example", isExternal="true")])])
def test_control_fields_have_strict_types(document):
    with pytest.raises(ExtensionError):
        extract_sbom(document, source_id="build")


def test_authoritative_immutable_examples():
    fixtures = Path(__file__).parent / "fixtures" / "upstream"
    checksums = {
        "cyclonedx-1.7-evidence.json": "0ff0f3d383d4c74e2d60f95196150438d89c63399def513921c33a0dfbd245d5",
        "cyclonedx-1.7-identifiers.json": "6d863e50647dd6d9378a0302b1475c9f30a4b403ec37f1b3d172e65a15fcf760",
        "cyclonedx-1.7-assembly.json": "2a8f25a6564c12040d2930f9800b5aaa09ab6b65c5cc1c39ee7b9ac488079223",
        "spdx-2.3-example.json": "02587af9865ab1c926eb0513700e59fcf105881f1b6cc025def5fbff919e98d1",
        "spdx-3.0.1-example13.json": "968511c66702bf824545a67fa9e61bad3b9bd7257b699375eca9f26b5ee3319f",
    }
    documents = {}
    for name, expected in checksums.items():
        raw = (fixtures / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        documents[name] = decode_json(raw)
    rows, reviews = extract_sbom(documents["cyclonedx-1.7-evidence.json"], source_id="upstream-example")
    assert len(rows) == 2 and not reviews
    assert {row["ecosystem"] for row in rows} == {"Maven"}
    for name in ["cyclonedx-1.7-identifiers.json", "spdx-2.3-example.json"]:
        with pytest.raises((ExtensionError, InventoryValidationError)):
            extract_sbom(documents[name], source_id="upstream-example")
    rows, reviews = extract_sbom(documents["cyclonedx-1.7-assembly.json"], source_id="upstream-example")
    assert not rows and len(reviews) == 2
    rows, reviews = extract_sbom(documents["spdx-3.0.1-example13.json"], source_id="upstream-example")
    assert not rows and len(reviews) == 4


@pytest.mark.parametrize("creation", [None, {}, "https://untrusted.invalid/creation", "urn:example:pkg"])
def test_spdx3_package_binds_to_local_creation_info(creation):
    document = spdx3()
    document["@graph"][1]["creationInfo"] = creation
    with pytest.raises(ExtensionError):
        extract_sbom(document, source_id="build")


@pytest.mark.parametrize("alias,value", [("@id", "urn:contradiction"), ("@type", "Person")])
def test_spdx3_rejects_ambiguous_jsonld_aliases(alias, value):
    document = spdx3()
    document["@graph"][1][alias] = value
    with pytest.raises(ExtensionError):
        extract_sbom(document, source_id="build")


@pytest.mark.parametrize("component", [
    dict(name="example", version="1", purl="pkg:pypi/example@1", versionRange="vers:pypi/>=2"),
    dict(name="example", version="1", purl="pkg:pypi/example@1", versionRange="vers:pypi/>=2", isExternal=True),
])
def test_cyclonedx_version_range_contradiction(component):
    with pytest.raises(ExtensionError, match="versionRange"):
        extract_sbom(cdx([component]), source_id="build")


def test_unpaired_surrogate_fails_cleanly_preserves_output(tmp_path):
    source, output = tmp_path / "sbom.json", tmp_path / "out.json"
    source.write_text(json.dumps(cdx()))
    import_sbom(source, output, source_id="build")
    before = output.read_bytes()
    source.write_text(json.dumps(cdx([dict(name="\ud800", version="1")])))
    assert main(["sbom", "import", str(source), "--output", str(output), "--source-id", "build"]) == 2
    assert output.read_bytes() == before
