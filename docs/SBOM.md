# SBOM ingestion

The optional companion extracts inventory from local supplied SBOMs. It does not
generate SBOMs, fetch schemas or external references, resolve JSON-LD over the
network, or import vulnerability/VEX decisions.

```console
cvebeacon-ext sbom import application.cdx.json --source-id application-build --output application.json
cvebeacon-ext validate application.json
```

Use `--format cyclonedx` or `--format spdx` to require a format; the default is
`auto`. The input remains unchanged. Outputs are canonical inventory,
`application.json.manifest.json` and `application.json.review.json`.

## Supported extraction profiles

| Format | Scope |
| --- | --- |
| CycloneDX JSON 1.4–1.7 | Root components, nested assembly components and metadata.component; explicit `purl`, CPE 2.3 and version |
| SPDX JSON 2.2/2.3 | Packages with PACKAGE-MANAGER/purl or SECURITY/cpe23Type external references |
| SPDX 3.0.1 compact JSON-LD | Official context string, `@graph` objects, CreationInfo 3.0.1, software_Package, software_packageUrl/version and typed packageUrl/cpe23 externalIdentifier objects |

This is bounded inventory extraction, not full SBOM schema/conformance validation
or universal JSON-LD support. XML, protobuf, SPDX tag/value, custom or nested
contexts, expanded JSON-LD and CPE 2.2 conversion are not supported. SPDX 3 graph
IDs must be unique. Remote graph references and supplier/person contact details
are not dereferenced or copied.

These profiles follow the published [CycloneDX formats](https://cyclonedx.org/specification/overview/),
[SPDX 2.3 package fields](https://spdx.github.io/spdx-spec/v2.3/package-information/),
and [SPDX 3.0.1 package model](https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Package/).
CycloneDX 1.7 `isExternal` denotes a component expected from the runtime
environment, not an observation that it is installed. Such components, optional
or excluded scopes, and their nested children produce review entries. Tool and
pedigree metadata do not become installed components. A version range is not an
installed version. Dependency relationships do not change applicability.

## Identity and uncertainty

Explicit PURLs and CPEs pass the real core validator. Display names are retained
in review output but do not override registry names. Supplier names alone do not
prove software vendor identity, so the importer does not construct generic
vendor/product rows from supplier text. It never manufactures PURLs or CPEs from
names. Qualifiers, architecture, Unicode and version spelling remain intact;
unsupported core lookup types/qualifiers retain unknown coverage.

Malformed identity, mismatched explicit versions, contradictory references, or
combined PURL/CPE identity abort the import. A document may legitimately contain
both identifiers, but this importer cannot prove their equivalence. Review or
prepare a separate curated input; do not silently discard contradictions.

Exact duplicate components coalesce. Conflicting reuse of a document component
identifier fails. IDs derive from source alias and versionless explicit identity,
so ordinary upgrades retain their ID. Multiple versions of the same slot require
separate supplied inventory instance grouping; they are not collapsed. Changing
the source alias or identity qualifiers changes IDs.

Missing explicit identity/version or unsupported CPE 2.2 yields a review entry.
If eligible components remain, the snapshot is marked partial with
`review-required`; downstream validation/merge requires `--allow-partial` and
retains that status. If none remain, only review output is written, the command
fails, and any previous inventory/manifest remains unchanged and ages normally.
Review output is advisory and not the inventory authority. Collection errors
must stop scheduled pipelines.

Inputs are capped at 32 MiB, 64 structural nesting levels, 100000 components and
8192 characters per selected field. Duplicate JSON object keys and nonfinite
JSON constants are rejected. Existing source IDs, paths and SBOM contents should
be treated as local operational data. Use trusted staging directories and the
[snapshot contract](EXTENSIONS.md) for freshness and merge policies.
