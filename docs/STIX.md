# STIX 2.1 export

`cvebeacon export stix` writes the latest successful inventory scan as one
STIX 2.1 JSON bundle. It is an optional interoperability output: CVEBeacon has
no runtime dependency on STIX, OpenCTI, a SIEM, a data lake, or a TAXII server.

The export is a snapshot, not a threat-intelligence feed and not a claim that an
asset is safe. Review the access and handling rules before sharing a bundle.

## Command

```console
cvebeacon --config cvebeacon.toml export stix --output findings.json
cvebeacon --config cvebeacon.toml export stix --output acme.json --client Acme
cvebeacon --config cvebeacon.toml export stix --output clients.json --include-clients
cvebeacon --config cvebeacon.toml export stix --output recent.json --since 2026-11-01
```

`--output` is required. The command is read-only: it does not create the state
database, change findings, deliver notifications, query public sources, or read
the watch database. Only the configured state database is needed; an inventory
path is not read, so a state-only configuration is sufficient for this command.

| Option | Meaning |
| --- | --- |
| `--output FILE` | Write the bundle to this file atomically. |
| `--client LABEL` | Export only findings on assets assigned to this client. Matching ignores case. The label is not emitted unless `--include-clients` is also set. |
| `--include-clients` | Emit one `identity` object per exported client, add client labels to relationship properties, and put a client label in the report name. Off by default. |
| `--since DATE` | Export only findings whose first-seen time is on or after this UTC date or ISO 8601 timestamp. |

The source is the newest inventory run with `status='completed'` in the state
database. A failed or degraded run does not replace the last successful run.
An empty state or a filter that matches nothing still produces a valid bundle
with an empty `objects` list.

## What is exported

Only `affected` and `needs_review` findings are included. The state is preserved
in every relationship and vulnerability object.

| Applicability | Exported | `x_cvebeacon_applicability` | Interpretation |
| --- | --- | --- | --- |
| `affected` | yes | `affected` | Affirmative primary-source evidence supports the match. |
| `needs_review` | yes | `needs_review` | Relevant evidence exists but the match is incomplete, unsupported, or conflicting. This is the "probable" state; it is not confirmation. |
| `not_affected` | no | not present | The exporter makes no statement about omitted assets. |
| `coverage_unknown` | no | not present | Unknown coverage is never presented as affected. |

The exporter does not add a clean result for an omitted finding. Consumers must
not infer that an absent object means an asset is unaffected.

## Mapping

| CVEBeacon value | STIX 2.1 representation |
| --- | --- |
| Finding identifier, preferring a CVE | `vulnerability.name` and the stable input to the vulnerability UUID |
| CVE ID | `external_references` with `source_name: cve` and the exact CVE, plus an NVD reference |
| Non-CVE advisory ID | The advisory ID becomes `vulnerability.name`; its external reference uses `source_name: advisory` |
| Vulnerability summary | `vulnerability.description` when present |
| Asset vendor, product, version, CPE | `software.name`, `software.vendor`, `software.version`, `software.cpe` |
| Asset PURL and ecosystem | `x_cvebeacon_purl` and `x_cvebeacon_ecosystem` on `software` |
| Finding applicability | `x_cvebeacon_applicability` on `vulnerability` and `relationship` |
| Finding confidence | `x_cvebeacon_confidence` on `vulnerability` and `relationship` |
| Finding first-seen time | `created` on vulnerability and relationship; `x_cvebeacon_first_seen` |
| Finding last-seen time | `modified` on vulnerability and relationship |
| Evidence source names | `x_cvebeacon_sources` on vulnerability and relationship |
| Client label (only with `--include-clients`) | An `identity` object, `x_cvebeacon_clients` on relationship, and the report name |
| Software-to-vulnerability match | `relationship` with `relationship_type: has` |
| The selected export | One `report` object containing every exported object reference |

The export deliberately omits asset IDs, system IDs, categories, repository
URLs, commits, evidence statements, and source details. Those values are local
operational data and are not needed for interoperability. The software object
uses the public component identity, so two assets with the same vendor, product,
version, and identity path produce one software object.

### The `has` relationship

STIX 2.1 defines standard relationship types such as `targets`, `uses`, and
`related-to`, but it does not define a standard software-to-vulnerability
relationship type. The specification permits user-defined relationship types
(section 5.1), so this exporter uses `has` to make the direction explicit:
software `has` vulnerability.

A consumer that accepts only specification-defined relationship types should map
`has` to `related-to`. This exporter does not emit both because that would create
two edges for one match.

## Deterministic identifiers

Every object ID is a UUIDv5 under the fixed project namespace
`1c0ca72c-9854-4be1-b48b-ef2e89900fdc`. The name is a stable key:

| Object | Stable key |
| --- | --- |
| `vulnerability` | `vulnerability\|<identifier>` |
| `software` | `software\|purl\|<purl>\|<version>`, `software\|cpe\|<cpe>\|<version>`, or `software\|product\|<ecosystem>\|<vendor>\|<product>\|<version>` |
| `relationship` | `relationship\|has\|<software id>\|<vulnerability id>` |
| `identity` | `identity\|client\|<case-folded client label>` |
| `report` | `report\|<sorted object IDs>` |
| `bundle` | `bundle\|<sorted object IDs>` |

Re-exporting the same state produces the same IDs, so a consumer that updates by
ID does not create duplicates. A new scan changes `modified` and can add or
remove objects. Removed findings are not emitted as revoked objects: the bundle
is a snapshot, not a tombstone feed.

`created` and `modified` come from the stored finding timestamps. Identity and
report objects use the export time; the report `published` value is the same
time. All timestamps are UTC with millisecond precision and a `Z` suffix.

## Privacy and client labels

Client labels are internal by default. Without `--include-clients`, the bundle
contains no client label, no client identity object, and no report name that
mentions a client. `--client` only selects which findings are exported; it does
not add the label to the output.

`--include-clients` is an explicit disclosure decision. It creates one
`identity` object per exported client, adds the labels to
`x_cvebeacon_clients` on relationships, and names the report after the client or
after "multiple clients". Review the result before sending it outside the team.

## Limits

- This is an inventory-derived applicability snapshot, not a threat-intelligence
  feed. It does not include actors, campaigns, malware, indicators, sightings, or
  analytic confidence in a threat.
- Watch-only alerts are not exported. A watch event has no inventory asset and no
  applicability state, so promoting it to a vulnerability finding would misstate
  what CVEBeacon knows. The watch database is not read.
- Applicability evidence, reasons, CVSS, EPSS, and KEV details are not copied into
  this version of the bundle. The state and source names are preserved; inspect
  the normal report or history for the full evidence.
- There are no STIX data markings. Handling rules are outside the bundle.
- The exporter does not deliver anything, run continuously, or act as a TAXII
  server. Re-run the command to refresh the snapshot.
- The target consumer may ignore custom properties or user-defined relationship
  types. Test ingestion and the queries you need before relying on it.
- The bundle is produced without the optional `stix2` package. The test suite
  checks required properties, ID formats, references, and timestamp forms with a
  small offline validator, not with a third-party schema implementation.
- A state database written before run-scoped finding details existed is read
  through a conservative fallback. Run a scan with the current version to store
  exact per-run details.
