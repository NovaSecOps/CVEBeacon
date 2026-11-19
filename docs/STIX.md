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

`--output` is required. The command is read-only for database content: it does
not create the state database, change findings, deliver notifications, query
public sources, or read the watch database. Only the configured state database
is needed; an inventory path is not read, so a state-only configuration is
sufficient for this command.

SQLite may create or refresh `-wal` and `-shm` sidecar files beside a
write-ahead-logging state database while it is opened read-only. Those files are
a SQLite read-side effect, not a CVEBeacon state change. On read-only media,
copy the state database and any sidecar files to a writable location before
exporting.

| Option | Meaning |
| --- | --- |
| `--output FILE` | Write the bundle to this file atomically. |
| `--client LABEL` | Export only findings on assets assigned to this client. Matching ignores case. The label is not emitted unless `--include-clients` is also set. |
| `--include-clients` | Emit one `identity` object per exported client, add client labels to relationship properties, and put a client label in the report name. Off by default. |
| `--since DATE` | Export only findings whose first-seen time is on or after this UTC date or ISO 8601 timestamp. |

The source is the newest inventory run with `status='completed'` in the state
database. A failed or degraded run does not replace the last successful run.
An empty state or a filter that matches nothing still produces a valid bundle:
the `objects` member is omitted, because STIX 2.1 `objects` is an optional set
of one or more objects rather than an empty list.

## What is exported

Only `affected` and `needs_review` findings are included. Relationships are
emitted once per state, so a software/vulnerability pair with both an affected
observation and a needs-review observation has two edges with their own sources
and confidence. A vulnerability object shows the highest state in
`x_cvebeacon_applicability` and lists every observed state in
`x_cvebeacon_states`; its sources and confidence describe that highest state.
The lower-state edge remains available for consumers that need it.

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
| Asset PURL and ecosystem | `x_cvebeacon_purl` and `x_cvebeacon_ecosystem` on `software`; the PURL is reduced to type, namespace, name, and version |
| Finding applicability | `x_cvebeacon_applicability` on `vulnerability` and `relationship`; every state is in `x_cvebeacon_states` on `vulnerability` |
| Finding confidence | `x_cvebeacon_confidence` on `vulnerability` and `relationship` |
| Finding first-seen time | `created` on vulnerability and relationship; `x_cvebeacon_first_seen` |
| Finding last-seen time | `modified` on vulnerability and relationship |
| Evidence source names | `x_cvebeacon_sources` on vulnerability and relationship when at least one source exists |
| Client label (only with `--include-clients`) | An `identity` object, `x_cvebeacon_clients` and `x_cvebeacon_client_refs` on relationship, and the report name |
| Software-to-vulnerability match | `relationship` with `relationship_type: has` |
| The selected export | One `report` object containing every exported object reference |

The export deliberately omits asset IDs, system IDs, categories, repository
URLs, commits, evidence statements, and source details. Those values are local
operational data and are not needed for interoperability. PURL qualifiers and
subpaths are also dropped before the PURL is used in the output or in an object
key, so repository, download, VCS, and token-bearing qualifiers cannot leak.
PURL namespace and name components are treated as package identity and are
intentionally retained; they must not contain credentials, tokens, or other
secrets. Do not put a URL with user information or a token into a PURL
namespace or name. The software object uses the public component identity, so
two assets with the same vendor, product, version, and identity path produce one
software object. The software identity key uses the resolved version, including
a version taken from the PURL when the inventory row has no separate version.

### The `has` relationship

STIX 2.1 defines the name `has` only for Infrastructure -> Vulnerability and
Tool -> Vulnerability. It does not define a standard software-to-vulnerability
relationship type. The specification permits any relationship name for other
source and target pairs (section 5.1), so this exporter reuses `has` from
software to vulnerability to make the direction explicit.

A consumer that enforces the specification's source/target table for `has`
should treat this edge as an extension and may map it to `related-to`. This
exporter does not emit both because that would create two edges for one match.

## Deterministic identifiers

Every object ID is a UUIDv5 under the fixed project namespace
`1c0ca72c-9854-4be1-b48b-ef2e89900fdc`. The name is a stable key:

| Object | Stable key |
| --- | --- |
| `vulnerability` | `vulnerability\|<upper-cased identifier>` |
| `software` | `software\|purl\|<sanitised purl>\|<resolved version>`, `software\|cpe\|<cpe>\|<resolved version>`, or `software\|product\|<case-folded ecosystem>\|<case-folded vendor>\|<case-folded product>\|<resolved version>` |
| `relationship` | `relationship\|has\|<software id>\|<vulnerability id>\|<state>` |
| `identity` | `identity\|client\|<case-folded client label>` |
| `report` | `report\|<sorted object IDs>` |
| `bundle` | `bundle\|<sorted object IDs>`, or `bundle\|empty` when there are no objects |

Re-exporting the same state produces the same IDs, so a consumer that updates by
ID does not create duplicates. A new scan changes `modified` and can add or
remove objects. Removed findings are not emitted as revoked objects: the bundle
is a snapshot, not a tombstone feed.

Vulnerability and relationship `created` values come from the earliest
first-seen observation in the full stored `current_findings` history for that
object, including observations outside the selected run. `modified` is the
latest observation in the selected run, clamped to be no earlier than
`created`. Report `created` is the earliest such
value in the report, and identity `created` is the earliest first-seen
observation for that client in the full history. Report `modified`/`published`
and identity `modified` use the export time, clamped to be no earlier than
`created`. This keeps `created` stable when the same state is exported again
under the same fixed IDs, including after an earlier observation drops out of a
later scan. All timestamps are UTC with millisecond precision and a `Z` suffix.

## Privacy and client labels

Client labels are internal by default. Without `--include-clients`, the bundle
contains no client label, no client identity object, and no report name that
mentions a client. `--client` only selects which findings are exported; it does
not add the label to the output.

`--include-clients` is an explicit disclosure decision. It creates one
`identity` object per exported client, adds the labels to
`x_cvebeacon_clients` on relationships, adds the matching identity IDs to
`x_cvebeacon_client_refs`, and names the report after the client or after
"multiple clients". Review the result before sending it outside the team.

Identity IDs are derived only from the client label and the fixed project
namespace. Two independent deployments that both use a label such as `Acme`
therefore mint the same identity ID for unrelated organisations. That is useful
for stable re-exports but not a global identity guarantee; keep bundles from
different deployments in separate namespaces or review identity collisions
before merging them.

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
- Only the newest successful run's finding snapshot is retained. Detail rows for
  every other run are pruned by later scans, so the table stays bounded to one
  run's findings; monitoring history and events are not pruned by this policy.
- `created` values are derived from the full stored current-findings history
  rather than a separate STIX object-version ledger. They remain stable while
  that history retains the earliest observation; deleting or replacing the
  state database removes that history.
- There are no STIX data markings. Handling rules are outside the bundle.
- The exporter does not deliver anything, run continuously, or act as a TAXII
  server. Re-run the command to refresh the snapshot.
- The target consumer may ignore custom properties or user-defined relationship
  types. Test ingestion and the queries you need before relying on it.
- The bundle is produced without the optional `stix2` package. The test suite
  checks required properties, ID formats, references, and timestamp forms with a
  small offline validator, not with a third-party schema implementation.
- A state database written before run-scoped finding details existed is read
  through a conservative fallback. The fallback matches advisory identifiers
  without case sensitivity and only accepts current-finding rows whose
  `last_seen` is the selected successful run. Run a scan with the current
  version to store exact per-run details.
