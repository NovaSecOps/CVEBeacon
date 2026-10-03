# Optional inventory extensions

Install the core as usual. To add the companion from this repository:

```console
python -m pip install .
python -m pip install ./extensions
cvebeacon-ext --help
```

No extension is needed for supplied inventory, monitoring, reporting or the
dashboard. The companion only produces inventory; it never writes monitoring
SQLite or decides vulnerability applicability.

See [SBOM import](SBOM.md) for supported formats and conservative identity rules.

## Inventory contract v1

A snapshot is a UTF-8 JSON list, directly accepted by the existing core JSON
loader, plus `<snapshot>.manifest.json`. Records use `asset_id`, `vendor`,
`product`, `version`, `category`, `system_id`, `ecosystem`, `purl`, `cpe`,
`repository`, `commit`. Values are strings; optional values serialize as empty
strings. Unknown fields are rejected in the exchange contract. IDs are unique
under core normalization and case-insensitive comparison. Version spelling and
explicit identity qualifiers are preserved.

Core `cvebeacon.inventory.validate_records` is the semantic authority and shares
the exact validator used by file input. There is intentionally no duplicate JSON
Schema identity model: structural validation alone cannot express the audited
PURL/CPE/version rules. The companion enforces bounded input (32 MiB, 100000
records, 8192 characters per inventory field) and requires separate review for
multiple strong identity systems on one row. These additional exchange limits
do not change ordinary core inventory support.

The sidecar identifies `contract` (`cvebeacon.inventory.v1`), collector/version,
`source_id`, UTC `generated_at` and `observed_at`, exact inventory `sha256`,
`record_count`, `status` and `omissions`. Successful complete collection has
`status=success`; explicit partial output carries omissions. Generation time is
publication time; observation time is the oldest included observation. Merging
does not refresh the age of old data. No sidecar field influences applicability
or enters vulnerability lookups. Source IDs should be administrator-chosen
stable aliases, not credentials or sensitive hostnames.

Writers fsync temporary files and replace inventory then manifest atomically.
Two files cannot be replaced as one transaction: interruption between replacements
produces a detectable hash mismatch. A failed collection leaves the previous
snapshot unchanged and aging. Monitor exit codes as well as snapshot age.
Concurrent cooperating writers are excluded by an exclusive output lock. After
a crash, confirm the writer has stopped before removing its stale `.lock` file.
Use administrator-controlled directories; hostile shared-directory races and
malicious collectors are outside the file trust model. Leaf symlinks/reparse
points and nonregular input/output files are rejected. Hashes are not signatures.

## Merge and freshness

```console
cvebeacon-ext merge linux-a.json linux-b.json windows-a.json --output inventory.json --source-id central --expected-source linux-a --expected-source linux-b --expected-source windows-a --max-age-seconds 86400
cvebeacon-ext validate inventory.json
cvebeacon --config cvebeacon.toml inventory validate inventory.json
```

The output and record ordering are deterministic for the same inputs; publication
timestamps naturally change. Repeated identical rows are coalesced. Conflicting
asset IDs, duplicate source IDs, or conflicting package slots within a system
fail; there is no last-writer-wins policy. Strong package slots retain PURL
qualifiers and exclude version. Ambiguous coinstalled versions in the same slot
require explicit separate system/instance grouping before merging.

Freshness defaults to 24 hours. Future timestamps, missing files, stale sources,
bad hashes, invalid records and undeclared partial snapshots fail before output.
Expected sources are optional but recommended to detect a forgotten input.
`--allow-partial` permits missing inputs/required sources and declared partial
snapshots, recording omissions; it never ignores corruption or conflicts. Stale
snapshots must be explicitly omitted from the input list with their source still
listed as expected to obtain a partial result. Consumers must opt in again to
read partial snapshots. Core alone does not read the sidecar: automation must
validate/merge immediately before invoking core and stop on failure.
