# Upgrading

Stop active mutating jobs and keep a backup of the configuration and SQLite
state before replacing an installation. A normal mutating command, such as
`cvebeacon watch sync`, applies the watch schema upgrade transactionally under
the existing run lock. Dashboard reads do not migrate state or acquire writer
locks. Schema-7 watch observations can be browsed before the first write.

## Watch schema 7 to 8

Existing NVD rows and EUVD items remain in place, including extra legacy
columns. The migration adds empty provider, origin, source-check, scoped EUVD,
initial-evaluation and delta-progress tables. It does not copy or parse existing
NVD/EUVD records, backfill descriptions, rebuild `watch_cve`, or index the full
historical database. Reserved CVE List state lives in its provider record;
legacy identity placeholders do not require replacing the old status constraint.

The FTS index contains only new provider descriptions. Existing NVD descriptions
stay in their original table and retain the original FTS5 keyword semantics
through an in-memory candidate matcher (literal LIKE when FTS5 is unavailable). Thus
initial migration work is independent of the number of CVEs. A small amount of
space for new table/index pages and the SQLite journal is still required; disk
or injected failures roll back the schema and added tables together. The
synthetic acceptance measurement is reproducible with:

```console
python tools/cve_migration_benchmark.py --rows 430000
```

A malformed historical record does not block this migration. Reading that CVE
fails closed with its identifier in the error. Restore a known-good backup or
use `cvebeacon watch refresh CVE-2026-12345` to replace the malformed source row
from a valid targeted response; failed source lookups leave the old evidence
untouched. No row is silently skipped or described as unaffected.

Adding `cve_list` to an existing installation starts its independent no-history
baseline, even if `watch.initial` still says `full` or `backfill`. Importing
source history requires an explicit confirmed command; see [watch](WATCH.md).
Its pending or failed initialization is degraded source coverage and does not
hold the existing NVD/EUVD initial window open.

## Pre-release schema 8 and older provenance

The unreleased provider-copy layout has a separate transactional recovery path,
gated by its missing sparse-storage marker. It restores original NVD fields,
removes redundant NVD copies, and rebuilds only new-provider search rows. Unlike
the released schema-7 upgrade, this path scans and parses provider copies and may
need additional time/journal space. Stop writers and keep a backup first. Invalid
provider JSON rolls back the recovery and names the CVE; repair that provider
copy or restore the backup before retrying. It is not silently quarantined.

The oldest schema-1 rows may contain deprecated EUVD/EPSS columns without source
provenance. Those columns remain intact. They cannot establish whether NVD also
supplied the row, so rows lacking explicit provenance retain the legacy NVD/base
classification; it must not be interpreted as verified NVD origin. A normal
source sync or targeted refresh supplies current attributed evidence. No origin
is guessed from a missing description or score.

Fix 2 adds an expected-revision queue column and an empty per-CVE observation-order
table under schema 8. Existing sparse tables and their populated FTS index are not reprocessed
through the pre-release recovery. Old delta tokens that could have been accepted
from log-only evidence are invalidated; the previous cursor is retained as an
explicit unproven interval until a confirmed snapshot repair. Old pending rows lacking a verifiable expected revision
remain pending rather than being silently acknowledged; an explicit confirmed
history repair can replace that old obligation. Read-only pages still do not
migrate or take write locks.
