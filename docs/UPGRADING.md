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
stay in their original table and remain searchable through literal LIKE. Thus
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
