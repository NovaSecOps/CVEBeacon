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

## Optional Teams bot channel

Back up the watch database before upgrading. The first write-capable watch
operation migrates schema 8 to 9 in a transaction, preserving existing event,
delivery and reporting history. The new tables store Teams bot conversation
references, frozen message batches and per-recipient results. Bot migration
checks actual tables and columns even if an earlier build already wrote the
version number. Main's schema 7 upgrades directly to 9 in the same transaction,
including provider/search storage before bot storage. CVE-1's schema 8 to 9
upgrade preserves its existing provider and search data. Both fresh-install and
upgraded schema-8 layouts are supported; the legacy CVE status constraint stays
unchanged. Read-only views do not migrate an existing database.

The unreleased Teams schema 8 was never shipped and is not a supported upgrade
input. There is no migration for its initial-digest batches or missing columns.
Schema 8 here means CVE-1's provider schema; CVE-1 is incorporated first.

Existing Teams Workflow webhook configuration remains unchanged. A pre-release
`teams_bot` configuration with a custom HTTPS `service_url` outside the allowed
Microsoft origin now fails validation. Replace the channel and conversation
reference URLs with documented public-cloud service URLs, or remove the channel
before upgrading. The allowlist checks the HTTPS origin and port; approved
regional paths remain intact, rather than being limited to `/teams/`.

The new `teams_bot` channel is opt-in and requires the Azure registration
and Teams app installation described in [Teams bot setup](TEAMS.md). No schedules
or notifications are created by the upgrade itself.

After schema migration, older binaries will reject the newer schema. To roll
back, stop all processes using the watch database and restore its pre-upgrade
backup together with the previous configuration and application version. A
restore also restores the delivery ledger, so review notifications sent since
the backup before resuming delivery.
