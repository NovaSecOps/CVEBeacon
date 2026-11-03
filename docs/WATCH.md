# Watch mode

Watch mode keeps a separate local history of recently changed CVEs. It is
independent of the inventory database: `cvebeacon watch` never reads the
inventory file, and enabling watch mode does not change `scan`, `query`, or any
other command. This phase stores changes only; it does not send alerts or
notifications.

```console
cvebeacon --config cvebeacon.toml watch sync
cvebeacon --config cvebeacon.toml watch status
```

## Configuration

Watch mode is disabled by default. Add a `[watch]` table to the existing
configuration:

```toml
[watch]
enabled = false
database = "cvebeacon-watch.db"
sources = ["nvd", "euvd", "cisa_kev", "eu_kev", "epss"]
initial = "baseline"
backfill_days = 7
overlap_minutes = 15
```

- `enabled`: watch commands refuse to run until this is `true`.
- `database`: a separate SQLite file. Relative paths resolve from the
  configuration file directory, like other paths.
- `sources`: any subset of `nvd`, `euvd`, `cisa_kev`, `eu_kev`, and `epss`.
  `nvd` is required. Unknown names are rejected.
- `initial`: what the first sync does; see [initial modes](#initial-modes).
- `backfill_days`: 1 to 120, used only when `initial = "backfill"`.
- `overlap_minutes`: 0 to 1440. Later runs re-read this much before the stored
  NVD cursor so that late-published changes are not missed.

The NVD API key is read from the existing `sources.nvd_api_key_env` variable.
It is optional; pacing follows `sources.minimum_request_interval`.

## Storage model

Each source keeps its own raw table; a CVE's combined view is derived when it
is needed. The schema is not migrated from earlier watch builds.

- `watch_cve` holds NVD-owned data only: status, description, CNA, CVSS from
  NVD, CNA, CISA ADP and other providers, SSVC, CPE products, references, and
  NVD's own CISA KEV fields. `nvd_fingerprint` covers the NVD alert fields.
- `watch_euvd_item` holds one row per EUVD item, keyed by `euvd_id`, whether or
  not its CVE is known. `watch_euvd_alias` maps each CVE alias to its items.
  When several items describe one CVE, the view uses the one with an
  exploitation date, then the latest `dateUpdated`, then the highest numeric
  EUVD id. Items are replaced in place when they change.
- `watch_kev` holds CISA and EU catalog rows, keyed by catalog and CVE. Each
  successful catalog download replaces that catalog's rows in one transaction,
  including removals. When a catalog is configured it is the source for that
  part of the view; otherwise NVD's CISA KEV fields are used.
- `watch_epss` holds the current EPSS score, percentile, and score date for each
  CVE. It is replaced once per UTC day from FIRST's official dated file.
- `watch_view` stores the alert-relevant fingerprint of each CVE's derived view.
  EPSS, identifiers, and timestamps are excluded from that fingerprint.

EUVD item pruning runs once per day. It deletes items that have no
exploitation date, have not been seen for 30 days, and whose aliased CVEs are
all absent from `watch_cve`.

## NVD sync

NVD is read through the change feed in windows of at most 120 days. A window
whose first page reports more than one page of results (2,000) is split in
half by time, down to a minimum window of one hour. Only a one-hour window
still above 2,000 results is read page by page; its total is pinned and the
window restarts up to three times if the total or a CVE identifier repeats.
Most windows therefore need one request, which avoids churn between pages.

Each finished window is written with its `nvd_cursor` in the same transaction,
so a backfill or full run resumes from the last committed window. NVD rows are
created only by the change feed or by a lookup for a KEV/EUVD CVE described
below.

The stored cursor is `min(local time, NVD response timestamp)`. NVD timestamps
are accepted without a suffix, with `Z`, or with `+00:00`; anything else is
invalid. This keeps a device without a real-time clock from moving the cursor
past NVD's own time. A cursor more than 120 days old prints a warning and the
sync continues in bounded windows.

## EUVD sync

EUVD is read in 30-day chunks and `euvd_cursor` is committed after each chunk.
The request end is always widened by one day while the cursor stays at the
chunk end: same-day EUVD queries otherwise report a total below the number of
items they return. Requests are paced at least one second apart. A failed
chunk leaves the cursor at the previous chunk.

## KEV and early lookups

The CISA and EU KEV catalogs are downloaded once per run and replace their
previous rows. For a CVE that NVD has not created yet, the sync tracks a
bounded lookup in `watch_lookup`:

- KEV entries in a configured catalog whose `dateAdded` is on or after the
  start of the database's initial window (never for full mode);
- EUVD items with an exploitation date whose CVE is not in `watch_cve`.

Up to 25 lookups run per sync, oldest due first. A failed lookup keeps its row
and backs off for 1 hour, doubling to a maximum of 7 days; attempts never reset
because a catalog is downloaded again. The row is removed when the CVE appears
in `watch_cve` or its trigger disappears.

Failed lookups are reported on the NVD summary line as
`, N lookup(s) failed`. They do not change the exit code. `watch status` shows
`lookups pending/backing off: N`.

## EPSS

Once per UTC day, the sync downloads
`https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` directly,
without following redirects. It tries today and then yesterday; a 404 means the
file is not published yet. The file is decompressed and parsed as a stream with
`gzip` and `csv`, never held whole in memory, and written in batches of 5,000
rows in one transaction. The compressed file is capped at 20 MB and 1,000,000
rows. The leading `#model_version:...,score_date:...` line, the
`cve,epss,percentile` header, every score, and every CVE identifier are
validated. A validation error fails the EPSS step (exit 4) and keeps the
previous table. When the day's file is already loaded, no EPSS request is made.

The view reads EPSS directly, so no score refresh is needed for changed CVEs.
The daily load also computes the CVEs whose EPSS band (`<0.1`, `<0.5`, `<0.9`,
or higher) changed and exposes them with the run's touched CVEs.

## Initial modes

The first sync chooses what history to build:

- `baseline` (default): reads nothing, stores no CVE history, and sets the NVD
  cursor to the current time. Later syncs start from there. This is the
  cheapest and safest choice for a new deployment.
- `backfill`: reads NVD changes from the last `backfill_days` days and EUVD
  changes from the same date range.
- `full`: reads NVD history from 1999-01-01 and EUVD history from 1999-01-01.
  Before starting it prints an estimate of the NVD windows, request counts, and
  the one EPSS file per day, then requires `--yes` or an interactive
  confirmation. When stdin is closed, the prompt counts as "no".

`initialized_at` is set only when an initial run reaches its last window. A
resumed initial run continues from the stored cursor and does not ask for
confirmation again.

After the first sync, `nvd_cursor` advances to the end of the window that was
read. Later runs start `overlap_minutes` before that cursor and end at the
current time. `euvd_cursor` is a date and is re-read inclusively, so a second
sync on the same day reads the same EUVD day again.

## Failure behavior

- An NVD failure aborts the sync with exit code 2. Windows already committed
  keep their records and cursor; nothing past the cursor is committed and the
  next run resumes there.
- If an optional source fails, the NVD data is committed, the failing source is
  named, and the command exits 4. Its cursor does not advance past the last
  successful chunk. A failed EPSS download keeps the previous table.
- A successful sync exits 0. A refused or cancelled sync does not contact the
  sources.

`watch status` prints the database path, schema version, cursors, EPSS score
date, row counts, EUVD items, KEV counts, active SSVC exploitation, EPSS rows,
and pending/backing-off lookups. It creates an empty database if none exists.

## Cost

A normal sync is small: one or more NVD pages for the cursor window, one EUVD
page or a few, the KEV catalogs, and at most one EPSS file. NVD is paced at the
configured interval; EUVD is paced at one second. Without an NVD API key, NVD
allows five requests per 30 seconds; with a key, fifty.

`initial = "full"` is the expensive path. From 1999 to the present there are
about 85 NVD windows. A busy window can need many pages, so expect roughly 400
or more NVD requests and roughly 4,200 EUVD requests. At the default pacing
that is several hours of continuous work, a large download, and many small
database commits. EPSS is one current file per sync, not one per historical
day. Run full history deliberately, preferably with an NVD API key.

## Source attribution

Watch mode uses the same public sources as the rest of CVEBeacon:

- [NIST National Vulnerability Database](https://nvd.nist.gov/developers/vulnerabilities)
  for CVE records, CVSS, SSVC, and KEV metadata. This product uses data from
  the NVD API but is not endorsed or certified by the NVD.
- [ENISA EUVD](https://euvd.enisa.europa.eu/) for European enrichment and
  exploitation information.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
  the ENISA consolidated EU KEV dump.
- [FIRST EPSS](https://www.first.org/epss/) for exploitation probability.

See [sources](SOURCES.md) for the full source roles and limitations.
