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
epss_floor = 0.1
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
- `epss_floor`: 0 to 1. Every CVE above the floor is refreshed once per UTC
  day, in addition to newly changed CVEs. The public API's `epss-gt` filter is
  strictly greater than, so a stored score equal to the floor is not returned
  by that query; the daily reconciliation described below re-queries it.

The NVD API key is read from the existing `sources.nvd_api_key_env` variable.
It is optional; pacing follows `sources.minimum_request_interval`.

## What sync stores

Each sync reads the NVD change feed (`lastModStartDate` to `lastModEndDate`,
2000 results per page, in windows of at most 120 days) and writes one row per
CVE to `watch_cve`. A row contains:

- CVE identifiers, publication and modification dates, and `published` or
  `rejected` status.
- The first English description, truncated to 1000 characters, and the CNA.
- Attributed CVSS metrics from NVD, CNA, CISA ADP, and EUVD, with version,
  vector, score, and severity. Scores outside 0 to 10 are ignored.
- CISA SSVC exploitation (`none`, `poc`, or `active`), CWE identifiers, CPE
  vendor/product pairs, and references.
- CISA KEV dates, required action, and ransomware indicator; the EU KEV date.
- EUVD identifiers, exploitation date, and the EUVD-reported CVSS score.
- EPSS score, percentile, and score date.

EUVD only enriches CVEs that already exist. KEV only updates existing rows.
Neither source creates a row on its own. NVD is authoritative for CVE creation.
The EUVD `epss` field is ignored because it uses a 0 to 100 scale; EPSS comes
from FIRST on a 0 to 1 scale.

Each EUVD fetch is collapsed to one item per CVE before writing, preferring an
item with an exploitation date, then the newest `dateUpdated`, then the highest
EUVD identifier. An EUVD update always replaces the previous EUVD CVSS entry,
including removing it when EUVD no longer reports a score. An invalid supplied
score fails that EUVD step without committing it.

When an EUVD update, CISA KEV entry, or EU KEV entry names a CVE that NVD has
not created yet, it is kept in `watch_pending`. At the end of a run, up to 25
alert-relevant pending CVEs (KEV entries, or EUVD entries with an exploitation
date) are fetched from NVD by identifier, oldest first, and their pending data
is applied. Other pending EUVD data is applied automatically when NVD first
inserts the CVE. A pending entry is dropped after ten failed attempts, or after
30 days if it is a non-exploited EUVD update. On a baseline first run, only KEV
entries added on or after the baseline date become pending; earlier catalog
entries are ignored.

After a successful KEV catalog download, rows no longer present in that catalog
have the catalog's columns cleared. CISA columns are cleared only when
`cisa_kev` is configured, and `eu_kev_added` only when `eu_kev` is configured.
The same rule decides who owns the CISA columns: when `cisa_kev` is configured
the catalog owns them and NVD only fills empty values; otherwise NVD owns them,
including clearing values that disappear from an NVD record.

The daily EPSS floor query reads scores above `epss_floor` in pages. After a
complete download, stored rows at or above the floor that the response did not
include are re-queried through the normal batch endpoint, which catches scores
that fell below the floor. Rows that still have no EPSS date, for example after
an earlier EPSS failure, are also retried in batches, at most 1,000 per run and
oldest `first_seen` first.

The alert-relevant fingerprint covers status, CVSS, SSVC, the CISA KEV fields,
the EU KEV date, and the EUVD exploitation date. EPSS and timestamps are
excluded, so score churn does not change the fingerprint. Upserts are
idempotent: unchanged data is not rewritten, and `updated_at` changes only when
a field changes.

## Initial modes

The first sync chooses what history to build:

- `baseline` (default): reads nothing, stores no CVE history, and sets the NVD
  cursor to the current time. Later syncs start from there. This is the
  cheapest and safest choice for a new deployment.
- `backfill`: reads NVD changes from the last `backfill_days` days and EUVD
  changes from the same date range.
- `full`: reads NVD history from 1999-01-01 and EUVD history from 1999-01-01.
  Before starting it prints an estimate of the NVD windows and request counts
  plus a bandwidth warning, then requires `--yes` or an interactive
  confirmation. When stdin is closed, the prompt counts as "no".

NVD is read one bounded window at a time, at most 120 days per window. A window
whose first page reports more than 20,000 results is split in half and retried,
down to a one-day minimum. Each finished window is written in its own
transaction together with `nvd_cursor` set to that window's end, so the cursor
never passes unread data and memory is limited to one window. A large backfill
or full run therefore resumes from the last committed window after an
interruption instead of starting over, and the full-history confirmation is not
asked again once work has started. `initialized_at` and `initial_complete` are
set only when the initial run reaches its last window.

The stored NVD cursor is `min(local time, NVD response timestamp)`; NVD's
`timestamp` field is UTC without an offset and is parsed strictly. This keeps a
Raspberry Pi without a real-time clock from moving the cursor past NVD's own
time. A cursor more than 120 days old prints a one-line warning and the sync
continues in bounded windows.

EUVD ranges longer than 30 days are read in 30-day chunks, and `euvd_cursor` is
committed after each chunk. A failed chunk leaves the cursor at the previous
chunk so the next run retries it.

After the first sync, `nvd_cursor` advances to the end of the window that was
read. Later runs start `overlap_minutes` before that cursor and end at the
current time. `euvd_cursor` is a date and is re-read inclusively, so a second
sync on the same day reads the same EUVD day again.

## Failure behavior

- An NVD failure aborts the sync with exit code 2. Windows already committed
  keep their records and cursor; nothing past the cursor is committed and the
  next run resumes there.
- Pagination that changes totals, or repeats a CVE identifier inside one NVD
  window, restarts that window up to three times and then fails the source. The
  same total-pinning rule applies to each EUVD chunk and to the EPSS floor
  pager.
- If an optional source fails, the NVD data is committed, the failing source is
  named, and the command exits 4. Its cursor does not advance past the last
  successful chunk.
- A successful sync exits 0. A refused or cancelled sync does not contact the
  sources.

`watch status` prints the database path, schema version, cursors, row count, and
counts of rows with KEV data, active SSVC exploitation, and EPSS above the
configured floor. It creates an empty database if none exists.

## Cost

A normal sync is small: one or more NVD pages for the cursor window, one EUVD
page or a few, one KEV download, and EPSS batches for the CVEs that changed.
NVD is paced at the configured interval. Without an API key NVD allows five
requests per 30 seconds; with a key, fifty.

`initial = "full"` is the expensive path. From 1999 to the present there are
about 85 NVD windows. A busy window can need many 2000-result pages, so expect
roughly 400 or more NVD requests and roughly 4,200 EUVD requests. At the
default pacing that is several hours of continuous work, a large download, and
many small database commits. The once-daily EPSS floor query can also page
through tens of thousands of scores. Run full history deliberately, preferably
with an NVD API key.

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
