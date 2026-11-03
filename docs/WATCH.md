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
- `epss_floor`: 0 to 1. Every CVE at or above the floor is refreshed once per
  UTC day, in addition to newly changed CVEs.

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
- `full`: reads NVD history from 1999-01-01 in 120-day windows and EUVD history
  from 1999-01-01. Before starting it prints an estimate of the NVD request
  count and a bandwidth warning, then requires `--yes` or an interactive
  confirmation.

After the first sync, `nvd_cursor` advances to the end of the window that was
read. Later runs start `overlap_minutes` before that cursor and end at the
current time. `euvd_cursor` is a date and is re-read inclusively, so a second
sync on the same day reads the same EUVD day again.

## Failure behavior

- An NVD failure aborts the sync with exit code 2. No records or cursors are
  committed.
- If an optional source fails, the NVD data is committed, the failing source is
  named, and the command exits 4. Its cursor does not advance.
- A successful sync exits 0. A refused or cancelled sync does not contact the
  sources.

`watch status` prints the database path, schema version, cursors, row count, and
counts of rows with KEV data, active SSVC exploitation, and EPSS at or above the
configured floor. It creates an empty database if none exists.

## Cost

A normal sync is small: one or more NVD pages for the cursor window, one EUVD
page or a few, one KEV download, and EPSS batches for the CVEs that changed.
NVD is paced at the configured interval. Without an API key NVD allows five
requests per 30 seconds; with a key, fifty.

`initial = "full"` is the expensive path. From 1999 to the present there are
about 85 NVD windows, and a busy window can need many 2000-result pages. It can
take hours and download a large amount of data. The once-daily EPSS floor query
can also page through tens of thousands of scores. Run full history
deliberately, preferably with an NVD API key.

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
