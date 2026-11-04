# Watch mode

Watch mode keeps a separate local history of recently changed CVEs. It is
independent of the inventory database: `cvebeacon watch` never reads the
inventory file, and enabling watch mode does not change `scan`, `query`, or any
other command. Watch mode can select matching CVEs with rules and stores the
resulting alert events. It does not deliver them yet.

```console
cvebeacon --config cvebeacon.toml watch sync
cvebeacon --config cvebeacon.toml watch run
cvebeacon --config cvebeacon.toml watch status
cvebeacon --config cvebeacon.toml watch events
cvebeacon --config cvebeacon.toml watch rules check
cvebeacon --config cvebeacon.toml watch evaluate --all
```

`watch run` syncs the sources and then evaluates the CVEs touched by that sync.
`watch sync` only syncs; the durable touch queue keeps the evaluation for the
next `watch run`.

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

When `[watch].enabled = true`, `[inventory]` is optional. Commands that need an
inventory (`scan`, `export`, `asset`, `inventory ...`, `doctor`, and the
inventory dashboard pages) fail with a clear message until
`[inventory] path` is added. A configuration with neither watch mode nor an
inventory is rejected, so existing configurations keep their behavior.
`schedule install`, `doctor`, and `serve` refuse in a watch-only configuration;
run `cvebeacon --config <file> watch run` from cron or Task Scheduler instead.

The NVD API key is read from the existing `sources.nvd_api_key_env` variable.
It is optional; pacing follows `sources.minimum_request_interval`.

## Rules

Rules select CVEs from the watch database. Each rule has a name, a condition,
and one or more channel names. Channel names are validated when delivery is
added; this phase stores pending deliveries for them.

```toml
[[watch.rules]]
name = "critical-or-likely"
enabled = true
condition = { any = [ { cvss_min = 9.0 }, { epss_min = 0.5 } ] }
channels = ["soc-email"]
events = ["match", "kev_added", "exploitation_active", "severity_increase", "epss_increase", "nvd_score_added", "rejected"]
cvss_providers = ["cna", "nvd", "cisa-adp", "euvd", "other"]
```

- `name`: required and unique, case-insensitively. It starts with a letter or
  digit and contains at most 64 letters, digits, spaces, underscores, dots, or
  hyphens.
- `enabled`: defaults to `true`.
- `condition`: required. See the syntax below.
- `channels`: required, at least one name.
- `events`: defaults to every event kind above. An empty list is rejected.
- `cvss_providers`: defaults to every provider. Only these scores count as "the
  CVSS" for `cvss_min` and `cvss_max`.
- `old_cves`: `"digest"` (default), `"alert"`, or `"ignore"`; see
  [old CVEs](#old-cves).

A condition is a small boolean tree. A node is a table holding exactly one of
`all`, `any`, or `not`, or one or more leaf keys. Several leaf keys in one table
are ANDed:

```toml
condition = { all = [ { cvss_min = 9.0 }, { epss_min = 0.5 } ] }
condition = { any = [ { cvss_min = 9.0 }, { epss_min = 0.5 } ] }
condition = { cvss_min = 9.0 }
condition = { epss_min = 0.5 }
condition = { kev = "any" }
condition = { all = [ { kev = "any" }, { any = [ { cvss_min = 8 }, { epss_min = 0.5 } ] } ] }
condition = { all = [ { vendor = ["microsoft"] }, { cvss_min = 8 } ] }
condition = { all = [ { cvss_min = 9 }, { not = { vendor = ["examplecorp"] } } ] }
```

Limits: nesting depth at most 4, at most 32 leaves per rule, list values at
most 100 items, and strings at most 200 characters. Unknown keys are rejected,
empty `all`/`any` lists are rejected, and a boolean key cannot be mixed with
leaf keys in the same table.

Leaf keys:

- `cvss_min` (0 to 10): the highest score among `cvss_providers` is at least
  this value. A missing score is false.
- `cvss_max` (0 to 10): that highest score is at most this value. A missing
  score is false, so it never selects an unscored CVE.
- `epss_min` (0 to 1): EPSS is at least this value. A missing EPSS is false. A
  rule that uses `epss_min` requires `epss` in `watch.sources`.
- `kev = "cisa" | "eu" | "any"`: the CVE is in that KEV catalog. A rule that
  uses `kev = "eu"` requires `eu_kev` in `watch.sources`.
- `exploitation = "poc" | "active"`: `active` is true when SSVC reports
  active exploitation or, with `euvd` configured, EUVD has an exploitation
  date. `poc` is true for poc or active evidence from either source.
- `vendor`, `product`: case-insensitive exact names. They match against NVD CPE
  tokens (`palo_alto_networks`) and the selected EUVD item's display names
  (`Apache Software Foundation`). A rule must list both forms when the sources
  spell a name differently, or use a `keyword`.
- `keyword`: case-insensitive substring match in the description.
- `cwe`: CWE identifiers. `79`, `cwe-79`, and `CWE-79` are accepted and stored
  as `CWE-79`; anything else is rejected.
- `cna`: case-insensitive exact match against `source_identifier`.
- `status = "published" | "rejected"`.

Per provider, a CVSS 2.0 score is ignored when that provider also has a 3.x or
4.0 score. When one provider has both 3.x and 4.0 scores, the highest score is
used. Event reasons include the selected version, for example
`cvss 9.8 v3.1 (cna)`.

A rejected CVE never produces a `match` event unless `status = "rejected"` is
one of the true leaves of the evaluation. A negated status leaf does not count.

A rule that selects only the `euvd` CVSS provider requires `euvd` in
`watch.sources`. NVD is always available, so `kev = "cisa"` needs no catalog
setting.

The rule combinations above cover CVSS and EPSS together, either one alone, any
KEV addition, KEV gated by a score, vendor filters, and exclusions. `watch rules
check` prints each condition in readable form.

## Events

A rule produces a `match` event the first time its condition is true for a CVE.
The event records which leaves were true, for example `cvss 9.8 v3.1 (cna)`,
`epss 0.62`, and `kev cisa`. Later evaluations of that rule and CVE only produce
escalations, even when the condition is no longer true:

- `kev_added`: the CVE enters the CISA or EU KEV catalog.
- `exploitation_active`: SSVC or EUVD first reports active exploitation.
- `severity_increase`: the highest selected CVSS moves above its previous
  maximum band.
- `epss_increase`: EPSS moves above its previous maximum band. A first score
  below `0.1` does not escalate.
- `nvd_score_added`: an NVD score appears.
- `rejected`: the CVE changes from published to rejected.

Severity and EPSS keep high-water marks in the alert snapshot. A decrease
updates the current band silently, and reaching an earlier maximum again does
not alert again. A genuinely higher band alerts once, for example
`severity high -> critical`. `exploitation_active` names its evidence source,
for example `exploitation active (cisa-adp)` or
`exploitation active (euvd)`.

Reasons are stored separately from the event identity. Events are unique per
rule, CVE, kind, and occurrence:

- `match`: `match`
- `kev_added`: `<catalog>:<date_added>`
- `exploitation_active`: `active`
- `severity_increase` and `epss_increase`: the new band name
- `nvd_score_added`: `nvd`
- `rejected`: `rejected:<last_modified date>`

A KEV withdrawal and re-addition with a new date therefore alerts again, while
a failed download that restores the same entry does not. Repeating a run cannot
duplicate an event. Every event creates one pending delivery row per channel.

Rule state and event rule names are keyed by the casefolded rule name. A
case-only rename keeps the existing matches. A different rule name is a new
rule and starts with a new `match`. Renaming or removing a rule does not prune
its stored states; re-adding the same name keeps the old matches.
`watch evaluate --all` seeds a new rule against the full stored history; it
does not reset an existing rule's matches. A disabled rule's touches are
consumed; on re-enable, its escalations surface at the CVE's next touch.
After adding a rule, run `cvebeacon watch evaluate --all --yes` before the next
`watch run`. Otherwise old CVEs alert one by one when NVD next touches them.

Editing a rule's condition or `cvss_providers` keeps the existing matches. The
next evaluation compares against the stored state as usual, so an escalation
that arrives with the edit still alerts. A change to `cvss_providers` moves the
severity baseline to the new providers without an event, so the change alone
does not alert. Editing only channels or `events` does not reset state. A
disabled rule is not evaluated until it is
enabled again.

`cvebeacon watch events [--limit N] [--rule NAME] [--pending]` lists stored
events, newest first. `--rule` is case-insensitive. `--pending` keeps events
that still have a pending delivery.

### Old CVEs

The first `match` for a CVE is treated as backlog when all of these hold:

- the CVE's `published` date is before the database's `initial_window_start`
  date (`initialized_at` for baseline mode, or when the window start is not
  stored);
- no CISA or EU KEV `date_added` for that CVE is on or after that date;
- no EUVD exploitation date (`exploitedSince`, when `euvd` is configured) is on
  or after that date. An unparseable EUVD date does not exempt the CVE.

Backlog matches keep `initial = 1`, so the delivery phase can fold them into a
digest. Later escalations behave normally: a new KEV addition, active
exploitation, a higher score band, or rejection still alerts. A first match of
an old CVE that an EPSS or SSVC change triggered is digested too, unless the
rule sets `old_cves = "alert"`.

`old_cves` controls this per rule:

- `"digest"` (default): backlog matches are initial and go to the digest.
- `"alert"`: backlog matches are ordinary alerts.
- `"ignore"`: the match is stored silently with no event. Later escalations
  still alert normally.

### First-run and `initial`

An evaluation during the first sync of a database in `backfill` or `full` mode
marks its `match` events `initial = 1`. `cvebeacon watch evaluate --all` marks
only the `match` events it creates as initial; escalations keep `initial = 0`.
It requires `--yes` or a confirmation. `initial_evaluated_at` is set only after
an initial evaluation whose sync had no source failures, so a later clean sync
can finish an interrupted initial window. Initial events are intended for one
summary digest rather than individual alerts. A baseline first sync stores
no history, so it produces no events. Later syncs evaluate only the CVEs
touched by that sync.

## Vendor and product data

Vendor and product filters depend on source data being present. NVD supplies
CPE products after analysis, and EUVD supplies vendor and product names from
its `enisaIdVendor` and `enisaIdProduct` fields. NVD platform-only CPEs marked
`"vulnerable": false` are ignored. Up to 1,000 NVD vendor/product pairs are
stored, and the derived view keeps up to 500 vendor names and 500 product
names.

Names are matched exactly and case-insensitively. NVD uses CPE tokens such as
`palo_alto_networks`, while EUVD uses display names such as
`Apache Software Foundation`; list both forms, or add a `keyword`. Fresh CVEs
often have no CPE data yet. When a vendor filter matters, also add a `keyword`
alternative for important names.

EUVD data is used only when `"euvd"` is in `watch.sources`. Removing it from the
configuration removes EUVD scores, exploitation dates, and names from the
derived view, and queues every stored CVE for re-evaluation.

`not` over a missing vendor or product field is true, because a missing value
does not match the positive leaf. Prefer a positive filter for exclusions, or
pair the exclusion with another positive check. For example,
`{ all = [ { vendor = ["palo_alto_networks"] }, { not = { product = ["globalprotect"] } } ] }`
still matches a CVE whose product list is empty.

## Storage model

Each source keeps its own raw table; a CVE's combined view is derived when it
is needed. Watch databases created by earlier watch builds are migrated in
place from schema version 1 to version 2. An unknown version still fails
closed. The upgrade deletes the old `watch_touched` queue, because P1a had no
rules and therefore no evaluation obligation, and sets `initial_evaluated_at`
whenever `initial_mode` is already stored. It also rewinds `euvd_cursor` to
`initial_window_start`, but only when both values are stored, so the next sync
re-reads that window once. P1a stored EUVD items without vendor names, and that
re-read gives pre-upgrade items their names. In `full` mode
`initial_window_start` is 1999-01-01, so this re-reads the whole EUVD history
once. After the upgrade, run `cvebeacon watch evaluate --all --yes` BEFORE the
first `watch run`, as after adding a rule. Otherwise every CVE from the initial
window alerts one by one as NVD touches it. Schema 2 databases written by a
pre-release build of this branch are refused with a message to delete them and
run `watch sync` again. They are not migrated.

- `watch_cve` holds NVD-owned data only: status, description, CNA, CVSS from
  NVD, CNA, CISA ADP and other providers, SSVC, CPE products, references, and
  NVD's own CISA KEV fields.
- `watch_euvd_item` holds one row per EUVD item, keyed by `euvd_id`, whether or
  not its CVE is known. `watch_euvd_alias` maps each CVE alias to its items.
  When several items describe one CVE, the view uses the one with an
  exploitation date, then the latest `dateUpdated`, then the highest numeric
  EUVD id. Items are replaced in place when they change, and `seen_at` records
  the last observation, including identical re-reads.
- `watch_kev` holds CISA and EU catalog rows, keyed by catalog and CVE. Each
  successful catalog download replaces that catalog's rows in one transaction,
  including removals. When a catalog is configured it is the source for that
  part of the view; otherwise NVD's CISA KEV fields are used.
- `watch_epss` holds the current EPSS score, percentile, and score date for each
  CVE. It is replaced from FIRST's official dated file, at most once per file
  day.
- `watch_view` stores the alert-relevant fingerprint of each CVE's derived view.
  EPSS, identifiers, timestamps, and vendor/product names are excluded from
  that fingerprint.
- `watch_touched` is the durable evaluation queue. Every source transaction
  inserts the CVE ids it changed, so an interrupted or failed run cannot lose
  the obligation. Only ids with a `watch_cve` row are queued; an id first seen
  from EUVD or KEV is queued when NVD inserts its row. `pending_evaluations`
  reads the queue and `acknowledge` removes completed entries.
- `watch_alert_state` keeps the first match time, the alert snapshot, and the
  rule and CVSS-provider hashes for each casefolded rule name and CVE. A later
  evaluation compares against that snapshot.
- `watch_event` stores each event once. Its uniqueness key covers the rule,
  CVE, event kind, and occurrence; the reason text is stored separately.
- `watch_delivery` creates one pending row per event and channel. Delivery
  updates it in the next phase.
- `watch_meta.view_policy` records the configured sources that affect view
  derivation: `cisa_kev`, `eu_kev`, `euvd`, and `epss`. When it changes, every stored
  view is recomputed in batches of 5,000 and every stored CVE is queued,
  including CVEs whose fingerprint did not change, because vendor and product
  names are not part of the fingerprint.

`watch_touched` is the evaluation set; the view fingerprint only detects
escalations. NVD-only content changes such as products, CWEs, or description
still enqueue the CVE even when the fingerprint does not change.

EUVD item pruning runs once per day. It deletes items that have no
exploitation date, have not been seen for 30 days, and whose aliased CVEs are
all absent from `watch_cve`.

## NVD sync

NVD is read through the change feed in windows of at most 120 days. A window
whose first page reports more than one page of results (2,000) is split in
half by time until a window is one hour or shorter. Only such a window still
above 2,000 results is read page by page; its total is pinned and the window
restarts up to three times if the total or a CVE identifier repeats. Most
windows therefore need one request, which avoids churn between pages.

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
A chunk whose first page reports more than 10,000 items is split in half by
days, down to a one-day chunk, and every sub-chunk commits on its own. The
cursor only moves forward, so a device without a real-time clock cannot
rewind it. The request end is always widened by one day while the cursor stays
at the chunk end: same-day EUVD queries otherwise report a total below the
number of items they return. Requests are paced at least one second apart. A
page that repeats an EUVD id restarts the chunk through the same bounded
retry path, and the distinct item count must equal the pinned total before the
chunk commits. A failed chunk leaves the cursor at the previous chunk.

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

While `epss_file_day` is earlier than today, the sync downloads
`https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` directly,
without following redirects. It tries today and then yesterday; HTTP 403 and
404 both mean the dated file is not published yet. `epss_file_day` records the
day of the file that was loaded, so a later run asks again until today's file
appears. When yesterday's file is already loaded, only a small request for
today is made until it is published. A clock that moves backwards never
reloads an older file.

The file is decompressed and parsed as a stream, never held whole in memory,
and written in batches of 5,000 rows in one transaction. The compressed file
is capped at 20 MB and the decompressed stream at 64 MB. Comment and header
lines are read with a 4,096-character bound and data lines with a 256-character
bound; a longer line is rejected, as is an unterminated line except a complete
final one. Fields are split directly on commas, and every score and CVE
identifier is validated. A file with fewer than 100,000 rows is rejected, as is
one with fewer than half of the current table's rows when the table is not
empty. The header's `score_date` may be a date or a UTC timestamp with `Z` or
`+00:00`; its UTC date must be the requested day or the day before. A
validation error fails the EPSS step (exit 4) and keeps the previous table,
including corrupt gzip data.

The view reads EPSS directly. The daily load queues a watched CVE when its
score appears or disappears, or when the old-to-new move crosses any threshold
in the set passed to the store. The sync always includes the band edges `0.1`,
`0.5`, and `0.9`, plus every `epss_min` used by an enabled rule, so a rule sees
threshold crossings even when the score stays inside the same band.

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
confirmation again. `initial_evaluated_at` is set only after the initial
evaluation completes during a sync with no source failures; until then, later
runs keep `initial = 1` for matches and backlog matches. `initial_window_start`
is the boundary used by the `old_cves` policy in baseline, backfill, and full
mode.

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
- Committed source changes also remain in `watch_touched`, so a later failure or
  interruption does not lose an evaluation obligation. The initial window stays
  open until an evaluation completes after a sync with no failures.
- A successful sync exits 0. A refused or cancelled sync does not contact the
  sources.

`watch status` prints the database path, schema version, cursors, EPSS score
date, row counts, EUVD items, KEV catalog entries, watched CVEs in KEV, active
SSVC exploitation, EPSS rows, and pending/backing-off lookups. It creates an
empty database if none exists.

## Summary lines

Each source prints `request(s)`, `record(s)`, `new`, and `changed`.
`request(s)` counts every HTTP attempt, including retries.

- `nvd`: `record(s)` counts CVE rows read, `new` counts inserted rows, and
  `changed` counts derived-view fingerprint changes.
- `euvd`: `record(s)` counts EUVD items read, `new` counts new items, and
  `changed` counts derived-view fingerprint changes.
- `cisa_kev` and `eu_kev`: `record(s)` counts catalog entries, `new` counts
  entries absent from the previous catalog, and `changed` counts derived-view
  fingerprint changes.
- `epss`: `record(s)` counts score rows loaded and `changed` counts watched
  CVEs queued by an appearance, disappearance, or configured threshold
  crossing.

## Cost

A normal sync is small: one or more NVD pages for the cursor window, one EUVD
page or a few, the KEV catalogs, and at most one EPSS file plus a probe when
today's file is not published yet. NVD is paced at the configured interval;
EUVD is paced at one second. Without an NVD API key, NVD allows five requests
per 30 seconds; with a key, fifty.

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
