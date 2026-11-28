# CVEBeacon user guide

## 1. Purpose and operating model

CVEBeacon reads a supplied component inventory, asks primary vulnerability sources about each distinct product or explicit package identity, preserves the returned evidence, and records material finding changes. The inventory remains the source of truth; the SQLite database is monitoring history, not an asset database.

The tool is deliberately conservative. A missing CPE, empty search result, unsupported version scheme, disagreement, or source outage never becomes an automatic clean result.

## 2. Requirements and installation

A source installation requires Python 3.11 or newer, DNS, and outbound HTTPS access described in [network requirements](NETWORK_REQUIREMENTS.md).

Windows PowerShell:

```console
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade "pip>=26.2"
.venv\Scripts\python.exe -m pip install .
.venv\Scripts\cvebeacon.exe --help
```

Linux:

```console
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade 'pip>=26.2'
.venv/bin/python -m pip install .
.venv/bin/cvebeacon --help
```

A platform-specific standalone executable needs no separate Python installation. Keep the executable, configuration, and inventory in operator-controlled locations. Windows and Linux executables must be built on their respective operating systems; see [packaging](PACKAGING.md).

## 3. Initial configuration

### Set up from the dashboard

If you use the dashboard, start on **Home** and follow its **Getting started**
checklist. It guides you through turning on watch data and completing the first
sync, setting up and testing an alert channel, choosing a rule, adding a client
software list, installing a schedule, and making a backup. The list reflects
recorded settings and activity; it is not a coverage guarantee. **Done** means
only that the condition for that step is recorded. A successful channel test
means the destination service accepted the message, so check the destination
yourself. The dashboard keeps the last 200 finished jobs in history; older
channel tests eventually leave that history. See the [dashboard guide](DASHBOARD.md)
for details.

To add an alert destination, open **Configuration → Alert channels → Guided
setup**. Choose the channel type, enter its details, review and save the
change, then send a test. Use the full channel form for options not shown in
the guided setup.

Copy `cvebeacon.example.toml` to `cvebeacon.toml`. Relative inventory, database, and output paths resolve from the configuration file’s directory. The minimum configuration is:

```toml
[inventory]
path = "inventory.csv"

[inventory.columns]
asset_id = "asset_id"
vendor = "vendor"
product = "product"
version = "version"
```

The legacy product path requires `asset_id`, `vendor`, and `product` as nonblank text; `version` is optional on every path. Explicit package/PURL/CPE/commit identities may omit generic fields; see [identity rules and optional mappings](IDENTITY.md). Asset IDs must be unique without regard to case. CVEBeacon normalizes surrounding whitespace but does not rewrite the source inventory. Store versions as text, including `7.0`, `7.0.0`, and leading zeros; numeric, date, boolean, and compound values are rejected because their original spelling cannot be recovered reliably. Quote versions in JSON and YAML and format Excel cells as text before entering them.

A product or package row without a version is accepted, whether it uses vendor/product, ecosystem/package, a PURL without a version, or a CPE whose version is `*`. Such a row is scanned against every version of the product. Its findings are `needs_review` with the reason "version unknown: may be affected depending on the version". This is deliberately overzealous: CVEBeacon would rather warn about a possible exposure than omit a product whose version is unknown. Confirm the version when you can. The dashboard marks these rows **No version**. An exact repository and commit identity is assessed at the commit itself: matching GIT ranges and membership evidence can establish applicability without a release version, so these rows are not marked **No version**.

An inventory is optional in watch-only mode. Set `[watch] enabled = true` and no `[inventory] path` to keep KEV, critical-severity and custom-rule alerting; those alerts work without an inventory. Upload a client inventory in the dashboard or add an `[inventory] path` later to enable asset applicability, findings and reports. See [watch mode](WATCH.md#configuration).

For products added from Web assets, `[web]` defines the inventory sync defaults.
Each client can override the mode and automatic removal on the Web assets page.

| Option | Default | Accepted values and effect |
| --- | --- | --- |
| `inventory_sync` | `"off"` | `"off"` flags missing products, `"review"` also proposes additions and version changes, and `"auto"` applies eligible additions and version changes. |
| `inventory_auto_remove` | `false` | `true` allows automatic removal only in `"auto"` mode. Otherwise missing products stay in the inventory until manually removed. |
| `removal_grace_days` | `30` | Integer from `0` to `365`. Days to wait after a product is flagged before automatic removal is allowed. |

See [Web assets inventory sync](DASHBOARD.md#inventory-sync).

An optional `client` column labels the client that owns an asset. The value under `[inventory.columns]` is the source column name, not a client name: use `client = "Account"` for a column named `Account`, or `client = "client"` for the default `client` header. A row can then contain `Acme` in that column. Client names are internal, limited to 120 characters, and cannot contain control or format characters. Assets without a client belong to no client. You can keep a shared file with a `client` column and also upload separate client inventories through the dashboard.

Source controls, retry/timeouts, output paths, optional exact CPE mappings, and notification settings are illustrated in the example configuration. A configured product CPE must be a complete CPE 2.3 name with a wildcard version; verify it against NVD before use.

Two optional sources extend exploitation and discovery evidence:

- **VulnCheck KEV** is enabled by default but stays off until a token is set. Get a free community token at [vulncheck.com](https://vulncheck.com/) and set `VULNCHECK_API_TOKEN`, another environment variable named by `vulncheck_api_key_env`, or an owner-only file named by `vulncheck_api_key_file`. Without a token, Settings and the Sources view report `off: no token`; scans record no VulnCheck row and continue normally. The token is never displayed, logged, exported, written to state or retained from a response. The token file follows the same backup rule as the NVD key file: excluded by default and copied only when secret inclusion is selected.
- **Shodan CVEDB** is free and needs no key, but is disabled by default. When explicitly enabled it sends product CPE identifiers and CVE IDs to `cvedb.shodan.io`; no client names, hostnames or IP addresses are sent. It adds corroborating evidence and, for a CVE only it reports, a `needs_review` finding with the reason `reported by Shodan CVEDB only; confirm applicability`. It never changes an NVD or OSV applicability decision and is capped at 500 CVE lookups and 500 discovery results per run.

Settings shows each source as `on`, `off: no token` or `off: disabled`. Check Shodan's and VulnCheck's terms of use for your use case. See [vulnerability data sources](SOURCES.md) for endpoints, fields and limits.

## 4. Inventory formats and mapping

The file extension selects XLSX, CSV, JSON, or YAML when `format = "auto"`. A different supported format can be named explicitly.

### XLSX

Set `worksheet`, `header_row`, and the source column names. Mapped inventory cells must contain literal text; formulas are rejected because their cached results may be stale. Inspect all worksheet names and headers first:

```console
cvebeacon inventory inspect inventory.xlsx
```

See `examples/xlsx.toml`. Generate the non-sensitive example workbook with `python tools/create_sample_xlsx.py`.

### CSV

Set the one-character `delimiter`, text `encoding`, and column mapping. The default encoding is `utf-8-sig`. See `cvebeacon.example.toml` and `examples/inventory.csv`.

### JSON and YAML

The configured record value must be a list of objects. A document-root list needs no `records_path`; a nested list can be selected with a simple dot path such as `assets` or `data.assets`. YAML uses safe loading. See `examples/json.toml` and `examples/yaml.toml`.

Inspect and validate before scanning:

```console
cvebeacon inventory inspect examples/inventory.json
cvebeacon inventory validate --identities
cvebeacon inventory validate path/to/alternate.csv
```

Validation reports source locations for malformed records, missing mapped columns, blank fields, duplicate IDs, invalid structure, and unreadable files. A product or package row without a version is accepted and scanned for every version of the product.

XLSX parts and total expanded data are limited to 32 MiB. A workbook can
contain up to 1,000,000 cells across all sheets. Configured workbooks also
have a 1,000,000-cell limit on the declared range of each sheet. Use a smaller
used range or split larger inventories. For YAML inventories, write each
value directly. Aliases and merge keys are refused.

### Clients and inventories

1. In the dashboard, open **Clients → Add client**. Enter the name and any
   notes or contact details you want to keep with it.
2. On the client page, choose **Upload inventory** and select a CSV, XLSX, JSON
   or YAML file up to 32 MiB, or paste text up to 100 KB and choose CSV, JSON
   or YAML in the format selector. **Download a CSV template** provides the
   field headings and an example row. For CSV, use UTF-8 and
   comma-separated columns. Excel uses the first sheet, with column names in
   the first row. For JSON and YAML, use a list of records or put one list
   under a top-level field such as `assets`. Use text for versions, including
   in Excel.
3. Check the first rows and choose the matching column for each field. For
   example, match **Product** to a column called **Application**. Select
   **Check column mapping** to see which rows are ready and which need a fix.
   Each asset needs a unique Asset ID across all inventories. The client you
   selected is assigned to every row.
4. **Add these assets to the current inventory** is selected by default and
   keeps the assets already saved. Choose **Replace this client's inventory**
   only when the file is the full inventory; assets missing from that file are
   removed. Then choose **Save inventory**. You can download the saved JSON,
   restore one of the five previous versions, or remove the current upload from
   the client page.
5. Choose **Run a scan now** if you have permission to start scans. Scheduled
   scans pick up saved changes automatically. If your schedule runs only
   watch jobs, use **Operations → Schedule** to select a schedule that includes
   scans. The watchlist and client findings use the latest successful scan.

Uploads live in the private `inventories` folder next to the state database.
CVEBeacon merges current uploads with the configured inventory and any enabled
web snapshots. With no configured inventory, the first upload enables scanning.
New configurations set `[inventory] managed = true`. Older configurations use
uploads automatically when the folder contains a current inventory. Set
`managed = false` under `[inventory]` to exclude dashboard uploads. Archived
versions are used only when restored. Back up the private inventory directory
with the matching database backups. The JSON download contains the canonical
records used for inventory input, while collector snapshots also carry a
separate exchange manifest. Run `cvebeacon inventory validate` or
`cvebeacon doctor` to check the merged inventory. A corrupt upload is skipped
with a warning and a duplicate asset ID across inventories prevents the scan.
Exports wait until unreadable client inventories are replaced or removed.

## 5. First scan

Run a complete monitoring scan and create an XLSX report:

```console
cvebeacon --config cvebeacon.toml scan --report xlsx
```

The run queries each identical component identity/version target once, then associates results with each asset ID. Completed findings, source health, events, and pending notification work are committed together. A run that fails before commit does not appear as successful state. Notification attempts occur after this commit so failures can retry safely.

The first scan may be slow without an NVD API key because the default respects NVD’s public-client pacing guidance. Set the configured API-key environment variable to use a key; never put the key in TOML.

Exit codes are `0` for a successful operation, `2` for validation/operational failure, `3` for notification failure, and `4` for a scan with uncertain coverage or degraded sources. A completed scan can contain useful findings and still exit `4`; review its report and `source-status`. Notification failure takes precedence if both occur. `cvebeacon run` uses the same codes across its parts: any part failing gives `2`, otherwise a notification or delivery failure gives `3`, otherwise coverage warnings or degraded sources give `4`.

Package/PURL identities, category and system grouping work in all four input formats; `examples/general.toml` demonstrates a mixed inventory. An optional `client` label assigns an asset to a client for alert and dashboard reporting; it never affects applicability or source queries. No accounts or credentials are needed for core scans.

## 6. Queries and assets

An arbitrary manual query uses the same matching engine:

```console
cvebeacon query --vendor "Example Vendor" --product "Example Product" --version "1.0.0"
```

Query a current inventory asset by ID:

```console
cvebeacon asset asset-001
```

These commands print JSON and do not mutate scheduled finding fingerprints or notification delivery state. Manual investigation therefore cannot suppress a later monitoring alert.

## 7. History and reports

Show material events, optionally filtered:

```console
cvebeacon history
cvebeacon history --asset-id asset-001
cvebeacon history --cve-id CVE-2024-0001 --limit 25
```

Run a fresh non-committing query and generate a report:

```console
cvebeacon export --format xlsx
cvebeacon export --format json --output report.json
```

XLSX reports contain Summary, Findings, Uncertainty, Evidence, Source Health, Identities, and Advisory Details sheets. They are generated on demand rather than maintained as a vulnerability mirror.

An optional STIX 2.1 export is also available for OpenCTI, a SIEM or a data lake. It reads findings without changing them; its created-timestamp ledger is the only state write:

```console
cvebeacon export stix --output findings.json
```

It exports only affected or needs-review findings from the latest successful inventory scan, keeps client labels out by default, and uses deterministic UUIDv5 identifiers. See the [STIX export guide](STIX.md) for the mapping, `--client`, `--include-clients`, `--since`, and the limits of the bundle.

## 8. Applicability and coverage states

- `affected`: affirmative exact-version evidence supports applicability.
- `not_affected`: affirmative authoritative evidence explicitly excludes the version.
- `needs_review`: relevant evidence exists but version semantics are unsupported, incomplete, rejected, or conflicting.
- `coverage_unknown`: exact product identity or authoritative coverage could not be established.

`not_affected` is never inferred from zero search results. Human-oriented or custom version ranges are preserved but not forced through a generic comparator. A known-exploitation catalog entry is prioritization evidence; it does not by itself prove product-version applicability. EPSS is predictive and remains distinct from known exploitation.

A product or package row without a version cannot produce `affected` or `not_affected`. Using the commit identity is different: when the advisory's GIT ranges and membership evidence match the exact repository and commit, CVEBeacon can record `affected` without a release version. For a version-less product or package, CVEBeacon scans for every known CVE of the product and each finding is `needs_review` with the reason "version unknown: may be affected depending on the version". The NVD lookup uses the product's CPE with `*` in the version field, OSV uses the package identity without a version, and other enabled sources search by product as usual. A product-wide NVD response is capped at 2,000 CVEs per asset; when the cap is reached, source health reports the limit and coverage stays unknown rather than appearing complete. These findings still count on Findings and Assets, and they follow the same event and notification path as other `needs_review` findings.

SemVer and Python version ranges use their respective ordering rules. Generic product schemes and partial-version wildcards without a supported comparator require review. Package-native ranges additionally support declared ecosystem ordering; see [supported semantics](IDENTITY.md). Product punctuation is significant; automatic CPE resolution allows CPE underscores to represent spaces, but does not guess vendor aliases. Configure a verified mapping when names differ. Configured edition, update, and platform fields are retained. NVD AND/negated/environment-dependent configurations and CVE platform-scoped claims require review when the inventory cannot establish those conditions. A CPE API search hit alone does not prove the full configuration applies.

## 9. Material changes

Notifications are created for a new finding or a meaningful change to applicability, affected evidence, rejection/withdrawal state, CVSS, CISA KEV membership, EU KEV membership, or a comparable remediation-relevant claim. VulnCheck KEV is evidence and a badge only; enabling it does not create a material change. Upstream modification timestamps and ordinary EPSS movement are stored when available but do not independently trigger alerts.

Any change in the selected CVSS score/vector/version is material. When sources provide different scores, the highest reported base score and its associated vector/version are displayed together; the conflict and original metrics remain in the evidence. Reordering equivalent evidence does not create an alert. Schema 3 preserves legacy fingerprints and alias-only changes do not produce an upgrade alert storm. Changed source claims still produce material events.

Watch alerts, initial digests, `watch events` output, webhook documents and statements show which clients are affected. A client is affected when the latest successful inventory scan recorded an `affected` or `needs_review` finding for the CVE on one of that client's assets. Needs-review clients carry a `(review)` marker. The line is omitted when no successful scan or affected client exists, and client names are never sent to public sources.

## 10. Degraded sources and diagnostics

Source health is recorded per asset and source. For generic product targets, an NVD failure degrades discovery coverage while independent evidence remains available. For exact packages, OSV is required and NVD/CVE/EUVD are optional enrichment; an enrichment outage does not invalidate native applicability. If EPSS fails, applicability can remain valid while the score is unavailable. KEV outages degrade prioritization enrichment. Notification channels do not depend on one another.

Empty independent product searches and disabled core sources leave coverage unconfirmed. KEV membership is `null` when unavailable, `false` when a healthy catalogue does not list the CVE, and `true` when listed. VulnCheck KEV is unavailable without a token; that state is `off: no token`, not a source failure. A Shodan CVEDB lookup cap or truncated discovery result is degraded health for that source only. None of these values implies absence of exploitation outside that catalogue. Reports are fresh query results; they do not contain notification delivery state. Inspect SQLite deliveries for channel acceptance details.

An incomplete core refresh retains prior stored findings rather than marking them resolved. Failed CISA KEV and EU KEV refreshes retain previous membership and its original evidence timestamps in monitoring state. Missing findings are never automatically resolved or deleted. Previously observed CVEs for the same product/version are refreshed even if discovery no longer returns them, allowing rejected records to produce material events. Source health must be read alongside stored findings. There is no persistent offline source cache; retained findings are historical observations, not fresh source responses.

Validate local configuration and state access:

```console
cvebeacon doctor
cvebeacon doctor --live
cvebeacon source-status
```

`doctor --live` also performs a bounded query against enabled public sources without committing scan state and returns a nonzero status if any check fails. Without an inventory, `doctor` checks the watch deployment instead: configuration, the watch and state data directories, watch database, channels, sources and the native schedule; it says that inventory checks are skipped and exits nonzero only for a real problem. `source-status` reports the latest persisted scan’s per-asset source outcome, including failed refreshes. An incomplete scan is recorded with run status `failed` and retains its source-health evidence and useful partial findings. Use `--verbose` for additional local diagnostics. Secrets and full webhook URLs are not printed.

Common failures:

- `coverage_unknown`: verify vendor/product spelling and add a verified product mapping if CPE resolution is ambiguous.
- HTTP 429: keep default pacing, reduce concurrent external use, or configure an NVD API key.
- certificate errors: verify the host trust store, corporate proxy, and TLS-inspection CA; do not disable TLS verification.
- inventory mapping errors: run `inventory inspect`, then match the exact configured header names.
- notification authentication errors: verify environment variables, tenant consent, sender, recipient, and workflow ownership.

## 11. Teams notifications

`[notifications.teams]` and `[notifications.email]` are the scan-report notification sections. They are legacy, send scan findings, and read secrets from the environment. Watch alert channels use the separate `[watch.channels.*]` tables described in [watch mode](WATCH.md#channels); the two mechanisms are independent.

Create a Teams Workflow with the “When a Teams webhook request is received” trigger and an action that posts the received Adaptive Card to the intended channel or chat. Store the generated URL in an environment variable, then enable the channel:

```toml
[notifications.teams]
enabled = true
webhook_env = "CVEBEACON_TEAMS_WEBHOOK_URL"
```

Set the environment variable in the account that runs the scan and test it:

```console
cvebeacon notify test --channel teams
```

Treat the webhook URL as a secret. Workflow lifecycle and ownership remain Microsoft tenant administration concerns.

The Teams integration sends the secret URL without an Entra bearer token. Use a workflow trigger configured to accept that request mode; triggers restricted to tenant-authenticated callers require an authentication flow this integration does not implement. Test the actual tenant workflow before enabling scheduled alerts.

## 12. Microsoft 365 email

Register an Entra application, grant the Microsoft Graph `Mail.Send` application permission, obtain administrator consent, and limit mailbox scope with Exchange controls where appropriate. Configure only non-secret sender and recipient values in TOML:

```toml
[notifications.email]
enabled = true
tenant_id_env = "CVEBEACON_M365_TENANT_ID"
client_id_env = "CVEBEACON_M365_CLIENT_ID"
client_secret_env = "CVEBEACON_M365_CLIENT_SECRET"
sender = "scanner@example.invalid"
recipients = ["security@example.invalid"]
```

Set the three credential variables outside the configuration, then run:

```console
cvebeacon notify test --channel email
```

Graph HTTP 202 means Microsoft accepted the request for processing; it is not proof of final recipient delivery.

Enable both channel tables to send one consolidated alert independently to each channel. On split success, the successful channel stays accepted and only the failed channel retries on a later scan. Use `cvebeacon notify test` to test all enabled channels.

Remote acceptance and local SQLite acknowledgement are separate operations. A crash after remote acceptance but before local acknowledgement, or overlapping scanner processes, can produce a duplicate on retry. Delivery is at least once, not exactly once; run only one scheduled scanner per state database. Large notifications summarize the first 50 Teams items or 100 email items and direct the operator to history for the remaining changes.

## 13. Automatic scheduling

Preview and install the default four-hour schedule:

```console
cvebeacon --config /absolute/path/cvebeacon.toml schedule install --dry-run
cvebeacon --config /absolute/path/cvebeacon.toml schedule install
```

The interactive setup asks for an interval or fixed times, shows the proposal, and requires confirmation. Fixed times use `--times 07:00,19:00`; `--command scan|watch|both` selects the action and defaults to the configured mode. For automation, provide a value such as `--every 4h --yes`; Windows accepts 2 through 24 whole hours, while Linux cron accepts 2, 3, 4, 6, 8, 12, or 24. Inspect and remove with `schedule status` and `schedule remove`. See [scheduling](SCHEDULING.md) for exact ownership and safe manual native scheduling.

Ensure the scheduled account can read the inventory/configuration, write state/reports, reach source endpoints, and obtain notification environment variables.

## 14. Standalone use and upgrades

The standalone executable accepts the same commands, for example `cvebeacon.exe scan` on Windows and `./cvebeacon scan` on Linux. Keep configuration and inventory outside the executable directory so upgrades do not replace operator data. Back up the SQLite file before a version upgrade. Run `doctor`, an inventory validation, and a dry-run schedule proposal after replacement. Reinstall the native schedule if the executable path changed.

The dashboard uses the same executable and configuration: `cvebeacon serve` listens at `http://127.0.0.1:8787`. Existing CVEBeacon accounts require individual login with configurable roles; create the deploying administrator with `users add USERNAME --admin` or use the localhost-only first-account bootstrap. With no accounts, localhost remains accessible without login unless the optional shared password is configured using `cvebeacon dashboard hash-password` and an environment-supplied hash. Account sessions expire after one hour or fifteen idle minutes by default and can be revoked with Log out. Remote binding without authentication requires `--allow-unauthenticated-remote`; remote password sessions need HTTPS to resist interception. Authenticated operators can start scans, watch runs, evaluations, deliveries and channel tests as single-flight background jobs with bounded logs and audited history, and can install or remove the native schedule where the host setup is safe. See the [dashboard guide](DASHBOARD.md) for setup, permissions, secure cookies, reverse proxies, findings, history, manual queries, exports, source freshness, operations and schedules. No dashboard password or public-source API key is required for core CLI monitoring.

State schema version 3 retains version 2 scan-attempt and coverage metadata and adds an advisory alias index. Existing findings, material events, and delivery state are preserved transactionally. Back up the database while the scanner and dashboard are stopped before upgrading; to roll back to an older application, restore that matching backup. Historical scans do not acquire invented coverage or attempt metadata.
