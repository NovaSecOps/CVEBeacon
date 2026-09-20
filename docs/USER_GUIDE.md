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

The legacy product path requires `asset_id`, `vendor`, `product`, and `version` as nonblank text. Explicit package/PURL/CPE/commit identities may omit generic fields; see [identity rules and optional mappings](IDENTITY.md). Asset IDs must be unique without regard to case. CVEBeacon normalizes surrounding whitespace but does not rewrite the source inventory. Store versions as text, including `7.0`, `7.0.0`, and leading zeros; numeric, date, boolean, and compound values are rejected because their original spelling cannot be recovered reliably. Quote versions in JSON and YAML and format Excel cells as text before entering them.

Source controls, retry/timeouts, output paths, optional exact CPE mappings, and notification settings are illustrated in the example configuration. A configured product CPE must be a complete CPE 2.3 name with a wildcard version; verify it against NVD before use.

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

Validation reports source locations for malformed records, missing mapped columns, blank fields, duplicate IDs, invalid structure, and unreadable files.

## 5. First scan

Run a complete monitoring scan and create an XLSX report:

```console
cvebeacon --config cvebeacon.toml scan --report xlsx
```

The run queries each identical component identity/version target once, then associates results with each asset ID. Completed findings, source health, events, and pending notification work are committed together. A run that fails before commit does not appear as successful state. Notification attempts occur after this commit so failures can retry safely.

The first scan may be slow without an NVD API key because the default respects NVD’s public-client pacing guidance. Set the configured API-key environment variable to use a key; never put the key in TOML.

Exit codes are `0` for a successful operation, `2` for validation/operational failure, `3` for notification failure, and `4` for a scan with uncertain coverage or degraded sources. A completed scan can contain useful findings and still exit `4`; review its report and `source-status`. Notification failure takes precedence if both occur.

Package/PURL identities, category and system grouping work in all four input formats; `examples/general.toml` demonstrates a mixed inventory. No accounts or credentials are needed for core scans.

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

## 8. Applicability and coverage states

- `affected`: affirmative exact-version evidence supports applicability.
- `not_affected`: affirmative authoritative evidence explicitly excludes the version.
- `needs_review`: relevant evidence exists but version semantics are unsupported, incomplete, rejected, or conflicting.
- `coverage_unknown`: exact product identity or authoritative coverage could not be established.

`not_affected` is never inferred from zero search results. Human-oriented or custom version ranges are preserved but not forced through a generic comparator. A known-exploitation catalog entry is prioritization evidence; it does not by itself prove product-version applicability. EPSS is predictive and remains distinct from known exploitation.

SemVer and Python version ranges use their respective ordering rules. Generic product schemes and partial-version wildcards without a supported comparator require review. Package-native ranges additionally support declared ecosystem ordering; see [supported semantics](IDENTITY.md). Product punctuation is significant; automatic CPE resolution allows CPE underscores to represent spaces, but does not guess vendor aliases. Configure a verified mapping when names differ. Configured edition, update, and platform fields are retained. NVD AND/negated/environment-dependent configurations and CVE platform-scoped claims require review when the inventory cannot establish those conditions. A CPE API search hit alone does not prove the full configuration applies.

## 9. Material changes

Notifications are created for a new finding or a meaningful change to applicability, affected evidence, rejection/withdrawal state, CVSS, CISA KEV membership, EU KEV membership, or a comparable remediation-relevant claim. Upstream modification timestamps and ordinary EPSS movement are stored when available but do not independently trigger alerts.

Any change in the selected CVSS score/vector/version is material. When sources provide different scores, the highest reported base score and its associated vector/version are displayed together; the conflict and original metrics remain in the evidence. Reordering equivalent evidence does not create an alert. Schema 3 preserves legacy fingerprints and alias-only changes do not produce an upgrade alert storm. Changed source claims still produce material events.

## 10. Degraded sources and diagnostics

Source health is recorded per asset and source. For generic product targets, an NVD failure degrades discovery coverage while independent evidence remains available. For exact packages, OSV is required and NVD/CVE/EUVD are optional enrichment; an enrichment outage does not invalidate native applicability. If EPSS fails, applicability can remain valid while the score is unavailable. KEV outages degrade prioritization enrichment. Notification channels do not depend on one another.

Empty independent product searches and disabled core sources leave coverage unconfirmed. KEV membership is `null` when unavailable, `false` when a healthy catalogue does not list the CVE, and `true` when listed. None of these values implies absence of exploitation outside that catalogue. Reports are fresh query results; they do not contain notification delivery state. Inspect SQLite deliveries for channel acceptance details.

An incomplete core refresh retains prior stored findings rather than marking them resolved. Failed KEV refreshes retain previous membership and its original evidence timestamps in monitoring state. Missing findings are never automatically resolved or deleted. Previously observed CVEs for the same product/version are refreshed even if discovery no longer returns them, allowing rejected records to produce material events. Source health must be read alongside stored findings. There is no persistent offline source cache; retained findings are historical observations, not fresh source responses.

Validate local configuration and state access:

```console
cvebeacon doctor
cvebeacon doctor --live
cvebeacon source-status
```

`doctor --live` also performs a bounded query against enabled public sources without committing scan state and returns a nonzero status if any check fails. `source-status` reports the latest persisted scan’s per-asset source outcome, including failed refreshes. An incomplete scan is recorded with run status `failed` and retains its source-health evidence and useful partial findings. Use `--verbose` for additional local diagnostics. Secrets and full webhook URLs are not printed.

Common failures:

- `coverage_unknown`: verify vendor/product spelling and add a verified product mapping if CPE resolution is ambiguous.
- HTTP 429: keep default pacing, reduce concurrent external use, or configure an NVD API key.
- certificate errors: verify the host trust store, corporate proxy, and TLS-inspection CA; do not disable TLS verification.
- inventory mapping errors: run `inventory inspect`, then match the exact configured header names.
- notification authentication errors: verify environment variables, tenant consent, sender, recipient, and workflow ownership.

## 11. Teams notifications

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

The interactive setup asks for an interval, defaults to four hours, shows the proposal, and requires confirmation. For automation, provide a value such as `--every 4h --yes`; Windows accepts 2 through 24 whole hours, while Linux cron accepts 2, 3, 4, 6, 8, 12, or 24. Inspect and remove with `schedule status` and `schedule remove`. See [scheduling](SCHEDULING.md) for exact ownership and safe manual native scheduling.

Ensure the scheduled account can read the inventory/configuration, write state/reports, reach source endpoints, and obtain notification environment variables.

## 14. Standalone use and upgrades

The standalone executable accepts the same commands, for example `cvebeacon.exe scan` on Windows and `./cvebeacon scan` on Linux. Keep configuration and inventory outside the executable directory so upgrades do not replace operator data. Back up the SQLite file before a version upgrade. Run `doctor`, an inventory validation, and a dry-run schedule proposal after replacement. Reinstall the native schedule if the executable path changed.

The dashboard uses the same executable and configuration: `cvebeacon serve` listens at `http://127.0.0.1:8787` without login by default. Optional password authentication uses `cvebeacon dashboard hash-password` and an environment-supplied hash. Sessions expire after one hour by default and can be revoked with Log out. Remote binding without authentication requires `--allow-unauthenticated-remote`; remote password sessions need HTTPS to resist interception. See the [dashboard guide](DASHBOARD.md) for setup, secure cookies, reverse proxies, findings, history, manual queries, exports, and source freshness. No dashboard password or public-source API key is required for core CLI monitoring.

State schema version 3 retains version 2 scan-attempt and coverage metadata and adds an advisory alias index. Existing findings, material events, and delivery state are preserved transactionally. Back up the database while the scanner and dashboard are stopped before upgrading; to roll back to an older application, restore that matching backup. Historical scans do not acquire invented coverage or attempt metadata.
