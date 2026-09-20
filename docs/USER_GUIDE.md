# CVEBeacon user guide

## 1. Purpose and operating model

CVEBeacon reads a current product inventory, asks primary vulnerability sources about each distinct vendor/product/version target, preserves the returned evidence, and records material finding changes. The inventory remains the source of truth; the SQLite database is monitoring history, not an asset database.

The tool is deliberately conservative. A missing CPE, empty search result, unsupported version scheme, disagreement, or source outage never becomes an automatic clean result.

## 2. Requirements and installation

A source installation requires Python 3.11 or newer, DNS, and outbound HTTPS access described in [network requirements](NETWORK_REQUIREMENTS.md).

Windows PowerShell:

```console
python -m venv .venv
.venv\Scripts\python.exe -m pip install .
.venv\Scripts\cvebeacon.exe --help
```

Linux:

```console
python3 -m venv .venv
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

`asset_id`, `vendor`, `product`, and `version` are required and cannot be blank. Asset IDs must be unique without regard to case. CVEBeacon normalizes surrounding whitespace but does not rewrite the source inventory.

Source controls, retry/timeouts, output paths, optional exact CPE mappings, and notification settings are illustrated in the example configuration. A configured product CPE must be a complete CPE 2.3 name with a wildcard version; verify it against NVD before use.

## 4. Inventory formats and mapping

The file extension selects XLSX, CSV, JSON, or YAML when `format = "auto"`. A different supported format can be named explicitly.

### XLSX

Set `worksheet`, `header_row`, and the four source column names. Formulas are read from their cached values; do not rely on CVEBeacon to calculate a workbook. Inspect all worksheet names and headers first:

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
cvebeacon inventory validate
cvebeacon inventory validate path/to/alternate.csv
```

Validation reports source locations for malformed records, missing mapped columns, blank fields, duplicate IDs, invalid structure, and unreadable files.

## 5. First scan

Run a complete monitoring scan and create an XLSX report:

```console
cvebeacon --config cvebeacon.toml scan --report xlsx
```

The run queries each identical vendor/product/version target once, then associates results with each asset ID. Completed findings, source health, events, and pending notification work are committed together. A run that fails before commit does not appear as successful state. Notification attempts occur after this commit so failures can retry safely.

The first scan may be slow without an NVD API key because the default respects NVD’s public-client pacing guidance. Set the configured API-key environment variable to use a key; never put the key in TOML.

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

XLSX reports contain Summary, Findings, Uncertainty, Evidence, and Source Health sheets. They are generated on demand rather than maintained as a vulnerability mirror.

## 8. Applicability and coverage states

- `affected`: affirmative exact-version evidence supports applicability.
- `not_affected`: affirmative authoritative evidence explicitly excludes the version.
- `needs_review`: relevant evidence exists but version semantics are unsupported, incomplete, rejected, or conflicting.
- `coverage_unknown`: exact product identity or authoritative coverage could not be established.

`not_affected` is never inferred from zero search results. Human-oriented or custom version ranges are preserved but not forced through a generic comparator. A known-exploitation catalog entry is prioritization evidence; it does not by itself prove product-version applicability. EPSS is predictive and remains distinct from known exploitation.

## 9. Material changes

Notifications are created for a new finding or a meaningful change to applicability, affected evidence, rejection/withdrawal state, CVSS, CISA KEV membership, EU KEV membership, or a comparable remediation-relevant claim. Upstream modification timestamps and ordinary EPSS movement are stored when available but do not independently trigger alerts.

## 10. Degraded sources and diagnostics

Source health is recorded per asset and source. If NVD fails, official record or EUVD evidence may still be reported, but coverage remains degraded. If EPSS fails, applicability can remain valid while the score is unavailable. KEV outages degrade prioritization enrichment. Notification channels do not depend on one another.

Validate local configuration and state access:

```console
cvebeacon doctor
cvebeacon doctor --live
cvebeacon source-status
```

`doctor --live` also performs a bounded query against enabled public sources without committing state. `source-status` reports the last completed scan’s per-asset source outcome. Use `--verbose` for additional local diagnostics. Secrets and full webhook URLs are not printed.

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

## 13. Automatic scheduling

Preview and install the default four-hour schedule:

```console
cvebeacon --config /absolute/path/cvebeacon.toml schedule install --dry-run
cvebeacon --config /absolute/path/cvebeacon.toml schedule install
```

The interactive setup asks for an interval, defaults to four hours, shows the proposal, and requires confirmation. For automation, provide a value such as `--every 4h --yes`; the accepted range is 2 through 24 whole hours. Inspect and remove with `schedule status` and `schedule remove`. See [scheduling](SCHEDULING.md) for exact ownership and safe manual native scheduling.

Ensure the scheduled account can read the inventory/configuration, write state/reports, reach source endpoints, and obtain notification environment variables.

## 14. Standalone use and upgrades

The standalone executable accepts the same commands, for example `cvebeacon.exe scan` on Windows and `./cvebeacon scan` on Linux. Keep configuration and inventory outside the executable directory so upgrades do not replace operator data. Back up the SQLite file before a version upgrade. Run `doctor`, an inventory validation, and a dry-run schedule proposal after replacement. Reinstall the native schedule if the executable path changed.

No browser dashboard is included. This avoids an inbound service and keeps the supported operational surface to the CLI, reports, notifications, and native scheduler.
