# CVEBeacon

CVEBeacon is a conservative command-line vulnerability monitor for product inventories. It correlates primary public sources, preserves claim provenance, records material changes in SQLite, and reports uncertainty instead of treating missing coverage as a clean result.

## Capabilities

- XLSX, CSV, JSON, and YAML inventories with configurable field mappings
- NVD/CPE product resolution and exact-version discovery
- official CVE List V5 and ENISA EUVD cross-checks
- CISA KEV, ENISA EU KEV, and FIRST EPSS enrichment
- four explicit applicability/coverage states: `affected`, `not_affected`, `needs_review`, and `coverage_unknown`
- transactional history and independent notification delivery state
- on-demand XLSX and JSON reports
- Teams Workflows and Microsoft Graph app-only email
- Windows Task Scheduler and Linux user-cron integration

## Quick start

CVEBeacon requires Python 3.11 or newer for a source installation. On Windows PowerShell:

```console
python -m venv .venv
.venv\Scripts\python.exe -m pip install .
copy cvebeacon.example.toml cvebeacon.toml
.venv\Scripts\cvebeacon.exe inventory validate
.venv\Scripts\cvebeacon.exe scan --report xlsx
```

On Linux:

```console
python3 -m venv .venv
.venv/bin/python -m pip install .
cp cvebeacon.example.toml cvebeacon.toml
.venv/bin/cvebeacon inventory validate
.venv/bin/cvebeacon scan --report xlsx
```

Edit `cvebeacon.toml` before the first scan. The included example uses a CSV inventory; equivalent XLSX, JSON, and YAML examples are under `examples/`.

Common commands:

```console
cvebeacon query --vendor "Example Vendor" --product "Example Product" --version "1.0.0"
cvebeacon asset asset-001
cvebeacon history
cvebeacon export --format xlsx
cvebeacon doctor
cvebeacon source-status
cvebeacon schedule install --every 4
```

Notifications are optional and obtain credentials only from environment variables. Native schedules default to every four hours and require confirmation unless `--yes` is supplied. The web dashboard is not included; all supported workflows are available through the CLI.

See the [user guide](docs/USER_GUIDE.md), [source notes](docs/SOURCES.md), [network requirements](docs/NETWORK_REQUIREMENTS.md), and [scheduling guide](docs/SCHEDULING.md).

No license has been selected. Choose and add a license before publication or distribution.
