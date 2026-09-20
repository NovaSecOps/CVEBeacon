# CVEBeacon

CVEBeacon is a conservative vulnerability monitor for product inventories, with a command-line interface and an optional local web dashboard. It correlates primary public sources, preserves claim provenance, records material changes in SQLite, and reports uncertainty instead of treating missing coverage as a clean result.

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
- dashboard for scan activity, findings, history, asset lookup, manual queries, and reports

## Quick start

CVEBeacon requires Python 3.11 or newer for a source installation. CPython 3.11–3.14 are tested on Windows and Linux; see the [validation matrix](docs/VALIDATION.md). On Windows PowerShell:

```console
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade "pip>=26.2"
.venv\Scripts\python.exe -m pip install .
copy cvebeacon.example.toml cvebeacon.toml
.venv\Scripts\cvebeacon.exe inventory validate
.venv\Scripts\cvebeacon.exe scan --report xlsx
```

On Linux:

```console
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade 'pip>=26.2'
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
cvebeacon serve
```

Notifications are optional and obtain credentials only from environment variables. Native schedules default to every four hours and require confirmation unless `--yes` is supplied. The dashboard defaults to `http://127.0.0.1:8787`; scanning remains a separate scheduled process. See the [dashboard guide](docs/DASHBOARD.md) before exposing it to a network.

See the [user guide](docs/USER_GUIDE.md), [source notes](docs/SOURCES.md), [network requirements](docs/NETWORK_REQUIREMENTS.md), [scheduling guide](docs/SCHEDULING.md), and [validation workflow](docs/VALIDATION.md).

No license has been selected. Choose and add a license before publication or distribution.
