# Native scheduling

CVEBeacon supports a single narrowly owned native schedule: the exact Windows task name `CVEBeacon Monitor`, or one marked block in the current Linux user’s crontab.

Install the default four-hour schedule:

```console
cvebeacon --config /absolute/path/cvebeacon.toml schedule install
```

Preview without modifying the host:

```console
cvebeacon --config /absolute/path/cvebeacon.toml schedule install --every 4 --dry-run
```

With no `--every` value, setup asks for an interval and defaults to four hours. For unattended installation, use a value such as `--every 4h --yes`. Intervals must be whole hours from 2 through 24. The common values are 2, 4, 6, 12, and 24. NVD asks automated clients not to request modified data more often than every two hours.

`--platform auto` is the default. An explicit `windows` or `linux` override is rejected for live changes on an incompatible host, but can be used with `--dry-run` to inspect the generated proposal.

Inspect or remove the owned schedule:

```console
cvebeacon schedule status
cvebeacon schedule remove
```

Removal requires confirmation unless `--yes` is used. It never performs wildcard deletion. On Linux, only text between `# BEGIN CVEBEACON MANAGED` and `# END CVEBEACON MANAGED` is replaced or removed; unrelated crontab entries are preserved.

The generated command uses absolute executable and configuration paths. A packaged executable schedules itself. A source invocation uses the installed console launcher when available, or the active Python interpreter with `-m cvebeacon`.

For manual administration, create an equivalent task or cron entry that runs `cvebeacon --config <absolute-path> scan`. Run it under an account with read access to the inventory and configuration, write access to the state/output directories, and access to required environment variables.
