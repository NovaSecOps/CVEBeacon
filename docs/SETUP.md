# Setup

`cvebeacon setup` writes a commented TOML configuration, validates it with the
same loader used by every command, and offers to install the native schedule.
It asks before overwriting an existing file and keeps a copy at
`<name>.bak-<timestamp>`. Secrets are never written into the configuration.

```console
cvebeacon setup
cvebeacon setup --config /etc/cvebeacon/cvebeacon.toml
cvebeacon setup --config cvebeacon.toml --force
```

Every question shows its default in brackets; Enter accepts it. `--force` skips
the overwrite question but still creates the backup. Ctrl-C or end of input
cancels without writing a configuration.

## What it asks

1. **Mode.** `inventory` scans a component file, `watch` monitors CVE changes,
   and `both` does each. The default is `watch`.
2. **Inventory.** The file path and format, defaulting to the extension. The
   file is loaded once so a bad path or format can be corrected immediately,
   or skipped and fixed later. Paths in the file are relative to the
   configuration directory.
3. **Watch sources.** NVD, EUVD, CISA KEV, EU KEV and EPSS are enabled by
   default; NVD cannot be disabled. Disabling EPSS warns that `epss_min` rules
   will be unavailable.
4. **First run.** `baseline` (default, alerts start now), `backfill N days`
   (1 to 120), or `full` history with a warning about time and bandwidth. The
   first `watch sync` still asks before downloading full history.
5. **NVD API key.** Optional. Use an environment variable or a protected secret
   file; a key raises the request limit and speeds up syncs.
6. **Rules.** Choose one or more presets, edit their thresholds, name them, add
   an optional vendor filter, and choose how old CVEs are handled (`digest` by
   default). The presets are critical CVSS, likely-exploited EPSS, any KEV,
   KEV plus a score, active exploitation, and a custom condition with an
   AND/OR choice. Watch mode requires at least one rule.
7. **Channels.** Pick one or more types, answer only that type's required
   fields, and assign rules to channels (default: every channel). Optional
   fields stay at their defaults and are written as comment lines. Email
   presets cover Gmail, Microsoft 365 SMTP, Microsoft 365 Graph, and a custom
   SMTP server. After writing, the wizard offers a test message per channel.
8. **Schedule.** Choose fixed times (default `07:00,19:00`) or an interval in
   hours, and what the schedule runs (`scan`, `watch`, or `both`). The exact
   command is shown before installation; the default is not to install, and
   the `schedule install` command is printed for later.

## Secrets

For each channel secret, choose an environment variable or a file. File
secrets are written next to the configuration as
`secrets/<channel>-<field>`, with directory mode `0700` and file mode `0600` on
POSIX. On Windows, restrict the files with NTFS permissions. The configuration
contains only the environment variable name or the relative file path.

## Example session

```text
Mode (inventory/watch/both) [watch]:
Enable EUVD? [Y/n]:
Enable CISA_KEV? [Y/n]:
Enable EU_KEV? [Y/n]:
Enable EPSS? [Y/n]:
First run history (baseline/backfill/full) [baseline]:
NVD API key (skip/env/file) [skip]:
Rule numbers (comma-separated) [1]:
CVSS minimum [9]:
Rule name [critical]:
Vendor filter (comma-separated, blank for none) []:
Old CVEs (digest/alert/ignore) [digest]:
Channel name [alerts]:
Channel type [smtp]:
Email preset (gmail/m365-smtp/m365-graph/custom) [gmail]:
From address [alerts@example.com]:
To addresses [security@example.com]:
SMTP username (use - for no authentication) [alerts@example.com]:
Store the password in (env/file) [env]:
Environment variable name [CVEBEACON_SMTP_PASSWORD]:
Channels for rule "critical" (comma-separated or all) [alerts]:
Send a test message to each channel now? [y/N]:
Schedule type (times/interval) [times]:
Times (comma-separated HH:MM) [07:00,19:00]:
Scheduled command (scan/watch/both) [watch]:
Install this schedule now? [y/N]:
```

The final lines list the configuration path and the commands to run next.

## After setup

```console
cvebeacon --config cvebeacon.toml watch sync
cvebeacon --config cvebeacon.toml watch evaluate --all --yes
cvebeacon --config cvebeacon.toml watch run
cvebeacon --config cvebeacon.toml scan
```

Run `watch evaluate --all --yes` after a `backfill` or `full` first run. The
wizard only prints the commands that apply to the selected mode. See
[watch mode](WATCH.md) and [scheduling](SCHEDULING.md) for the details.
