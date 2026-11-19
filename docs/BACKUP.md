# Backup and restore

CVEBeacon can create, verify, prune and restore local backups from the command
line, and additionally create, verify, download, prune and restore them from
the dashboard. Backups are administrator data: they contain monitoring history,
watch state, account records and the configuration file. Keep the backup
directory writable only by the service account and trusted administrators.

## What a backup contains

One backup is a private directory named after its UTC creation time:

```text
<backup directory>/20261119T120000Z/
  manifest.json
  config.toml
  0.db
  1.db
  ...
  secrets/0          # only when secret files were included
```

The backup contains:

- every configured state database: monitoring/inventory state, the watch
  database, the account database and the dashboard job history;
- other SQLite databases discovered in the data directory that the application
  owns;
- the configuration file;
- referenced secret files only when **include secret files** is selected (or
  `--include-secrets` is passed).

State that optional automation keeps outside the core data directory is not
discovered automatically; back it up with the automation guide's procedure.
Directories that are themselves backup stores are never discovered as owned
databases, even after `backup.directory` changes.

Each SQLite file is copied with SQLite's online backup API, integrity-checked,
and hashed. A normal file copy is not sufficient while a database is using WAL.

`manifest.json` records the manifest format version, the backup identifier,
`created_by`, creation time, every file's name, size and SHA-256 digest, each
database's original path and logical content digest, and the detected schema
versions. Verification ties every database, configuration and secret row to
its file-list entry, checks every size and hash, re-runs SQLite integrity
checks, and compares the stored logical content digests.

Hashes detect corruption; they are not a signature. An attacker who can rewrite
a backup directory can also rewrite its manifest. Treat copied or downloaded
backups as untrusted input and keep them on protected storage.

Verification performs a full logical read of every database, so large watch
databases make `verify`, `create` and dashboard downloads noticeably slower.

The directory, its subdirectories and its files are created owner-only: `0700`
directories and `0600` files on POSIX.

### Secret files

Referenced secret files are excluded by default. This keeps webhook tokens,
SMTP passwords, API keys and similar material out of routine backups. Enable
inclusion only when the backup location is at least as protected as the live
secret directory, and remember to protect and dispose of those copies with the
same care as the originals.

Included secret files are restored with the databases. A secret path that is no
longer configured and is outside the data directory is refused rather than
written.

## Settings

Backups work without any new configuration. An optional `[backup]` section
changes the defaults:

```toml
[backup]
# directory = "backups"    # disabled: default is <state database parent>/backups
retention_days = 7
keep_min = 3
compress = true            # applies to dashboard downloads only
```

- `directory` is administrator-only, like other filesystem paths in the
  configuration editor. A relative value resolves from the configuration file's
  directory; when the key is absent the default is the `backups` directory
  beside the state database. A configuration file outside the data directory
  therefore needs an explicit, service-writable location if the default is not
  wanted.
- `retention_days` must be from 1 to 3650.
- `keep_min` must be from 0 to 1000. Pruning never removes the newest
  `keep_min` backups, even when they are older than `retention_days`.
- `compress` selects gzip for downloads. Stored backups are always plain files.

Old configurations without a `[backup]` section keep working with these
defaults.

## Command line

```console
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup create
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup create --include-secrets
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup list
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup verify 20261119T120000Z
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup restore 20261119T120000Z
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup restore 20261119T120000Z --yes
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup prune
```

`restore` asks for confirmation unless `--yes` is supplied. `list` shows the
identifier, creation time, size, database count, creator, schema versions and
whether the manifest is structurally valid. `verify` checks every hash and
returns a non-zero exit code when a file is missing or changed.

Create, verify, restore, prune and dashboard download take the shared run
locks. Restore is refused while another run or a dashboard job is active, and
says what to stop or wait for.

`restore` takes the shared run lock before verification, validation or any
filesystem work, then verifies the whole backup and validates the backed-up
configuration with the running loader before changing anything. It refuses a
configuration that this version cannot load and a backup whose state or watch
schema is newer than the running code. It then keeps an automatic `pre-restore`
safety backup and stages every replacement in a private temporary file beside
its target with fsync. Databases are copied into the live files with SQLite's
own backup API, so open SQLite connections are tolerated and each database is
replaced atomically; configuration and secret files use bounded atomic file
replacement. The safety backup includes the live account, job-history and other
state databases, the current configuration and every secret file that the
restore will overwrite, including secret files that are no longer referenced by
the current configuration. If any replacement or migration step fails, the
previous files are restored automatically from that safety backup and the
safety identifier is reported. If automatic rollback itself fails, the error
names the safety backup for manual recovery.

Absent records are not destructive: if the backup recorded a database or secret
as absent and live data now exists at that path, restore leaves it in place and
reports it as preserved. Use a matching backup or move the live data aside
first if removal is intended.

Do not cancel a running restore. A cancelled or interrupted restore attempts
the same automatic rollback, but stopping the process twice may prevent it;
recover with the reported safety backup in that case. Databases are migrated
forward after replacement when needed.

Stop the dashboard before a command-line restore. From the dashboard, the
running job preserves its own live account database and job-history database so
the restore can report its outcome; the backup still contains both for a
command-line restore with the service stopped. Restart or reload the dashboard
after a restore that changes the configuration.

Backups stored under the data directory are included in administrator updater
snapshots, which keep their existing data-directory behaviour. Choose a
`backup.directory` outside that data directory if snapshots must not contain
them.

## Dashboard

The **Backups** page is available to signed-in users with `view`. It shows the
retained count and the last backup time. Administrators can create a backup
(with an optional include-secrets checkbox), verify one, download it, prune
expired backups, and restore one by typing its identifier.

Creation, verification and restore run as ordinary dashboard jobs, share the
run locks, and appear in the job history. Every action is audited under the
signed-in administrator. A failed job retains its log and outcome.
Downloads are assembled from the verified backup on request and streamed from
a temporary file; no archive is retained on disk. The archived manifest uses
relative backup names instead of local filesystem paths. The configuration file
itself is included verbatim, including any legacy inline endpoint values, so
protect downloaded archives accordingly.

Pruning applies the configured retention and keeps the newest valid `keep_min`
backups. A crashed or unreadable backup directory is aged by its timestamp and
removed once past retention; it never consumes a `keep_min` slot.

## Scheduling

Backups do not need a new scheduler. Use the existing cron or systemd timer
mechanism with the service account. For example, a daily cron entry:

```cron
17 3 * * * /opt/cvebeacon/.venv/bin/cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup create && /opt/cvebeacon/.venv/bin/cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup prune
```

Or a systemd timer for a native Linux install:

```ini
# /etc/systemd/system/cvebeacon-backup.service
[Unit]
Description=CVEBeacon local backup

[Service]
Type=oneshot
User=cvebeacon
UMask=0077
ExecStart=/opt/cvebeacon/.venv/bin/cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup create
ExecStart=/opt/cvebeacon/.venv/bin/cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup prune
```

```ini
# /etc/systemd/system/cvebeacon-backup.timer
[Unit]
Description=Daily CVEBeacon backup

[Timer]
OnCalendar=*-*-* 03:17:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer with `sudo systemctl enable --now cvebeacon-backup.timer`.
Adjust paths and times for the installation. Keep backups on storage with the
same access controls as the live data, and copy them off the host only with an
equally protected transport.

## Verification and recovery checks

After creating a backup, verify it once and periodically:

```console
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml backup verify 20261119T120000Z
```

A restore replaces state with the backup contents. Compare a known watch,
inventory or account observation afterwards and run:

```console
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml doctor --allow-watch-only --local-state
```

See [upgrading](UPGRADING.md) for schema compatibility, and
[deployment](DEPLOY.md) for service ownership and directory permissions.
