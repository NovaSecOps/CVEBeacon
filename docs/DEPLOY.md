# Deployment

One Linux VM, either from a source checkout or with Docker. Details are in the
[setup guide](SETUP.md), [watch mode](WATCH.md), and [scheduling](SCHEDULING.md).

## A. Linux VM, native install

### Prerequisites

- Python 3.11 or newer, `git`, `venv`, the `sqlite3` CLI, and outbound HTTPS to
  the [network requirements](NETWORK_REQUIREMENTS.md) hosts; the built-in
  schedule needs a running cron daemon (`crontab`).
- A dedicated unprivileged account and separate code and state directories.

Check the interpreter; use `python3.12` below when `python3` is older.

```console
python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'
sudo useradd --system --user-group --home-dir /var/lib/cvebeacon --shell /usr/sbin/nologin cvebeacon
sudo install -d -m 0750 -o cvebeacon -g cvebeacon /opt/cvebeacon /var/lib/cvebeacon
sudo -u cvebeacon git clone https://github.com/NovaSecOps/CVEBeacon.git /opt/cvebeacon
sudo -u cvebeacon python3 -m venv /opt/cvebeacon/.venv
sudo -u cvebeacon /opt/cvebeacon/.venv/bin/python -m pip install --upgrade 'pip>=26.2'
sudo -u cvebeacon /opt/cvebeacon/.venv/bin/python -m pip install /opt/cvebeacon
```

### Write the configuration

```console
sudo -u cvebeacon /opt/cvebeacon/.venv/bin/cvebeacon setup \
  --config /var/lib/cvebeacon/cvebeacon.toml
```

The wizard writes the configuration and any `secrets/` files beside it (`0700`
directory, `0600` files on POSIX), and relative paths resolve there; leave the
schedule question for later. Watch-only deployments keep
`[watch] enabled = true`; `scan` and dashboard pages then need
`[inventory] path`, and a combined install uses `run`. The wizard writes the
watch database beside the configuration.

Load the command once as a function (a variable would not split in zsh):

```console
cb() { sudo -u cvebeacon /opt/cvebeacon/.venv/bin/cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml "$@"; }
```

### First day

Set `initial` and, for `backfill`, `backfill_days` (the wizard offers both).
Then run:

```console
cb watch run
```

That syncs the initial window, evaluates it, closes initialization and sends
the initial summary (add `--yes` for a `full` first sync). A baseline run stores
a silent baseline and sends nothing. To inspect downloads first, run
`cb watch sync`, then `cb watch run`; sync alone leaves initialization open.

One initial summary is sent per channel; generic webhooks split it into
documents of at most 1,000 events (see [delivery](WATCH.md#delivery)). With
`[watch] enabled = true`, `watch status` shows the database path, cursors,
counts and pending deliveries, and creates an empty database when none exists.
Check a channel:

```console
cb watch notify test soc-email
```

### Schedule it

The built-in command writes one managed block to the service account's crontab:

```console
cb schedule install --times 07:00,19:00 --command watch --yes
```

Use `--command both` with an inventory ([native scheduling](SCHEDULING.md)).
A systemd service and timer are an alternative; save each unit under its own
path:

```ini
# /etc/systemd/system/cvebeacon.service
[Unit]
Description=CVEBeacon watch run
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=cvebeacon
Group=cvebeacon
EnvironmentFile=-/var/lib/cvebeacon/cvebeacon.env
ExecStart=/opt/cvebeacon/.venv/bin/cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml run
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/cvebeacon
PrivateTmp=yes
```

```ini
# /etc/systemd/system/cvebeacon.timer
[Unit]
Description=Run CVEBeacon on a schedule
[Timer]
OnCalendar=*-*-* 07,19:00:00
Persistent=true
[Install]
WantedBy=timers.target
```

`EnvironmentFile=` is read before privileges drop, so it can be mode `0600`
owned by `root`. Enable the timer; `Persistent=true` catches up one missed run:

```console
sudo systemctl daemon-reload
sudo systemctl enable --now cvebeacon.timer
```

### Check the result

```console
cb watch status
cb schedule status
sudo systemctl list-timers cvebeacon.timer
```

Use the line for the scheduler you installed; see [exit codes](DEVELOPMENT.md#exit-codes).

### Upgrade

Stop the scheduler you actually use and wait for a running job to finish; run
one line:

```console
cb schedule remove --yes                                # built-in crontab
sudo systemctl stop cvebeacon.timer cvebeacon.service   # systemd timer
```

Back up the watch database with SQLite's online backup (use the path
`watch status` reports):

```console
sudo -u cvebeacon sqlite3 /var/lib/cvebeacon/cvebeacon-watch.db ".backup '/var/lib/cvebeacon/watch-backup.db'"
```

If you copy the database, `-wal` and `-shm` files instead, do so only while
nothing runs. Then upgrade and restore the scheduler you removed:

```console
sudo -u cvebeacon git -C /opt/cvebeacon pull --ff-only
sudo -u cvebeacon /opt/cvebeacon/.venv/bin/python -m pip install /opt/cvebeacon
cb schedule install --times 07:00,19:00 --command watch --yes
# or: sudo systemctl start cvebeacon.timer
```

## B. Docker

### Prerequisites

Requires Docker Engine with Compose 2.24 or newer (`docker compose version`);
`cvebeacon.env` uses the long `env_file` form. Use `/opt/cvebeacon` from A, or
clone one as root on a Docker-only host:

```console
sudo git clone https://github.com/NovaSecOps/CVEBeacon.git /opt/cvebeacon
sudo docker build --target core --tag cvebeacon:local /opt/cvebeacon
```

The image is built locally; no image is published. Build only from the
checkout. The copied file below keeps `build.context: ../..`, which points at
`/` after the copy; it only runs the prebuilt `cvebeacon:local` image. Rebuild
from the checkout after every upgrade.

### Prepare the runtime directory

```console
sudo install -d -m 0700 -o 65532 -g 65532 /srv/cvebeacon/state /srv/cvebeacon/reports /srv/cvebeacon/secrets
sudo install -d -m 0755 /srv/cvebeacon/inventory
sudo cp /opt/cvebeacon/deploy/container/compose.yml /srv/cvebeacon/compose.yml
sudo cp /opt/cvebeacon/deploy/container/cvebeacon.example.toml /srv/cvebeacon/cvebeacon.toml
```

`watch` does not read the inventory, so a watch-only deployment may leave
`/srv/cvebeacon/inventory` empty. `run` and `scan` need a real `inventory.json`
there (validate with `cvebeacon inventory validate`; see [setup](SETUP.md)).
The example writes state and the watch database to `/state`, and keeps
`[watch]` and its sample channel disabled: enable both and replace the webhook
URL. Leave `[watch] database` unset. Do not reuse a native wizard
configuration, which sets that path beside the read-only `/config`.

### Secrets

Prefer an untracked `/srv/cvebeacon/cvebeacon.env`, mode `0600`, with the
`*_env` names the configuration uses (for example `NVD_API_KEY` and
`CVEBEACON_HOOK_SECRET`). The `watch` and `run` services load it when present;
a missing file is fine. Secret file paths are relative to `/config`, so
`secrets/...` is `/config/secrets/...`. Install each prepared file directly,
mode `0600` owned by `65532:65532`:

```console
sudo install -m 0600 -o 65532 -g 65532 /path/to/prepared-secret /srv/cvebeacon/secrets/hook-secret
```

Repeat for each named secret; do not use a wildcard, because a normal shell
cannot list the `0700` directory. CVEBeacon rejects group- or other-readable
secret files, including `sources.nvd_api_key_file`.

Load the command once in your shell, again as a function:

```console
dc() { sudo docker compose -f /srv/cvebeacon/compose.yml "$@"; }
```

### First day

Set `initial` and, for `backfill`, `backfill_days` in
`/srv/cvebeacon/cvebeacon.toml`, then:

```console
dc --profile watch run --rm watch
```

The service command is `--config /config/cvebeacon.toml watch run`, so this
syncs, evaluates the initial window, closes initialization and sends the initial
summary. For a `full` first sync, override with:
`dc --profile watch run --rm watch --config /config/cvebeacon.toml watch run --yes`.
Test one channel:

```console
dc --profile watch run --rm watch --config /config/cvebeacon.toml watch notify test soc-webhook
```

### Schedule it

The image contains no scheduler. Use host cron or a systemd timer, with one lock
and `-T` (no TTY). Put the watch-only line in root's crontab
(`sudo crontab -e`), or in an account with Docker access that owns the lock path:

```cron
0 7,19 * * * /usr/bin/flock -n /srv/cvebeacon/cvebeacon.lock /usr/bin/docker compose -f /srv/cvebeacon/compose.yml --profile watch run -T --rm watch
```

With an inventory, replace the final `--profile watch run -T --rm watch` with
`--profile run run -T --rm run`. NVD asks automated clients not to request
modified data more often than every two hours; `0 */4 * * *` is also valid.

A systemd timer is equivalent. Save each unit under its own path:

```ini
# /etc/systemd/system/cvebeacon-container.service
[Unit]
Description=CVEBeacon container run
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/docker compose -f /srv/cvebeacon/compose.yml --profile watch run -T --rm watch
```

```ini
# /etc/systemd/system/cvebeacon-container.timer
[Unit]
Description=Run CVEBeacon container on a schedule
[Timer]
Unit=cvebeacon-container.service
OnCalendar=*-*-* 07,19:00:00
Persistent=true
[Install]
WantedBy=timers.target
```

```console
sudo systemctl daemon-reload
sudo systemctl enable --now cvebeacon-container.timer
```

Docker access is root-equivalent; restrict the account that runs the schedule.

### Upgrade

Stop the scheduler and wait for a running container to finish, then back up
state and rebuild from the checkout:

```console
sudo systemctl stop cvebeacon-container.timer
sudo cp -a /srv/cvebeacon/state /srv/cvebeacon/state-backup-$(date +%F-%H%M)
sudo git -C /opt/cvebeacon pull --ff-only                 # root-owned checkout
sudo -u cvebeacon git -C /opt/cvebeacon pull --ff-only    # checkout from A
sudo docker build --target core --tag cvebeacon:local /opt/cvebeacon
sudo cp /opt/cvebeacon/deploy/container/compose.yml /srv/cvebeacon/compose.yml
sudo systemctl start cvebeacon-container.timer
```

Use the cron line instead of the timer commands when cron runs the schedule.
The next run uses the rebuilt image; never build from `/srv/cvebeacon/compose.yml`.

### Check the result

```console
dc --profile watch run --rm watch --config /config/cvebeacon.toml watch status
sudo systemctl list-timers cvebeacon-container.timer
```

`watch status` should report `/state/cvebeacon-watch.db`; exit codes match the native install.

## C. Resource notes

System requirements are still being measured; see [validation](VALIDATION.md) and the [README](../README.md).
