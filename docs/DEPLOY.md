# Deployment

One Linux VM, either from a source checkout or with Docker. Details are in the
[setup guide](SETUP.md), [watch mode](WATCH.md), and [scheduling](SCHEDULING.md).

## A. Linux VM, native install

### Prerequisites

- Python 3.11 or newer (`pyproject.toml` requires `>=3.11`), plus `git` and
  `venv`, and outbound HTTPS to the hosts in
  [network requirements](NETWORK_REQUIREMENTS.md).
- A dedicated unprivileged account and separate code and state directories.

```console
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

The wizard writes the configuration and any `secrets/` files beside it
(directory `0700`, files `0600` on POSIX). Relative paths resolve from there;
leave the schedule question for later.

Watch-only deployments keep `[watch] enabled = true`; `scan` and inventory
dashboard pages then need `[inventory] path`. For both, configure an inventory
and use `run`. The wizard writes the watch database beside the configuration.

Load the command once in your shell:

```console
CB='sudo -u cvebeacon /opt/cvebeacon/.venv/bin/cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml'
```

### First day

**Baseline (default).** The first run stores a silent baseline and sends
nothing; later runs alert on changes after that point. Run `$CB watch run`.

**Backfill N days.** Set `initial = "backfill"` and `backfill_days` (the wizard
offers both). Then:

```console
$CB watch sync
$CB watch evaluate --all --yes
$CB watch notify
```

`watch sync` downloads only. `watch evaluate --all --yes` evaluates stored CVEs
and marks first matches as initial; `watch notify` sends the one digest. One
`watch run` does all three. A `full` first sync prints an estimate; see
[initial modes](WATCH.md#initial-modes).

Check a channel:

```console
$CB watch notify test soc-email
```

`watch status` shows the database path, cursors, counts, and pending
deliveries; it creates an empty database when none exists.

### Schedule it

The built-in command writes one managed block to the service account's crontab:

```console
sudo -u cvebeacon /opt/cvebeacon/.venv/bin/cvebeacon \
  --config /var/lib/cvebeacon/cvebeacon.toml \
  schedule install --times 07:00,19:00 --command watch --yes
```

Use `--command both` with an inventory; see [native scheduling](SCHEDULING.md).
A systemd service and timer are an alternative, with an environment file:

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
$CB watch status
sudo systemctl list-timers cvebeacon.timer
```

Exit `0` means success, `1` cancelled, `2` validation or operational failure,
`3` notification delivery failure, and `4` uncertain coverage or degraded
sources. See [exit codes](DEVELOPMENT.md#exit-codes).

### Upgrade

Stop the timer and back up the SQLite files, including `-wal` and `-shm` (or
use `sqlite3 <db> ".backup <copy>"`). Then:

```console
sudo systemctl stop cvebeacon.timer
sudo -u cvebeacon git -C /opt/cvebeacon pull --ff-only
sudo -u cvebeacon /opt/cvebeacon/.venv/bin/python -m pip install /opt/cvebeacon
sudo systemctl start cvebeacon.timer
```

## B. Docker

The image is built locally; no image is published. Build from the checkout:

```console
docker compose -f deploy/container/compose.yml --profile watch build
```

### Prepare the runtime directory

```console
sudo install -d -m 0700 -o 65532 -g 65532 /srv/cvebeacon/state /srv/cvebeacon/reports /srv/cvebeacon/secrets
sudo install -d -m 0755 /srv/cvebeacon/inventory
sudo cp deploy/container/compose.yml /srv/cvebeacon/compose.yml
sudo cp deploy/container/cvebeacon.example.toml /srv/cvebeacon/cvebeacon.toml
```

The copied compose file keeps the reference build context: build from the
checkout, and scheduled runs reuse the local image. `run` and `scan` need
`/srv/cvebeacon/inventory`; `inventory.json` is a placeholder. The example
writes state and the watch database to `/state`; it keeps `[watch]` and its
sample channel disabled, so enable both and replace the webhook URL. Leave
`[watch] database` unset so it stays inside `/state`.

### Secrets

Prefer an untracked `/srv/cvebeacon/cvebeacon.env`, mode `0600`, with the
`*_env` names the configuration uses (for example `NVD_API_KEY` and
`CVEBEACON_HOOK_SECRET`). Compose loads it when present; a missing file is fine.

Secret file paths are relative to `/config`, so `secrets/...` is
`/config/secrets/...`. Give each file mode `0600` owned by `65532:65532`:

```console
sudo chown 65532:65532 /srv/cvebeacon/secrets/*
sudo chmod 0600 /srv/cvebeacon/secrets/*
```

CVEBeacon rejects group- or other-readable secret files, including
`sources.nvd_api_key_file`.

Load the command once in your shell:

```console
DC='sudo docker compose -f /srv/cvebeacon/compose.yml'
```

### First day

**Baseline:** `$DC --profile watch run --rm watch`.

**Backfill:** `docker compose run` replaces the service command, so repeat
`--config` and the full subcommand. Set `initial = "backfill"` and
`backfill_days` first.

```console
$DC --profile watch run --rm watch --config /config/cvebeacon.toml watch sync
$DC --profile watch run --rm watch --config /config/cvebeacon.toml watch evaluate --all --yes
$DC --profile watch run --rm watch --config /config/cvebeacon.toml watch notify
```

Test one channel:

```console
$DC --profile watch run --rm watch --config /config/cvebeacon.toml watch notify test soc-webhook
```

Use `--profile run` and the `run` service with an inventory.

### Schedule it

The image contains no scheduler. Use host cron or a systemd timer, with one lock
and `-T` (no TTY):

```cron
*/30 * * * * /usr/bin/flock -n /srv/cvebeacon/cvebeacon.lock /usr/bin/docker compose -f /srv/cvebeacon/compose.yml --profile run run -T --rm run
```

For watch-only deployments, replace `--profile run run` with
`--profile watch watch`. Reuse the timer unit from A with this service:

```ini
# /etc/systemd/system/cvebeacon-container.service
[Unit]
Description=CVEBeacon container run
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/docker compose -f /srv/cvebeacon/compose.yml --profile run run -T --rm run
```

Docker access is root-equivalent; restrict the account that runs the schedule.

### Check the result

```console
$DC --profile watch run --rm watch --config /config/cvebeacon.toml watch status
```

`watch status` should report `/state/cvebeacon-watch.db`. Exit codes match the
native install.

## C. Resource notes

System requirements are still being measured, so no sizing numbers are
published here. Check the tested platforms in [validation](VALIDATION.md) and
the overview in the [README](../README.md).
