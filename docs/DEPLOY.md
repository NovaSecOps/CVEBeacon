# Deployment

One Linux VM or one Windows host, installed from a source checkout or with
Docker. Details are in the [setup guide](SETUP.md), [watch mode](WATCH.md), and
[scheduling](SCHEDULING.md).

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

## C. Windows (native)

Windows 11 or Windows Server 2019 or newer, with Python 3.11 or newer from
python.org or `winget install Python.Python.3.12` on Windows 11 (Server:
python.org), Git for Windows, and outbound HTTPS to the [network requirements](NETWORK_REQUIREMENTS.md)
hosts. Use a dedicated local or domain account such as `svc-cvebeacon`; keep the
checkout and virtual environment in `C:\CVEBeacon\app`, and configuration,
state and secrets in `C:\CVEBeacon\data`.

### Prepare the account and directories

As an elevated administrator, create the account and directories, and grant the
service account "Log on as a batch job" in `secpol.msc` (Local Policies, User
Rights Assignment; a domain GPO can override it). Replace `CVEHOST` with the
computer or domain name, and never add the service account to Administrators.

```powershell
New-LocalUser svc-cvebeacon -Password (Read-Host -AsSecureString "Password") -PasswordNeverExpires
New-Item -ItemType Directory -Force C:\CVEBeacon\app, C:\CVEBeacon\data | Out-Null
icacls C:\CVEBeacon\app /grant "CVEHOST\svc-cvebeacon:(OI)(CI)M"
icacls C:\CVEBeacon\data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "CVEHOST\svc-cvebeacon:(OI)(CI)F"
```

`/inheritance:r` drops inherited permissions and `(OI)(CI)` applies the grants
to new files and subdirectories, including `data\secrets`. Run it before the
first secret is created; on an existing directory, add `/T` and review
unrelated explicit entries. On non-English Windows, use localized names or
equivalent SIDs.

### Install

Sign in as the service account, or run `runas /user:CVEHOST\svc-cvebeacon powershell`:

```powershell
git clone https://github.com/NovaSecOps/CVEBeacon.git C:\CVEBeacon\app
py -3.12 -m venv C:\CVEBeacon\app\.venv
C:\CVEBeacon\app\.venv\Scripts\python.exe -m pip install --upgrade "pip>=26.2"
C:\CVEBeacon\app\.venv\Scripts\python.exe -m pip install C:\CVEBeacon\app
C:\CVEBeacon\app\.venv\Scripts\cvebeacon.exe setup --config C:\CVEBeacon\data\cvebeacon.toml
```

The wizard writes `data\cvebeacon.toml` and secret files under `data\secrets`,
and prints an NTFS reminder; the POSIX mode check does not apply. Leave the
schedule question for later. Load `cb` in this shell; a new shell needs it again:

```powershell
function cb { & C:\CVEBeacon\app\.venv\Scripts\cvebeacon.exe --config C:\CVEBeacon\data\cvebeacon.toml @args }
```

For scheduled runs, use secret files in the ACL-restricted `data\secrets`; the
wizard writes them there. Use environment variables only for interactive runs
(`[Environment]::SetEnvironmentVariable('NVD_API_KEY', '<value>', 'User')` as
that account); a logged-out task's environment is not reliable for credentials.

### First day

Same as A: set `initial` and, for `backfill`, `backfill_days`, then `cb watch run`.
A baseline stores silently; `cb watch status` shows the database path, cursors,
counts and pending deliveries, and `cb watch notify test soc-email` checks a channel.

### Schedule it

Pick one registration flow. Both must show
`Runs as: CVEHOST\svc-cvebeacon (S4U, while logged off)` before `--yes`. S4U
stores no password: HTTPS works, Windows-authenticated shares do not.

**The service account registers its own task.** In the service account's shell
(`runas /user:CVEHOST\svc-cvebeacon powershell`), define `cb` there, then:

```powershell
cb schedule install --times '07:00,19:00' --command watch --run-logged-out --yes
cb schedule status
```

**An administrator registers for the service account.** From an elevated
administrator shell (define `cb` there too), name the account explicitly:

```powershell
cb schedule install --times '07:00,19:00' --command watch --run-logged-out --account CVEHOST\svc-cvebeacon --yes
cb schedule status
```

The creator or an administrator can later change or remove the task; if an
administrator created it, rerun `schedule remove` from that same context. Check
Task Scheduler: General shows `CVEHOST\svc-cvebeacon` and "Run whether user is
logged on or not"; Triggers shows 07:00 and 19:00. Then test it immediately:

```powershell
schtasks /Run /TN "CVEBeacon Monitor"
schtasks /Query /TN "CVEBeacon Monitor" /V /FO LIST
```

Read `Last Result` with the [exit codes](DEVELOPMENT.md#exit-codes). If the task
does not run, check "Log on as a batch job" in `secpol.msc` and any domain GPO.
A scheduled `watch run` needs an unattended first run: use `baseline` or
`backfill`, or run `cb watch sync --yes` once first.

### Upgrade

In the same account context that owns the task, disable it, wait for a running
job, back up the watch database, upgrade, and re-enable:

```powershell
schtasks /Change /TN "CVEBeacon Monitor" /DISABLE
$Backup = "C:\CVEBeacon\data\backup-$(Get-Date -Format yyyyMMdd-HHmm)"
New-Item -ItemType Directory $Backup | Out-Null; Copy-Item C:\CVEBeacon\data\cvebeacon-watch.db* $Backup
git -C C:\CVEBeacon\app pull --ff-only
C:\CVEBeacon\app\.venv\Scripts\python.exe -m pip install C:\CVEBeacon\app
schtasks /Change /TN "CVEBeacon Monitor" /ENABLE
```

`watch status` reports the database path when it is not the default; copy `-wal` and `-shm` only while the task is disabled.

### Docker Desktop or WSL 2 on Windows

Docker Desktop's Linux engine runs in the signed-in user's session, so a
logged-out or S4U task cannot use it; schedule it with an interactive task that
runs only while that user is signed in, and use native Windows or a Linux VM for
unattended service. The WSL 2 backend runs Section B's compose file as-is: use
`C:\CVEBeacon\docker` in place of `/srv/cvebeacon`, build `cvebeacon:local` from
the checkout as in B, and call `docker compose -f
C:\CVEBeacon\docker\compose.yml --profile watch run -T --rm watch` from Task
Scheduler. Windows bind mounts do not preserve Unix `0600`, so use
`cvebeacon.env` for secrets; file secrets need the WSL filesystem. Docker
Desktop has a free tier for smaller companies (under 250 employees and $10M
annual revenue) and is not supported on Windows Server.

WSL 2 stops an idle distribution, and systemd in `/etc/wsl.conf` does not keep
it alive. Follow Section A inside the distribution, then use a recurring
Windows task calling `wsl.exe -d <distro> -u cvebeacon --
/opt/cvebeacon/.venv/bin/cvebeacon --config
/var/lib/cvebeacon/cvebeacon.toml run`; the task must run as the Windows account
that owns the distribution, because `-u` selects only the Linux user. WSL 2 is
supported on Server 2022/2025, not 2019, and needs nested virtualization when
Windows is itself a VM. On Windows Server, native Windows is simplest.

## D. Resource notes

System requirements are still being measured; see [validation](VALIDATION.md) and the [README](../README.md).
