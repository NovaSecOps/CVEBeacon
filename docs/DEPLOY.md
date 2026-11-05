# Deployment

One Linux VM or one Windows host, installed from a source checkout or with
Docker. Details are in the [setup guide](SETUP.md), [watch mode](WATCH.md), and
[scheduling](SCHEDULING.md).

## Storage trust

Every account that can write a state directory is trusted with the SQLite
databases stored there, including monitoring, watch and account data and their
`-wal`, `-shm` or journal sidecar files. The monitoring and watch databases are
created with the process umask, not owner-only, so another writer can read or
change them. The account database remains owner-only, but a directory writer can
still delete or replace it. Keep state directories writable only by the service
account and trusted administrators. A shared operation directory is acceptable
only when every writer is trusted. The dashboard's `dashboard-jobs/` history
directory is created and checked owner-only regardless of its parent.

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
sudo -u cvebeacon sh -c 'umask 077; install -m 600 /dev/null /var/lib/cvebeacon/users-backup.db; sqlite3 /var/lib/cvebeacon/cvebeacon-users.db ".backup /var/lib/cvebeacon/users-backup.db"'
sudo -u cvebeacon chmod 600 /var/lib/cvebeacon/users-backup.db
```

The account file holds password hashes and is created `0600` on POSIX. Account
backups need the same confidentiality as the live file: the `install -m 600`
step resets an existing destination before SQLite copies credential data into
it, and `chmod 600` is the final check. Verify with
`stat -c '%a %n' /var/lib/cvebeacon/users-backup.db` (expect `600`). Keep both
files inside the protected data directory.

If you copy the database, `-wal` and `-shm` files instead, do so only while
nothing runs. Then upgrade and restore the scheduler you removed:

```console
sudo -u cvebeacon git -C /opt/cvebeacon pull --ff-only
sudo -u cvebeacon /opt/cvebeacon/.venv/bin/python -m pip install /opt/cvebeacon
cb schedule install --times 07:00,19:00 --command watch --yes
# or: sudo systemctl start cvebeacon.timer
```

### Windows data-directory ACLs

The native Windows deployment keeps the configuration, state, watch database,
account file and backups under `%PROGRAMDATA%\CVEBeacon`. Grant only the account
that runs CVEBeacon and local administrators; remove inherited access from
ordinary users.

```powershell
$data = Join-Path $env:ProgramData "CVEBeacon"
New-Item -ItemType Directory -Path $data -Force | Out-Null
icacls $data /inheritance:r
icacls $data /grant:r "CVEBeaconSvc:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F"
icacls $data /remove:g "BUILTIN\Users" "NT AUTHORITY\Authenticated Users"
icacls $data
```

Replace `CVEBeaconSvc` with the actual service account (for example
`NT AUTHORITY\LocalService`). The final `icacls` command must show only that
account and administrators. Put the account file and account backups in this
directory; their protection is the directory ACL, because Windows does not use
the POSIX `0600` mode. See also
[watch identity](WATCH.md#identity-modes-and-accounts) and the
[scheduler guide](SCHEDULING.md).

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
`[watch]` and its sample channel disabled: enable both and set the webhook URL
environment variable or use `url_file`. Leave `[watch] database` unset. Do not
reuse a native wizard configuration, which sets that path beside the read-only
`/config`.

### Secrets

Prefer an untracked `/srv/cvebeacon/cvebeacon.env`, mode `0600`, with the
`*_env` names the configuration uses (for example `NVD_API_KEY`,
`CVEBEACON_HOOK_URL` and `CVEBEACON_HOOK_SECRET`). The `watch` and `run` services
load it when present; a missing file is fine. Secret file paths are relative to `/config`, so
`secrets/...` is `/config/secrets/...`. Install each prepared file directly,
mode `0600` owned by `65532:65532`:

```console
sudo install -m 0600 -o 65532 -g 65532 /path/to/prepared-secret /srv/cvebeacon/secrets/hook-secret
```

Repeat for each named secret; do not use a wildcard, because a normal shell
cannot list the `0700` directory. CVEBeacon rejects group- or other-readable
secret files, including `sources.nvd_api_key_file`. Existing files under
`/config/secrets` remain readable by the loader and are suitable for command-line
runs, but dashboard in-place rotation requires the referenced file to resolve
inside the account data directory (the directory containing the watch and
account databases; `/state` in this layout). Use an environment reference or
place a dashboard-managed secret in that protected data directory instead.

### Dashboard configuration editor

The container example runs the dashboard with a read-only root filesystem and
mounts `cvebeacon.toml` read-only. That is the hardened default, and the
configuration editor will show a read-only notice: sections can be inspected,
but saving and rollback are disabled. Keep this layout unless browser-based
editing is required.

To enable editing, give only the dashboard service a writable configuration
**directory** (not a single-file mount, because atomic replacement needs
directory write access). For example, keep the file at
`/srv/cvebeacon/config/cvebeacon.toml`, owned by `65532:65532`, and use:

```yaml
  dashboard:
    read_only: true
    volumes:
      - ./config:/config:rw
```

Mount the same directory read-only in the watch, report and scheduled services.
The dashboard still needs its normal writable `/state` and `/reports` mounts.
The configuration directory, its `.CONFIG_FILENAME.backups` directory and any
dashboard-managed secret files must be writable by the service account; keep
them owner-only and outside the checkout. After a save the dashboard reloads
its own configuration, but other services keep their old configuration until
restarted. Restart the watch and report services after changing settings they
consume. See the [dashboard guide](DASHBOARD.md#configuration-editor) for the
validation, backup and permission behavior.

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
computer name for the local account below (or use `$env:COMPUTERNAME`). For a
domain account, create it in Active Directory and use `DOMAIN\account` instead.
Never add the service account to Administrators.

```powershell
New-LocalUser svc-cvebeacon -Password (Read-Host -AsSecureString "Password") -PasswordNeverExpires
New-Item -ItemType Directory -Force C:\CVEBeacon\app, C:\CVEBeacon\data | Out-Null
icacls C:\CVEBeacon\app /grant "CVEHOST\svc-cvebeacon:(OI)(CI)M"
icacls C:\CVEBeacon\app /setowner "CVEHOST\svc-cvebeacon"
icacls C:\CVEBeacon\data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "CVEHOST\svc-cvebeacon:(OI)(CI)F"
```

`/inheritance:r` drops inherited permissions and `(OI)(CI)` applies the grants
to new files and subdirectories, including `data\secrets`. Run it before the
first secret is created; on an existing directory, add `/T` and review
unrelated explicit entries. `setowner` makes the service account the owner of
the checkout so Git accepts its own pulls; if ownership must stay with an
administrator, add a `safe.directory` entry for only `C:/CVEBeacon/app` for the
maintenance account, never disable Git's ownership checks globally. On
non-English Windows, use localized names or equivalent SIDs.

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

From an elevated administrator shell, register the task as the service account:

```powershell
function cb { & C:\CVEBeacon\app\.venv\Scripts\cvebeacon.exe --config C:\CVEBeacon\data\cvebeacon.toml @args }
cb schedule install --times '07:00,19:00' --command watch --run-logged-out --account CVEHOST\svc-cvebeacon --yes
cb schedule status
```

The command prompts for the service account password; Windows stores it in its
own credential store and CVEBeacon does not. The plan must show
`Runs as: CVEHOST\svc-cvebeacon (stored password, while logged off)` before
`--yes`. Changing the service account password later requires re-running this
install. For automation, `--password-stdin` requires `--yes` and an explicit
`--times` or `--every`, and reads one UTF-8 line from stdin instead of prompting.

Check Task Scheduler: General shows `CVEHOST\svc-cvebeacon` and "Run whether
user is logged on or not"; Triggers shows 07:00 and 19:00. The creator or an
administrator can change or remove the task. Then test it immediately:

```powershell
schtasks /Run /TN "CVEBeacon Monitor"
schtasks /Query /TN "CVEBeacon Monitor" /V /FO LIST
```

Read `Last Result` with the [exit codes](DEVELOPMENT.md#exit-codes). If the task
does not run, check "Log on as a batch job" in `secpol.msc` and any domain GPO.
A scheduled `watch run` needs an unattended first run: use `baseline` or
`backfill`, or run `cb watch sync --yes` once first.

S4U is not used: Windows refuses passwordless S4U for this setup (a standard
account cannot self-register it, and an administrator cannot register it for
another account), so the task uses the stored service-account password.

### Upgrade

Run the first command as the administrator who registered the task, and wait for
a running job to finish:

```powershell
schtasks /Change /TN "CVEBeacon Monitor" /DISABLE
```

Run the backup, pull and pip commands as the service account that owns
`C:\CVEBeacon\app`; do not run Git maintenance for that checkout as an
administrator:

```powershell
$Backup = "C:\CVEBeacon\data\backup-$(Get-Date -Format yyyyMMdd-HHmm)"
New-Item -ItemType Directory $Backup | Out-Null; Copy-Item C:\CVEBeacon\data\cvebeacon-watch.db* $Backup
git -C C:\CVEBeacon\app pull --ff-only
C:\CVEBeacon\app\.venv\Scripts\python.exe -m pip install C:\CVEBeacon\app
```

Then re-enable the task as the administrator:

```powershell
schtasks /Change /TN "CVEBeacon Monitor" /ENABLE
```

`watch status` always reports the database path; copy `-wal` and `-shm` only while the task is disabled.

### Docker Desktop or WSL 2 on Windows

Docker Desktop's Linux engine runs in the signed-in user's session, so a
logged-out task cannot use it; schedule it with an interactive task that runs
only while that user is signed in, and use native Windows or a Linux VM for
unattended service. The WSL 2 backend runs Section B's compose file as-is: use
`C:\CVEBeacon\docker` in place of `/srv/cvebeacon`, build `cvebeacon:local` from
the checkout as in B, and call `docker compose -f
C:\CVEBeacon\docker\compose.yml --profile watch run -T --rm watch` from Task
Scheduler. Windows bind mounts do not preserve Unix `0600`, so use
`cvebeacon.env` for secrets; file secrets need the WSL filesystem. Docker
Desktop has a free tier for smaller companies (under 250 employees and $10M
annual revenue); government entities are not eligible, and personal,
education and open-source use has separate terms. It is not supported on
Windows Server.

WSL 2 stops an idle distribution, and systemd in `/etc/wsl.conf` does not keep
it alive. Follow Section A inside the distribution, then use a recurring
Windows task calling `wsl.exe -d <distro> -u cvebeacon --
/opt/cvebeacon/.venv/bin/cvebeacon --config
/var/lib/cvebeacon/cvebeacon.toml run`; the task must run as the Windows account
that owns the distribution, because `-u` selects only the Linux user. WSL 2 is
supported on Server 2022/2025, not 2019, and needs nested virtualization when
Windows is itself a VM. On Windows Server, native Windows is simplest.

## D. Resource notes

Measured memory, disk, time and request figures are in
[System requirements](../README.md#system-requirements). Plan the first 120-day
or full-history load on a machine with free disk and a stable connection; full
history needs several syncs before EUVD is complete. Steady state after the
initial load is small.
