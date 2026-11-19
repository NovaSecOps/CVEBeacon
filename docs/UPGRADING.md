# Upgrading CVEBeacon

Old configuration files remain valid. The optional `[update]` section defaults
to disabled. Database migrations run locally and preserve existing records.
Back up before upgrading; do not run an older executable against newer schemas.

## Supported updater installations

Applying updates is supported on native Linux systemd installations with
administrator-owned code, a separate service-owned data directory, and a
running loopback dashboard. Releases contain a signed binary wheelhouse for
CPython 3.11–3.14 on Linux x86_64 and aarch64 (manylinux). Other Python versions,
musl systems and missing binary dependencies fail closed during offline install.
The old installation is restored on failure. No source builds are allowed.

Containers, Kubernetes, the Windows executable and Windows source installations
are check-only. Upgrade their images or native files using [deployment](DEPLOY.md),
[containers](CONTAINERS.md), [Kubernetes](KUBERNETES.md) and [packaging](PACKAGING.md).
Never run the privileged updater inside a container.

## Manual upgrades

1. Disable the scheduler you actually use. Remove a managed cron schedule with
   `cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml schedule remove --yes`,
   or stop the systemd timer. Wait for running work to finish; do not terminate
   a sync. Stop the dashboard and other data writers after work finishes.
2. Use SQLite's online backup for **each** state database, including watch,
   account, monitoring, dashboard job and automation ledgers. Keep backups and
   configuration copies private. SQLite files may have live WAL contents: a
   simple file copy is insufficient. Record all paths and ownership.
3. Obtain the release from the configured GitHub repository. Verify
   `SHA256SUMS.sig` against an independently pinned public key, then verify
   every artifact against `SHA256SUMS`:

   ```console
   ssh-keygen -Y verify -f /etc/cvebeacon/release-allowed-signers \
     -I cvebeacon-release -n cvebeacon-release \
     -s SHA256SUMS.sig < SHA256SUMS
   sha256sum --check SHA256SUMS
   ```

4. Create a fresh venv and install the verified wheels with
   `python -m pip --isolated install --no-index --only-binary=:all: --find-links /path/to/verified-wheels cvebeacon==VERSION`.
   Include `cvebeacon-extensions==VERSION` and `cvebeacon-automation==VERSION`
   when those distributions were installed before. No PyPI or git pull is part
   of the updater. Never mix unverified files into the wheel directory.
5. As the service account, run the new `cvebeacon --config CONFIG migrate` and
   `doctor --allow-watch-only --local-state`. These commands migrate and integrity-check local databases without
   contacting sources; `doctor` also validates an inventory when configured.
6. Select the new installation, restart the dashboard and re-enable the
   scheduler. Check `doctor` and the loopback `/healthz` endpoint. If validation
   fails, stop writers, restore **all** database and config backups with their
   original service ownership, and restart the previous executable.

## Adopt an existing single-venv install

First bootstrap a **fresh administrator-owned venv from verified release wheels**,
using the manual procedure above and an independently authenticated public key.
Never invoke a privileged updater from a potentially compromised service-writable
venv. Changing ownership is not proof of provenance: after any possible service
compromise, replace the code and venv from verified artifacts before adoption.
Do not carry editable installs, unverified `.pth` files or an unverified packaged
signer pin into the bootstrap. The old single-venv path must be `/opt/cvebeacon/.venv`, installed normally rather than
editable. Preserve all state under `/var/lib/cvebeacon`, including state in
subdirectories, and keep the runtime config directly there. Every writer of
these directories must be trusted with the stored data.

Remove any existing cron schedule before enabling systemd timers. The updater
refuses a remaining service-account managed crontab and coordinates systemd
units and the shared run locks; it does not rewrite cron or external schedules. Add every installed monitoring timer/service to `units` in
the administrator policy. Persistent external data writers must be stopped
before invoking updates.

Use the service account's **primary** group for the fresh bootstrap code tree. Its
layout below is root ownership, service-group ownership, `0750` directories,
`0640` non-executable files and `0750` executable files. This allows the service
to read/traverse/execute, while denying it code writes. Supplementary groups are
cleared by the updater and must not be needed for access.

Apply these commands only to the fresh code tree **before** adoption, not to an
already running versioned prefix containing service-owned snapshots:

```console
sudo chown -hR root:cvebeacon /opt/cvebeacon
sudo find -P /opt/cvebeacon -type d -exec chmod 0750 {} +
sudo find -P /opt/cvebeacon -type f ! -perm /111 -exec chmod 0640 {} +
sudo find -P /opt/cvebeacon -type f -perm /111 -exec chmod 0750 {} +
sudo install -d -m 0755 /etc/cvebeacon
sudo install -m 0600 deploy/systemd/update-policy.example /etc/cvebeacon/update.toml
```

Keep runtime config readable by the service (`0600` service-owned, or `0640`
owned by root and the service primary group). A root-owned `0600` systemd
environment file can remain private in the data directory: state discovery
skips unreadable unrelated files. It does not loosen their permissions. Adoption
and apply execute a read/execute/config preflight under the actual service UID,
primary GID and no supplementary groups before changing layout or stopping units.
They also create/remove a temporary file in each data/lock directory and probe
the config and run locks, so inaccessible storage is refused before quiescence.
Inventory inspection also runs without root privileges.

Review that policy, set `enabled = true`, and pin the signing key (see below).
Then run:

```console
sudo /opt/cvebeacon/.venv/bin/cvebeacon update adopt
```

Adoption creates `releases/VERSION/.venv` pointing to the original venv and
atomically creates `current`. Keeping the original venv in place preserves its
absolute script shebangs. Do not delete it while that release is used or needed
for rollback. Newly installed releases get their own real venv directories.
Generated `releases`, version and `transactions` directories are root-owned
`0755`, explicitly set regardless of the administrator's umask. New venvs use
root ownership and umask `022` (normally `0755` directories/executables and
`0644` non-executable files). The outer root:service `0750` prefix still limits
traversal to that group. Every generated layout directory is checked under
service credentials for read/traversal and denied write access; adoption also
executes through `current/.venv` before completing. No recursive permission or
ownership change is applied to existing snapshots.

Use the reference units in `deploy/systemd/`: their executable path is
`/opt/cvebeacon/current/.venv/bin/cvebeacon`. Choose `watch run` instead of `run`
in the monitoring unit for watch-only deployments. Install the units locally,
reload systemd and restart the dashboard once. No database migration or monitor
interruption happens during adoption itself. The updater never installs units
or enables schedules automatically.

After copying the reviewed units to `/etc/systemd/system`, reload systemd and
explicitly enable the dashboard unit to start at boot. Keep the reference
`ExecStartPre=... update guard` startup fence in every configured writer unit,
including additional automation/ingest units; the dashboard uses `--role serve`.
Keep `StartLimitIntervalSec=0` in fenced units so boot-time refusals cannot
temporarily prevent the updater's recovery restart.
Manual Core invocations enforce the same fence. Enable
`cvebeacon-update.path` only when requests should be processed, and the
monitoring timer only when its schedule is wanted.

## Enable checking and applying

The release key placeholder deliberately trusts **no** key. Obtain the public
key through an authenticated channel and compare its fingerprint independently.
The packaged `release-allowed-signers` is the default, or set `signers` in the
administrator policy to a root-owned override with this format:

```text
cvebeacon-release namespaces="cvebeacon-release" ssh-ed25519 PUBLIC_KEY
```

Keep `/etc/cvebeacon/update.toml`, its ancestors, the code tree and the override
owned by root without group/other write access. The runtime config can remain
service-owned for the dashboard editor. It cannot select privileged paths,
commands, units or signing keys. The policy's repository and pre-release choice
are authoritative when applying; match them to the optional runtime settings:

```toml
[update]
enabled = true
repository = "NovaSecOps/CVEBeacon"
daily = false
allow_prereleases = false
```

Check manually:

```console
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml update check
sudo /opt/cvebeacon/current/.venv/bin/cvebeacon update apply
sudo /opt/cvebeacon/current/.venv/bin/cvebeacon update apply --version VERSION
```

A check makes one bounded, anonymous HTTPS request to the GitHub releases API;
it sends no token, inventory, configuration, user, host or local paths. Checking
lists at most 30 recent releases. The administrator can select an explicit
version if it is outside that window. Drafts, unsigned releases, downgrades and
unapproved pre-releases are refused. Checks show an advertised candidate;
authenticity is established during apply, before stopping any service.

Optional daily checks use `update check --daily`: this exits without network
access unless both `enabled` and `daily` are true, and skips checks within 24
hours of the last successful check. Schedule that command as the service user
if wanted. Checking and applying are never scheduled by default.

The dashboard **Updates** page is visible with `view` permission. Only an
administrator account can check or request an update. Release notes are escaped
plain text. **Update now** writes only a small version/user/time request into
the data directory and records the request in account audit. It never runs pip
or writes code. Install `cvebeacon-update.path` and its one-shot service, and
explicitly enable the path unit to process requests. The privileged process
ignores the supplied identity and time, consumes the request, checks the version
again, downloads the release again and verifies every artifact itself. Invalid
requests are atomically renamed to a unique claimed name before reading, so
consuming one request cannot unlink a later replacement. Invalid files are
consumed, while malformed directories remain quarantined under their claimed
name. A request arriving during a manual apply is consumed with an explicit
`busy` audit/status result and can be submitted again. The request service exits
cleanly for refusals and has no start-rate limit; contention cannot disable the
path unit. PathExists is checked again after a triggered service exits.

## Transaction and rollback

The updater takes a separate exclusive update lock. After signature and checksum
verification it stops configured timers, waits for current oneshot services and
run locks without killing syncs, then stops the dashboard. SQLite's online
backup captures every database under the data directory, including WAL contents,
and the config. Symlinks and linked/non-regular data files are refused. All core
state paths must stay inside that directory. The snapshot helper runs as the
service account, not root; backups live under the protected code prefix.
The configuration writer lock stays held while discovering and waiting for run
locks, so the dashboard cannot move storage paths during that wait. Dashboard
children finish before the dashboard unit is stopped.
The updater's `doctor` uses `--local-state --allow-watch-only`: it checks the
configuration, inventory when present, and local databases. Notification
environment variables are loaded by the restarted service units and are not
passed through the privileged updater. This health check sends no test alerts.

`dashboard_unit` explicitly names the persistent web unit and must be included
in `units`; it can have a custom name. Its ExecStart must use `current`. Health
requires that unit to be active, its MainPID to own the listening socket, and
`/healthz` to report that PID and the expected running package version. A stale
or unrelated listener cannot satisfy the probe. The endpoint caches the running
version at process startup rather than rereading a switched metadata path.
Listener ownership must match the probe's exact address family and address;
a wildcard bind is accepted only within that same address family.

The verified wheelhouse installs offline into `releases/VERSION/.venv`, retaining
the optional extensions/automation distributions already present. The existing
verified interpreter creates the new venv, preserving supported side-by-side
Python installations instead of selecting a possibly older system default. The
installed regular files, directories and the containing `releases` directory
are fsynced before migration; adoption also syncs its original code tree. The
new executable migrates state as the service account. The updater atomically replaces
`current`, restarts the dashboard, runs `doctor`
and probes loopback `/healthz`. Only after durable completion and releasing
resource locks does it resume previously active timers, allowing immediate
persistent-timer catch-up. A migration, installation or health failure
switches back, restores the snapshot (also removes newly created databases),
restarts and records failure. A second concurrent updater is refused.

For repeatable local acceptance, prepare a binary dependency wheelhouse and run
`.venv/bin/python tools/updater_smoke.py --wheelhouse /path/to/wheelhouse`.
It builds three local versions, generates a scratch signing key, serves a fake
release API on loopback, adopts a temporary prefix, applies an update and forces
an abrupt process exit between migration and switching, verifies blocked writers
and recovery, then forces a later health failure to verify rollback. Only the
administrator-owned path guard is relaxed for this rootless scratch check; no systemd unit is started or installed and no
external release endpoint is contacted.
For a separate real-credential check, run
`sudo .venv/bin/python tools/updater_permissions_smoke.py --wheelhouse /path/to/wheelhouse`.
It tests adoption under administrator umasks `077` and `027`, all created
directory modes, generated-release read-only execution, cleared groups,
read-only data and private config refusal entirely in a disposable prefix. It does not create
accounts or inspect or install schedules.

Before stopping anything, the updater writes and fsyncs one active
`/opt/cvebeacon/update-journal.json` record with the old/new releases, snapshot
name, unit state and phase. Every subsequent phase is durable **before** its
state change. Snapshot databases, config, completion manifest and directory
entries are synced before migration is permitted. Audit and dashboard status
publication are best effort and cannot skip recovery.

An active record fences normal CLI and unit writer startup and dashboard writes.
Only the recorded version may start for migration or the updater's health
phase. A durable `complete` record permits ordinary writers only for the
verified selected version. A subsequent apply recovers the pending transaction first, without
checking another release or replacing the record. Explicit recovery is:

```console
sudo /opt/cvebeacon/current/.venv/bin/cvebeacon update recover
```

Restore is idempotent and has no generic command timeout; neither do backup,
local database verification and migration. It can be retried after interruption.
The restored config hash, every snapshot hash, SQLite integrity and logical
contents, absence of newly introduced databases, actual selected symlink, old
`doctor`, old dashboard version and listener ownership must pass before a
rollback is reported successful. Snapshot config bytes are checked before
replacing the live config, including a check of the copied temporary file;
recovery installs that config as service-owned `0600`. Timers restart only after
state and health verification, durable completion and resource-lock release.
If the journal or storage cannot be made durable, state restoration is still attempted
using the last durable record and writers remain fenced until recovery succeeds.
A completed-but-not-finalized record is finalized without restoring older data.

Verified completed records are copied and fsynced into
`/opt/cvebeacon/transactions/` while the active record remains. Only after timer
restart and durable archival is the active name removed and its parent synced.
A finalization failure retains a completed recovery entry and reports the
committed outcome with a warning; recovery retries without restoring old data.
Retention and advisory publication failures cannot change that outcome.
The active record is never replaced by a fresh
apply. An unrecognized legacy journal lacks recovery coordinates and is refused:
an administrator must verify code/state and retained snapshots before archiving
that legacy record. Do not delete an active record to bypass recovery.

`update-audit.jsonl` records events; `update-result.json` is a convenience mirror
of the authoritative completed transaction. The dashboard status is advisory
and uses the resolved **config directory**, as does the privileged request
consumer, regardless of where database subdirectories reside. The reference
path unit watches that config directory; adjust its path and the service's
`--config` together for a custom installation.
Check-only deployments with a read-only config mount fall back to the watch
database directory for advisory status. Checks still return release information
if neither advisory location can be written.

Backups are private, retain the most recent seven snapshots by default, and
include password hashes. The policy's `retention` overrides that count. A pending
transaction's snapshot is never pruned. Retained venvs are not deleted
automatically. A new apply refuses an existing staging release directory;
recover and inspect it before removing only that failed staging directory.
For a deliberate later rollback, stop writers and restore the matching snapshot
and code together; never select older code against newer schemas.
