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

First install a release containing these updater commands manually. The old
single-venv path must be `/opt/cvebeacon/.venv`, installed normally rather than
editable. Preserve all state under `/var/lib/cvebeacon`, including state in
subdirectories, and keep the runtime config directly there. Every writer of
these directories must be trusted with the stored data.

Remove any existing cron schedule before enabling systemd timers. The updater
coordinates systemd units and the shared run locks; it does not manage cron or
external schedulers. Add every installed monitoring timer/service to `units` in
the administrator policy. Persistent external data writers must be stopped
before invoking updates.

Make the code tree administrator-owned and non-writable by the service account.
Do this only after reviewing the existing installation; ownership changes do
not establish the provenance of previously writable code.

```console
sudo chown -R root:root /opt/cvebeacon
sudo chmod -R go-w /opt/cvebeacon
sudo install -d -m 0755 /etc/cvebeacon
sudo install -m 0600 deploy/systemd/update-policy.example /etc/cvebeacon/update.toml
```

Review that policy, set `enabled = true`, and pin the signing key (see below).
Then run:

```console
sudo /opt/cvebeacon/.venv/bin/cvebeacon update adopt
```

Adoption creates `releases/VERSION/.venv` pointing to the original venv and
atomically creates `current`. Keeping the original venv in place preserves its
absolute script shebangs. Do not delete it while that release is used or needed
for rollback. Newly installed releases get their own real venv directories.

Use the reference units in `deploy/systemd/`: their executable path is
`/opt/cvebeacon/current/.venv/bin/cvebeacon`. Choose `watch run` instead of `run`
in the monitoring unit for watch-only deployments. Install the units locally,
reload systemd and restart the dashboard once. No database migration or monitor
interruption happens during adoption itself. The updater never installs units
or enables schedules automatically.

After copying the reviewed units to `/etc/systemd/system`, reload systemd and
explicitly enable the dashboard unit to start at boot. Enable
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
requests are consumed and refused to prevent repeated path activation.

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

The verified wheelhouse installs offline into `releases/VERSION/.venv`, retaining
the optional extensions/automation distributions already present. The new
executable migrates state as the service account. The updater atomically replaces
`current`, restarts previously enabled timers and the dashboard, runs `doctor`
and probes loopback `/healthz`. A migration, installation or health failure
switches back, restores the snapshot (also removes newly created databases),
restarts and records failure. A second concurrent updater is refused.

For repeatable local acceptance, prepare a binary dependency wheelhouse and run
`.venv/bin/python tools/updater_smoke.py --wheelhouse /path/to/wheelhouse`.
It builds three local versions, generates a scratch signing key, serves a fake
release API on loopback, adopts a temporary prefix, applies an update and forces
a later failure to verify rollback. Only the root-ownership guard is relaxed for
this rootless scratch check; no systemd unit is started or installed and no
external release endpoint is contacted.

`/opt/cvebeacon/update-audit.jsonl` is the persistent administrator audit;
`update-journal.json` contains the current transaction steps and
`update-result.json` its result. The dashboard status file is advisory because
the service account owns its directory. Backups are private, retain the most
recent seven snapshots by default, and include password hashes. The policy's
`retention` overrides that count. Retained venvs are not deleted automatically.
An update to an existing release directory is refused; inspect a failed staging
directory before removing it locally and retrying.

If automatic rollback fails, writers remain stopped where possible and the
result says `rollback-failed`. Recover locally from the recorded snapshot and
old release. After power loss or forced process termination, inspect the journal
and finish restoration before restarting writers; ordinary process exceptions
are handled automatically. For a deliberate later rollback, stop writers, use
the matching snapshot and previous venv together, restore state as the service
account, atomically replace `current`, and restart. Do not switch code alone
across a schema change.
