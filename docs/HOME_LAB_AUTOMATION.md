# Central VM Automation reference

Use a dedicated VM to receive Windows snapshots, pull an enrolled Linux host,
optionally acquire Kubernetes SBOMs, merge, scan and notify on an external
schedule. The [three-source lifecycle demo](AUTOMATION_LIFECYCLE.md) exercises
those data paths and their failures without touching a real system. The files
below are reference examples; nothing installs accounts, services or schedules.

## Accounts, storage and configuration

Build/install all three distributions in an administrator-owned virtual
environment such as `/opt/cvebeacon/venv`. Create separate unprivileged
`cvebeacon-ingest` and `cvebeacon-pipeline` accounts, and a dedicated read-only
sharing group `cvebeacon-stage`. Only the receiver handles upload tokens and TLS
keys. The pipeline handles its SSH/registry/provider credentials and owns Core
SQLite, reports and independent Automation state.

Provision the staging root and source directories in advance. A root-owned
parent prevents either writer from replacing another source directory:

| Path | Owner/group and mode | Purpose |
| --- | --- | --- |
| `/var/lib/cvebeacon/staging` | root / cvebeacon-stage, 2750 | Shared traversable root, neither account can create or replace source directories |
| `staging/windows-a` | cvebeacon-ingest / cvebeacon-stage, 2750 | Receiver writes; pipeline reads newly accepted generations |
| `staging/linux-a`, `staging/cluster-a` | cvebeacon-pipeline / cvebeacon-pipeline, 0700 | Pipeline collector/acquisition output; receiver has no access |
| `/var/lib/cvebeacon/pipeline` | cvebeacon-pipeline / cvebeacon-pipeline, 0700 | Merged pair, local Core database, reports, Automation state and optional observations |
| `/etc/cvebeacon/ingest-secrets` | root / cvebeacon-ingest, 0750 | Token/TLS key files owned by receiver, 0600 |
| `/etc/cvebeacon/pipeline-secrets` | root / cvebeacon-pipeline, 0750 | SSH key and integration secret files owned by pipeline, 0600 |

Use distinct accounts/groups, restrictive parent directories and corresponding
administrator ACLs on Windows. Secret-file permission validation requires
POSIX files themselves to have no group/other permissions; group-readable
0640 credentials are rejected. Public CA certificates and enrolled known-host
files can be readable, but must be administrator controlled and not writable
by an untrusted user. Never put credentials in TOML, CLI arguments or a crontab.

Start from the [Automation](../automation/deploy/homelab/automation.example.toml),
[receiver](../automation/deploy/homelab/ingest.example.toml) and
[Core](../automation/deploy/homelab/core.example.toml) examples. Replace the
illustrative host and paths; replace `reader_gid = 12345` with the actual
provisioned sharing-group ID. Both service accounts must belong to that group.
The receiver may write only `windows-a`; the pipeline never gets its token/key
files. Accepted generations/pointer get group-read permissions before pointer
publication. Historical files are not migrated by an idempotent upload.

The Automation and Core inventory paths must identify the same JSON file.
Use SQLite on local persistent storage, keep the database and all WAL/SHM
sidecars together, and never put it on an unreviewed network filesystem.
Core vulnerability lookups still require their normal public egress. Its child
receives a sanitized environment with no integration credentials by default.
The VM runner and its trusted child share an OS account, so this is not a hard
filesystem sandbox between collection and Core. Use the separate
[Kubernetes stages](AUTOMATION_KUBERNETES.md) when that stronger boundary is needed.

## Collection and transport

Windows uses the frozen local collector plus `cvebeacon-auto ingest push` with
its own upload credential and a verified HTTPS receiver endpoint. Schedule
local collection before pushing, and retain the exact inventory/manifest pair.
See [remote collection](REMOTE_COLLECTION.md) for Windows examples and the
disabled WinRM status. Do not refresh old timestamps to disguise stale data.

Linux uses the strict SSH collector: enroll the host key out of band, select an
explicit key and a least-privilege read account, and install Python3 plus the
selected package-query backend on that host. The remote probe is transient and
read-only. The example Ubuntu package namespace is an administrator assertion;
review it against the actual distribution before enabling it. Do not accept a
new key automatically or use root merely to simplify setup.

For Kubernetes, refresh a frozen observation-only snapshot with namespace
Pod-list RBAC before the pipeline. Registry acquisition has its own HTTPS
allowlist and bearer credential; it does not use an API token. Enable the
commented source only after supplying eligible SBOM artifacts for exact running
platform digests. Missing required SBOMs stop the scan. The
[Kubernetes reference](AUTOMATION_KUBERNETES.md) provides the complete ordered
observer/acquirer/scanner/notifier sequence instead of a second VM schedule.

The receiver example binds loopback behind an explicitly trusted HTTPS proxy.
Configure the proxy's certificate, request-size/deadline/rate limits and exact
`/v1/snapshots` route; preserve Authorization and source headers, ignore
forwarded identity claims and block direct remote access to the backend port.
For direct TLS, remove `proxy_https`, configure receiver certificate/key and
bind only the intended interface. Use a high port and firewall its ingress;
push always verifies the certificate and hostname. See [ingestion](INGESTION.md).

## One schedule and observable failures

Review the [receiver service](../automation/deploy/schedulers/cvebeacon-ingest.service),
[one-shot pipeline service](../automation/deploy/schedulers/cvebeacon-pipeline.service)
and [15-minute timer](../automation/deploy/schedulers/cvebeacon-pipeline.timer).
They use separate accounts, private temp space, no capabilities, read-only
system/home access and narrowly writable source/state directories. All named
paths must exist before use. Run `systemd-analyze verify` on your edited files;
then install/enable them only through your own approved administration process.
They are not applied by this repository or its acceptance tools.

The timer adds up to60seconds of random delay and catches missed calendar
activation once. systemd does not start a second instance of an active service;
Automation additionally locks its state, merged inventory and Core database.
Exit75 reports contention, 2 a stopped/failed pipeline, 4 incomplete Core
coverage, and 5 completed scanning with optional-operation degradation. The
service deliberately treats4 as a non-success exit, keeping the coverage issue
visible. Review `status --json`, journal output and Core source/coverage health.

Alternatively use the [dedicated-user cron example](../automation/deploy/schedulers/cron.example)
or [PowerShell task action](../automation/deploy/schedulers/run-pipeline.ps1).
Choose one scheduler. For Task Scheduler, configure an unprivileged dedicated
account, absolute executable/script/configuration paths, a15-minute trigger,
"Do not start a new instance", a bounded maximum execution time and run whether
the account is logged on. Store login credentials through the OS task mechanism;
do not put them or integration tokens in the action. Use your normal signed
script policy. The action preserves the exact CLI exit code. No task is
registered by the script.

Opt-in operational notifications cover heartbeat/digest, failure/recovery and
discovery aggregates. A healthy pipeline message is not a no-vulnerability
claim. Provider outages retain retry/ambiguity state; required source failures
preserve the prior merged pair and Core history. Monitor scheduling and health
independently too: a machine that never starts cannot send its own failure alert.

## Backup, retention and upgrades

Back up source generation directories, atomic pointers and registry evidence
together; preserve `accepted_at` and replay state. Back up the merged pair,
Automation health/locks metadata, notification ledger and Core database/reports.
Use SQLite's online backup API or quiesce the owning processes and preserve
WAL/SHM files consistently; copying only a live main DB file can omit committed
events. Keep credentials in a separate encrypted backup with restricted restore
access. Never restore a delivery ledger alone over a newer Core database without
reviewing cursor/event identity and potential replay consequences.

Stop schedules during a planned rollback, keep versioned copies of configuration,
packages and all state, and restore one coherent checkpoint. Do not edit raw
source generations or reset the receiver pointer to bypass freshness/replay.
An abrupt crash between merged inventory and manifest replacement is hash-fail-
closed; the next successful pipeline rebuilds it from retained accepted sources.
No automatic historical evidence deletion or ledger reset is implemented.

The services log safe summaries to journald. Configure bounded journal retention
under your administrator policy. The cron alternative needs explicit size/time
rotation of `cron.log`, with0700 directory/0600 files and appropriate writer
ownership; keep old logs as required. Windows task history and event logs need a
corresponding retention policy. Inventory/report/registry evidence may contain
internal labels even when logs do not contain secrets. Review storage growth and
rotate/retain archives only through an explicit administrator operation.

Before an upgrade, keep the previous wheel/config/state backup, run the offline
suite and disposable native gates, verify schema support, then perform a manual
one-shot run and examine health. Do not combine this optional pipeline with an
independent Core schedule writing the same DB; only cooperating Automation
commands hold its shared resource locks.
