# Central monitoring VM

A central VM can stage inventory snapshots, validate and merge them, run
CVEBeacon, and retain local SQLite state and reports. Each optional collector
runs once on its own host. The core continues to work with ordinary supplied
inventory and needs no collector or remote administration credentials.

```text
Linux A ── local collection ── snapshot + manifest ──┐
Linux B ── local collection ── snapshot + manifest ──┼─ secure transfer
Windows ── local collection ── snapshot + manifest ──┘
    → private staging on central VM
    → validate freshness/completeness → merge → core scan
    → local SQLite history and reports → optional notifications/dashboard
```

Choose an existing transfer mechanism such as restricted SCP/SFTP, a secured
share, or existing orchestration. This toolkit has no upload listener or remote
SSH/WinRM collection service. The hosts initiate or receive transfers according
to the administrator's policy; transfer credentials stay outside core config.
Use source aliases such as `linux-a`, `linux-b`, and `windows-a`, with one stable,
unique alias per host. An alias is not an authentication mechanism.

## Collection and transfer

Install the core and optional companion on hosts where collection is wanted.
Run the [local collector](HOST_COLLECTORS.md) under an ordinary account:

```console
cvebeacon-ext collect linux --source-id linux-a --output linux-a.json
cvebeacon-ext collect linux --source-id linux-b --output linux-b.json
cvebeacon-ext collect windows --source-id windows-a --output windows-a.json
```

Run only the command for the relevant host. Preserve collector exit codes.
Transfer the JSON inventory and its `.manifest.json` together into a new private
staging directory; include `.review.json` for operator review. Publish a staging
batch for consumption only when both authoritative files have arrived. A hash
mismatch during a transfer is a failure, not permission to scan the old data.
The manifest hash detects mismatched bytes, not an untrusted sender: restrict
who can write each source's staging area and authenticate the transfer.

Default Linux collection does not assume every installed package belongs to the
OS vendor. Those package observations remain in review. Use
`--package-namespace` only where the package set's origin has been established;
do not apply one vendor label to a mixed-origin host. Curated inventory or supplied
[SBOMs](SBOM.md) can provide individual explicit identities. Windows publisher,
display name and version remain generic observations, not guessed PURLs.
Partial snapshots need a deliberate `--allow-partial` policy at each consumer.
The examples below use strict completeness by default.

## A scheduled central pipeline

Keep incoming batches, selected inventory, SQLite state, and reports in separate
administrator-controlled directories. Give the scanning account read access to
staged sources and write access only to its inventory output, state and reports.
Keep the database on local storage suitable for SQLite WAL. Do not put one live
SQLite database on a network share or use independent multi-writer containers.

Configure `inventory.path` to the exact merged path used below. Configure
`state.database` and the report directory in the normal core configuration.
Use one external scheduler and one exclusive job lock around the entire
merge/validate/scan pipeline, including any manual invocation. Serialize source
batch promotion as well; the per-output writer lock does not lock a whole scan.
Do not independently schedule the core scan against whichever inventory happens
to remain after a failed collection.

For a selected, complete batch, the command sequence is:

```sh
set -eu
cvebeacon-ext merge \
  /srv/cvebeacon/staging/batch/linux-a.json \
  /srv/cvebeacon/staging/batch/linux-b.json \
  /srv/cvebeacon/staging/batch/windows-a.json \
  --expected-source linux-a --expected-source linux-b --expected-source windows-a \
  --max-age-seconds 3600 --source-id central \
  --output /srv/cvebeacon/inventory/current.json
cvebeacon-ext validate /srv/cvebeacon/inventory/current.json --max-age-seconds 3600
cvebeacon --config /etc/cvebeacon/cvebeacon.toml inventory validate
cvebeacon --config /etc/cvebeacon/cvebeacon.toml scan --report json
```

The example assumes the external job lock is already held and directories already
exist. Substitute administrator-selected paths; no command here installs a
schedule or changes permissions. A stale/missing source, bad hash, partial source
without opt-in, conflicting identity, or validation failure stops before scanning.
Monitor scan exit codes too: incomplete vulnerability coverage returns a warning
exit status and must not be treated as proof that the hosts are safe. The core
does not read extension manifests by itself. See the [exchange contract](EXTENSIONS.md)
and [scheduling guide](SCHEDULING.md).

Merging preserves the oldest included observation time. Re-merging or copying
an old snapshot cannot make it fresh. A collector failure leaves its previous
inventory/manifest aging; do not replace it with an invented empty success.
Keep required sources configured even if one file was forgotten. An explicitly
partial run records omissions and continues to require consumer opt-in.

An optional dashboard belongs to the core's existing local deployment model.
Keep its default loopback binding; use configured authentication and HTTPS for
remote access as described in [dashboard security](DASHBOARD.md). Keep collector
transfer access separate from dashboard access. Optional notifications may send
configured inventory labels; review their recipients before enabling them.

## Offline three-host demonstration

From a checkout with the core and companion installed:

```console
python tools/home_lab_demo.py --output demo-home-lab-v1
```

The destination must not already exist. Use a new directory for another run;
the tool never deletes or overwrites earlier demonstrations. It supplies
fabricated dpkg, RPM and Windows observation data to the real collector
normalizers. It never calls native host collection or reads the owner's package
database, registry, credentials, or operational inventory. Network operations
are blocked for the whole single-threaded demonstration. No schedule, transfer,
dashboard listener, or notification is started.

The demonstration uses the real snapshot writer, freshness-aware merger, core
inventory loader, query engine, state store, and JSON/XLSX report writers:

| Round | Inventory and verification |
| --- | --- |
| Initial | Two synthetic Linux hosts and one Windows host; ten total assets |
| Changed | One Linux package upgrades with the same asset ID, one disappears, one is added, eight assets are unchanged |
| Failure gates | Incomplete package observation, stale required source and missing source fail without refreshing prior authoritative snapshots; no scan runs for these failures |
| Repeat | Recollection matches the changed inventory bytes exactly; the third core scan reopens the same persistent database |

Artifacts include each round's source snapshots/manifests/reviews and merged
inventory, `state/demo.db`, three JSON reports, `reports/repeat.xlsx`, a deliberately
stale fixture, and `summary.json`. The scenario, asset IDs and summary are
deterministic. Publication times, scan timestamps and generated run IDs naturally
vary. The synthetic namespace assertions are properties of the fabricated test
data; they do not verify package origin on a real host.

All public vulnerability sources are deliberately disabled. Every asset remains
`coverage_unknown`, there are zero findings, events and deliveries, and the core
records each of the three runs as `failed` because coverage is incomplete. The
demo exits successfully only when those expected safeguards and lifecycle checks
pass. Its success means orchestration worked, not that a vulnerability assessment
succeeded. Qualified DEB/RPM identities also remain outside the current core's
exact public lookup coverage even when sources are enabled.

## Removal and history

The merged inventory and each new scan contain only the latest collected rows.
A removed package remains in the earlier run's stored `scan_assets`; an upgraded
package has its old version in the earlier scan and new version under the same
asset ID in later scans. The demonstration verifies thirty stored asset
observations across three runs without rewriting historical rows.

Inventory removal does not create a vulnerability finding, alert, or synthetic
resolution. Core `current_findings` and event history are not garbage-collected
when an asset disappears. In a real deployment, a previously observed finding
may remain visible with its historical last-seen time until authoritative later
evidence changes it. This offline demonstration starts with no findings, so it
does not claim to test live advisory resolution or delivery. Use the current
inventory and scan history to distinguish absence from assessed remediation.
