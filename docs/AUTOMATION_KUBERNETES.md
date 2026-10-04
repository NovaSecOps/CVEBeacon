# Automation v2 Kubernetes reference

The optional Automation reference adds registry acquisition and separate
notification delivery to the frozen Extensions observation boundary. It creates a
namespace-scoped Pod reader, three persistent claims and a suspended CronJob.
It does not alter the v1 deployment or grant cluster-wide access.

The four containers execute in order:

| Stage | Boundary and command | Credentials | Data access |
| --- | --- | --- | --- |
| `observe` init | Frozen Extensions `collect kubernetes --observations-only` | Explicit projected API token/CA | Observations `emptyDir` read/write; no persistent monitoring state |
| `acquire` init | Automation `collect cluster-v2` | Its registry bearer and registry CA | Observations read-only; source staging read/write; no Core database |
| `scan` init | Automation `run`, then consistent notifier snapshot | No API, registry or notifier credential | Source staging read-only; Core inventory/database/reports/runner state read/write |
| `notify` main | Automation `notify run` | Its optional provider credential | Core snapshot volume read-only; separate notification ledger read/write |

Service-account automount is disabled on both the account and Pod. Only `observe`
mounts the explicit projected token, CA and namespace files. The Role contains
exactly `pods/list` in `cvebeacon-v2-demo`, with no Secrets, ConfigMaps, watch, Pod get,
node or other-namespace permission. Pod-list API responses can include literal
environment values; the frozen collector immediately projects its bounded output
to reviewed observation fields. Those extra values are not serialized as inventory.

Registry and notifier values use separate Secret references in their own container
environments. They are not placed in ConfigMaps, images or the scanner environment.
`acquire` has no Core configuration mount: `collect` validates and stages one source
without reading a Core configuration, invoking a scan or resolving notification
credentials. The scanner consumes that same `cluster-v2` source as `kind = "upload"`;
it does not reacquire registry evidence.

All containers run as UID/GID 65532 with read-only root filesystems, all capabilities
dropped, privilege escalation disabled and RuntimeDefault seccomp. Each gets its
own bounded temporary volume. There are no host mounts, runtime sockets, privileged
containers or dashboard. Images use illustrative `:local` values until replaced
with images distributed through your trusted process.

## Registry attribution and failure policy

[acquire.example.toml](../automation/deploy/kubernetes/acquire.example.toml) contains
an administrator-configured HTTPS origin and repository allowlist. Replace them
with your registry and intended repositories. The registry adapter selects exact
reported **running platform-manifest digests**, fetches verified manifest bytes,
uses the reviewed OCI 1.1 Referrers subset, verifies the artifact subject and SBOM
blob digest/size, and delegates component identity to the frozen SBOM importer.
Authentication and hash integrity do not establish vendor attestation or package
completeness. See [registry acquisition](REGISTRY_SBOM.md) for the supported
subset and limitations.

The observer source ID, acquisition source ID and scanner upload source ID must
match. Observations remain low-trust input until acquisition yields a validated
snapshot. Missing, ambiguous, inaccessible or unusable required SBOM evidence stops
the acquisition init container; the scanner and notifier do not start. Existing
source generations, last good inventory and previous Core run history are retained.
Other acquisition failures follow the same fail-closed init-container boundary.

The strict reference sets `allow_partial = false` in both acquisition and scan
configuration. Every running container needing enrichment must have eligible
registry attribution, including the observation init container if it is observed
as running. Supply appropriate SBOMs/allowlists for those images or explicitly
accept partial inventory in **both** configurations after review. Omitted images
and components remain recorded as review/partial coverage; partial acceptance does
not establish that unknown packages are safe.

## Read-only notifier database

Core uses SQLite WAL. An SQLite `mode=ro` connection issues read-only SQL but can
create transient `-wal` and `-shm` sidecars in a writable database directory. A
strict read-only mount of a clean live WAL database is therefore not a reliable
notifier boundary by itself. `immutable=1` against live WAL can omit uncheckpointed
rows and is not used here.

The deployment-only [scan wrapper](../automation/deploy/kubernetes/scan.py) runs the
existing Automation CLI, then uses SQLite's backup API to create
`notification-core.db` beside the live `core.db`. It changes the journal mode of
the **copy** to DELETE, checks integrity and atomically publishes it. The live Core
rows and journal mode are unchanged. Run UUIDs, event IDs and schema 3 are preserved,
so the notification ledger can retain its stable delivery cursor and event keys.
The copy is published only after successful execution. Failure before publication
fails the init stage and preserves the previous copy; a directory-sync failure
after publication reports failure with the verified new copy already in place.
Backup is capped at 256 MiB and a 30-second SQLite processing budget, including
source schema lookup; filesystem sync can exceed that budget. The shared Core
resource lock remains held through atomic publication and directory sync.

The notifier's [Core configuration](../automation/deploy/kubernetes/core-notify.example.toml)
points at that copy on `/core-ro`, mounted read-only. Alert rendering still uses
Automation's bounded schema-3 reader, and accepted additional deliveries are stored
only on the separate notification claim. Core's Teams rows are not changed.
Copy publication and notification are distinct operations; a crash can defer new
alerts until a later successful schedule. Ambiguous provider outcomes still require
the documented intervention in [notification delivery](NOTIFICATION_EXTENSIONS.md).

## Preparing a deployment you administer

1. Build the frozen `extensions` Docker target and the separate `automation/Dockerfile`.
   Replace image references with your immutable image digests. This repository does
   not publish images or install a schedule on an owner cluster.
2. Edit [reference.yaml](../automation/deploy/kubernetes/reference.yaml), namespace
   references and the stable source ID together. Select an RWOP-capable CSI
   filesystem storage class for all three claims; verify UID/GID and `fsGroup` access.
3. Prepare the five TOML files and registry CA below. Set the registry origin,
   repository allowlist, authentication policy, freshness and partial policy.
   Configure Core's usual vulnerability sources and their egress policy in the
   scanner configuration. Core notification channels are disabled in this reference.
4. Keep the CronJob suspended while applying the edited namespace, RBAC, claims and
   CronJob. Create the ConfigMaps in the deliberate cluster/context you selected.
5. Provision registry/provider Secrets using your normal secret management process.
   The reference reads `bearer` from `cvebeacon-v2-registry` and the optional
   `matrix-token` from `cvebeacon-v2-notifier`. An authentication-free registry should
   omit the `bearer` option and associated environment reference deliberately.

Example non-secret configuration commands:

```bash
kubectl -n cvebeacon-v2-demo create configmap cvebeacon-v2-acquire \
  --from-file=acquire.toml=./acquire.toml
kubectl -n cvebeacon-v2-demo create configmap cvebeacon-v2-scan \
  --from-file=scan.toml=./scan.toml
kubectl -n cvebeacon-v2-demo create configmap cvebeacon-v2-notify \
  --from-file=notify.toml=./notify.toml
kubectl -n cvebeacon-v2-demo create configmap cvebeacon-v2-core-scan \
  --from-file=core.toml=./core-scan.toml
kubectl -n cvebeacon-v2-demo create configmap cvebeacon-v2-core-notify \
  --from-file=core.toml=./core-notify.toml
kubectl -n cvebeacon-v2-demo create configmap cvebeacon-v2-registry-ca \
  --from-file=ca.crt=./registry-ca.crt
kubectl -n cvebeacon-v2-demo create configmap cvebeacon-v2-scripts \
  --from-file=scan.py=automation/deploy/kubernetes/scan.py
```

TOML and script mounts use explicit `subPath` files, preserving ordinary file inputs
for the audited file checks. Those file contents do not update in an existing Pod;
a new Job receives current configuration. Keep credentials out of these files.
The optional notifier example has no channels and therefore sends nothing; configure
only provider destinations you intend to receive alerts. Add any further provider
Secret references only to the notifier container.

Run an initial manual Job while the CronJob is still suspended, inspect its stage
results and persistent health, then deliberately resume the schedule:

```bash
kubectl -n cvebeacon-v2-demo create job cvebeacon-v2-initial --from=cronjob/cvebeacon-v2
kubectl -n cvebeacon-v2-demo wait --for=condition=complete job/cvebeacon-v2-initial --timeout=600s
kubectl -n cvebeacon-v2-demo patch cronjob cvebeacon-v2 --type=merge -p '{"spec":{"suspend":false}}'
```

Core exit 4 records a completed scan with coverage warnings. The strict reference
keeps that nonzero result and stops the Job. If your execution policy explicitly
allows the notifier to continue after it, set the scanner wrapper's `args` to
`[--accept-coverage-warning]`. Automation then maps that process result to zero;
`/core-state/runner/health.json` retains `core_exit = 4` and `coverage_warning`.
Other failures remain nonzero. Successful container execution does not mean
vulnerability-free inventory or complete coverage.

The supported Automation scan persists results in Core SQLite. It does not request
Core's optional on-demand JSON/XLSX export; an empty reports directory does not mean
the scan failed. Use Core's supported export command separately when an export is
needed.

## Persistence and scheduling

The three claims hold immutable source generations/acquisition state, Core
inventory/database/reports/scanner health, and the independent notification ledger.
Use SQLite-safe backups and administrator-controlled local/CSI filesystem storage;
NFS/SMB/RWX storage is not a demonstrated WAL strategy. Preserve claims across image
and schedule changes. RWOP constrains a supported claim to one Pod; the reference
requires an appropriate CSI driver and sidecars. Its actual production failover,
backup and storage behavior require deployment-specific validation.

`concurrencyPolicy: Forbid` coordinates this CronJob's Jobs. It does not coordinate
manual Jobs or another CronJob. Automation uses OS locks and shared Core/inventory
resource locks for cooperating callers; nonblocking conflicts exit 75. The snapshot
wrapper also takes the shared Core resource lock. Every writer must follow the
appropriate locking contract. Scheduling has a 120-second start deadline, no retry
backoff and a 600-second active deadline. SIGTERM is translated by the scanner and
Automation entrypoints; Kubernetes can still force termination after the 20-second
grace period. Suspend future scheduling to stop recurrence; an active Job continues
until it completes or is explicitly stopped.

## Native acceptance and evidence limits

[automation-kubernetes.yml](../.github/workflows/automation-kubernetes.yml) builds both
needed images, installs checksum-verified kind/kubectl pins matching the frozen v1
workflow, and runs [kubernetes_acceptance.py](../automation/tools/kubernetes_acceptance.py).
The script creates a unique disposable kind cluster and private temporary kubeconfig,
uses its exact context on every kubectl call, and deletes only its generated cluster
with that explicit kubeconfig. It never selects an owner context or publishes images.

The native gate exercises actual projected-token CA-verified API listing and seven
HTTP 403 denials, process/volume credential separation, anonymous API denial in the
other stages, immutable source staging, two persisted scans, a genuine controller
scheduled Job, unknown coverage, unchanged Core delivery rows, lock exclusion, and
failed acquisition preserving prior inventory/run history. The scanner publishes
the backup and the notifier reads it through an actual read-only volume mount.
The anonymous API probes use a public API CA in a CI-only test ConfigMap to verify
TLS without a service-account token; that test mount is absent from the reference.
An additional explicitly labelled Matrix TEST uses the real HTTPS driver, a local
TLS service, synthetic bearer and a test-only CA; it sends no real provider message.

The TLS registry Pod is a **protocol simulator**. Its image subject is the raw,
digest-verified pinned public Python platform manifest, matching the node's actual
reported image ID. Its CycloneDX artifact/referrer is synthetic; it does not assert
real workload contents, vendor SBOM provenance or attestation. CI-only `hostAliases`
map `docker.io` to this simulator for acquisition; kind node image pulls retain
normal public resolution. Those aliases do not appear in the production reference.
The separate native registry gate uses pinned Zot v2.1.21 for positive Referrers
acceptance and pinned Distribution 3.1.2 for the unsupported-Referrers rejection.
The Kubernetes simulator does not replace those real implementation checks. The
safe CI artifact retains the result and public subject bytes, not
kubeconfigs, TLS private keys, Secret values, full Pod responses or raw credentials.

CI explicitly permits partial inventory for unmapped simulator/collector images,
disables external vulnerability feeds and accepts Core exit 4. kind substitutes its
local-path RWO claims for production RWOP, so that run establishes neither a CSI
RWOP guarantee nor failover/backup behavior. Offline reference/snapshot tests do not
establish runtime mount or API behavior; those claims require a successful native
workflow at the reviewed head.

Primary references: [service-account projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/),
[CronJob semantics](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/),
[persistent-volume access modes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes),
and [kind's explicit deletion kubeconfig option](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/cmd/kind/delete/cluster/deletecluster.go).
