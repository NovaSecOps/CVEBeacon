# Optional Kubernetes collector and scheduled scans

The companion collector lists Pods through verified in-cluster HTTPS and projects namespace, Pod name/UID, immediate owner, container class/name, declared image, reported image ID and running status. It never turns tags into package versions. The standalone core has no Kubernetes client or credentials.

Pod `list` permission exposes complete Pod objects, including plaintext environment values, transiently to the collector. Kubernetes RBAC cannot restrict this response to image fields. The collector retains only the allowlisted observation fields; it does not retain environment values, arbitrary labels, annotations, commands or volume contents. It never requests Secrets. Use the namespace Role by default; a separate [optional cluster-scope grant](../deploy/kubernetes/cluster-scope.optional.yaml) expands only Pod listing. Do not apply that grant for the namespaced reference.

## Image identity and supplied SBOMs

The collector accepts exact reported `repository@sha256:<64 lowercase hex>` identities, optionally with a supported runtime prefix. Bare runtime SHA256 values can be configuration IDs and remain review observations. A declared image index and the running platform manifest can differ; only the exact reported supported identity selects a mapping. No image pulls, registry credentials, attestation retrieval or signature verification are implemented.

Supply a local map using the [example structure](../deploy/kubernetes/map.example.json):

```json
{
  "contract": "cvebeacon.image-sboms.v1",
  "images": {
    "registry.example/team/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": "workload.json"
  }
}
```

Replace the illustrative reference with the **reported running reference** and provide its actual SBOM. Values are plain JSON filenames beside the map. The mapping is an administrator attribution assertion; it does not cryptographically prove an SBOM belongs to an image. Protect and version both files. SBOM packages pass the same conservative importer and canonical core inventory validation as standalone imports.

Running images without usable mappings and SBOM components requiring review produce partial results. The collector observes its own running init container too: supply its SBOM, or deliberately append `--allow-partial` to the collector wrapper arguments. The reference refuses partial inputs by default. Explicit partial mode preserves omissions in both collected and merged manifests; it does not mean unobserved packages are safe. A collection with no usable mapped components fails and never supplies a fresh inventory to the scanner.

Component IDs include source, namespace, Pod UID, container class/name and SBOM component identity. They remain stable within that Pod instance but change when a replacement Pod has a new UID. Only the immediate owner is reported; a ReplicaSet is not silently relabeled as its Deployment. Completed init containers, pending containers and zero-replica workloads are outside running-package enrichment. Node/cluster software enumeration is outside this first reference.

## Reference deployment

[reference.yaml](../deploy/kubernetes/reference.yaml) creates a namespace, service account, namespace Pod-list Role/Binding, PVC and suspended CronJob. Its init container collects, merges and validates an inventory into an `emptyDir`. The main container scans that inventory with persistent SQLite and reports. Scheduling is external to the images.

| Container | API token/CA | Inventory | Monitoring state/reports |
| --- | --- | --- | --- |
| Collector init | Explicit projected mount | Read/write staging | No mount |
| Core scan | No mount | Read-only | Read/write PVC |

Both containers run as UID/GID 65532 with a read-only root filesystem, no added capabilities, no privilege escalation and RuntimeDefault seccomp. The reference has no host mounts, runtime socket, privileged containers or dashboard. Service-account automount is disabled; token and CA are projected only into the init container. ConfigMaps are mounted by kubelet without granting their API read permission to the collector.

Before applying to a cluster you administer:

1. Build the `core` and `extensions` Docker targets. Make them available through your normal trusted image distribution process; replace the illustrative `:local` image values with your own immutable image digests. This repository does not publish images.
2. Select the observation namespace and distinct source ID, updating the namespace references and collector arguments together. The reference uses `cvebeacon-demo` and `cluster-demo`.
3. Select a suitable CSI block-backed filesystem storage class for the PVC's `ReadWriteOncePod` mode and confirm `fsGroup: 65532` provides access. Do not use NFS/SMB/RWX storage for SQLite WAL.
4. Prepare `map.json`, its SBOM files and a core configuration based on [cvebeacon.example.toml](../deploy/kubernetes/cvebeacon.example.toml). Notifications are disabled. The example otherwise uses normal public vulnerability sources; apply your deployment's egress policy and source configuration.
5. Apply your edited reference while `spec.suspend` remains `true`, then create the three read-only ConfigMaps below.

For the example's single SBOM, run these commands against your deliberately chosen cluster/context:

```bash
kubectl -n cvebeacon-demo create configmap cvebeacon-scripts \
  --from-file=collector.py=deploy/kubernetes/collector.py \
  --from-file=scan.py=deploy/kubernetes/scan.py
kubectl -n cvebeacon-demo create configmap cvebeacon-config \
  --from-file=cvebeacon.toml=deploy/kubernetes/cvebeacon.example.toml
kubectl -n cvebeacon-demo create configmap cvebeacon-sboms \
  --from-file=map.json=./map.json --from-file=workload.json=./workload.json
```

The map/SBOM mounts use explicit `subPath` entries because regular ConfigMap directories contain symlinks and the importer rejects link inputs. Add an explicit mount for each additional map filename. ConfigMaps have Kubernetes size limits; larger SBOM sets need an administrator-controlled read-only volume containing ordinary files. `subPath` file contents do not update in an existing Pod; newly scheduled Jobs receive the current configuration. These examples contain no credentials; do not put credentials in these ConfigMaps.

Run a deliberate initial Job from the suspended CronJob and inspect its status/logs before resuming the schedule:

```bash
kubectl -n cvebeacon-demo create job cvebeacon-initial --from=cronjob/cvebeacon
kubectl -n cvebeacon-demo wait --for=condition=complete job/cvebeacon-initial --timeout=300s
kubectl -n cvebeacon-demo patch cronjob cvebeacon --type=merge -p '{"spec":{"suspend":false}}'
```

Core exit 4 means the scan was recorded with coverage warnings or degraded source health. The wrapper preserves it as a Job failure by default, with `backoffLimit: 0` to avoid repeating a completed degraded scan. If your operational policy treats that result as completed execution, append `--accept-degraded` to the core wrapper arguments. The original code remains recorded in `/persistent/last-execution.json`; findings and coverage remain in SQLite/reports. Exit 0 under this explicit policy is not a statement of clean coverage. Other failures keep their nonzero status.

## Persistence, concurrency and stopping

`concurrencyPolicy: Forbid` only coordinates Jobs from this CronJob. Manual Jobs or another CronJob can still overlap. The [scan wrapper](../deploy/kubernetes/scan.py) acquires a nonblocking Linux `flock` on the persistent state volume before opening monitoring state; competing cooperating writers exit 75. Every writer to this database must use this same lock. `ReadWriteOncePod` adds a cluster storage constraint when supported by the chosen CSI driver. Ordinary `ReadWriteOnce` permits multiple Pods on one node and is not a single-writer guarantee.

Do not run a concurrent dashboard against this reference database. A separately designed dashboard requires a demonstrated access/backup strategy. Back up state only through a SQLite-safe method while coordinating writers. Preserve the PVC when changing images or schedules.

Suspend the CronJob to stop future scheduling. This does not cancel an already active Job. The reference bounds each Job to 300 seconds and translates SIGTERM through the wrapper so Python can close the database and release the lock; Kubernetes can still force termination after the grace period. SQLite recovery remains necessary after an abrupt host/container failure. No cron daemon runs in either image.

## Native acceptance workflow

[kubernetes.yml](../.github/workflows/kubernetes.yml) builds both images locally, verifies pinned kind/kubectl binary checksums, and invokes [kubernetes_smoke.py](../tools/kubernetes_smoke.py). The script creates a unique kind cluster and private temporary kubeconfig, uses only that explicit context, and removes only its own cluster in `finally`. It never uses an owner cluster or publishes images.

The acceptance checks use a pinned public Python workload and a deliberately synthetic demonstration SBOM. They verify real in-cluster CA/token TLS, allowed namespace Pod listing, seven actual HTTP 403 responses including Secrets and another namespace, allowlisted observation output without synthetic env/annotation canaries, enrichment using the actual reported repository digest, core credential/dependency isolation, two sequential scans, persistent SQLite integrity/reports, preserved unknown coverage, zero notification deliveries, lock exclusion, and a third scan from a genuine scheduled CronJob Job. Controller scheduling is identified by its scheduled-timestamp annotation; manual Jobs also have CronJob owner references.

CI deliberately enables partial inventory with an unmapped synthetic workload (and the unmapped collector image), and accepts core exit 4 because all external vulnerability sources are disabled. The extra workload makes partial provenance independent of the collector's own status-update timing. These are explicit synthetic test policies, not reference defaults. The synthetic SBOM is not a claim about packages in the public workload image.

kind uses its ephemeral local-path `ReadWriteOnce` storage plus the same lock, so this smoke does **not** establish your production CSI driver's `ReadWriteOncePod`, failover, backup or filesystem behavior. Actual runtime acceptance is established only by a successful native workflow; syntax checks on a machine without Docker do not establish it.

Primary references: [in-cluster API access](https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/), [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/), [CronJob semantics](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/), [persistent volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/), [SQLite WAL constraints](https://sqlite.org/wal.html), and [kind v0.33.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0).
