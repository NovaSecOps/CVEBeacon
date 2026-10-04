# Optional Automation container

Build locally with `docker build -f automation/Dockerfile -t cvebeacon-automation:local .`.
This separate image installs the three distributions in dependency order. It
does not change the v1 Core or Extensions images. The Python base is digest
pinned; OpenSSH, Nmap and SBOM generators are not bundled. Use a native host
runner for those optional external backends, or build a separately reviewed
derivative image with administrator supplied tools.

The default UID/GID is 65532, root filesystem can be read-only, and the reference
[Compose file](../automation/deploy/container/compose.yml) drops all capabilities,
sets no-new-privileges and bounds temporary storage. Prepare local directories
and restrict ownership before running. SQLite and advisory locks require local
storage with reliable locking; do not mount network filesystems for state.

Use the pipeline profile for one-shot runs, scheduled externally. `/config` is
read-only; staged inputs are read-only when sources are upload/snapshot only.
Registry or SSH acquisition needs a writable staging mount and its own approved
tool/credential configuration. Keep pipeline state, merged inventory, Core
SQLite, reports and credentials on separate mounts. Only explicitly named Core
credentials in `core_env` reach its child process; integration credentials are
rejected from that list.

The ingest profile mounts only its receiver-only configuration, upload/TLS
credentials and writable staging tree. It has no Core database, reports or
notification ledger mount. Bind beyond container loopback only with direct TLS;
the loopback host port mapping does not make plaintext container traffic safe.
An HTTPS proxy needs the explicit loopback-only proxy mode described in
[ingestion](INGESTION.md). Do not pass pipeline credentials to the receiver.

The entrypoint translates SIGTERM into bounded CLI cleanup and exits 143. The
pipeline preserves Core exit 4 and records `coverage_warning`. The explicit
`run --accept-coverage-warning` switch lets a completed container initialization
step continue while retaining Core exit 4 in health. It does not alter reports
or assert clean vulnerability coverage; normal schedulers should use the default
exit behavior.

CI inspects both the exported filesystem and every image layer, runs with no
network/capabilities and a read-only root, verifies two persisted offline scans,
then exercises an isolated TLS intake container with generated credentials and
SIGTERM. No images are published by these workflows. Back up writable volumes
and immutable source pointers/generations together; retention is an explicit
administrator operation.
