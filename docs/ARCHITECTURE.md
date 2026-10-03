# Architecture

CVEBeacon's standalone core accepts supplied inventory, retrieves public
vulnerability intelligence, assesses applicability, and maintains local state,
reports, alerts and an optional dashboard. Installing only the core remains a
complete supported deployment. It never connects to monitored hosts or clusters.

Optional extensions run as separate one-shot programs. The companion
`cvebeacon-extensions` distribution depends on the core's public inventory
validator; the core has no dependency on collectors, SBOM tools, Kubernetes or
container runtimes. There is no plugin discovery or extension startup in core.

The boundary is canonical inventory: extensions observe software and produce
snapshots. All accepted records pass the same validator as ordinary core input.
Only core decides applicability and writes monitoring SQLite state. Extensions
never write findings or the monitoring database.

Snapshot manifests describe collection provenance, integrity and age separately
from inventory. Merging must detect conflicts and incomplete or stale sources.
Provenance does not establish vulnerability applicability. A manifest hash
detects mismatched files; it is not a signature or proof of a trusted collector.
Deployers control collection, staging and transfer permissions.

Explicit package identifiers retain their qualifiers and uncertainty. Names,
banners, image tags and labels alone do not establish package identity. Weak
observations require review. Unsupported identities remain unknown rather than
being rewritten to imply coverage. Operational source labels and grouping stay
local to public vulnerability lookups; deliberately enabled notifications have
their own recipient and privacy boundary.

See [identity rules](IDENTITY.md), [network requirements](NETWORK_REQUIREMENTS.md),
and [the extension contract](EXTENSIONS.md).
