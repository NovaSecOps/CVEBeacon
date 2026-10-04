# Registry SBOM acquisition

Automation can retrieve an existing SBOM attached to an explicitly allowed image digest, validate its content address and subject association, and reuse the Extensions v1 package importer. Core receives the resulting local snapshot. Registry credentials remain in Automation.

This is a conservative OCI Distribution 1.1 Referrers API subset. It requires HTTPS, fully qualified repository references and lowercase SHA256 digests. It does not resolve tags or infer package versions from image names. SBOM acquisition checks transport integrity and association; it does not verify signatures, supplier authorship, completeness or attestation.

## Configure an exact registry and repository

```toml
[[registries]]
id = "example-registry"
url = "https://registry.example"
repositories = ["team/application"]
# Optional private CA bundle; normal certificate verification always applies.
# ca_file = "registry-ca.pem"
# Optional administrator-provisioned, short-lived pull bearer token.
# bearer = { env = "EXAMPLE_REGISTRY_TOKEN" }
# bearer = { file = "secrets/registry-token" }
timeout_seconds = 15
budget_seconds = 60
max_pages = 16
max_referrers = 128
max_sbom_bytes = 8388608

[[sources]]
id = "application-sbom"
kind = "registry"
required = true
allow_partial = false
max_age_seconds = 86400
[sources.options]
registry = "example-registry"
image = "registry.example/team/application@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
# Pin one attached SBOM when several eligible artifacts exist:
# artifact_digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
```

The example digest is synthetic. Replace it with an independently known image manifest or index digest. The configured URL contains only an HTTPS origin; it has no prefix, userinfo, query or fragment. Repository allowlists are exact, with no implicit Docker Hub, wildcards or redirects. A private endpoint is contacted only because an administrator configured its exact origin and repository.

Anonymous reads and pre-provisioned bearer tokens are supported. A token should grant pull access only to the configured repository. Automation does not exchange username/password credentials, follow a 401 challenge realm, request catalog scope, refresh tokens or discover authentication endpoints. A registry requiring that exchange returns `registry_authentication_required`; provision an appropriately scoped token outside Automation. All redirects are rejected, including same-origin redirects. No proxy or TLS keylog environment setting is used by the HTTPS transport.

Secret files must be private to the service account; on POSIX their group/other permission bits must be clear. Config parsing validates the secret reference without resolving it. Acquisition resolves only the selected registry credential. Errors and pipeline health contain fixed categories, never server bodies, bearer tokens or challenge URLs.

Run a configured source once with `cvebeacon-auto --config automation.toml collect application-sbom`, or use the normal one-shot `run` pipeline. A collection failure preserves the previously accepted source pointer. The pipeline applies its required/optional source policy and preserves the previous merged inventory when required collection fails.

## Supported artifact shape and selection

The target manifest bytes are fetched at the exact digest and hashed before use. A target may be an OCI/Docker image manifest or an explicitly selected image index. Image config/layer contents are not downloaded; this feature imports an existing SBOM rather than generating one from image files.

Referrers discovery consumes every bounded page. It filters descriptors locally and ignores server filter claims. Pagination accepts a single `rel="next"` link to the same HTTPS origin and the exact referrers path for the same repository and target digest. Only its query can change. Off-origin, path-changing, ambiguous, looping or excessive pagination fails before selection. Descriptor `urls` and embedded data never choose a download destination.

Eligible artifacts use this precise layout:

| Field | Required value |
|---|---|
| Manifest | `schemaVersion: 2`, `application/vnd.oci.image.manifest.v1+json` |
| `artifactType` | One of the bare JSON SBOM media types below |
| `subject` | Target digest, raw byte size and exact manifest media type |
| `config` | `application/vnd.oci.empty.v1+json`, exact SHA256 and size of the two bytes `{}` |
| `layers` | Exactly one JSON blob with the same media type as `artifactType` |

The artifact manifest and both config/SBOM blobs are downloaded from the same configured repository and checked against their digests and sizes. A generic blob response Content-Type is acceptable because its verified descriptor selects the type. Contradictory manifest media or digest metadata fails.

| SBOM layer media type | Frozen importer profile |
|---|---|
| `application/vnd.cyclonedx+json` | CycloneDX JSON 1.4–1.7 |
| `application/spdx+json` | SPDX JSON 2.2/2.3 |
| `application/spdx3+json` | SPDX 3.0.1 compact JSON-LD with the exact official context and local CreationInfo |

Remote JSON-LD contexts are never fetched. Packages need explicit PURL/CPE identity and installed version; existing identity, conflict and resource checks remain authoritative. Components needing review cause failure unless that source explicitly allows partial snapshots. Review remains visible through snapshot omissions and the separate acquisition evidence.

Without `artifact_digest`, exactly one eligible referrer must exist. Several distinct eligible artifacts return `registry_sbom_ambiguous`; order, annotations and claimed timestamps do not choose a winner. An explicit digest must name an advertised eligible artifact and still passes every integrity, media and subject check. A supported empty Referrers response returns `registry_sbom_missing`. HTTP404/405 returns `registry_referrers_unavailable`.

Legacy referrers-tag fallback, cosign tag conventions, BuildKit/in-toto envelopes, artifact indexes, archives/compression, arbitrary JSON and SBOM media parameters are unsupported. The client does not claim universal OCI discovery compatibility.

## Kubernetes observations and digest attribution

Use a separate Extensions v1 observation-only collector with its existing Pod-only RBAC and API credential. Supply its `cvebeacon.kubernetes-observations.v1` file to Automation; the registry stage needs no Kubernetes API token.

```toml
[[sources]]
id = "cluster-a"
kind = "kubernetes"
required = true
allow_partial = false
max_age_seconds = 3600
[sources.options]
observations = "cluster-a-observations.json"
registries = ["example-registry"]
# Optional per-image selection, keyed by exact running repository@digest:
# [sources.options.artifact_digests]
# "registry.example/team/application@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
```

The observation document source ID must match the configured source. Its original generation time becomes the enriched snapshot observation time; downloading an SBOM cannot make stale Pod evidence fresh. Future/stale files, duplicate container slots and inconsistent Pod identities fail before registry requests.

Only a running container's reported `image_id` can select evidence. A declared image tag/index or bare runtime/config SHA256 does not substitute for a running manifest reference. A running reference resolving to an index fails explicitly. Unallowed or missing exact running identities remain review omissions; they create no package inventory. Existing frozen enrichment keeps separate stable per-container component identities and reuses the same exact-image templates.

## Evidence, bounds and recovery

Each accepted source generation has an immutable `registry-evidence/<generation>/` archive beside the normal source generations. It retains exact target/artifact/config/SBOM bytes, optional projected observation bytes and a separate versioned provenance document. Short indexed filenames avoid unnecessarily long Windows paths; provenance maps them to full verified digests and includes the v1 local image/SBOM map. Evidence includes configured image labels and projected workload labels, so secure and back up the staging tree as inventory data.

The archive is completed and validated before the source pointer commits. A crash after archive publication can leave an unreferenced complete archive; an identical-generation retry checks every byte and metadata field, retains the first acquisition timestamp and reuses it. Corrupt archives are rejected rather than overwritten. Failed acquisition or publication leaves the previous source available. Historical generations remain until an administrator applies a retention/backup policy. Use a suitably short administrator-controlled staging path on Windows; an inaccessible archive fails before pointer publication.

Operations are sequential and finite: four concurrent acquisitions per process, up to64 selected images, up to64 HTTP requests per registry client, 4MiB per manifest/page, 64MiB total response bytes per client, and 32MiB total retained evidence/observations per source. Configured limits cap pages at32, referrers at512, an SBOM at32MiB, each request at60seconds and source acquisition budget at300seconds. Requests use the remaining budget; parsing/publication checks it again. Frozen JSON depth/record/identity checks remain in force. Exhausting a bound is an explicit failure, never an incomplete success.

## Optional generation status

No external SBOM generator is enabled. Current Syft can scan a digest through its registry backend without a runtime, but its underlying bearer transport can contact response-selected public token realms and does not enforce this platform's exact administrator-selected destination policy. A sanitized subprocess environment cannot close that gap.

A future offline generator would require verified image-to-OCI-layout acquisition, sandboxed network denial, bounded layer expansion/CPU/memory/disk, an isolated tool configuration without credential helpers, a maintained pinned tool and explicit generated provenance. No container socket, owner Docker credentials or convenience insecure mode is part of this feature.

Protocol sources: [OCI Distribution1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-referrers), [OCI Image1.1.1 manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md), [descriptor](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md), [CycloneDX JSON registration](https://www.iana.org/assignments/media-types/application/vnd.cyclonedx+json), [SPDX2](https://www.iana.org/assignments/media-types/application/spdx+json), [SPDX3](https://www.iana.org/assignments/media-types/application/spdx3+json), [Docker bearer authentication](https://docs.docker.com/reference/api/registry/auth/), [Syft1.54.0 transport dependency](https://github.com/anchore/syft/blob/v1.54.0/go.mod) and [pinned bearer transport](https://github.com/google/go-containerregistry/blob/v0.22.1/pkg/v1/remote/transport/bearer.go).
