# Optional inventory extensions

Install the core as usual. To add the companion from this repository:

```console
python -m pip install .
python -m pip install ./extensions
cvebeacon-ext --help
```

No extension is needed for supplied inventory, monitoring, reporting or the
dashboard. The companion only produces inventory; it never writes monitoring
SQLite or decides vulnerability applicability.

See [SBOM import](SBOM.md) and [local host collectors](HOST_COLLECTORS.md) for
supported inputs, permissions and conservative identity rules.

## Web technology detection

`cvebeacon-ext web detect` observes explicitly authorised web assets with one
ordinary `GET` per asset. It records only direct evidence in the response:
`Server` and `X-Powered-By`-style headers, cookie names, generator metadata,
script/link URLs and specific HTML markers. Results are inventory hints for
review, not proof that a product is present, unpatched or exploitable. There is
no active probing, crawling, subresource fetching, JavaScript execution,
authentication or exploitation.

### What it sends

- One `GET` to the configured path, plus at most two redirects that are
  re-checked at every hop.
- `User-Agent: CVEBeacon-web-detect/<version>`, `Accept:
  text/html,application/xhtml+xml`, `Accept-Language: en`, `Cache-Control:
  no-cache`, `Accept-Encoding: gzip, deflate` and `Connection: close`.
- No client cookies, authentication headers, request body, `Range`, `POST`,
  link following, subresource requests or path guessing.
- TLS verification is always on with a minimum of TLS 1.2. An optional
  per-client CA bundle is trusted in addition to the system store; there is no
  insecure switch.

### Authorisation and the allowlist

The allowlist is a bounded JSON file. An entry is refused before any request if
`authorized_by` or `authorized_at` is missing, if `expires_at` has passed, or if
the fields are malformed. Unknown fields are refused so a misspelled safety
option cannot silently fall back to a less safe default.

```json
{
  "client": "acme",
  "ca_bundle": "acme-ca.pem",
  "assets": [
    {
      "hostname": "www.example.com",
      "scheme": "https",
      "port": 443,
      "path": "/",
      "authorized_by": "Acme Security <security@example.com>",
      "authorized_at": "2026-11-01T00:00:00Z",
      "expires_at": "2027-11-01T00:00:00Z",
      "allow_redirects": true,
      "max_redirects": 2,
      "allow_private_address": false
    }
  ]
}
```

- Use exactly one of `hostname` or `url` per asset. `scheme` defaults to
  `https`, `port` to 443/80, and `path` to `/`. A URL must be absolute and must
  not contain credentials, a query or a fragment.
- `authorized_by` and `authorized_at` are required. `expires_at` is optional.
  Timestamps are ISO 8601 UTC values. A future `authorized_at` is refused.
- `allow_redirects` defaults to true and `max_redirects` to 2 (the hard maximum
  is 2). A redirect must stay on an endpoint present in the same allowlist,
  stay on the same registrable domain, and must not downgrade HTTPS to HTTP.
- Private, loopback, link-local, metadata, multicast, reserved, unspecified,
  IPv4-mapped/compatible IPv6 and NAT64 answers are refused by default. Set
  `allow_private_address: true` on a specific entry to attest an internal site;
  loopback still needs that explicit flag. This is intended for controlled
  internal services, not as a general scanner switch.
- `ca_bundle` is optional and relative paths are resolved against the
  allowlist file. It must be a regular file.

Preview the request count without resolving or sending anything:

```console
cvebeacon-ext web detect --client acme --assets acme-assets.json \
  --output acme-web.json --source-id acme-web --plan
```

Then run the observation:

```console
cvebeacon-ext web detect --client acme --assets acme-assets.json \
  --output acme-web.json --source-id acme-web
```

### Network and resource limits

- Resolve first, reject the asset if any answer is non-global (unless
  `allow_private_address` is set), then connect to the validated IP while
  keeping the original Host header and TLS SNI. Every redirect is resolved and
  validated again.
- Connect timeout 5 seconds, read timeout 10 seconds and 20 seconds total per
  asset. Response headers are capped at 64 KiB and the decompressed body at
  2 MiB; gzip and deflate streams are decoded incrementally with the same cap.
- At most 4 assets run concurrently, with one request per host per second. A
  run is capped at 1,000 assets and 15 minutes.
- `429` and `503` stop that host for the rest of the run and record
  `Retry-After`. `401`, `403` and `404` are never retried. Connection errors
  are retried at most twice with bounded backoff.
- Bodies, cookies and `Set-Cookie` values are never written to output or
  review files. Error details contain status categories, not response content.

### Output and feeding the core inventory

The command writes the usual `cvebeacon.inventory.v1` snapshot, manifest and
`<snapshot>.review.json`. Every inventory row carries the `client` label, and
one snapshot is produced per client run. Asset and system IDs are stable,
client-scoped hashes rather than raw hostnames. CDN and edge technologies have
`category = "edge"` and are never attributed to the origin server.

Unknown versions are never written as `unknown` or inferred. When a validated
CPE carries the product identity, the row keeps an empty version and a
`version-unknown` review entry; without a CPE the observation stays in the
review file only, because the core product identity needs a version. Conflicting
versions for one product become a `version-conflict` review entry and no row.
Direct evidence only is used: WordPress does not imply MySQL or PHP.

Version gaps and other review-only findings still publish a `partial` snapshot
with the corresponding omissions, so the dashboard can show the product and
ask for manual review. A run that hit a fetch failure is different: without
`--allow-partial` the command writes the review file and fails, leaving any
previous snapshot unchanged. With `--allow-partial` it publishes a `partial`
snapshot whose `omissions` list the failures and review reasons. A run with no
rows, including a run where every asset failed, never publishes an empty
success. Treat `needs_review`, `coverage_unknown`, blocked and stale assets as
unknown, not as clean.

Validate or merge the result with the normal extension commands, then point the
core inventory at it. The core remains the applicability authority:

```console
cvebeacon-ext validate acme-web.json
cvebeacon-ext merge acme-web.json other-client-web.json \
  --output inventory.json --source-id central
```

```toml
[inventory]
path = "inventory.json"
```

`cvebeacon --config cvebeacon.toml scan` records the `client` label with each
scanned asset and preserves it in reports and findings. Use a stable
`source-id` such as `<client>-web`, not a hostname or credential.

Core deployments can also use the separate [container reference](CONTAINERS.md).
For automated deployment, see [Kubernetes](KUBERNETES.md) and the
[central home-lab workflow](HOME_LAB.md).

## Inventory contract v1

A snapshot is a UTF-8 JSON list, directly accepted by the existing core JSON
loader, plus `<snapshot>.manifest.json`. Records use `asset_id`, `vendor`,
`product`, `version`, `category`, `system_id`, `ecosystem`, `purl`, `cpe`,
`repository`, `commit`, and the optional `client` label. Values are strings;
optional values serialize as empty
strings. Unknown fields and empty records are rejected in the exchange contract.
IDs are unique under core normalization and case-insensitive comparison. Version spelling and
explicit identity qualifiers are preserved.

Core `cvebeacon.inventory.validate_records` is the semantic authority and shares
the exact validator used by file input. There is intentionally no duplicate JSON
Schema identity model: structural validation alone cannot express the audited
PURL/CPE/version rules. The companion enforces bounded input (32 MiB, 100000
records, 8192 characters per inventory field) and requires separate review for
multiple strong identity systems on one row. These additional exchange limits
do not change ordinary core inventory support.

The sidecar identifies `contract` (`cvebeacon.inventory.v1`), collector/version,
`source_id`, UTC `generated_at` and `observed_at`, exact inventory `sha256`,
`record_count`, `status` and `omissions`. Successful complete collection has
`status=success`; explicit partial output carries omissions. Generation time is
publication time; observation time is the oldest included observation. Merging
does not refresh the age of old data. No sidecar field influences applicability
or enters vulnerability lookups. Source IDs should be administrator-chosen
stable aliases, not credentials or sensitive hostnames.

Writers fsync temporary files and replace inventory then manifest atomically.
Two files cannot be replaced as one transaction: interruption between replacements
produces a detectable hash mismatch. The inventory is replaced before the manifest,
so if the manifest write fails or is interrupted the pair is left mismatched, is
rejected by the hash check on the next read, and is recovered only by publishing
again; it is not rolled back automatically. A failed collection leaves the previous
snapshot unchanged and aging. Monitor exit codes as well as snapshot age.
Concurrent cooperating writers are excluded by an exclusive output lock. After
a crash, confirm the writer has stopped before removing its stale `.lock` file.
Use administrator-controlled directories; hostile shared-directory races and
malicious collectors are outside the file trust model. Leaf symlinks/reparse
points and nonregular input/output files are rejected. Hashes are not signatures.

## Merge and freshness

```console
cvebeacon-ext merge linux-a.json linux-b.json windows-a.json --output inventory.json --source-id central --expected-source linux-a --expected-source linux-b --expected-source windows-a --max-age-seconds 86400
cvebeacon-ext validate inventory.json
cvebeacon --config cvebeacon.toml inventory validate inventory.json
```

The output and record ordering are deterministic for the same inputs; publication
timestamps naturally change. Repeated identical rows are coalesced. Conflicting
asset IDs, duplicate source IDs, or conflicting package slots within a system
fail; there is no last-writer-wins policy. Strong package slots retain PURL
qualifiers and exclude version. Ambiguous coinstalled versions in the same slot
require explicit separate system/instance grouping before merging.
Repository/commit identities also conflict within the same system and exact
repository URL. The merger does not infer that different repository URLs are
equivalent.

Freshness defaults to 24 hours. Future timestamps, missing files, stale sources,
bad hashes, invalid records and undeclared partial snapshots fail before output.
Expected sources are optional but recommended to detect a forgotten input.
`--allow-partial` permits missing inputs/required sources and declared partial
snapshots, recording omissions; it never ignores corruption or conflicts. Stale
snapshots must be explicitly omitted from the input list with their source still
listed as expected to obtain a partial result. Consumers must opt in again to
read partial snapshots. Core alone does not read the sidecar: automation must
validate/merge immediately before invoking core and stop on failure.
