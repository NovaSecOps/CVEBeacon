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
ordinary `GET` per configured page and bounded `GET` requests for browser
referenced resources. It records direct evidence from page headers, cookie
names, generator metadata, URLs and HTML markers, and from successfully fetched
resource text. Results are inventory hints for review, not proof that a product
is present, unpatched or exploitable. There is no active probing, crawling,
JavaScript execution, authentication or exploitation.

The dashboard can manage client allowlists, preview requests, run the companion
and display observation metadata. See [dashboard web assets](DASHBOARD.md#client-web-technology-detection).
Set `[inventory] web_snapshots = true` to append saved dashboard snapshots to
normal scans (default false); an inventory path is optional in that mode. Partial
snapshots remain usable with warnings, corrupt snapshots are skipped with
warnings, and asset ID collisions fail validation. The companion review file
also records timestamps, total duration, request attempts and product evidence
types, without storing response bodies or cookie values.

### What web detection recognises

The rules use direct evidence from response headers, cookie names, generator
metadata, page markup, linked URLs, and the text or hashes of resources supplied
to the detector, including framework-specific manifest fields and CMS robots
entries. They recognise web servers and languages; server frameworks
and CMS products; JavaScript libraries and CSS frameworks; build tooling; and
third-party services such as analytics, maps, payments, chat and bot checks.
Third-party service and CDN URLs are read as text only. The detector does not
fetch those URLs or execute JavaScript. Retire.js signatures are bundled under
Apache-2.0 with attribution and a pinned source record; their vulnerability
entries are ignored.

Some technologies imply a likely runtime or framework. Examples include
Laravel and supported PHP CMS products implying PHP, Angular implying
TypeScript, Next.js and Gatsby implying React, Nuxt implying Vue and Node.js,
Express implying Node.js, and Livewire implying Laravel. These results are
labelled as inferred and have no version. Inferred-only results are for review;
they are not inventory rows or review entries that could be mistaken for a
direct version observation.

When a library has an npm identity, a disclosed version is recorded with that
exact package name so it can use an npm package URL. Examples include
`@angular/core`, `@fortawesome/fontawesome-free`, `@popperjs/core`, `core-js`,
`zone.js`, `react`, `react-dom`, `vue`, `jquery`, `bootstrap`, `lodash`,
`moment`, `axios`, `chart.js`, `d3`, `rxjs` and `tslib`. Products without a
disclosed version are listed for review and are not added to the inventory.

Rules are checked against version-pinned published builds. When a selected
minified artifact has no literal version string, the detector recognises only
that exact build by its SHA-256 digest. The maintainer script
`tools/web_detection_corpus.py` checks a caller-supplied package manifest; its
offline mode reads local files, while its download mode retrieves the named
files from the npm registry. It is an opt-in maintenance check and is not part
of CI.

Public CDN paths are parsed without fetching files. jsDelivr and unpkg paths
such as `cdn.jsdelivr.net/npm/<package>@<version>/` and
`unpkg.com/<package>@<version>/` supply the npm package name and version. For
cdnjs paths such as `cdnjs.cloudflare.com/ajax/libs/<library>/<version>/`, a
package identity is added only for a recognised library. Unknown but valid
cdnjs names remain generic private review evidence with no product, package or
version identity. Decoded separators, controls, URL-like values and invalid
library names are rejected. CDN detections are bounded per page.

### Optional Wappalyzer-format fingerprints

CVEBeacon can read operator-supplied fingerprint files in the published
Wappalyzer JSON layout. CVEBeacon includes no Wappalyzer fingerprint data and
does not download fingerprint files at run time. An operator may obtain a copy
of a published collection, for example by cloning its community repository,
and point the reader at its `src` directory or its `src/technologies`
directory. The maintained community collection is licensed under GPL-3.0; that
licence applies to the fingerprint data. Check the licence for any collection
you choose to use and follow its terms.

Reading an external collection is currently supported on Linux and other POSIX
systems. On Windows the scan reports the collection as not supported and is
marked partial; the built-in rules still run.

The reader supports passive matching for response headers, cookie names, all
HTML meta tags, script source URLs, script text, CSS, HTML, visible page text,
the page URL, robots resources and a bounded static DOM selector subset. Static
DOM selectors include tags, IDs, classes, attribute presence and the `=`, `*=`,
`^=` and `$=` attribute operators, with `exists`, `attributes` and `text`
conditions. The `js`, `xhr`, `dns`, `certIssuer` and `probe` kinds are not
evaluated. Those patterns need a browser, additional lookups or requests, or
dynamic page state; DOM `properties` conditions also need JavaScript execution.
Technology files may contain multiple named entries. The reader only uses the
supported technologies and metadata files, with bounds on file sizes, pattern
counts and evaluated text. Direct matches across a site observation are
combined before `implies`, `excludes` and requirement relationships are
resolved. Fingerprints are only matched against data already collected for the
authorised page observation.

### What it sends

- One `GET` to the configured page path, plus at most ten redirects that are
  re-checked at every hop.
- After a page succeeds, requests may follow `<script src>`, stylesheet links,
  module preloads, script or style preloads, CSS `@import`, literal static or
  dynamic imports in module scripts, and literal chunk paths from recognised
  webpack or Vite loaders and maps. CSS imports must occur in the stylesheet
  prelude. Module specifiers must be URLs or paths beginning with `/`, `./`
  or `../`. A same-origin `<base href>` is honoured. Nested references resolve
  against the final URL of the containing file. References with raw control
  characters, backslashes or more than 4,096 characters are rejected. Repeated
  resource URLs are fetched once per starting origin.
- The page's web manifest and declared icon are fetched. If it declares no
  icon, `/favicon.ico` is requested. `/robots.txt` is requested once per site.
  Manifest and robots text are available to detection; icon bytes are hashed
  but its resource text is empty.
- A referenced file is fetched only when its scheme, host and port match the
  final page or another site in that client's allowlist. Page rules can inspect
  linked URL text independently. An HTTPS page or file cannot lead to an HTTP
  resource request, including through redirects.
- At most 300 files are fetched per site, each up to 10 MiB decoded and 20 MiB
  on the wire, with a shared 96 MiB decoded budget. Starting paths on the same
  origin share these caps, and paths redirected to the same final origin
  share them there too. Decoded bytes count as they are
  produced, including during failed reads and retries. Resource collection
  and each page's analysis have 180-second deadlines. The run is limited to
  60 minutes, with a five-second margin to publish completed results.
  Oversized, refused, invalid-type and timed-out files are counted by reason
  in the review run metadata.
- `User-Agent: CVEBeacon-web-detect/<version>`, `Accept:
  text/html,application/xhtml+xml`, `Accept-Language: en`, `Cache-Control:
  no-cache`, `Accept-Encoding: gzip, deflate` and `Connection: close`.
- Resource requests use `Accept: */*` for scripts or
  `Accept: text/css,*/*;q=0.1` for styles. Each hop uses the
  `strict-origin-when-cross-origin` Referer policy with the final page as
  the referrer. Same-origin requests send the full page URL without its
  fragment. Cross-origin requests send only the page's origin. Downgrades
  send no request. Requests are sequential within a site, serialized per host
  and paced at least 100 ms apart for the same host.
- Requests omit client cookies, authentication headers, request bodies and
  `Range`. Discovery excludes source maps, images, fonts, media and frames.
  The detector uses `GET` and inspects scripts without executing them.
- Fetched files are processed one at a time and never saved. The private review
  file can include up to 20 evidence items per product, with excerpts capped at
  160 characters. File evidence also includes SHA-256 of the decoded bytes and
  their decoded size; icon evidence has the same hash and size.
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
  Expiry is checked again after waiting and before each request, including
  redirects and retries. A refusal records `authorisation expired`.
- `allow_redirects` defaults to true and `max_redirects` to 2 (the hard maximum
  is 10). Values from 0 through 10 are accepted. The authorisation unit is the
  scheme, host and port of each listed entry; the configured path is only the
  starting point. A redirect may use any
  path and query on an allowlisted host and port, provided the path plus query
  is at most 2,048 characters, contains no credentials and has no fragment. The
  originating entry's `allow_redirects` and `max_redirects` apply to every
  hop. Both the originating and destination entries must permit a non-global
  address. An HTTPS to HTTP downgrade is refused. A refused redirect records
  its fixed reason. For an unlisted target, the review records its scheme,
  host and port. When the redirect limit is reached, the detail reports how
  many hops were followed and points to the Maximum redirects setting.
- Private, loopback, link-local, metadata, multicast, reserved, unspecified and
  NAT64 answers are refused. IPv4-mapped and IPv4-compatible IPv6 forms are also
  refused by default, even when the embedded address is public. Set
  `allow_private_address: true` on a specific entry to attest an internal site;
  loopback and the mapped/compatible forms still need that explicit flag. NAT64
  remains refused even with the flag. By default a 6to4 answer (`2002::/16`) is
  accepted only when its embedded IPv4 address is globally routable (the
  per-entry attestation relaxes this like any other private answer); that decision is
  made explicitly and does not depend on how the `ipaddress` release classifies
  6to4 space. This is intended for controlled internal services, not as a
  general scanner switch.
- `ca_bundle` is optional and relative paths are resolved against the
  allowlist file. It must be a regular file, not a symlink. Its certificates are
  trusted in addition to the system roots.

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
  validated again. DNS resolution runs in a bounded pool of at most four daemon
  workers. A lookup that times out is abandoned, not killed: a resolver that
  never returns keeps its worker thread until it does, so long-lived processes
  that call the detector repeatedly may accumulate such threads.
- Connect timeout 5 seconds, read timeout 10 seconds and 20 seconds total per
  asset, covering resolution, connect, header parsing and every body read. The
  5-second connection limit covers both the TCP connection and the TLS
  handshake.
  Response headers (including the status line) are capped at 64 KiB before they
  are parsed, and the decompressed body at 2 MiB. Gzip and deflate streams must
  be complete; concatenated gzip members are decoded under one cumulative cap
  and chunk framing and trailers count toward the 4 MiB compressed wire limit.
- At most 4 origins run concurrently, with one page request per host per
  second. A run is capped at 1,000 assets and 60 minutes. The parent allows
  five more minutes before terminating an unresponsive companion, then waits
  up to ten seconds before killing it.
- `429` and `503` stop that host for the rest of the run and record
  `Retry-After`. `401`, `403` and `404` are never retried. Connection errors
  are retried at most twice with bounded backoff.
- Bodies, cookies and `Set-Cookie` values are never written to output or
  review files. Error details use fixed, path-free messages, bounded counts
  and status categories, not response content.

### Output and feeding the core inventory

The command writes the usual `cvebeacon.inventory.v1` snapshot, manifest and
`<snapshot>.review.json`. The review sidecar, snapshot and manifest are
published under one output lock. Every inventory row carries the `client`
label, and one snapshot is produced per client run. Asset and system IDs are
stable, client-scoped hashes rather than raw hostnames. CDN and edge
technologies have `category = "edge"` and are never attributed to the origin
server.

Unknown versions are never written as `unknown` or inferred. Hyphenated
pre-release suffixes are preserved, as are recognised dotted qualifiers such as
`.Beta1` and `.RC1`; build metadata such as `.Final` and `.v20210629` is not
treated as part of the version. When a validated CPE carries the product
identity, the row keeps an empty version and a `version-unknown` review entry;
without a CPE the observation stays in the review file only, because the core
product identity needs a version. Conflicting versions for one product become a
`version-conflict` review entry and no row. Direct evidence only is used:
WordPress does not imply MySQL or PHP.

Version gaps and other review-only findings still publish a `partial` snapshot
with the corresponding omissions when at least one usable inventory row was
found. If one or more sites fetched successfully but no usable rows were found,
the command exits successfully, records `no-usable-versions` in review metadata,
prints the recognised product and version counts, and retains any earlier
snapshot. If every site failed to fetch, or fetch failures are not accepted by
`--allow-partial`, the command exits 2, reports the number of failed sites and
their reason codes, and leaves any previous snapshot unchanged. With
`--allow-partial`, successful rows are published in a `partial` snapshot and
the review file records the failed sites. Treat `needs_review`,
`coverage_unknown`, blocked and stale assets as unknown, not as clean.

Validate or merge the result with the normal extension commands, then point the
core inventory at it. The core remains the applicability authority:

```console
cvebeacon-ext validate acme-web.json --allow-partial
cvebeacon-ext merge acme-web.json other-client-web.json \
  --output inventory.json --source-id central --allow-partial
```

Add `--allow-partial` to both `validate` and `merge` whenever an input snapshot
is partial (for example after a version-unknown review or an accepted fetch
failure).

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
