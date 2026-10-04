# Authorized service discovery

Discovery records service observations separately from canonical inventory. It never turns banners or CPE guesses into packages, asset identities, vulnerability findings, or automatic inventory additions. Install Nmap yourself on a system where you are authorized to probe the configured targets. Discovery is disabled unless the job explicitly sets `enabled = true`.

This valid example is inert until enabled and covers only loopback:

```toml
[[discovery]]
id = "authorized-loopback"
enabled = false
targets = ["127.0.0.1"]
allowlist = ["127.0.0.1"]
ports = [22, 80, 443]
allow_public = false
timeout = 120
```

After approving the actual target scope, use `cvebeacon-auto --config automation.toml discover --json`. The full `run` command can also execute configured discovery jobs. A disabled job reports `disabled` and does not create discovery state or degrade an otherwise healthy pipeline.

The job accepts only `id`, `enabled`, `targets`, `allowlist`, `ports`, `allow_public`, and `timeout`. Targets and the mandatory allowlist contain numeric IP addresses or strict CIDRs. Every expanded target must be allowlisted. No DNS names, address ranges, zone IDs, input files, default network, interface enumeration, or free-form Nmap arguments are accepted. Each job permits at most 256 target addresses, 128 explicit TCP ports, and a 5–300 second total subprocess deadline; at most 16 jobs run serially. A CIDR larger than 256 addresses is rejected before enumeration. IPv4 network and broadcast addresses are excluded when expanding its subnet; an explicitly supplied address does not reveal its subnet mask.

Private RFC1918, IPv6 ULA, and loopback destinations are permitted only within the explicit allowlist. Public destinations additionally require `allow_public = true`. Unspecified, multicast, limited broadcast, reserved, link-local, and known cloud metadata destinations are rejected, including mapped IPv4 forms. Link-local scopes are not supported. An allowlist expresses your configured authorization; it cannot establish legal or operational permission to probe another party's network.

The fixed profile uses TCP connect scanning and light service detection: `--unprivileged -n -Pn -sT -sV --version-light --open -oX -`. It adds finite retry, parallelism, host-time, output, and total-time limits, and disables XML stylesheets and interactive control. Numeric targets are batched in groups of at most 32; IPv6 uses a separate `-6` invocation under the same job deadline. It does not request raw-socket scans, OS detection, user-selected scripts, or `--allports`. Nmap's default TCP 9100 version-probe exclusion is retained.

Version detection sends application probes and automatically invokes Nmap's special `version` scripts. There is no guarantee that the traffic is harmless to fragile services or that all executed code is categorized as safe. Authorize service detection itself, and exclude sensitive targets or ports before enabling a job. These behaviors are documented in [version detection](https://nmap.org/book/man-version-detection.html), [NSE usage](https://nmap.org/book/nse-usage.html), and [TCP connect scanning](https://nmap.org/book/man-port-scanning-techniques.html).

## Backend and output safety

Only an externally installed Nmap executable is selected from fixed installation directories. Each run excludes inherited `PATH`, `NMAPDIR`, Lua paths, and ambient credentials, and gets a temporary working directory and config-home environment. It supplies an installed `--datadir` and pins the services and version-probe databases to that directory. Required engine, script, and library files and directories must exist without links or reparse points. Use a complete, administrator-controlled Nmap installation; the adapter does not sandbox installed executable or script code. Standard Linux and Windows installation locations are supported. Missing or incompatible installations fail clearly.

Nmap can fall back to a real user's configuration directory for a missing data file even with an explicit data directory; setting `HOME` does not override its Unix user-account lookup. Before running, Automation checks only whether the actual Unix user/effective-user `~/.nmap` or Windows OS AppData `nmap` fallback path exists. Its presence fails with `nmap_user_configuration_present`; no contents are read or removed. Configure a dedicated account without custom Nmap data rather than asking the adapter to delete personal configuration. This closes the ambient script fallback described by the [upstream lookup implementation](https://raw.githubusercontent.com/nmap/nmap/master/nmap.cc); remaining installed-tool code stays an administrator trust boundary.

Output is bounded to 16 MiB per invocation, strictly UTF-8, and parsed as events without building an XML tree. Preflight rejects entities, external or internal DTDs, NULs, UTF-16, duplicate doctypes, and oversized unfinished tokens before parsing. The one exact benign `<!DOCTYPE nmaprun>` emitted by current Nmap is accepted and removed. The parser enforces XML output version 1.05, structural locations, 150,000 elements, depth 16, 32 attributes per element, bounded attributes and text, and a successful completion record with matching target totals. Future schema versions require explicit support. Consult [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html) and [Python XML security](https://docs.python.org/3/library/xml.html#xml-security) for the source formats and parser risks.

Only authorized addresses and selected open TCP ports are projected. Each row contains an address, up to eight hostnames, a port, service/product/version text, detection method, optional confidence from 0 to 10, and up to eight CPE strings. Service and CPE fields are capped at 1,024 characters. These fields retain the trust level `discovery-observation`; method, confidence, and CPE text are evidence about what Nmap reported, not proof of product identity or vulnerability applicability. Unexpected addresses, ports, duplicate records, nested completion records, and malformed fields fail the job.

## History and incomplete results

Successful observations are stored under `state_dir/discovery/<id>/current.json`. An immutable `history/<fingerprint>.json` stores each distinct target/port scope and projected observation set. Repeated identical observations update the current observation time without creating another content-history entry or reporting a service change. Current and history hashes are checked before a subsequent scan; corrupt state fails without resetting the baseline.

The JSON job result reports `changed`, `scope_changed`, `added`, `not_observed`, and `service_changes`. Changes are operational observations, not Core vulnerability transition events. A scope change can account for an endpoint no longer being observed. An endpoint absent from this evidence is not an authoritative removal from inventory.

With `--open`, Nmap can omit a host because it has no reported open ports or because processing was incomplete. This version treats omitted hosts, or hosts without projected open-port evidence, as `incomplete`; it preserves the previous current/history state and last-success time. It consequently cannot certify a complete empty scan or all-service disappearance. Process failure, timeout, invalid XML, or incomplete coverage never replaces the last good evidence and is surfaced as degraded operational health. The separate canonical inventory remains unchanged in all cases.

## Distribution and validation

Automation does not bundle Nmap, its data files, scripts, Npcap, or installers, and does not automatically download them. The optional adapter is intended for the user-installed tool/results boundary in the [Nmap Public Source License](https://svn.nmap.org/nmap/LICENSE). Nmap distribution, embedding, or different execution arrangements need their own license assessment. The Automation package's Apache-2.0 license does not replace upstream tool licensing.

Offline tests cover authorization, argument injection, XML expansion and size attacks, provenance, completion ambiguity, history integrity, and change tracking. `automation/tools/native_remote_discovery.py` exercises actual Nmap XML against one generated, loopback-only SSH fixture on a disposable Linux CI runner and verifies that canonical inventory is untouched. It refuses to scan an owner's host or an arbitrary target. That gate does not claim broad device compatibility, harmless service probing, Windows native Nmap acceptance, or validated product-to-inventory identity mapping.
