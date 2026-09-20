# Dashboard

Launch from the directory containing your configuration, or provide an explicit path:

```console
cvebeacon --config /absolute/path/cvebeacon.toml serve
```

The default address is `http://127.0.0.1:8787`. Windows packages use `cvebeacon.exe serve`; Linux packages use `./cvebeacon serve`. The server prints its listening address after binding successfully. No development or debugging console is enabled.

To select a port or deliberately bind to the LAN with password authentication configured as below:

```console
cvebeacon serve --host 0.0.0.0 --port 8787
```

The dashboard is optional. Continue running `cvebeacon scan` as a separate short-lived scheduled process. The dashboard does not schedule scans, send notifications, or start background refresh workers.

## Views and investigation

- **Overview:** last successful full scan, most recent attempted scan, current inventory count, latest known affected/review findings, coverage gaps, KEV counts, recent material changes, notification acceptance/failure, and source observations.
- **Findings:** filter by asset, vendor, product, version, CVE, applicability, severity or minimum CVSS, and CISA/EU KEV. Expand evidence to see the assessment reason, provenance, conflicts, CVSS and EPSS. Unknown KEV membership is distinct from a healthy negative result.
- **Assets:** search the current configured inventory and inspect an asset's stored findings. A changed version or removed asset leaves its older observations explicitly labelled as historical.
- **History:** browse material events, filter exact asset/CVE identifiers, and open the evidence saved with an event. Older-event links provide access beyond the first page.
- **Manual query:** query a vendor/product/version using the same core operation as the CLI. Results show uncertainty and degraded source status. Queries can take several minutes and do not change scheduled alert state.
- **Reports:** query the current inventory and download an XLSX or JSON report using the existing reporting functions. Exports do not commit monitoring state. Check the report's coverage and source-health fields even when the download succeeds.
- **Sources:** view cached observations from the latest recorded scan, including check result, retrieval time and available source timestamp. Opening this page does not contact the sources.

## Freshness and failures

Stored data is not live source availability. A successful check is labelled as a cached observation and becomes stale after 24 hours. Old scan data, failed/degraded scans, and scan attempts without recorded completion receive prominent warnings. An unfinished attempt may represent a running or interrupted scanner; check the actual process and logs.

Retained findings keep their last observation timestamp. A failed refresh cannot make older SQLite data appear newly observed. Asset identities absent from the last scan, changed inventory versions, and legacy scans without per-asset metadata have unknown coverage. Counts describe stored observations, not proof that the current inventory is clean.

New scan-attempt metadata covers failures after configuration loads and the state database opens. Failures before that point cannot be written to SQLite; monitor scheduler exit codes/logs as well as the displayed scan age. Delivery acceptance is reported separately from full-scan success and does not establish recipient receipt.

## Network and security

Localhost use requires no login by default. Without authentication, clients that can reach the dashboard can read observations and initiate manual queries or reports. A non-loopback bind without authentication is refused unless you explicitly pass `--allow-unauthenticated-remote`. Use that override only with appropriate external access controls; do not expose an unauthenticated instance to the public internet.

### Optional local password

Generate a strong salted scrypt hash with the existing Werkzeug primitives:

```console
cvebeacon dashboard hash-password
```

The helper requires a terminal with hidden input, asks for confirmation, and accepts 12–1024 characters. Use a long unique password. It prints only the hash and needs no inventory or configuration. Supply the output through `CVEBEACON_DASHBOARD_PASSWORD_HASH` in the server process environment using your deployment's secret injection. Never place the password or hash in TOML, source control, command arguments, logs, or SQLite. Keep the hash private too. The supported hash format is Werkzeug's `scrypt:32768:8:1`; regenerate unsupported hashes with the helper. An unset variable disables authentication; an empty or invalid value prevents startup.

Optional TOML settings contain no password material:

```toml
[dashboard]
password_hash_env = "CVEBEACON_DASHBOARD_PASSWORD_HASH"
session_lifetime_seconds = 3600
secure_cookie = false
```

When enabled, all observation, query, report and history routes require login. Only the login page and bundled static assets are public. Login clears earlier session state and rotates the CSRF token. Sessions expire absolutely after one hour by default (configurable from 60 to 86400 seconds), regardless of activity. **Log out** uses a CSRF-protected POST and revokes that session immediately, including copies of its cookie. Cookies use HttpOnly and SameSite=Strict without a persistent remember-me expiry. Restarting the server invalidates all sessions. At most 256 active sessions are kept; a new successful login can evict the oldest.

Failed attempts use per-origin exponential delays from 1 to 60 seconds. The bounded process-local table retains at most 4096 origins for 15 minutes after an attempt; if full, new origins must wait for entries to expire. Cookies cannot bypass the limit. There is no permanent account lockout. This is a small single-process dashboard, not a distributed authentication service; volumetric attacks still require network controls. A reverse proxy's backend address is the origin for throttling, so clients sharing that proxy share a limit.

### Remote transport and reverse proxy

Built-in password authentication does **not** protect passwords or session cookies from interception over plain HTTP. For remote authenticated use, terminate HTTPS at a trusted reverse proxy or provide an equivalent encrypted transport. Set `secure_cookie = true` when the browser-facing connection is HTTPS. This flag controls browser cookie transport; it does not enable TLS on the dashboard itself. Restrict direct backend access and protect any backend network hop. Password auth does not replace firewall or normal network security controls.

Loopback bindings validate the requested host. Wildcard bindings accept numeric IP host headers and `localhost`, protecting against arbitrary hostname rebinding. For a reverse proxy, forward a numeric backend `Host` header and preserve the application at the URL root. Forwarded host, address and scheme headers are not trusted. A specific hostname binding accepts that hostname. Outbound TLS verification remains enabled. Password configuration affects only the dashboard; core monitoring continues to work without credentials.

Forms use CSRF protection, output is escaped, errors omit sensitive details, and downloads cannot select filesystem paths. Configuration and credential values are not rendered. Report/query operations are synchronous; avoid submitting repeated requests while an investigation is running.

The same SQLite database stores monitoring state and dashboard metadata. Before an upgrade, stop the scanner/dashboard and back up that database. Schema upgrades preserve existing observations and delivery records; an older application requires its corresponding pre-upgrade backup.

## Package identities and advisory views

The manual query page has Product, Package (ecosystem/name/version), and Explicit PURL modes. Each uses the CLI assessment engine and preserves monitoring/event/delivery state. Findings can be filtered by category, system, ecosystem, PURL, advisory ID and CVE alias. Asset and evidence details show supplied identities, aliases and fixed boundaries. Fixed boundaries require review of the branch and source range before choosing an upgrade. Reports include separate Identities and Advisory Details sheets to keep Findings compact. Authentication and CSRF protection apply equally to all query modes.
