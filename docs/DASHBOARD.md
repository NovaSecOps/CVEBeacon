# Dashboard

Launch from the directory containing your configuration, or provide an explicit path:

```console
cvebeacon --config /absolute/path/cvebeacon.toml serve
```

The default address is `http://127.0.0.1:8787`. Windows packages use `cvebeacon.exe serve`; Linux packages use `./cvebeacon serve`. The server prints its listening address after binding successfully. No development or debugging console is enabled.

To select a port or deliberately bind to the LAN:

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

Local use requires no login. The dashboard has no built-in authentication; every client that can reach it can read observations and initiate manual queries or reports. Non-loopback binding prints a warning that the deployer controls network access. Use firewall rules and, where appropriate, an authenticated TLS reverse proxy. Do not expose an unauthenticated instance to the public internet.

Loopback bindings validate the requested host. Wildcard bindings accept numeric IP host headers and `localhost`, protecting against arbitrary hostname rebinding. For a reverse proxy, forward a numeric backend `Host` header; forwarded host headers are not trusted automatically. A specific hostname binding accepts that hostname. Outbound TLS verification remains enabled.

Forms use CSRF protection, output is escaped, errors omit sensitive details, and downloads cannot select filesystem paths. Configuration and credential values are not rendered. Report/query operations are synchronous; avoid submitting repeated requests while an investigation is running.

The same SQLite database stores monitoring state and dashboard metadata. Before an upgrade, stop the scanner/dashboard and back up that database. Schema upgrades preserve existing observations and delivery records; an older application requires its corresponding pre-upgrade backup.
