# Network requirements

CVEBeacon uses DNS and outbound HTTPS over TCP 443. It does not require inbound access for its CLI workflows.

## Anonymous core vulnerability sources

| Purpose | Destination |
| --- | --- |
| NVD CVE and CPE APIs | `services.nvd.nist.gov` |
| official targeted CVE List V5 records | `raw.githubusercontent.com` |
| ENISA EUVD search and KEV dump | `euvdservices.enisa.europa.eu` |
| CISA KEV JSON | `www.cisa.gov` |
| FIRST EPSS API | `api.first.org` |
| OSV package queries and advisory records | `api.osv.dev` |

These sources require no API key, token or account. Requests carry public vendor/product/version or CPE terms, a supported versionless PURL, ecosystem/package name, an exact supplied commit hash, or advisory/CVE identifiers. Package version comparisons happen locally. OSV repository URLs are compared locally, not fetched. Full CISA/EU KEV catalogs are downloaded without inventory metadata.

Asset IDs, system IDs, categories, owners, comments, hostnames and local paths are never serialized into public vulnerability queries. Only provide public software names in identity fields. Component terms can reveal technologies being investigated. This is agentless monitoring, isolated from monitored assets; live public lookups are not air-gapped operation. Qualified PURLs and subpaths remain local and unsupported for exact lookup.

## Optional credentialed functionality

| Purpose | Destination |
| --- | --- |
| Microsoft Entra app-only token | `login.microsoftonline.com` |
| Microsoft Graph mail | `graph.microsoft.com` |
| Teams Workflow webhook | the tenant-specific HTTPS hostname in the configured webhook URL |

Only enabled features contact their corresponding endpoints. The NVD API key and all Microsoft credentials are optional and are read from environment variables. The Teams webhook URL contains a secret and should be handled like a credential.

When explicitly enabled, notifications send finding summaries, asset IDs, category/system labels and advisory IDs to the configured Teams/email recipient. They are disabled by default and are independent of public vulnerability lookups.

Corporate proxies and TLS inspection can affect certificate validation or outbound access. Configure proxy behavior through the standard environment supported by the HTTP client (`HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`) and install the organization’s trusted CA according to local policy. Do not disable TLS verification.

## Build traffic

Source installation and executable builds may require HTTPS access to the configured Python package index to download declared dependencies and build tools. Runtime source data is not downloaded during deterministic tests.

## Inbound traffic

CLI scans do not open an inbound service. The optional `cvebeacon serve` dashboard listens on `127.0.0.1:8787` without login by default. Built-in single-password authentication is optional, configured through an environment-supplied scrypt hash. Remote binding such as `--host 0.0.0.0` requires either that authentication or the explicit `--allow-unauthenticated-remote` acknowledgment. Configure firewall and access controls before using it.

The dashboard does not terminate TLS. Plain HTTP password authentication exposes credentials and session cookies to on-path interception. Protect remote browser traffic using HTTPS through a trusted reverse proxy or equivalent encrypted transport; enable `[dashboard] secure_cookie = true` for browser-facing HTTPS and restrict direct backend access. Forwarded headers are not trusted, and proxy clients share the proxy origin's login throttle. See the [dashboard guide](DASHBOARD.md) for password generation, expiry, logout and host configuration. Authentication introduces no external account or outbound endpoint.

Dashboard overview/history/findings/source views read local inventory and SQLite state. Manual queries and report generation contact the same enabled outbound sources as the CLI. They do not send notifications. No additional outbound service is required by the dashboard. See [dashboard deployment](DASHBOARD.md) for host-header handling.
