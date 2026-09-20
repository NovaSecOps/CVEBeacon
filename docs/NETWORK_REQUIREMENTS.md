# Network requirements

CVEBeacon uses DNS and outbound HTTPS over TCP 443. It does not require inbound access for its CLI workflows.

## Runtime destinations

| Purpose | Destination |
| --- | --- |
| NVD CVE and CPE APIs | `services.nvd.nist.gov` |
| official targeted CVE List V5 records | `raw.githubusercontent.com` |
| ENISA EUVD search and KEV dump | `euvdservices.enisa.europa.eu` |
| CISA KEV JSON | `www.cisa.gov` |
| FIRST EPSS API | `api.first.org` |
| Microsoft Entra app-only token | `login.microsoftonline.com` |
| Microsoft Graph mail | `graph.microsoft.com` |
| Teams Workflow webhook | the tenant-specific HTTPS hostname in the configured webhook URL |

Only enabled features contact their corresponding endpoints. The NVD API key and all Microsoft credentials are optional and are read from environment variables. The Teams webhook URL contains a secret and should be handled like a credential.

Corporate proxies and TLS inspection can affect certificate validation or outbound access. Configure proxy behavior through the standard environment supported by the HTTP client (`HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`) and install the organization’s trusted CA according to local policy. Do not disable TLS verification.

## Build traffic

Source installation and executable builds may require HTTPS access to the configured Python package index to download declared dependencies and build tools. Runtime source data is not downloaded during deterministic tests.

## Inbound traffic

There is no inbound runtime requirement. CVEBeacon does not include a web dashboard or listening service.
