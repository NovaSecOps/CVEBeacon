# Vulnerability data sources

CVEBeacon uses primary public sources with distinct roles. Source coverage is not universal, and a missing record is not proof that a product is unaffected.

All vulnerability sources below support anonymous core access. The optional NVD key improves pacing; no GitHub token is used to fetch public CVE records.

## Open Source Vulnerabilities (OSV)

- Purpose: exact package/ecosystem and repository/commit evidence, including advisories without CVEs.
- Interfaces: anonymous [OSV API](https://google.github.io/osv.dev/api/), `POST /v1/querybatch` and `GET /v1/vulns/{id}` at `api.osv.dev`; authoritative [OSV schema](https://ossf.github.io/osv-schema/).
- Package-wide queries omit version and retrieve complete records for local applicability assessment. Batches preserve response order and per-query pagination. Partial failures and bounded pagination limits remain visible as degraded coverage.
- Explicit aliases group advisories; related/upstream IDs alone do not. Withdrawn or conflicting claims require review. CVE aliases use existing sources for enrichment; NVD absence does not invalidate exact OSV evidence.
- Exact commit queries rely on source graph membership and a matching supplied repository. No local commit inference or repository download occurs.
- Limitations: unsupported ecosystems/ranges, qualified PURLs and uncertain identities do not become exclusions. OSV is an aggregator; original ranges, source IDs, references, timestamps and provenance remain available in Evidence. See [identity and version behavior](IDENTITY.md).

PURLs use maintained [packageurl-python](https://github.com/package-url/packageurl-python) parsing and registered [Package URL type definitions](https://github.com/package-url/purl-spec). Ecosystem comparisons use declared semantics and [univers](https://github.com/aboutcode-org/univers) where appropriate, not universal SemVer.

## NIST National Vulnerability Database

- Purpose: generic product identity through CPE, CVE discovery, applicability statements, and CVSS enrichment.
- Interfaces: [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) and [NVD CPE APIs](https://nvd.nist.gov/developers/products).
- Data used: CPE names, match criteria, configurations, CVE metadata, affected data, and attributed CVSS metrics.
- Limitations: the CPE Dictionary and NVD enrichment are incomplete. Product ambiguity, missing CPE data, deferred enrichment, and source failure are reported as uncertainty rather than clean results.

This product uses data from the NVD API but is not endorsed or certified by the NVD.

## CVE Program

- Purpose: canonical CVE records and an independent applicability cross-check.
- Interface: [official CVE List V5 repository](https://github.com/CVEProject/cvelistV5) and [CVE Record Format](https://cveproject.github.io/cve-schema/).
- Data used: CVE state, CNA and ADP containers, descriptions, affected products and versions, metrics, and references.
- Limitations: records are supplied by many authorities and vary in completeness and version syntax. Unsupported or conflicting version semantics require review.

## ENISA European Vulnerability Database

- Purpose: independent European vulnerability data, vendor/product evidence, enrichment, and EU Known Exploited Vulnerabilities status.
- Interfaces: [EUVD](https://euvd.enisa.europa.eu/) and [EUVD API documentation](https://euvd.enisa.europa.eu/apidoc).
- Data used: CVE aliases, descriptions, dates, vendor/product/version evidence, CVSS data, references, exploitation information, and the consolidated KEV dump.
- Limitations: product-version strings may be descriptive rather than safely machine-comparable. EUVD evidence does not replace exact applicability evidence.

## CISA Known Exploited Vulnerabilities

- Purpose: identify vulnerabilities with evidence of exploitation in the wild.
- Interface: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Data used: CVE ID, date added, vendor/product, required action, due date, ransomware-use indicator, and notes.
- Limitations: absence from KEV does not mean a vulnerability is not exploited or not important.

## FIRST Exploit Prediction Scoring System

- Purpose: add a daily probability estimate for exploitation prioritization.
- Interfaces: [EPSS](https://www.first.org/epss/) and [EPSS API](https://api.first.org/epss/).
- Data used: score, percentile, and score date.
- Limitations: EPSS is predictive and changes regularly. It is not evidence of known exploitation and is not used as exact applicability evidence.

## Microsoft notification services

- Teams: [webhooks through Teams Workflows](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook).
- Email: [Microsoft Graph sendMail](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0) with [app-only authentication](https://learn.microsoft.com/en-us/graph/auth-v2-service).
- Limitations: an HTTP 202 from Graph means the request was accepted for processing, not that final mailbox delivery is proven.

### CVE List watch feed

The `cve_list` watch provider reads the official
[CVEProject/cvelistV5 release assets](https://github.com/CVEProject/cvelistV5#releases):
a daily baseline and an hourly delta cumulative since that baseline. Release
metadata uses conditional ETag requests. An unchanged archive is not downloaded
again. After a day change or a gap, the next daily baseline closes the gap before
the current delta is applied. This avoids relying on the rolling retention of
`deltaLog.json` or issuing a request for every historical CVE.

Downloads use the shared HTTP timeouts, retries and pacing. Release metadata is
limited to 4 MiB, each compressed archive to 1 GiB, total expanded members to
8 GiB, individual records to 4 MiB, and archive entries to one million. Archives
are spooled to temporary disk and records are imported in batches of 100. The
published size and SHA-256 digest (when supplied by GitHub), ZIP CRCs and
record/file identifiers are checked. The baseline's optional `cves.zip` wrapper
is supported without extracting paths. Redirects are limited to GitHub's release
asset hosts. Failures preserve committed batches and never advance the failed
archive's cursor; retries replay those batches idempotently.

The first `full` import and each new daily baseline may download hundreds of MiB
(up to the 1 GiB cap), requiring temporary disk for the archive and possibly its
inner ZIP, plus the watch database and indexes. `backfill` reads the same archive
but imports only records modified in its configured window. `baseline` initially
records a starting point without a download. Later imports keep changes since
the cursor, with the configured overlap. This trades a daily archive download
for complete recovery across gaps. A source failure remains visible; no partial
archive is described as complete.

CNA and ADP containers remain stored with their descriptions, affected products,
metrics, references and dates. Published, rejected and visible reserved records
are kept. CVE List-only records enter the same rule and event history as NVD
records; later NVD enrichment does not create a second initial match.
