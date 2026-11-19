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

### CVE List watch feed

The `cve_list` provider uses the official
[CVEProject/cvelistV5 release assets](https://github.com/CVEProject/cvelistV5#releases)
and repository `cves/deltaLog.json`. Ordinary updates use the hourly cumulative
delta ZIP, with conditional release metadata and unchanged-asset detection.
**There is no daily full-baseline download.**

Across midnight or a longer gap, the rolling log proves continuity from the
cursor. A durable queue coalesces changed CVE IDs. Cheap daily delta archives
cover most queued IDs before any remaining records are fetched individually.
Archive size is compared with an 8 KiB-per-record lookup estimate; a large ZIP
is skipped when targeted requests are cheaper. At most three archived-day
metadata lookups and 100 remaining record lookups are processed per run, with
progress retained between runs. Ordinary same-day syncs do not download the
rolling log. This combines the small hourly archive with the log's complete
cross-midnight coverage, without one lookup for every historical change.

A full baseline is used only for an initial `backfill`/`full` import or when the
stored cursor predates the log's retained coverage. A new provider on an existing
installation defaults to no history; history requires an explicit confirmed
choice. The real baseline name may end in `.zip.zip` and wrap `cves.zip`. The
00:00 release may contain yesterday's baseline and today's empty delta. That
combination is valid: the log repairs the intervening changes, and an empty
midnight delta never advances the cursor past unprocessed records.

For cost context, public metadata read on 2026-11-19 advertised a
665,939,820-byte baseline (about 635 MiB), a 4,551,306-byte 23:00 delta
(about 4.34 MiB), and a 30,777,380-byte rolling log (about 29.35 MiB).
Only metadata was read to establish these figures. These sizes vary. A daily
635 MiB baseline would cost about 226 GiB/year before deltas; this implementation
does not incur that recurring baseline cost. A first history import or genuine
retention gap can still require that one large download.

Downloads use shared HTTP timeouts, retries and pacing. Release metadata is
limited to 4 MiB, the rolling log to 64 MiB, a compressed archive to 1 GiB,
expanded members to 8 GiB, a record to 4 MiB, and entries to one million. Before
`ZipFile` allocates directory objects, an independent scan validates ZIP/ZIP64
counts, each directory entry, the expanded-size sum and a 64 MiB central-directory
cap. Bodies stream in batches of 100 records. Published size, SHA-256 when
supplied, ZIP CRCs and record/file identities are checked. Redirects require
HTTPS, an exact GitHub asset host, the default TLS port and at most three hops.
No archive paths are extracted.

Archive caches and the optional inner ZIP live beside the state database rather
than in an implicit RAM-backed temporary directory. Preflight reserves two
archive sizes plus 64 MiB of free space; allow additional space for new provider
data and indexes. Only one compressed cache is retained. Completed downloads
are reused for parsing retries. A partial network download restarts from zero,
bounded to one archive of at most 1 GiB per sync; retries before any body arrives
use the configured bounded HTTP policy. Database batches remain idempotent and
no failed or unfinished repair advances its cursor.

CNA/ADP records retain descriptions, affected products, metrics, references,
dates and visible published/rejected/reserved states. NVD keeps status and
description precedence and every populated NVD field. Active CVE List data fills
missing fields or supplies a CVE List-only record. Disabling a provider removes
its evidence from rules and filters while retaining it for provenance. Later
NVD publication uses the existing CVE event identity, preventing a second initial
match. CVE List initialization has independent progress and initial-digest marks;
its failure is degraded coverage and cannot hold NVD/EUVD initialization open.

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
