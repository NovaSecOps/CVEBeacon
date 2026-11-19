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

Across midnight or a longer gap, the rolling log supplies **hints, not proof of
completeness**. A durable queue retains each ID's expected record revision and
its latest log observation. Every accepted current or archived daily delta is
read independently, including records omitted from the log. At most three
archived-day metadata lookups and 100 remaining record lookups run per sync.
A body only acknowledges a logged revision when its normalized `dateUpdated`
matches; a stale or unverifiable body stays queued. Revision selection follows
log observation order, allowing upstream record dates to be corrected backwards.
Archive ordering is tracked separately from those content dates.

The daily deltas do not prove the final interval between yesterday's 23:00
release and the baseline reset. Even an apparently complete log cannot prove
that interval. Its cursor therefore stays pinned and coverage remains degraded;
verified records and subsequent daily deltas can still be imported. The source
status explains how to repair it with an explicit confirmed
`watch sync --cve-list-initial full --yes` (omit `--yes` for an interactive
confirmation). A gap outside log retention also uses a bounded full-snapshot
fallback. There is no automatic daily baseline download. The cursor never moves
backwards or beyond the last independently processed archive boundary.

A full baseline is used for initial `backfill`/`full` history or a gap repair.
Adding this provider to an existing installation defaults to no initial history;
history requires an explicit confirmed choice. Routine cumulative deltas may
include earlier changes from that same day; record dates are not safe filters
for repository revision order. The real baseline may end in `.zip.zip` and wrap
`cves.zip`. A 00:00 release with yesterday's baseline and today's empty delta is
valid, but does not itself close an outstanding midnight interval.

For cost context, public metadata read on 2026-11-19 advertised a
665,939,820-byte baseline (about 635 MiB), a 4,551,306-byte 23:00 delta
(about 4.34 MiB), and a 30,777,380-byte rolling log (about 29.35 MiB).
Only metadata was read to establish these figures. These sizes vary. A daily
635 MiB baseline would cost about 226 GiB/year before deltas; this implementation
does not incur that recurring baseline cost. A first history import or genuine
retention gap can still require that one large download.

Downloads use shared HTTP timeouts, retries and pacing. Release metadata is
limited to 4 MiB, the rolling log to 64 MiB, each compressed archive to 1 GiB,
expanded members to 8 GiB, each record (including targeted refresh) to 4 MiB,
and entries to one million. ZIP/ZIP64 preflight validates the exact directory
range, member count, expanded sizes and a 64 MiB directory-byte cap. Ambiguous
prefixed layouts are rejected. Directory entries are then read one at a time;
there is no full `ZipInfo` index. Duplicate detection uses temporary disk storage.
Batches contain at most 100 records and 8 MiB of serialized JSON (one bounded
record may exceed the remaining batch space). The per-run changed-ID summary
also has a 16 MiB accounted-memory budget; reaching it retains committed progress
for replay. Decoded JSON and tokenizer objects add overhead to these byte budgets.
Published size, SHA-256 when supplied, CRCs and file/record identities are checked.
Redirects require HTTPS, an exact GitHub asset host, default TLS port and at most
three hops. No archive paths are extracted.

Archive caches, duplicate indexes and an optional inner ZIP live beside state,
not in an implicit RAM-backed directory. Preflight checks compressed space,
then the inner archive and expanded directory before import. It reserves eight
times expanded bytes for provider/search/index/transaction growth, four times
directory bytes for temporary indexes, plus 64 MiB. Space is rechecked for each
batch. This is a conservative storage estimate, not a guarantee against another
process filling the disk. Only one compressed cache is retained. A validation
or parse failure discards it; the next bounded attempt downloads it again.
An interrupted body restarts without HTTP Range; pre-body retries use the shared
bounded policy. The limit is **per archive**, not aggregate: a history/fallback
sync can transfer a baseline and current delta (up to 2 GiB), and retained-log
repair can transfer the current plus three archived deltas (up to 4 GiB), besides
bounded metadata/log/record requests. Database batches are idempotent; completed
bytes may be reused, and unfinished or unproven repair never advances its cursor.

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
