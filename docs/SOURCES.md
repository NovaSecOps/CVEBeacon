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

The `cve_list` provider uses only the official
[CVEProject/cvelistV5 release assets](https://github.com/CVEProject/cvelistV5#releases).
It does not read `cves/deltaLog.json`. The cursor is the UTC boundary of the
last archive that was fully imported, except during baseline initialisation,
where the newest available boundary is stored without importing an archive.

- **Same day:** import the newest hourly cumulative delta archive for the
  current release (`YYYY-MM-DD_delta_CVEs_at_HHMMZ.zip`). It contains every
  change since midnight. Imports are idempotent by CVE ID and `dateUpdated`, and
  never replace a newer stored revision with an older one.
- **Each past day:** import that day's official closed-day cumulative delta from
  the separate `cve_YYYY-MM-DD_at_end_of_day` release, asset
  `YYYY-MM-DD_delta_CVEs_at_end_of_day.zip`. It is published shortly after the
  following day's 00:00 hourly release and can itself appear as GitHub's
  `releases/latest`. The sync never trusts `/latest`: it lists a bounded set of
  recent releases and selects the newest hourly release by its archive names and
  UTC time; draft and prerelease entries are ignored. Each archive is read
  independently, so an omitted or stale upstream index cannot hide a record. A
  sync between the 00:00 release and the end-of-day
  tag publication fails closed with the cursor unchanged and retries; daily
  schedules should avoid the short 00:00–00:45 window.
- **Missing archive or long gap:** if a required end-of-day archive is absent,
  or more than seven days are outstanding, read one baseline archive instead.
  It streams in bounded batches; records at or after the cursor are stored, so
  a boundary record is re-offered idempotently. Catch-up continues from the
  baseline's published midnight time. A
  baseline that does not advance past the cursor fails clearly and leaves the
  cursor in place.
- **Failure:** the cursor advances only after the whole archive has been
  validated and committed. Any download, integrity or record failure leaves the
  previous cursor, and the next sync retries the same archives. Completed
  batches are replayed idempotently.
- **Initial modes** apply only to the first initialisation, before any cursor
  exists. `baseline` stores the newest hourly archive boundary as the cursor
  without importing or alerting on anything older. `backfill N` imports records
  whose `dateUpdated` is inside the saved window, as initial and non-alerting;
  records with no usable `dateUpdated` are also imported as initial. It then
  stores the newest boundary. `full` imports all records as initial and
  non-alerting, then stores the newest boundary. Adding this provider to an
  existing installation defaults to baseline even when the old
  `watch.initial` says `full` or `backfill`. History requires an explicit
  confirmed choice.
- **After initialisation** the initial mode is never consulted again. Every
  hourly delta, end-of-day delta and gap-fallback baseline imports records whose
  `dateUpdated` is at or after the cursor as normal changes that can alert.
  Records before the cursor are skipped as already known; a record stamped
  exactly on the boundary is re-offered idempotently, so it is neither lost nor
  alerted twice. Records with a missing or unparseable `dateUpdated` are always
  imported and counted, regardless of `dateReserved` or `datePublished`; they
  are never silently skipped. When both observations have a valid
  `dateUpdated`, the newer date wins; when either lacks one, the observation
  fetched most recently wins. The fallback baseline therefore fills exactly the
  outstanding interval and is complete by construction.
- **Manual refresh:** `watch refresh` never changes the feed cursor, archive
  token or initial state.

Conditional requests avoid re-reading an unchanged release list, and an unchanged
archive token is skipped. The real baseline may end in `.zip.zip` and
wrap `cves.zip`; both published forms are supported. A 00:00 release with
yesterday's baseline and today's empty delta is valid. Visible published,
rejected and reserved records are stored.

For cost context, public release metadata read on 2026-11-19 advertised a
665,939,820-byte baseline (about 635 MiB) and a 4,551,306-byte 23:00 delta
(about 4.34 MiB). These sizes vary. A routine same-day sync transfers release
metadata and at most the current cumulative delta. A midnight or multi-day
catch-up transfers one closed-day archive per outstanding day, up to seven. A
daily 635 MiB baseline would cost about 226 GiB/year; this design does not
download one in normal operation. Only a first history import, an explicit
history reset, a missing archive or a gap longer than seven days pays that
larger bounded cost.

Downloads use shared HTTP timeouts, retries and pacing. Release and tag metadata
are limited to 4 MiB, each compressed archive to 1 GiB, expanded members to
8 GiB, each record (including targeted refresh) to 4 MiB, and entries to one
million. ZIP/ZIP64 preflight validates the exact directory range, member count,
expanded sizes and a 64 MiB directory-byte cap. Ambiguous prefixed layouts are
rejected. Directory entries are then read one at a time; there is no full
`ZipInfo` index. Duplicate detection uses temporary disk storage. Batches contain
at most 100 records and 8 MiB of serialized JSON (one bounded record may exceed
the remaining batch space). Decoded JSON and tokenizer objects add overhead to
these byte budgets, but no global ID queue or whole-log object graph is built.
Published size, SHA-256 when supplied, CRCs and file/record identities are
checked. Redirects require HTTPS, an exact GitHub asset host, default TLS port
and at most three hops. No archive paths are extracted.

Archive caches, duplicate indexes and an optional inner ZIP live beside state,
not in an implicit RAM-backed directory. Preflight checks compressed space,
then the inner archive and expanded directory before import. It reserves three
times expanded bytes for provider/search/index/transaction growth, four times
directory bytes for temporary indexes, plus 64 MiB. Space is rechecked for each
batch. This is a storage estimate with a 2x margin over the expanded archive,
not a guarantee against another process filling the disk; a large baseline can
still require several GiB of free space. Only one compressed cache is retained.
A validation or parse failure discards it; the next bounded attempt downloads
it again.
An interrupted body restarts without HTTP Range; pre-body retries use the shared
bounded policy. The limit is **per archive**, not aggregate: an ordinary
midnight sync can transfer the closed-day archive and current delta (up to
2 GiB), and a seven-day catch-up can transfer up to eight archive bodies (up to
8 GiB) besides metadata. A baseline fallback adds its own bounded transfer.
Database batches are idempotent; completed bytes may be reused, and a failed or
unfinished import never advances its cursor.

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
