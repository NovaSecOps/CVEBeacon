# Component identity and advisory history

Legacy `asset_id`, `vendor`, `product`, `version` inventories continue to work in CSV, XLSX, JSON and YAML. Advanced fields are optional and use the same `[inventory.columns]` mapping. `asset_id` uniquely identifies one component record; `system_id` optionally groups components. Free-form `category` and system labels organize views, reports, and notifications. Neither affects applicability or source queries.

| Path | Supplied fields | Evidence |
| --- | --- | --- |
| Product | vendor, product, version | Existing CPE/NVD/CVE/EUVD assessment |
| PURL | purl, optionally separate version | Exact package identity and OSV |
| CPE | complete cpe, optionally separate version | Explicit CPE outranks discovery; qualifiers retained |
| Package | ecosystem, product (package name), version | OSV ecosystem identity |
| Commit | HTTPS repository and full commit hash | OSV exact commit membership with matching repository evidence |

Precedence is PURL, CPE, ecosystem, commit, then product. Contradictory versions or package names fail validation. Supplying CPE with PURL/ecosystem, or commit with another strong identity, requires review: similar names do not establish equivalence. Categories never resolve a conflict. Repository names alone are not commit identities.

Use `inventory inspect` to see source headers and samples, then `inventory validate --identities` to see each selected path. Versions must be literal text. Numeric/date/boolean values, formulas, control characters, and duplicate asset IDs are rejected. Package spelling is preserved according to ecosystem rules; there is no universal lowercasing. PyPI uses its normalized-name convention; Maven and Go retain case; npm preserves grandfathered mixed-case names; NuGet comparisons ignore case.

Examples (these versions are demonstration inputs, not upgrade recommendations):

```console
cvebeacon query --ecosystem PyPI --product requests --version 2.31.0
cvebeacon query --purl pkg:npm/lodash@4.17.20
cvebeacon query --ecosystem Maven --product org.apache.logging.log4j:log4j-core --version 2.14.1
cvebeacon query --cpe "cpe:2.3:a:apache:guacamole:1.3.0:*:*:*:*:*:*:*"
```

See `examples/general-inventory.csv` and `examples/general.toml`. The default column names automatically recognize optional fields. A PURL can supply its version; a versionless PURL without a separate version requires review. PURL qualifiers and subpaths are parsed and preserved locally, but currently cannot establish exact OSV lookup identity and return `coverage_unknown` without transmitting the PURL. Supported lookup PURL types are pypi, npm, maven, golang, cargo, nuget, gem, and composer. Other valid types remain unknown. Unknown ecosystems or unsupported version schemes also remain explicit uncertainty.

OSV package queries retrieve package-wide advisories, then evaluate version evidence locally. This avoids treating OSV's fuzzy version matching as proof. SEMVER is used only when declared by the source; ECOSYSTEM ranges use supported ecosystem rules (PyPI, npm, Go, crates.io, Maven, NuGet, Debian and selected RPM distributions). Epochs/revisions use distro ordering. Unsupported schemes, incomplete/malformed events, and Git graph comparisons without exact source membership require review. Version lists can affirm inclusion; absence from an incomplete list cannot prove exclusion. `fixed`, `last_affected`, and `limit` boundaries retain their distinct meanings. Fixed boundaries in reports are source evidence, not a universal safe-upgrade recommendation.

Advisories have a primary ID, optional CVE ID, authoritative aliases and source IDs. Only explicit alias relationships merge records; similar descriptions and `related` references do not. CVE aliases enable existing CVE/KEV/EPSS enrichment without claiming CPE equivalence. Withdrawn records require review. Zero returned advisories never means clean.

State schema 3 adds a transactional alias index to schema 1/2 databases. Historical rows, events, timestamps, scan activity and delivery records remain intact. A later CVE alias keeps the existing monitoring identity; alias-only updates do not create alerts. Existing legacy fingerprints stay compatible. Back up the stopped database before upgrading; roll back using the matching application and backup, not by deleting state. The internal legacy SQLite `cve_id` column also stores non-CVE primary IDs. Public JSON exposes `advisory_id`, nullable `cve_id`, `aliases`, `source_ids`, and `fixed_versions`.

Required sources depend on identity. OSV failure makes package coverage unknown; optional NVD enrichment failure does not erase valid package evidence. OSV is not queried for generic/CPE assets. Incomplete refreshes retain historical findings with original observation times; disappearance never silently resolves an advisory.
