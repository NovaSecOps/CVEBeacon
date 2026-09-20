# Validation

The cross-platform workflow tests Windows Server 2025 and Ubuntu 24.04 on x86-64 with CPython 3.11, 3.12, 3.13, and 3.14. All eight native combinations and both native packaging jobs have passed. Consult the completed workflow results for the commit being deployed; this matrix does not claim support for untested architectures, operating systems, or future Python versions.

Each test job installs the declared dependencies into a clean runner environment, runs `pip check`, and executes:

```console
python tools/test_offline.py -q
python tools/smoke.py
```

The test runner blocks socket connections and DNS before test collection. The smoke checks disable every external source and both notification channels, copy the example inventories to a temporary working directory, and verify startup, configuration, inventory validation, SQLite state, reports, source status, and scheduler generation. An offline scan must report incomplete coverage, rather than success. Separate server smoke checks use only loopback HTTP to test dashboard pages, stylesheets, manual investigation, exports, and monitoring-state isolation, then stop the temporary server. Both unauthenticated localhost and password-authenticated login/logout flows run against source and packaged applications. Offline authentication regressions also cover expiry, cookie replay after logout, CSRF, throttling, host validation, secret non-disclosure, and remote binding controls.

Python 3.12 jobs also exercise a uniquely named native schedule on disposable hosted runners. They check installation, status, removal, and preservation of unrelated entries. These checks do not establish that a deployed machine will execute unattended jobs under its intended account; perform that acceptance check during deployment. The native mutation harness refuses to run outside GitHub-hosted runners.

After all test jobs pass, native packaging jobs build both one-folder and one-file applications with Python 3.13. They run the same isolated smoke checks and inspect the archives for operational data and embedded local application paths. Successful jobs retain platform-specific ZIP or tar archives for 14 days as workflow artifacts. The tar archive preserves Linux executable permissions. These artifacts are validation builds, not published releases.

Dependency installation requires internet access. Normal tests do not require vulnerability-service availability, credentials, or live notification endpoints. Live source acceptance is a separate operation; use `cvebeacon doctor --live` to check enabled sources during deployment.

Generalized-identity tests cover four inventory formats, type-specific PURL case and encoding, ecosystem range boundaries, malformed/partial OSV responses, withdrawals, authoritative aliases, non-CVE findings, source-specific degradation, outbound metadata minimization, transactional schema migration and alert deduplication. CLI and dashboard package/PURL queries and report formula safety run offline; native application smoke includes these query modes with external sources disabled.

For the explicit anonymous live workflow and seven-ecosystem matrix, see [zero-credential acceptance](ZERO_CREDENTIAL_ACCEPTANCE.md). Run it separately from CI and retain failures alongside successful repetitions. Current public source disagreements may legitimately produce `needs_review` at a boundary that one source calls fixed.
