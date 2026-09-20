# Live zero-credential acceptance

Normal CI is deterministic and blocks external connections. Live acceptance is a separate, explicit operation against public services whose availability and records change. Use only public synthetic component names and a new local output directory. Never point this procedure at production state or enable notifications.

Run the opt-in harness from a source installation:

```console
python tools/live_acceptance.py --allow-network --output reports/live-acceptance-001
```

The harness starts a child with an allowlist of essential OS environment variables. NVD keys, Teams/email credentials, dashboard hashes, GitHub tokens, proxy credentials and other inherited secrets are absent. It creates its own configuration, public inventory and SQLite database with all public sources enabled and notifications disabled. It records command outputs and current source evidence; an existing output directory is rejected to preserve earlier evidence.

The workflow validates inventory, runs product and PURL queries, performs a monitoring scan, checks SQLite integrity/history/delivery state, writes JSON and XLSX reports, reads source health, tests localhost dashboard pages, and generates both native scheduler proposals without installing them. Manual queries and dashboard reads must preserve the monitoring database. Exit code 4 from a scan is retained as an incomplete-coverage observation, never relabelled clean. Source failures are reported separately from functional assertions.

The package matrix checks current anonymous OSV records across PyPI, npm, Maven, Go, crates.io, NuGet and Debian. For each selected source range, test an affected version and its exact fixed boundary. Record advisory IDs, aliases, source timestamps and actual decisions. Include a non-CVE record when available, invalid identity rejection and unresolved identity behavior. A fixed result applies to that advisory and range, not the whole component's security status.

General software samples exercise a network appliance, operating system, infrastructure, server application, Samba and database using the same generic engine. Some public identities or custom versions may require review; preserve that uncertainty. Do not add product-specific production logic to make examples pass.

Review the resulting evidence before acceptance. A failed service call is not proof that integration works; repeat in a new versioned directory after diagnosing it. A successful HTTP response alone is not proof of exact applicability. Keep raw returned evidence alongside the decisions and distinguish source availability, application behavior, and coverage limitations.
