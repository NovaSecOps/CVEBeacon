# Reproduce the synthetic Automation lifecycle

The offline demo exercises ingestion, SSH observations, Kubernetes registry evidence, inventory merge, Core reconciliation/state, four notification adapters and discovery history. Every asset, advisory, credential and response is synthetic. It opens no socket, executes no SSH/Nmap command and sends no external message.

From a checkout with the Core/Extensions/Automation dependencies installed, run:

```console
python automation/tools/lifecycle.py --output .private/automation-lifecycle-demo-1
```

Use a new or empty output directory. Existing evidence is refused. The command asserts each transition, writes an inspectable staging tree, real Core SQLite state, independent notification/discovery state and `summary.json`, and prints the machine-readable summary. A failed assertion leaves its synthetic evidence for diagnosis and never writes a successful summary.

The same harness runs in `automation/tests/test_lifecycle.py`. The tests compare two complete runs for deterministic summaries, verify context/environment restoration, refuse an existing evidence directory and inject an unexpected socket attempt to confirm it cannot proceed to Core.

## What the fixture proves

| Step | Asserted result |
|---|---|
| Uploaded host | Real receiver authenticates one synthetic source credential, accepts exact snapshot envelope bytes; exact repeat is idempotent, older replay is rejected |
| SSH host | Real fixed argv/host-key options, probe protocol validation, frozen Linux normalization and staging; explicit fake subprocess result supplies one OS and one Debian package |
| Kubernetes image | Projected v1 observation identifies an exact running digest; real registry client verifies target/referrer/artifact/empty-config/SBOM bytes through finite synthetic HTTPS responses; frozen SBOM importer/enrichment creates one component |
| First pipeline | Three source snapshots merge into four assets; real Core QueryEngine discovers one synthetic OSV advisory and enriches its CVE alias with synthetic NVD CVSS7.5; StateStore creates one material event; all four adapters attempt one accepted send |
| Unchanged pipeline | Three sources refresh; Core records a second scan with no new event; no provider send is attempted |
| Material change | Synthetic NVD CVSS changes7.5→9.8; StateStore creates one changed event; exactly four new provider sends are attempted |
| Notification outage | Separate operational digest gets one Slack429 and three accepted providers; retry state survives ledger reopening; fake clock advances past backoff and exactly one Slack retry succeeds |
| Missing SBOM | Supported empty Referrers result is explicit; previously accepted Kubernetes source pointer remains unchanged |
| Stale required source | Fake clock advances; pipeline stops before Core, preserves exact previous merged pair and Core database |
| Missing required source | Missing input produces a distinct failure; no Core call or previous inventory/database change |
| Discovery | Real bounded Nmap XML parser and discovery history record one weak service/CPE observation, no change on repeat, then one service change; merged inventory and Core DB stay unchanged |

Core writes happen through `QueryEngine.scan` and `StateStore.record_scan`. The demo never inserts vulnerability events through direct SQL. Read-only SQLite queries inspect the evidence. Automation uses its separate delivery ledger and leaves Core's deliveries table empty.

The only advisory is an explicitly invented fixture (`LIFECYCLE-SYNTHETIC-2099-1`, alias `CVE-2099-0001`). Its affected-package/version claim and CVSS values come from the synthetic source responses. They assert no fact about real software or a real advisory.

## Coverage remains visible

Only the uploaded package has sufficient synthetic affected-package evidence. The Linux OS/package and container package retain `coverage_unknown`. All three completed scans therefore return Core exit4 and Automation health `coverage_warning`. Operational completion and accepted notifications do not imply vulnerability-free inventory.

Operational notifications are counted separately from vulnerability events. Final totals are three Core scans, two material events, eight event provider attempts, five operational provider attempts (including one retry), twelve accepted Automation delivery rows and zero Core delivery rows. There are zero actual network calls and no real credentials.

## Fixture versus native authority

The demo blocks socket construction, connect/send/listen/bind and DNS entry points. It replaces only transport/time boundaries, then runs real product validation, staging, merge, reconciliation, persistence and rendering logic. Its Core API call temporarily uses the sanitized environment; synthetic integration credentials are unavailable to that scanner and absent from all written artifacts. The fake clock controls snapshot freshness and provider backoff without waiting.

It does not prove actual TLS, SSH host authentication, a deployed registry, Nmap service detection, OCI runtime confinement or Kubernetes RBAC. Those are separate acceptance tools and CI jobs: `local_protocol.py`, `local_notifications.py`, `native_remote_discovery.py`, `native_registry.py`, `container_acceptance.py` and `kubernetes_acceptance.py`. Their own actual results establish native evidence; a passed lifecycle summary does not upgrade a fixture into native proof.

The ingestion receiver is called through its authenticated envelope API without starting a listener. SSH uses inert invalid key/known-host files and a clearly marked fake result; they cannot be reused as credentials. Registry responses contain an existing synthetic attached SBOM and never generate one or contact a challenge realm. Notifications use valid provider payload code and fake provider replies, including Matrix encryption-state checking. Discovery consumes only synthetic loopback XML, never probes that address.

The output contains synthetic inventory, raw SBOM/provenance and monitoring history. Keep it as reproducible evidence or choose a separate new directory for another run. No owner environment, scheduler, registry, cluster, host or provider account is configured by this command.
