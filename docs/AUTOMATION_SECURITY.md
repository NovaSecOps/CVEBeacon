# Automation security boundaries

Automation adds optional credential-bearing collectors, receivers and provider
adapters. Core remains independently usable without those packages or credentials.
The baseline Core and Extensions code and v1 deployments are unchanged.
Administrator-owned configuration, executable files, source parents and secret
ACLs are trust inputs. This layer does not sandbox a malicious administrator or
compromised peer with write access to its private state.

| Boundary | Protection and remaining responsibility |
| --- | --- |
| Receiver | Separate config/account/mounts with no Core DB; per-source bearer binding, verified TLS or explicit loopback HTTPS proxy, finite worker/queue/body/deadline/failed-auth tracking. Add maintained ingress admission controls and firewall rules. |
| SSH | Fixed transient probe/argv, explicit key and enrolled known-host file, no shell interpolation/agent/proxy/forwarding/password fallback. Enrollment, remote account authority and package namespace assertions belong to the administrator. |
| Registry | Administrator HTTPS origin/repositories; supplied bearer only, no response-selected token-realm requests, redirects, credential helpers or runtime socket. Exact manifest/artifact/subject/blob hashes bind evidence; hashes and authentication are not vendor attestation. |
| Providers | Reviewed Telegram/Discord/Slack origins or explicit Matrix HTTPS origin; secret references, no redirect forwarding, bounded payloads and persisted provider-aware retry. Selected alert labels leave the host intentionally. |
| Discovery | Disabled by default; explicit numeric targets, allowlist, port/address/fanout/deadline limits and external unprivileged Nmap. Authorization and destination firewalling remain administrator duties. Output is weak observation and never becomes inventory automatically. |
| Core child | Supported CLI, finite subprocess/output/deadline, sanitized environment and no integration credential allowlist overlap. A same-account VM child is trusted code, not an independent filesystem security principal. |
| Kubernetes | Purpose-specific mounts/tokens, namespace pods/list only, scanner with no integration/API credential, notifier on a consistent separate read-only DB copy. Secrets API remains denied. |

Configured origins may be private infrastructure: the product does not contact
origins supplied by an SBOM, registry challenge, Pod annotation, redirect or
provider reply. DNS resolution and HTTPS requests have finite capacity/deadlines;
TLS verifies CA and hostname without environment proxy/SSL key-log settings.
Administrator-origin validation is not DNS pinning or a network sandbox. Enforce
egress policy outside the process when address-level confinement is required.

Parser/record/size/depth budgets, queue/semaphore limits, absolute request and
subprocess deadlines, OS process containment, strict file types and shared locks
bound individual operations. Snapshot freshness, source identity and the frozen
hash contract remain authoritative. HTTP responses and CLI/health errors use
safe fixed categories; exception messages, secret URLs, raw provider replies and
credentials are not retained. Trusted directory ownership remains necessary to
prevent parent-path substitution and concurrent administrator tampering.

The notifier opens supported Core schema3 with read-only/query-only SQL and
uses its own ledger. It does not change Core rows or Teams/email delivery state.
SQLite WAL readers can create transient sidecars on a writable directory;
the Kubernetes deployment makes a consistent DELETE-mode **copy** before its
read-only notifier mount. It never sets `immutable=1` on live WAL. Provider
acceptance is not recipient receipt. Non-idempotent uncertain sends remain
ambiguous and stop automatic replay; no exactly-once claim is made.

Ordinary merged-pair publication failures restore prior bytes. An abrupt crash
between two file replacements can leave an invalid pair; validation fails closed
and accepted generations/backups enable recovery. Retention and rollback are
explicit administrator operations. Independent Core schedules do not participate
in Automation's locks. Live infrastructure installation, schedules, real provider
messages and active discovery must be deliberately authorized by its owner.

WinRM is disabled because secure native Windows remoting acceptance is absent.
External SBOM generation is disabled because the reviewed registry transport
can follow response-selected bearer realms and the required offline image/layer
sandbox has not been implemented. The supported OCI subset, plaintext Matrix
room limitations and Nmap version-script behavior are documented in their guides.
