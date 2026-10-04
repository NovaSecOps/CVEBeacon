# Remote collection

Automation can collect Linux package observations with a user-installed OpenSSH client. It sends a bundled, transient Python probe on standard input, normalizes the returned data locally through the unchanged Extensions v1 collector, and publishes a validated snapshot pair to the source's staging area. The target needs `/usr/bin/python3` and `/usr/bin/dpkg-query` or `/usr/bin/rpm`. Collection does not install software or create target files.

Configure an administrator-approved host and a dedicated account that can read package metadata without elevated privileges. This source fragment belongs in the Automation TOML configuration:

```toml
[[sources]]
id = "linux-example"
kind = "ssh"
required = true
max_age_seconds = 86400
allow_partial = false

[sources.options]
host = "collector.example.test"
user = "collector"
port = 22
known_hosts = "/etc/cvebeacon/ssh/known_hosts"
key = "/etc/cvebeacon/ssh/collector-key"
timeout = 60
backend = "auto"
# Optional administrator assertion after verifying package origin:
# package_namespace = "ubuntu"
```

Run `cvebeacon-auto --config automation.toml run` to collect and stage configured sources, apply source freshness and partial-coverage policy, merge, and invoke the Core scan. A required failed or unacceptable source stops the pipeline before replacing a previous good merged inventory.

The finite SSH options are `host`, `user`, `port`, `known_hosts`, `key`, `timeout`, `backend`, and `package_namespace`. The backend is `auto`, `dpkg`, or `rpm`; the timeout is an integer from 5 to 300 seconds. Paths are explicitly supplied and normalized relative to the configuration file; use absolute paths when possible. Spaces are supported. Token expansions, environment substitutions, links, reparse points, and hard-linked key or host-key files are rejected. On Unix the key must have no group or other permissions, and the host-key file must not be writable by group or other users. Protect the enclosing directories and Windows ACLs yourself; path validation is not an ACL manager.

Enroll the server key independently before enabling collection, and provision the exact hostname or nonstandard-port entry in this one `known_hosts` file. Do not rely on an unauthenticated key scan as proof of server identity. Unknown or changed keys fail collection. The client cannot learn or rotate trusted keys automatically. Hostname use also trusts administrator-selected DNS routing, with server identity still checked against the enrolled key. OpenSSH's [host-key controls](https://man.openbsd.org/ssh_config) describe this trust boundary.

The client uses `-F none`, strict host-key checking, public-key-only authentication, one explicit identity, no agent, no terminal, and no X11 or other forwarding. It disables proxy commands, local commands, host-key commands, connection multiplexing, and ambient SSH configuration. The executable comes from fixed installation directories, not the inherited `PATH` or working directory. Install a current OpenSSH that understands these options; unsupported clients fail without a weaker fallback. The [OpenSSH CLI documentation](https://man.openbsd.org/ssh) documents the `-F none` behavior.

The remote command is the literal `exec /usr/bin/python3 -I -S -B -`; no target, package, version, namespace, or arbitrary command is inserted into it. Python skips site initialization and bytecode writes. OpenSSH still starts the account's configured shell for remote commands, so server-side startup hooks and account configuration remain part of the server's trust boundary. The probe selects only fixed package commands, uses a clean environment, bounds release-file reads and package output, and terminates its package process group after 30 seconds. The local runner bounds output and time and cleans up its own child process tree. Disconnecting cannot guarantee cleanup of deliberately detached descendants on a hostile server. See the [server command execution model](https://man.openbsd.org/sshd).

Returned bytes are untrusted observations. Only a strict versioned JSON envelope is accepted; login banners, malformed UTF-8, duplicate keys, mismatched backends, oversized output, and invalid records fail without replacing the last staged generation. Error categories omit remote output, key paths, and credentials. Snapshot and manifest bytes use the existing v1 identity, freshness, and partial-coverage rules. Reviews are stored alongside the generation under `state_dir/remote/<source-id>/<generation>.review.json`.

Without an explicit `package_namespace`, Linux package origins remain review items and the manifest records omissions. The collector does not infer a trusted repository namespace from an operating-system label. Supply the namespace only after independently verifying that assertion; setting `allow_partial = true` accepts documented omissions without resolving their uncertainty.

## Windows and WinRM

WinRM collection is disabled: `winrm` is not a supported source kind, and the placeholder backend fails before credential or network use. Secure native WinRM acceptance is not established. There is no Basic-over-HTTP, TrustedHosts wildcard, certificate-check bypass, or insecure CI fallback.

Use the existing local Windows collector and authenticated TLS ingestion instead:

```powershell
cvebeacon-ext collect windows --source-id windows-example --output snapshot.json
cvebeacon-auto ingest push snapshot.json --endpoint https://receiver.example.test/v1/snapshots --secret-env CVEBEACON_UPLOAD_TOKEN
```

The configured receiver must authorize that source ID and validate the paired manifest. For a private CA, use `--ca-file` with its explicitly trusted certificate. The token is resolved only by the push stage; keep its value out of command lines and configuration. Local Windows observations still retain the v1 collector's identity and review limits.

A future WinRM implementation must demonstrate server identity and transport protection with native tests. Microsoft describes [Kerberos/NTLM protection and authentication limits](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security?view=powershell-7.6) and the [certificate requirements for WinRM HTTPS](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/configure-winrm-for-https). Adding a backend requires new validation; enabling it by weakening those requirements is outside this version's support.

## Validation boundary

Offline tests exercise hostile configuration, key-file safety, fixed argv and stdin, sanitized subprocess wiring, malformed observations, review omissions, and preservation of prior staging. `automation/tools/native_remote_discovery.py` supplies the native Linux acceptance gate: a disposable CI runner, generated fixture keys, a high-port SSH server bound only to loopback, enrolled-key success, and wrong or unknown host-key rejection. It refuses to run outside that CI context. This gate does not certify an owner's server, package repository, or account permissions.
