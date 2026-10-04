# Secure snapshot ingestion

The optional receiver accepts Extensions v1 inventory and manifest pairs. It
does not collect packages, run scans, open Core SQLite, access reports or load
notification/registry credentials. Run it with its separate
[receiver configuration](../automation/examples/cvebeacon-ingest.example.toml):

```console
cvebeacon-auto --config /etc/cvebeacon/ingest.toml ingest serve
cvebeacon-auto ingest push host.json --endpoint https://inventory.example.invalid/v1/snapshots --secret-file /run/secrets/host-upload-token
```

Create a separate long random token (at least 32 ASCII characters) for each
source. References use `credential = {env = "HOST_UPLOAD_TOKEN"}` or a
restricted secret file. A credential authorized for `host-a` cannot upload a
pair whose manifest identifies `host-b`. Constant-time comparison checks the
bearer credential. Neither credentials nor provider errors appear in replies,
health or request logs. Credentials never travel in query strings.

Protocol version 1 is `POST /v1/snapshots`, `Content-Type: application/json`,
`Authorization: Bearer <secret>` and `X-CVEBeacon-Source: <source-id>`. The exact
body keys are `version` (integer 1), `source_id`, `inventory_b64` and
`manifest_b64`. Both base64 strings preserve the original bytes. Extensions
validates hash, identity, records, status and original freshness. Unknown keys,
duplicate JSON/header keys, invalid base64, corrupt/truncated sides, compression
and transfer encoding are rejected.

Default binding is `127.0.0.1:8765`. Authentication is mandatory even on
loopback. For direct remote binding, set `certificate` and `key`; startup
validates the certificate/key pair and TLS 1.2 or newer is required. Push always
verifies the server certificate/hostname; `--ca-file` supports a private CA.
There is no insecure push switch and redirects are rejected.

For a trusted HTTPS reverse proxy, bind the receiver only to loopback and set
`proxy_https = true`. The administrator must restrict the receiver port and
configure proxy TLS, body/connection/rate limits and authentication-header
forwarding. Forwarded headers are ignored; they cannot assert secure transport
or client identity. A proxy on another machine must use the receiver's direct
TLS option. The receiver is an isolated reference service; expose it through a
maintained HTTPS proxy with additional admission limits for production.

The default request limit is 12 MiB, with an explicit configurable maximum of
48 MiB (base64 expansion included); inventory is at most 32 MiB and manifest at
most 64 KiB. Two request workers, eight queued connections and a 15-second total
request/handshake deadline bound fanout and slow clients. Ten failed
authentication attempts per peer per minute trigger a temporary rate limit;
peer tracking is capped at 1024. A proxy's clients share its peer quota.

Receipt validates first, then takes an exclusive per-source publication lock.
It creates an immutable exact-byte generation and atomically commits the source
pointer. The pointer records generated/observed times, both hashes and arrival
time. An exact replay within the freshness window is idempotent; a different
pair must have a strictly newer generated time and no older observation time.
Corrupt pointers fail closed. Timestamps and unsigned manifests are not
cryptographic provenance. The source credential is the authentication boundary.

The push client retries the same captured pair at most three times after a lost
acknowledgement or transient gateway error. It leaves rate-limited retries to
the scheduler and never follows redirects. A concurrent source publication may
return a transient busy response. Older snapshots do not replace newer ones.
Administrative rollback requires an explicit offline state procedure, backup
and audit; there is no automatic rollback/reset endpoint.

Mount only receiver configuration, its upload credentials and its staging tree.
Use a separate OS account from Core. Accepted uploads are consumed by the next
one-shot pipeline; request handlers never start Core scans. Back up pointers and
generations together. Historical generations are retained until an explicit
administrator retention operation.

For separate Unix receiver and runner accounts, an explicit `reader_gid` in
`[ingestion]` grants that local group read access to newly published source
directories (2750), inventory/manifest files and pointer (0640). The receiver
must already belong to that group; it cannot add itself or select arbitrary
groups. Prepare the staging root so the runner can traverse it. Upload tokens,
TLS keys, validation scratch, locks and other state remain private. Existing
historical generation permissions are not rewritten, and idempotent uploads
do not migrate them; an administrator must review existing ACLs or collect a
new generation. Without this option files remain private to their writer.
Windows uses explicit administrator-controlled directory ACLs instead; the
Unix group option is rejected there. Containers may share a numeric UID while
isolating the receiver through its limited mounts.
