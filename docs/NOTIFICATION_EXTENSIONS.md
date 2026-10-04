# Additional notification channels

The optional `cvebeacon-automation` package adds Telegram, Discord incoming webhooks,
Slack incoming webhooks and unencrypted Matrix rooms. Core's existing Teams path
continues to use Core's configuration and delivery state. Additional channels use
Automation configuration and a separate delivery ledger.

Configure only destinations you administer and intend to receive vulnerability
alerts. Configuring an enabled channel permits real sends when you run `notify run`
or the Automation pipeline. The shipped examples contain secret references; they
do not provision provider accounts or credentials. No channels are enabled by an
empty notification configuration.

## Configuration

Add notification tables to the version-1 Automation TOML configuration:

```toml
[[notifications]]
id = "telegram-operations"
provider = "telegram"
token = { env = "CVEBEACON_TELEGRAM_TOKEN" }
chat_id = "-1001234567890"
# message_thread_id = 42

[[notifications]]
id = "discord-security"
provider = "discord"
webhook = { env = "CVEBEACON_DISCORD_WEBHOOK" }

[[notifications]]
id = "slack-security"
provider = "slack"
webhook = { env = "CVEBEACON_SLACK_WEBHOOK" }

[[notifications]]
id = "matrix-security"
provider = "matrix"
homeserver = "https://matrix.example.org"
room_id = "!roomid:example.org"
token = { env = "CVEBEACON_MATRIX_TOKEN" }
```

Supply each credential through its referenced environment variable, or replace the
reference with `{ file = "secrets/provider.txt" }`. Relative file references resolve
against the Automation configuration directory. Secret files must be regular files
with one link; on POSIX they must have no group or other permissions. Protect the
containing directory and use appropriate Windows ACLs. Raw tokens and raw webhook
URLs in TOML are rejected. Configuration validation checks references without
reading them; sending resolves them in the consuming process.

IDs are unique without regard to case, at most 96 ASCII letters, digits, `_`, `-`
or `.`, and cannot be reserved Windows names. At most 32 channels are accepted.
Each table accepts its provider fields above and these optional common fields:

| Field | Default | Accepted range |
| --- | --- | --- |
| `enabled` | `true` | Boolean |
| `timeout_seconds` | 15 | Integer 1â€“30 per HTTP request |
| `max_attempts` | 5 | Integer 1â€“10 per part |
| `batch_size` | 64 | Integer 1â€“256 events prepared and sends attempted per channel/run |
| `max_parts` | 8 | Integer 1â€“16 parts per logical message |
| `min_interval_seconds` | Telegram 3; others 1 | Integer 1â€“86400; Telegram requires at least 3 |
| `retry_base_seconds` | 30 | Integer 1â€“3600 |
| `retry_max_seconds` | 3600 | Integer 1â€“86400, at least the base |

Unknown keys, unknown providers, Booleans used as numeric bounds, non-finite values
and raw credentials are rejected. Telegram accepts a nonzero numeric chat ID or an
`@channelusername`; the optional thread ID is a positive integer. The Matrix room
ID must be a bounded ASCII `!opaque:server` identifier. A Matrix homeserver is an
explicit HTTPS origin with no application path, query, fragment or user information.

Resolved webhook URLs must use HTTPS on port 443, with no query or extra path:

| Provider | Allowed origin and path |
| --- | --- |
| Telegram | Constructed internally at `https://api.telegram.org/bot<TOKEN>/sendMessage` |
| Discord | `https://discord.com/api/v10/webhooks/<id>/<token>`; an unversioned `/api/webhooks/` reference is normalized to v10 |
| Slack | `https://hooks.slack.com/services/<T-id>/<B-id>/<secret>` |
| Matrix | The administrator's configured origin, only reviewed Client-Server room routes |

These adapters do not support custom Telegram API servers, Discord forum/thread
selection, Slack GovSlack origins, attachments, rich templates or encrypted Matrix
rooms. The shared transport verifies HTTPS certificates and hostnames, bounds DNS
and response reads, ignores ambient proxy configuration and does not follow
redirects. Provider responses cannot select another network destination.

## Commands and alert content

```text
cvebeacon-auto --config cvebeacon-automation.toml notify status
cvebeacon-auto --config cvebeacon-automation.toml notify test discord-security
cvebeacon-auto --config cvebeacon-automation.toml notify run
```

`status` reports safe JSON counts for each configured channel without resolving its
credential. `test` sends an explicitly labelled TEST to the chosen enabled channel;
it does not drain queued vulnerability alerts or older tests. `notify run` reads the
Core database selected by the Core configuration. It does not collect inventory or
invoke a scan. The complete `run` pipeline dispatches after its Core scan boundary.

The compact alert contains the asset ID, bounded product/version labels, advisory
ID, material event type, applicability, CVSS score and CISA/EU KEV flags. Unknown
fields remain labelled unknown. Payload metadata, evidence, references, reasons,
source identifiers, collector paths and host credentials are excluded. Control
characters in labels are flattened. Asset and component labels still describe your
inventory, so choose a destination suitable for those facts.

Automation reads Core SQLite schema exactly 3 using `mode=ro`, `query_only=ON` and
`trusted_schema=OFF`. It never opens Core's mutating `StateStore` in production or
updates Core's Teams delivery rows. Only bounded batches are selected; SQL rejects
payloads above 64 KiB before Python decodes them. Unknown schemas and unreadable
databases refuse all alert channels; malformed events refuse the affected channel,
including its prepared backlog.
All alert channels share one read-only Core snapshot for schema checks and bounded
event reads. An event key combines the Core run UUID and event ID, so a replaced
database with the same numeric IDs is distinguished.

SQLite can create transient WAL sidecars beside a live WAL-mode database even for
`mode=ro` queries when its directory is writable; these reads do not update Core
rows. A strictly read-only container mount needs a consistent snapshot prepared by
the writer. The Kubernetes v2 scanner publishes a separate DELETE-mode backup for
that purpose. Do not use SQLite's `immutable=1` against a live WAL database: it can
miss uncheckpointed rows.

A newly configured destination begins at the first stored material Core event and
works through the retained history in batches. Prepared text is frozen before
transmission. Keeping the channel ID and destination identity preserves that
history across credential rotation. Changing the channel ID or provider destination
creates a new delivery history and can send retained events again. Duplicate
configured destinations are rejected within a run.

## Delivery state and retries

Automation stores `notification-ledger.sqlite3` in its state directory and uses an
OS lock to serialize cooperating notification processes. The version-1 ledger owns
prepared logical text/parts, transaction IDs, hashed destination identity, event
cursors, attempts, due times and provider cooldowns. It does not store tokens,
webhook URLs, provider response bodies or provider exception messages. A Matrix
token-context digest is retained only to prevent unsafe replay after token changes.
The local ledger contains the prepared alert facts; protect and back it up with the
state directory. The reader rejects changes to the known version-1 schema,
including keys, defaults, constraints and indexes, before processing events. Do not
edit, delete or reset delivery state as an automatic retry mechanism.

Each part moves through `pending`, `sending`, `accepted`, `retryable`, `permanent`
or `ambiguous`. The text and Matrix transaction are committed before a part enters
transport; `sending` and its attempt count are committed before the network call.
Later parts wait for earlier parts to be accepted. Channels progress independently.
Accepted means the provider returned its documented success acknowledgement; it
does not prove that a person received or read the message.

| Outcome | Automatic behavior |
| --- | --- |
| Failure proven before transmission | Retry with finite exponential backoff and bounded jitter |
| Definitive 429 / documented flood rejection | Retry after at least the complete provider delay and the configured backoff |
| Definitive ordinary 4xx rejection | `permanent`; no automatic resend |
| Non-idempotent timeout, lost acknowledgement, uncertain success, 408, 5xx or redirect | `ambiguous`; no automatic resend |
| Process dies during a non-idempotent `sending` part | Recover as `ambiguous` |
| Matrix uncertain send or interrupted send, same token context | Replay the same endpoint, transaction ID and frozen body within the attempt cap |
| Previously attempted Matrix part with a changed token | `ambiguous`; administrator intervention |

Matrix's specification scopes transaction deduplication to the same device and
endpoint. A refreshed token can represent the same device, whereas a new login can
represent a different one. This implementation does not verify that relationship
and conservatively pauses attempted parts after *any* token change, including a
same-device refresh. Reusing a transaction with another device does not establish
exactly-once delivery. Each Matrix attempt first checks `m.room.encryption`; only a
documented `M_NOT_FOUND` response permits the plaintext PUT. Encrypted or unknown
room state refuses it. Use a dedicated unencrypted room; the state check and PUT
are separate requests, so room administration must not enable encryption between
them.

Telegram and Slack pacing is conservatively shared across their configured
destinations; Discord global 429 cooldowns apply across Discord destinations.
Cooldowns survive restarts and apply to newly configured destinations. Discord's
remaining-zero bucket reset is also respected. Telegram/Discord/Slack retry hints
are interpreted in seconds; Matrix's legacy `retry_after_ms` is divided by 1000.
HTTP `Retry-After` seconds and dates are recognized. A valid provider delay is never
reduced to `retry_max_seconds`; distant due times wait for a later scheduler run.
Malformed or missing hints use the bounded backoff policy. Retry hints are parsed
as finite bounded numbers, not unrestricted numeric expressions.

At most 32 parts are attempted per service invocation. Scheduling has a 30-second
budget and waits at most three seconds at a time for near due parts. Each attempt
receives a bounded share of the remaining run time so a slow provider leaves time
for other channels. Matrix encryption preflight and message PUT share that same
attempt deadline. The service returns remaining work for later scheduler runs
instead of starting an indefinite retry loop. The ledger refuses growth beyond
100,000 prepared parts or a 256 MiB database; there is no automatic pruning.
`unhealthy` is true for enabled channels with retryable, sending, permanent or
ambiguous parts, or safe preparation/binding errors. `pending` alone describes
scheduled work. Status includes terminal history for a channel; acknowledge and
investigate it operationally instead of treating a later successful send as repair
of an earlier ambiguous delivery.

Telegram uses plain text without `parse_mode` and disables link previews. Discord
escapes formatting, supplies `allowed_mentions = { parse = [] }` and uses
`wait=true` so success includes the saved message. Slack uses a bounded `plain_text`
section plus an escaped `<`, `>` and `&` fallback. Matrix sends `m.text` with
`m.mentions = {}`. Splitting counts UTF-16 units conservatively: 900 units for
Discord, 2400 for Slack and 3800 for Telegram/Matrix, reserving room for labels and
escaping. Request bodies are capped at 32 KiB and responses at 64 KiB. These are
implementation safety budgets; they do not assert undocumented provider byte caps.

## Optional operational messages

```toml
[operations]
enabled = true
interval_seconds = 86400
failures = true
recovery = true
discovery = false
```

Operational messages are disabled by default. The interval is an integer from 60
to 604800 seconds. A digest/heartbeat uses one stable time bucket per interval and
channel. Failure and recovery messages require their explicit flags. Discovery
messages report only bounded aggregate change counts when enabled; observations
are not authoritative vulnerability inventory. Digests report fixed pipeline
status, source counts and Core completion/coverage status without source identities
or error details. Every digest states that pipeline operational does not mean
vulnerability-free. Operational delivery is isolated from the vulnerability queue,
and its safe result is available to the pipeline's health record.

## Verified protocol references and limitations

The adapter subset was checked against primary documentation on 2026-10-04:

- [Telegram Bot API](https://core.telegram.org/bots/api) and
  [Telegram bot limits](https://core.telegram.org/bots/faq#my-bot-is-hitting-limits-how-do-i-avoid-this)
  define plain `sendMessage`, acknowledged `Message` results and flood hints.
- [Discord execute webhook](https://docs.discord.com/developers/resources/webhook#execute-webhook)
  and [Discord rate limits](https://docs.discord.com/developers/topics/rate-limits)
  define `wait`, allowed mentions, content limits and dynamic cooldowns. The
  webhook route does not offer the separate Create Message nonce contract.
- [Slack incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/),
  [Slack rate limits](https://docs.slack.dev/apis/web-api/rate-limits/) and
  [Slack section blocks](https://docs.slack.dev/reference/block-kit/blocks/section-block/)
  define the reviewed webhook acknowledgement, pacing and plain-text block budget.
- [Matrix Client-Server v1.19](https://spec.matrix.org/v1.19/client-server-api/)
  defines device-scoped transactions, rate-limit hints, bearer authentication,
  room state checks and explicit mention metadata.

Offline regressions inject synthetic transports and block external sockets. They
exercise provider payloads, privacy canaries, crashes, ambiguity, cooldowns,
replacement Core databases, future schemas and finite batches. Native local TLS
acceptance uses synthetic credentials and a deliberately injected loopback gateway;
it does not widen production endpoint restrictions. No real provider delivery,
account permissions or runtime rate-limit capacity is claimed by those tests.

Provider length wording does not completely settle Unicode counting or webhook
byte caps; conservative local budgets are used. No cross-provider exactly-once
guarantee, encrypted Matrix support or automatic resolution of ambiguous outcomes
is claimed. The scheduler must continue running to process due work and expose
delivery health.
