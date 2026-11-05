# Watch mode

Watch mode keeps a separate local history of recently changed CVEs. It is
independent of the inventory database: `cvebeacon watch` never reads the
inventory file, and enabling watch mode does not change `scan`, `query`, or any
other command. Watch mode can select matching CVEs with rules, stores the
resulting alert events, and delivers them to configured channels.

```console
cvebeacon --config cvebeacon.toml watch sync
cvebeacon --config cvebeacon.toml watch run
cvebeacon --config cvebeacon.toml watch notify
cvebeacon --config cvebeacon.toml watch notify test soc-email
cvebeacon --config cvebeacon.toml watch status
cvebeacon --config cvebeacon.toml watch events
cvebeacon --config cvebeacon.toml watch rules check
cvebeacon --config cvebeacon.toml watch evaluate --all
cvebeacon --config cvebeacon.toml watch report CVE-2026-1234
cvebeacon --config cvebeacon.toml watch unreport CVE-2026-1234
cvebeacon --config cvebeacon.toml watch reported
cvebeacon --config cvebeacon.toml watch statement CVE-2026-1234 --out statement.md
cvebeacon --config cvebeacon.toml users list
```

`watch run` syncs the sources, evaluates the CVEs touched by that sync, and
delivers pending alerts. `watch sync` only syncs; the durable touch queue keeps
the evaluation for the next `watch run`. `watch notify` delivers pending alerts
without syncing or evaluating. `watch statement` renders one stored CVE from a
Markdown, plain-text, or Word template without syncing or delivering; see
[statements](STATEMENTS.md).

## Configuration

Watch mode is disabled by default. Add a `[watch]` table to the existing
configuration:

```toml
[watch]
enabled = false
database = "cvebeacon-watch.db"
sources = ["nvd", "euvd", "cisa_kev", "eu_kev", "epss"]
initial = "baseline"
backfill_days = 7
overlap_minutes = 15
language = "en"
```

- `enabled`: watch commands refuse to run until this is `true`.
- `database`: a separate SQLite file. Relative paths resolve from the
  configuration file directory, like other paths. When omitted, it defaults to
  `cvebeacon-watch.db` in the directory of the resolved `[state] database`, so
  it stays beside the monitoring state. With no `[state] database`, that is
  `.cvebeacon/cvebeacon-watch.db` under the configuration directory.
  Configurations from earlier builds that omitted this setting should pin
  `database = "cvebeacon-watch.db"` before upgrading, or the old file is
  ignored and a new baseline starts.
- `sources`: any subset of `nvd`, `euvd`, `cisa_kev`, `eu_kev`, and `epss`.
  `nvd` is required. Unknown names are rejected.
- `initial`: what the first sync does; see [initial modes](#initial-modes).
- `backfill_days`: 1 to 120, used only when `initial = "backfill"`.
- `overlap_minutes`: 0 to 1440. Later runs re-read this much before the stored
  NVD cursor so that late-published changes are not missed.
- `language`: `"en"` (default) or `"pt-PT"`. It selects the catalog used for
  alert messages, digests, notices, email subjects, and test messages. An
  unknown value is rejected with the supported list. Each channel can override
  it; see [message format and language](#format-and-language). These
  messages use the catalog even when the CLI output around them stays English.

Optional client-report identity policy:

```toml
[watch.reporting]
identity = "open"   # open, registered, or authenticated
```

- `open` is the default and keeps the free-text `--by` behavior.
- `registered` requires `--by` to name an enabled CVEBeacon user.
- `authenticated` requires `--user` plus that user's password, and refuses
  `--by`. The three modes are described under
  [reported to clients](#reported-to-clients).

When `[watch].enabled = true`, `[inventory]` is optional. Commands that need an
inventory (`scan`, `export`, `asset`, `inventory ...`, `doctor`, and the
inventory dashboard pages) fail with a clear message until
`[inventory] path` is added. A configuration with neither watch mode nor an
inventory is rejected, so existing configurations keep their behavior.
`schedule install` supports watch-only and combined configurations: it runs
`watch run` by default when no inventory is configured, and the ordered `run`
command (scan, then watch run) when both are configured. See
[scheduling](SCHEDULING.md).

The NVD API key is read from the existing `sources.nvd_api_key_env` variable,
or from `sources.nvd_api_key_file` when the variable is unset. It is optional;
pacing follows `sources.minimum_request_interval`.

## Channels

Each channel is a `[watch.channels.<name>]` table. Names start with a letter or
digit and contain at most 64 letters, digits, underscores, dots, or hyphens.
Every rule channel must name one of these tables.

Common keys:

- `type` (required): `smtp`, `graph`, `teams`, `slack`, `discord`, `telegram`,
  `matrix`, `ntfy`, `gotify`, or `webhook`.
- `enabled`: `true` by default. A disabled channel keeps its pending deliveries.
- `grouping`: `"run"` (default) sends one message per channel per run that lists
  that run's events. `"event"` sends one message per event.
- `max_items`: 1 to 100, default 20. A long message lists this many CVEs and
  then "and N more" with a pointer to `cvebeacon watch events`.
- `min_interval_seconds`: 0 to 3600, default 0. Telegram defaults to 3 and
  rejects smaller values.
- `timeout_seconds`: 1 to 300, default 30.
- `allow_insecure`: `false` by default. This is required for plain SMTP and for
  a plain-HTTP webhook or ntfy server.
- `notify_reported`: `false` by default. When true, the channel receives report
  and unreport notices; see [reported to clients](#reported-to-clients).
- `language`: optional per-channel override of `[watch] language`. A Portuguese
  client mailbox and an English SOC channel can coexist.

Secrets are never written in the configuration. A secret key comes as a pair:
`*_env` names an environment variable, and `*_file` names a file. At least one
is required where a secret is marked. A secret file must not be group or other
accessible on POSIX, must be at most 16 KiB, and its value is stripped of
surrounding whitespace.

### SMTP

```toml
[watch.channels.soc-email]
type = "smtp"
host = "smtp.gmail.com"
port = 587
security = "starttls"          # starttls, tls (implicit TLS), or none
username = "alerts@example.com"
password_env = "CVEBEACON_SMTP_PASSWORD"
from = "alerts@example.com"
to = ["soc@example.com"]
# cc = ["manager@example.com"]
# bcc = ["archive@example.com"]
format = "text"                # text (default) or html
```

`security = "none"` requires `allow_insecure = true` and logs a warning. Every
TLS connection verifies certificates with the system trust store; a certificate
failure is reported as "certificate verification failed". A `starttls` channel
refuses a server that does not offer STARTTLS. Gmail needs an app password; use
`smtp.gmail.com:587` with STARTTLS. Microsoft 365 uses
`smtp.office365.com:587`, but SMTP AUTH must be enabled on the mailbox;
otherwise use the `graph` channel. `timeout_seconds` bounds the connection and
every socket operation, and the delivery deadline is checked before each SMTP
phase. Bodies are always quoted-printable, so relays do not need 8BITMIME. `bcc`
recipients are part of the SMTP envelope and never appear as a message header.
`format = "html"` sends `multipart/alternative`: the plain-text body first and
the HTML body second, both quoted-printable. The default `"text"` sends the
same message as earlier builds.

### Microsoft Graph

```toml
[watch.channels.m365]
type = "graph"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "00000000-0000-0000-0000-000000000000"
client_secret_env = "CVEBEACON_GRAPH_CLIENT_SECRET"
sender = "alerts@example.com"
to = ["soc@example.com"]
format = "text"                # text (default) or html
```

This sends through the Microsoft Graph `sendMail` endpoint and needs an
application permission such as `Mail.Send` for the sender mailbox. `cc` and
`bcc` recipients are sent as Graph `ccRecipients` and `bccRecipients`.
`format = "html"` sends the same HTML document as `contentType: "HTML"`; the
plain-text body is still generated from the same facts and is what
`format = "text"` sends. Graph cannot send both parts; with `format = "html"`
only the HTML body is sent.

### Teams

```toml
[watch.channels.teams]
type = "teams"
webhook_url_env = "CVEBEACON_TEAMS_WEBHOOK_URL"
```

Use a Teams Workflows webhook URL. Messages are Adaptive Cards; dynamic CVE text
is Markdown-escaped so a description cannot inject a link or formatting.

### Slack

```toml
[watch.channels.slack]
type = "slack"
webhook_url_env = "CVEBEACON_SLACK_WEBHOOK_URL"
```

The URL must start with `https://hooks.slack.com/services/`.

### Discord

```toml
[watch.channels.discord]
type = "discord"
webhook_url_env = "CVEBEACON_DISCORD_WEBHOOK_URL"
```

The URL must be a `discord.com` or `discordapp.com` webhook URL. Messages set
`allowed_mentions: {parse: []}` and escape Markdown and mentions.

### Telegram

```toml
[watch.channels.telegram]
type = "telegram"
bot_token_env = "CVEBEACON_TELEGRAM_BOT_TOKEN"
chat_id = "-1001234567890"
min_interval_seconds = 3
```

`chat_id` may be a numeric id or an `@channel` name; it is normalised to a
string.

### Matrix

```toml
[watch.channels.matrix]
type = "matrix"
homeserver = "https://matrix.example.org"
room_id = "!room:example.org"
access_token_env = "CVEBEACON_MATRIX_ACCESS_TOKEN"
```

Only unencrypted rooms are supported. The channel first asks for the
`m.room.encryption` state and requires a 404 `M_NOT_FOUND`. Messages use the
plain-text form. Sends use a deterministic transaction id per message part, so
an explicit retry after an ambiguous send usually does not post the same part
twice. Ambiguous rows are never retried automatically; use
`--retry-ambiguous` to send them again.

### ntfy

```toml
[watch.channels.ntfy]
type = "ntfy"
server = "https://ntfy.sh"     # the default
topic = "cvebeacon-a1b2c3d4e5f6"  # choose a unique, unguessable topic
# token_env = "CVEBEACON_NTFY_TOKEN"
priority = 3                    # 1 to 5
```

ntfy.sh topics are public unless the topic is protected: anyone who knows or
guesses the name can read the alerts. Use a unique topic, a token, or a
self-hosted ntfy server for private alerts.

The body is plain text and does not repeat the title; the title is sent in the
`Title` header. That header is ASCII-only: accented characters in a pt-PT
subject are replaced with `?`, while the body keeps the full text.

### Gotify

```toml
[watch.channels.gotify]
type = "gotify"
server = "https://gotify.example.org"
app_token_env = "CVEBEACON_GOTIFY_TOKEN"
priority = 5                    # -2 to 10
```

### Generic webhook

```toml
[watch.channels.hook]
type = "webhook"
url = "https://example.org/cvebeacon"
# header_name = "X-Auth"
# header_value_env = "CVEBEACON_HOOK_SECRET"
```

The URL must use HTTPS unless `allow_insecure = true`. The channel POSTs the
stable document described below. Redirects are never followed.

### HTTP behavior

Every HTTP send uses the existing bounded HTTP client with redirects disabled
and no retries inside one send. A send is accepted only on the provider's
documented success status. Errors contain only a category and, when relevant,
the HTTP status: never the URL, a token, or a response body. Request URLs are
not logged.

## Delivery

Each event creates one delivery row per channel. Delivery aims to be at least
once: every event has a durable row, and definite failures are retried. Because
a message may already have arrived when the outcome is unknown, ambiguous rows
are not resent automatically. A row moves through these states:

- `pending`: queued but not attempted.
- `sending`: committed atomically immediately before the request or SMTP
  `DATA`. Rows are claimed with a conditional update, so two runs cannot send
  the same delivery.
- `sent`: the provider accepted the message. This state is final.
- `failed`: a definite failure (connection, DNS, TLS, an HTTP error, or any
  SMTP error reply, including one after `DATA`). A connection drop or timeout
  before `DATA` is also definite. The row is retried with backoff.
- `ambiguous`: the request or `DATA` may have reached the provider (a connection
  drop, EOF or timeout after `DATA`, or a success status without a readable
  confirmation), or a stale `sending` row was found. It is never downgraded to
  `failed`, and never resent automatically. A Matrix retry reuses a transaction
  id per part, so an explicit retry after an ambiguous send is usually
  idempotent.

Failed rows wait 5 minutes, then double the delay up to 6 hours, and stay
`failed` after 10 attempts. Authentication failures (SMTP 535 and Graph
401/403) give up after 3 attempts to avoid an account lockout.
`cvebeacon watch notify` sends pending rows and due retries;
`--retry-ambiguous` also resends ambiguous rows, `--retry-failed` retries every
failed row regardless of attempts or backoff, and `--channel NAME` limits the
run to one channel. `cvebeacon watch notify test <channel>` sends a clearly
labelled test message directly, outside this state machine. If a previous run
stopped after committing `sending` more than 10 minutes ago, the next delivery
prints a recovery line and marks those rows ambiguous before it continues.
Newer `sending` rows belong to a live run and are left alone.

A channel sends at most 10 messages per run and the whole delivery step has a
60-second budget. Leftovers stay `pending` for the next run; a group whose
budget ran out before its first message stays pending and does not count an
attempt. The budget also bounds each HTTP response body read, and the SMTP
connection is checked between phases. A provider that keeps sending headers one
byte at a time, or keeps an SMTP phase alive below the socket timeout, can still
hold the run open longer than the budget; each operation has its own timeout.
One channel failing never blocks the others. `watch run` exits 3 when a delivery
failed or became ambiguous in that run, before the usual source-failure exit
code 4. A source failure still delivers rows that were already pending.

`watch status` prints pending, failed (with the number that reached the attempt
cap), ambiguous, stuck `sending`, and the last success time for each channel.
`watch run` prints a delivery line per channel, for example
`soc (smtp): 1 message, 4 events sent`, using that channel's own counts. When
failed rows have reached the attempt cap, the line adds
`; N given up (run cvebeacon watch notify --retry-failed)`.

## Reported to clients

A per-CVE mark records that clients have been informed, so the same CVE is not
reported twice. The mark is append-only: every report or withdrawal is kept,
and the latest row is the current state. A single reporting service binds the
configured identity policy and user store for every front end; the raw store
write methods are private.

```console
cvebeacon --config cvebeacon.toml watch report CVE-2026-1234
cvebeacon --config cvebeacon.toml watch report CVE-2026-1234 --by account_user --note "Sent in ticket OPS-42"
cvebeacon --config cvebeacon.toml watch unreport CVE-2026-1234 --by account_user --note "Sent in error"
cvebeacon --config cvebeacon.toml watch reported
cvebeacon --config cvebeacon.toml watch reported --all
```

- `watch report` requires the CVE to exist in the watch database; otherwise it
  prints a clear error and exits 2.
- `--note` is optional, at most 500 characters, and single-line UTF-8 without
  control characters.
- Reporting a CVE that is already reported prints the existing mark and exits 0
  without a new row. `--force` appends another report row and notification.
  When the earlier notice failed, the repeated report also prints a hint to run
  `watch notify --retry-failed`.
- `watch unreport` appends a withdrawal row. When the CVE is not currently
  reported, it says so and exits 0.
- `watch reported` lists the currently reported CVEs with the reporter, UTC
  time, and note. `--all` prints the full audit trail and each notice's
  per-channel delivery state (`pending`, `sent`, `failed`, `ambiguous`, or
  `sending`). Notice delivery errors remain visible in `watch status` counts.
- `watch reported --verify` recomputes the report audit chain and exits 2 at
  the first row that no longer matches.
- `watch reported --all --format text|csv|json` exports the audit trail.
  CSV and JSON additionally carry the account id, username, identity mode,
  operating-system account, host, chain value, and a legacy flag. CSV cells
  that start with a spreadsheet formula marker are prefixed with an apostrophe.
  `--format` other than `text` requires `--all`.

### Identity modes and accounts

The `[watch.reporting] identity` setting selects how a report identifies the
person:

| Mode | Who may report | Recorded identity |
| --- | --- | --- |
| `open` (default) | anyone with local access | free-text `--by`, or the OS login name |
| `registered` | an enabled CVEBeacon user named by `--by` | display name, username and user id |
| `authenticated` | a CVEBeacon user who enters the password | display name, username and user id |

In `registered` mode `--by` accepts a username or email address,
case-insensitively, and must match an enabled account. In `authenticated` mode
the command is `watch report CVE-2026-1234 --user account_user`; `--by` is refused and
the login name is the username, never the email address. An unknown user, a
disabled user, and a wrong password all print the same error and exit 2 without
adding a report row.

In open mode `--by` is free text of at most 100 characters and must be
single-line UTF-8 without control characters. It defaults to the OS login name,
or `unknown` when that name is unavailable or unsafe.

Accounts can be managed from the dashboard or the server command line. For
CLI administration, access to the account file is the administrator boundary:

```console
cvebeacon --config cvebeacon.toml users add account_user --name "Example account" --email account@example.test
cvebeacon --config cvebeacon.toml users add other_user --no-password
cvebeacon --config cvebeacon.toml users passwd account_user
cvebeacon --config cvebeacon.toml users disable account_user
cvebeacon --config cvebeacon.toml users enable account_user
cvebeacon --config cvebeacon.toml users unlock account_user
cvebeacon --config cvebeacon.toml users list
cvebeacon --config cvebeacon.toml users verify
```

In `authenticated` mode, account administration needs an administrator login:
`--admin-user NAME` plus a hidden password prompt, verified through the same
account store. The action is audited with the administrator as its actor. The
first `users add --admin` is the bootstrap exception when no administrator
account exists; it is audited as `(bootstrap)` and requires a password. A user may
change their own password with `users passwd USERNAME` and their current
password; resetting another user's password, disabling, enabling or unlocking
an account requires `--admin-user` and an administrator account. In `open` and
`registered` modes, these commands keep the direct behavior and `--admin` is a
stored label rather than an enforced CLI privilege. Dashboard permissions
always apply, regardless of the reporting identity setting.

```console
cvebeacon --config cvebeacon.toml users add admin_user --admin
cvebeacon --config cvebeacon.toml users add other_user --admin-user admin_user
cvebeacon --config cvebeacon.toml users passwd other_user
cvebeacon --config cvebeacon.toml users passwd other_user --admin-user admin_user
cvebeacon --config cvebeacon.toml users disable other_user --admin-user admin_user
```

The CLI runs as the CVEBeacon service account. Anyone who can use that shell can
still edit the database files directly, so authenticated mode attributes a
report to whoever knows the password (or could reset it under the administrator
rules); it guards against mistakes and casual misattribution, not against
co-administrators or someone with the service account. Person-level separation
needs a front end that people use instead of a service-account shell, such as
the [dashboard](DASHBOARD.md). The report and user-admin audit chains make edits to
those logs detectable unless the person also recomputes them; `cb_user` account
rows and the configuration file are not covered by either chain. An action with
an empty actor after bootstrap in authenticated mode means it was performed
outside the administrator gate.

- A username is 1–64 characters from letters, digits, dot, underscore, at sign,
  or hyphen, and is unique case-insensitively. A display name is optional and at
  most 100 characters. An email address is optional, lightly checked, and
  unique case-insensitively when present.
- `--no-password` is intended for `registered` mode. An account without a
  password cannot log in until `users passwd` sets one; `authenticated` mode
  rejects it.
- There is no delete command because the audit trail refers to accounts. Use
  `disable`; the account and its history remain. The last enabled administrator
  cannot be disabled or demoted; create a replacement administrator first.
- `users list` never displays password material. `users verify` recomputes the
  user-admin audit chain and exits 2 at the first broken row. It covers the
  user-admin audit log only; direct edits to `cb_user` (password hash, disabled
  flag, role, email) are not part of that chain. Treat file access as
  administrator access and compare against a trusted backup if account-row
  tampering matters.

Passwords are read with hidden input and confirmation; there is no
`--password` option and no environment variable for a password. They must be
12–1024 characters, cannot be all whitespace, and cannot equal the account's
username or email address. They are hashed with the dashboard's
`scrypt:32768:8:1` scheme, which stores a salt and its parameters in the hash so
the parameters can be raised later. Verification is constant-time for the hash
comparison; an unknown or unusable account still runs a fixed dummy hash so
timing does not reveal valid usernames. Five consecutive failures lock the
account for 15 minutes; a success resets the count, and `users unlock` clears a
lock. Lockout is wall-clock UTC based: moving the host clock forward past the
deadline ends the lock, and moving it backward extends it. Control of the host
clock is administrator access. Every failed attempt is recorded in the user
audit trail with the typed name (sanitized and truncated), time,
operating-system account and host, never the password.

The account file is `cvebeacon-users.db` beside the watch database. It is
created owner-only (`0600`) on POSIX and is separate from the CVE history so
credentials are not copied with a public watch database and accounts survive a
watch database rebuild. On POSIX every ancestor of the account file up to the
filesystem root must be owned by the CVEBeacon account or root, or be
sticky-bit protected; a root-owned sticky directory such as `/tmp` is accepted.
An ancestor owned by another account is rejected unless it is sticky-bit
protected; read-only mode alone is not trusted because that owner could change
it. When
CVEBeacon creates a missing data directory it uses mode `0700` regardless of
the process umask; an existing directory that fails the check is reported with
an actionable `chmod go-w <dir>` message. The account database stores a random
store id in `cb_user_meta`; after SQLite opens the file, a read-only first
transaction checks the `cb_user` schema and that id, and compares the file's
device and inode. On POSIX the original inode stays pinned for the process
lifetime, preventing reuse of its inode number during opening while preserving
SQLite's transaction locks across account-store instances. Concurrent writes to
the same file may change its size and modification time. Existing account
databases without a store id receive one once. Back up both files together, and keep account
backups at `0600` as well. On
Windows, place both in the
[ACL-protected data directory](DEPLOY.md#windows-data-directory-acls). The same
account store and verification function also serve dashboard login. Dashboard
roles are stored in this database; the existing admin flag retains its meaning.
See [dashboard accounts and permissions](DASHBOARD.md#accounts-and-bootstrap).

### Report audit trail

Every `watch_report` row records the CVE, the action, the display identity, the
user id and username (registered and authenticated modes only), the identity
mode, the operating-system account, the host, the UTC time, and an optional
note. The operating-system account comes from `pwd.getpwuid` on POSIX,
`GetUserNameExW` on Windows, or `getpass.getuser()` as a fallback; it is
informational and never used for authorization.

Each chained row stores `chain = sha256(previous chain || canonical JSON of the
row)`. The chain is **unkeyed**: it detects edits and deletions that do not also
recompute the hashes, and it is not a signature or authentication of the writer.
Anyone who can write the database can recompute the remaining chain, append a
forged row with a valid chain, or remove the newest rows. Keep an external
reference (a backup, an off-box copy of the head, or write-once storage) for
that stronger claim. `watch reported --verify` reports the first broken row and
exits 2; when it succeeds it prints how many rows are chained and how many are
legacy and unchained. The user audit table uses the same construction.

The watch database schema is version 7. Rows written before the identity upgrade
have `chain_version = 0`, a null chain, and are reported as legacy unchained;
the chain starts with the first report written after the upgrade. Migration
records the highest legacy row id in `watch_meta` once. A legacy row must be at
or below that boundary and have null identity columns; marking an identity-era
row as legacy is reported as damage. Verification never rewrites a stored
chain, even if the schema metadata is rolled back. If the chain columns are
dropped after the boundary exists, migration fails closed rather than
recreating legacy history. A schema 6 database keeps its existing chains and
gains the explicit version marker without re-hashing them.

A writer who can edit the database can still relabel the whole trail as legacy
by changing the boundary or the schema. That state is indistinguishable from a
genuine never-reported schema-5 database, so compare the printed chained count
with an external reference; the chain alone cannot rule out a total rewrite.

A reported CVE is displayed as
`Reported to clients by X at YYYY-MM-DD HH:MM UTC`; registered and
authenticated marks add the username in parentheses when it differs from the
display name. The mark appears in `watch events` lines, in alert messages and
the initial digest when the CVE is already reported at send time, and in the
generic webhook document as `view.reported` (`null` or an object with `by`,
`at`, and `note`, plus `username` when present). `watch status` prints the
number of currently reported CVEs.

### Reported notification

Set `notify_reported = true` on a channel to send a short notice when a CVE is
reported or its report is withdrawn:

```toml
[watch.channels.soc-chat]
type = "slack"
webhook_url_env = "CVEBEACON_SLACK_WEBHOOK_URL"
notify_reported = true
```

The message is
`[REPORTED] CVE-2026-1234 reported to clients by Example account (account_user) <account@example.test> at 2026-11-04 12:00 UTC`,
with the optional note as a second line, or
`[UNREPORTED] CVE-2026-1234 report withdrawn by Example account (account_user) at 2026-11-04 12:00 UTC`.
The username appears when it differs from the display name, and the email
address when the account has one. In open mode the free-text name is used
unchanged. Channels without the setting receive nothing.

Notices use the same delivery ledger as alerts. `watch report` and
`watch unreport` attempt only their own notice immediately and print the
delivery line; they do not flush other pending alerts or the initial digest.
A failed notice is retried by `watch notify` or `watch run` with the usual
backoff, and a successful one is final, so the delivery phase never sends it
twice.

Notices for one CVE and channel follow the audit order, by durable insertion
sequence rather than alert severity. A newer notice waits while an earlier
notice for the same CVE and channel is pending, sending, ambiguous, or failed
below the attempt cap. A notice that reached the attempt cap no longer blocks
later notices. `watch notify --retry-ambiguous` or `--retry-failed` revives the
earlier notice first, and the successor follows it in the same ordered run.

The generic webhook receives a notice as a normal version 2 document whose
event has `kind` `reported` or `unreported`, `rule` `@reported`, and an extra
`notice` object (`action`, `by`, and `note`, plus `username` and `email` when
present). Notice events are delivery records rather than alert events, so
`watch events` does not list them; use `watch reported --all` or the channel
counts in `watch status` to inspect their delivery state.

## Messages

All channels use the same formatter. Messages are short: one header line per
CVE, a description cut to 160 characters, each matching rule, and links. When
several rules match the same CVE under the same label, they share one block and
a `Rule: a, b` line.

```text
[NEW] CVE-2026-1234 · CVSS 9.8 (CNA: Acme), NVD pending · EPSS 0.62 · KEV: CISA ✓ EU – · Exploitation: active
  Published 2026-10-30 · first seen 2026-11-04
  Acme Widget before 4.2.1 allows unauthenticated remote code execution…
  Rule: critical-or-likely · https://nvd.nist.gov/vuln/detail/CVE-2026-1234
```

Each CVE block also shows its publication and first-seen dates as UTC dates.
`Published` is the official NVD/CVE publication date and is shown as
`Published unknown` when the record has none. `first seen` is when this
CVEBeacon instance first stored the CVE.

Event labels:

| Kind | Label |
| --- | --- |
| `match` | `[NEW]` |
| `kev_added` | `[KEV ADDED: CISA]` or `[KEV ADDED: EU]` |
| `exploitation_active` | `[ACTIVELY EXPLOITED]` |
| `severity_increase` | `[SEVERITY UP high->critical]` |
| `epss_increase` | `[EPSS UP 0.08->0.61]` |
| `nvd_score_added` | `[NVD SCORED 9.1]` |
| `rejected` | `[REJECTED]` |
| `reported` | `[REPORTED]` (notice, not an alert) |
| `unreported` | `[UNREPORTED]` (notice, not an alert) |

Every CVSS score names its provider: `CNA` (with the CNA's short name or email
domain), `NVD`, `CISA-ADP`, `EUVD`, or `Other`. When only a CNA or ADP score
exists, the line adds `NVD pending`; a rejected CVE does not. A KEV-added line
also shows the CISA due date and required action, cut to 120 characters.
Dynamic text is escaped for each channel's markup, so a CVE description cannot
inject a Slack link, a Discord mention, or a Teams Markdown link.

Events are ordered with KEV entries and active exploitation first, then the
highest CVSS, then EPSS. A run message has a title such as
`CVEBeacon: 3 new, 1 KEV added (critical-or-likely)`; an event message uses
`CVEBeacon: [KEV ADDED] CVE-2026-1234`.

Initial events (`initial = 1`) are never sent one by one. They become one digest
per channel per run. The digest covers every selected initial row, whatever its
prior status: pending rows, due failed rows, and ambiguous rows when
`--retry-ambiguous` is used.

```text
CVEBeacon initial summary: 12 CVEs across 3 rules since 2026-10-27

critical-or-likely: 8 matches, 1 KEV added
kev-watch: 4 matches

[NEW] CVE-2026-1234 · CVSS 9.8 (CNA: Acme), NVD pending · EPSS 0.62 · KEV: CISA – EU – · Exploitation: none
  Published 2026-10-30 · first seen 2026-11-04
  Acme Widget before 4.2.1 allows unauthenticated remote code execution…
and 8 more. Run `cvebeacon watch events` to list all.
```

The subject counts distinct CVEs. The per-rule lines and the overall digest
total count events, so one CVE matched by two rules appears in both rules. The
digest counts every selected initial row, even beyond 1,000, without loading the
backlog: counts come from SQL and only the top `max_items` rows are rendered. It
lists those rows and reports the rest as "and N more" (distinct CVEs). A one-item
digest uses "1 CVE across 1 rule". The list-all hint quotes a rule name that
contains spaces. The SQL sample orders KEV, active exploitation, CVSS and EPSS;
the selected rows are sorted exactly before rendering.

A generic webhook receives initial events as JSON documents of at most 1,000
events each. Each document is one delivery attempt for exactly its rows.

Provider limits are respected by splitting at line boundaries into numbered
parts: Telegram 4,096 characters, Discord 2,000, Slack 3,800, Matrix 30,000,
Teams about 25 KB of card text, and ntfy 4,096. The Matrix, Teams and ntfy limits
are counted in UTF-8 bytes. When an HTML part is sent, the decoded plain-text
body and the HTML document are kept under 1,000,000 characters together for
SMTP, and the HTML body alone for Graph; `format = "text"` keeps the earlier
text-only behavior. Email still applies `max_items`.

Links: the NVD detail page is always present, the CVE.org record is always
present, the EUVD detail page appears when an EUVD id exists, and the CISA KEV
catalog link appears when the CVE is in KEV.

### Format and language

`format = "html"` is available on `smtp` and `graph` channels and defaults to
`"text"`, so existing configurations are unchanged. The key is rejected on
other channel types. Use `html` for mailboxes read by people; `text` is the
compatibility default. The HTML part is generated from the same message model
as the plain-text part, not from a second content path, and both carry the
same facts. An alert shows a header line per CVE with
its label and CVSS, the EPSS, KEV, and exploitation fields, the publication and
first-seen line, the reported line when present, the description, the matching
rules, and the links. A digest shows a heading, a section per rule with its
counts, and a compact table with the CVE, severity, EPSS, KEV, exploitation,
published, and first-seen columns. A screenshot of an HTML alert would show one
light card with a bold header such as
`[NEW] CVE-2026-1234 · CVSS 9.8 (CNA: Acme), NVD pending · EPSS 0.62 · KEV: CISA ✓ EU – · Exploitation: active`,
followed by the date line, the description, the rule and link line, and a grey
reported line when the CVE is marked. A digest screenshot would show the
summary heading, one short section per rule, and the table below it. The layout
is a simple table with inline styles only: there are no images, web fonts,
scripts, tracking pixels, or remote stylesheets, and it stays readable in dark
mode and in Outlook.

Every dynamic value is HTML-escaped, and links use only the fixed NVD, CVE.org,
EUVD, and CISA KEV URL builders with percent-quoted identifiers. A CVE
description, rule name, reporter, or note therefore renders as inert text even
when it contains HTML or Markdown. The size unit is decoded characters:
SMTP counts its plain-text and HTML parts together against 1,000,000, while
Graph counts only the HTML body it actually sends. A message is shortened
rather than sent over the limit; a fixed summary that cannot fit is a
controlled delivery failure. Text-only mail keeps the earlier behavior.

`[watch] language` selects the message catalog. Supported languages are `"en"`
and `"pt-PT"`; the default is `"en"`. Any channel can set its own `language`,
so a Portuguese client channel and an English SOC channel can coexist. The
generic webhook's stable JSON document stays English and is independent of the
catalog; only its test `message` is localised. CVE identifiers, CVSS, EPSS,
KEV, SSVC, provider names, rule names, and URLs are never translated, and
dates stay ISO `YYYY-MM-DD` or `HH:MM UTC`. CLI output (`watch events`,
`watch status`, and error messages) stays English in this phase; only
delivered messages, notices, subjects, and test messages use the catalog.

To add a language, copy the `en` dictionary in `src/cvebeacon/watch/catalog.py`,
translate its values, and add the language name to `SUPPORTED_LANGUAGES`. Keep
the keys and the placeholder names unchanged: a test checks that every catalog
has the same keys and the same placeholders per key, and another renders every
channel family in `pt-PT`.

### Webhook document

The generic webhook receives a stable JSON document:

```json
{
  "version": 2,
  "events": [
    {
      "rule": "critical-or-likely",
      "cve_id": "CVE-2026-1234",
      "kind": "match",
      "reasons": ["cvss 9.8 v3.1 (cna)"],
      "initial": false,
      "created_at": "2026-11-03T12:00:00+00:00",
      "view": {
        "published": "2026-10-30T14:00:00.000",
        "first_seen": "2026-11-04T09:15:00+00:00",
        "cvss": [
          {"provider": "cna", "source": "security@acme.example", "version": "3.1", "score": 9.8, "vector": null}
        ],
        "kev": {
          "cisa": {"added": "2026-11-03", "due": "2026-11-20", "required_action": "Apply the update."},
          "eu": null
        },
        "epss": {"score": 0.62, "percentile": 0.97, "date": "2026-11-03"},
        "reported": null,
        "vendors": ["Acme"],
        "products": ["Widget"],
        "links": {
          "nvd": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
          "cve": "https://www.cve.org/CVERecord?id=CVE-2026-1234",
          "euvd": null,
          "kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        }
      }
    }
  ]
}
```

`published` and `first_seen` are the full ISO timestamps as stored; `published`
is `null` when the CVE record has none. Version 2 adds these two `view` fields.
Every version 1 field keeps its meaning. `view.kev.cisa` and `view.kev.eu` are
`null` when the CVE is not in that catalog. `epss` and `links.euvd` are `null`
when the value is absent. `view.reported` is `null` or an object with `by`,
`at`, and `note`, plus `username` when the identity came from a CVEBeacon
account. The order is the same as the text messages, with notice
events after alert events. A test message adds `"test": true` and `"message"`
and has an empty `events` list. A report or unreport notice event has `kind`
`reported` or `unreported`, `rule` `@reported` (an `@`-prefixed name is reserved
and cannot be a configured rule), and a `notice` object with `action` (`report`
or `unreport`), `by`, and `note`, plus `username` and `email` when present.

### Privacy

Messages go to the providers you configure: Slack, Discord, Telegram, Teams,
Microsoft 365, Gmail, ntfy.sh, and so on. Each provider sees the CVE identifiers,
scores, descriptions, and rule names in the alerts. Self-host ntfy, Gotify, or
Matrix, or use your own SMTP server, to keep alerts private.

## Rules

Rules select CVEs from the watch database. Each rule has a name, a condition,
and one or more channel names. Every channel must be configured in
`[watch.channels.<name>]`; a rule that names an unknown channel is rejected when
the configuration is loaded.

```toml
[[watch.rules]]
name = "critical-or-likely"
enabled = true
condition = { any = [ { cvss_min = 9.0 }, { epss_min = 0.5 } ] }
channels = ["soc-email"]
events = ["match", "kev_added", "exploitation_active", "severity_increase", "epss_increase", "nvd_score_added", "rejected"]
cvss_providers = ["cna", "nvd", "cisa-adp", "euvd", "other"]
```

- `name`: required and unique, case-insensitively. It starts with a letter or
  digit and contains at most 64 letters, digits, spaces, underscores, dots, or
  hyphens.
- `enabled`: defaults to `true`.
- `condition`: required. See the syntax below.
- `channels`: required, at least one name.
- `events`: defaults to every event kind above. An empty list is rejected.
- `cvss_providers`: defaults to every provider. Only these scores count as "the
  CVSS" for `cvss_min` and `cvss_max`.
- `old_cves`: `"digest"` (default), `"alert"`, or `"ignore"`; see
  [old CVEs](#old-cves).

A condition is a small boolean tree. A node is a table holding exactly one of
`all`, `any`, or `not`, or one or more leaf keys. Several leaf keys in one table
are ANDed:

```toml
condition = { all = [ { cvss_min = 9.0 }, { epss_min = 0.5 } ] }
condition = { any = [ { cvss_min = 9.0 }, { epss_min = 0.5 } ] }
condition = { cvss_min = 9.0 }
condition = { epss_min = 0.5 }
condition = { kev = "any" }
condition = { all = [ { kev = "any" }, { any = [ { cvss_min = 8 }, { epss_min = 0.5 } ] } ] }
condition = { all = [ { vendor = ["microsoft"] }, { cvss_min = 8 } ] }
condition = { all = [ { cvss_min = 9 }, { not = { vendor = ["examplecorp"] } } ] }
```

Limits: nesting depth at most 4, at most 32 leaves per rule, list values at
most 100 items, and strings at most 200 characters. Unknown keys are rejected,
empty `all`/`any` lists are rejected, and a boolean key cannot be mixed with
leaf keys in the same table.

Leaf keys:

- `cvss_min` (0 to 10): the highest score among `cvss_providers` is at least
  this value. A missing score is false.
- `cvss_max` (0 to 10): that highest score is at most this value. A missing
  score is false, so it never selects an unscored CVE.
- `epss_min` (0 to 1): EPSS is at least this value. A missing EPSS is false. A
  rule that uses `epss_min` requires `epss` in `watch.sources`.
- `kev = "cisa" | "eu" | "any"`: the CVE is in that KEV catalog. A rule that
  uses `kev = "eu"` requires `eu_kev` in `watch.sources`.
- `exploitation = "poc" | "active"`: `active` is true when SSVC reports
  active exploitation or, with `euvd` configured, EUVD has an exploitation
  date. `poc` is true for poc or active evidence from either source.
- `vendor`, `product`: case-insensitive exact names. They match against NVD CPE
  tokens (`palo_alto_networks`) and the selected EUVD item's display names
  (`Apache Software Foundation`). A rule must list both forms when the sources
  spell a name differently, or use a `keyword`.
- `keyword`: case-insensitive substring match in the description.
- `cwe`: CWE identifiers. `79`, `cwe-79`, and `CWE-79` are accepted and stored
  as `CWE-79`; anything else is rejected.
- `cna`: case-insensitive exact match against `source_identifier`.
- `status = "published" | "rejected"`.

Per provider, a CVSS 2.0 score is ignored when that provider also has a 3.x or
4.0 score. When one provider has both 3.x and 4.0 scores, the highest score is
used. Event reasons include the selected version, for example
`cvss 9.8 v3.1 (cna)`.

A rejected CVE never produces a `match` event unless `status = "rejected"` is
one of the true leaves of the evaluation. A negated status leaf does not count.

A rule that selects only the `euvd` CVSS provider requires `euvd` in
`watch.sources`. NVD is always available, so `kev = "cisa"` needs no catalog
setting.

The rule combinations above cover CVSS and EPSS together, either one alone, any
KEV addition, KEV gated by a score, vendor filters, and exclusions. `watch rules
check` prints each condition in readable form.

## Events

A rule produces a `match` event the first time its condition is true for a CVE.
The event records which leaves were true, for example `cvss 9.8 v3.1 (cna)`,
`epss 0.62`, and `kev cisa`. Later evaluations of that rule and CVE only produce
escalations, even when the condition is no longer true:

- `kev_added`: the CVE enters the CISA or EU KEV catalog.
- `exploitation_active`: SSVC or EUVD first reports active exploitation.
- `severity_increase`: the highest selected CVSS moves above its previous
  maximum band.
- `epss_increase`: EPSS moves above its previous maximum band. A first score
  below `0.1` does not escalate.
- `nvd_score_added`: an NVD score appears.
- `rejected`: the CVE changes from published to rejected.

Severity and EPSS keep high-water marks in the alert snapshot. A decrease
updates the current band silently, and reaching an earlier maximum again does
not alert again. A genuinely higher band alerts once, for example
`severity high -> critical`. `exploitation_active` names its evidence source,
for example `exploitation active (cisa-adp)` or
`exploitation active (euvd)`.

Reasons are stored separately from the event identity. Events are unique per
rule, CVE, kind, and occurrence:

- `match`: `match`
- `kev_added`: `<catalog>:<date_added>`
- `exploitation_active`: `active`
- `severity_increase` and `epss_increase`: the new band name
- `nvd_score_added`: `nvd`
- `rejected`: `rejected:<last_modified date>`

A KEV withdrawal and re-addition with a new date therefore alerts again, while
a failed download that restores the same entry does not. Repeating a run cannot
duplicate an event. Every event creates one pending delivery row per channel.

Rule state and event rule names are keyed by the casefolded rule name. A
case-only rename keeps the existing matches. A different rule name is a new
rule and starts with a new `match`. Renaming or removing a rule does not prune
its stored states; re-adding the same name keeps the old matches.
`watch evaluate --all` seeds a new rule against the full stored history; it
does not reset an existing rule's matches. A disabled rule's touches are
consumed; on re-enable, its escalations surface at the CVE's next touch.
After adding a rule, run `cvebeacon watch evaluate --all --yes` before the next
`watch run`. Otherwise old CVEs alert one by one when NVD next touches them.

Editing a rule's condition or `cvss_providers` keeps the existing matches. The
next evaluation compares against the stored state as usual, so an escalation
that arrives with the edit still alerts. A change to `cvss_providers` moves the
severity baseline to the new providers without an event, so the change alone
does not alert. Editing only channels or `events` does not reset state. A
disabled rule is not evaluated until it is
enabled again.

`cvebeacon watch events [--limit N] [--rule NAME] [--pending]` lists stored
events, newest first. `--rule` is case-insensitive. `--pending` keeps events
that still have a pending delivery. Each line ends with the CVE's
`Published YYYY-MM-DD · first seen YYYY-MM-DD` dates, with `Published unknown`
when the record has no publication date.

### Old CVEs

The first `match` for a CVE is treated as backlog when all of these hold:

- the CVE's `published` date is before the database's `initial_window_start`
  date (`initialized_at` for baseline mode, or when the window start is not
  stored);
- no CISA or EU KEV `date_added` for that CVE is on or after that date;
- no EUVD exploitation date (`exploitedSince`, when `euvd` is configured) is on
  or after that date. An unparseable EUVD date does not exempt the CVE.

Backlog matches keep `initial = 1`, so the delivery phase can fold them into a
digest. Later escalations behave normally: a new KEV addition, active
exploitation, a higher score band, or rejection still alerts. A first match of
an old CVE that an EPSS or SSVC change triggered is digested too, unless the
rule sets `old_cves = "alert"`.

`old_cves` controls this per rule:

- `"digest"` (default): backlog matches are initial and go to the digest.
- `"alert"`: backlog matches are ordinary alerts.
- `"ignore"`: the match is stored silently with no event. Later escalations
  still alert normally.

### First-run and `initial`

An evaluation during the first sync of a database in `backfill` or `full` mode
marks its `match` events `initial = 1`. `cvebeacon watch evaluate --all` marks
only the `match` events it creates as initial; escalations keep `initial = 0`.
It always does this, including after initialization is closed, so re-evaluating
after a rule change produces a summary digest instead of individual alerts. It
requires `--yes` or a confirmation. Once a failure-free initial sync has
finished all enabled sources, `evaluate --all` also records
`initial_evaluated_at` and clears the touch queue it evaluated, closing
initialization. Before that, for example after a source failure or an
interrupted full history, initialization stays open and the command says so.
Initial events are intended for one summary digest rather than individual
alerts. A baseline first sync stores no history, so it produces no events.
Later syncs evaluate only the CVEs touched by that sync.

## Vendor and product data

Vendor and product filters depend on source data being present. NVD supplies
CPE products after analysis, and EUVD supplies vendor and product names from
its `enisaIdVendor` and `enisaIdProduct` fields. NVD platform-only CPEs marked
`"vulnerable": false` are ignored. Up to 1,000 NVD vendor/product pairs are
stored, and the derived view keeps up to 500 vendor names and 500 product
names.

Names are matched exactly and case-insensitively. NVD uses CPE tokens such as
`palo_alto_networks`, while EUVD uses display names such as
`Apache Software Foundation`; list both forms, or add a `keyword`. Fresh CVEs
often have no CPE data yet. When a vendor filter matters, also add a `keyword`
alternative for important names.

EUVD data is used only when `"euvd"` is in `watch.sources`. Removing it from the
configuration removes EUVD scores, exploitation dates, and names from the
derived view, and queues every stored CVE for re-evaluation.

`not` over a missing vendor or product field is true, because a missing value
does not match the positive leaf. Prefer a positive filter for exclusions, or
pair the exclusion with another positive check. For example,
`{ all = [ { vendor = ["palo_alto_networks"] }, { not = { product = ["globalprotect"] } } ] }`
still matches a CVE whose product list is empty.

## Storage model

Each source keeps its own raw table; a CVE's combined view is derived when it
is needed. Watch databases created by earlier watch builds are migrated in
place to schema version 7. An unknown version still fails closed. The version 1
upgrade deletes the old `watch_touched` queue, because P1a had no rules and
therefore no evaluation obligation, and sets `initial_evaluated_at` whenever
`initial_mode` is already stored. It also rewinds `euvd_cursor` to
`initial_window_start`, but only when both values are stored, so the next sync
re-reads that window once. P1a stored EUVD items without vendor names, and that
re-read gives pre-upgrade items their names. In `full` mode
`initial_window_start` is 1999-01-01, so this re-reads the whole EUVD history
once. The version 2 upgrade keeps delivery rows and adds the `sending` and
`ambiguous` states. The version 3 upgrade adds `first_attempt_at`, which records
when a row was first claimed. The version 4 to 5 upgrade adds the
`watch_report` trail; the table is created by the schema step for every
upgrade, so older versions get it too, and no existing row is rewritten. The
version 5 to 7 upgrade adds the identity, operating-system account, host and
chain columns to `watch_report`. Existing rows keep their CVE, action, name,
note and time; the identity fields stay null, `chain_version` is 0 and the chain
is null, so those rows are explicitly legacy and unchained. The chain starts
with the first report written after the upgrade. A version 6 database keeps its
existing chains and gains `chain_version = 1` without re-hashing them. Migration
never rewrites a stored chain, even when the version metadata claims to be
older. Later edits and middle deletions then fail `watch reported --verify`.
After the upgrade, run
`cvebeacon watch evaluate --all --yes`
BEFORE the first `watch run`, as after adding a rule. Otherwise every CVE from
the initial window alerts one by one as NVD touches it. Schema 2 databases
written by a pre-release build of this branch are refused with a message to
delete them and run `watch sync` again. They are not migrated.

- `watch_cve` holds NVD-owned data only: status, description, CNA, CVSS from
  NVD, CNA, CISA ADP and other providers, SSVC, CPE products, references, and
  NVD's own CISA KEV fields.
- `watch_euvd_item` holds one row per EUVD item, keyed by `euvd_id`, whether or
  not its CVE is known. `watch_euvd_alias` maps each CVE alias to its items.
  When several items describe one CVE, the view uses the one with an
  exploitation date, then the latest `dateUpdated`, then the highest numeric
  EUVD id. Items are replaced in place when they change, and `seen_at` records
  the last observation, including identical re-reads.
- `watch_kev` holds CISA and EU catalog rows, keyed by catalog and CVE. Each
  successful catalog download replaces that catalog's rows in one transaction,
  including removals. When a catalog is configured it is the source for that
  part of the view; otherwise NVD's CISA KEV fields are used.
- `watch_epss` holds the current EPSS score, percentile, and score date for each
  CVE. It is replaced from FIRST's official dated file, at most once per file
  day.
- `watch_view` stores the alert-relevant fingerprint of each CVE's derived view.
  EPSS, identifiers, timestamps, and vendor/product names are excluded from
  that fingerprint.
- `watch_touched` is the durable evaluation queue. Every source transaction
  inserts the CVE ids it changed, so an interrupted or failed run cannot lose
  the obligation. Only ids with a `watch_cve` row are queued; an id first seen
  from EUVD or KEV is queued when NVD inserts its row. `pending_evaluations`
  reads the queue and `acknowledge` removes completed entries.
- `watch_alert_state` keeps the first match time, the alert snapshot, and the
  rule and CVSS-provider hashes for each casefolded rule name and CVE. A later
  evaluation compares against that snapshot.
- `watch_event` stores each event once. Its uniqueness key covers the rule,
  CVE, event kind, and occurrence; the reason text is stored separately.
- `watch_delivery` creates one row per event and channel. Its status is
  `pending`, `sending`, `sent`, `failed`, or `ambiguous`; `attempts`,
  `last_error`, and `updated_at` drive retries and status output.
- `watch_report` is the append-only report trail. Each row records the CVE,
  `report` or `unreport`, the display identity, user id and username when the
  identity mode provides them, the identity mode, the operating-system account,
  host, an optional note, a UTC time, and the audit chain value. The latest row
  for a CVE is its current state.
- `cvebeacon-users.db` sits beside the watch database and holds `cb_user`
  accounts and the `cb_user_audit` trail. Audit rows record the action, subject
  username, optional actor (administrator or `(bootstrap)`), time, operating-system
  account, host and chain value. It is not part of the watch database,
  so the watch history can be rebuilt without losing accounts, and its POSIX
  mode is `0600`. It contains password hashes; keep it with the watch database
  backup and inside the same ACL-protected directory on Windows.
- `watch_meta.view_policy` records the configured sources that affect view
  derivation: `cisa_kev`, `eu_kev`, `euvd`, and `epss`. When it changes, every stored
  view is recomputed in batches of 5,000 and every stored CVE is queued,
  including CVEs whose fingerprint did not change, because vendor and product
  names are not part of the fingerprint.
- `watch_meta.euvd_page_cursor` holds the in-progress EUVD window, its pinned
  total, the next page, the page size, and whether the window is being scanned
  or verified. It is cleared when the window commits.
- `watch_euvd_scan` holds the identifiers accepted so far in the active EUVD
  window, with their page. It is cleared when the window commits or restarts.
- `watch_meta.euvd_next_window` holds the next unread window saved with a
  completed EUVD window or with a split probe when catch-up work remains. It is
  cleared when that window starts committing pages or when catch-up reaches
  today.

`watch_touched` is the evaluation set; the view fingerprint only detects
escalations. NVD-only content changes such as products, CWEs, or description
still enqueue the CVE even when the fingerprint does not change.

EUVD item pruning runs once per day. It deletes items that have no
exploitation date, have not been seen for 30 days, and whose aliased CVEs are
all absent from `watch_cve`.

## NVD sync

NVD is read through the change feed in windows of at most 120 days. A window
whose first page reports more than one page of results (2,000) is split in
half by time until a window is one hour or shorter. Only such a window still
above 2,000 results is read page by page; its total is pinned and the window
restarts up to three times if the total or a CVE identifier repeats. Most
windows therefore need one request, which avoids churn between pages.

Each finished window is written with its `nvd_cursor` in the same transaction,
so a backfill or full run resumes from the last committed window. NVD rows are
created only by the change feed or by a lookup for a KEV/EUVD CVE described
below.

The stored cursor is `min(local time, NVD response timestamp)`. NVD timestamps
are accepted without a suffix, with `Z`, or with `+00:00`; anything else is
invalid. This keeps a device without a real-time clock from moving the cursor
past NVD's own time. A cursor more than 120 days old prints a warning and the
sync continues in bounded windows.

## EUVD sync

EUVD is read in 30-day chunks and `euvd_cursor` records the last fully
committed day. A chunk whose first page reports more than 10,000 items is split
in half by days, down to a one-day chunk. The split probe saves its first half
as the next window and clears any older page cursor and scan ledger in the same
transaction, before the first child page is read. Later windows are rebuilt
from that child's end, so nested splits leave no date gap even when a run makes
only one request. Every accepted page of the current scan is committed in its
own transaction, and a page cursor in `watch_meta` records the window, next page,
pinned total, the page size, and whether the window is being scanned or
verified. A throttled or interrupted run therefore keeps every completed page,
and the next run resumes at that page instead of replaying the window from its
first page. A single very busy day with more items than one run can fetch still
makes progress across runs; it does not need a smaller date range, which the
source cannot provide.

An active window keeps a durable identifier ledger of every accepted item, not
just the last page. A resumed page that repeats any identifier already accepted
in the window restarts the window from its first page. At the end of the scan,
the number of distinct accepted identifiers must equal the pinned total; a
mismatch also restarts the window, up to three scans per window in one sync
invocation. A later invocation retries the window with a fresh attempt count;
pages already committed for that window remain, while each restart begins a new
scan from page 0. Pages that were accepted in earlier runs are then re-read in a
resumable verification pass. The window is complete only when every verified
page still has the identifiers accepted for it; a changed total or page
contents restart the scan. A window completed in a single run needs no
verification because every page was read in that run. If a window still cannot
be scanned after the bounded restarts, the source fails and the next run tries
the same window again. This fails closed on the instability that is actually
detected. A mutation after a page's final scan or verification read can still go
unseen, because the source exposes no snapshot or version token; the
implementation does not claim to detect every possible continuing mutation.

When a window completes, `euvd_cursor` moves to its end and the page cursor and
ledger are cleared in the same transaction. If catch-up work remains, the next
unread window is stored in the same transaction, so a request limit reached on
the last page of a busy day cannot make the next run replay that day. The next
run continues with the saved window; once catch-up reaches today, the ordinary
inclusive re-read of the cursor day resumes. The cursor only moves forward, so a
device without a real-time clock cannot rewind it. The request end is always
widened by one day while the cursor stays at the chunk end: same-day EUVD
queries otherwise report a total below the number of items they return.
Requests are paced at least one second apart.

Each page must contain the expected number of items. A cursor written without
the current page size or phase is restarted from the window's first page rather
than being interpreted at the wrong offset, and a ledger that does not match
the saved page is rebuilt the same way.

When a request returns HTTP 403 or 429 after at least one successful request
from the same source in the run, watch mode treats it as throttling. It honours
a usable `Retry-After` when present and otherwise waits 60, 120, then 240 seconds,
shortening the last wait to the remaining budget, then retries the same
request; an unusable header uses those scheduled waits. Each wait is capped at
240 seconds and all waits share a 10-minute budget per run, including the EU KEV
dump on the same host. A `Retry-After` longer than the remaining budget ends
the retries. When the budget is exhausted the source fails as usual and every
completed page stays committed.

The first request of each EU source has its own 403 rule. A first EUVD request
that is rejected fails immediately even when the EU KEV dump earlier in the run
succeeded, because a rejected query is a more likely cause than throttling. The
EU KEV dump itself fails immediately on a first 403. The successful KEV request
does not reset the shared wait counters, so later retries still draw on the same
600-second budget.

The EU KEV dump is a single request and is fetched before the EUVD backfill, so
a long EUVD catch-up cannot exhaust the shared budget before the dump is read.
A run whose first EU request is a 403 fails the dump immediately and does not
retry it.

This backoff belongs to watch sync. Scan and package-query EUVD lookups use a
separate, unpaced search adapter; they do not use this budget and report a
failed EUVD source for that asset instead.

## KEV and early lookups

The CISA and EU KEV catalogs are downloaded once per run and replace their
previous rows. For a CVE that NVD has not created yet, the sync tracks a
bounded lookup in `watch_lookup`:

- KEV entries in a configured catalog whose `dateAdded` is on or after the
  start of the database's initial window (never for full mode);
- EUVD items with an exploitation date whose CVE is not in `watch_cve`.

Up to 25 lookups run per sync, oldest due first. A failed lookup keeps its row
and backs off for 1 hour, doubling to a maximum of 7 days; attempts never reset
because a catalog is downloaded again. The row is removed when the CVE appears
in `watch_cve` or its trigger disappears.

Failed lookups are reported on the NVD summary line as
`, N lookup(s) failed`. They do not change the exit code. `watch status` shows
`lookups pending/backing off: N`.

## EPSS

While `epss_file_day` is earlier than today, the sync downloads
`https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` directly,
without following redirects. It tries today and then yesterday; HTTP 403 and
404 both mean the dated file is not published yet. `epss_file_day` records the
day of the file that was loaded, so a later run asks again until today's file
appears. When yesterday's file is already loaded, only a small request for
today is made until it is published. A clock that moves backwards never
reloads an older file.

The file is decompressed and parsed as a stream, never held whole in memory,
and written in batches of 5,000 rows in one transaction. The compressed file
is capped at 20 MB and the decompressed stream at 64 MB. Comment and header
lines are read with a 4,096-character bound and data lines with a 256-character
bound; a longer line is rejected, as is an unterminated line except a complete
final one. Fields are split directly on commas, and every score and CVE
identifier is validated. A file with fewer than 100,000 rows is rejected, as is
one with fewer than half of the current table's rows when the table is not
empty. The header's `score_date` may be a date or a UTC timestamp with `Z` or
`+00:00`; its UTC date must be the requested day or the day before. A
validation error fails the EPSS step (exit 4) and keeps the previous table,
including corrupt gzip data.

The view reads EPSS directly. The daily load queues a watched CVE when its
score appears or disappears, or when the old-to-new move crosses any threshold
in the set passed to the store. The sync always includes the band edges `0.1`,
`0.5`, and `0.9`, plus every `epss_min` used by an enabled rule, so a rule sees
threshold crossings even when the score stays inside the same band.

## Initial modes

The first sync chooses what history to build:

- `baseline` (default): reads nothing, stores no CVE history, and sets the NVD
  cursor to the current time. Later syncs start from there. This is the
  cheapest and safest choice for a new deployment.
- `backfill`: reads NVD changes from the last `backfill_days` days and EUVD
  changes from the same date range.
- `full`: reads NVD history from 1999-01-01 and EUVD history from 1999-01-01.
  Before starting it prints the NVD window count, the request floors, a
  pacing-based minimum time, and the one EPSS file per day, then requires
  `--yes` or an interactive confirmation. When stdin is not a terminal, it
  prints a one-line instruction and cancels instead of waiting; run
  `watch sync --yes` once before the first scheduled run.

`initialized_at` is set only when an initial run reaches its last NVD window,
so it records NVD progress and resume state, not completion of the whole initial
sync. A resumed initial run continues from the stored cursor and does not ask
for confirmation again. `initial_sync_completed_at` is set only after an
initial sync finishes every enabled source without a failure.
`initial_evaluated_at` is set after an initial evaluation completes during a
clean sync, or by `watch evaluate --all` once `initial_sync_completed_at` is
set; until then, later runs keep `initial = 1` for matches and backlog matches.
A database whose initial sync finished before `initial_sync_completed_at`
existed, and whose initial evaluation is still open, needs one successful
`watch sync` after upgrading before `watch evaluate --all` can close it; one
clean `watch run` also completes it.
`initial_window_start` is the boundary used by the `old_cves` policy in
baseline, backfill, and full mode.

After the first sync, `nvd_cursor` advances to the end of the window that was
read. Later runs start `overlap_minutes` before that cursor and end at the
current time. `euvd_cursor` is a date and is re-read inclusively, so a second
sync on the same day reads the same EUVD day again. While a large EUVD window
is incomplete, its page cursor resumes at the next unread page. When a window
finishes but catch-up work remains, the saved successor window is read next, so
a completed busy day is not replayed; the inclusive re-read resumes once
catch-up has reached today. Pages from earlier runs are verified before the
window's cursor advances.

## Failure behavior

- An NVD failure aborts the sync with exit code 2. Windows already committed
  keep their records and cursor; nothing past the cursor is committed and the
  next run resumes there.
- If an optional source fails, the NVD data is committed, the failing source is
  named, and the command exits 4. Its cursor does not advance past the last
  completed window. A failed EPSS download keeps the previous table.
- EUVD throttling is retried within the run, for up to 10 minutes of waits. The
  EU KEV dump is fetched before the EUVD backfill and shares that budget for any
  retry; as the first EU request, its first 403 fails immediately. A run that
  exhausts the budget fails the source, keeps every completed EUVD page and the
  previous KEV rows, and exits 4.
- Committed source changes also remain in `watch_touched`, so a later failure or
  interruption does not lose an evaluation obligation. The initial window stays
  open until every enabled source has finished a sync without a failure and an
  evaluation completes. That failure-free sync records `initial_sync_completed_at`;
  `watch evaluate --all` closes initialization only when that marker exists.
- A successful sync exits 0. A refused or cancelled sync does not contact the
  sources.

`watch status` prints the database path, schema version, cursors, EPSS score
date, row counts, EUVD items, KEV catalog entries, watched CVEs in KEV, active
SSVC exploitation, EPSS rows, pending/backing-off lookups, and the number of
CVEs marked as reported to clients. When a large EUVD window is still being
read, the EUVD cursor line also names the window, whether it is being scanned
or verified, and the next page, so a throttled full-history catch-up shows its
progress. When a completed window has a saved successor whose first page has
not been read yet, the line names that next window. It also prints
each channel's pending, failed (with the given-up count), ambiguous, sending,
and last success counts. It creates an empty database if none exists.

## Summary lines

Each source prints `request(s)`, `record(s)`, `new`, and `changed`.
`request(s)` counts every HTTP attempt, including retries. When EUVD or the EU
KEV dump backed off during the run, its line also adds
`throttled Nx, waited Ns`.

- `nvd`: `record(s)` counts CVE rows read, `new` counts inserted rows, and
  `changed` counts derived-view fingerprint changes.
- `euvd`: `record(s)` counts EUVD items processed, including verification
  re-reads and pages read again after a restart (a repeated page is counted
  again); `new` counts new items, and `changed` counts derived-view fingerprint
  changes.
- `cisa_kev` and `eu_kev`: `record(s)` counts catalog entries, `new` counts
  entries absent from the previous catalog, and `changed` counts derived-view
  fingerprint changes.
- `epss`: `record(s)` counts score rows loaded and `changed` counts watched
  CVEs queued by an appearance, disappearance, or configured threshold
  crossing.

After a `watch run` the delivery step prints one line per channel, for example
`soc (smtp): 1 message, 4 events sent`, with failed or ambiguous counts when
they are non-zero.

## Cost

A normal sync is small: one or more NVD pages for the cursor window, one EUVD
page or a few, the KEV catalogs, and at most one EPSS file plus a probe when
today's file is not published yet. NVD is paced at the configured interval;
EUVD is paced at one second. Without an NVD API key, NVD allows five requests
per 30 seconds; with a key, fifty.

`initial = "full"` is the expensive path. From 1999 to the present there are
about 85 NVD windows. A busy window can need many pages, so expect roughly 400
or more NVD requests and roughly 4,200 EUVD requests; both counts are planning
floors, not measurements. The pacing-based minimum uses the configured NVD
interval for NVD requests and the fixed one-second EUVD pace for EUVD requests:
at least 2 hours at the default NVD interval before extra NVD pages, retries,
and throttling. Under throttling, EUVD full history needs several scheduled
runs: each run reads and commits the pages the budget allows, `watch status`
shows the window, phase, and page, and the next run continues there. Pages
accepted in earlier runs are re-read once to verify them, so a fully throttled
catch-up needs a second pass over that progress; the pass is itself resumable.
Budget several hours of continuous work, a large download, and many small
database commits. EPSS is one current file per sync, not one per historical day.
Run full history deliberately, preferably with an NVD API key.

## Source attribution

Watch mode uses the same public sources as the rest of CVEBeacon:

- [NIST National Vulnerability Database](https://nvd.nist.gov/developers/vulnerabilities)
  for CVE records, CVSS, SSVC, and KEV metadata. This product uses data from
  the NVD API but is not endorsed or certified by the NVD.
- [ENISA EUVD](https://euvd.enisa.europa.eu/) for European enrichment and
  exploitation information.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
  the ENISA consolidated EU KEV dump.
- [FIRST EPSS](https://www.first.org/epss/) for exploitation probability.

See [sources](SOURCES.md) for the full source roles and limitations.
