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
```

`watch run` syncs the sources, evaluates the CVEs touched by that sync, and
delivers pending alerts. `watch sync` only syncs; the durable touch queue keeps
the evaluation for the next `watch run`. `watch notify` delivers pending alerts
without syncing or evaluating.

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

### Microsoft Graph

```toml
[watch.channels.m365]
type = "graph"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "00000000-0000-0000-0000-000000000000"
client_secret_env = "CVEBEACON_GRAPH_CLIENT_SECRET"
sender = "alerts@example.com"
to = ["soc@example.com"]
```

This sends through the Microsoft Graph `sendMail` endpoint and needs an
application permission such as `Mail.Send` for the sender mailbox. `cc` and
`bcc` recipients are sent as Graph `ccRecipients` and `bccRecipients`.

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
`Title` header. Subjects use ASCII, so the header needs no RFC 2047 encoding.

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
are counted in UTF-8 bytes. Email has no practical limit but still applies
`max_items`.

Links: the NVD detail page is always present, the CVE.org record is always
present, the EUVD detail page appears when an EUVD id exists, and the CISA KEV
catalog link appears when the CVE is in KEV.

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
when the value is absent. The order is the same as the text messages. A test
message adds `"test": true` and `"message"` and has an empty `events` list.

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
place to schema version 4. An unknown version still fails closed. The version 1
upgrade deletes the old `watch_touched` queue, because P1a had no rules and
therefore no evaluation obligation, and sets `initial_evaluated_at` whenever
`initial_mode` is already stored. It also rewinds `euvd_cursor` to
`initial_window_start`, but only when both values are stored, so the next sync
re-reads that window once. P1a stored EUVD items without vendor names, and that
re-read gives pre-upgrade items their names. In `full` mode
`initial_window_start` is 1999-01-01, so this re-reads the whole EUVD history
once. The version 2 upgrade keeps delivery rows and adds the `sending` and
`ambiguous` states. The version 3 upgrade adds `first_attempt_at`, which records
when a row was first claimed. After the upgrade, run
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
- `watch_meta.view_policy` records the configured sources that affect view
  derivation: `cisa_kev`, `eu_kev`, `euvd`, and `epss`. When it changes, every stored
  view is recomputed in batches of 5,000 and every stored CVE is queued,
  including CVEs whose fingerprint did not change, because vendor and product
  names are not part of the fingerprint.

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

EUVD is read in 30-day chunks and `euvd_cursor` is committed after each chunk.
A chunk whose first page reports more than 10,000 items is split in half by
days, down to a one-day chunk, and every sub-chunk commits on its own. The
cursor only moves forward, so a device without a real-time clock cannot
rewind it. The request end is always widened by one day while the cursor stays
at the chunk end: same-day EUVD queries otherwise report a total below the
number of items they return. Requests are paced at least one second apart. A
page that repeats an EUVD id restarts the chunk through the same bounded
retry path, and the distinct item count must equal the pinned total before the
chunk commits. A failed chunk leaves the cursor at the previous chunk.

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
  Before starting it prints an estimate of the NVD windows, request counts, and
  the one EPSS file per day, then requires `--yes` or an interactive
  confirmation. When stdin is not a terminal, it prints a one-line instruction
  and cancels instead of waiting; run `watch sync --yes` once before the first
  scheduled run.

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
sync on the same day reads the same EUVD day again.

## Failure behavior

- An NVD failure aborts the sync with exit code 2. Windows already committed
  keep their records and cursor; nothing past the cursor is committed and the
  next run resumes there.
- If an optional source fails, the NVD data is committed, the failing source is
  named, and the command exits 4. Its cursor does not advance past the last
  successful chunk. A failed EPSS download keeps the previous table.
- Committed source changes also remain in `watch_touched`, so a later failure or
  interruption does not lose an evaluation obligation. The initial window stays
  open until every enabled source has finished a sync without a failure and an
  evaluation completes. That failure-free sync records `initial_sync_completed_at`;
  `watch evaluate --all` closes initialization only when that marker exists.
- A successful sync exits 0. A refused or cancelled sync does not contact the
  sources.

`watch status` prints the database path, schema version, cursors, EPSS score
date, row counts, EUVD items, KEV catalog entries, watched CVEs in KEV, active
SSVC exploitation, EPSS rows, and pending/backing-off lookups. It also prints
each channel's pending, failed (with the given-up count), ambiguous, sending,
and last success counts. It creates an empty database if none exists.

## Summary lines

Each source prints `request(s)`, `record(s)`, `new`, and `changed`.
`request(s)` counts every HTTP attempt, including retries.

- `nvd`: `record(s)` counts CVE rows read, `new` counts inserted rows, and
  `changed` counts derived-view fingerprint changes.
- `euvd`: `record(s)` counts EUVD items read, `new` counts new items, and
  `changed` counts derived-view fingerprint changes.
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
or more NVD requests and roughly 4,200 EUVD requests. At the default pacing
that is several hours of continuous work, a large download, and many small
database commits. EPSS is one current file per sync, not one per historical
day. Run full history deliberately, preferably with an NVD API key.

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
