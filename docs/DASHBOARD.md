# Dashboard

Launch from the directory containing your configuration, or provide an explicit path:

```console
cvebeacon --config /absolute/path/cvebeacon.toml serve
```

The default address is `http://127.0.0.1:8787`. Windows packages use `cvebeacon.exe serve`; Linux packages use `./cvebeacon serve`. The server prints its listening address after binding successfully. No development or debugging console is enabled.

To select a port or deliberately bind to the LAN with password authentication configured as below:

```console
cvebeacon serve --host 0.0.0.0 --port 8787
```

The dashboard is optional. Continue running `cvebeacon scan` as a separate short-lived scheduled process. The dashboard does not schedule scans, send notifications, or start background refresh workers.

## Views and investigation

- **Overview:** last successful full scan, most recent attempted scan, current inventory count, latest known affected/review findings, coverage gaps, KEV counts, recent material changes, notification acceptance/failure, and source observations.
- **Findings:** filter by asset, vendor, product, version, CVE, applicability, severity or minimum CVSS, and CISA/EU KEV. Expand evidence to see the assessment reason, provenance, conflicts, CVSS and EPSS. Unknown KEV membership is distinct from a healthy negative result.
- **Assets:** search the current configured inventory and inspect an asset's stored findings. A changed version or removed asset leaves its older observations explicitly labelled as historical.
- **History:** browse material events, filter exact asset/CVE identifiers, and open the evidence saved with an event. Older-event links provide access beyond the first page.
- **Manual query:** query a vendor/product/version using the same core operation as the CLI. Results show uncertainty and degraded source status. Queries can take several minutes and do not change scheduled alert state.
- **Reports:** query the current inventory and download an XLSX or JSON report using the existing reporting functions. Exports do not commit monitoring state. Check the report's coverage and source-health fields even when the download succeeds.
- **Sources:** view cached observations from the latest recorded scan, including check result, retrieval time and available source timestamp. Opening this page does not contact the sources.

### Watch views

The **Watch** pages read the watch database through the same store and status
helpers as `cvebeacon watch status`. They never contact a source and do not
change scan or delivery state.

- **Watch overview:** database path and schema, NVD and EUVD cursors (including
  EUVD page progress), the last sync per source with request counts, EPSS score
  date, watched/KEV/SSVC counts, per-channel pending, sending, failed and
  ambiguous deliveries, the reported-to-clients count, and initial-mode state.
  A database written before sync summaries were recorded shows the counts as not
  recorded until the next sync.
- **Events:** filter by rule, kind, initial flag, date range, exact CVE and
  pending delivery. Results are ordered newest first and limited to 50 per page.
  Each row shows the published and first-seen dates and the current reported
  mark. Report and unreport notices are excluded; they appear in the CVE trail.
- **CVE detail:** the stored view with CVSS by provider, EPSS, CISA and EU KEV
  dates and required action, SSVC exploitation, CWEs, products, references,
  publication and first-seen dates, the CVE's events with per-channel delivery
  state, and the report/unreport trail with its notice states. Links open NVD,
  CVE.org and EUVD. Reference links are rendered only for HTTP and HTTPS URLs.
- **Reported to clients:** current report marks, 100 per page. The full
  append-only report/unreport trail downloads as CSV or JSON and requires
  `view_audit`; the current list requires `view`. CSV cells beginning with
  `=`, `+`, `-`, `@`, tab or carriage return are prefixed with an apostrophe so
  spreadsheet software treats them as text.
- **Statement:** render one stored CVE from the built-in Markdown template or an
  uploaded UTF-8 `.md`/`.txt` or `.docx` template. Uploads are limited to 5 MiB,
  read through the existing hardened statement renderer, and processed only in a
  temporary directory. The generated file is downloaded and not stored by the
  dashboard.

Reporting from the dashboard requires `report` and always uses the logged-in
account, never a name supplied by the form. The configured identity mode still
applies: in `open` mode the account username is recorded as the open identity,
in `registered` mode the enabled account is resolved to its display identity,
and in `authenticated` mode the existing dashboard session proof is accepted
without asking for the password again. The account and credential version are
rechecked inside the report write transaction, so a disabled or changed account
fails closed. A channel with `notify_reported = true` gets a queued notice; the
delivery state is shown in the trail, and delivery still runs through
`cvebeacon watch notify` or `watch run`. The shared-password compatibility mode
can browse watch pages and generate statements, but cannot record a client
report because there is no CVEBeacon account identity.

## Freshness and failures

Stored data is not live source availability. A successful check is labelled as a cached observation and becomes stale after 24 hours. Old scan data, failed/degraded scans, and scan attempts without recorded completion receive prominent warnings. An unfinished attempt may represent a running or interrupted scanner; check the actual process and logs.

Retained findings keep their last observation timestamp. A failed refresh cannot make older SQLite data appear newly observed. Asset identities absent from the last scan, changed inventory versions, and legacy scans without per-asset metadata have unknown coverage. Counts describe stored observations, not proof that the current inventory is clean.

New scan-attempt metadata covers failures after configuration loads and the state database opens. Failures before that point cannot be written to SQLite; monitor scheduler exit codes/logs as well as the displayed scan age. Delivery acceptance is reported separately from full-scan success and does not establish recipient receipt.

## Network and security

With no CVEBeacon accounts, localhost use requires no login by default. Without authentication, clients that can reach the dashboard can read observations and initiate manual queries or reports. A non-loopback bind without authentication is refused unless you explicitly pass `--allow-unauthenticated-remote`. Use that override only with appropriate external access controls; do not expose an unauthenticated instance to the public internet.

### Accounts and bootstrap

The dashboard uses the same accounts as `cvebeacon users` and watch reporting,
regardless of the reporting identity setting. Create the deploying administrator
with `cvebeacon users add USERNAME --admin` (see [accounts](WATCH.md#identity-modes-and-accounts)).
Keep a second enabled administrator for recovery. The last enabled administrator
cannot be disabled or demoted, including through the CLI; concurrent changes
are checked in the same database transaction. Accounts are disabled rather than
deleted, preserving identity and audit references.

Alternatively, on a fresh installation visit `/bootstrap` from localhost and
choose the first administrator's username and password. This works only while
the account store is completely empty and the directly connected peer is a
loopback IP address. When a shared password is configured, complete the
shared-password login before opening bootstrap. It ignores forwarded addresses.
**The first person to
complete this form controls the dashboard. Bootstrap on a trusted local
computer before exposing the service. A local reverse proxy makes remote
visitors appear local: never expose an empty account store through it.** CLI
bootstrap remains available when existing non-admin accounts predate dashboard
setup; the dashboard bootstrap cannot claim such a store.

Once any account exists, every dashboard request uses individual account login.
The shared dashboard password and old shared-password sessions are refused,
including when accounts are created while the server is running. A disabled
account or an account without a password cannot log in. If all pre-existing
accounts lack passwords, set them using `users passwd` locally. Account-store
errors fail closed; they do not enable anonymous access. Restart after restoring
an account-store backup. The persistent sibling creation-lock file
(`cvebeacon-users.db.lock`, or the configured database name plus `.lock`) also
records prior initialization. Keep it with the account database and its backups;
do not remove it to work around an error. If it exists but the database is
missing, startup fails even with a shared password or the remote-access override.
Unreadable or invalid stores also fail closed. Stop the dashboard, restore the
correct account database with service-account ownership and private permissions,
then restart. A fresh installation has neither file.

An upgraded store with **no enabled administrator** reports that condition in
the startup logs. Recover from the service-account shell with
`cvebeacon users add RECOVERY_NAME --admin`, choosing a new username and a strong
password. This local bootstrap works only while there is no enabled administrator,
including in authenticated reporting mode; it is checked again in the creation
transaction. Existing disabled administrators remain disabled. Dashboard bootstrap
still requires a completely empty store.

Login uses the existing scrypt verification, dummy verification for unknown or
unusable accounts, generic failure message, and account lockout: five failed
attempts lock the account for fifteen minutes. Administrators can unlock it.
Account login also reserves per-origin exponential backoff from 1 to 60 seconds
before verification, using at most 4096 origins retained for fifteen minutes.
Only two password verifications can run concurrently in the server; excess
attempts fail immediately without occupying workers waiting for a hash slot.
Forwarded addresses are ignored, so clients behind one proxy share its limit.
Password hashing runs outside the account write transaction; credentials and
lockout are rechecked atomically afterward. Identity checks use read transactions.
The first 10,000 failed or locked attempts per store are retained, followed by one
`login_failures_suppressed` entry. Further failures do not add audit rows; lockout
still applies and successful logins and administrative actions remain audited.
Existing audit rows are preserved, including when an older store exceeds this
limit. Requests rejected before password verification do not add audit entries.
Passwords accept 12–1024 characters, must contain non-whitespace text, and must
differ from the username and email. Users can change their own password under
**My account and sessions** by supplying their current password. Administrators
set a password when creating or resetting an account and must share it privately
with its holder. There is no temporary-password or email-delivery workflow.

### Roles and permissions

**Users** requires `manage_users`; **Roles** requires an administrator.
User management supports adding accounts, editing display name and email,
setting passwords, enabling/disabling accounts, unlocking, and assigning one
role per account. The `admin` role follows the
existing account admin flag, always has every permission, and cannot be edited
or deleted. Editable defaults are `viewer` (`view`) and `operator` (`view`,
`report`, `statement`, `run`, `retry`, `test_channel`). Existing non-admin accounts
receive `viewer` during migration. Administrators can create roles with any
subset of the fixed permissions, edit defaults, and delete unassigned roles.
Reassign users before deleting their role. Deleted defaults stay deleted.

Only administrators can grant or revoke admin, modify an administrator's
profile, enabled state or password, unlock an administrator, or create, edit or
delete roles. A non-admin with `manage_users` can manage non-admin accounts only
within their own permissions and assign roles whose permissions are a subset of
their own. They cannot change their own role. Password resets cannot take over an
account with broader permissions. These limits are rechecked inside each user-store
transaction. Every route declares a policy checked on the server. Changing a
role's permissions takes effect on the next
request; changing an account's profile, role or enabled status revokes its
existing sessions. Each account can always access its own account page and
logout, even if its role has no permissions.

| Permission | Capability |
| --- | --- |
| `view` | Observation pages, findings, watch pages, the current reported list, query results and exports |
| `report` | Mark or unmark a CVE as reported from the CLI or dashboard |
| `statement` | Generate statements from the CLI or dashboard |
| `run` | Operation forms; submit manual queries and inventory report exports with `view`; reserved sync, evaluation and notification operations |
| `retry` | Retry failed or ambiguous deliveries |
| `test_channel` | Send channel tests |
| `edit_rules` | Edit rules |
| `edit_channels` | Edit notification channels |
| `edit_sources` | Edit source settings |
| `edit_watch` | Edit watch settings |
| `edit_reporting` | Edit reporting settings |
| `edit_dashboard` | Edit dashboard settings |
| `edit_inventory` | Edit inventory settings |
| `edit_http` | Edit HTTP client settings |
| `manage_schedule` | Manage scheduling |
| `manage_users` | Manage non-admin accounts and role assignments within the acting permissions; administrators can manage all accounts |
| `view_audit` | View account administration, login and logout history, with hash-chain verification status; export the full reported audit trail |

Some capabilities reserve authorization for later dashboard operations; granting
them does not add an operation that the current dashboard does not implement.
Opening query/report forms requires `run`; submissions require both `run` and
`view` because they return findings or exports.
Role changes and administrative account actions are recorded in the existing
chained user audit trail. Verification detects changes within that trail, not
direct edits to `cb_user`, `cb_role` or `cb_user_role`, or removal of its final
rows; protect database files and backups as described in the watch guide.

### Account sessions

Account login places only a fresh random session identifier in the
`cvebeacon_account` cookie. The server keeps the identity, credential version,
CSRF token, creation time and last activity in bounded process memory. This
avoids persistent bearer credentials and additional database writes for each
session touch. Separate pools hold at most 256 authenticated sessions and
256 anonymous login forms. Anonymous allocation never evicts an authenticated
session. Authenticated sessions are limited to 16 per account; another login can
evict that account's oldest session. When the authenticated pool is full, new
logins are refused until space becomes available. Other accounts' sessions are
preserved. Use one server process; independent processes do not share sessions. Restarts invalidate them all.

Cookies are HttpOnly and SameSite=Strict; enable `secure_cookie` with browser-facing
HTTPS. Account sessions expire absolutely after `session_lifetime_seconds`
(default 3600) or after `session_idle_seconds` without a request (default 900).
Both settings accept integers from 60 to 86400. Activity cannot extend the
absolute deadline. Password changes, enable/disable, profile/role assignment
changes, and credential-version changes revoke existing sessions. Logout
immediately revokes the current session. **Log out of all sessions** revokes
every login using the account's credential version, including other processes.
The account page lists valid sessions in the current process by age and idle
time without displaying bearer identifiers. All forms, including login and
bootstrap, require a session-bound CSRF token; login rotates both identifiers
and tokens.

```toml
[dashboard]
password_hash_env = "CVEBEACON_DASHBOARD_PASSWORD_HASH" # Used only without accounts
session_lifetime_seconds = 3600
session_idle_seconds = 900 # Account sessions only
secure_cookie = false # Set true behind browser-facing HTTPS
```

### Optional local password

This compatibility mode applies only while there are no CVEBeacon accounts.

Generate a strong salted scrypt hash with the existing Werkzeug primitives:

```console
cvebeacon dashboard hash-password
```

The helper requires a terminal with hidden input, asks for confirmation, and accepts 12–1024 characters. Use a long unique password. It prints only the hash and needs no inventory or configuration. Supply the output through `CVEBEACON_DASHBOARD_PASSWORD_HASH` in the server process environment using your deployment's secret injection. Never place the password or hash in TOML, source control, command arguments, logs, or SQLite. Keep the hash private too. The supported hash format is Werkzeug's `scrypt:32768:8:1`; regenerate unsupported hashes with the helper. In this compatibility mode, an unset variable disables shared authentication;
an empty or invalid value prevents startup. Once accounts exist, this hash is
ignored, including invalid values.

Optional TOML settings contain no password material:

```toml
[dashboard]
password_hash_env = "CVEBEACON_DASHBOARD_PASSWORD_HASH"
session_lifetime_seconds = 3600
secure_cookie = false
```

When enabled, all observation, query, report and history routes require login. The login page and bundled static assets are public. The
empty-store, direct-loopback `/bootstrap` exception described under
[Accounts and bootstrap](#accounts-and-bootstrap) requires shared-password login
when a shared password is configured. Login clears earlier session state and rotates the CSRF token. Sessions expire absolutely after one hour by default (configurable from 60 to 86400 seconds), regardless of activity. **Log out** uses a CSRF-protected POST and revokes that session immediately, including copies of its cookie. Cookies use HttpOnly and SameSite=Strict without a persistent remember-me expiry. Restarting the server invalidates all sessions. At most 256 active sessions are kept; a new successful login can evict the oldest.

Failed attempts use per-origin exponential delays from 1 to 60 seconds. The bounded process-local table retains at most 4096 origins for 15 minutes after an attempt. When full, a new origin evicts the least recently attempted entry so unrelated clients are not globally locked out. Cookies cannot bypass a retained origin's delay; attacks rotating through more origins than the table holds can defeat per-origin retention. There is no permanent account lockout. This is a small single-process dashboard, not a distributed authentication service; volumetric attacks still require network controls. A reverse proxy's backend address is the origin for throttling, so clients sharing that proxy share a limit.

### Remote transport and reverse proxy

Built-in password authentication does **not** protect passwords or session cookies from interception over plain HTTP. For remote authenticated use, terminate HTTPS at a trusted reverse proxy or provide an equivalent encrypted transport. Set `secure_cookie = true` when the browser-facing connection is HTTPS. This flag controls browser cookie transport; it does not enable TLS on the dashboard itself. Configure HSTS at the HTTPS proxy. Restrict direct backend access and protect any backend network hop. Password auth does not replace firewall or normal network security controls.

Loopback bindings validate the requested host. Wildcard bindings accept numeric IP host headers and `localhost`, protecting against arbitrary hostname rebinding. For a reverse proxy, forward a numeric backend `Host` header and preserve the application at the URL root. Forwarded host, address and scheme headers are not trusted. A specific hostname binding accepts that hostname. Outbound TLS verification remains enabled. Password configuration affects only the dashboard; core monitoring continues to work without credentials.

Forms use CSRF protection, output is escaped, errors omit sensitive details, and downloads cannot select filesystem paths. Configuration and credential values are not rendered. Report/query operations are synchronous; avoid submitting repeated requests while an investigation is running.

The monitoring SQLite database stores observations and dashboard scan metadata.
Accounts and roles live separately in `cvebeacon-users.db` beside the watch
database. Before an upgrade, stop the scanner/dashboard and back up both data
stores. Schema upgrades preserve existing observations and delivery records;
an older application requires its corresponding pre-upgrade backups.

## Package identities and advisory views

The manual query page has Product, Package (ecosystem/name/version), and Explicit PURL modes. Each uses the CLI assessment engine and preserves monitoring/event/delivery state. Findings can be filtered by category, system, ecosystem, PURL, advisory ID and CVE alias. Asset and evidence details show supplied identities, aliases and fixed boundaries. Fixed boundaries require review of the branch and source range before choosing an upgrade. Reports include separate Identities and Advisory Details sheets to keep Findings compact. Authentication and CSRF protection apply equally to all query modes.
