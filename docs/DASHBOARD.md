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

The dashboard is optional. Scheduled scans and watches remain separate short-lived processes. An authenticated account with the `run` permission can start the same `cvebeacon` commands as background jobs from the **Operations** page; every data-changing job shares a single-flight lock with the command line and scheduled runs.

With no `[inventory] path` and watch mode enabled, the dashboard starts in watch-only mode. Watch, Clients, Operations with watch jobs, accounts, audit and the native schedule remain available. Inventory views show a notice with a configuration example and a link to the user guide, and Operations explains that inventory scan and combined run jobs are unavailable.

## Views and investigation

- **Overview:** last successful full scan, most recent attempted scan, current inventory count, latest known affected/review findings, coverage gaps, KEV counts, recent material changes, notification acceptance/failure, and source observations.
- **Findings:** filter by asset, vendor, product, version, CVE, applicability, severity or minimum CVSS, and CISA/EU KEV. Expand evidence to see the assessment reason, provenance, conflicts, CVSS and EPSS. Unknown KEV membership is distinct from a healthy negative result.
- **Assets:** search the current configured inventory and inspect an asset's stored findings. A changed version or removed asset leaves its older observations explicitly labelled as historical.
- **History:** browse material events, filter exact asset/CVE identifiers, and open the evidence saved with an event. Older-event links provide access beyond the first page.
- **Manual query:** query a vendor/product/version using the same core operation as the CLI. Results show uncertainty and degraded source status. Queries can take several minutes and do not change scheduled alert state.
- **Reports:** query the current inventory and download an XLSX or JSON report using the existing reporting functions. Exports do not commit monitoring state. Check the report's coverage and source-health fields even when the download succeeds.
- **Sources:** view cached observations from the latest recorded scan, including check result, retrieval time and available source timestamp. Opening this page does not contact the sources.
- **Operations:** start `scan`, `watch sync`, `watch evaluate --all`, `watch notify`, `watch run` or the combined `run` as a background job, retry failed or ambiguous deliveries, and send a labelled channel test. Each job has a status, timestamps, exit code and meaning, the account that started it, a bounded log tail, cancellation and an audit entry.

## Operations and background jobs

Operations run as short-lived children of the same `cvebeacon` executable with the same configuration and exit codes. The dashboard request returns immediately; the job page shows `queued`, `running`, `succeeded`, `failed` or `cancelled`, together with the queue and start times, end time, exit code and its documented meaning. A running or queued job page refreshes with a meta refresh, and only a bounded tail of the log is shown.

**Single flight.** Data-changing operations take a persistent `cvebeacon-run.lock` beside each canonical storage location they write. Inventory scans lock `[state] database`; watch operations lock `[watch] database`. Combined runs take both required locks in sorted canonical path order, release any partial acquisition on failure, and take a shared-directory lock only once. Inventory-only or watch-only runs take only the applicable lock.

| Command | Storage locked |
| --- | --- |
| `scan` | Inventory state |
| `run` | Inventory state when an inventory is configured; watch storage when watch is enabled |
| `watch sync`, `watch evaluate`, `watch run` | Watch storage |
| `watch notify`, including retry variants | Watch storage |
| `watch report`, `watch unreport`, dashboard report/unreport | Watch storage |
| `watch notify test` | None; sends a labelled test without changing delivery state |

Configurations sharing either storage location therefore coordinate even when their other location differs. Channel tests are offered only when watch is enabled. On contention the CLI prints `another run is in progress` and exits `2`; the dashboard returns a conflict with holder details when available. Other lock failures are operational errors. Dashboard probes are advisory; the child takes the authoritative locks. The operating system releases locks on process exit.

**Cancel.** Cancelling a running job sends the documented interrupt: `SIGINT` to the command's process group on Linux, or `Ctrl+Break` on Windows. The CLI handles both interrupts through its cleanup path. Windows jobs require a console and a separate process group; console-less operation is refused. After three seconds without exit, the dashboard terminates the child, waits another two seconds, then kills it if necessary. Forced termination is labelled explicitly because cleanup is not confirmed. An interrupt the dashboard did not request, such as an external break or a running-job dashboard shutdown, is reported as an external interrupt rather than a cancellation and its audit entry names no cancelling account. Capture failures and orderly dashboard shutdown also stop and reap the child, including when cancellation bookkeeping fails. Queued rows whose cancellation cannot be saved remain stored for restart recovery. A queued job can be cancelled before it starts; cancellation records the requesting account separately from the starter.

**History.** The last 200 terminal jobs are kept in `dashboard-jobs.db` inside the private `dashboard-jobs/` directory beside the state database, with the job logs in the same directory. Active jobs and logs are never pruned. At most 20 jobs may be queued or running; further submissions receive a conflict response. The directory is created 0700 on POSIX or with a protected owner-only ACL on Windows, and an existing directory that is accessible to other accounts is refused. The database and log files are created owner-only, without following links. Existing linked or non-regular log files are refused. Every job start, cancellation request and outcome is appended to the chained account audit trail with its job identifier and operation. Failed outcome appends stay pending and are retried independently, and their rows and logs remain retained. Transient storage or audit failures are logged and retried with a delay capped at five seconds; later jobs can still run once storage recovers. A dashboard restart marks jobs that were still queued or running as failed, because the tracking process no longer exists.

**Full history.** When `[watch] initial = "full"` would make the next sync download the complete history, the UI requires an explicit confirmation before it passes the CLI's `--yes`. The confirmation is separate from the normal run form and is shown with the expected scale of the download. Viewing this warning uses a read-only metadata snapshot and never initializes or migrates watch storage; a database needing recovery or containing a write-ahead log requires confirmation conservatively.

## Native schedule

The **Schedule** page requires `manage_schedule`. It shows `schedule status`, and can install or remove the same native Windows task or managed Linux crontab block as `cvebeacon schedule install` and `cvebeacon schedule remove`. The form accepts an interval or fixed local times, the `scan`, `watch` or `both` command, and the Windows `--run-logged-out` option.

Schedule changes require an audited intent before installation or removal. An outcome audit failure returns an error and retains the pending audit for retry; check schedule status before repeating the action. Audit history is append-only and grows independently of job retention.

Operation storage accepts existing shared POSIX and Windows parent directories; the path itself and each ancestor must be a directory, not a link or reparse point. New directories use 0700 on POSIX and a protected owner-only ACL on Windows. The `dashboard-jobs/` directory is always private even under a shared parent: on POSIX it must be owned by the service account and have no group or other permission bits, and on Windows it must have a protected owner-only ACL. The run-lock file carries no state and may be owned by another service account, so only its regular-file shape, link count and non-truncating open are checked. A new POSIX lock file is created under the process umask instead of a forced mode, so in a cross-account setup both accounts need write access to the lock file. Job history and log files still require service-account ownership, private permissions and no links; new POSIX files use 0600. Use a single dashboard process per state directory. Every account that can write the state directory is trusted with the SQLite databases in it and their sidecar files; keep it writable only by trusted accounts.

On Windows, logged-out registration requires the service account password. The dashboard accepts it in a password field, passes it only to the existing installer in memory, and never writes, logs or displays it. The operating system's task service stores it only according to the same rules as the CLI.

If installing from the dashboard is unsafe for the current host, the page refuses the action and shows the exact equivalent command for the intended account. This happens on unsupported platforms and when the dashboard itself runs as root on POSIX, because a schedule installed there would run as root. Always use the command-line fallback when the dashboard service account is not the account that should own monitoring work.

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
- **Events:** filter by rule, kind, initial flag, date range, exact CVE, client
  and pending delivery. The client filter matches CVEs currently affecting that
  client in the latest successful inventory scan. Results are ordered newest
  first and limited to 50 per page. Client choices are capped at 1,000 with an
  explicit notice; select other clients through the paginated Clients page.
  A client filter exceeding 100,000 CVEs shows a results-incomplete notice;
  an exact CVE filter checks membership directly without that cap.
  Each row shows the published and first-seen
  dates and the current reported mark. Report and unreport notices are excluded;
  they appear in the CVE trail.
- **Clients:** every client label in the latest successful inventory scan with
  its asset count and the CVEs currently affecting it, 50 clients per page. A
  `review` badge marks findings stored as needs-review; advisory identifiers
  without a CVE are shown without a CVE link. Client names are internal and
  never sent to public sources.
- **CVE detail:** the stored view with CVSS by provider, EPSS, CISA and EU KEV
  dates and required action, SSVC exploitation, CWEs, products, references,
  publication and first-seen dates, the clients affected in the latest
  successful inventory scan, the CVE's events with per-channel delivery
  state, and the report/unreport trail with its notice states. The trail is
  paginated at 50 entries per page; each event or notice shows at most 20
  channel deliveries and says explicitly when more exist. Links open NVD,
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
without asking for the password again. The dashboard session proof itself
authorizes the write in every mode; the account, credential version and
`report` permission are rechecked inside the report write transaction, so a
disabled account, changed password or revoked permission fails closed even if
it changes after the request began. A channel with `notify_reported = true`
gets a queued notice; its delivery state is shown in the trail, and delivery
still runs through `cvebeacon watch notify` or `watch run`. The shared-password
compatibility mode can browse watch pages and generate statements, but cannot
record a client report because there is no CVEBeacon account identity.

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
| `view` | Observation pages, findings, watch pages, the current reported list, query results, exports, operations and job history |
| `report` | Mark or unmark a CVE as reported from the CLI or dashboard |
| `statement` | Generate statements from the CLI or dashboard |
| `run` | Start scan, sync, evaluation, notification and combined run jobs; submit manual queries and inventory report exports with `view` |
| `retry` | Retry failed or ambiguous deliveries as background jobs |
| `test_channel` | Send a labelled channel test message |
| `edit_rules` | Edit rules |
| `edit_channels` | Edit notification channels |
| `edit_sources` | Edit source settings |
| `edit_watch` | Edit watch settings |
| `edit_reporting` | Edit reporting settings |
| `edit_dashboard` | Edit dashboard settings |
| `edit_inventory` | Edit inventory settings |
| `edit_http` | Edit HTTP client settings |
| `edit_system` | Edit state database and report output paths |
| `manage_schedule` | View, install and remove the native schedule, including the Windows logged-out password prompt |
| `manage_secrets` | Change secret references, create new file secrets and change where a stored channel credential is sent; replacing an existing file secret's contents is also allowed with the section's edit permission |
| `manage_users` | Manage non-admin accounts and role assignments within the acting permissions; administrators can manage all accounts |
| `view_audit` | View account administration, login and logout history, with hash-chain verification status; export the full reported audit trail |

Each operation route declares its own permission: running jobs needs `run`, retry jobs need `retry`, channel tests need `test_channel`, schedule changes need `manage_schedule`, and job pages need `view`. A role without `view` cannot open the operations page even if it can call an action route directly. Opening query/report forms requires `run`; submissions require both `run` and `view` because they return findings or exports.
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

Forms use CSRF protection, output is escaped, errors omit sensitive details, and downloads cannot select filesystem paths. Credential values are not rendered. Report/query operations are synchronous; avoid submitting repeated requests while an investigation is running.

The monitoring SQLite database stores observations and dashboard scan metadata.
Accounts and roles live separately in `cvebeacon-users.db` beside the watch
database. The operations job table (`dashboard-jobs.db`) and its logs share the
private `dashboard-jobs/` directory beside the state database; the directory and
its files are owner-only. Every account that can write the state directory is
trusted with the databases and SQLite sidecar files in it; keep it writable only
by trusted accounts. Before an
upgrade, stop the scanner/dashboard and back up all three data stores. Schema
upgrades preserve existing observations and delivery records; an older
application requires its corresponding pre-upgrade backups.

## Configuration editor

After account login, open **Configuration**. Each section requires both `view`
and its edit permission for viewing, previewing and saving. Shared-password and
anonymous sessions cannot use the editor. A viewer without edit permissions
can see the section index, but cannot read configuration values.

The editor needs a configuration directory that the dashboard service can
write: atomic replacement needs directory write access, not only write access
to the file. The hardened container example keeps the configuration mount
read-only. In that mode the editor shows a read-only notice: sections can be
inspected, but saving and rollback are disabled with an explanation. To enable
editing, give only the dashboard service a writable configuration directory,
for example a writable bind mount containing the TOML file; the container root
filesystem can remain read-only. Keep the watch and report services read-only
and restart them after a configuration save. See the deployment guide for the
container layout.

| Section | Required edit permission |
| --- | --- |
| Watch settings | `edit_watch` |
| Sources | `edit_sources` |
| Rules: conditions, event triggers and channel assignments | `edit_rules` |
| Watch notification channels, with fields for the selected type | `edit_channels` |
| Legacy Teams and email notifications | `edit_channels` |
| Watch reporting identity | `edit_reporting` |
| Inventory and exact product mappings | `edit_inventory` |
| Dashboard sessions and cookies | `edit_dashboard` |
| HTTP client | `edit_http` |
| State database and report output paths | `edit_system` |

Blank fields omit a setting and use the configuration loader's default. String
fields accept plain text; arrays, column mappings and nested rule conditions
accept TOML values. For example, use `["soc-email"]` for channels and
`{ any = [{ cvss_min = 9.0 }, { epss_min = 0.5 }] }` for a condition.
The final blank row adds a rule, mapping or channel. Choose the new channel type
before making other changes; choosing it reloads the form. Removal checkboxes
remove existing rows. Every submitted document is validated by `load_config`,
including channel references and source requirements. Invalid submissions show
the loader's guidance with submitted values redacted and leave the file intact.
Unrecognized configuration fields must be reviewed outside the editor before
editing; they are never silently copied or discarded. Column mappings must use
only the known canonical or optional inventory fields, so an unknown column is
never rendered or preserved. Channel types are matched case-insensitively after surrounding whitespace,
as the loader does; the submitted spelling is preserved. Existing generic webhook
endpoint values are legacy direct values: they are hidden and retained only
when that same channel keeps the exact value. New or converted channels must
supply `url_env` or `url_file`.

**Validate and preview** builds TOML in a temporary file beside the configuration.
The diff contains only the selected section and its editable fields; nested
sections with separate permissions are excluded. Review the diff, then
**Confirm and save**. Replacement file contents are validated through the same
loader before preview and again before publication; every consumer of a shared
file is checked with the staged bytes, even when another consumer names an
environment variable that would otherwise mask the file at run time. Previews
expire after ten minutes and belong to the current session and section. A
successful save consumes the preview; a failed confirmation leaves it usable
until it expires. Each session has a bounded number of pending previews, so one
editor cannot fill the shared preview space; one account may hold several
sessions. If the original file changed since the form loaded or preview was
created, the save is refused with a reload message. The editor serializes its
writers using the account database transaction and checks the file again
immediately before replacement. External editors do not participate in that
lock: avoid simultaneous filesystem edits. A configuration-file writer lock
covers target capture, live secret writes, transaction exit and compensation;
release and descriptor-close failures are sanitized maintenance so a completed
save is not reported as failed. Requests are bounded by the dashboard's
8192-byte form limit, and a section form accepts at most 100 rows per save;
split larger edits into smaller saves where possible. Pending previews hold
full documents, so a session's pending count is also a memory bound.

Saving removes hand-written **comments and formatting**. Before replacement,
the original bytes are kept in an owner-only sibling directory named
`.CONFIG_FILENAME.backups`. The last ten timestamped backups are retained.
The new configuration is written atomically with `os.replace`, preserving the
original owner and mode. Configuration files must be regular files with no
extra hard links, owned by the service account and not group or other writable
on POSIX. Parent directories must pass the account store's ownership checks.
New backup and secret directories are owner-only. On Windows, apply the same
service-account-only ACL protections described in the account guide; POSIX
mode bits do not establish Windows ACL isolation.

The account audit records the actor, time, section, changed-line count and the
number of secret files written, never configuration values.
Permission and credential revocation are rechecked in the write transaction.
The complete replacement application is prepared from the validated final
contents before the live file changes. Validation, replacement preparation and
handled write or audit failures leave the existing application and configuration
in place, including restoring any secret contents already replaced. Post-commit
temporary cleanup is best-effort maintenance and cannot turn a completed save
into a failure. Successful saves reload the dashboard and end **all dashboard
sessions**; log in again. Already-running non-configuration requests finish with
their original configuration; a configuration request that reaches the old
application during the swap is refused and can be retried after reloading. Other
running commands retain their configuration until restarted. A reload reuses the
process's single dashboard job manager: queued and running jobs keep their
worker and store, future jobs use the reloaded settings, and `serve` shuts the
same manager down when the process exits. Moving the state database, and with it
the private job storage directory, is refused while a job is queued or running.
Run the disposable loopback acceptance check with
`python tools/dashboard_config_smoke.py`; it creates no schedules and sends no
notifications.

Access and session comparisons use the running configuration and the current
file where it is valid, at preview and again in the write transaction. A stale
in-process configuration therefore cannot skip a lockout confirmation or an
account-store administrator check. Operational watch, state and output paths
must not alias the configuration file or its writer lock, the account, watch or
state databases, any of their `-wal`, `-shm`, `-journal` or `.lock` sidecars,
the private `dashboard-jobs` directory with its database and logs, both operation
run-lock files, the backup or secret directories, every referenced `*_file`
secret, or the inventory input. Equality, same-file identity and any path beneath a protected
file as an ancestor are rejected, as are watch, state and output paths that
alias each other. Resolved paths, symbolic links and existing hard links are
checked. A path collision is rejected with guidance.

All dashboard setting changes require an additional access confirmation.
Changing the effective account database path (the sibling of the watch
database, including changes induced by the state database default) also requires
an administrator and an existing destination store with an enabled administrator.
The editor cannot turn off account authentication. It does not move databases.
Host and port remain `serve --host` and `--port` options; they are not TOML
settings. Moving stores requires making the protected destination available
before choosing it. Keep a working administrator login for that destination.

Secrets remain `*_env` or `*_file` references. Environment variables can be named
but cannot be set. Names accepted by the editor begin with a letter or underscore
and contain only letters, digits and underscores, up to 128 characters; the core
loader accepts a wider historical range, so repair such a name outside the editor.
Existing secret contents are never returned, including in
validation errors, diffs, audit entries or logs. Slack, Teams, Discord and
generic webhook URLs are credentials: the first three use `webhook_url_env` or
`webhook_url_file`, and a generic webhook uses `url_env` or `url_file`. URL
values are hidden in forms, diffs and audit records. Existing generic webhook
`url` values remain supported for existing configurations, are hidden and
retained only when unchanged, and are not used for new channels. An existing
direct value can be converted to `url_env` or `url_file` with
`manage_secrets`; the conversion removes the direct value from the next saved
file. The resolved URL is revalidated with the channel's HTTPS or explicit
`allow_insecure` setting immediately before every delivery or test send.

A channel that carries any secret reference has credential-destination fields
that decide where, or how securely, the credential is sent. Changing SMTP
`host`, `port`, `security` or `allow_insecure`; Matrix `homeserver` or
`allow_insecure`; ntfy or Gotify `server` or `allow_insecure`; or a generic
webhook `url` or `allow_insecure` while it has a header credential requires
`manage_secrets`. These controls are read-only without that permission, and
the server compares the current and submitted documents at preview and again in
the write transaction. A channel without a secret keeps those fields editable
with its section permission. A new channel that reuses an existing credential
also needs `manage_secrets` unless it is a pure rename.

Existing references cannot be added, changed or repointed without
`manage_secrets`: they render read-only and the server rechecks the rule before
validating or reading a new reference target and again inside the write
transaction. An editor without that permission may still replace the **contents**
of an existing `*_file` reference. The submitted value is staged, validated by
the shared loader, then written to the same owner-only file atomically; the
reference itself does not change. Conflicting new contents for one physical
file are rejected; identical writes are coalesced. Renaming or deleting a
channel is not itself a reference change, because references are compared by
value and field rather than by the channel key. Renaming a channel and rotating
its secret file must still be saved separately: a rename with new file
contents is refused with guidance. Writable secret files must
resolve inside the current protected data directory and must not be symbolic
links or extra hard links. They use the same protected set as operational-path
checks: the configuration file and writer lock, every current, running and
candidate account, watch and state database with its `-wal`, `-shm`, `-journal`
and `.lock` sidecars, the private `dashboard-jobs` directory with its database
and logs, both operation run-lock files, backups, secret directories, every
referenced `*_file`, and the inventory input. Files inside the protected `dashboard-secrets`
directory remain writable when they are the referenced secret, including when a
report output directory contains that secret directory. Readable external
references remain usable by the loader but are never written through this
interface. Creating a new file reference or changing an environment or file
reference requires `manage_secrets`, which administrators always have. A
supplied destination path is never overwritten: a new file secret is created
with a random name in `dashboard-secrets` beside the account database, inside
the protected data directory. No secret value is placed in TOML or a
confirmation form.

A new file value is rejected when its paired `*_env` reference is also set,
because the environment value would take precedence at run time. This includes
the NVD default `NVD_API_KEY` when that variable has a value, even if the form
field is blank. An explicit paired environment reference is rejected for file
rotation until it is cleared. Staged files expire with their preview after ten
minutes. Cleanup runs on editor requests and for old unreferenced files after a
restart. Previews that reference another preview's generated file adopt it and
renew its deletion lease, including across separate application instances. A
staged file is removed only when no current configuration, retained backup or
live preview references it; if reference discovery cannot complete, cleanup
retains generated files rather than risk deleting a live secret. Invalid
submissions remove their staged files. Reserved `.dashboard-secret-` and `.dashboard-staged-` names left
in the protected data directory by a crash are removed after their lease
expires; no other data-directory files are touched. Generated names use
`.dashboard-secret-` and `.dashboard-staged-`; configuration backups use
`.CONFIG_FILENAME.backups`, validation temporaries use `.config-`, and the
configuration writer lock uses `.config-CONFIG_FILENAME.lock`. These paths are
ignored by the repository's `.gitignore`; keep runtime data directories outside
the worktree where possible.

**Backups and rollback** requires `view` and every configuration edit permission,
because a backup can change every section. Changing a secret reference through
rollback also requires `manage_secrets`. Choose a backup, validate it, review
the diff and confirm. Rollback uses the same validation, concurrency checks,
access confirmation, audit, atomic replacement, backup and reload path as saving.
The backups list and rollback remain available when the live file fails the
loader: the page reads the raw bytes and version signature, and validates only
the chosen backup. Rollback in that state requires the access confirmation, and
an unparseable current file also requires `manage_secrets`; sections cannot be
edited from an invalid live file, so restore a backup first. Rollback does not
restore secret-file contents; it preserves files referenced by retained backups.
Configuration permissions allow changing operational paths and notification
destinations; grant them only to accounts trusted to control those settings.

## Package identities and advisory views

The manual query page has Product, Package (ecosystem/name/version), and Explicit PURL modes. Each uses the CLI assessment engine and preserves monitoring/event/delivery state. Findings can be filtered by category, system, ecosystem, PURL, advisory ID and CVE alias. Asset and evidence details show supplied identities, aliases and fixed boundaries. Fixed boundaries require review of the branch and source range before choosing an upgrade. Reports include separate Identities and Advisory Details sheets to keep Findings compact. Authentication and CSRF protection apply equally to all query modes.
