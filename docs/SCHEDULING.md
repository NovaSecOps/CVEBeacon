# Native scheduling

CVEBeacon supports a single narrowly owned native schedule: the exact Windows task name `CVEBeacon Monitor`, or one marked block in the current Linux user’s crontab.

Install the default four-hour schedule:

```console
cvebeacon --config /absolute/path/cvebeacon.toml schedule install
```

Preview without modifying the host:

```console
cvebeacon --config /absolute/path/cvebeacon.toml schedule install --every 4 --dry-run
```

With no `--every` or `--times` value, setup asks for an interval and defaults to four hours. `--hours` is accepted as an alias for `--every`. For unattended installation, use a value such as `--every 4h --yes`. Windows accepts whole hours from 2 through 24. Linux cron accepts only divisors of 24 (2, 3, 4, 6, 8, 12, 24), preventing a shorter interval when the hour field wraps at midnight. NVD asks automated clients not to request modified data more often than every two hours.

## Fixed times

Use `--times` with one to twelve distinct local times in `HH:MM` form:

```console
cvebeacon --config /absolute/path/cvebeacon.toml schedule install --times 07:00,19:00
```

`--times` and `--every` are mutually exclusive. Duplicate times, `24:00`, a
single-digit hour such as `7:5`, and more than twelve times are rejected.

On Linux, times that share a minute become one cron line, for example
`0 7,19 * * *`, while different minutes produce separate lines. Every line is
kept inside the single managed block. Removing or replacing it still preserves
unrelated crontab entries.

On Windows, fixed times create one task, `CVEBeacon Monitor`, through
`schtasks /Create /XML <file> /TN "CVEBeacon Monitor" /F`. The generated XML has
one daily `CalendarTrigger` per time, runs at the least-privilege level, and
starts only when the user is logged on. It is written as UTF-16 to a temporary
file that is deleted after `schtasks` returns. Interval mode uses the plain
`schtasks /SC` form and needs no XML: `/SC HOURLY /MO N` for intervals below 24
hours, or `/SC DAILY` for 24 hours.

Add `--run-logged-out` to run the task whether the account is signed in or not.
It is Windows-only, and Linux rejects it. The task principal uses `LogonType
Password` with an explicit `UserId` and `RunLevel` least privilege. The account
defaults to the current OS account; use `--account DOMAIN\user` to run the task
as another account from an elevated administrator shell. The password comes from
a hidden prompt (entered twice for confirmation), or from `--password-stdin`,
which requires `--yes` and an explicit `--times` or `--every` and reads one
UTF-8 line from stdin for automation. CVEBeacon passes it to PowerShell only on stdin and never stores it;
Windows stores it in its own credential store. Changing the account password
requires re-running `schedule install --run-logged-out`.

The task is registered through the Task Scheduler COM API with
`RegisterTask` and `TASK_LOGON_PASSWORD`. The plan prints `Runs as: <account>
(stored password, while logged off)`; check that line before `--yes`. The account
must already exist and, unless policy grants it, needs the "Log on as a batch
job" right (`secpol.msc`, Local Policies, User Rights Assignment; a domain GPO
can override it). An identifiable access-denied, bad-password or missing-right
failure prints a one-line hint. With this flag, interval mode also uses the XML
form. Without it the default stays `InteractiveToken` for desktops. `schedule
status` shows the account when the task XML has a `UserId`, and whether the task
runs while logged off. S4U is not used: Windows refuses passwordless S4U for
this setup, and a password-logon task is the documented alternative.

## What runs

`--command scan|watch|both` chooses the scheduled action. With no value, it
follows the configuration:

- `watch` when watch mode is enabled and there is no inventory;
- `scan` when only an inventory is configured;
- `both` when both are configured.

`watch` runs `<executable> --config <path> watch run`. `scan` runs
`<executable> --config <path> scan`. `both` runs the single command
`<executable> --config <path> run`: `scan` when `[inventory]` is configured,
then `watch run` when `[watch].enabled` is true, in that order in one process.
It is one cron line or one Windows task action, never shell chaining.

`run` reports the most severe result of its parts:

- `2` when either part failed;
- otherwise `3` when any notification or delivery failed;
- otherwise `4` for coverage warnings or degraded sources;
- otherwise `1` when either part was cancelled;
- otherwise `0`.

Any other unexpected part code is also reported as `2` when no `2`, `3`, `4` or
`1` result takes precedence. A cancelled part is reported as `1` only when no
part failed or warned. In particular, a scheduled `run` exits `1` when the
first `full` history sync needs an interactive confirmation and stdin is not a
terminal. Configure `baseline` or `backfill` for unattended first runs, or run
`watch sync --yes` once before the first scheduled run.

## Single-flight lock

`scan` locks the inventory state storage beside `[state] database`. `run` locks
that storage when an inventory is configured and the watch storage when watch
is enabled. `watch sync`, `watch evaluate`, `watch run`, `watch report`,
`watch unreport` and delivery runs (`watch notify`, including the retry
variants) lock the watch storage beside `[watch] database`. Channel tests do
not take the lock because they do not change delivery state.

Each locked storage location uses a persistent `cvebeacon-run.lock` file in its
directory. The lock file carries no state, so a shared storage directory and a
lock file created by another service account remain usable. A new POSIX lock
file is created under the process umask rather than a forced mode, so in a
cross-account setup both accounts need write access to the lock file. `run`
takes both required locks in sorted canonical path order, takes a
shared-directory lock only once, and releases any partial acquisition if a
later lock is busy. Inventory-only or watch-only runs take only the applicable
lock. Configurations sharing either storage location therefore coordinate even
when their other location differs. The dashboard's background jobs take the
same locks. A second run fails immediately with `another run is in progress`
and exit code `2`; it does not wait and never changes state concurrently. The
operating system releases the lock when a process exits, including after a
crash.

Inspect or remove the owned schedule:

```console
cvebeacon schedule status
cvebeacon schedule remove
```

`schedule status` shows the installed times or interval and the commands, each
listed once. Removal requires confirmation unless `--yes` is used. It never
performs wildcard deletion. On Linux, only text between
`# BEGIN CVEBEACON MANAGED` and `# END CVEBEACON MANAGED` is replaced or
removed; unrelated crontab entries are preserved byte for byte, including
trailing whitespace, carriage returns and non-UTF-8 bytes. A separating newline
is added when the entry before the managed block has none, and removal restores
the original final newline state.

`--platform auto` is the default. An explicit `windows` or `linux` override is rejected for live changes on an incompatible host, but can be used with `--dry-run` to inspect the generated proposal.

The generated command uses absolute executable and configuration paths. A packaged executable schedules itself. A source invocation uses the installed console launcher when available, or the active Python interpreter with `-m cvebeacon`.

For manual administration, create an equivalent task or cron entry that runs
`cvebeacon --config <absolute-path> scan`, `... watch run`, or both. Run it under
an account with read access to the inventory and configuration, write access to
the state/output directories, and access to required environment variables.

Linux user cron requires an installed, running cron service. It uses the host's local clock and does not recover runs missed while the host is off; daylight-saving transitions can skip or repeat executions. Its environment is usually smaller than an interactive shell, so provision notification credentials for the scheduled account. Percent characters and line breaks in schedule paths are rejected. Do not create a second scheduler that bypasses the shared single-flight lock. Windows task credentials and execution while logged out must be verified for the intended account through Task Scheduler; CVEBeacon passes the password to Task Scheduler and does not retain it.
