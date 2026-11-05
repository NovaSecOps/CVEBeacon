# Development

CVEBeacon is a conservative vulnerability inventory monitor. This guide covers
repository layout, behavior that changes must preserve, and the checks to run
locally. User-facing behavior is documented in the [user guide](USER_GUIDE.md).

## Repository layout

Three distributions are installed separately:

```text
Core          src/cvebeacon/          cvebeacon
Extensions    extensions/src/         cvebeacon-ext
Automation    automation/src/         cvebeacon-auto
```

Dependency direction is Core <- Extensions <- Automation. Extensions depends on
the core public inventory validator, and Automation depends on both packages.
Core declares no dependency on the other two and never imports them;
`tests/test_extension_boundary.py` enforces that boundary.

Extensions produce inventory snapshots. They never write monitoring SQLite
state, deliver notifications, or decide applicability;
`extensions/tests/test_audit_regressions.py` enforces that authority split.
Automation reads Core state read-only and runs Core as a child process. It keeps
its own health and integration ledgers. See [architecture](ARCHITECTURE.md),
[optional extensions](EXTENSIONS.md), and [automation](AUTOMATION.md).

## Non-negotiable behavior

- Missing, failed, disabled, ambiguous, or contradictory evidence never becomes
  `not_affected` and never produces a clean exit. It stays `needs_review` or
  `coverage_unknown`, with the limitation visible in reports and source status.
- Internal asset IDs, client labels, categories, system IDs, hostnames, and local paths never
  enter public source queries. Only public component identity terms are sent.
- Inputs are bounded and failures are closed. Errors must not echo secrets,
  tokens, credentials, full webhook URLs, or upstream response text.
- Keep layer authority. Do not add collector, SBOM, Kubernetes, or container
  dependencies to Core.

## Change rules

- Fix the reported problem narrowly. Avoid speculative refactors and mass
  dependency upgrades.
- Add a regression test for every bug fix. Confirm that it fails for the
  original behavior before applying the fix.
- Never weaken or delete an existing test to make a change pass. If a test is
  wrong, correct it explicitly and explain why in the commit message.
- Follow the style of the module you are changing: naming, error handling,
  typing, and test structure.
- Prefer the simplest robust solution. Avoid new dependencies and new
  configuration when existing behavior is sufficient.

## Setup

Install all three packages into a virtual environment. Installation needs
network access; the offline test suite does not.

```console
python -m venv .venv
.venv/bin/python -m pip install --upgrade 'pip>=26.2'
.venv/bin/python -m pip install '.[dev]' ./extensions ./automation
```

On Windows, use `.venv\Scripts\python.exe` in place of `.venv/bin/python`.

## Tests

Run the full offline suite from the repository root:

```console
python tools/test_offline.py -q tests extensions/tests automation/tests
```

`tools/test_offline.py` blocks socket connections and DNS before test collection.
Plain `pytest` uses `testpaths = ["tests"]` from `pyproject.toml`, so it collects
only `tests/` and does not install that network block before collection. Pass all
three directories explicitly when validating a change.

For a quick end-to-end check:

```console
python tools/smoke.py
```

The smoke script works in a temporary directory with external sources disabled.
An offline scan must report incomplete coverage, not a clean result.

Acceptance tools include `tools/scheduler_smoke.py`,
`tools/host_collector_smoke.py`, `tools/container_smoke.py`,
`tools/kubernetes_smoke.py`, `automation/tools/container_acceptance.py`, and
`automation/tools/kubernetes_acceptance.py`. CI runs them in these workflows:

- `.github/workflows/validation.yml`
- `.github/workflows/extensions.yml`
- `.github/workflows/automation.yml`
- `.github/workflows/containers.yml`
- `.github/workflows/kubernetes.yml`
- `.github/workflows/automation-kubernetes.yml`

See [validation](VALIDATION.md) for what each job proves and which platform
combinations have passed.

## Exit codes

Core reports `0`, `1`, `2`, `3`, and `4`. Automation preserves those codes and adds
`5` for degraded optional operations and `75` for a nonblocking resource-lock
conflict. Container entrypoints translate SIGTERM into bounded cleanup and exit
`143`.

| Code | Scope | Meaning |
| --- | --- | --- |
| 0 | Core, Automation | Operation or configured pipeline completed |
| 1 | Core | Operation cancelled by the user or a required confirmation was refused |
| 2 | Core, Automation | Validation or operational failure |
| 3 | Core | Notification delivery failure (takes precedence over 4) |
| 4 | Core, Automation | Uncertain coverage or degraded sources |
| 5 | Automation | Completed with degraded optional operations |
| 75 | Automation | Nonblocking resource-lock conflict |
| 143 | Container entrypoint | SIGTERM handled and cleanup completed |

Core codes are described in the [user guide](USER_GUIDE.md), pipeline behavior in
[automation](AUTOMATION.md), `75` in the [Kubernetes guide](AUTOMATION_KUBERNETES.md),
and `143` in the [container guide](AUTOMATION_CONTAINER.md).

## Commits and branches

Use the existing `feature/`, `audit/`, and `release/` branch prefixes. Keep one
logical change per commit and write an imperative subject that describes the
behavior change, for example `Reject stale snapshots before merge`. Keep private
notes, local absolute paths, generated state, and credentials out of tracked
files. Follow the [release checklist](RELEASE_CHECKLIST.md) before publishing.
