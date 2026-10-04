# Optional Automation and Integrations

Automation is a third, separately installed distribution. Dependency direction
is Core ← Extensions ← Automation. Core and Extensions production code,
metadata and v1 deployment files remain unchanged. Core users need neither
Automation nor integration credentials.

```console
python -m pip install . ./extensions ./automation
cvebeacon-auto --config /etc/cvebeacon/cvebeacon-automation.toml run
cvebeacon-auto --config /etc/cvebeacon/cvebeacon-automation.toml status --json
```

Start from [the example](../automation/examples/cvebeacon-automation.example.toml).
Configuration version is 1. Unknown settings, invalid bounds, duplicate source
identifiers and colliding paths fail. Paths are relative to the configuration
file. Staging and state parents must be administrator controlled local storage.
Do not share writable directories with untrusted processes. Source IDs use
ASCII letters, numbers, dots, dashes and underscores, with a maximum of 96
characters and no Windows reserved filename stems.

`run` terminates after collection, source validation, deterministic Extensions
merge, Core inventory validation, Core CLI scan, optional notification dispatch
and health recording. An OS lock covers the whole operation and releases after
process death. External systemd timers, cron, Windows Task Scheduler and
Kubernetes CronJobs provide scheduling. No embedded scheduling daemon is used.

Every source has explicit `required`, `max_age_seconds` and `allow_partial`
policy. Required failures stop before scan and preserve the previous good
inventory. Optional failures are recorded as degradation; surviving inputs
produce an explicitly partial merged manifest. A prior remote source may be
used only while its original observations remain fresh; recollection failure
is still reported. Snapshot dates and identity semantics come from Extensions.

Exit 0 means the configured pipeline completed. Core exits 2/3/4 are preserved;
4 means incomplete coverage. Automation failure returns 2, and a completed
scan with degraded optional operations returns 5. Operational health does not
assert vulnerability absence. `health.json` and the independent integration
ledgers reside under `state_dir`; Automation never stores operational state in
Core SQLite.

Integration credentials use `{env = "VARIABLE_NAME"}` or
`{file = "/run/secrets/integration-token"}` references. POSIX secret files must
have no group/other permissions; Windows requires administrator-controlled
ACLs. No raw secret belongs in TOML. Core is invoked with a minimal environment;
its separately configured `core_env` allowlist is empty by default.

Uploaded and collected sources use immutable exact-byte generations, selected
by an atomic pointer. Keep staging, state, Core database and reports in your
backup plan. Do not edit generation files or reset pointers to bypass replay
protection. Retention requires an explicit administrator policy; the service
does not automatically delete historical evidence.
