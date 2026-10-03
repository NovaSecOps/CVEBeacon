# Container deployment

The core image runs the same CLI as a source installation. It contains no
optional companion, host collectors, Kubernetes clients, cron or supervisor.
No image publication is part of the reference build.

```console
docker build --target core --tag cvebeacon:local .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true cvebeacon:local --help
```

The multistage build uses official Python 3.13 slim Debian Trixie pinned by
manifest digest. Runtime receives installed core dependencies, a signal adapter,
LICENSE and NOTICE. The build context excludes private files, Git, operational
configuration/state, tests and local environments. Base pinning does not freeze
Python dependency resolution: compatible ranges remain in effect. CI records
resolved versions; review dependencies and the base digest regularly. Source and
native executable installations remain independent of Docker.

## Runtime and mounts

The default user/group is **65532:65532**, with no login shell or home. Use
read-only root, drop all capabilities and enable no-new-privileges. No Docker
socket, host PID namespace, device access or privileged mode is needed. The
image does not create anonymous writable volumes.

| Path | Access | Purpose |
| --- | --- | --- |
| `/config/cvebeacon.toml` | read-only | Administrator-owned configuration |
| `/inventory` | read-only | Inventory; validate extension sidecars before scanning |
| `/state` | writable | SQLite database and WAL/SHM files |
| `/reports` | writable | Reports |
| `/tmp` | bounded tmpfs | Temporary XLSX/dashboard report files |

Prepare dedicated host state/report directories owned by the runtime UID/GID,
or deliberately select another non-root UID with appropriate ownership. Keep
production permissions private; do not make state world-writable. Example:

```sh
sudo install -d -m 0700 -o 65532 -g 65532 /srv/cvebeacon/state /srv/cvebeacon/reports
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  --mount type=bind,src=/srv/cvebeacon/cvebeacon.toml,dst=/config/cvebeacon.toml,readonly \
  --mount type=bind,src=/srv/cvebeacon/inventory,dst=/inventory,readonly \
  --mount type=bind,src=/srv/cvebeacon/state,dst=/state \
  --mount type=bind,src=/srv/cvebeacon/reports,dst=/reports \
  cvebeacon:local --config /config/cvebeacon.toml scan --report json
```

Adapt [the sample configuration](../deploy/container/cvebeacon.example.toml). Normal scans
need outbound public-source HTTPS ([network requirements](NETWORK_REQUIREMENTS.md)).
`--network none` is for help/validation or deliberately offline tests with all
sources disabled. Scan exit code 4 means incomplete/review/unknown coverage.

SQLite needs local storage with correct locking. Use one scheduled scanner per
state directory and prevent overlapping manual/scheduled writers. A local
dashboard may share state under normal core transactions; do not scale replicas
across hosts or put WAL state on an arbitrary network share. Stop processes and
back up state before upgrades. Roll back with the matching image and database
backup, not an in-place database downgrade.

## External scheduling

The host/orchestrator schedules one-shot containers. Put the validated command
above in an administrator-owned `/srv/cvebeacon/scan.sh`, then use host cron or a
systemd timer. Example cron entry:

```cron
0 */4 * * * /usr/bin/flock -n /srv/cvebeacon/scan.lock /bin/sh /srv/cvebeacon/scan.sh
```

Use the same lock for manual scans and secure Docker access as privileged host
administration. Monitor exit status and freshness. The image runs no scheduler.
Its PID-1 adapter converts SIGTERM into the core cancellation path, runs resource
cleanup and exits 143. Interrupted scans remain distinct from successful scans.
Allow a shutdown grace period before forced kill.

## Compose and dashboard

[The Compose reference](../deploy/container/compose.yml) has explicit `scan` and
`dashboard` profiles. Prepare private `state`, `reports`, `inventory` directories
beside it with the ownership above and the sample configuration. Build once and
invoke scans from your scheduler:

```console
cp deploy/container/cvebeacon.example.toml deploy/container/cvebeacon.toml
docker compose -f deploy/container/compose.yml --profile scan build
docker compose -f deploy/container/compose.yml --profile scan run --rm scan
```

Generate a hash interactively with `cvebeacon dashboard hash-password`, then
inject `CVEBEACON_DASHBOARD_PASSWORD_HASH` through a trusted runtime environment
or secret manager. The sample forwards it by name, keeping its value out of YAML
and command arguments. Core does not implement a `_FILE` convention: mounting a
secret file alone does not enable authentication. Never bake hashes into images
or commit local environment files. Avoid printing expanded Compose configuration
or runtime environments.

```console
docker compose -f deploy/container/compose.yml --profile dashboard up -d dashboard
```

The application binds `0.0.0.0` inside its network namespace for bridge forwarding;
the host publishes only `127.0.0.1:8787`. Core requires authentication for that
internal wildcard bind; absent/invalid hashes fail startup. The sample never
enables the unauthenticated-remote override.

Remote password sessions require browser-facing HTTPS through a trusted reverse
proxy or equivalent encrypted transport, `secure_cookie=true` and restricted
backend access. The app does not terminate TLS. Follow the
[dashboard guide](DASHBOARD.md) for Host headers and shared-origin throttling.

## Validation

Native Linux CI builds without publishing and exercises help, validation, two
offline scan containers sharing state, reports, SQLite integrity, zero
notifications, non-root identity and read-only root. Auth/no-auth dashboard tests
run on container loopback with external networking disabled; the no-auth test is
not a published-port example. Tests verify login, protected routes, unchanged
monitoring state and graceful stop without SIGKILL. Filesystem and saved-layer inspection
rejects private/Git/operational files and extension packages. Core Windows/Linux
source and native-package jobs continue independently.
