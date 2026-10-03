# Local host collectors

Collectors run once on their own host, emit local inventory/review files and
exit. They do not listen, upload, probe remote machines, collect secrets or
require administrator/root privileges. Use an administrator-chosen source alias
unique across hosts and keep it stable.

```console
cvebeacon-ext collect linux --source-id linux-a --output linux-a.json
cvebeacon-ext collect windows --source-id windows-a --output windows-a.json
```

Both emit the [snapshot contract](EXTENSIONS.md) and a `.review.json` file.
Incomplete observations are explicit review entries and mark the snapshot
partial. Downstream use requires `--allow-partial`; it must be a deliberate
coverage decision. Permission, parsing and command failures return nonzero and
leave the previous inventory/manifest aging. Monitor command exit codes.

## Linux

The collector reads the fixed `/etc/os-release` path (falling back to
`/usr/lib/os-release`) and either `/usr/bin/dpkg-query` or `/usr/bin/rpm`.
`--backend dpkg` or `--backend rpm` selects explicitly. Automatic selection uses
OS family only to choose the command, never to rewrite the observed release.
There is no root filesystem crawl or process-name scraping. Alpine/apk and other
package managers are outside this version.

Fixed subprocess arguments query installed names, full versions and architecture;
RPM also provides release and epoch. No package text becomes a command argument
or shell program. The command receives a minimal environment and empty temporary
home/config directory to avoid user RPM macros and package-manager environment
overrides. Output is capped at 32 MiB and 100000 rows, with a 30-second query
deadline and bounded process-group cleanup. The host's system package-manager
configuration and binaries remain trusted inputs.

The OS row uses its actual ID/name/version. Missing rolling-release versions
produce review. Installed DEB/RPM identity includes architecture; Debian epochs
remain in the version, while RPM epoch is a PURL qualifier and RPM version is
VERSION-RELEASE. Removed dpkg configuration records are not installed packages.
Half-installed or malformed database output fails collection.

**A package database does not prove every package came from the host's vendor.**
Default package observations therefore retain name/version/architecture/epoch in
review output. If the deployment can establish a consistent vendor namespace for
the queried package set, supply an explicit policy:

```console
cvebeacon-ext collect linux --source-id linux-a --backend dpkg --package-namespace debian --output linux-a.json
```

This is a deployer assertion, not signature/origin verification. Do not use it
to mislabel third-party or locally built packages. Mixed-origin hosts should
retain reviews or supply a curated SBOM/inventory with correct individual
identities. Namespace strings must be lowercase vendor identifiers. The
distribution qualifier retains the actual host ID and version; derivative
versions are never interpreted as their parent distribution's release.

Qualified `deb`/`rpm` PURLs preserve useful package identity, but the current core
does not support their exact public vulnerability lookup. They remain
`coverage_unknown`; neither collection nor the namespace policy expands coverage.
See the [core identity rules](IDENTITY.md). Coinstalled versions of one
name/architecture (commonly RPM kernels) all remain in review until explicit
instance grouping is supplied. Other packages and the OS can still be collected;
no coinstalled version silently replaces another.

## Windows

The collector reads standard Uninstall registry locations under HKLM and the
executing user's HKCU using KEY_READ and separate 64/32-bit views. Only
DisplayName, DisplayVersion and Publisher are queried. It never reads uninstall
commands, license/product keys, owner fields, arbitrary registry values or other
users' profiles. It never invokes Win32_Product, WMI, remote queries or a package
manager. REG_EXPAND_SZ values remain literal; environment variables are not
expanded or copied.

Complete publisher/name/version triples use the existing generic product path,
with its conservative discovery and uncertainty. Display names do not become
NuGet/winget identities or exact CPEs. Missing fields produce review. Both logical
registry views are retained: identical strings do not prove two registrations
are physically shared. This can show duplicates on Windows versions that share
a view; preserving observations avoids discarding distinct installations.
Ambiguous duplicate slots within one view fail instead of overwriting.

OS observation reads ProductName, CurrentBuildNumber and UBR from the fixed
Windows CurrentVersion key. A build is required; UBR alone never becomes a
version. Registry product labels may retain older Windows branding, and build
numbers are not silently converted to marketing releases or CPE versions.
Portable applications, other users' installs, Store applications without these
registry entries, and ARM-specific registry views are not universally covered.

## Stable IDs and privacy

Linux IDs hash source alias plus package-manager/name/architecture slot. Windows
IDs hash source alias plus scope/view/normalized publisher/display-name slot.
Versions are excluded, so ordinary upgrades keep IDs; removals disappear from
the next snapshot and remain historical in core monitoring. Renames, changed
publishers, architecture/view changes, or source-alias changes can change IDs.
OS IDs use one stable source-scoped slot. No machine ID, serial number or actual
hostname is needed.

Keep review files and snapshots private: installed software and source labels
are operational data. Only inventory identity fields participate in public
vulnerability lookups; source/system IDs stay local to those queries. Optional
notifications intentionally include configured labels. No transfer mechanism or
remote credentials are built into these collectors.

Observation semantics follow the [dpkg query manual](https://manpages.debian.org/trixie/dpkg/dpkg-query.1.en.html),
[RPM query formats](https://rpm.org/docs/4.20.x/manual/queryformat.html),
[official PURL types](https://github.com/package-url/purl-spec/tree/main/types),
[Windows uninstall metadata](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key),
and [Windows registry views](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view).
