<!--
Release notes template. The release workflow fills in the version, date and
container image digest, then creates a draft release. Review the draft, the
asset list and the checksums before publishing it.
-->

# CVEBeacon {{VERSION}}

Released {{DATE}}.

## Artifacts

| File | Contents |
| --- | --- |
| `cvebeacon-{{VERSION}}-py3-none-any.whl` | Core Python wheel |
| `cvebeacon_extensions-{{VERSION}}-py3-none-any.whl` | Optional extensions wheel |
| `cvebeacon_automation-{{VERSION}}-py3-none-any.whl` | Optional automation wheel |
| `cvebeacon-{{VERSION}}.tar.gz` | Core source distribution |
| `cvebeacon-windows-x64.zip` | Windows x86-64 one-folder bundle, one-file executable, `LICENSE` and `NOTICE` |
| Runtime wheelhouse (`*.whl`) | Additional binary dependency wheels for CPython 3.11–3.14 on Linux x86-64 and aarch64 |
| `SHA256SUMS` | SHA-256 checksums for every other artifact |
| `SHA256SUMS.sig` | SSH signature over `SHA256SUMS` |

The core, extensions and automation wheels and the source distribution require
Python 3.11 or newer. The runtime wheelhouse covers CPython 3.11–3.14 on Linux
x86-64 and aarch64. Install the extensions and automation wheels only if you use
those features (or already have them installed). The Windows archive is built on
Windows Server 2025 for x86-64; extract it and run `cvebeacon.exe --help` before
replacing an existing installation.
GitHub also attaches the source archives for the tag.

Verify the signature and checksums from the directory that contains the
downloaded files. Obtain the signer pin through an authenticated channel and
compare its key fingerprint independently; a checksum file without its SSH
signature is insufficient.

```console
ssh-keygen -Y verify -f /etc/cvebeacon/release-allowed-signers \
  -I cvebeacon-release -n cvebeacon-release \
  -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check SHA256SUMS
```

Use the path to your independently obtained copy of the pinned signers file in
place of `/etc/cvebeacon/release-allowed-signers`.

## Container image

When published, the core image is available from GHCR:

```console
docker pull ghcr.io/novasecops/cvebeacon:{{VERSION}}
```

Platforms are `linux/amd64` and `linux/arm64` (Raspberry Pi class boards). The
image runs as UID/GID 65532 with no shell and no scheduler. Manifest digest:
`{{IMAGE_DIGEST}}`.

The `latest` tag follows the highest stable version tag present in the
registry. Publishing runs are serialized across release tags, so an older or
repeated release does not move it backward. Pre-releases publish only their
version tag. The version tag above is immutable; publish a new patch version
instead of replacing it.

## Upgrade notes

- **Installs made from source before `0.1.0`.** Installs made before the first
  published release (`0.1.0`) carry only the fail-closed placeholder signing pin, so
  the updater cannot authenticate an update. Upgrade each such installation
  manually once as described in
  [upgrading](https://github.com/novasecops/cvebeacon/blob/main/docs/UPGRADING.md);
  after that, the updater verifies and installs later releases normally.
- Stop running scans and back up the SQLite state before upgrading.
- Roll back with the matching release and database backup, not an in-place
  database downgrade.
- Read the [container guide](https://github.com/novasecops/cvebeacon/blob/main/docs/CONTAINERS.md)
  and [user guide](https://github.com/novasecops/cvebeacon/blob/main/docs/USER_GUIDE.md)
  for configuration changes.

## Publishing checklist

- [ ] Confirm the version and notes in this draft.
- [ ] Confirm `SHA256SUMS` covers every uploaded artifact except itself and
      `SHA256SUMS.sig`.
- [ ] Confirm the GHCR manifest digest matches `{{IMAGE_DIGEST}}`.
- [ ] Publish only after `docs/RELEASE_CHECKLIST.md` passes.
