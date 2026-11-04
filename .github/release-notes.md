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
| `cvebeacon-{{VERSION}}.tar.gz` | Core source distribution |
| `cvebeacon-windows-x64.zip` | Windows x86-64 one-folder bundle and one-file executable |
| `SHA256SUMS` | SHA-256 checksums for every asset |

The wheel and source distribution require Python 3.11 or newer. The Windows
archive is built on Windows Server 2025 for x86-64; extract it and run
`cvebeacon.exe --help` before replacing an existing installation.

Verify the downloads from the directory that contains them:

```console
sha256sum -c SHA256SUMS
```

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

- Stop running scans and back up the SQLite state before upgrading.
- Roll back with the matching release and database backup, not an in-place
  database downgrade.
- Read the [container guide](https://github.com/novasecops/cvebeacon/blob/main/docs/CONTAINERS.md)
  and [user guide](https://github.com/novasecops/cvebeacon/blob/main/docs/USER_GUIDE.md)
  for configuration changes.

## Publishing checklist

- [ ] Confirm the version and notes in this draft.
- [ ] Confirm `SHA256SUMS` covers every uploaded asset.
- [ ] Confirm the GHCR manifest digest matches `{{IMAGE_DIGEST}}`.
- [ ] Publish only after `docs/RELEASE_CHECKLIST.md` passes.
