# Release checklist

This page covers the one-time repository setup, the per-release procedure, and
the checks that must pass before a release is published. The release workflow
builds every artifact without publishing; a `v*` tag push publishes only after
the `release` environment approves the run.

## One-time setup

1. Create the `release` environment in the repository settings and add the
   required reviewers. The environment approval is the only path that allows
   image pushes and the draft release; without it the publishing jobs stay
   queued.
2. Allow the workflow to use the environment from tag refs only. Do not add
   branch deployment rules for this environment.
3. Confirm that the repository packages namespace can host
   `ghcr.io/novasecops/cvebeacon`. Make the package public after the first
   publish, or grant the intended audience read access.
4. Keep the default `GITHUB_TOKEN` permissions read-only at repository level.
   The workflow requests `contents: write` only in the release job and
   `packages: write` only in the container publish job.
5. Confirm that the `release` environment has no secrets. The workflow uses the
   repository token and does not need a personal token or a registry password.

## Before tagging

- Confirm distributions include the Apache-2.0 `LICENSE` and project attribution `NOTICE`.
- Run the deterministic test suite on every supported Python version.
- Build and smoke-test the standalone executable separately on Windows and Linux.
- Review dependency versions and vulnerability advisories.
- Confirm the source and network documentation against current endpoints.
- Scan the public tree for secrets, private inventories, machine-specific paths, and generated state.
- Bump `version` in `pyproject.toml`; the tag must equal `v` plus that exact
  version (`0.1.0` becomes `v0.1.0`).
- Update the release notes template values that are not filled in by the
  workflow, and commit the version bump.
- Open a pull request that touches `.github/workflows/release.yml` or a
  packaging file when the workflow itself changed, and confirm the build-only
  jobs pass.

## Release procedure

1. Merge the version bump to `main` and confirm the validation workflows pass.
2. Create and push the annotated tag from the release commit. Pushing the tag
   starts the release workflow; it does not publish anything by itself.
3. Approve the `release` environment deployment requests for the container
   publish job and the draft release job. Approval is required before any
   image push or release creation.
4. Wait for the `verify`, `python-dist`, `windows-exe`, `container-publish` and
   `release` jobs. Every job must pass; a failed job leaves no release.
5. Open the draft release and review the generated notes, the asset list, and
   `SHA256SUMS`.
6. Download the assets and verify the checksums with
   `sha256sum -c SHA256SUMS`. Install the wheel in a clean environment and run
   `cvebeacon --help`. Extract the Windows archive on a Windows host and run
   `cvebeacon.exe --help`.
7. Confirm the published image tags and the manifest digest recorded in the
   notes (replace `0.1.0` with the released version):

   ```console
   docker buildx imagetools inspect ghcr.io/novasecops/cvebeacon:0.1.0
   docker pull ghcr.io/novasecops/cvebeacon:0.1.0
   docker run --rm --network none --read-only --cap-drop ALL \
     --security-opt no-new-privileges:true \
     ghcr.io/novasecops/cvebeacon:0.1.0 --help
   ```

8. Publish the draft release only after the checks above pass. Publishing is a
   separate manual action; the workflow never publishes a release.
9. Confirm the release page lists every asset and the source archives.
10. Announce the release only after the GHCR package visibility and the
    release assets are confirmed.

## After publishing

- Keep the tag and the release immutable. Fix a defect with a new patch
  version; do not move or re-create the tag.
- Record the image digest and the checksums from the release in the
  operational notes for the deployments that consume them.
- Roll back a deployment with the matching image tag and a database backup,
  not with an in-place database downgrade.
- If an artifact is wrong, edit the draft before publishing when possible.
  After publishing, mark the release as withdrawn in its notes and publish a
  corrected patch release rather than replacing assets.
