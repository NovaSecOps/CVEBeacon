# Release checklist

This page covers the one-time repository setup, the per-release procedure, and
the checks that must pass before a release is published.

The workflow itself enforces three things: publishing jobs run only for a `v*`
tag push, both reference the `release` environment, and both require the
`RELEASE_PUBLISH_ENABLED` value in the merged `vars` context to be exactly
`true` before checkout, registry login, image push or release creation. GitHub
creates a referenced environment automatically when it does not exist, without
reviewers or rules, so the environment name alone is not protection. The
workflow cannot prove that the variable is environment-scoped, that reviewers
are required, or that the tag rule and admin-bypass settings exist; GitHub
enforces those only when the environment is configured. The setup and
verification below are release prerequisites.

| Control | Enforced by |
| --- | --- |
| Publish on `v*` tag push only | Workflow conditions |
| `RELEASE_PUBLISH_ENABLED` is exactly `true` in merged `vars` | Workflow step (cannot distinguish scope) |
| Variable scoped to the `release` environment | Repository configuration; verified manually |
| Required reviewers | GitHub environment protection |
| Tag rule `v*` | GitHub environment protection |
| Administrative bypass disabled | GitHub environment protection |

The opt-in makes a missing environment fail closed only while the variable is
absent. A repository- or organization-level variable would pass the workflow
step, which is why step 5 below forbids that scope and step 9 verifies the
environment directly.

## One-time setup

1. In the repository settings, open **Environments** and create `release`.
2. Add at least one required reviewer. Enable **Prevent self-review** when the
   plan offers it.
3. Add a deployment **Tag** rule for `v*`. Use a tag rule, not a branch rule.
4. Turn off **Allow administrators to bypass configured protection rules**.
5. Only after steps 1-4, add an environment variable
   `RELEASE_PUBLISH_ENABLED` with the value `true` to `release`. Do not create
   this variable at repository or organization level. The workflow reads the
   merged value and cannot verify its scope; a repository-level variable would
   defeat the missing-environment protection. The verification below reads the
   environment directly.
6. Keep the default `GITHUB_TOKEN` permissions read-only at repository level.
   The workflow requests `contents: write` only in the release job and
   `packages: write` only in the container publish job.
7. Confirm that the repository packages namespace can host
   `ghcr.io/novasecops/cvebeacon`. Make the package public after the first
   publish, or grant the intended audience read access.
8. Confirm that the `release` environment has no secrets. The workflow uses the
   repository token and does not need a personal token or a registry password.
9. Verify the setup read-only after the variable is in place:

   ```console
   gh api repos/NovaSecOps/CVEBeacon/environments/release \
     --jq '{can_admins_bypass, protection_rules, deployment_branch_policy}'
   gh api repos/NovaSecOps/CVEBeacon/environments/release/deployment-branch-policies \
     --jq '.branch_policies[] | {name, type}'
   gh api repos/NovaSecOps/CVEBeacon/environments/release/variables \
     --jq '.variables[] | {name, value}'
   ```

   Confirm `can_admins_bypass` is `false`, `protection_rules` contains a
   `required_reviewers` rule, the branch policies list a `tag` named `v*`, and
   the environment variables include `RELEASE_PUBLISH_ENABLED=true`. The last
   check reads the environment directly; a repository-level variable with the
   same name is not sufficient and must be removed.
10. Add a repository tag ruleset that blocks updates and deletions for `v*`.
    The release job also verifies that the tag still points at the built
    commit before creating the draft, but the ruleset prevents the move in the
    first place.

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
- Treat changes to `requirements/release-build.txt` as reviewed changes. The
  python distribution build fails when a pinned version or hash does not match
  the index.
- Open a pull request that touches `.github/workflows/release.yml` or a
  packaging file when the workflow itself changed, and confirm the build-only
  jobs pass.

## Release procedure

1. Merge the version bump to `main` and confirm the validation workflows pass.
2. Create and push the annotated tag from the release commit. Pushing the tag
   starts the release workflow; it does not publish anything by itself.
3. Approve the `release` environment deployment requests for the container
   publish job and the draft release job. Approval is required before any
   image push or release creation. Container publishing is serialized across
   all release tags: one shared concurrency group with cancellation disabled
   covers the registry check through the image push. Queued publish runs
   execute one at a time, and a newer queued run can replace an older waiting
   run, so publish tags one at a time.
4. Wait for the `verify`, `python-dist`, `windows-exe`, `container-publish` and
   `release` jobs. If a job fails, do not assume the run left nothing behind:
   the image push happens before draft creation, and a draft can exist with
   only some of its assets. Inspect the registry tags and any existing draft
   before retrying or cleaning up; see [Recovery from a partial run](#recovery-from-a-partial-run).
   The release job also verifies that the tag still resolves to the commit the
   run built; a moved or recreated tag stops draft creation.
5. Open the draft release and review the generated notes, the asset list, and
   `SHA256SUMS`.
6. Download the assets and verify the checksums with
   `sha256sum -c SHA256SUMS`. Install the wheel in a clean environment and run
   `cvebeacon --help`. Extract the Windows archive on a Windows host and run
   `cvebeacon.exe --help`.
7. Confirm the published image tag and the manifest digest recorded in the
   notes (replace `0.1.0` with the released version). The version tag is
   immutable. For a stable release, also confirm `latest`:

   ```console
   docker buildx imagetools inspect ghcr.io/novasecops/cvebeacon:0.1.0
   docker pull ghcr.io/novasecops/cvebeacon:0.1.0
   docker run --rm --network none --read-only --cap-drop ALL \
     --security-opt no-new-privileges:true \
     ghcr.io/novasecops/cvebeacon:0.1.0 --help
   docker buildx imagetools inspect ghcr.io/novasecops/cvebeacon:latest
   ```

   `latest` moves only when the version is the highest stable tag in the
   registry at the time the serialized publish job runs. A pre-release
   publishes only its version tag and does not create or move `latest`.

8. Publish the draft release only after the checks above pass. Publishing is a
   separate manual action; the workflow never publishes a release.
9. Confirm the release page lists every asset and the source archives.
10. Announce the release only after the GHCR package visibility and the
    release assets are confirmed.

## Recovery from a partial run

GitHub release creation and its asset uploads are separate operations, and the
image push happens before either. A failed or interrupted run can therefore
leave a published image, a draft with only some assets, or both. The workflow
does not roll either back. Inspect first; keep cleanup manual and
owner-authorized.

1. List the failed run's jobs and its downloadable artifacts. Confirm which
   jobs completed.
2. Inspect the image tags and digest:

   ```console
   docker buildx imagetools inspect ghcr.io/novasecops/cvebeacon:VERSION
   docker buildx imagetools inspect ghcr.io/novasecops/cvebeacon:latest
   ```

3. Inspect any existing draft and its assets:

   ```console
   gh release view vVERSION --json isDraft,assets
   ```

4. If the version image already exists, do not re-run the publish job. It
   refuses to overwrite an existing version tag. Reuse the digest recorded by
   the original run when completing or repairing the release.
5. If a draft contains only some assets, download and compare them against
   `SHA256SUMS` before deleting or completing it. Delete or replace draft
   assets only with owner approval, and never publish an incomplete draft.
6. If the version image is wrong and its release is still unpublished, publish
   a superseding patch version. Deleting an unpublished GHCR package version is
   an owner decision; never move or retag an existing version.
7. If `latest` was not moved, leave it. The workflow promotes `latest` only
   when the released version is the highest stable tag present when the
   serialized publish job runs. Publish the next higher patch and let the
   workflow move `latest` forward; do not point it backward by hand.

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
