"""Checks for the release workflow wiring."""

from __future__ import annotations

from pathlib import Path
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
REQUIREMENTS = ROOT / "requirements" / "release-build.txt"


@pytest.fixture(scope="module")
def jobs():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def step_with(steps, *, uses_prefix: str | None = None, name: str | None = None, step_id: str | None = None):
    for step in steps:
        if uses_prefix is not None and not step.get("uses", "").startswith(uses_prefix):
            continue
        if name is not None and step.get("name") != name:
            continue
        if step_id is not None and step.get("id") != step_id:
            continue
        return step
    raise AssertionError("step not found")


def test_container_tools_are_pinned_without_comment_values(jobs):
    for job in ("container", "container-publish"):
        steps = jobs[job]["steps"]
        qemu = step_with(steps, uses_prefix="docker/setup-qemu-action@")
        assert qemu["with"]["image"] == (
            "tonistiigi/binfmt:qemu-v10.2.3@sha256:"
            "400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
        )
        buildx = step_with(steps, uses_prefix="docker/setup-buildx-action@")
        assert buildx["with"]["version"] == "v0.38.2"
        driver_opts = buildx["with"]["driver-opts"].strip()
        assert driver_opts == (
            "image=moby/buildkit:v0.34.2@sha256:"
            "c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe"
        )


def test_publish_jobs_require_the_environment_opt_in_before_checkout(jobs):
    for job in ("container-publish", "release"):
        first = jobs[job]["steps"][0]
        assert first["name"] == "Require release publishing opt-in"
        assert first["env"]["RELEASE_PUBLISH_ENABLED"] == "${{ vars.RELEASE_PUBLISH_ENABLED }}"
        assert "uses" not in first


def test_container_publish_is_serialized_across_tags(jobs):
    concurrency = jobs["container-publish"]["concurrency"]
    assert concurrency["group"] == "release-container-publish"
    assert concurrency["cancel-in-progress"] is False


def test_registry_guard_runs_from_the_versioned_script(jobs):
    steps = jobs["container-publish"]["steps"]
    guard = step_with(steps, step_id="registry")
    assert guard["run"].strip() == "python3 scripts/release_registry_check.py"
    build = step_with(steps, step_id="build")
    assert build["with"]["tags"] == "${{ steps.registry.outputs.tags }}"


def test_release_verifies_the_tag_target_before_creating_the_draft(jobs):
    steps = jobs["release"]["steps"]
    names = [step.get("name") for step in steps]
    verify_index = names.index("Verify the tag still points at the built commit")
    create_index = names.index("Create the draft release")
    assert verify_index < create_index
    run = steps[verify_index]["run"]
    assert "git rev-parse HEAD" in run
    assert "git/ref/tags" in run


def test_release_review_checklist_is_in_job_summary_not_release_body(jobs):
    notes_step = step_with(jobs["release"]["steps"], name="Write release notes")
    notes_template = (ROOT / ".github" / "release-notes.md").read_text(encoding="utf-8")
    assert "GITHUB_STEP_SUMMARY" in notes_step["run"]
    assert "Confirm the version and notes" in notes_step["run"]
    assert "<!--" not in notes_template
    assert "[ ] Confirm" not in notes_template
    assert "{{VERSION}}" in notes_template and "{{DATE}}" in notes_template and "{{IMAGE_DIGEST}}" in notes_template


def test_python_distribution_build_uses_the_hashed_toolchain(jobs):
    step = step_with(jobs["python-dist"]["steps"], name="Build core sdist and wheel")
    run = step["run"]
    assert "--require-hashes" in run
    assert "requirements/release-build.txt" in run
    assert "--no-isolation" in run


def test_release_build_toolchain_is_hash_pinned():
    text = REQUIREMENTS.read_text(encoding="utf-8")
    pins = re.findall(
        r"^([A-Za-z0-9_.-]+)==(\S+) \\\n\s+--hash=sha256:([0-9a-f]{64})$",
        text,
        re.MULTILINE,
    )
    assert {name for name, _, _ in pins} == {
        "build",
        "packaging",
        "pip",
        "pyproject_hooks",
        "setuptools",
        "wheel",
    }


def test_release_builds_optional_wheels_and_the_binary_runtime_closure(jobs):
    steps = jobs["python-dist"]["steps"]
    build = step_with(steps, name="Build core sdist and wheel")["run"]
    assert "--wheel --outdir dist ./extensions" in build
    assert "--wheel --outdir dist ./automation" in build
    assert step_with(steps, name="Assemble the offline runtime wheelhouse")["run"] == "python scripts/build_release_wheelhouse.py dist"


def test_publishing_requires_signing_key_and_verifies_namespace_and_pin(jobs):
    for job in ("release", "container-publish"):
        assert "release-signing" in jobs[job]["needs"]
        assert "RELEASE_SIGNING_KEY" not in str(jobs[job])
    steps = jobs["release-signing"]["steps"]
    signing = step_with(steps, name="Sign and verify the checksum manifest")
    assert signing["env"]["RELEASE_SIGNING_KEY"] == "${{ secrets.RELEASE_SIGNING_KEY }}"
    assert 'test -n "${RELEASE_SIGNING_KEY:-}"' in signing["run"]
    assert "ssh-keygen -Y sign" in signing["run"]
    assert "-n cvebeacon-release" in signing["run"]
    assert "ssh-keygen -Y verify -f src/cvebeacon/release-allowed-signers" in signing["run"]
    assert "trap 'rm -f" in signing["run"]
    assert steps.index(signing) < steps.index(step_with(steps, uses_prefix="actions/upload-artifact@"))
    publish = jobs["release"]["steps"]
    assert publish.index(step_with(publish, name="Verify signed release artifacts")) < publish.index(step_with(publish, name="Create the draft release"))


def test_wheelhouse_smoke_resolves_only_compatible_runtime_wheels(jobs):
    smoke = step_with(jobs["python-dist"]["steps"], name="Install and smoke-test the wheel")["run"]
    assert "--no-index --only-binary=:all: --find-links dist cvebeacon cvebeacon-extensions cvebeacon-automation" in smoke
    assert "pip install dist/*.whl" not in smoke


def test_windows_bundle_keeps_metadata_for_check_only_version_reporting():
    script = (ROOT / "scripts" / "build-windows.ps1").read_text()
    assert "--copy-metadata cvebeacon" in script


def test_all_publication_jobs_wait_for_a_pin_validation_gate_without_container_key_access(jobs):
    gate = jobs["release-signing"]
    assert gate["environment"] == "release"
    assert "release-signing" in jobs["container-publish"]["needs"]
    assert "release-signing" in jobs["release"]["needs"]
    assert "RELEASE_SIGNING_KEY" not in str(jobs["container-publish"])


def test_020_upgrade_notes_require_the_administrator_command():
    guide = (ROOT / "docs" / "UPGRADING.md").read_text(encoding="utf-8")
    template = (ROOT / ".github" / "release-notes.md").read_text(encoding="utf-8")
    for notes in (guide, template):
        boundary = " ".join(notes.split("**Upgrading from 0.2.0.**", 1)[1].split("\n\n", 1)[0].split())
        assert "sudo /opt/cvebeacon/current/.venv/bin/cvebeacon update apply" in boundary
        assert "crontab" in boundary and "update service" in boundary
        assert "Dashboard-triggered upgrades work from 0.2.1 onward" in boundary
