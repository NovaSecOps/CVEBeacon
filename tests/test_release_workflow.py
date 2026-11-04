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
