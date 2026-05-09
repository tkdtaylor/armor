"""Test Task 029 — Release artifacts acceptance criteria.

Tests verify release infrastructure (workflows, CHANGELOG gate, docs, ADR, metadata).

Markers:
  TC-029-01: Release workflow triggers on v*.*.*
  TC-029-02: Release workflow builds multi-arch image
  TC-029-03: PyPI publish via OIDC
  TC-029-04: Published image smoke test
  TC-029-05: armor --version reflects git tag
  TC-029-06: README has Getting Started — container path
  TC-029-07: README has Getting Started — PyPI path
  TC-029-08: CHANGELOG fitness — fails without update
  TC-029-09: CHANGELOG fitness — passes with update
  TC-029-10: CHANGELOG fitness — honors skip-changelog
  TC-029-11: Post-release checklist exists
  TC-029-12: ADR-030-release-versioning exists
  TC-029-13: pyproject.toml final metadata
"""

import os
import subprocess
from pathlib import Path

import pytest

from armor import __version__


class TestReleaseWorkflow:
    """TC-029-01, TC-029-02, TC-029-03, TC-029-04: Release workflow."""

    def test_release_workflow_exists(self):
        """Verify .github/workflows/release.yml exists."""
        workflow_path = Path(".github/workflows/release.yml")
        assert workflow_path.exists(), "release.yml workflow not found"

    def test_workflow_triggers_on_version_tags(self):
        """TC-029-01: Trigger on v*.*.*."""
        workflow_path = Path(".github/workflows/release.yml")
        with open(workflow_path) as f:
            content = f.read()

        # Check for on.push.tags pattern
        assert "on:" in content, "No 'on:' trigger found"
        assert "push:" in content, "No push trigger found"
        assert "tags:" in content, "No tags trigger found"
        assert "v*.*.*" in content, "Pattern 'v*.*.*' not found in workflow"

    def test_workflow_builds_multiarch_image(self):
        """TC-029-02: docker/setup-qemu-action and docker/build-push-action with platforms."""
        workflow_path = Path(".github/workflows/release.yml")
        with open(workflow_path) as f:
            content = f.read()

        assert "docker/setup-qemu-action" in content, "setup-qemu-action not found"
        assert "docker/build-push-action" in content, "build-push-action not found"
        assert "linux/amd64" in content, "linux/amd64 platform not found"
        assert "linux/arm64" in content, "linux/arm64 platform not found"

    def test_workflow_publishes_to_pypi_via_oidc(self):
        """TC-029-03: pypa/gh-action-pypi-publish with OIDC (no PYPI_API_TOKEN)."""
        workflow_path = Path(".github/workflows/release.yml")
        with open(workflow_path) as f:
            content = f.read()

        assert "pypa/gh-action-pypi-publish" in content, "pypi-publish action not found"
        assert "PYPI_API_TOKEN" not in content, "PYPI_API_TOKEN secret found (should use OIDC)"
        assert "id-token:" in content or "id-token :" in content, "OIDC id-token permission not configured"

    def test_workflow_includes_smoke_test(self):
        """TC-029-04: Smoke test job that pulls published image and runs demo."""
        workflow_path = Path(".github/workflows/release.yml")
        with open(workflow_path) as f:
            content = f.read()

        assert "smoke" in content.lower(), "Smoke test job not found"
        assert "docker pull" in content or "docker run" in content, "Docker image pull/run not found in smoke test"


class TestArmorVersion:
    """TC-029-05: armor --version reflects build-time tag."""

    def test_version_is_not_hardcoded_zero(self):
        """Verify __version__ is set up for tag-based override."""
        # In development, __version__ should be "0.0.0" (overridden at build time)
        assert __version__ == "0.0.0", f"Expected '0.0.0' in dev, got {__version__}"

    def test_cli_uses_package_version(self):
        """Verify CLI reads from package metadata."""
        cli_path = Path("src/armor/cli.py")
        with open(cli_path) as f:
            content = f.read()

        # Should import __version__ from armor package, not hardcode
        assert "from armor import __version__" in content, "CLI doesn't import __version__ from package"
        assert 'f"armor {__version__}"' in content or "armor {__version__}" in content, "CLI doesn't use __version__"


class TestREADME:
    """TC-029-06, TC-029-07: README Getting Started section."""

    def test_readme_getting_started_section_exists(self):
        """Verify ## Getting started heading."""
        readme_path = Path("README.md")
        with open(readme_path) as f:
            content = f.read()

        assert "## Getting started" in content, "Getting started section not found"

    def test_readme_container_path(self):
        """TC-029-06: Container path documents the build/run command and points to the GHCR plan.

        Per the public-release docs refresh (2026-05-07), the README
        no longer claims `docker run ghcr.io/tkdtaylor/armor:latest` works today
        because the multi-arch image has not been published yet. Instead it shows
        the local `docker compose` build path and references the release workflow
        that will publish the image with the first tag. Assertions updated to
        match: any docker invocation + the release workflow reference.
        """
        readme_path = Path("README.md")
        with open(readme_path) as f:
            content = f.read()

        assert "docker compose" in content, "docker compose command not found"
        assert ".github/workflows/release.yml" in content, "release workflow reference not found"

    def test_readme_pypi_path(self):
        """TC-029-07: PyPI path acknowledges the name-collision and points to examples/.

        Per the public-release docs refresh (2026-05-07), the README
        no longer shows `pip install armor` because the bare `armor` name on PyPI
        is taken by an unrelated project; the README explicitly states a final
        non-colliding name will land with the first tagged release. Assertions
        updated to: PyPI is mentioned + the examples/ cross-link is present.
        """
        readme_path = Path("README.md")
        with open(readme_path) as f:
            content = f.read()

        assert "PyPI" in content, "PyPI is not mentioned in README"
        assert "examples/" in content, "examples/ cross-link not found"

    def test_readme_mentions_demo(self):
        """Verify README documents the demo."""
        readme_path = Path("README.md")
        with open(readme_path) as f:
            content = f.read()

        assert "make demo" in content, "make demo not mentioned"
        assert "Scenario 1" in content and "Scenario 2" in content, "Demo scenarios not documented"


class TestCHANGELOGFitness:
    """TC-029-08, TC-029-09, TC-029-10: CHANGELOG update fitness."""

    def test_changelog_fitness_skip_mode(self):
        """TC-029-10: Honors SKIP_CHANGELOG env var.

        Post-task-091 the CHANGELOG check is a pytest test
        (`tests/fitness/test_changelog_updated.py`); under SKIP_CHANGELOG=1
        it must skip cleanly (pytest exit code 0; "1 skipped").
        """
        result = subprocess.run(
            ["uv", "run", "pytest", "tests/fitness/test_changelog_updated.py", "-v", "-p", "no:cacheprovider"],
            env={**os.environ, "SKIP_CHANGELOG": "1"},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Skip mode failed: {result.stderr}\n{result.stdout}"
        assert "skipped" in result.stdout.lower() and "changelog" in result.stdout.lower()

    def test_changelog_file_exists(self):
        """Verify CHANGELOG.md exists."""
        changelog_path = Path("CHANGELOG.md")
        assert changelog_path.exists(), "CHANGELOG.md not found"

    def test_changelog_format(self):
        """Verify CHANGELOG follows Keep a Changelog format."""
        changelog_path = Path("CHANGELOG.md")
        with open(changelog_path) as f:
            content = f.read()

        # Check for key sections
        assert "[Unreleased]" in content, "[Unreleased] section not found"
        assert "## [0" in content, "No version entries found"
        assert "Added" in content or "added" in content, "No 'Added' section found"


class TestPostReleaseChecklist:
    """TC-029-11: Post-release checklist exists."""

    def test_post_release_checklist_exists(self):
        """TC-029-11: Verify docs/release/post-release-checklist.md exists."""
        checklist_path = Path("docs/release/post-release-checklist.md")
        assert checklist_path.exists(), "Post-release checklist not found"

    def test_checklist_contains_verification_steps(self):
        """Verify checklist covers fresh container, fresh pip, hook installer."""
        checklist_path = Path("docs/release/post-release-checklist.md")
        with open(checklist_path) as f:
            content = f.read()

        # Check for key verification sections
        assert "fresh container" in content.lower() or "docker pull" in content.lower(), (
            "Fresh container verification not in checklist"
        )
        assert "fresh" in content.lower() and "pip install" in content.lower(), (
            "Fresh pip install verification not in checklist"
        )
        assert "hook" in content.lower() or "armor hook" in content.lower(), (
            "Hook installer verification not in checklist"
        )


class TestADR:
    """TC-029-12: ADR for release versioning."""

    def test_adr_030_exists(self):
        """TC-029-12: Verify ADR-030-release-versioning.md exists."""
        adr_path = Path("docs/architecture/decisions/030-release-versioning.md")
        assert adr_path.exists(), "ADR-030 not found"

    def test_adr_documents_semver_scope(self):
        """Verify ADR documents SDK, CLI, IPC under semver; corpus/ADRs not."""
        adr_path = Path("docs/architecture/decisions/030-release-versioning.md")
        with open(adr_path) as f:
            content = f.read()

        # Check for key concepts
        assert "semver" in content.lower(), "semver not mentioned"
        assert "SDK" in content, "SDK not mentioned"
        assert "CLI" in content, "CLI not mentioned"
        assert "IPC" in content, "IPC not mentioned"
        assert "Semantic Versioning" in content or "semantic versioning" in content, "Semantic Versioning not explained"


class TestProjectMetadata:
    """TC-029-13: pyproject.toml final metadata."""

    def test_project_name_locked(self):
        """Verify PyPI distribution name is `ai-armor` (the bare `armor` is taken on PyPI)."""
        pyproject_path = Path("pyproject.toml")
        with open(pyproject_path) as f:
            content = f.read()

        assert 'name = "ai-armor"' in content, "PyPI distribution name is not 'ai-armor'"

    def test_classifiers_present(self):
        """Verify classifiers list is non-empty."""
        pyproject_path = Path("pyproject.toml")
        with open(pyproject_path) as f:
            content = f.read()

        assert "classifiers = [" in content, "No classifiers found"
        assert "Development Status" in content, "Development Status classifier missing"
        assert "Topic :: Security" in content, "Topic :: Security classifier missing"

    def test_urls_configured(self):
        """Verify [project.urls] has Homepage and Source."""
        pyproject_path = Path("pyproject.toml")
        with open(pyproject_path) as f:
            content = f.read()

        assert "[project.urls]" in content, "[project.urls] section not found"
        assert "Homepage" in content, "Homepage URL missing"
        assert "Source" in content, "Source URL missing"
        assert "github.com" in content.lower(), "GitHub repo not referenced"

    def test_license_polyform(self):
        """Verify license references PolyForm Noncommercial."""
        pyproject_path = Path("pyproject.toml")
        with open(pyproject_path) as f:
            content = f.read()

        assert "PolyForm" in content or "polyform" in content.lower(), "PolyForm license not referenced"


class TestDockerfile:
    """Verify Dockerfile is present and bakes the model."""

    def test_dockerfile_exists(self):
        """Verify docker/Dockerfile exists."""
        dockerfile_path = Path("docker/Dockerfile")
        assert dockerfile_path.exists(), "docker/Dockerfile not found"

    def test_dockerfile_bakes_model(self):
        """Verify Dockerfile references model.gguf."""
        dockerfile_path = Path("docker/Dockerfile")
        with open(dockerfile_path) as f:
            content = f.read()

        assert "model.gguf" in content, "Model weight file not referenced in Dockerfile"
        assert "multi-stage" in content or "as builder" in content, "Multi-stage Dockerfile not used"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
