# SPDX-License-Identifier: Apache-2.0
"""Fitness checks for .github/ infrastructure (task 060).

Spec markers:
    TC-060-01 — codeql.yml exists and is valid YAML
    TC-060-02 — codeql.yml uses security-extended query suite
    TC-060-03 — codeql.yml triggers on PR, push, and schedule
    TC-060-04 — codeql.yml excludes tests/ and archive/ paths
    TC-060-05 — dependabot.yml exists, version 2
    TC-060-06 — dependabot.yml covers pip, github-actions, docker ecosystems
    TC-060-07 — bug_report.yml exists and uses YAML form schema (has body:)
    TC-060-08 — bug_report.yml has an attack-class dropdown
    TC-060-09 — feature_request.yml + config.yml exist
    TC-060-10 — config.yml disables blank issues, links SECURITY.md / security
    TC-060-11 — PULL_REQUEST_TEMPLATE.md has required checklist items
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GH = REPO_ROOT / ".github"


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text())


def _on_block(data: dict[str, Any]) -> dict[str, Any]:
    """PyYAML quirk: 'on' may parse as Python True."""
    return data.get("on", data.get(True, {}))


def test_tc_060_01_codeql_yml_exists_and_valid() -> None:
    """TC-060-01: codeql.yml is valid YAML."""
    p = GH / "workflows" / "codeql.yml"
    assert p.exists(), "codeql.yml missing"
    data = _load_yaml(p)
    assert isinstance(data, dict)


def test_tc_060_02_codeql_uses_security_extended() -> None:
    """TC-060-02: codeql.yml uses the security-extended query suite."""
    text = (GH / "workflows" / "codeql.yml").read_text()
    assert "security-extended" in text, "codeql.yml does not use security-extended queries"


def test_tc_060_03_codeql_triggers_on_pr_push_schedule() -> None:
    """TC-060-03: codeql.yml triggers on PR, push, and schedule."""
    data = _load_yaml(GH / "workflows" / "codeql.yml")
    on = _on_block(data)
    for trigger in ("pull_request", "push", "schedule"):
        assert trigger in on, f"codeql.yml missing {trigger} trigger"


def test_tc_060_04_codeql_excludes_tests_and_archive() -> None:
    """TC-060-04: codeql.yml excludes tests/ and archive/ paths."""
    workflow_text = (GH / "workflows" / "codeql.yml").read_text()
    config = GH / "codeql" / "codeql-config.yml"
    assert "config-file: ./.github/codeql/codeql-config.yml" in workflow_text
    assert config.exists(), "CodeQL config file missing"

    text = config.read_text()
    for needle in ("tests", "archive"):
        assert needle in text, f"codeql.yml does not reference {needle}/ in path filters"


def test_tc_060_05_dependabot_yml_valid_v2() -> None:
    """TC-060-05: dependabot.yml is valid YAML, version 2."""
    p = GH / "dependabot.yml"
    assert p.exists(), "dependabot.yml missing"
    data = _load_yaml(p)
    assert data.get("version") == 2, "dependabot.yml not version 2"


def test_tc_060_06_dependabot_covers_three_ecosystems() -> None:
    """TC-060-06: dependabot.yml covers pip, github-actions, docker."""
    data = _load_yaml(GH / "dependabot.yml")
    ecosystems = {u.get("package-ecosystem") for u in data.get("updates", [])}
    for needle in ("pip", "github-actions", "docker"):
        assert needle in ecosystems, f"dependabot.yml missing {needle} ecosystem"


def test_tc_060_07_bug_report_yml_uses_form_schema() -> None:
    """TC-060-07: bug_report.yml is in the issue-form schema (has body)."""
    p = GH / "ISSUE_TEMPLATE" / "bug_report.yml"
    assert p.exists(), "bug_report.yml missing"
    data = _load_yaml(p)
    assert "body" in data, "bug_report.yml is not in the issue-form schema"


def test_tc_060_08_bug_report_has_attack_class_dropdown() -> None:
    """TC-060-08: bug_report.yml has a dropdown enumerating attack classes."""
    data = _load_yaml(GH / "ISSUE_TEMPLATE" / "bug_report.yml")
    dropdowns = [b for b in data["body"] if b.get("type") == "dropdown"]
    assert dropdowns, "bug_report.yml has no dropdown"
    options_combined = " ".join(" ".join(d.get("attributes", {}).get("options", [])) for d in dropdowns).lower()
    for needle in ("inject", "exfiltrat", "tool", "multi-turn"):
        assert needle in options_combined, f"attack-class dropdown missing {needle}"


def test_tc_060_09_feature_and_config_exist() -> None:
    """TC-060-09: feature_request.yml + config.yml exist and parse as YAML."""
    for name in ("feature_request.yml", "config.yml"):
        p = GH / "ISSUE_TEMPLATE" / name
        assert p.exists(), f"{name} missing"
        _load_yaml(p)


def test_tc_060_10_config_disables_blank_links_security() -> None:
    """TC-060-10: config.yml disables blank issues + has a security contact link."""
    data = _load_yaml(GH / "ISSUE_TEMPLATE" / "config.yml")
    assert data.get("blank_issues_enabled") is False, "blank issues not disabled"
    links_repr = str(data.get("contact_links", [])).lower()
    assert "security" in links_repr, "config.yml does not link to SECURITY.md / security advisory"


def test_tc_060_11_pr_template_has_required_checklist() -> None:
    """TC-060-11: PR template has checkboxes for test spec, make check, make fitness, CHANGELOG."""
    p = GH / "PULL_REQUEST_TEMPLATE.md"
    assert p.exists(), "PULL_REQUEST_TEMPLATE.md missing"
    text = p.read_text().lower()
    for needle in ("test spec", "make check", "make fitness", "changelog"):
        assert needle in text, f"PR template missing checklist item: {needle}"


def test_ci_fitness_jobs_fetch_release_tags() -> None:
    """CI fitness jobs need release tags for the public-release fitness gate."""
    data = _load_yaml(GH / "workflows" / "ci.yml")
    jobs = data["jobs"]

    for job_name in ("fitness", "make-fitness"):
        steps = jobs[job_name]["steps"]
        checkout = next(step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@"))
        assert checkout.get("with", {}).get("fetch-depth") == 0, f"{job_name} does not fetch full history"
        assert checkout.get("with", {}).get("fetch-tags") is True, f"{job_name} does not fetch tags"
