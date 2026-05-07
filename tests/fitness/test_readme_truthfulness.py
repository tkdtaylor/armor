"""README truthfulness fitness checks (task 057).

Asserts the README contains the structural and content elements that make
its claims auditable: a Limitations section that enumerates the known gaps,
a threat-model summary linking to the long-form doc, a measured-performance
section with cited numbers (each anchored to a source path), and no
canary-shaped strings that could become a leak channel.

Spec markers:
    TC-057-01 — README has a "Limitations" section
    TC-057-02 — Limitations section covers adversary, soft-fail, multilingual, UI
    TC-057-03 — README links to docs/architecture/threat-model.md and uses threat-model phrasing
    TC-057-04 — README cites at least 3 numeric claims with source path references
    TC-057-05 — README has a Measured/Performance/Benchmark/Detection section
    TC-057-06 — README has no real-shape AKIA strings without FAKE/EXAMPLE markers
    TC-057-08 — Limitations section cites at least one ADR or spec doc
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"


@pytest.fixture(scope="module")
def readme_text() -> str:
    return README.read_text()


def _limitations_section(text: str) -> str:
    m = re.search(
        r"^#+\s+.*Limitations.*?(?=^##\s|\Z)",
        text,
        flags=re.M | re.S | re.I,
    )
    assert m, "README missing Limitations section"
    return m.group(0)


def test_tc_057_01_readme_has_limitations_section(readme_text: str) -> None:
    """TC-057-01: A heading whose text contains 'Limitations' exists."""
    assert re.search(r"^#+\s+.*Limitations", readme_text, flags=re.M | re.I), "README missing Limitations section"


def test_tc_057_02_limitations_covers_required_topics(readme_text: str) -> None:
    """TC-057-02: Limitations section covers adversary, soft-fail, multilingual, UI."""
    section = _limitations_section(readme_text).lower()
    for needle in ["adversary", "soft-fail", "multilingual", "ui"]:
        assert needle in section, f"Limitations section missing topic: {needle!r}"


def test_tc_057_03_readme_links_threat_model(readme_text: str) -> None:
    """TC-057-03: README links to threat-model.md and uses threat-model phrasing."""
    assert "docs/architecture/threat-model.md" in readme_text, "README does not link to threat-model.md"
    assert "threat model" in readme_text.lower(), "no threat-model phrasing in README"


def test_tc_057_04_readme_cites_numbers_with_sources(readme_text: str) -> None:
    """TC-057-04: At least 3 numeric claims (with units) and a source path reference."""
    claims = re.findall(r"\d+(?:[.,]\d+)?\s*(?:%|ms|s\b|MB|KB|GB)", readme_text)
    assert len(claims) >= 3, f"README has fewer than 3 numeric claims: {claims}"
    assert re.search(r"(tests/|artifacts/|docs/architecture/)", readme_text), (
        "README has numeric claims but no source path references"
    )


def test_tc_057_05_readme_has_performance_section(readme_text: str) -> None:
    """TC-057-05: A heading signals empirical results."""
    assert re.search(
        r"^#+\s+.*(Measured|Performance|Benchmark|Detection)",
        readme_text,
        flags=re.M | re.I,
    ), "README missing measured-performance section"


def test_tc_057_06_no_real_canary_shape_in_readme(readme_text: str) -> None:
    """TC-057-06: No real-shape AKIA strings without FAKE/EXAMPLE markers."""
    matches = re.findall(r"AKIA[A-Z0-9]{8,20}", readme_text)
    for m in matches:
        assert "FAKE" in m or "EXAMPLE" in m, f"README contains potentially-real AKIA-shaped string: {m}"


def test_tc_057_08_limitations_cites_adr_or_spec(readme_text: str) -> None:
    """TC-057-08: Limitations section cites at least one ADR or spec doc."""
    section = _limitations_section(readme_text)
    assert re.search(r"docs/(architecture/decisions/|spec/)", section), (
        "Limitations section has no ADR or spec citations"
    )
