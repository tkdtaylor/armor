# SPDX-License-Identifier: Apache-2.0
"""README / public-doc truthfulness fitness checks (task 057).

Asserts the project's published docs keep their claims auditable. After the
ecosystem-style README rewrite the detailed content moved out of the README
into dedicated docs, so these checks follow the content to its home:

  - honest status + limitations: README status blockquote + threat-model.md
  - measured performance (cited numbers, sample sizes, hardware envelope,
    source paths, dated run): docs/performance.md
  - no canary-shaped strings in the README that could become a leak channel

Spec markers:
    TC-057-01 — README carries an honest status/limitations disclosure and links threat-model.md
    TC-057-02 — threat-model.md enumerates the out-of-scope / not-defended attack classes
    TC-057-03 — README links to docs/architecture/threat-model.md and uses threat-model phrasing
    TC-057-04 — README cites at least 3 numeric claims with source path references
    TC-057-05 — README has a Measured/Performance/Benchmark/Detection section
    TC-057-06 — README has no real-shape AKIA strings without FAKE/EXAMPLE markers
    TC-057-08 — threat-model.md cites at least one ADR or spec doc
    TC-098-01 — Performance rate rows include N and Wilson 95% CI
    TC-098-02 — Performance latency rows cite a hardware envelope
    TC-098-03 — Performance rows cite a source path or reproduction procedure
    TC-098-04 — Performance preamble dates the run
    TC-098-05 — Fitness check enforces performance table evidence format
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"
PERF = REPO_ROOT / "docs" / "performance.md"
THREAT_MODEL = REPO_ROOT / "docs" / "architecture" / "threat-model.md"


@pytest.fixture(scope="module")
def readme_text() -> str:
    return README.read_text()


@pytest.fixture(scope="module")
def perf_text() -> str:
    return PERF.read_text()


@pytest.fixture(scope="module")
def threat_model_text() -> str:
    return THREAT_MODEL.read_text()


def _measured_performance_section(text: str) -> str:
    m = re.search(
        r"^##\s+Measured performance.*?(?=^##\s|\Z)",
        text,
        flags=re.M | re.S,
    )
    assert m, "README missing Measured performance section"
    return m.group(0)


def _performance_table_rows(text: str) -> list[tuple[str, str, str]]:
    section = _measured_performance_section(text)
    rows: list[tuple[str, str, str]] = []
    for line in section.splitlines():
        if not line.startswith("| ") or line.startswith("| Metric ") or line.startswith("|---"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 3:
            rows.append((cells[0], cells[1], cells[2]))
    assert rows, "Measured performance table has no data rows"
    return rows


def test_tc_057_01_readme_has_status_disclosure(readme_text: str) -> None:
    """TC-057-01: README carries an honest status/limitations disclosure that
    names at least one known-weak area and points to the long-form threat model."""
    assert re.search(r">\s*\*\*Status", readme_text), "README missing status disclosure blockquote"
    assert re.search(r"under-tested|remain|not yet|out of scope", readme_text, flags=re.I), (
        "README status disclosure names no known-weak area"
    )
    assert "docs/architecture/threat-model.md" in readme_text, "README does not link the threat model for limitations"


def test_tc_057_02_threat_model_enumerates_out_of_scope(threat_model_text: str) -> None:
    """TC-057-02: threat-model.md enumerates the not-defended / out-of-scope classes."""
    m = re.search(r"^##\s+NOT Defended Against.*?(?=^##\s|\Z)", threat_model_text, flags=re.M | re.S)
    assert m, "threat-model.md missing 'NOT Defended Against' section"
    classes = re.findall(r"^###\s+", m.group(0), flags=re.M)
    assert len(classes) >= 3, f"threat model enumerates fewer than 3 out-of-scope classes: {len(classes)}"


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


def test_tc_057_08_threat_model_cites_adr_or_spec(threat_model_text: str) -> None:
    """TC-057-08: threat-model.md cites at least one ADR or spec doc."""
    assert re.search(r"(decisions/\d{3}|ADR-\d{3}|docs/spec/)", threat_model_text, flags=re.I), (
        "threat model has no ADR or spec citations"
    )


def test_tc_098_01_rate_rows_include_n_and_wilson_ci(perf_text: str) -> None:
    """TC-098-01: percentage/rate rows include sample size and Wilson 95% CI."""
    rows = _performance_table_rows(perf_text)
    rate_rows = [(metric, value) for metric, value, _source in rows if "%" in value]
    assert rate_rows, "Measured performance table has no rate rows"
    for metric, value in rate_rows:
        assert re.search(r"\(\d+/\d+;", value), f"{metric!r} missing sample size in value cell"
        assert "Wilson 95% CI" in value, f"{metric!r} missing Wilson 95% CI"


def test_tc_098_02_latency_rows_reference_hardware_envelope(perf_text: str) -> None:
    """TC-098-02: the performance preamble documents the hardware/inference envelope
    the latency numbers were measured under (CPU, RAM, threading)."""
    section = _measured_performance_section(perf_text)
    assert "Intel Core Ultra 9 185H" in section, "performance preamble missing CPU model"
    assert "62 GiB RAM" in section, "performance preamble missing RAM"
    assert re.search(r"single-thread|n_threads=1", section), "performance preamble missing threading model"
    latency_rows = [
        (m, s) for m, _v, s in _performance_table_rows(perf_text) if "latency" in m.lower() or "cold-start" in m.lower()
    ]
    assert latency_rows, "no latency/cold-start rows in performance table"
    for metric, source in latency_rows:
        assert source.strip(), f"{metric!r} latency row has no source cell"


def test_tc_098_03_every_performance_row_has_source(perf_text: str) -> None:
    """TC-098-03: every measured-performance row cites a source or procedure."""
    for metric, _value, source in _performance_table_rows(perf_text):
        assert re.search(r"(tests/|docs/|artifacts/|architecture/|decisions/)", source), (
            f"{metric!r} has no source path"
        )


def test_tc_098_04_performance_preamble_dates_run(perf_text: str) -> None:
    """TC-098-04: measured-performance preamble includes a YYYY-MM-DD date."""
    section = _measured_performance_section(perf_text)
    preamble = section.split("| Metric |", 1)[0]
    assert re.search(r"\b20\d{2}-\d{2}-\d{2}\b", preamble), "performance preamble missing run date"
