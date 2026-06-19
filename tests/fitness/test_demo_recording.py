# SPDX-License-Identifier: Apache-2.0
"""Fitness checks for the demo recording artifact (task 059).

Spec markers:
    TC-059-01 — recording artifact exists (local SVG/cast OR hosted asciinema link)
    TC-059-02 — README references the recording in the top section
    TC-059-03 — artifacts/recording.md (or README.md) documents the recording process
    TC-059-04 — recording artifact does not contain real canary values
    TC-059-05 — recording artifact size is ≤1 MB
    TC-059-06 — this fitness file exists
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO_ROOT / "artifacts"
README = REPO_ROOT / "README.md"

CANDIDATES = [
    ARTIFACTS / "demo.svg",
    ARTIFACTS / "demo-recording.cast",
    ARTIFACTS / "demo.cast",
]


def _local_recording() -> Path | None:
    return next((p for p in CANDIDATES if p.exists()), None)


def _readme_text() -> str:
    return README.read_text()


def test_tc_059_01_recording_artifact_exists() -> None:
    """TC-059-01: at least one local recording OR a hosted asciinema link."""
    local = _local_recording()
    hosted = "asciinema.org/a/" in _readme_text()
    assert local or hosted, "no demo recording artifact found and no asciinema.org link in README"


def test_tc_059_02_readme_references_recording_in_top_section() -> None:
    """TC-059-02: top of README references the recording (path or hosted link)."""
    head = "\n".join(_readme_text().splitlines()[:50])
    assert "artifacts/demo" in head or "asciinema.org/a/" in head, "README top section does not reference the recording"


def test_tc_059_03_recording_doc_exists() -> None:
    """TC-059-03: artifacts/recording.md (or README) documents the recording process."""
    candidates = [ARTIFACTS / "recording.md", ARTIFACTS / "README.md"]
    found = next((p for p in candidates if p.exists()), None)
    assert found, "no artifacts recording-doc (recording.md or README.md)"
    text = found.read_text().lower()
    assert "asciinema" in text, "recording doc does not mention asciinema"
    assert "make demo" in text, "recording doc does not mention make demo"


def test_tc_059_04_recording_does_not_leak_canaries() -> None:
    """TC-059-04: recording artifacts contain no real-shape canary values."""
    local = _local_recording()
    if not local:
        pytest.skip("no local recording artifact to scan")
    try:
        text = local.read_text()
    except UnicodeDecodeError:
        text = local.read_bytes().decode("utf-8", errors="ignore")
    matches = re.findall(r"AKIA[A-Z0-9]{8,20}", text)
    for m in matches:
        assert "FAKE" in m or "EXAMPLE" in m or "DEMO" in m, (
            f"recording {local.name} contains potentially-real AKIA-shaped string: {m}"
        )


def test_tc_059_05_recording_size_under_1mb() -> None:
    """TC-059-05: any local recording is ≤ 1 MB."""
    local = _local_recording()
    if not local:
        pytest.skip("no local recording artifact to size-check")
    size = local.stat().st_size
    assert size <= 1_048_576, f"{local.name} is {size} bytes (>1 MB)"
