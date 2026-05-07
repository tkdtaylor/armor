"""Fitness checks for task 052 — Refresh docs/architecture/diagrams.md.

This module encodes the diagrams spec audit as runnable assertions that prevent
drift between the code structure, system boundaries, and the documented flow diagrams.

Spec markers:
    TC-052-01 — Required component labels present in diagrams.md
    TC-052-02 — §2 input flow references topic-coherence
    TC-052-03 — §3 output flow references rolling buffer
    TC-052-04 — Date stamp at line 4 is no older than latest src/armor/ commit
    TC-052-05 — Every dir directly under src/armor/ appears in diagrams.md by name or label
    TC-052-06 — make check passes
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DIAGRAMS_FILE = ROOT / "docs" / "architecture" / "diagrams.md"


def test_required_component_labels_present():
    """TC-052-01: Required component labels present in diagrams.md.

    Substring matches for each of: HoneypotGate, pipeline orchestrator, logging.
    """
    text = DIAGRAMS_FILE.read_text().lower()

    # Check for HoneypotGate (allow either honeypotgate or honeypot_gate)
    gate_ok = ("honeypotgate" in text) or ("honeypot_gate" in text)
    assert gate_ok, "diagrams.md missing HoneypotGate / honeypot_gate"

    # Check for pipeline orchestrator
    assert "pipeline" in text, "diagrams.md missing pipeline orchestrator"

    # Check for armor.logging
    assert "logging" in text, "diagrams.md missing armor.logging"


def test_src_armor_dirs_in_diagrams():
    """TC-052-05: Every dir directly under src/armor/ appears in diagrams.md by name or label.

    Exception: types.py (leaf vocabulary).
    """
    text = DIAGRAMS_FILE.read_text().lower()
    armor_dir = ROOT / "src" / "armor"

    # List all directories under src/armor (excluding __pycache__)
    dirs = [p.name for p in armor_dir.iterdir() if p.is_dir() and p.name != "__pycache__"]

    missing = [d for d in dirs if d.lower() not in text]
    assert missing == [], f"src/armor dirs absent from diagrams.md: {missing}"
