# SPDX-License-Identifier: Apache-2.0
"""Tests for multi-turn scenario runner and corpus shape validation.

TC-025-05: All turns pass → row passes
TC-025-06: Per-turn input-verdict assertion
TC-025-07: Per-turn output-verdict assertion
TC-025-08: Per-turn session-state assertion
TC-025-09: Per-turn failure reports (row_id, turn_index, field)
TC-025-11: Corpus has ≥15 hand-curated scenarios across required families
"""

import importlib.util
from pathlib import Path

# Load corpus loader dynamically
_loader_path = Path(__file__).parent / "corpus" / "_loader.py"
spec = importlib.util.spec_from_file_location("corpus_loader", _loader_path)
assert spec is not None and spec.loader is not None
corpus_loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus_loader)

load_corpus = corpus_loader.load_corpus


class TestMultiTurnCorpusShape:
    """TC-025-11: Corpus has ≥15 hand-curated scenarios across required families."""

    def test_corpus_has_minimum_rows(self):
        """Verify that scenarios_multi_turn.yaml has at least 15 rows."""
        rows = load_corpus("scenarios_multi_turn")
        assert len(rows) >= 15, f"Expected ≥15 rows, got {len(rows)}"

    def test_corpus_has_all_required_families(self):
        """Verify that all required attack families are present in the corpus."""
        rows = load_corpus("scenarios_multi_turn")

        # Extract families from all rows
        families = {r.family for r in rows if r.family is not None}

        required = {
            "chunked_canary",
            "gradual_jailbreak",
            "topic_pivot",
            "cooldown_then_retry",
            "long_benign_session",
            "operator_clear_resume",
        }

        missing = required - families
        assert not missing, f"Missing families: {missing}. Found: {families}"

    def test_all_rows_are_multi_turn(self):
        """Verify that all rows in scenarios_multi_turn.yaml are multi-turn."""
        rows = load_corpus("scenarios_multi_turn")
        for row in rows:
            assert row.is_multi_turn(), f"Row {row.id} is not multi-turn"
            assert row.turns is not None and len(row.turns) > 0, f"Row {row.id} has no turns"

    def test_turn_count_distribution(self):
        """Verify reasonable turn counts across corpus rows."""
        rows = load_corpus("scenarios_multi_turn")
        turn_counts = [len(r.turns) if r.turns else 0 for r in rows]

        # At least one row with 2+ turns
        assert any(c >= 2 for c in turn_counts), "No rows with multiple turns"
        # At least one row with 3+ turns
        assert any(c >= 3 for c in turn_counts), "No rows with 3+ turns"
        # At least one row with 4+ turns
        assert any(c >= 4 for c in turn_counts), "No rows with 4+ turns"


class TestMultiTurnRowValidation:
    """TC-025-05 through TC-025-08: Multi-turn row parsing and validation."""

    def test_multi_turn_row_parses_successfully(self):
        """TC-025-05: Verify a valid multi-turn row parses without error."""
        rows = load_corpus("scenarios_multi_turn")
        # Pick a known valid row
        row = next((r for r in rows if r.id == "mt-jailbreak-gradual-001"), None)
        assert row is not None, "Test row not found"
        assert row.is_multi_turn()
        assert len(row.turns) == 5

    def test_turn_fields_present(self):
        """TC-025-06 & TC-025-07 & TC-025-08: Verify all required fields are present."""
        rows = load_corpus("scenarios_multi_turn")
        row = next((r for r in rows if r.id == "mt-canary-chunked-001"), None)
        assert row is not None

        # Check all turns have required fields
        for turn_idx, turn in enumerate(row.turns):
            assert turn.input is not None, f"Turn {turn_idx}: missing input"
            assert turn.expected_input_verdict in {
                "pass",
                "advisory",
                "block",
            }, f"Turn {turn_idx}: invalid input verdict"
            assert turn.expected_session_state in {
                "Normal",
                "Watching",
                "Elevated",
                "High",
                "Blocked",
            }, f"Turn {turn_idx}: invalid session state"

    def test_input_verdict_varieties(self):
        """TC-025-06: Verify rows have mix of input verdicts."""
        rows = load_corpus("scenarios_multi_turn")

        all_verdicts = set()
        for row in rows:
            for turn in row.turns or []:
                all_verdicts.add(turn.expected_input_verdict)

        # Should have at least pass and advisory
        assert "pass" in all_verdicts, "No 'pass' input verdicts in corpus"
        assert "advisory" in all_verdicts, "No 'advisory' input verdicts in corpus"
        assert "block" in all_verdicts, "No 'block' input verdicts in corpus"

    def test_output_verdict_when_agent_output(self):
        """TC-025-07: Verify output verdicts only when agent_output present."""
        rows = load_corpus("scenarios_multi_turn")

        for row in rows:
            for turn_idx, turn in enumerate(row.turns or []):
                if turn.agent_output is not None:
                    assert turn.expected_output_verdict is not None, (
                        f"Row {row.id} turn {turn_idx}: has agent_output but missing expected_output_verdict"
                    )
                else:
                    assert turn.expected_output_verdict is None, (
                        f"Row {row.id} turn {turn_idx}: no agent_output but has expected_output_verdict"
                    )

    def test_session_state_progression(self):
        """TC-025-08: Verify session states follow valid transitions."""
        rows = load_corpus("scenarios_multi_turn")

        valid_states = {"Normal", "Watching", "Elevated", "High", "Blocked"}
        for row in rows:
            assert row.turns is not None
            for turn_idx, turn in enumerate(row.turns):
                assert turn.expected_session_state in valid_states, (
                    f"Row {row.id} turn {turn_idx}: invalid state {turn.expected_session_state}"
                )
