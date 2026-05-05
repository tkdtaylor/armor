"""Parametrized tests over the evaluation corpus.

This test suite loads all corpus YAML files and runs each row through
the pipeline, asserting that the verdict matches the expected value.
"""

# Load corpus directly with absolute import
import importlib.util
from pathlib import Path

import pytest

from armor.detectors import DetectorRegistry
from armor.pipeline import Pipeline
from armor.types import Payload, SessionContext

_loader_path = Path(__file__).parent / "corpus" / "_loader.py"
spec = importlib.util.spec_from_file_location("corpus_loader", _loader_path)
assert spec is not None and spec.loader is not None
corpus_loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus_loader)
load_corpus = corpus_loader.load_corpus

# Load registry and corpus at collection time
registry = DetectorRegistry()
detectors = registry.all()
corpus = load_corpus()


@pytest.mark.skipif(
    not corpus,
    reason="No corpus rows loaded",
)
@pytest.mark.asyncio
@pytest.mark.parametrize("row", corpus, ids=lambda r: r.id)
async def test_corpus_verdict(row: "corpus_loader.CorpusRow") -> None:
    """Run each corpus row through the pipeline and assert verdict matches.

    Args:
        row: A corpus row from the parametrize.
    """
    # Build payload
    payload = Payload(text=row.input)

    # Build session context
    ctx = SessionContext(session_id="test", signal_history=[])

    # Run pipeline
    verdict = await Pipeline.run(detectors, payload, ctx)

    # Assert verdict decision matches expected
    assert verdict.decision == row.expected_verdict, (
        f"Corpus {row.id}: expected verdict {row.expected_verdict}, got {verdict.decision}"
    )

    # If signal ID is expected, assert it matches
    if row.expected_signal_id is not None:
        assert verdict.signal_id == row.expected_signal_id, (
            f"Corpus {row.id}: expected signal {row.expected_signal_id}, got {verdict.signal_id}"
        )
