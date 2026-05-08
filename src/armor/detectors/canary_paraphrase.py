"""Paraphrase n-gram detector — detects fragmented canary leaks via sub-prefix n-gram matching.

This detector operates on the rolling buffer (per ADR-025) and scans for paraphrased or
fragmented canary leaks. It builds an Aho-Corasick automaton of all n-grams of length
[ngram_min, ngram_max] from each canary value. When >= K distinct n-grams of the same
canary appear in the rolling buffer, it fires an advisory signal.

Approach A (deterministic, fast, no model dependency) from ADR-034.
"""

import logging
import tempfile
from functools import lru_cache
from pathlib import Path

import ahocorasick

from armor.canaries._generate import write_values_file
from armor.canaries.catalogue import Catalogue
from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)


def _build_ngram_automaton(
    canary_map: dict[str, str],
    ngram_min: int = 6,
    ngram_max: int = 11,
) -> tuple[ahocorasick.Automaton, dict[str, int]]:
    """Build an Aho-Corasick automaton of n-grams from canary values.

    For each canary, generates all contiguous n-grams of length [ngram_min, ngram_max].
    Each n-gram is added to the automaton with (canary_id, ngram_hash) as the payload.

    Args:
        canary_map: Dictionary mapping canary_id -> canary_value.
        ngram_min: Minimum n-gram length (default 6).
        ngram_max: Maximum n-gram length (default 11).

    Returns:
        A tuple of (automaton, ngram_lengths) where:
        - automaton: pyahocorasick Automaton with n-grams as keys
        - ngram_lengths: dict mapping each n-gram string to its length
    """
    automaton = ahocorasick.Automaton()
    ngram_lengths: dict[str, int] = {}

    for canary_id, value in canary_map.items():
        # Generate all n-grams of length [ngram_min, ngram_max]
        for ngram_len in range(ngram_min, min(ngram_max + 1, len(value) + 1)):
            for i in range(len(value) - ngram_len + 1):
                ngram = value[i : i + ngram_len]
                # Use tuple (canary_id, ngram) as payload to track which n-gram matched
                # We store the actual n-gram to identify distinct n-grams per canary
                payload = (canary_id, ngram)
                automaton.add_word(ngram, payload)
                ngram_lengths[ngram] = ngram_len

    automaton.make_automaton()
    return automaton, ngram_lengths


@lru_cache(maxsize=1)
def _default_automaton() -> tuple[ahocorasick.Automaton, dict[str, int]]:
    """Build an automaton from the bundled default catalogue.

    Cached so the automaton is built only once per process. The daemon
    overrides this by injecting its own automaton constructed from the operator's
    configured catalogue.

    For v0.2+, the bundled catalogue contains only schema (no values).
    This function generates ephemeral values with a fixed seed for reproducibility.
    """
    schema_path = Path(__file__).parent.parent / "canaries" / "default_catalogue.json"

    # Generate values in a temp file with a fixed seed for reproducibility
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        temp_values_path = Path(tf.name)

    try:
        write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
        # Load with the generated values
        catalogue = Catalogue.load(temp_values_path)
        canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
        return _build_ngram_automaton(canary_map)
    finally:
        # Clean up temp file
        if temp_values_path.exists():
            temp_values_path.unlink()


class CanaryParaphraseDetector:
    """Detector that scans rolling buffer for paraphrased canary leaks via n-gram matching.

    Attributes:
        id: "canary.paraphrase"
        category: "exfiltration.canary_paraphrase"
        cost_tier: "static" (no LLM involvement)
    """

    id = "canary.paraphrase"
    category = "exfiltration.canary_paraphrase"
    cost_tier = "static"

    def __init__(
        self,
        automaton: ahocorasick.Automaton | None = None,
        ngram_lengths: dict[str, int] | None = None,
        ngram_min: int = 6,
        ngram_max: int = 11,
        k_threshold: int = 3,
    ) -> None:
        """Initialize the detector with an n-gram automaton.

        Args:
            automaton: Aho-Corasick Automaton for n-gram matching. If None, lazy-loads
                from the bundled default catalogue.
            ngram_lengths: Dictionary mapping n-grams to their lengths (for internal tracking).
            ngram_min: Minimum n-gram length (default 6).
            ngram_max: Maximum n-gram length (default 11).
            k_threshold: Number of distinct n-grams needed to fire advisory (default 3).
        """
        if automaton is None:
            automaton, ngram_lengths = _default_automaton()

        self.automaton = automaton
        self.ngram_lengths = ngram_lengths or {}
        self.ngram_min = ngram_min
        self.ngram_max = ngram_max
        self.k_threshold = k_threshold

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check rolling buffer for n-gram fragments of canary values.

        Args:
            payload: The payload to check (unused; we scan the rolling buffer).
            ctx: Session context with rolling_buffer.

        Returns:
            Verdict.advisory() if >= k_threshold distinct n-grams of a canary are found,
            Verdict.pass() otherwise.
        """
        try:
            # Get the rolling buffer from context
            if not hasattr(ctx, "rolling_buffer") or ctx.rolling_buffer is None:
                return Verdict.pass_verdict()

            # Concatenate the rolling buffer
            buffer_text = ctx.rolling_buffer.concatenated()
            if not buffer_text:
                return Verdict.pass_verdict()

            # Scan the buffer for n-gram matches
            # Track distinct n-grams per canary_id
            distinct_ngrams_per_canary: dict[str, set[str]] = {}

            for _end_index, payload_tuple in self.automaton.iter(buffer_text):
                # payload is (canary_id, ngram)
                if isinstance(payload_tuple, tuple) and len(payload_tuple) == 2:
                    canary_id, ngram = payload_tuple
                    if canary_id not in distinct_ngrams_per_canary:
                        distinct_ngrams_per_canary[canary_id] = set()
                    # Track the distinct n-gram (we never expose it in forensics)
                    distinct_ngrams_per_canary[canary_id].add(ngram)

            # Check if any canary has >= k_threshold distinct n-grams
            for canary_id, distinct_ngrams in distinct_ngrams_per_canary.items():
                k_observed = len(distinct_ngrams)
                if k_observed >= self.k_threshold:
                    # Calculate confidence: min(1.0, K_observed / K_threshold * 0.5)
                    confidence = min(1.0, (k_observed / self.k_threshold) * 0.5)

                    return Verdict.advisory_verdict(
                        signal_id=f"canary.paraphrase:{canary_id}:ngram",
                        severity="high",
                        message=f"Potential paraphrased canary leak detected (n-grams: {k_observed})",
                        details={
                            "canary_id": canary_id,
                            "ngram_count": k_observed,
                            "k_threshold": self.k_threshold,
                            "confidence": confidence,
                        },
                    )

            return Verdict.pass_verdict()

        except Exception as e:
            logger.error(f"Paraphrase detector error: {e}", exc_info=True)
            return Verdict.error_verdict(reason=f"Paraphrase detector error: {e}")
