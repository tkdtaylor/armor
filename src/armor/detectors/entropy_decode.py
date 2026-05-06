"""Entropy-gated opportunistic decode-and-rescan detector.

Detects encoded canary leakage in output by:
1. Computing Shannon entropy on substrings of length >= min_length
2. For high-entropy substrings (>= threshold), attempting single-pass decode
3. Re-scanning decoded plaintext with the existing canary scanner

This catches the case where a successful injection makes the model emit a canary
in base64/hex encoding, evading the raw-text canary scanner.

Single-pass decode only (not recursive). Time-budgeted per pipeline config.
"""

import base64
import binascii
import logging
import math
import tempfile
import time
from functools import lru_cache
from pathlib import Path

from armor.canaries._generate import write_values_file
from armor.canaries.catalogue import Catalogue
from armor.canaries.scanner import CanaryScanner
from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits per character) for a string.

    Args:
        text: Input string.

    Returns:
        Shannon entropy in bits per character. For a uniform distribution
        of N characters, returns log2(N). For English text, typically 4.0-4.3.
    """
    if not text:
        return 0.0

    # Count character frequencies
    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    # Compute entropy: sum(-p_i * log2(p_i)) for each character
    entropy = 0.0
    length = float(len(text))
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def _try_decode_base64(text: str) -> str | None:
    """Attempt to decode text as base64.

    Args:
        text: Candidate base64-encoded string (may include padding).

    Returns:
        Decoded plaintext if successful and plausible, None otherwise.
        Plausible means: decoded bytes can be decoded as UTF-8 and contain
        at least 50% printable ASCII or common whitespace characters.
    """
    try:
        # Remove whitespace (RFC 4648 allows whitespace to be ignored)
        clean = text.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")

        # Attempt decode
        decoded_bytes = base64.b64decode(clean, validate=True)

        # Try to interpret as UTF-8
        try:
            decoded_str = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None

        # Heuristic: at least 50% of characters should be printable
        printable_count = sum(1 for c in decoded_str if c.isprintable() or c in ("\n", "\r", "\t"))
        if printable_count / len(decoded_str) < 0.5:
            return None

        return decoded_str

    except (binascii.Error, ValueError, TypeError):
        return None


def _try_decode_hex(text: str) -> str | None:
    """Attempt to decode text as hex.

    Args:
        text: Candidate hex-encoded string (even number of hex digits).

    Returns:
        Decoded plaintext if successful and plausible, None otherwise.
    """
    try:
        # Remove whitespace
        clean = text.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")

        # Hex requires even length
        if len(clean) % 2 != 0:
            return None

        # Attempt decode
        decoded_bytes = bytes.fromhex(clean)

        # Try to interpret as UTF-8
        try:
            decoded_str = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None

        # Heuristic: at least 50% printable
        printable_count = sum(1 for c in decoded_str if c.isprintable() or c in ("\n", "\r", "\t"))
        if printable_count / len(decoded_str) < 0.5:
            return None

        return decoded_str

    except (ValueError, TypeError):
        return None


@lru_cache(maxsize=1)
def _default_scanner() -> CanaryScanner:
    """Build a scanner from the bundled default catalogue.

    Cached so the AC automaton is built only once per process. The daemon
    overrides this by injecting its own scanner constructed from the operator's
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
        return CanaryScanner(canary_map)
    finally:
        # Clean up temp file
        if temp_values_path.exists():
            temp_values_path.unlink()


class EntropyDecodeDetector:
    """Detector that catches encoded canary exfiltration.

    Algorithm:
    1. For each substring of length >= min_length, compute Shannon entropy
    2. If entropy >= threshold, attempt single-pass decode (base64, then hex)
    3. Re-scan decoded plaintext with the existing canary scanner
    4. On canary hit: return block with signal_id = entropy.decode_rescan:<canary_id>

    Attributes:
        id: "entropy.decode_rescan"
        category: "exfiltration"
        cost_tier: "static" (no LLM involvement)

    Config parameters (from armor.toml):
        entropy.min_length: Minimum substring length to entropy-check (default 40)
        entropy.threshold: Entropy bits/char threshold (default 4.5)
        pipeline.per_detector_budget_ms: Latency budget in milliseconds (default 100)
    """

    id = "entropy.decode_rescan"
    category = "exfiltration"
    cost_tier = "static"

    # Default config values (can be overridden by daemon)
    DEFAULT_MIN_LENGTH = 40
    DEFAULT_THRESHOLD = 4.5

    def __init__(
        self,
        scanner: CanaryScanner | None = None,
        min_length: int = DEFAULT_MIN_LENGTH,
        threshold: float = DEFAULT_THRESHOLD,
        budget_ms: float = 100.0,
    ) -> None:
        """Initialize the detector.

        Args:
            scanner: CanaryScanner instance. If None, lazy-loads from bundled catalogue.
                     The daemon injects its own scanner built from the operator-configured catalogue.
            min_length: Minimum substring length to entropy-check.
            threshold: Entropy bits/char threshold for flagging substrings.
            budget_ms: Latency budget in milliseconds. If decode+scan would exceed this,
                       return error verdict (fail-open per detector).
        """
        self.scanner = scanner if scanner is not None else _default_scanner()
        self.min_length = min_length
        self.threshold = threshold
        self.budget_ms = budget_ms

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for encoded canary exfiltration.

        Args:
            payload: The payload to check (text).
            ctx: Session context.

        Returns:
            Verdict.block() on canary hit in decoded plaintext.
            Verdict.pass() if no high-entropy substrings or decode yields no hits.
            Verdict.error() if decode+scan would exceed latency budget.
        """
        start_time = time.time()

        try:
            text = payload.text or ""

            # Early exit: empty or very short text
            if len(text) < self.min_length:
                return Verdict.pass_verdict()

            # Strategy: find contiguous high-entropy "blocks" and try to decode each one.
            # We use a sliding window to find blocks where entropy >= threshold,
            # then extract the maximal contiguous block around each high-entropy position.
            # This avoids splitting encoded values across window boundaries.

            processed_blocks = set()  # Track blocks we've already processed (avoid duplicates)

            for i in range(len(text) - self.min_length + 1):
                # Check latency budget before processing each position
                elapsed_ms = (time.time() - start_time) * 1000
                if elapsed_ms > self.budget_ms:
                    logger.warning(f"Entropy detector latency budget exceeded: {elapsed_ms:.1f}ms > {self.budget_ms}ms")
                    return Verdict.error_verdict(reason="Entropy detector latency budget exceeded")

                substring = text[i : i + self.min_length]

                # Compute entropy of this window
                entropy = _shannon_entropy(substring)

                # Skip if below threshold
                if entropy < self.threshold:
                    continue

                # Found a high-entropy position. Extract the maximal contiguous high-entropy block.
                # Expand left and right from this position to include adjacent high-entropy characters.
                # (A high-entropy character is roughly >= threshold for individual entropy.)

                # For simplicity, we'll just try decoding progressively longer substrings
                # starting from this position, up to a reasonable limit.
                # Start with the min_length window and expand to 2x, 3x, etc.

                block_start = i
                block_end = min(i + self.min_length * 3, len(text))  # Max 3x the min length
                block_key = (block_start, block_end)

                if block_key in processed_blocks:
                    continue
                processed_blocks.add(block_key)

                # Try to decode the expanded block
                block = text[block_start:block_end]

                decoded_plaintext = None

                # Try base64 first
                decoded_plaintext = _try_decode_base64(block)

                # If base64 failed, try hex
                if decoded_plaintext is None:
                    decoded_plaintext = _try_decode_hex(block)

                # If decode succeeded, re-scan the decoded plaintext
                if decoded_plaintext is not None:
                    hits = self.scanner.scan(decoded_plaintext)
                    if hits:
                        first_hit = hits[0]
                        canary_ids = [hit.canary_id for hit in hits]

                        return Verdict.block_verdict(
                            signal_id=f"entropy.decode_rescan:{first_hit.canary_id}",
                            message="Output suppressed by armor.",
                            severity="critical",
                            details={
                                "canary_ids": canary_ids,
                                "encoding_flag": True,
                            },
                        )

            # No canary matches found after checking all high-entropy substrings
            return Verdict.pass_verdict()

        except Exception as e:
            logger.error(f"Entropy decoder error: {e}", exc_info=True)
            return Verdict.error_verdict(reason=f"Entropy decoder error: {e}")
