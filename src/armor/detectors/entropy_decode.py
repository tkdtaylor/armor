"""Entropy-gated opportunistic decode-and-rescan detector.

Detects encoded canary leakage in output by:
1. Computing Shannon entropy on substrings of length >= min_length
2. For high-entropy substrings (>= threshold), attempting bounded-depth recursive decode
3. Re-scanning decoded plaintext at each depth with the existing canary scanner

This catches multi-layer encodings like base64(hex(canary)), evading the raw-text canary scanner.

Bounded recursive decode: capped at max_decode_depth (default 3), terminating on:
- Depth cap reached
- No-progress: decoded entropy < input entropy - margin (default 0.5 bits/char)
- Per-detector latency budget consumed
- Successful canary match
"""

import base64
import binascii
import logging
import math
import tempfile
import time
import urllib.parse
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


def _try_decode_url_encode(text: str) -> str | None:
    """Attempt to decode text as URL-encoded (%XX format).

    Args:
        text: Candidate URL-encoded string.

    Returns:
        Decoded plaintext if successful and plausible, None otherwise.
        Only decodes if input contains %XX patterns.
    """
    try:
        # Only attempt if input contains %XX pattern
        if "%" not in text:
            return None

        # Attempt to decode
        decoded_str = urllib.parse.unquote(text)

        # If nothing was decoded, return None
        if decoded_str == text:
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
    """Detector that catches encoded canary exfiltration with recursive decoding.

    Algorithm:
    1. For each substring of length >= min_length, compute Shannon entropy
    2. If entropy >= threshold, attempt bounded-depth recursive decode
    3. On each decode pass: try base64 (std + URL-safe), hex, URL-encode
    4. Re-scan decoded plaintext with the existing canary scanner
    5. On canary hit: return block with signal_id = entropy.decode_rescan:<chain>:<canary_id>
       where <chain> is codec sequence (e.g., "b64.hex")

    Recursion termination conditions:
    - Depth cap reached (entropy.max_decode_depth, default 3)
    - No-progress: decoded entropy < input entropy - margin (entropy.no_progress_margin_bits, default 0.5)
    - Per-detector latency budget consumed
    - Successful canary match

    Attributes:
        id: "entropy.decode_rescan"
        category: "exfiltration"
        cost_tier: "static" (no LLM involvement)

    Config parameters (from armor.toml):
        entropy.min_length: Minimum substring length to entropy-check (default 40)
        entropy.threshold: Entropy bits/char threshold (default 4.5)
        entropy.max_decode_depth: Maximum recursion depth (default 3)
        entropy.no_progress_margin_bits: Entropy margin for no-progress termination (default 0.5)
        pipeline.per_detector_budget_ms: Latency budget in milliseconds (default 100)
    """

    id = "entropy.decode_rescan"
    category = "exfiltration"
    cost_tier = "static"

    # Default config values (can be overridden by daemon)
    DEFAULT_MIN_LENGTH = 40
    DEFAULT_THRESHOLD = 4.5
    DEFAULT_MAX_DECODE_DEPTH = 3
    DEFAULT_NO_PROGRESS_MARGIN_BITS = 0.5

    def __init__(
        self,
        scanner: CanaryScanner | None = None,
        min_length: int = DEFAULT_MIN_LENGTH,
        threshold: float = DEFAULT_THRESHOLD,
        budget_ms: float = 100.0,
        max_decode_depth: int = DEFAULT_MAX_DECODE_DEPTH,
        no_progress_margin_bits: float = DEFAULT_NO_PROGRESS_MARGIN_BITS,
    ) -> None:
        """Initialize the detector.

        Args:
            scanner: CanaryScanner instance. If None, lazy-loads from bundled catalogue.
                     The daemon injects its own scanner built from the operator-configured catalogue.
            min_length: Minimum substring length to entropy-check.
            threshold: Entropy bits/char threshold for flagging substrings.
            budget_ms: Latency budget in milliseconds. If decode+scan would exceed this,
                       return error verdict (fail-open per detector).
            max_decode_depth: Maximum recursion depth for decoding (default 3).
            no_progress_margin_bits: Entropy margin below which to stop recursing (default 0.5).
        """
        self.scanner = scanner if scanner is not None else _default_scanner()
        self.min_length = min_length
        self.threshold = threshold
        self.budget_ms = budget_ms
        self.max_decode_depth = max_decode_depth
        self.no_progress_margin_bits = no_progress_margin_bits

    def _try_decode_single_pass(self, text: str) -> tuple[str, str] | tuple[None, None]:
        """Attempt to decode text using available codecs.

        Args:
            text: Candidate encoded string.

        Returns:
            Tuple of (decoded_plaintext, codec_name) if successful, (None, None) otherwise.
            Tries base64 (std + URL-safe), hex, then URL-encode in order.
        """
        # Try base64 standard alphabet
        decoded = _try_decode_base64(text)
        if decoded is not None:
            return decoded, "b64"

        # Try hex
        decoded = _try_decode_hex(text)
        if decoded is not None:
            return decoded, "hex"

        # Try URL-encode (only if % patterns present)
        decoded = _try_decode_url_encode(text)
        if decoded is not None:
            return decoded, "url"

        return None, None

    def _recursive_decode(
        self,
        text: str,
        depth: int,
        start_time: float,
        codec_chain: list[str],
    ) -> tuple[str | None, list[str]]:
        """Recursively attempt to decode and rescan for canaries.

        Args:
            text: Current plaintext to decode.
            depth: Current recursion depth (0 = first pass, 1 = second, etc.).
            start_time: Wall-clock start time for budget tracking.
            codec_chain: List of codec names applied so far (e.g., ["b64", "hex"]).

        Returns:
            Tuple of (terminal_canary_id, final_codec_chain) on canary hit,
            or (None, updated_codec_chain) if no hit and recursion terminated.
        """
        # Check latency budget
        elapsed_ms = (time.time() - start_time) * 1000
        if elapsed_ms > self.budget_ms:
            logger.debug(f"Entropy detector budget exceeded at depth {depth}: {elapsed_ms:.1f}ms")
            return None, codec_chain

        # Check depth cap
        if depth >= self.max_decode_depth:
            return None, codec_chain

        # Compute entropy of current text
        current_entropy = _shannon_entropy(text)

        # Attempt to decode
        decoded_result, codec_result = self._try_decode_single_pass(text)

        if decoded_result is None or codec_result is None:
            # Decode failed; stop recursion
            return None, codec_chain

        # Record the codec used
        new_chain = [*codec_chain, codec_result]
        decoded_plaintext = decoded_result

        # Immediately rescan the decoded plaintext for canaries
        hits = self.scanner.scan(decoded_plaintext)
        if hits:
            first_hit = hits[0]
            # Canary found at this depth; return immediately
            return first_hit.canary_id, new_chain

        # No hit at this level; check for no-progress before recursing deeper
        decoded_entropy = _shannon_entropy(decoded_plaintext)
        entropy_reduction = current_entropy - decoded_entropy

        # No-progress: entropy decreases but by less than the margin.
        # This catches self-referential encodings, fixed points, and garbage.
        # But if entropy increases or decreases significantly, that's good progress.
        if 0 < entropy_reduction < self.no_progress_margin_bits:
            # Small entropy reduction: looks like we're hitting a fixed point or noise.
            # Stop recursion without recursing deeper.
            logger.debug(
                f"No-progress termination at depth {depth}: "
                f"entropy {current_entropy:.2f} → {decoded_entropy:.2f} (reduction {entropy_reduction:.2f})"
            )
            return None, new_chain

        # Good progress (either entropy increased, or decreased significantly); recurse deeper
        result_canary, result_chain = self._recursive_decode(
            decoded_plaintext,
            depth + 1,
            start_time,
            new_chain,
        )
        return result_canary, result_chain

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for encoded canary exfiltration (recursive).

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

                # Found a high-entropy position. Extract the block.
                block_start = i
                block_end = min(i + self.min_length * 3, len(text))  # Max 3x the min length
                block_key = (block_start, block_end)

                if block_key in processed_blocks:
                    continue
                processed_blocks.add(block_key)

                # Try to decode the block recursively
                block = text[block_start:block_end]

                canary_id, codec_chain = self._recursive_decode(
                    block,
                    depth=0,
                    start_time=start_time,
                    codec_chain=[],
                )

                if canary_id is not None:
                    # Canary found; build the signal_id with codec chain
                    chain_str = ".".join(codec_chain)
                    signal_id = f"entropy.decode_rescan:{chain_str}:{canary_id}"

                    return Verdict.block_verdict(
                        signal_id=signal_id,
                        message="Output suppressed by armor.",
                        severity="critical",
                        details={
                            "canary_ids": [canary_id],
                            "encoding_flag": True,
                            "decode_chain": codec_chain,
                            "decode_depth": len(codec_chain),
                        },
                    )

            # No canary matches found after checking all high-entropy substrings
            return Verdict.pass_verdict()

        except Exception as e:
            logger.error(f"Entropy decoder error: {e}", exc_info=True)
            return Verdict.error_verdict(reason=f"Entropy decoder error: {e}")
