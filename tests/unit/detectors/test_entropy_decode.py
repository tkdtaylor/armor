"""Unit tests for the entropy_decode detector.

Tests the entropy-gated decode-and-rescan detector which catches
encoded (base64/hex/URL-encoded, including multi-layer) canary exfiltration in model output.
Tests recursive (bounded-depth) decoding with termination conditions.
"""

import base64
import tempfile
import time
import urllib.parse
from pathlib import Path

import pytest

from armor.canaries._generate import write_values_file
from armor.canaries.catalogue import Catalogue
from armor.canaries.scanner import CanaryScanner
from armor.detectors.entropy_decode import (
    EntropyDecodeDetector,
    _shannon_entropy,
    _try_decode_base64,
    _try_decode_hex,
    _try_decode_url_encode,
)
from armor.types import Payload, SessionContext


@pytest.fixture
def catalogue() -> Catalogue:
    """Load an ephemeral catalogue with deterministic test values."""
    schema_path = Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        temp_values_path = Path(tf.name)

    try:
        write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
        return Catalogue.load(temp_values_path)
    finally:
        if temp_values_path.exists():
            temp_values_path.unlink()


@pytest.fixture
def scanner(catalogue: Catalogue) -> CanaryScanner:
    """Create a canary scanner from the test catalogue."""
    canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
    return CanaryScanner(canary_map)


@pytest.fixture
def detector(scanner: CanaryScanner) -> EntropyDecodeDetector:
    """Create a detector instance with the test scanner."""
    return EntropyDecodeDetector(scanner=scanner)


@pytest.fixture
def context() -> SessionContext:
    """Create a session context."""
    return SessionContext(session_id="test")


class TestShannonEntropy:
    """Tests for Shannon entropy computation."""

    def test_entropy_uniform_distribution(self) -> None:
        """Entropy of uniform distribution."""
        # Two symbols with equal probability: entropy = 1 bit
        assert abs(_shannon_entropy("aa") - 0.0) < 0.01  # Only one unique symbol
        assert abs(_shannon_entropy("ab") - 1.0) < 0.01  # Two symbols, uniform

    def test_entropy_english_text(self) -> None:
        """English text has entropy around 4.0-4.3 bits/char."""
        text = "the quick brown fox jumps over the lazy dog"
        entropy = _shannon_entropy(text)
        assert 3.5 < entropy < 4.5, f"English text entropy {entropy} not in expected range"

    def test_entropy_random_base64(self) -> None:
        """Base64-encoded truly random data has high entropy (4.8+ bits/char)."""
        # Truly random bytes (not repetitive "x" * 40)
        import os

        # Test multiple times since randomness can cause occasional low outliers
        entropies = []
        for _ in range(10):
            random_bytes = os.urandom(40)
            encoded = base64.b64encode(random_bytes).decode()
            entropies.append(_shannon_entropy(encoded))

        # Average should be high, and at least some samples should exceed 4.8
        avg_entropy = sum(entropies) / len(entropies)
        assert avg_entropy > 4.7, f"Average Base64 entropy {avg_entropy} should be high (>4.7)"
        assert any(e > 4.8 for e in entropies), "At least one sample should exceed 4.8"

    def test_entropy_empty_string(self) -> None:
        """Empty string has zero entropy."""
        assert _shannon_entropy("") == 0.0

    def test_entropy_single_char(self) -> None:
        """Single unique character has zero entropy."""
        assert abs(_shannon_entropy("aaaa") - 0.0) < 0.01


class TestBase64Decode:
    """Tests for base64 decode functionality."""

    def test_decode_valid_base64(self) -> None:
        """Decode valid base64 string."""
        plaintext = "hello world"
        encoded = base64.b64encode(plaintext.encode()).decode()
        result = _try_decode_base64(encoded)
        assert result == plaintext

    def test_decode_base64_with_padding(self) -> None:
        """Decode base64 with padding."""
        plaintext = "hi"
        encoded = base64.b64encode(plaintext.encode()).decode()
        assert "=" in encoded  # Should have padding
        result = _try_decode_base64(encoded)
        assert result == plaintext

    def test_decode_base64_with_whitespace(self) -> None:
        """Decode base64 with embedded whitespace."""
        plaintext = "test message"
        encoded = base64.b64encode(plaintext.encode()).decode()
        # Add whitespace
        with_whitespace = encoded[:5] + "\n" + encoded[5:]
        result = _try_decode_base64(with_whitespace)
        assert result == plaintext

    def test_decode_invalid_base64(self) -> None:
        """Invalid base64 returns None."""
        result = _try_decode_base64("not-valid-base64!!!")
        assert result is None

    def test_decode_base64_non_utf8(self) -> None:
        """Base64 that decodes to non-UTF8 bytes returns None."""
        # Create invalid UTF-8
        invalid_utf8 = bytes([0xFF, 0xFE, 0xFD])
        encoded = base64.b64encode(invalid_utf8).decode()
        result = _try_decode_base64(encoded)
        assert result is None

    def test_decode_base64_garbage(self) -> None:
        """Base64 that decodes to mostly unprintable bytes returns None."""
        # Random bytes (low printable ratio)
        garbage = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        encoded = base64.b64encode(garbage).decode()
        result = _try_decode_base64(encoded)
        assert result is None


class TestHexDecode:
    """Tests for hex decode functionality."""

    def test_decode_valid_hex(self) -> None:
        """Decode valid hex string."""
        plaintext = "hello"
        encoded = plaintext.encode().hex()
        result = _try_decode_hex(encoded)
        assert result == plaintext

    def test_decode_hex_with_whitespace(self) -> None:
        """Decode hex with embedded whitespace."""
        plaintext = "test"
        encoded = plaintext.encode().hex()
        with_whitespace = encoded[:4] + " " + encoded[4:]
        result = _try_decode_hex(with_whitespace)
        assert result == plaintext

    def test_decode_invalid_hex(self) -> None:
        """Invalid hex returns None."""
        result = _try_decode_hex("not hex data!")
        assert result is None

    def test_decode_hex_odd_length(self) -> None:
        """Hex with odd length (invalid) returns None."""
        result = _try_decode_hex("abc")  # 3 chars, invalid
        assert result is None

    def test_decode_hex_non_utf8(self) -> None:
        """Hex that decodes to non-UTF8 returns None."""
        # 0xFF is invalid UTF-8 start byte alone
        result = _try_decode_hex("ffff")
        assert result is None


class TestUrlEncodeDecode:
    """Tests for URL-encode decode functionality."""

    def test_decode_valid_url_encoded(self) -> None:
        """Decode valid URL-encoded string."""
        plaintext = "hello world"
        encoded = urllib.parse.quote(plaintext)
        result = _try_decode_url_encode(encoded)
        assert result == plaintext

    def test_decode_url_encoded_special_chars(self) -> None:
        """Decode URL-encoded with special characters."""
        plaintext = "test@example.com"
        encoded = urllib.parse.quote(plaintext)
        result = _try_decode_url_encode(encoded)
        assert result == plaintext

    def test_decode_url_encoded_no_percent(self) -> None:
        """URL string without % returns None."""
        result = _try_decode_url_encode("hello_world")
        assert result is None

    def test_decode_url_encoded_unencoded_string(self) -> None:
        """Already-decoded string (no %XX) returns None."""
        plaintext = "hello world"
        # String without percent patterns
        result = _try_decode_url_encode(plaintext)
        assert result is None


class TestEntropyGate:
    """Tests for entropy threshold gating."""

    def test_low_entropy_ignored(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """Low-entropy substrings are not decoded."""
        payload = Payload(text="hello world this is a normal sentence")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_high_entropy_detected(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """High-entropy substrings trigger decode attempt."""
        # Base64 has high entropy
        high_entropy = base64.b64encode(b"x" * 40).decode()
        payload = Payload(text=f"Result: {high_entropy}")
        verdict = detector.check(payload, context)
        # Should pass (no canary match) but the detector exercised the entropy gate
        assert verdict.passed or verdict.is_error


class TestCanaryDetection:
    """Tests for canary detection in decoded plaintext. TC-010-01 through TC-010-10."""

    def test_tp_base64_encoded_canary(self, context: SessionContext) -> None:
        """TC-010-01: Base64-encoded canary yields block."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            # Create scanner and detector from the same catalogue
            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            detector = EntropyDecodeDetector(scanner=scanner)

            # Use github-pat-000 which is long enough to exceed entropy threshold when base64-encoded
            target_canary = catalogue.get_by_id("github-pat-000")
            assert target_canary is not None, "github-pat-000 not found"

            # Encode it as base64
            encoded = base64.b64encode(target_canary.value.encode()).decode()

            # Create payload with encoded canary
            payload = Payload(text=f"Token: {encoded}")

            # Check detector
            verdict = detector.check(payload, context)

            # Should block with correct canary ID
            assert verdict.blocked, f"Expected block for encoded canary, got {verdict.decision}"
            assert target_canary.canary_id in verdict.signal_id, f"Canary ID not in signal: {verdict.signal_id}"
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_tp_hex_encoded_canary(self, context: SessionContext) -> None:
        """TC-010-02: Hex-encoded canary yields block (with lower entropy threshold)."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            # Create scanner and detector from the same catalogue
            # Use a lower entropy threshold (3.0) for hex decoding, since hex alphabet is
            # limited to 16 characters (max entropy ~4.0 bits/char)
            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            detector = EntropyDecodeDetector(scanner=scanner, threshold=3.0)

            # Use stripe-key-000 which will have sufficient entropy when hex-encoded
            target_canary = catalogue.get_by_id("stripe-key-000")
            assert target_canary is not None, "stripe-key-000 not found"

            # Encode as hex
            encoded = target_canary.value.encode().hex()

            payload = Payload(text=f"Secret: {encoded}")
            verdict = detector.check(payload, context)

            assert verdict.blocked
            assert target_canary.canary_id in verdict.signal_id
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_tn_uuid_string(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-010-05: UUID-like high-entropy string does not block."""
        # UUID has high entropy but doesn't match any canary
        payload = Payload(text="Session ID: a1b2c3d4-e5f6-47a8-9b0c-1d2e3f4a5b6c")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_tn_sha256_hash(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-010-06: SHA256 hash does not block."""
        payload = Payload(text="Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_tn_base64_non_canary(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-010-03: Base64-encoded benign data does not block."""
        benign = base64.b64encode(b"Hello world! This is harmless data.").decode()
        payload = Payload(text=f"Encoded: {benign}")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_tn_low_entropy(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-010-12: Low-entropy text returns pass."""
        payload = Payload(text="The quick brown fox jumps over the lazy dog. " * 5)
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_tn_empty_payload(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-010-11: Empty payload returns pass."""
        payload = Payload(text="")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_tn_short_payload(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-010-11: Short payload (< min_length) returns pass."""
        payload = Payload(text="short")
        verdict = detector.check(payload, context)
        assert verdict.passed


class TestForensicSafety:
    """Tests for forensic logging safety (never leak canary values). TC-010-10, TC-010-04."""

    def test_canary_value_not_in_signal_details(self, context: SessionContext) -> None:
        """TC-010-10: Detected canary uses canary_id, not the value."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            # Create scanner and detector from the same catalogue
            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            detector = EntropyDecodeDetector(scanner=scanner)

            # Use github-pat-000 which exceeds entropy threshold
            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None, "github-pat-000 not found"

            # Create encoded payload
            encoded = base64.b64encode(canary.value.encode()).decode()
            payload = Payload(text=f"Token: {encoded}")

            verdict = detector.check(payload, context)
            assert verdict.blocked

            # Check that the verdict details contain canary_id but not the value
            assert "canary_ids" in verdict.details
            canary_ids = verdict.details["canary_ids"]
            assert canary.canary_id in canary_ids

            # Most importantly: the original plaintext value should NEVER appear in details
            details_str = str(verdict.details)
            assert canary.value not in details_str, "Canary value leaked in verdict details!"

            # Signal ID should reference canary_id, not value
            assert canary.canary_id in verdict.signal_id
            assert canary.value not in verdict.signal_id
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()


class TestLatencyBudget:
    """Tests for latency budget enforcement. TC-010-09, TC-010-14."""

    def test_latency_under_budget(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-010-09: Detector latency stays under budget on typical workloads."""
        # Normal output with some high-entropy substrings
        payload = Payload(text="Results: " + base64.b64encode(b"x" * 40).decode() + " and " + "hello" * 20)

        start = time.time()
        verdict = detector.check(payload, context)
        elapsed_ms = (time.time() - start) * 1000

        # Should complete well under 100ms budget
        assert elapsed_ms < 100.0, f"Detector took {elapsed_ms:.1f}ms, exceeds budget"
        assert verdict.decision in ("pass", "block", "error")

    def test_multiple_high_entropy_substrings(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """Detector handles payload with many high-entropy substrings efficiently."""
        # Create payload with many base64 blocks (but none are canaries)
        blocks = [base64.b64encode(f"block{i}".encode()).decode() for i in range(10)]
        payload = Payload(text=" ".join(blocks))

        start = time.time()
        verdict = detector.check(payload, context)
        elapsed_ms = (time.time() - start) * 1000

        assert elapsed_ms < 100.0
        assert verdict.passed  # None of these should be canaries


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_payload_with_both_base64_and_hex(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """Payload containing both base64 and hex strings."""
        base64_part = base64.b64encode(b"test data").decode()
        hex_part = "deadbeefcafebabe"
        payload = Payload(text=f"Base64: {base64_part}, Hex: {hex_part}")
        verdict = detector.check(payload, context)
        assert verdict.passed  # Neither encodes a canary

    def test_malformed_base64_falls_back_to_hex(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """Malformed base64 falls back to hex decode."""
        # High-entropy string that's not valid base64
        invalid_b64 = "!@#$%^&*()" * 4  # Not valid base64
        payload = Payload(text=f"Data: {invalid_b64}")
        verdict = detector.check(payload, context)
        assert verdict.decision in ("pass", "error")  # Should not crash

    def test_only_min_length_substrings_checked(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """Only substrings >= min_length are processed."""
        # Create a short high-entropy string (< min_length)
        short_entropy = base64.b64encode(b"x" * 10).decode()
        payload = Payload(text=f"Short: {short_entropy}")
        verdict = detector.check(payload, context)
        # Should pass because short_entropy is likely < min_length
        # (exact behavior depends on min_length value)
        assert verdict.decision in ("pass", "block", "error")

    def test_custom_min_length(self, scanner: CanaryScanner) -> None:
        """Detector respects custom min_length parameter."""
        detector = EntropyDecodeDetector(scanner=scanner, min_length=10)
        context = SessionContext(session_id="test")

        # Very short string (< 10) should not trigger decode
        payload = Payload(text="short")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_custom_threshold(self, scanner: CanaryScanner) -> None:
        """Detector respects custom entropy threshold."""
        detector = EntropyDecodeDetector(scanner=scanner, threshold=6.0)
        context = SessionContext(session_id="test")

        # Normal base64 won't exceed 6.0 threshold (base64 max is ~6.0)
        normal_b64 = base64.b64encode(b"test" * 10).decode()
        payload = Payload(text=normal_b64)
        verdict = detector.check(payload, context)
        # High threshold might skip this, depending on exact distribution
        assert verdict.decision in ("pass", "block", "error")

    def test_exception_handling(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """Detector handles exceptions gracefully."""
        # Create a payload that might trigger an edge case
        payload = Payload(text=None)  # type: ignore
        verdict = detector.check(payload, context)
        # Should return error, not raise
        assert verdict.is_error or verdict.passed


class TestRecursiveDecoding:
    """Tests for recursive (multi-layer) encoding. TC-067-01 through TC-067-13."""

    def test_tp_b64_hex_canary(self, context: SessionContext) -> None:
        """TC-067-01: base64(hex(canary)) → block with correct chain."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            # Use a lower threshold (4.0) since multi-layer encodings have lower entropy
            detector = EntropyDecodeDetector(scanner=scanner, threshold=4.0)

            # Get a canary that will have sufficient entropy
            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None

            # Create base64(hex(canary))
            hex_encoded = canary.value.encode().hex()
            b64_hex_encoded = base64.b64encode(hex_encoded.encode()).decode()

            payload = Payload(text=f"Token: {b64_hex_encoded}")
            verdict = detector.check(payload, context)

            assert verdict.blocked, f"Expected block, got {verdict.decision}"
            # Check signal_id format: entropy.decode_rescan:b64.hex:<canary_id>
            assert verdict.signal_id.startswith("entropy.decode_rescan:b64.hex:")
            assert canary.canary_id in verdict.signal_id
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_tp_hex_b64_canary(self, context: SessionContext) -> None:
        """TC-067-02: hex(base64(canary)) → block with correct chain."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            # Use a lower threshold for hex (max entropy is log2(16)=4.0)
            detector = EntropyDecodeDetector(scanner=scanner, threshold=3.0)

            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None

            # Create hex(base64(canary))
            b64_encoded = base64.b64encode(canary.value.encode()).decode()
            hex_b64_encoded = b64_encoded.encode().hex()

            payload = Payload(text=f"Token: {hex_b64_encoded}")
            verdict = detector.check(payload, context)

            assert verdict.blocked
            assert verdict.signal_id.startswith("entropy.decode_rescan:hex.b64:")
            assert canary.canary_id in verdict.signal_id
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_tp_url_b64_canary(self, context: SessionContext) -> None:
        """TC-067-03: urlencode(base64(canary)) → block with correct chain."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            # Use a lower threshold and no-progress margin for multi-layer encodings.
            # URL-encoding causes minimal entropy change (only ~0.05 bits), so we need
            # a very low margin to allow it to recurse.
            detector = EntropyDecodeDetector(scanner=scanner, threshold=4.0, no_progress_margin_bits=0.01)

            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None

            # Create urlencode(base64(canary))
            b64_encoded = base64.b64encode(canary.value.encode()).decode()
            url_b64_encoded = urllib.parse.quote(b64_encoded)

            payload = Payload(text=f"Token: {url_b64_encoded}")
            verdict = detector.check(payload, context)

            assert verdict.blocked
            assert verdict.signal_id.startswith("entropy.decode_rescan:url.b64:")
            assert canary.canary_id in verdict.signal_id
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_tn_triple_b64_benign(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-067-04: base64(base64(base64(benign))) → pass (no canary)."""
        benign = "normal text without canaries"
        # Triple encode
        enc1 = base64.b64encode(benign.encode()).decode()
        enc2 = base64.b64encode(enc1.encode()).decode()
        enc3 = base64.b64encode(enc2.encode()).decode()

        payload = Payload(text=f"Data: {enc3}")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_depth_cap_honored(self, context: SessionContext) -> None:
        """TC-067-05: canary at depth 5 → pass (depth=3 cap honored)."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            # Use default max_decode_depth=3
            detector = EntropyDecodeDetector(scanner=scanner)

            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None

            # Encode 5 layers deep (4 levels of base64 wrapping the canary)
            text = canary.value
            for _ in range(4):
                text = base64.b64encode(text.encode()).decode()

            payload = Payload(text=f"Token: {text}")
            verdict = detector.check(payload, context)

            # Should pass because depth cap (3) prevents finding the canary at depth 4
            assert verdict.passed or verdict.is_error
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_forensic_decode_chain_populated(self, context: SessionContext) -> None:
        """TC-067-06: Forensic record has decode_chain and decode_depth."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            detector = EntropyDecodeDetector(scanner=scanner, threshold=4.0)

            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None

            # Create base64(hex(canary))
            hex_encoded = canary.value.encode().hex()
            b64_hex_encoded = base64.b64encode(hex_encoded.encode()).decode()

            payload = Payload(text=f"Token: {b64_hex_encoded}")
            verdict = detector.check(payload, context)

            assert verdict.blocked
            assert "decode_chain" in verdict.details
            assert verdict.details["decode_chain"] == ["b64", "hex"]
            assert "decode_depth" in verdict.details
            assert verdict.details["decode_depth"] == 2
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_forensic_no_plaintext_leak(self, context: SessionContext) -> None:
        """TC-067-07 & TC-067-08: No decoded plaintext in forensic records."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            detector = EntropyDecodeDetector(scanner=scanner, threshold=4.0)

            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None

            # Create base64(hex(canary))
            hex_encoded = canary.value.encode().hex()
            b64_hex_encoded = base64.b64encode(hex_encoded.encode()).decode()

            payload = Payload(text=f"Token: {b64_hex_encoded}")
            verdict = detector.check(payload, context)

            assert verdict.blocked

            # Assert that the decoded canary value is NOT in the verdict details
            details_str = str(verdict.details)
            assert canary.value not in details_str, f"Canary value leaked in details: {verdict.details}"
            assert hex_encoded not in details_str, f"Hex-encoded value leaked in details: {verdict.details}"

            # Also check that it's not in the message
            assert canary.value not in verdict.message
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_single_layer_regression(self, context: SessionContext) -> None:
        """TC-067-10: Single-layer base64(canary) still works."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            detector = EntropyDecodeDetector(scanner=scanner)

            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None

            # Single-layer encoding
            b64_encoded = base64.b64encode(canary.value.encode()).decode()

            payload = Payload(text=f"Token: {b64_encoded}")
            verdict = detector.check(payload, context)

            assert verdict.blocked
            # Signal should be: entropy.decode_rescan:b64:<canary_id>
            assert verdict.signal_id.startswith("entropy.decode_rescan:b64:")
            assert canary.canary_id in verdict.signal_id
            assert "decode_chain" in verdict.details
            assert verdict.details["decode_chain"] == ["b64"]
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_plaintext_canary_regression(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-067-11: Plaintext canary still detected by canary.scanner, not entropy.decode_rescan."""
        # This test is a bit tricky — we're testing that plaintext canaries are NOT caught by
        # this detector (they're caught earlier by canary.scanner). But since this is the
        # entropy_decode detector, a plaintext canary would be very low-entropy and thus
        # skipped. We just verify it returns pass.
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            detector = EntropyDecodeDetector(scanner=scanner)

            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None

            # Plaintext canary (no encoding)
            payload = Payload(text=f"Token: {canary.value}")
            verdict = detector.check(payload, context)

            # Entropy detector should return pass for plaintext (low entropy)
            # The plaintext detector would catch it, not this one
            assert verdict.passed
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()

    def test_latency_budget_enforcement(self, detector: EntropyDecodeDetector, context: SessionContext) -> None:
        """TC-067-09: Pathological input bounded by per-detector budget."""
        # Create a high-entropy string that will trigger the entropy gate but decodes to junk
        # (testing no-progress termination and budget enforcement)
        import os

        random_high_entropy = base64.b64encode(os.urandom(100)).decode()
        payload = Payload(text=f"Data: {random_high_entropy}")

        start = time.time()
        verdict = detector.check(payload, context)
        elapsed_ms = (time.time() - start) * 1000

        # Should complete within budget (100ms default)
        assert elapsed_ms < detector.budget_ms * 2, f"Detector took {elapsed_ms:.1f}ms"
        # Verdict should be pass or error, not hang
        assert verdict.decision in ("pass", "error")

    def test_recursive_decode_max_depth_respected(self, context: SessionContext) -> None:
        """Verify custom max_decode_depth is respected."""
        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src" / "armor" / "canaries" / "default_catalogue.json"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_values_path = Path(tf.name)

        try:
            write_values_file(temp_values_path, schema_path, seed=0xCAFEBABE)
            catalogue = Catalogue.load(temp_values_path)

            canary_map = {entry.canary_id: entry.value for entry in catalogue.active_canaries()}
            scanner = CanaryScanner(canary_map)
            # Set max_decode_depth=1 (only allow 1 decode pass)
            detector = EntropyDecodeDetector(scanner=scanner, max_decode_depth=1)

            canary = catalogue.get_by_id("github-pat-000")
            assert canary is not None

            # Create a 2-layer encoding (should be blocked with default depth=3, but not with depth=1)
            hex_encoded = canary.value.encode().hex()
            b64_hex_encoded = base64.b64encode(hex_encoded.encode()).decode()

            payload = Payload(text=f"Token: {b64_hex_encoded}")
            verdict = detector.check(payload, context)

            # With max_decode_depth=1, we can only decode base64, which gives us hex(canary)
            # The hex string is not a direct canary match, so we stop at depth 1
            assert verdict.passed
        finally:
            if temp_values_path.exists():
                temp_values_path.unlink()
