# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the canary scanner detector."""

from armor.canaries.scanner import CanaryScanner
from armor.detectors.canary_scanner import CanaryScannerDetector
from armor.types import Payload, SessionContext


class TestCanaryScannerDetectorAttributes:
    """Tests for detector attributes."""

    def test_detector_id(self):
        """Test detector has correct ID."""
        detector = CanaryScannerDetector()
        assert detector.id == "canary.scanner"

    def test_detector_category(self):
        """Test detector has correct category."""
        detector = CanaryScannerDetector()
        assert detector.category == "exfiltration"

    def test_detector_cost_tier(self):
        """Test detector has correct cost tier."""
        detector = CanaryScannerDetector()
        assert detector.cost_tier == "static"


class TestCanaryScannerDetectorCheck:
    """Tests for the check method."""

    def test_check_pass_on_clean_text(self):
        """Test detector passes on clean text."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="This is benign output")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.passed
        assert verdict.decision == "pass"

    def test_check_block_on_hit(self):
        """Test detector blocks when canary is found."""
        canaries = {"aws-key-001": "EXAMPLEKEY0000000001"}
        scanner = CanaryScanner(canaries)
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="Stolen: EXAMPLEKEY0000000001 do not share")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert verdict.decision == "block"

    def test_check_signal_id_format(self):
        """Test block verdict has correct signal_id format."""
        canary_id = "github-pat-001"
        scanner = CanaryScanner({canary_id: "ghp_abcdefghijklmnopqrstuvwxyz123456abcd"})
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="Pat: ghp_abcdefghijklmnopqrstuvwxyz123456abcd")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert verdict.signal_id == f"canary.scanner:{canary_id}"

    def test_check_multiple_hits_signal_id(self):
        """Test signal_id references first hit."""
        canary_1 = "aws-key-001"
        canary_2 = "github-pat-001"
        scanner = CanaryScanner(
            {
                canary_1: "EXAMPLEKEY0000000001",
                canary_2: "ghp_abcdefghijklmnopqrstuvwxyz123456abcd",
            }
        )
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="Keys: EXAMPLEKEY0000000001 and ghp_abcdefghijklmnopqrstuvwxyz123456abcd")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        # signal_id should reference the first hit
        assert "canary.scanner:" in verdict.signal_id

    def test_check_details_contains_canary_ids(self):
        """Test block verdict details contain canary IDs."""
        canary_id = "stripe-key-001"
        scanner = CanaryScanner({canary_id: "sk_live_1234567890abcdefghijklmn"})
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="Key: sk_live_1234567890abcdefghijklmn")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert "canary_ids" in verdict.details
        assert canary_id in verdict.details["canary_ids"]

    def test_check_details_multiple_hits(self):
        """Test details contain all hit canary IDs."""
        canary_1 = "aws-key-001"
        canary_2 = "github-pat-001"
        scanner = CanaryScanner(
            {
                canary_1: "EXAMPLEKEY0000000001",
                canary_2: "ghp_abcdefghijklmnopqrstuvwxyz123456abcd",
            }
        )
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="Exfil: EXAMPLEKEY0000000001 and ghp_abcdefghijklmnopqrstuvwxyz123456abcd")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        canary_ids = verdict.details["canary_ids"]
        assert len(canary_ids) >= 2
        assert canary_1 in canary_ids
        assert canary_2 in canary_ids

    def test_check_message_is_vague(self):
        """Test block message is vague and not informative."""
        scanner = CanaryScanner({"aws-key-001": "EXAMPLEKEY0000000001"})
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="EXAMPLEKEY0000000001")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        # Message should be a safe replacement, not a detailed signal
        assert "suppressed" in verdict.message.lower() or "blocked" in verdict.message.lower()

    def test_check_severity_is_critical(self):
        """Test block verdict has critical severity."""
        scanner = CanaryScanner({"aws-key-001": "EXAMPLEKEY0000000001"})
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="EXAMPLEKEY0000000001")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert verdict.severity == "critical"

    def test_check_without_scanner(self):
        """Test detector without scanner returns pass."""
        detector = CanaryScannerDetector(scanner=None)

        payload = Payload(text="Any text")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        # Should pass gracefully without scanner
        assert verdict.passed

    def test_check_empty_text(self):
        """Test detector with empty text."""
        scanner = CanaryScanner({"aws-key-001": "EXAMPLEKEY0000000001"})
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.passed

    def test_check_none_text(self):
        """Test detector with None text."""
        scanner = CanaryScanner({"aws-key-001": "EXAMPLEKEY0000000001"})
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text=None)
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        # Should handle None gracefully
        assert verdict.passed or verdict.is_error

    def test_check_canary_at_start(self):
        """Test detecting canary at start of text."""
        canary_id = "aws-key-001"
        scanner = CanaryScanner({canary_id: "EXAMPLEKEY0000000001"})
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="EXAMPLEKEY0000000001 is the secret")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert canary_id in verdict.details["canary_ids"]

    def test_check_canary_at_end(self):
        """Test detecting canary at end of text."""
        canary_id = "github-pat-001"
        scanner = CanaryScanner({canary_id: "ghp_abcdefghijklmnopqrstuvwxyz123456abcd"})
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="The secret is ghp_abcdefghijklmnopqrstuvwxyz123456abcd")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert canary_id in verdict.details["canary_ids"]

    def test_check_canary_in_middle(self):
        """Test detecting canary in middle of text."""
        canary_id = "stripe-key-001"
        scanner = CanaryScanner({canary_id: "sk_live_1234567890abcdefghijklmn"})
        detector = CanaryScannerDetector(scanner=scanner)

        payload = Payload(text="Start here sk_live_1234567890abcdefghijklmn end here")
        ctx = SessionContext(session_id="test-session")

        verdict = detector.check(payload, ctx)

        assert verdict.blocked
        assert canary_id in verdict.details["canary_ids"]
