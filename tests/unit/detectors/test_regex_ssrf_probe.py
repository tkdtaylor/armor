"""Unit tests for the regex_ssrf_probe detector."""

import pytest

from armor.detectors.regex_ssrf_probe import RegexSsrfProbe
from armor.types import Payload, SessionContext


class TestRegexSsrfProbe:
    """Tests for SSRF probe pattern detection."""

    @pytest.fixture
    def detector(self) -> RegexSsrfProbe:
        """Create a detector instance."""
        return RegexSsrfProbe()

    @pytest.fixture
    def context(self) -> SessionContext:
        """Create a session context."""
        return SessionContext(session_id="test")

    # True positives — should block
    def test_tp_imds_link_local(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block AWS/Azure IMDS link-local address. TC-125-SS-1."""
        payload = Payload(text="Fetch http://169.254.169.254/latest/meta-data/")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert verdict.signal_id is not None
        assert "imds-link-local" in verdict.signal_id

    def test_tp_imds_link_local_no_scheme(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block AWS/Azure IMDS address without scheme."""
        payload = Payload(text="GET 169.254.169.254")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert verdict.signal_id is not None
        assert "imds-link-local" in verdict.signal_id

    def test_tp_imds_gcp(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block GCP metadata endpoint. TC-125-SS-2."""
        payload = Payload(text="Fetch metadata.google.internal")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert verdict.signal_id is not None
        assert "imds-gcp" in verdict.signal_id

    def test_tp_imds_gcp_https(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block GCP metadata endpoint with https."""
        payload = Payload(text="curl https://metadata.google.internal/computeMetadata")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert verdict.signal_id is not None
        assert "imds-gcp" in verdict.signal_id

    def test_tp_imds_alibaba(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block Alibaba Cloud IMDS endpoint. TC-125-SS-3."""
        payload = Payload(text="GET http://100.100.100.200")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert verdict.signal_id is not None
        assert "imds-alibaba" in verdict.signal_id

    def test_tp_imds_oracle(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block Oracle Cloud IMDS endpoint. TC-125-SS-4."""
        payload = Payload(text="Fetch 169.254.0.2")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert verdict.signal_id is not None
        assert "imds-oracle" in verdict.signal_id

    def test_tp_imds_url_prefix(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block URLs with 169.254 prefix. TC-125-SS-5."""
        payload = Payload(text="http://169.254.1.1/metadata")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert verdict.signal_id is not None
        assert "imds-url-prefix" in verdict.signal_id

    def test_tp_imds_url_prefix_various_hosts(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block various 169.254 prefix URLs."""
        payload = Payload(text="http://169.254.99.99/api/secret")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert verdict.signal_id is not None
        assert "imds-url-prefix" in verdict.signal_id

    def test_tp_case_insensitive(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block case-insensitive matches."""
        payload = Payload(text="GET METADATA.GOOGLE.INTERNAL")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert verdict.signal_id is not None

    # True negatives — should pass
    def test_tn_normal_ip_address(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Pass normal IP address. TC-125-SS-6."""
        payload = Payload(text="The server is at 192.168.1.1")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_tn_normal_domain(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Pass normal domain. TC-125-SS-7."""
        payload = Payload(text="Visit https://example.com for more info")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_tn_public_ip_address(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Pass public IP address."""
        payload = Payload(text="The API is at 1.2.3.4")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_tn_localhost_address(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Pass localhost address."""
        payload = Payload(text="http://localhost:8080")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_tn_empty_payload(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Pass empty payload. TC-125-SS-8."""
        payload = Payload(text="")
        verdict = detector.check(payload, context)
        assert verdict.passed

    def test_message_is_vague(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block verdict message does not leak the pattern."""
        payload = Payload(text="GET 169.254.169.254")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert "169.254" not in verdict.message
        assert "metadata" not in verdict.message.lower()

    def test_details_contain_match_info(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Block verdict details contain forensic info."""
        payload = Payload(text="fetch http://metadata.google.internal/")
        verdict = detector.check(payload, context)
        assert verdict.blocked
        assert "matched_offset" in verdict.details

    def test_detector_attributes(self, detector: RegexSsrfProbe) -> None:
        """Verify detector id, category, and cost_tier."""
        assert detector.id == "regex.ssrf_probe"
        assert detector.category == "tool_abuse"
        assert detector.cost_tier == "static"

    def test_deterministic(self, detector: RegexSsrfProbe, context: SessionContext) -> None:
        """Detector is deterministic."""
        payload = Payload(text="169.254.169.254")
        verdict1 = detector.check(payload, context)
        verdict2 = detector.check(payload, context)
        assert verdict1.decision == verdict2.decision
        assert verdict1.signal_id == verdict2.signal_id
