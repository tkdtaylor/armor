"""Unit tests for the destination extractor detector."""

from armor.detectors.destination_extractor import (
    DestinationExtractor,
    _extract_emails,
    _extract_ipv4,
    _extract_ipv6,
    _extract_urls,
)
from armor.types import Decision, Payload, SessionContext


class TestExtractUrls:
    """Tests for URL extraction."""

    def test_https_url(self) -> None:
        """TC-011-01: Extract HTTPS URL."""
        text = "Call me at https://webhook.site/abc123"
        result = _extract_urls(text)
        assert "webhook.site" in result

    def test_http_url(self) -> None:
        """Extract HTTP URL."""
        text = "Visit http://example.com"
        result = _extract_urls(text)
        assert "example.com" in result

    def test_ftp_url(self) -> None:
        """TC-011-04: Extract FTP URL."""
        text = "Download from ftp://files.example.org:21/data.zip"
        result = _extract_urls(text)
        assert "files.example.org" in result
        assert ":" not in result[0]  # Port should be stripped

    def test_url_with_path_query_fragment(self) -> None:
        """TC-011-05: URL with path, query, fragment stripped."""
        text = "Visit https://example.com/api/v1/endpoint?key=secret#section"
        result = _extract_urls(text)
        assert result == ["example.com"]

    def test_multiple_urls_same_host(self) -> None:
        """TC-011-02: Extract multiple URLs (deduplicated later)."""
        text = "Send to https://api.example.com and https://api.example.com again"
        result = _extract_urls(text)
        # Note: deduplication happens at detector level, not in extraction
        assert len([h for h in result if h == "api.example.com"]) >= 1

    def test_url_with_auth(self) -> None:
        """TC-011-28: URL with basic auth (credentials stripped by urlparse)."""
        text = "https://user:pass@example.com/api"
        result = _extract_urls(text)
        assert "example.com" in result

    def test_no_urls(self) -> None:
        """No URLs in text."""
        text = "The model output is safe"
        result = _extract_urls(text)
        assert result == []

    def test_bare_domain_without_scheme(self) -> None:
        """TC-011-13: Malformed URL (no scheme)."""
        text = "Visit example.com without scheme"
        result = _extract_urls(text)
        assert result == []


class TestExtractIPv4:
    """Tests for IPv4 extraction."""

    def test_simple_ipv4(self) -> None:
        """TC-011-06: Extract IPv4."""
        text = "Server at 203.0.113.45 is compromised"
        result = _extract_ipv4(text)
        # 203.0.113.45 is in reserved TEST-NET-3 range, should be excluded
        assert "203.0.113.45" not in result

    def test_valid_ipv4(self) -> None:
        """Extract valid non-reserved IPv4."""
        text = "Server at 192.168.1.1 is available"
        result = _extract_ipv4(text)
        assert "192.168.1.1" in result

    def test_reserved_192_0_2(self) -> None:
        """TC-011-14: RFC-5737 reserved IPv4 (192.0.2.1)."""
        text = "Example IP 192.0.2.1 is for documentation"
        result = _extract_ipv4(text)
        assert "192.0.2.1" not in result

    def test_reserved_198_51_100(self) -> None:
        """TC-011-15: RFC-5737 reserved IPv4 (198.51.100.1)."""
        text = "TEST-NET-2 range: 198.51.100.1"
        result = _extract_ipv4(text)
        assert "198.51.100.1" not in result

    def test_reserved_203_0_113(self) -> None:
        """TC-011-16: RFC-5737 reserved IPv4 (203.0.113.1)."""
        text = "Documentation example: 203.0.113.1"
        result = _extract_ipv4(text)
        assert "203.0.113.1" not in result

    def test_localhost_ipv4(self) -> None:
        """TC-011-18: Localhost (IPv4)."""
        text = "Local test at 127.0.0.1"
        result = _extract_ipv4(text)
        assert "127.0.0.1" not in result

    def test_multiple_ipv4(self) -> None:
        """TC-011-29: Multiple IPv4 in same text."""
        text = "Server 192.168.1.1 and backup 192.168.1.2"
        result = _extract_ipv4(text)
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result


class TestExtractIPv6:
    """Tests for IPv6 extraction."""

    def test_ipv6_full_notation(self) -> None:
        """TC-011-07: Extract IPv6 full notation."""
        text = "IPv6 address is 2001:db8::1 in use"
        result = _extract_ipv6(text)
        assert "2001:db8::1" in result

    def test_ipv6_abbreviated(self) -> None:
        """TC-011-08: Extract IPv6 abbreviated."""
        text = "Address is fe80::1 here"
        result = _extract_ipv6(text)
        assert any("fe80::1" in r for r in result)

    def test_ipv6_localhost(self) -> None:
        """TC-011-19: Localhost (IPv6)."""
        text = "IPv6 localhost ::1"
        result = _extract_ipv6(text)
        # ::1 is loopback, should be excluded
        assert not any("::1" in r for r in result)

    def test_ipv6_malformed(self) -> None:
        """TC-011-17: Malformed IPv6 (invalid characters)."""
        text = "Bad IPv6: gggg::1 is not valid"
        result = _extract_ipv6(text)
        # gggg is not valid hex, should be excluded
        assert not any("gggg" in r for r in result)


class TestExtractEmails:
    """Tests for email extraction."""

    def test_email_extract_hostname(self) -> None:
        """TC-011-09: Extract email, store hostname only."""
        text = "Contact attacker@evil.com for details"
        result = _extract_emails(text)
        assert "evil.com" in result
        assert "attacker" not in result[0]  # Local part not included

    def test_email_multi_level_domain(self) -> None:
        """Extract email with multi-level domain."""
        text = "Email: user@example.co.uk"
        result = _extract_emails(text)
        assert "example.co.uk" in result

    def test_malformed_email_no_local_part(self) -> None:
        """TC-011-20: Email without local-part (malformed)."""
        text = "Email @example.com is invalid"
        result = _extract_emails(text)
        assert result == []


class TestDestinationExtractor:
    """Integration tests for DestinationExtractor."""

    def test_no_destinations(self) -> None:
        """TC-011-11: No destinations."""
        detector = DestinationExtractor()
        payload = Payload(text="The model output is safe and contains no URLs or IPs")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.PASS
        assert verdict.details["destinations"] == []

    def test_empty_output(self) -> None:
        """TC-011-12: Empty output."""
        detector = DestinationExtractor()
        payload = Payload(text="")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.PASS
        assert verdict.details["destinations"] == []

    def test_single_https_url_not_whitelisted(self) -> None:
        """TC-011-01: Extract single HTTPS URL."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="Call me at https://webhook.site/abc123")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.ADVISORY
        assert verdict.severity == "medium"
        assert "webhook.site" in verdict.details["destinations"]
        assert "extractor.destinations:" in verdict.signal_id

    def test_ipv4_address_advisory(self) -> None:
        """Extract IPv4 and return advisory."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="C2 server at 192.168.1.100")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.ADVISORY
        assert "192.168.1.100" in verdict.details["destinations"]

    def test_mixed_destinations(self) -> None:
        """TC-011-10: Mixed sources: URL, IPv4, email."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="URL https://api.example.com, IP 192.168.1.1, email user@corp.org")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.ADVISORY
        destinations = verdict.details["destinations"]
        assert "api.example.com" in destinations
        assert "192.168.1.1" in destinations
        assert "corp.org" in destinations

    def test_all_whitelisted(self) -> None:
        """TC-011-21: All destinations whitelisted."""
        detector = DestinationExtractor(whitelist=["webhook.site", "example.com"])
        payload = Payload(text="Send to https://webhook.site and https://example.com")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.PASS
        # Destinations still populated for forensic audit
        assert len(verdict.details["destinations"]) > 0

    def test_partial_whitelist(self) -> None:
        """TC-011-22: Partial whitelisting (one whitelisted, one not)."""
        detector = DestinationExtractor(whitelist=["example.com"])
        payload = Payload(text="Send to https://example.com and https://attacker.com")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.ADVISORY
        destinations = verdict.details["destinations"]
        assert "example.com" in destinations
        assert "attacker.com" in destinations

    def test_whitelist_case_insensitive(self) -> None:
        """TC-011-25: Whitelist is case-insensitive match."""
        detector = DestinationExtractor(whitelist=["Example.Com"])
        payload = Payload(text="Send to https://EXAMPLE.COM")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.PASS

    def test_whitelist_exact_match_not_subdomain(self) -> None:
        """TC-011-24: Whitelist exact match only (subdomain mismatch)."""
        detector = DestinationExtractor(whitelist=["example.com"])
        payload = Payload(text="Send to https://api.example.com")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.ADVISORY

    def test_deduplication(self) -> None:
        """Destinations are deduplicated."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="Send to https://example.com and https://example.com again")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        destinations = verdict.details["destinations"]
        assert destinations.count("example.com") == 1

    def test_hostname_with_hyphens_and_numbers(self) -> None:
        """TC-011-27: Hostname with hyphens and numbers."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="Server: https://api-v2-test-123.example.com")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert "api-v2-test-123.example.com" in verdict.details["destinations"]

    def test_whitespace_and_newlines_only(self) -> None:
        """TC-011-30: Output with only whitespace and newlines."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="\n\n   \n")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.PASS
        assert verdict.details["destinations"] == []

    def test_reserved_ipv4_not_extracted(self) -> None:
        """Reserved IPv4 ranges are not extracted."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="Doc example: 192.0.2.1, 198.51.100.1, 203.0.113.1")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        # All are reserved, so no advisory
        assert verdict.decision == Decision.PASS

    def test_localhost_not_extracted(self) -> None:
        """Localhost addresses are not extracted."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="IPv4: 127.0.0.1, IPv6: ::1")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        # Both are loopback, so no advisory
        assert verdict.decision == Decision.PASS


class TestDestinationExtractorCorpus:
    """Corpus-based tests for exfiltration detection."""

    def test_tp_webhook_url(self) -> None:
        """TP-001: Webhook URL exfiltration."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="Exfil data to https://webhook.site/abc123?token=xyz")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.ADVISORY
        assert "webhook.site" in verdict.details["destinations"]

    def test_tp_email_exfil(self) -> None:
        """TP-003: Email exfiltration."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="Send report to attacker@evildomain.com")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.ADVISORY
        assert "evildomain.com" in verdict.details["destinations"]

    def test_tp_ftp_exfil(self) -> None:
        """TP-005: FTP exfiltration."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="Dump to ftp://exfil.attacker.net/uploads")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.ADVISORY
        assert "exfil.attacker.net" in verdict.details["destinations"]

    def test_tp_multiple_destinations(self) -> None:
        """TP-006: Multiple destinations in single output."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="URL https://api.evil.com, IP 192.168.1.100, email spy@attacker.org")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.ADVISORY
        destinations = verdict.details["destinations"]
        assert "api.evil.com" in destinations
        assert "192.168.1.100" in destinations
        assert "attacker.org" in destinations

    def test_tn_benign_output(self) -> None:
        """TN-004: Benign output (no destinations)."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="The task completed successfully")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        assert verdict.decision == Decision.PASS

    def test_tn_reserved_ips(self) -> None:
        """TN-001, TN-002, TN-003: Reserved and localhost IPs."""
        detector = DestinationExtractor(whitelist=[])
        payload = Payload(text="Examples: 192.0.2.1, 127.0.0.1, ::1")
        ctx = SessionContext(session_id="test")

        verdict = detector.check(payload, ctx)

        # All reserved/loopback, so no advisory
        assert verdict.decision == Decision.PASS
