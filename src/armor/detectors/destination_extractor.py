"""Destination extractor detector for URL, IP, and email exfiltration.

Extracts URLs (http/https/ftp), IPv4, IPv6, and email addresses from output text.
Stores destinations as hostnames only (no paths, queries, fragments, or email local-parts).
Compares against a whitelist (exact-match, case-insensitive); non-whitelisted
destinations return advisory verdicts.

This is an output-side detector that feeds the session risk score but does not block
by default. It is always run as part of the exfiltration detection pipeline.
"""

import logging
import re
from ipaddress import AddressValueError, ip_address

from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)


def _extract_urls(text: str) -> list[str]:
    """Extract URLs (http, https, ftp) from text.

    Args:
        text: Input text to search.

    Returns:
        List of hostnames extracted from URLs (no paths, queries, fragments, or ports).
    """
    # Regex to match URLs with http, https, or ftp schemes
    # Matches: scheme://[user[:pass]@]host[:port][/path][?query][#fragment]
    url_pattern = r"(https?|ftp)://(?:[a-zA-Z0-9_%-]+(?::[a-zA-Z0-9_%-]+)?@)?([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])"

    hostnames = []
    for match in re.finditer(url_pattern, text):
        hostname = match.group(2)
        hostnames.append(hostname)

    return hostnames


def _extract_ipv4(text: str) -> list[str]:
    """Extract IPv4 addresses from text.

    Args:
        text: Input text to search.

    Returns:
        List of valid IPv4 addresses, excluding reserved/localhost ranges.
    """
    # IPv4 pattern: four decimal octets separated by dots
    ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

    # Reserved IPv4 ranges per RFC 5737 (documentation):
    # - 192.0.2.0/24 (TEST-NET-1)
    # - 198.51.100.0/24 (TEST-NET-2)
    # - 203.0.113.0/24 (TEST-NET-3)
    reserved_ranges = [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    ]

    reserved_networks = []
    try:
        from ipaddress import ip_network

        reserved_networks = [ip_network(r, strict=False) for r in reserved_ranges]
    except Exception as e:
        logger.error(f"Failed to parse reserved IPv4 ranges: {e}")

    addresses = []
    for match in re.finditer(ipv4_pattern, text):
        addr_str = match.group(0)
        try:
            addr = ip_address(addr_str)
            # Exclude localhost and reserved ranges
            if addr.is_loopback or any(addr in network for network in reserved_networks):
                continue
            addresses.append(addr_str)
        except AddressValueError:
            # Invalid address, skip
            continue

    return addresses


def _extract_ipv6(text: str) -> list[str]:
    """Extract IPv6 addresses from text.

    Args:
        text: Input text to search.

    Returns:
        List of valid IPv6 addresses, excluding localhost.
    """
    # Simplified IPv6 regex — matches common patterns including abbreviated forms
    # This regex is not exhaustive but covers most practical cases:
    # - Full notation: 2001:db8::1
    # - Abbreviated: ::1, fe80::1, ::ffff:192.0.2.1
    ipv6_pattern = r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}|::|::1"

    addresses = []
    for match in re.finditer(ipv6_pattern, text):
        addr_str = match.group(0)
        try:
            addr = ip_address(addr_str)
            # Exclude localhost
            if addr.is_loopback:
                continue
            addresses.append(addr_str)
        except AddressValueError:
            # Invalid address, skip
            continue

    return addresses


def _extract_emails(text: str) -> list[str]:
    """Extract email addresses from text and return hostnames only.

    Args:
        text: Input text to search.

    Returns:
        List of hostname-only parts from email addresses (no local-part).
    """
    # Email pattern: local-part@domain
    # Local part: alphanumeric, dots, hyphens, underscores
    # Domain: standard hostname pattern
    email_pattern = r"[a-zA-Z0-9._%-]+@([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])"

    hostnames = []
    for match in re.finditer(email_pattern, text):
        hostname = match.group(1)
        hostnames.append(hostname)

    return hostnames


class DestinationExtractor:
    """Detector that extracts and whitelists URLs, IPs, and emails.

    Algorithm:
    1. Extract all URLs, IPv4, IPv6, and email addresses from the output text.
    2. Normalize to hostnames only (no paths, queries, fragments, or email local-parts).
    3. Deduplicate.
    4. Compare each destination against the configured whitelist (exact-match, case-insensitive).
    5. If all are whitelisted, return pass (but include destinations in details for forensic audit).
    6. If any are non-whitelisted, return advisory.

    Attributes:
        id: "extractor.destinations"
        category: "exfiltration"
        cost_tier: "static" (no LLM involvement, pure regex/parsing)

    Config parameters (from armor.toml):
        destination_whitelist: List of exact-match hostnames to whitelist (default: [])
    """

    id = "extractor.destinations"
    category = "exfiltration"
    cost_tier = "static"

    def __init__(self, whitelist: list[str] | None = None) -> None:
        """Initialize the detector.

        Args:
            whitelist: List of hostnames to whitelist (exact-match, case-insensitive).
                      If None, defaults to empty list (no whitelisted destinations).
        """
        self.whitelist = set(h.lower() for h in (whitelist or []))
        logger.debug(f"DestinationExtractor initialized with {len(self.whitelist)} whitelisted destinations")

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Check payload for exfiltration destinations.

        Args:
            payload: The payload to check (text).
            ctx: Session context.

        Returns:
            Verdict.pass() if no destinations or all whitelisted (details still populated).
            Verdict.advisory() if any non-whitelisted destinations found.
            Verdict.error() on unexpected errors.
        """
        try:
            text = payload.text or ""

            # Extract all destination types
            url_hosts = _extract_urls(text)
            ipv4_addrs = _extract_ipv4(text)
            ipv6_addrs = _extract_ipv6(text)
            email_hosts = _extract_emails(text)

            # Combine and deduplicate (case-insensitive comparison for matching)
            all_destinations = []
            seen = set()

            for dst in url_hosts + ipv4_addrs + ipv6_addrs + email_hosts:
                dst_lower = dst.lower()
                if dst_lower not in seen:
                    seen.add(dst_lower)
                    all_destinations.append(dst)

            # Check against whitelist
            non_whitelisted = []
            for dst in all_destinations:
                if dst.lower() not in self.whitelist:
                    non_whitelisted.append(dst)

            # Return verdict based on whitelist match
            if non_whitelisted:
                # At least one destination is not whitelisted
                first_non_whitelisted = non_whitelisted[0]
                return Verdict.advisory_verdict(
                    signal_id=f"extractor.destinations:{first_non_whitelisted}",
                    severity="medium",
                    message="Exfiltration destination detected",
                    details={"destinations": all_destinations},
                )
            else:
                # All destinations whitelisted (or none found)
                return Verdict.pass_verdict(
                    message="No non-whitelisted destinations detected",
                    details={"destinations": all_destinations},
                )

        except Exception as e:
            logger.error(f"DestinationExtractor error: {e}", exc_info=True)
            return Verdict.error_verdict(reason=f"Destination extractor error: {e}")
