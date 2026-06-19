# SPDX-License-Identifier: Apache-2.0
"""CRITICAL INVARIANT TEST: Canary values must never leak from verdicts or logs.

This test is load-bearing. Failure means a security incident in the code.
The forensic log must never become a data exfiltration channel.
"""

import logging

from armor.canaries.scanner import CanaryScanner
from armor.detectors.canary_scanner import CanaryScannerDetector
from armor.types import Payload, SessionContext


def test_no_canary_value_in_verdict_message(caplog):
    """Assert: Canary value never appears in Verdict.message."""
    canary_id = "aws-key-001"
    canary_value = "EXAMPLEKEY0000000001"

    scanner = CanaryScanner({canary_id: canary_value})
    detector = CanaryScannerDetector(scanner=scanner)

    payload = Payload(text=f"Exfil: {canary_value}")
    ctx = SessionContext(session_id="test-session")

    with caplog.at_level(logging.DEBUG):
        verdict = detector.check(payload, ctx)

    assert verdict.blocked
    # The message should be vague
    assert "suppressed" in verdict.message.lower() or "blocked" in verdict.message.lower()
    # Most importantly: the canary value must not be in the message
    assert canary_value not in verdict.message
    assert canary_id not in verdict.message  # signal_id should reference detector+id, not raw canary


def test_no_canary_value_in_signal_id(caplog):
    """Assert: Canary value never appears in Verdict.signal_id."""
    canary_id = "github-pat-001"
    canary_value = "ghp_abcdefghijklmnopqrstuvwxyz123456abcd"

    scanner = CanaryScanner({canary_id: canary_value})
    detector = CanaryScannerDetector(scanner=scanner)

    payload = Payload(text=f"Data sent to {canary_value}")
    ctx = SessionContext(session_id="test-session")

    with caplog.at_level(logging.DEBUG):
        verdict = detector.check(payload, ctx)

    assert verdict.blocked
    assert verdict.signal_id is not None
    # The signal_id should reference the canary_id, not the value
    assert canary_id in verdict.signal_id
    assert canary_value not in verdict.signal_id


def test_no_canary_value_in_logs(caplog):
    """Assert: Canary value never appears in any log record."""
    canary_id = "stripe-key-001"
    canary_value = "sk_live_1234567890abcdefghijklmn"

    scanner = CanaryScanner({canary_id: canary_value})
    detector = CanaryScannerDetector(scanner=scanner)

    payload = Payload(text=f"Sending {canary_value} to attacker.com")
    ctx = SessionContext(session_id="test-session")

    with caplog.at_level(logging.DEBUG):
        verdict = detector.check(payload, ctx)

    assert verdict.blocked

    # Check all log records
    for record in caplog.records:
        message = record.getMessage()
        # Canary value must not appear in any log message
        assert canary_value not in message, f"Canary value leaked in log: {message}"


def test_no_canary_value_in_details_recursive(caplog):
    """Assert: Canary value never appears in Verdict.details (recursively)."""
    canary_id = "url-001"
    canary_value = "https://canary.armor-trap.invalid/url-001"

    scanner = CanaryScanner({canary_id: canary_value})
    detector = CanaryScannerDetector(scanner=scanner)

    payload = Payload(text=f"Exfil to {canary_value}")
    ctx = SessionContext(session_id="test-session")

    with caplog.at_level(logging.DEBUG):
        verdict = detector.check(payload, ctx)

    assert verdict.blocked
    assert verdict.details is not None

    # Recursively check all values in details
    def check_details_recursive(obj, path: str = "details"):
        """Recursively search for canary value in nested structure."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                assert canary_value not in str(key), f"Canary value in key at {path}.{key}"
                check_details_recursive(value, f"{path}.{key}")
        elif isinstance(obj, list | tuple):
            for i, item in enumerate(obj):
                check_details_recursive(item, f"{path}[{i}]")
        elif isinstance(obj, str):
            assert canary_value not in obj, f"Canary value in string at {path}: {obj}"

    check_details_recursive(verdict.details)


def test_canary_id_appears_in_details(caplog):
    """Assert: Canary IDs DO appear in Verdict.details (this is expected)."""
    canary_id = "aws-key-001"
    canary_value = "EXAMPLEKEY0000000001"

    scanner = CanaryScanner({canary_id: canary_value})
    detector = CanaryScannerDetector(scanner=scanner)

    payload = Payload(text=f"Leaked: {canary_value}")
    ctx = SessionContext(session_id="test-session")

    with caplog.at_level(logging.DEBUG):
        verdict = detector.check(payload, ctx)

    assert verdict.blocked
    assert verdict.details is not None
    assert "canary_ids" in verdict.details
    assert isinstance(verdict.details["canary_ids"], list)
    assert len(verdict.details["canary_ids"]) > 0
    assert canary_id in verdict.details["canary_ids"]


def test_multiple_canaries_no_value_leak(caplog):
    """Assert: No value leak with multiple canaries hit."""
    canary_1_id = "aws-key-001"
    canary_1_value = "EXAMPLEKEY0000000001"
    canary_2_id = "github-pat-001"
    canary_2_value = "ghp_abcdefghijklmnopqrstuvwxyz123456abcd"

    scanner = CanaryScanner(
        {
            canary_1_id: canary_1_value,
            canary_2_id: canary_2_value,
        }
    )
    detector = CanaryScannerDetector(scanner=scanner)

    payload = Payload(text=f"Exfil: {canary_1_value} and {canary_2_value}")
    ctx = SessionContext(session_id="test-session")

    with caplog.at_level(logging.DEBUG):
        verdict = detector.check(payload, ctx)

    assert verdict.blocked

    # Check message
    assert canary_1_value not in verdict.message
    assert canary_2_value not in verdict.message

    # Check signal_id
    assert canary_1_value not in verdict.signal_id
    assert canary_2_value not in verdict.signal_id

    # Check details
    assert canary_1_id in verdict.details["canary_ids"]
    assert canary_2_id in verdict.details["canary_ids"]
    # But values must not appear
    assert canary_1_value not in str(verdict.details)
    assert canary_2_value not in str(verdict.details)

    # Check logs
    for record in caplog.records:
        message = record.getMessage()
        assert canary_1_value not in message
        assert canary_2_value not in message


def test_no_stdout_stderr_leakage(caplog, capsys):
    """Assert: No canary value appears in stdout or stderr."""
    canary_id = "email-001"
    canary_value = "canary-email-001@armor-trap.invalid"

    scanner = CanaryScanner({canary_id: canary_value})
    detector = CanaryScannerDetector(scanner=scanner)

    payload = Payload(text=f"Reporting to {canary_value}")
    ctx = SessionContext(session_id="test-session")

    with caplog.at_level(logging.DEBUG):
        verdict = detector.check(payload, ctx)

    assert verdict.blocked

    # Capture any stdout/stderr that occurred
    captured = capsys.readouterr()
    assert canary_value not in captured.out
    assert canary_value not in captured.err

    # Also check captured logs
    for record in caplog.records:
        message = record.getMessage()
        assert canary_value not in message
