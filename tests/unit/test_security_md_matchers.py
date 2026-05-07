"""Unit tests for the SECURITY.md structural matcher (task 037, TC-037-03).

Negative-fixture coverage: the matcher must reject documents that are
missing one of the procedural anchors. The matcher itself lives in
``tests/fitness/test_public_release.py`` so the fitness check exercises the
same function. ``tests`` is not a Python package in this project, so we
load the matcher by file path rather than via ``import tests.fitness…``.
"""

import importlib.util
from pathlib import Path

import pytest

_FITNESS_PATH = Path(__file__).resolve().parents[1] / "fitness" / "test_public_release.py"
_spec = importlib.util.spec_from_file_location("_armor_public_release_matcher", _FITNESS_PATH)
assert _spec is not None and _spec.loader is not None
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
_assert_security_md_structure = _module._assert_security_md_structure


_FULL_FIXTURE = """\
# Sample policy

## Reporting a vulnerability
Use a private channel.

GitHub Security Advisory: <https://example/advisory>

## Disclosure timeline
Acknowledgement within 5 business days.

DO NOT file a public issue. Public issues are visible to attackers.
"""


def test_full_fixture_passes() -> None:
    _assert_security_md_structure(_FULL_FIXTURE)


def test_missing_reporting_heading_fails() -> None:
    text = _FULL_FIXTURE.replace("## Reporting a vulnerability", "## Overview")
    with pytest.raises(AssertionError, match="reporting section heading"):
        _assert_security_md_structure(text)


def test_missing_timeline_heading_fails() -> None:
    text = _FULL_FIXTURE.replace("## Disclosure timeline", "## Process")
    with pytest.raises(AssertionError, match="disclosure or timeline"):
        _assert_security_md_structure(text)


def test_missing_numeric_sla_fails() -> None:
    text = _FULL_FIXTURE.replace("5 business days", "promptly")
    with pytest.raises(AssertionError, match="numeric service-level commitment"):
        _assert_security_md_structure(text)


def test_do_not_guard_too_far_from_public_issue_fails() -> None:
    padding = "\n\nfiller " * 60
    text = _FULL_FIXTURE.replace(
        "DO NOT file a public issue.",
        "DO NOT file anything yet." + padding + "Public issue mentioned later.",
    )
    with pytest.raises(AssertionError, match="chars apart"):
        _assert_security_md_structure(text)


def test_missing_private_channel_anchor_fails() -> None:
    text = _FULL_FIXTURE.replace("GitHub Security Advisory: <https://example/advisory>", "Use the form.")
    with pytest.raises(AssertionError, match="private-channel anchor"):
        _assert_security_md_structure(text)
