"""armor - defense-in-depth security layer for LLM agents.

A security system that detects prompt injection, exfiltration via canary tokens,
encoding/obfuscation, jailbreaks, tool/API abuse, and session-level multi-turn
attacks. Ships as a Docker container with a small embedded validator LLM and
an importable Python library.

This package exports the main SDK client classes and key types for use as an
importable library. For daemon operation, see armor.daemon.

Typical usage:

    from armor import ArmorClient, Verdict

    client = ArmorClient(socket_path="/var/run/armor.sock")
    verdict = client.check_input("user input", session_id="sess-1")
    if verdict.blocked:
        # Handle blocked input
        pass
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("armor-ai")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

from armor.client import DaemonUnreachableError
from armor.sdk import ArmorClient, AsyncArmorClient
from armor.types import HealthReport, Incident, Verdict

__all__ = [
    "ArmorClient",
    "AsyncArmorClient",
    "DaemonUnreachableError",
    "HealthReport",
    "Incident",
    "Verdict",
]
