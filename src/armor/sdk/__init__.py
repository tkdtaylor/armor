"""armor Python SDK - A client library for the armor security daemon.

This module provides synchronous and asynchronous clients for interfacing
with the armor daemon via Unix socket IPC. It wraps the low-level daemon
transport with a typed, ergonomic public surface.

Example:
    >>> from armor import ArmorClient, Verdict
    >>> client = ArmorClient(socket_path="/var/run/armor.sock")
    >>> v = client.check_input("user input text", session_id="sess-1")
    >>> if v.blocked:
    ...     print("Input blocked:", v.message)

Classes:
    ArmorClient: Synchronous client for armor daemon communication.
    AsyncArmorClient: Asynchronous client for armor daemon communication.
    SessionContext: Context manager for session-bound checks.
"""

from armor.sdk.async_client import AsyncArmorClient
from armor.sdk.client import ArmorClient, SessionContext

__all__ = [
    "ArmorClient",
    "AsyncArmorClient",
    "SessionContext",
]
