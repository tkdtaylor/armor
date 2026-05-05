"""SQLite database layer for armor daemon persistence.

This module provides:
- Schema and migrations
- SessionStore for per-session state
- ForensicLogger for incident recording
- QuarantineStore for encrypted payload storage
"""

__all__ = [
    "ForensicLogger",
    "QuarantineStore",
    "SessionStore",
]
