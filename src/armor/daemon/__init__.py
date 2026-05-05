"""Armor daemon — long-lived security check server."""

from armor.daemon.logging import setup_logging
from armor.daemon.server import DaemonServer

__all__ = ["DaemonServer", "setup_logging"]
