# SPDX-License-Identifier: Apache-2.0
"""Armor daemon — long-lived security check server."""

from armor.daemon.server import DaemonServer
from armor.logging import setup_logging

__all__ = ["DaemonServer", "setup_logging"]
