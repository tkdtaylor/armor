"""armor daemon entry point.

Run with: python -m armor.daemon [--socket PATH] [--max-concurrent N] [--log-level LEVEL]
"""

import argparse
import asyncio
import logging
import sys

from armor.daemon.logging import setup_logging
from armor.daemon.server import DaemonServer


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the daemon.

    Args:
        argv: Command-line arguments (default: sys.argv[1:])

    Returns:
        Exit code (0 for success, 78 for config error)
    """
    parser = argparse.ArgumentParser(prog="armor daemon")
    parser.add_argument(
        "--socket",
        default="/var/run/armor.sock",
        help="Path to the Unix socket (default: /var/run/armor.sock)",
    )
    parser.add_argument(
        "--db",
        default="/var/lib/armor/armor.db",
        help="Path to SQLite database (default: /var/lib/armor/armor.db)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Path to validator LLM weights file",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to armor.toml configuration file",
    )
    parser.add_argument(
        "--catalogue",
        default=None,
        help="Path to canary catalogue JSON",
    )
    parser.add_argument(
        "--quarantine-key-path",
        default=None,
        help="Path to quarantine encryption key",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=64,
        help="Maximum concurrent connections (default: 64)",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Log level (default: info)",
    )

    args = parser.parse_args(argv)

    # Set up logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    # Warn if model flag is used (not supported in v0.1)
    if args.model:
        logger.warning("--model flag accepted but validator LLM is not used in v0.1")

    # Create and start the server
    try:
        server = DaemonServer(
            socket_path=args.socket,
            max_concurrent=args.max_concurrent,
            catalogue_path=args.catalogue,
            db_path=args.db,
            quarantine_key_path=args.quarantine_key_path,
        )
        asyncio.run(server.run())
        return 0

    except OSError as e:
        logger.error(f"Configuration error: {e}")
        print(f"Configuration error: {e}", file=sys.stderr)
        return 78

    except KeyboardInterrupt:
        logger.info("Shutdown requested")
        return 0

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
