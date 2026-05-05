"""Background sweeper task for TTL purging."""

import asyncio
import logging

from armor.db.quarantine import QuarantineStore

logger = logging.getLogger(__name__)


def start_sweeper(quarantine_store: QuarantineStore, interval_seconds: int = 300) -> asyncio.Task[None]:
    """Start the background sweeper task.

    Args:
        quarantine_store: QuarantineStore instance.
        interval_seconds: Sweep interval in seconds (default 300 = 5 minutes).

    Returns:
        The asyncio.Task for the sweeper.
    """
    return asyncio.create_task(_sweep_loop(quarantine_store, interval_seconds))


async def _sweep_loop(quarantine_store: QuarantineStore, interval_seconds: int) -> None:
    """Run the sweep loop indefinitely.

    Args:
        quarantine_store: QuarantineStore instance.
        interval_seconds: Sweep interval in seconds.
    """
    try:
        while True:
            await asyncio.sleep(interval_seconds)
            await quarantine_store.sweep_expired()
    except asyncio.CancelledError:
        logger.info("Sweeper task cancelled")
        raise
    except Exception as e:
        logger.error(f"Sweeper error: {e}")
