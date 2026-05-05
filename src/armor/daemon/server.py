"""Unix socket server for the armor daemon.

Handles NDJSON request/response protocol with concurrent client support.
"""

import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
from typing import Any

from armor.canaries.catalogue import Catalogue
from armor.canaries.scanner import CanaryScanner
from armor.db.forensic import ForensicLogger
from armor.db.migrations import run_migrations
from armor.db.quarantine import QuarantineStore
from armor.db.session_store import SessionStore
from armor.db.sweeper import start_sweeper
from armor.detectors import DetectorRegistry
from armor.detectors.canary_scanner import CanaryScannerDetector
from armor.pipeline import Pipeline
from armor.types import Payload, SessionContext

logger = logging.getLogger(__name__)


class DaemonServer:
    """Asyncio-based Unix socket server for the armor daemon."""

    def __init__(
        self,
        socket_path: str,
        max_concurrent: int = 64,
        catalogue_path: str | None = None,
        db_path: str | None = None,
        quarantine_key_path: str | None = None,
    ) -> None:
        """Initialize the daemon server.

        Args:
            socket_path: Path to the Unix socket to bind
            max_concurrent: Maximum number of concurrent connections
            catalogue_path: Path to canary catalogue JSON (optional for v0.1)
            db_path: Path to SQLite database (default /var/lib/armor/armor.db)
            quarantine_key_path: Path to quarantine encryption key (default <db_dir>/.key)

        Raises:
            ValueError: If catalogue is provided but invalid or empty.
            SystemExit: If catalogue validation fails (exit code 78).
        """
        self.socket_path = socket_path
        self.max_concurrent = max_concurrent
        self.active_connections = 0
        self._shutdown_event: asyncio.Event | None = None
        self._server: asyncio.Server | None = None
        self._semaphore = asyncio.Semaphore(max_concurrent)

        # Database paths
        self.db_path = db_path or "/var/lib/armor/armor.db"
        self.quarantine_key_path = quarantine_key_path

        # Database stores (initialized in start())
        self.session_store: SessionStore | None = None
        self.forensic_logger: ForensicLogger | None = None
        self.quarantine_store: QuarantineStore | None = None
        self._sweeper_task: asyncio.Task[None] | None = None

        # Load and validate canary catalogue if provided
        self.catalogue: Catalogue | None = None
        self.canary_scanner: CanaryScanner | None = None

        if catalogue_path:
            try:
                self.catalogue = Catalogue.load(catalogue_path)
                active_canaries = self.catalogue.active_canaries()

                if not active_canaries:
                    logger.error("Catalogue is empty (no active canaries)")
                    sys.exit(78)

                # Build canary value map for the scanner
                canary_map = {entry.canary_id: entry.value for entry in active_canaries}
                self.canary_scanner = CanaryScanner(canary_map)
                logger.info(f"Loaded canary catalogue with {len(active_canaries)} active canaries")

            except FileNotFoundError as e:
                logger.error(f"Catalogue file not found: {e}")
                sys.exit(78)
            except ValueError as e:
                logger.error(f"Invalid catalogue: {e}")
                sys.exit(78)
            except Exception as e:
                logger.error(f"Failed to load catalogue: {e}")
                sys.exit(78)

        # Initialize detector registry
        self.registry = DetectorRegistry()

        # If we have a canary scanner, inject it into the detector
        if self.canary_scanner:
            detector = CanaryScannerDetector(scanner=self.canary_scanner)
            self.registry.detectors["canary.scanner"] = detector
            logger.info("Injected canary scanner detector")

        logger.info(f"Loaded {len(self.registry)} detector(s)")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle a single client connection.

        Reads NDJSON requests and sends NDJSON responses.
        """
        async with self._semaphore:
            try:
                while True:
                    # Read one line (NDJSON)
                    try:
                        line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=30.0)
                    except TimeoutError:
                        logger.warning("Client timeout on read")
                        break
                    except asyncio.IncompleteReadError:
                        # EOF reached
                        break

                    if not line:
                        break

                    # Parse request
                    try:
                        request = json.loads(line.decode("utf-8").strip())
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON decode error: {e}")
                        response = {
                            "v": 1,
                            "verdict": "error",
                            "message": "Invalid JSON",
                        }
                        writer.write((json.dumps(response) + "\n").encode("utf-8"))
                        await writer.drain()
                        break

                    # Handle request
                    response = await self._handle_request(request)

                    # Send response
                    writer.write((json.dumps(response) + "\n").encode("utf-8"))
                    await writer.drain()

            except Exception as e:
                logger.error(f"Error handling client: {e}")
            finally:
                writer.close()
                await writer.wait_closed()

    async def _handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle a single request — single source of truth for request → response.

        For check operations, runs the pipeline once, updates session state, and
        writes a forensic incident + quarantined payload on block. For other
        operations (session.close, canary.list), returns the canned response.
        """
        try:
            version = request.get("v")
            operation = request.get("op")

            if version != 1:
                return {
                    "v": 1,
                    "verdict": "error",
                    "message": "Unsupported protocol version",
                }

            session_id = request.get("session_id", "anon")

            if operation in ("check.input", "check.output", "check.tool"):
                return await self._handle_check_operation(operation, request, session_id)

            if operation == "session.close":
                return {"v": 1, "verdict": "pass"}

            if operation == "canary.list":
                canaries: list[dict[str, Any]] = []
                if self.catalogue:
                    for entry in self.catalogue.active_canaries():
                        canaries.append(
                            {
                                "canary_id": entry.canary_id,
                                "kind": entry.kind,
                                "service": entry.service,
                                "active": True,
                            }
                        )
                return {"v": 1, "verdict": "pass", "canaries": canaries}

            return {
                "v": 1,
                "verdict": "error",
                "message": "unknown op",
            }

        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return {
                "v": 1,
                "verdict": "error",
                "message": str(e),
            }

    async def _handle_check_operation(self, operation: str, request: dict[str, Any], session_id: str) -> dict[str, Any]:
        """Handle a check operation (input/output/tool) end-to-end.

        Runs the pipeline once (awaited), updates session state, and on block
        writes a quarantined payload + forensic incident. This is the only path
        that exercises the pipeline; the previous duplicate (separate sync
        ``_handle_check_operation`` plus an async re-run in
        ``_handle_request_async``) was both buggy and double-cost.
        """
        try:
            payload_data = request.get("payload", {})

            if operation in ("check.input", "check.output"):
                text = payload_data.get("text", "")
                payload = Payload(text=text)
            elif operation == "check.tool":
                tool = payload_data.get("tool", "")
                params = payload_data.get("params", {})
                text = f"{tool} {json.dumps(params)}" if params else tool
                payload = Payload(text=text, tool=tool, params=params)
            else:
                return {"v": 1, "verdict": "error", "message": "Unknown operation"}

            ctx = SessionContext(session_id=session_id, signal_history=[])
            detectors = self.registry.all()
            verdict = await Pipeline.run(detectors, payload, ctx)

            response: dict[str, Any] = {
                "v": 1,
                "verdict": verdict.decision,
                "signal_id": verdict.signal_id,
                "message": verdict.message,
            }

            if self.session_store:
                await self.session_store.update_after_check(session_id, verdict)

            if verdict.blocked and self.forensic_logger and self.quarantine_store:
                quarantine_id = None
                try:
                    quarantine_id = await self.quarantine_store.write(payload.text)
                except Exception as e:
                    logger.warning(f"Failed to write quarantine: {e}")

                try:
                    incident_id = await self.forensic_logger.write_incident(
                        verdict, ctx, payload.text, quarantine_id=quarantine_id
                    )
                    response["incident_id"] = incident_id
                except Exception as e:
                    logger.error(f"Failed to write incident: {e}")

            return response

        except Exception as e:
            logger.error(f"Error handling check operation {operation}: {e}")
            return {
                "v": 1,
                "verdict": "error",
                "message": str(e),
            }

    async def start(self) -> None:
        """Start the daemon server.

        Raises:
            OSError: If socket directory is not writable
        """
        # Ensure socket directory exists and is writable
        socket_dir = os.path.dirname(self.socket_path)
        if not socket_dir:
            socket_dir = "."

        if not os.path.exists(socket_dir):
            raise OSError(f"Socket directory does not exist: {socket_dir}")

        if not os.access(socket_dir, os.W_OK):
            raise OSError(f"Socket directory is not writable: {socket_dir}")

        # Remove existing socket file
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.socket_path)

        # Initialize database and stores
        logger.info(f"Initializing database at {self.db_path}")
        await asyncio.to_thread(run_migrations, self.db_path)

        self.session_store = SessionStore(self.db_path)
        self.forensic_logger = ForensicLogger(self.db_path, catalogue=self.catalogue)
        self.quarantine_store = QuarantineStore(self.db_path, key_path=self.quarantine_key_path)

        # Start background sweeper task
        self._sweeper_task = start_sweeper(self.quarantine_store)
        logger.info("Started background sweeper task")

        # Create shutdown event
        self._shutdown_event = asyncio.Event()

        # Start the server
        logger.info(f"Starting daemon on {self.socket_path}")
        self._server = await asyncio.start_unix_server(self._handle_client, path=self.socket_path)

        logger.info(f"Daemon listening on {self.socket_path}")

    async def wait(self) -> None:
        """Wait for the shutdown event."""
        if self._shutdown_event:
            await self._shutdown_event.wait()

    def _shutdown(self) -> None:
        """Signal shutdown."""
        if self._shutdown_event:
            self._shutdown_event.set()

    async def stop(self) -> None:
        """Stop the daemon server."""
        # Cancel sweeper task
        if self._sweeper_task:
            self._sweeper_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sweeper_task

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # Remove socket file
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.socket_path)

        logger.info("Daemon stopped")

    async def run(self) -> None:
        """Run the daemon until shutdown signal.

        Registers SIGTERM/SIGINT handlers on the running event loop so the
        daemon can shut down cleanly when launched as a long-lived process.
        Tests that exercise start()/stop() directly skip this — they don't
        need signal handlers and registering them on a per-test event loop
        leaves dangling handlers that hang subsequent test loops.
        """
        try:
            await self.start()
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, self._shutdown)
            await self.wait()
        finally:
            await self.stop()
