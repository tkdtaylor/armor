"""Unix socket server for the armor daemon.

Handles NDJSON request/response protocol with concurrent client support.
"""

import asyncio
import contextlib
import fnmatch
import json
import logging
import os
import signal
import sys
import time
import tomllib
from collections import deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from armor.canaries._generate import sub_pattern_map
from armor.canaries.catalogue import Catalogue
from armor.canaries.scanner import CanaryScanner
from armor.daemon.honeypot_gate import should_invoke_honeypot
from armor.db.forensic import ForensicLogger
from armor.db.migrations import run_migrations
from armor.db.quarantine import QuarantineStore
from armor.db.session_store import SessionStore
from armor.db.sweeper import start_sweeper
from armor.detectors import DetectorRegistry
from armor.detectors.canary_scanner import CanaryScannerDetector
from armor.detectors.destination_extractor import DestinationExtractor
from armor.llm.session import LLMSession
from armor.pipeline import Pipeline
from armor.types import Payload, SessionContext, Source, Verdict

logger = logging.getLogger(__name__)

DEFAULT_DETECTOR_FILTERS: dict[str, list[str]] = {
    "check.input": ["*"],
    "check.output": ["*"],
    "check.tool": ["cmd_injection.*", "tool_param.*", "tool_rate.*", "tool_chain"],
}


def _duration_to_cutoff(value: object) -> str | None:
    """Return a SQLite UTC cutoff timestamp for duration strings like 30m or 1h."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("duration must be a non-empty string")

    raw = value.strip().lower()
    unit = raw[-1]
    magnitude_text = raw[:-1] if unit in {"s", "m", "h", "d"} else raw
    try:
        magnitude = int(magnitude_text)
    except ValueError as exc:
        raise ValueError(f"invalid duration {value!r}") from exc
    if magnitude < 0:
        raise ValueError("duration must be non-negative")

    if unit == "m":
        delta = timedelta(minutes=magnitude)
    elif unit == "h":
        delta = timedelta(hours=magnitude)
    elif unit == "d":
        delta = timedelta(days=magnitude)
    elif unit == "s" or unit.isdigit():
        delta = timedelta(seconds=magnitude)
    else:
        raise ValueError(f"unsupported duration unit {unit!r}")

    cutoff = datetime.now(UTC) - delta
    return cutoff.strftime("%Y-%m-%d %H:%M:%S")


class DaemonServer:
    """Asyncio-based Unix socket server for the armor daemon."""

    def __init__(
        self,
        socket_path: str,
        max_concurrent: int = 64,
        catalogue_path: str | None = None,
        canary_values_path: str | None = None,
        db_path: str | None = None,
        quarantine_key_path: str | None = None,
        config_path: str | None = None,
        model_path: str | None = None,
    ) -> None:
        """Initialize the daemon server.

        Args:
            socket_path: Path to the Unix socket to bind
            max_concurrent: Maximum number of concurrent connections
            catalogue_path: Path to canary catalogue JSON (legacy; for v0.1 backwards compat)
            canary_values_path: Path to canary values file (preferred for v0.2+)
            db_path: Path to SQLite database (default /var/lib/armor/armor.db)
            quarantine_key_path: Path to quarantine encryption key (default <db_dir>/.key)
            config_path: Path to armor.toml configuration file (optional)
            model_path: Path to validator LLM GGUF weights (optional; loads if ARMOR_DISABLE_LLM=false)

        Raises:
            ValueError: If catalogue is provided but invalid or empty.
            SystemExit: If catalogue validation fails (exit code 78) or model load fails (exit code 78).
        """
        self.socket_path = socket_path
        self.max_concurrent = max_concurrent
        self.active_connections = 0
        self._shutdown_event: asyncio.Event | None = None
        self._server: asyncio.Server | None = None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._start_time = time.time()
        self._total_checks = 0
        self._input_latencies_ms: deque[float] = deque(maxlen=512)
        self._output_latencies_ms: deque[float] = deque(maxlen=512)

        # Database paths
        self.db_path = db_path or "/var/lib/armor/armor.db"
        self.quarantine_key_path = quarantine_key_path

        # Database stores (initialized in start())
        self.session_store: SessionStore | None = None
        self.forensic_logger: ForensicLogger | None = None
        self.quarantine_store: QuarantineStore | None = None
        self._sweeper_task: asyncio.Task[None] | None = None

        # LLM session (loaded if ARMOR_DISABLE_LLM=false and model path exists/provided)
        self.llm_session: LLMSession | None = None
        disable_llm = os.environ.get("ARMOR_DISABLE_LLM", "false").lower() in ("true", "1", "yes")

        # Determine if we should load LLM:
        # - If ARMOR_DISABLE_LLM=true, skip loading
        # - If ARMOR_DISABLE_LLM=false or unset:
        #   - If model_path is explicitly provided, load it
        #   - If default /models/active.gguf exists, load it
        #   - Otherwise, skip (non-fatal)
        if not disable_llm and (model_path or Path("/models/active.gguf").exists()):
            effective_model_path = model_path or "/models/active.gguf"
            try:
                from armor.llm.loader import load_llm

                self.llm_session = load_llm(effective_model_path)
                logger.info("Validator LLM loaded successfully")
            except SystemExit:
                # load_llm exits with 78 on failure; propagate it
                raise

        # Load and validate canary catalogue if provided
        self.catalogue: Catalogue | None = None
        self.canary_scanner: CanaryScanner | None = None

        # Prefer canary_values_path (new v0.2+ model) over catalogue_path (v0.1 legacy)
        effective_catalogue_path = canary_values_path or catalogue_path

        if effective_catalogue_path:
            try:
                if canary_values_path:
                    # v0.2+ model: canary_values_path is a complete merged file
                    # (generated by 'armor canary generate' or similar)
                    self.catalogue = Catalogue.load(effective_catalogue_path)
                else:
                    # v0.1 legacy mode: catalogue_path might be a merged file or needs schema merge
                    # Try to load it directly first (works for merged files)
                    try:
                        self.catalogue = Catalogue.load(effective_catalogue_path)
                    except ValueError:
                        # If that fails, try to merge with bundled schema
                        from importlib import resources

                        schema_data = resources.files("armor").joinpath("canaries/default_catalogue.json").read_text()

                        # Write schema to temp file for loading
                        import tempfile

                        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
                            tf.write(schema_data)
                            schema_path = tf.name

                        try:
                            self.catalogue = Catalogue.load(schema_path, effective_catalogue_path)
                        finally:
                            os.unlink(schema_path)

                active_canaries = self.catalogue.active_canaries()

                if not active_canaries:
                    logger.error("Catalogue is empty (no active canaries)")
                    sys.exit(78)

                # Build canary value map for the scanner, then extend with sub-patterns
                # (email domain, distinctive middle names) that survive mild LLM reformatting.
                canary_map = {entry.canary_id: entry.value for entry in active_canaries}
                canary_map.update(sub_pattern_map())
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

        # Load configuration from armor.toml if provided
        self.config: dict[str, Any] = {}
        if config_path:
            try:
                with open(config_path, "rb") as f:
                    self.config = tomllib.load(f)
                logger.info(f"Loaded configuration from {config_path}")
            except FileNotFoundError:
                logger.warning(f"Configuration file not found: {config_path}")
            except Exception as e:
                logger.error(f"Failed to load configuration: {e}")

        # Load trusted source tools allowlist from config at daemon-init time (ADR-041)
        # Read once at daemon-init, not per-request
        self.trusted_source_tools: list[str] = []
        if self.config and "pipeline" in self.config and "fetched" in self.config["pipeline"]:
            fetched_config = self.config["pipeline"]["fetched"]
            trusted_tools = fetched_config.get("trusted_source_tools", [])
            if isinstance(trusted_tools, list):
                self.trusted_source_tools = trusted_tools
                logger.info("Loaded %d trusted source tool(s)", len(self.trusted_source_tools))

        # Load per-source multipliers from config (per ADR-041)
        if self.config and "pipeline" in self.config and "source_multipliers" in self.config["pipeline"]:
            from armor.pipeline import Pipeline

            multipliers = self.config["pipeline"]["source_multipliers"]
            Pipeline.set_source_multipliers(multipliers)
            logger.info("Loaded %d source multiplier override(s) from config", len(multipliers))

        self._detector_filters = self._load_detector_filters()

        # Check if we're running in an armor-development tree and emit advisory (per ADR-041 §5)
        cwd = Path.cwd()
        if (cwd / "src" / "armor").exists() and (cwd / "tests" / "eval" / "corpus").exists():
            logger.warning(
                "armor running from inside an armor-development tree. "
                "pipeline.exempt.read_paths defaults already cover tests/eval/corpus/, "
                "archive/, and similar research paths. Verify these are configured."
            )

        # Initialize detector registry
        self.registry = DetectorRegistry()

        # If we have a canary scanner, inject it into the detector
        if self.canary_scanner:
            detector = CanaryScannerDetector(scanner=self.canary_scanner)
            self.registry.detectors["canary.scanner"] = detector
            logger.info("Injected canary scanner detector")

        # Inject destination extractor with whitelist config
        whitelist = []
        if self.config and "destination_whitelist" in self.config:
            whitelist = self.config.get("destination_whitelist", [])
            if not isinstance(whitelist, list):
                logger.warning(f"destination_whitelist is not a list, ignoring: {type(whitelist)}")
                whitelist = []
        dest_extractor = DestinationExtractor(whitelist=whitelist)
        self.registry.detectors["extractor.destinations"] = dest_extractor
        logger.info(f"Injected destination extractor with {len(whitelist)} whitelisted destinations")

        # Inject instruction_burial detector with config
        from armor.detectors.instruction_burial import InstructionBurialDetector

        min_length_bytes = 4096
        tail_fraction = 0.25
        if self.config and "detector" in self.config and "instruction_burial" in self.config["detector"]:
            ib_config = self.config["detector"]["instruction_burial"]
            min_length_bytes = ib_config.get("min_length_bytes", 4096)
            tail_fraction = ib_config.get("tail_fraction", 0.25)
        instruction_burial = InstructionBurialDetector(
            min_length_bytes=min_length_bytes,
            tail_fraction=tail_fraction,
        )
        self.registry.detectors["meta.instruction_burial"] = instruction_burial
        logger.info(
            f"Injected instruction_burial detector (min_length_bytes={min_length_bytes}, tail_fraction={tail_fraction})"
        )

        # Inject conversation_hijack detector with config
        from armor.detectors.conversation_hijack import ConversationHijack

        unsupported_confidence = 0.7
        supported_confidence = 0.3
        if self.config and "detector" in self.config and "conversation_hijack" in self.config["detector"]:
            ch_config = self.config["detector"]["conversation_hijack"]
            unsupported_confidence = ch_config.get("unsupported_confidence", 0.7)
            supported_confidence = ch_config.get("supported_confidence", 0.3)
        conversation_hijack = ConversationHijack(
            unsupported_confidence=unsupported_confidence,
            supported_confidence=supported_confidence,
        )
        self.registry.detectors["meta.conversation_hijack"] = conversation_hijack
        logger.info(
            f"Injected conversation_hijack detector (unsupported_confidence={unsupported_confidence}, supported_confidence={supported_confidence})"
        )

        # Inject LLM session into detectors that depend on it (post-load loop, mechanism A)
        self._inject_llm_session()

        logger.info(f"Loaded {len(self.registry)} detector(s)")

    def _load_detector_filters(self) -> dict[str, list[str]]:
        """Load per-operation detector allowlists from `pipeline.*_detectors` config."""
        pipeline_config = self.config.get("pipeline", {}) if isinstance(self.config.get("pipeline", {}), dict) else {}
        config_keys = {
            "check.input": "input_detectors",
            "check.output": "output_detectors",
            "check.tool": "tool_detectors",
        }

        filters: dict[str, list[str]] = {}
        for operation, key in config_keys.items():
            default = DEFAULT_DETECTOR_FILTERS[operation]
            configured = pipeline_config.get(key, default)
            if not isinstance(configured, list) or not all(isinstance(item, str) for item in configured):
                logger.warning(f"pipeline.{key} must be a list of strings; using defaults")
                filters[operation] = list(default)
                continue
            filters[operation] = configured or list(default)
        return filters

    def _detectors_for_operation(self, operation: str) -> list[Any]:
        """Return detectors selected by the configured allowlist for the operation."""
        detectors = self.registry.all()
        patterns = self._detector_filters.get(operation)
        if not patterns or "*" in patterns:
            return detectors

        selected = [
            detector
            for detector in detectors
            if any(
                fnmatch.fnmatchcase(detector.id, pattern) or fnmatch.fnmatchcase(detector.category, pattern)
                for pattern in patterns
            )
        ]
        return selected

    def _inject_llm_session(self) -> None:
        """Inject LLM session into detectors that depend on it (post-load loop).

        Detectors that require an LLM session declare self._llm_session: LLMSession | None.
        This method (mechanism A) iterates all registered detectors and injects the loaded
        session if available. If a detector that requires the LLM is registered but no
        LLM was loaded (and ARMOR_DISABLE_LLM is not true), exits with code 78.

        Raises:
            SystemExit: If LLM-dependent detector is registered but no LLM available.
        """
        disable_llm = os.environ.get("ARMOR_DISABLE_LLM", "false").lower() in ("true", "1", "yes")

        # Detector IDs that require an LLM session
        llm_dependent_ids = {
            "llm.validator",
            "jailbreak.template",
        }

        # Check which LLM-dependent detectors are registered
        registered_llm_detectors = [detector for detector in self.registry.all() if detector.id in llm_dependent_ids]

        # Validate: if any LLM-dependent detector is registered but no LLM was loaded
        # and ARMOR_DISABLE_LLM is not true, this is a configuration error
        if registered_llm_detectors and not self.llm_session and not disable_llm:
            registered_ids = [d.id for d in registered_llm_detectors]
            logger.error(
                f"LLM-dependent detector(s) registered but no LLM session available: {registered_ids}. "
                f"Either load an LLM model or set ARMOR_DISABLE_LLM=true to skip these detectors."
            )
            sys.exit(78)

        # Inject the LLM session into all registered LLM-dependent detectors
        if self.llm_session:
            for detector in registered_llm_detectors:
                if hasattr(detector, "_llm_session"):
                    detector._llm_session = self.llm_session
                    logger.debug(f"Injected LLM session into detector {detector.id}")

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

            if operation in ("check.input", "check.output", "check.tool", "check.fetched"):
                started = time.perf_counter()
                response = await self._handle_check_operation(operation, request, session_id)
                elapsed_ms = (time.perf_counter() - started) * 1000
                self._record_check_metric(operation, elapsed_ms)
                return response

            if operation == "config.show":
                return await self._handle_config_show(request)

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

            if operation in ("incidents.list", "incidents.tail"):
                return await self._handle_incidents_list(request)

            if operation == "incidents.show":
                return await self._handle_incidents_show(request)

            if operation == "incidents.export":
                return await self._handle_incidents_export(request)

            if operation == "incident.get":
                return await self._handle_incident_get(request)

            if operation == "sessions.list":
                return await self._handle_sessions_list(request)

            if operation == "sessions.show":
                return await self._handle_sessions_show(request)

            if operation == "sessions.unblock":
                return await self._handle_sessions_unblock(request)

            if operation == "health.full":
                return await self._handle_health_full()

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

    def _record_check_metric(self, operation: str, elapsed_ms: float) -> None:
        """Record in-memory health metrics for completed check operations."""
        self._total_checks += 1
        if operation == "check.input":
            self._input_latencies_ms.append(elapsed_ms)
        elif operation == "check.output":
            self._output_latencies_ms.append(elapsed_ms)

    @staticmethod
    def _p95(samples: deque[float]) -> float | None:
        """Return nearest-rank P95 for a bounded in-memory sample window."""
        if not samples:
            return None
        ordered = sorted(samples)
        index = max(0, min(len(ordered) - 1, int(len(ordered) * 0.95 + 0.999999) - 1))
        return ordered[index]

    async def _handle_check_operation(self, operation: str, request: dict[str, Any], session_id: str) -> dict[str, Any]:
        """Handle a check operation (input/output/tool/fetched) end-to-end.

        Runs the pipeline once (awaited), updates session state, and on block
        writes a quarantined payload + forensic incident. This is the only path
        that exercises the pipeline.

        Per ADR-041, assigns Payload.source based on operation:
        - check.input → USER_INPUT
        - check.output → MODEL_OUTPUT
        - check.tool → TOOL_PARAMS
        - check.fetched → TOOL_RESULT_UNTRUSTED (default; can be overridden)

        For check.fetched, implements 4 KB chunking per ADR-033 when payload > chunk_size_bytes.
        """
        try:
            payload_data = request.get("payload", {})

            # Determine source and assign payload
            if operation == "check.input":
                text = payload_data.get("text", "")
                # Allow explicit source override for testing
                source = Source(payload_data.get("source", Source.USER_INPUT))
                payload = Payload(text=text, source=source)
            elif operation == "check.output":
                text = payload_data.get("text", "")
                # Allow explicit source override for testing
                source = Source(payload_data.get("source", Source.MODEL_OUTPUT))
                payload = Payload(text=text, source=source)
            elif operation == "check.tool":
                tool = payload_data.get("tool", "")
                params = payload_data.get("params", {})
                text = f"{tool} {json.dumps(params)}" if params else tool
                payload = Payload(text=text, tool=tool, params=params, source=Source.TOOL_PARAMS)
            elif operation == "check.fetched":
                text = payload_data.get("text", "")
                source_tool = payload_data.get("source_tool", "unknown")
                # Check if source_tool is in the trusted allowlist (case-sensitive match)
                # Trust upgrade: if tool is in allowlist, use TOOL_RESULT_TRUSTED (ADR-041)
                if source_tool in self.trusted_source_tools:
                    # Trust upgrade: source_tool is in allowlist
                    source = Source(payload_data.get("source", Source.TOOL_RESULT_TRUSTED))
                else:
                    # Default to TOOL_RESULT_UNTRUSTED
                    source = Source(payload_data.get("source", Source.TOOL_RESULT_UNTRUSTED))
                payload = Payload(text=text, source=source)
            else:
                return {"v": 1, "verdict": "error", "message": "Unknown operation"}

            # Build full SessionContext from session store
            ctx = await self._build_session_context(session_id)

            detectors = (
                self.registry.all() if operation == "check.fetched" else self._detectors_for_operation(operation)
            )

            # Special handling for check.fetched: implement 4 KB chunking (ADR-033)
            if operation == "check.fetched":
                verdict, chunk_index, chunk_metadata = await self._run_fetched_with_chunking(detectors, payload, ctx)
            else:
                verdict = await Pipeline.run(detectors, payload, ctx)
                chunk_index = None
                chunk_metadata = None

            # Honeypot invocation (B-011): check if honeypot should be invoked for check.output
            # Gate is invoked after static pipeline, and only for check.output operations
            if operation == "check.output" and should_invoke_honeypot(ctx, verdict):
                honeypot_verdict = await self._invoke_honeypot(payload, ctx)
                # If honeypot returns a non-pass verdict, use it instead of static verdict
                if honeypot_verdict.decision != "pass":
                    verdict = honeypot_verdict

            response: dict[str, Any] = {
                "v": 1,
                "verdict": verdict.decision,
                "signal_id": verdict.signal_id,
                "message": verdict.message,
            }

            if self.session_store:
                # Apply the verdict to the session state machine and persist atomically
                await self.session_store.apply_and_persist(session_id, verdict, self.config)

                # Append current check's payload to the rolling buffer for multi-turn detection
                if ctx.rolling_buffer is not None and payload.text:
                    # Use turn_id format: turn-{turn_count} for this check
                    turn_id = f"turn-{ctx.turn_count + 1}"
                    ctx.rolling_buffer.append(turn_id, payload.text)
                    # Persist the rolling buffer
                    await asyncio.to_thread(self.session_store.save_rolling_buffer, session_id, ctx.rolling_buffer)

            if verdict.blocked and self.forensic_logger and self.quarantine_store:
                quarantine_id = None
                try:
                    quarantine_id = await self.quarantine_store.write(payload.text)
                except Exception as e:
                    logger.warning(f"Failed to write quarantine: {e}")

                try:
                    # For check.fetched, add source_tool, chunk_index, and chunk_metadata to incident details
                    incident_details = dict(verdict.details) if verdict.details else {}
                    if operation == "check.fetched":
                        source_tool = payload_data.get("source_tool", "unknown")
                        incident_details["source_tool"] = source_tool
                        if chunk_index is not None:
                            incident_details["chunk_index"] = chunk_index
                        if chunk_metadata is not None:
                            incident_details["chunk_metadata"] = chunk_metadata

                    # Update verdict with modified details
                    verdict_with_details = Verdict(
                        decision=verdict.decision,
                        signal_id=verdict.signal_id,
                        severity=verdict.severity,
                        message=verdict.message,
                        details=incident_details,
                    )

                    # Pass source to forensic logger for category inference
                    source_str = str(payload.source)

                    incident_id = await self.forensic_logger.write_incident(
                        verdict_with_details, ctx, payload.text, quarantine_id=quarantine_id, source=source_str
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

    async def _invoke_honeypot(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Invoke the honeypot LLM and scan its response for canaries (B-011).

        Calls the honeypot LLM with a system prompt containing active canary values,
        receives a response (expected to contain canary credentials), and pipes the
        response through the canary scanner detector to detect canary leaks.

        Per B-011 and ADR-021, the honeypot's response is evaluated by the same
        canary_scanner that audits real output — if the honeypot response contains
        a canary value, it returns block + canary_id.

        Args:
            payload: The original payload (user input that triggered the injection attempt).
            ctx: The SessionContext with active canaries for substitution.

        Returns:
            Verdict: The verdict from scanning the honeypot response (block if canary leaked,
                    pass if honeypot generated no response or canary not detected).
        """
        from armor.llm.honeypot import respond

        # If no catalogue, return pass (honeypot requires canary catalogue)
        if not self.catalogue:
            logger.warning("Honeypot invoked but no canary catalogue available")
            return Verdict(
                decision="pass",
                signal_id="",
                severity="low",
                message="Canary catalogue unavailable",
                details={},
            )

        # Invoke honeypot LLM (safe to call with llm_session=None; returns empty string)
        honeypot_response = respond(
            text=payload.text,
            session_context=ctx,
            catalogue=self.catalogue,
            llm_session=self.llm_session,
            budget_ms=None,  # Uses default from llm_session if available
            active_canaries=ctx.active_canaries,  # Per-check active subset (ADR-038)
        )

        # If honeypot returned no response, return pass (soft-fail path)
        if not honeypot_response:
            return Verdict(
                decision="pass",
                signal_id="",
                severity="low",
                message="Honeypot LLM returned empty response",
                details={},
            )

        # Create a synthetic payload with the honeypot's response
        honeypot_payload = Payload(
            text=honeypot_response,
            source=Source.MODEL_OUTPUT,  # Honeypot output is model-like
        )

        # Scan the honeypot response with the canary scanner
        # Get the canary scanner detector from the registry
        canary_scanner_detector = self.registry.get("canary.scanner")
        if canary_scanner_detector and hasattr(canary_scanner_detector, "check"):
            verdict = canary_scanner_detector.check(honeypot_payload, ctx)
        else:
            # Fallback: no canary scanner (should not happen in production)
            logger.warning("Honeypot invoked but canary scanner not available")
            verdict = Verdict(
                decision="pass",
                signal_id="",
                severity="low",
                message="Canary scanner unavailable",
                details={},
            )

        return verdict

    async def _run_fetched_with_chunking(
        self,
        detectors: list[Any],
        payload: Payload,
        ctx: SessionContext,
    ) -> tuple[Verdict, int | None, dict[str, Any] | None]:
        """Run the pipeline on a fetched payload with 4 KB chunking (ADR-033).

        Splits the payload into non-overlapping 4 KB chunks, runs the pipeline
        on each chunk, and returns the first non-pass verdict. Records chunk metadata
        (indices run, indices skipped due to early termination, etc.).

        Args:
            detectors: Detector list.
            payload: The Payload (text is the fetched content).
            ctx: SessionContext.

        Returns:
            Tuple of (verdict, chunk_index, chunk_metadata).
            - verdict: The first blocking verdict, or pass if all chunks pass.
            - chunk_index: The 0-based index of the chunk that produced the verdict (None if no chunking).
            - chunk_metadata: A dict with keys:
              - additional_chunks: list of indices that were either skipped (due to early termination)
                                  or ran but didn't trip.
              - chunks_skipped: list of indices that were not processed (hard cap).
        """
        text = payload.text
        text_bytes = text.encode("utf-8")

        # Get chunk size from config (default 4096)
        chunk_size_bytes = 4096
        if self.config and "pipeline" in self.config and "fetched" in self.config["pipeline"]:
            chunk_size_bytes = self.config["pipeline"]["fetched"].get("chunk_size_bytes", 4096)

        # If payload fits in one chunk, run once (no chunking active)
        if len(text_bytes) <= chunk_size_bytes:
            verdict = await Pipeline.run(detectors, payload, ctx)
            return (verdict, None, None)

        # Chunking active: split into tiled (non-overlapping) 4 KB windows
        chunks: list[str] = []
        offset = 0
        while offset < len(text_bytes):
            end = min(offset + chunk_size_bytes, len(text_bytes))
            # Decode the chunk (may have partial UTF-8 sequences at boundaries)
            try:
                chunk_text = text_bytes[offset:end].decode("utf-8")
            except UnicodeDecodeError:
                # Backtrack to find a valid UTF-8 boundary
                for i in range(end - 1, offset, -1):
                    try:
                        chunk_text = text_bytes[offset:i].decode("utf-8")
                        end = i
                        break
                    except UnicodeDecodeError:
                        pass
                else:
                    # If we can't find a boundary, skip this chunk
                    chunk_text = ""
                    end = offset + 1

            if chunk_text:
                chunks.append(chunk_text)
            offset = end

        # Hard cap at 16 chunks (~64 KB max processed per check.fetched)
        hard_cap = 16
        chunks_skipped_indices: list[int] = []
        if len(chunks) > hard_cap:
            chunks_skipped_indices = list(range(hard_cap, len(chunks)))
            chunks = chunks[:hard_cap]

        # Run pipeline on each chunk until first hit
        winning_verdict: Verdict | None = None
        winning_chunk_index: int | None = None
        additional_chunks_set: set[int] = set()

        for idx, chunk_text in enumerate(chunks):
            chunk_payload = Payload(text=chunk_text, source=payload.source)
            verdict = await Pipeline.run(detectors, chunk_payload, ctx)

            if verdict.decision != "pass":
                # First hit wins
                winning_verdict = verdict
                winning_chunk_index = idx
                # Record all subsequent chunks as skipped (not run)
                for skip_idx in range(idx + 1, len(chunks)):
                    additional_chunks_set.add(skip_idx)
                break
            else:
                # This chunk passed; record it as checked but didn't trip
                additional_chunks_set.add(idx)

        # If no verdict hit but we ran all chunks, return pass
        if winning_verdict is None:
            winning_verdict = Verdict(
                decision="pass",
                signal_id="",
                severity="low",
                message="All chunks passed",
                details={},
            )

        # Build chunk_metadata dict
        chunk_metadata = {}
        if winning_chunk_index is not None or len(chunks) > 1:
            # Only populate if chunking was active
            sorted_additional = sorted(additional_chunks_set)
            chunk_metadata["additional_chunks"] = sorted_additional
            if chunks_skipped_indices:
                chunk_metadata["chunks_skipped"] = chunks_skipped_indices

        return (winning_verdict, winning_chunk_index, chunk_metadata if chunk_metadata else None)

    async def _build_session_context(self, session_id: str) -> SessionContext:
        """Build a full SessionContext from persisted session state.

        Loads the session from the store (or creates if new), populates the rolling buffer,
        retrieves the FSM state, turn count, and computes the active canaries per activation rules.

        Args:
            session_id: The session ID.

        Returns:
            SessionContext with all fields populated from session store and catalogue.

        Raises:
            ValueError: If the persisted state string is not a valid SessionState value.
        """
        from armor.session.state_machine import SessionState
        from armor.types import Signal

        # Get or create the session
        if self.session_store is None:
            # Fallback: no session store, return minimal context
            return SessionContext(
                session_id=session_id,
                signal_history=[],
                state=None,
                rolling_buffer=None,
                turn_count=0,
                active_canaries=[],
            )

        session_row = await self.session_store.get_or_create(session_id)

        # Coerce persisted state string to SessionState enum
        # Raises ValueError on unknown state (fail loudly)
        try:
            state_enum: SessionState | None = SessionState(session_row.current_state)
        except ValueError as e:
            raise ValueError(
                f"Invalid session state '{session_row.current_state}' for session {session_id}: {e}"
            ) from e

        # Load rolling buffer from DB
        rolling_buffer = await asyncio.to_thread(self.session_store.load_rolling_buffer, session_id)

        # Convert signal_history to Signal objects
        signal_list: list[Signal] = []
        for sig_dict in session_row.signal_history:
            ts_val = sig_dict.get("ts", 0.0)
            kind_val = sig_dict.get("kind", "")
            signal_id_val = sig_dict.get("signal_id", "")
            severity_val = sig_dict.get("severity", "low")

            signal_list.append(
                Signal(
                    timestamp=(ts_val if isinstance(ts_val, (int, float)) else 0.0),
                    kind=(kind_val if isinstance(kind_val, str) else ""),
                    signal_id=(signal_id_val if isinstance(signal_id_val, str) else ""),
                    severity=(severity_val if isinstance(severity_val, str) else "low"),
                )
            )

        # Get active canaries based on activation rules
        active_canaries = []
        if self.catalogue:
            # Create a temporary context just for evaluating activation rules
            temp_ctx = SessionContext(
                session_id=session_id,
                signal_history=signal_list,
                state=state_enum,
                rolling_buffer=rolling_buffer,
                turn_count=session_row.turn_count,
                active_canaries=[],
            )
            active_canaries = self.catalogue.active_for(temp_ctx, now=datetime.now(UTC))

        # Build and return the full context
        return SessionContext(
            session_id=session_id,
            signal_history=signal_list,
            state=state_enum,
            rolling_buffer=rolling_buffer,
            turn_count=session_row.turn_count,
            active_canaries=active_canaries,
        )

    async def _handle_config_show(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle config.show operation — expose runtime config to hooks.

        Payload:
          - section: str, the config section to show (e.g., "pipeline.exempt", "pipeline.source_multipliers")

        Returns NDJSON response with the requested section's config.
        """
        try:
            payload = request.get("payload", {})
            section = payload.get("section", "")

            if not section:
                return {
                    "v": 1,
                    "verdict": "error",
                    "message": "section is required",
                }

            # Parse the section path (e.g., "pipeline.exempt" → config["pipeline"]["exempt"])
            parts = section.split(".")
            config_value = self.config

            for part in parts:
                if isinstance(config_value, dict) and part in config_value:
                    config_value = config_value[part]
                else:
                    return {
                        "v": 1,
                        "verdict": "error",
                        "message": f"Section not found: {section}",
                    }

            return {
                "v": 1,
                "verdict": "pass",
                "config": config_value,
            }

        except Exception as e:
            logger.error(f"Error handling config.show: {e}")
            return {
                "v": 1,
                "verdict": "error",
                "message": str(e),
            }

    async def _handle_incidents_list(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return paginated incidents matching the request's filters.

        Payload fields (all optional except `limit`):
          - limit: int, page size (default 50)
          - session_id: str, restrict to one session
          - category: str glob (e.g. `direct_injection.*`)
          - since_id: int, return only incidents with `id > since_id`
          - since: str duration (e.g. `1h`, `30m`)
          - severity: str, restrict to one severity
        """
        if self.forensic_logger is None:
            return {"v": 1, "verdict": "error", "message": "forensic store unavailable"}

        payload = request.get("payload") or {}
        limit = payload.get("limit") or 50
        try:
            limit_int = max(1, min(int(limit), 1000))
        except (TypeError, ValueError):
            limit_int = 50

        session_id = payload.get("session_id") or None
        category = payload.get("category") or None
        since_id = payload.get("since_id")
        severity = payload.get("severity") or None
        try:
            since_ts = _duration_to_cutoff(payload.get("since"))
        except ValueError as exc:
            return {"v": 1, "verdict": "error", "message": str(exc)}

        rows = await asyncio.to_thread(
            self.forensic_logger.list_incidents,
            limit=limit_int,
            session_id=session_id if isinstance(session_id, str) else None,
            category=category if isinstance(category, str) else None,
            since_id=since_id if isinstance(since_id, int) else None,
            since_ts=since_ts,
            severity=severity if isinstance(severity, str) else None,
        )
        logger.info(
            "incidents.list served",
            extra={"event": "incidents.list", "decision": "pass", "session_id": session_id or ""},
        )
        return {"v": 1, "verdict": "pass", "incidents": rows}

    async def _handle_incidents_show(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return one incident by `incident_id` (CLI form)."""
        payload = request.get("payload") or {}
        incident_id = payload.get("incident_id") or payload.get("id")
        return await self._fetch_incident(incident_id)

    async def _handle_incident_get(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return one incident by `id` (SDK form)."""
        payload = request.get("payload") or {}
        incident_id = payload.get("id") or payload.get("incident_id")
        return await self._fetch_incident(incident_id)

    async def _fetch_incident(self, incident_id: object) -> dict[str, Any]:
        if self.forensic_logger is None:
            return {"v": 1, "verdict": "error", "message": "forensic store unavailable"}
        row = await asyncio.to_thread(self.forensic_logger.get_incident, incident_id)
        logger.info(
            "incidents.show served",
            extra={"event": "incidents.show", "decision": "pass" if row else "miss"},
        )
        return {"v": 1, "verdict": "pass", "incident": row}

    async def _handle_incidents_export(self, request: dict[str, Any]) -> dict[str, Any]:
        """Export incidents matching filters as NDJSON.

        Payload fields (all optional):
          - since: str, duration (e.g., 1h, 30m)
          - session_id: str, restrict to one session
          - severity: str, filter by severity level
        """
        if self.forensic_logger is None:
            return {"v": 1, "verdict": "error", "message": "forensic store unavailable"}

        payload = request.get("payload") or {}
        session_id = payload.get("session_id") or None
        severity = payload.get("severity") or None
        try:
            since_ts = _duration_to_cutoff(payload.get("since"))
        except ValueError as exc:
            return {"v": 1, "verdict": "error", "message": str(exc)}

        rows = await asyncio.to_thread(
            self.forensic_logger.list_incidents,
            limit=100000,
            session_id=session_id if isinstance(session_id, str) else None,
            category=None,
            since_id=None,
            since_ts=since_ts,
            severity=severity if isinstance(severity, str) else None,
        )

        logger.info(
            "incidents.export served",
            extra={
                "event": "incidents.export",
                "decision": "pass",
                "session_id": session_id or "",
                "count": len(rows),
            },
        )
        return {"v": 1, "verdict": "pass", "incidents": rows}

    async def _handle_sessions_list(self, request: dict[str, Any]) -> dict[str, Any]:
        if self.session_store is None:
            return {"v": 1, "verdict": "error", "message": "session store unavailable"}
        payload = request.get("payload") or {}
        state = payload.get("state") or None
        rows = await asyncio.to_thread(self.session_store.list_sessions, state)
        logger.info(
            "sessions.list served",
            extra={"event": "sessions.list", "decision": "pass"},
        )
        return {"v": 1, "verdict": "pass", "sessions": rows}

    async def _handle_sessions_show(self, request: dict[str, Any]) -> dict[str, Any]:
        if self.session_store is None:
            return {"v": 1, "verdict": "error", "message": "session store unavailable"}
        payload = request.get("payload") or {}
        session_id = payload.get("session_id")
        if not session_id:
            return {"v": 1, "verdict": "error", "message": "session_id required"}
        row = await asyncio.to_thread(self.session_store.get_session_view, session_id)
        logger.info(
            "sessions.show served",
            extra={"event": "sessions.show", "session_id": session_id, "decision": "pass" if row else "miss"},
        )
        return {"v": 1, "verdict": "pass", "session": row}

    async def _handle_sessions_unblock(self, request: dict[str, Any]) -> dict[str, Any]:
        """Atomically clear `Blocked` and write an `OperatorAuditLog` row."""
        from armor.session.state_machine import InvalidStateTransition, clear_blocked

        if self.session_store is None:
            return {"v": 1, "verdict": "error", "message": "session store unavailable"}

        payload = request.get("payload") or {}
        session_id = payload.get("session_id")
        reason = payload.get("reason") or ""
        actor = payload.get("actor") or os.environ.get("USER") or "operator"

        if not session_id:
            return {"v": 1, "verdict": "error", "message": "session_id required"}
        if not reason or not str(reason).strip():
            return {"v": 1, "verdict": "error", "message": "reason required"}

        try:
            new_state = await asyncio.to_thread(clear_blocked, session_id, actor, str(reason), db_path=self.db_path)
        except InvalidStateTransition as e:
            logger.warning(
                "sessions.unblock rejected",
                extra={"event": "sessions.unblock", "session_id": session_id, "decision": "error"},
            )
            return {"v": 1, "verdict": "error", "message": str(e)}
        except ValueError as e:
            return {"v": 1, "verdict": "error", "message": str(e)}

        # Invalidate any cached session row so subsequent reads see the new state.
        self.session_store._cache.pop(session_id, None)
        if session_id in self.session_store._cache_access_order:
            self.session_store._cache_access_order.remove(session_id)

        logger.info(
            "sessions.unblock served",
            extra={
                "event": "sessions.unblock",
                "session_id": session_id,
                "decision": "pass",
            },
        )
        return {"v": 1, "verdict": "pass", "new_state": new_state.value}

    async def _handle_health_full(self) -> dict[str, Any]:
        """Return the expanded health report consumed by `armor health`."""
        socket_reachable = self._server is not None
        db_reachable = False
        if self.db_path:
            try:
                import sqlite3 as _sql

                conn = _sql.connect(self.db_path)
                conn.execute("SELECT 1").fetchone()
                conn.close()
                db_reachable = True
            except Exception:
                db_reachable = False

        from armor import __version__

        uptime = max(0, int(time.time() - self._start_time))
        health: dict[str, Any] = {
            "socket_reachable": socket_reachable,
            "db_reachable": db_reachable,
            "model_loaded": self.llm_session is not None,
            "version": __version__,
            "uptime_seconds": uptime,
            "active_connections": self.active_connections,
            "max_concurrent": self.max_concurrent,
            "total_checks": self._total_checks,
        }
        p95_input = self._p95(self._input_latencies_ms)
        if p95_input is not None:
            health["p95_input_latency_ms"] = p95_input
        p95_output = self._p95(self._output_latencies_ms)
        if p95_output is not None:
            health["p95_output_latency_ms"] = p95_output

        return {
            "v": 1,
            "verdict": "pass",
            "health": health,
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

        # Log cold-start time
        elapsed_ms = int((time.time() - self._start_time) * 1000)
        logger.info(f"armor daemon cold-start: {elapsed_ms} ms")

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
