"""Detector for tool call sequence attack chains.

Detects multi-turn attack patterns where a sequence of tool calls matches
known chains (e.g., Read .env → WebFetch external host). Chains are defined
in tool_chains.yaml and optionally extended via user_chains_path config.

Per-session state tracks recent tool calls (timestamp, tool_name, params_summary).
On each check.tool call, the detector checks if the current call extends any
partial chain match. When a full chain matches, the chain's verdict (advisory
or block) is returned with signal_id = "meta.tool_chain:<chain_id>".

Blocked tool calls do NOT advance chain matches (per ADR-040 Q5).
"""

import logging
import re
import time
from collections import defaultdict
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from armor.types import Payload, SessionContext, Verdict

logger = logging.getLogger(__name__)

# Type aliases
ChainDict = dict[str, Any]
StepDict = dict[str, Any]
ToolCallRecord = dict[str, Any]

# Global per-session tool-call history:
# dict[session_id, list[ToolCallRecord]]
# Each record: {timestamp, tool, params_summary}
_session_histories: dict[str, list[ToolCallRecord]] = defaultdict(list)

# Global per-session partial match state:
# dict[session_id, dict[chain_id, (step_index, last_match_history_index)]]
# Tracks the furthest step matched and the history index of the last matching call
_session_chain_states: dict[str, dict[str, tuple[int, int]]] = defaultdict(lambda: defaultdict(lambda: (0, -1)))


class ToolChain:
    """Detector for tool-call sequence attack chains.

    Tracks per-session tool-call history and matches sequences against
    a catalogue of known attack chains. Supports both strict (consecutive)
    and loose (window-based) matching.

    Attributes:
        id: Detector identifier.
        category: Attack category ("meta" for system-level).
        cost_tier: "static" (in-memory, no ML).
        chains: List of chain definitions loaded from YAML.
        history_depth: Max tool calls to retain per session.
        window_turns: Max turns between consecutive chain steps (loose mode).
    """

    id: str = "meta.tool_chain"
    category: str = "meta"
    cost_tier: str = "static"

    def __init__(
        self,
        history_depth: int = 20,
        window_turns: int = 5,
        user_chains_path: str | None = None,
    ) -> None:
        """Initialize the tool-chain detector.

        Args:
            history_depth: Max number of recent tool calls to retain per session (default 20).
            window_turns: Max turns between consecutive chain steps in loose mode (default 5).
            user_chains_path: Path to an optional user-provided chains YAML file.
                             Format identical to tool_chains.yaml.
        """
        self.history_depth = history_depth
        self.window_turns = window_turns
        self.chains = self._load_chains(user_chains_path)

    @staticmethod
    def _load_chains(user_chains_path: str | None = None) -> list[ChainDict]:
        """Load and parse chains from bundled and optional user YAML files.

        Args:
            user_chains_path: Path to optional user-provided chains file.

        Returns:
            List of chain dicts with compiled step patterns.

        Raises:
            FileNotFoundError: If pattern file is not found.
            ValueError: If pattern file is malformed.
        """
        chains: list[ChainDict] = []

        # Load bundled chains
        try:
            chain_data = resources.files("armor").joinpath("detectors/tool_chains.yaml").read_text()
        except (AttributeError, TypeError, FileNotFoundError):
            # Fallback: try to load directly from filesystem (development)
            chain_file = Path(__file__).parent / "tool_chains.yaml"
            try:
                with open(chain_file) as f:
                    chain_data = f.read()
            except FileNotFoundError as e:
                raise FileNotFoundError(f"Bundled chain file not found: {chain_file}") from e

        # Parse YAML
        try:
            chains_raw = yaml.safe_load(chain_data)
        except yaml.YAMLError as e:
            raise ValueError(f"Malformed YAML in tool_chains.yaml: {e}") from e

        if not isinstance(chains_raw, list):
            raise ValueError("Chain file must be a YAML list of chain dicts")

        # Validate and process bundled chains
        for idx, chain_dict in enumerate(chains_raw):
            if not isinstance(chain_dict, dict):
                raise ValueError(f"Chain {idx} is not a dict: {type(chain_dict)}")

            chain = ToolChain._validate_and_process_chain(chain_dict, idx)
            chains.append(chain)

        # Load and merge user chains if provided
        if user_chains_path:
            try:
                with open(user_chains_path) as f:
                    user_chain_data = f.read()
            except FileNotFoundError:
                logger.warning(f"User chains file not found: {user_chains_path}")
                return chains

            try:
                user_chains_raw = yaml.safe_load(user_chain_data)
            except yaml.YAMLError as e:
                logger.warning(f"Malformed YAML in user chains file: {e}")
                return chains

            if isinstance(user_chains_raw, list):
                for idx, chain_dict in enumerate(user_chains_raw):
                    if not isinstance(chain_dict, dict):
                        logger.warning(f"User chain {idx} is not a dict: {type(chain_dict)}")
                        continue

                    try:
                        chain = ToolChain._validate_and_process_chain(chain_dict, idx)
                        chains.append(chain)
                    except ValueError as e:
                        logger.warning(f"Skipping invalid user chain {idx}: {e}")

        return chains

    @staticmethod
    def _validate_and_process_chain(chain_dict: ChainDict, idx: int) -> ChainDict:
        """Validate and compile a chain definition.

        Args:
            chain_dict: Raw chain dict from YAML.
            idx: Index in the chain list (for error messages).

        Returns:
            Processed chain dict with compiled regex patterns.

        Raises:
            ValueError: If chain is missing required keys or has invalid values.
        """
        required_keys = ["id", "description", "strictness", "verdict", "steps"]
        for key in required_keys:
            if key not in chain_dict:
                raise ValueError(f"Chain {idx} missing required key '{key}': {chain_dict}")

        chain_id = chain_dict["id"]
        strictness = chain_dict.get("strictness", "strict")
        verdict = chain_dict.get("verdict", "advisory")

        if strictness not in ("strict", "loose"):
            raise ValueError(f"Chain {chain_id} has invalid strictness '{strictness}', expected 'strict' or 'loose'")

        if verdict not in ("block", "advisory"):
            raise ValueError(f"Chain {chain_id} has invalid verdict '{verdict}', expected 'block' or 'advisory'")

        steps = chain_dict.get("steps", [])
        if not isinstance(steps, list) or len(steps) == 0:
            raise ValueError(f"Chain {chain_id} has empty or invalid steps list")

        # Compile regex patterns in each step's params_match
        processed_steps: list[StepDict] = []
        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ValueError(f"Chain {chain_id} step {step_idx} is not a dict: {type(step)}")

            if "tool" not in step:
                raise ValueError(f"Chain {chain_id} step {step_idx} missing 'tool' key")

            tool = step["tool"]
            params_match = step.get("params_match", {})

            # Compile regex patterns
            compiled_params_match = {}
            for param_key, pattern_str in params_match.items():
                try:
                    compiled_pattern = re.compile(pattern_str, re.MULTILINE | re.IGNORECASE)
                    compiled_params_match[param_key] = compiled_pattern
                except re.error as e:
                    raise ValueError(
                        f"Chain {chain_id} step {step_idx} param '{param_key}' has invalid regex: {e}"
                    ) from e

            processed_steps.append(
                {
                    "tool": tool,
                    "params_match": compiled_params_match,
                }
            )

        # Return processed chain with compiled patterns
        return {
            "id": chain_id,
            "description": chain_dict.get("description", ""),
            "strictness": strictness,
            "verdict": verdict,
            "steps": processed_steps,
        }

    def check(
        self,
        payload: Payload,
        ctx: SessionContext,
        now_fn: Callable[[], float] | None = None,
    ) -> Verdict:
        """Check a tool-call payload against the chain catalogue.

        Args:
            payload: The payload being checked (should have tool name and params).
            ctx: Session context (includes session_id).
            now_fn: Callable to get current time (for testing). Defaults to time.time.

        Returns:
            Block verdict if a chain matches and verdict is "block",
            advisory verdict if a chain matches and verdict is "advisory",
            pass otherwise.
        """
        try:
            if now_fn is None:
                now_fn = time.time

            try:
                now = now_fn()
            except Exception as e:
                logger.error(f"Error calling now_fn: {e}")
                now = time.time()

            # Extract tool name and params
            tool_name = payload.tool
            if not tool_name or not isinstance(tool_name, str) or not tool_name.strip():
                return Verdict.pass_verdict(message="No tool specified")

            # Get the call history for this session
            history = _session_histories[ctx.session_id]

            # Get the chain state for this session
            chain_state = _session_chain_states[ctx.session_id]

            params_summary = self._summarize_params(payload.params or {})

            # Check all chains to see if this call advances any partial matches
            matched_chain: ChainDict | None = None

            for chain in self.chains:
                chain_id = chain["id"]
                strictness = chain["strictness"]
                steps = chain["steps"]

                # Get current match state: (step_index, history_index_of_last_match)
                current_step, last_match_idx = chain_state[chain_id]

                # If we already matched this chain, skip it
                # (don't re-fire the same chain repeatedly)
                if current_step >= len(steps):
                    continue

                # Check if the current call (at history index len(history))
                # matches the next expected step
                next_step = steps[current_step]
                if self._step_matches(next_step, tool_name, payload.params or {}):
                    # Check window constraint
                    current_history_idx = len(history)
                    if self._check_window_constraint(current_history_idx, last_match_idx, strictness):
                        # Advance the chain match
                        chain_state[chain_id] = (current_step + 1, current_history_idx)

                        # Check if this completes the chain
                        if current_step + 1 >= len(steps):
                            # Full chain match!
                            matched_chain = chain
                            break

            # Record the current call in history (unconditionally, for forensics)
            history.append(
                {
                    "timestamp": now,
                    "tool": tool_name,
                    "params_summary": params_summary,
                }
            )

            # Trim history to depth
            while len(history) > self.history_depth:
                history.pop(0)
                # Also need to adjust all last_match_idx values when we trim
                for chain_id in chain_state:
                    step_idx, last_match_idx = chain_state[chain_id]
                    if last_match_idx >= 0:
                        chain_state[chain_id] = (step_idx, max(-1, last_match_idx - 1))

            # If a chain matched, return the appropriate verdict
            if matched_chain:
                chain_id = matched_chain["id"]
                verdict_type = matched_chain["verdict"]
                severity = "critical" if verdict_type == "block" else "medium"

                # Build chain_steps for forensic details
                chain_steps = []
                steps_list = matched_chain["steps"]
                # Get the last N calls from history that match the chain
                for step_idx, step in enumerate(steps_list):
                    # Reconstruct the matching call from history
                    # We'll include tool name and a params summary
                    chain_steps.append(
                        {
                            "step": step_idx + 1,
                            "tool": step["tool"],
                            "params_keys": list(step["params_match"].keys()),
                        }
                    )

                signal_id = f"{self.id}:{chain_id}"

                if verdict_type == "block":
                    return Verdict.block_verdict(
                        signal_id=signal_id,
                        message="Input blocked by armor.",
                        severity=severity,  # type: ignore
                        details={
                            "chain_id": chain_id,
                            "chain_description": matched_chain["description"],
                            "chain_steps": chain_steps,
                        },
                    )
                else:  # advisory
                    return Verdict.advisory_verdict(
                        signal_id=signal_id,
                        severity=severity,  # type: ignore
                        message=f"Detected suspicious tool call sequence: {matched_chain['description']}",
                        details={
                            "chain_id": chain_id,
                            "chain_description": matched_chain["description"],
                            "chain_steps": chain_steps,
                        },
                    )

            # No chain matched
            return Verdict.pass_verdict()

        except Exception as e:
            logger.error(f"Tool-chain detector error: {e}", exc_info=True)
            return Verdict.error_verdict(
                reason=f"Tool-chain detector error: {e!s}",
                details={"detector_id": self.id, "error": str(e)},
            )

    def _step_matches(self, step: StepDict, tool_name: str, params: dict[str, Any]) -> bool:
        """Check if a tool call matches a step pattern.

        Args:
            step: Step definition with tool name and params_match patterns.
            tool_name: Name of the tool being checked.
            params: Parameters of the tool call.

        Returns:
            True if the tool and all params_match patterns match, False otherwise.
        """
        # Check tool name
        if step["tool"] != tool_name:
            return False

        # Check all params_match patterns
        params_match = step["params_match"]
        for param_key, compiled_pattern in params_match.items():
            param_value = params.get(param_key, "")
            # Convert to string for matching
            param_str = str(param_value) if param_value is not None else ""

            if not compiled_pattern.search(param_str):
                return False

        return True

    def _check_window_constraint(self, current_idx: int, last_match_idx: int, strictness: str) -> bool:
        """Check if the current call is within the allowed window of the last match.

        Args:
            current_idx: Index of the current call in history (len(history) before append).
            last_match_idx: Index of the last matching call in history (-1 if no prior match).
            strictness: "strict" or "loose".

        Returns:
            True if the window constraint is satisfied, False otherwise.
        """
        # If no prior match, always allow
        if last_match_idx < 0:
            return True

        # Distance between current and last match
        distance = current_idx - last_match_idx

        if strictness == "strict":
            # In strict mode, current must immediately follow (distance == 1)
            return distance == 1
        else:  # loose
            # In loose mode, allow within window_turns
            # distance == 1 means consecutive, distance == 2 means one call between them
            # window_turns == 5 means we can have up to 4 calls in between (distance up to 5)
            return distance <= self.window_turns

    def _summarize_params(self, params: dict[str, Any]) -> str:
        """Summarize tool parameters for forensic logging (no sensitive data).

        Args:
            params: Tool parameters.

        Returns:
            String summary of parameters.
        """
        if not params:
            return ""

        items = []
        for key, value in params.items():
            val_str = value[:50] + ("..." if len(value) > 50 else "") if isinstance(value, str) else str(value)[:50]
            items.append(f"{key}={val_str}")

        return ", ".join(items)
