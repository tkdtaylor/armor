"""Command-line interface for the armor daemon and tools."""

import argparse
import json
import logging
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from armor import __version__
from armor.canaries._generate import write_values_file
from armor.client import DaemonClient, DaemonUnreachableError
from armor.daemon.__main__ import main as daemon_main

logger = logging.getLogger(__name__)


def _read_stdin() -> tuple[str | None, int]:
    """Read stdin for hook/client payloads."""
    try:
        return sys.stdin.read(), 0
    except Exception as e:
        sys.stderr.write(f"Error reading from stdin: {e}\n")
        return None, 1


def _json_object_from_text(text: str) -> dict[str, Any] | None:
    """Return a JSON object if text is an object, otherwise None."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _first_str(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """Return the first non-empty string value for any key."""
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _stringify_hook_value(value: Any) -> str:
    """Render a hook payload value into text for detector input."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(part for part in (_stringify_hook_value(item) for item in value) if part)
    if isinstance(value, dict):
        text = _first_str(
            value,
            (
                "text",
                "content",
                "output",
                "result",
                "stdout",
                "stderr",
                "message",
            ),
        )
        if text:
            return text
        return json.dumps(value, sort_keys=True)
    return str(value)


def _extract_hook_text(data: dict[str, Any], *, operation: str, raw_text: str) -> str:
    """Extract detector text from Claude Code/Codex-style hook JSON."""
    if operation == "check.input":
        text = _first_str(data, ("prompt", "user_prompt", "message", "text", "input"))
        if text:
            return text

    if operation in {"check.output", "check.fetched"}:
        for key in ("tool_response", "tool_result", "response", "result", "output", "content", "text"):
            if key in data:
                text = _stringify_hook_value(data[key])
                if text:
                    return text

    return raw_text


def _extract_hook_tool(data: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    """Extract tool name and parameters from Claude Code/Codex-style hook JSON."""
    tool_name = _first_str(data, ("tool_name", "tool", "name"))
    raw_params = data.get("tool_input", data.get("input", data.get("params", {})))
    params = raw_params if isinstance(raw_params, dict) else {"value": raw_params}

    # Codex hook inputs for shell commands commonly include only tool_input.command.
    if not tool_name and isinstance(raw_params, dict) and "command" in raw_params:
        tool_name = "Bash"

    return tool_name, params


def _get_safe_message(message_type: str, daemon_config: dict[str, Any] | None = None) -> str:
    """Get a safe user-facing message for a block verdict.

    Args:
        message_type: "input" or "output".
        daemon_config: Optional daemon configuration dict with safe_message overrides.

    Returns:
        Safe message string suitable for user display.
    """
    if daemon_config and "safe_message" in daemon_config:
        key = f"{message_type}_block"
        if key in daemon_config["safe_message"]:
            return str(daemon_config["safe_message"][key])

    # Defaults per configuration.md
    if message_type == "input":
        return "Input blocked by armor."
    else:
        return "Output suppressed by armor."


def _check_command(
    args: argparse.Namespace,
    operation: str,
    payload_builder: Callable[[str], dict[str, Any]],
) -> int:
    """Execute a check command (input/output/tool).

    Args:
        args: Parsed arguments.
        operation: The operation type (check.input, check.output, check.tool).
        payload_builder: Callable to build the payload dict from text.

    Returns:
        Exit code.
    """
    # Get socket path and session ID from args or env
    socket_path = args.socket or os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")
    session_id = args.session_id or os.environ.get("ARMOR_SESSION_ID")

    raw_stdin: str | None = None
    hook_data: dict[str, Any] | None = None

    needs_hook_stdin = args.hook_mode and (
        (operation == "check.tool" and not getattr(args, "name", None))
        or (operation != "check.tool" and not getattr(args, "text", None))
    )
    if needs_hook_stdin:
        raw_stdin, stdin_exit = _read_stdin()
        if stdin_exit:
            return stdin_exit
        hook_data = _json_object_from_text(raw_stdin or "")

    # Build payload based on operation type
    if operation == "check.tool":
        # For tool, we need name and params
        hook_tool_name: str | None = None
        hook_params: dict[str, Any] = {}
        if hook_data is not None:
            hook_tool_name, hook_params = _extract_hook_tool(hook_data)

        tool_name = getattr(args, "name", None) or hook_tool_name
        if not tool_name:
            sys.stderr.write("Error: --name is required for check tool\n")
            return 2

        if getattr(args, "params", None) is not None:
            try:
                params = json.loads(args.params or "{}")
            except json.JSONDecodeError as e:
                sys.stderr.write(f"Error: Invalid JSON in --params: {e}\n")
                return 2
        else:
            params = hook_params

        payload = {
            "tool": tool_name,
            "params": params,
        }
    else:
        # For input/output, get text from positional arg or stdin
        if hasattr(args, "text") and args.text:
            text = args.text
        elif hook_data is not None and raw_stdin is not None:
            text = _extract_hook_text(hook_data, operation=operation, raw_text=raw_stdin)
        elif raw_stdin is not None:
            text = raw_stdin
        else:
            stdin_text, stdin_exit = _read_stdin()
            if stdin_exit:
                return stdin_exit
            text = stdin_text or ""

        payload = payload_builder(text)

    # Send request to daemon
    try:
        client = DaemonClient(socket_path=socket_path)
        response = client.request(operation, payload=payload, session_id=session_id)
    except DaemonUnreachableError as e:
        if args.json:
            output = {
                "verdict": "error",
                "signal_id": None,
                "exit_code": 1,
                "message": str(e),
            }
            sys.stdout.write(json.dumps(output) + "\n")
        else:
            sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        if args.json:
            output = {
                "verdict": "error",
                "signal_id": None,
                "exit_code": 1,
                "message": str(e),
            }
            sys.stdout.write(json.dumps(output) + "\n")
        else:
            sys.stderr.write(f"Error: {e}\n")
        return 1

    # Parse verdict and determine exit code
    verdict = response.get("verdict", "error")
    signal_id = response.get("signal_id")
    message = response.get("message", "")

    # Map verdict to exit code
    verdict_to_exit = {
        "pass": 0,
        "block": 100,
        "advisory": 101,
        "error": 1,
    }
    exit_code = verdict_to_exit.get(verdict, 1)

    # Handle --hook-mode: translate verdicts to Claude Code hook contract
    if args.hook_mode:
        message_type = "input" if "input" in operation else "output"
        if verdict == "block":
            # Exit 2 + safe message to stderr
            sys.stderr.write(_get_safe_message(message_type) + "\n")
            exit_code = 2
        elif verdict == "advisory":
            # Advisory in hook-mode becomes exit 0 (caller decides)
            exit_code = 0
        elif verdict == "error":
            # Error stays as exit 1
            exit_code = 1
        else:
            # Pass stays as 0
            exit_code = 0
    else:
        # Without hook-mode, if blocked, print safe message to stderr
        if verdict == "block":
            message_type = "input" if "input" in operation else "output"
            sys.stderr.write(_get_safe_message(message_type) + "\n")

    # Output result
    if args.json:
        output = {
            "verdict": verdict,
            "signal_id": signal_id,
            "exit_code": exit_code,
            "message": message,
        }
        sys.stdout.write(json.dumps(output) + "\n")

    return exit_code


def _is_tty() -> bool:
    """Check if stdout is a TTY."""
    return sys.stdout.isatty()


def _parse_incident_filter_expr(filter_expr: str | None) -> dict[str, str]:
    """Parse `key=value[,key=value]` incident filters used by `incidents tail`."""
    if not filter_expr:
        return {}

    allowed = {"session", "session_id", "category", "since", "severity"}
    parsed: dict[str, str] = {}
    for raw_part in filter_expr.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError("filter expressions must use key=value pairs")
        key, value = (piece.strip() for piece in part.split("=", 1))
        if key not in allowed:
            raise ValueError(f"unsupported filter key: {key}")
        if not value:
            raise ValueError(f"empty filter value for {key}")
        parsed["session_id" if key == "session" else key] = value
    return parsed


def _incidents_list(
    socket_path: str,
    since: str | None = None,
    session_id: str | None = None,
    category: str | None = None,
    limit: int = 50,
    json_output: bool = False,
) -> int:
    """List incidents from the daemon.

    Args:
        socket_path: Path to daemon socket.
        since: Duration string (e.g., "1h", "30m").
        session_id: Filter by session ID.
        category: Filter by attack category pattern.
        limit: Maximum rows to return.
        json_output: Output as JSON.

    Returns:
        Exit code.
    """
    try:
        client = DaemonClient(socket_path=socket_path)
        payload: dict[str, object] = {"limit": limit}
        if since:
            payload["since"] = since
        if session_id:
            payload["session_id"] = session_id
        if category:
            payload["category"] = category
        response = client.request("incidents.list", payload=payload)

        incidents = response.get("incidents", [])

        if json_output:
            sys.stdout.write(json.dumps(incidents) + "\n")
        else:
            if not incidents:
                sys.stdout.write("No incidents found.\n")
                return 0

            # Use rich table if TTY, else plain text
            if _is_tty():
                console = Console()
                table = Table(title="Incidents")
                table.add_column("ID", style="cyan")
                table.add_column("Session", style="magenta")
                table.add_column("Category", style="yellow")
                table.add_column("Verdict", style="green")
                table.add_column("Timestamp", style="blue")

                for inc in incidents:
                    table.add_row(
                        str(inc.get("id", "")),
                        inc.get("session_id", "")[:20],
                        inc.get("attack_category", ""),
                        inc.get("action", ""),
                        inc.get("ts", ""),
                    )

                console.print(table)
            else:
                # Plain text fallback
                sys.stdout.write("ID | Session | Category | Verdict | Timestamp\n")
                sys.stdout.write("-" * 80 + "\n")
                for inc in incidents:
                    sys.stdout.write(
                        f"{inc.get('id', '')} | {inc.get('session_id', '')[:20]} | "
                        f"{inc.get('attack_category', '')} | {inc.get('action', '')} | {inc.get('ts', '')}\n"
                    )

        return 0
    except DaemonUnreachableError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


def _incidents_show(socket_path: str, incident_id: str, json_output: bool = False) -> int:
    """Show a single incident.

    Args:
        socket_path: Path to daemon socket.
        incident_id: Incident ID to retrieve.
        json_output: Output as JSON.

    Returns:
        Exit code.
    """
    try:
        client = DaemonClient(socket_path=socket_path)
        response = client.request("incidents.show", payload={"incident_id": incident_id})

        incident = response.get("incident", {})

        if not incident:
            sys.stderr.write(f"Incident {incident_id} not found\n")
            return 1

        if json_output:
            sys.stdout.write(json.dumps(incident) + "\n")
        else:
            sys.stdout.write(f"Incident ID: {incident.get('id', '')}\n")
            sys.stdout.write(f"Session ID: {incident.get('session_id', '')}\n")
            sys.stdout.write(f"Timestamp: {incident.get('ts', '')}\n")
            sys.stdout.write(f"Category: {incident.get('attack_category', '')}\n")
            sys.stdout.write(f"Signal ID: {incident.get('signal_id', '')}\n")
            sys.stdout.write(f"Action: {incident.get('action', '')}\n")
            sys.stdout.write(f"Risk Score: {incident.get('risk_score', '')}\n")
            if incident.get("quarantine_id"):
                sys.stdout.write(f"Quarantine ID: {incident.get('quarantine_id')}\n")

        return 0
    except DaemonUnreachableError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


def _incidents_tail(socket_path: str, filter_expr: str | None = None) -> int:
    """Stream new incidents (long-polling tail).

    Args:
        socket_path: Path to daemon socket.
        filter_expr: Optional `key=value[,key=value]` filter expression.

    Returns:
        Exit code.
    """
    try:
        last_id = 0
        use_rich = _is_tty()
        filters = _parse_incident_filter_expr(filter_expr)

        while True:
            client = DaemonClient(socket_path=socket_path)
            payload: dict[str, object] = {"since_id": last_id, "limit": 100, **filters}
            response = client.request("incidents.list", payload=payload)

            incidents = response.get("incidents", [])

            if incidents:
                if use_rich:
                    console = Console()
                    table = Table(title="New Incidents")
                    table.add_column("ID", style="cyan")
                    table.add_column("Session", style="magenta")
                    table.add_column("Category", style="yellow")
                    table.add_column("Verdict", style="green")

                    for inc in incidents:
                        table.add_row(
                            str(inc.get("id", "")),
                            inc.get("session_id", "")[:20],
                            inc.get("attack_category", ""),
                            inc.get("action", ""),
                        )
                        last_id = max(last_id, inc.get("id", 0))

                    console.print(table)
                else:
                    # Plain text
                    for inc in incidents:
                        sys.stdout.write(
                            f"{inc.get('id')} | {inc.get('session_id', '')[:20]} | "
                            f"{inc.get('attack_category', '')} | {inc.get('action', '')}\n"
                        )
                        last_id = max(last_id, inc.get("id", 0))

            time.sleep(1)  # Poll every 1 second

    except KeyboardInterrupt:
        return 0
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2
    except DaemonUnreachableError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


def _incidents_export(
    socket_path: str,
    since: str | None = None,
    session_id: str | None = None,
    severity: str | None = None,
    output_path: str = "-",
) -> int:
    """Export incidents as NDJSON.

    Args:
        socket_path: Path to daemon socket.
        since: Duration filter (e.g., 1h, 30m).
        session_id: Filter by session ID.
        severity: Filter by severity level.
        output_path: Output file path (- for stdout).

    Returns:
        Exit code.
    """
    try:
        client = DaemonClient(socket_path=socket_path)
        payload = {}
        if since:
            payload["since"] = since
        if session_id:
            payload["session_id"] = session_id
        if severity:
            payload["severity"] = severity

        response = client.request("incidents.export", payload=payload)

        incidents = response.get("incidents", [])

        # Determine output target
        if output_path == "-":
            # Write to stdout
            for incident in incidents:
                sys.stdout.write(json.dumps(incident) + "\n")
            return 0
        else:
            # Write to file using context manager
            try:
                with open(output_path, "w") as output_file:
                    for incident in incidents:
                        output_file.write(json.dumps(incident) + "\n")
                return 0
            except OSError as e:
                sys.stderr.write(f"Error opening output file {output_path}: {e}\n")
                return 1

    except DaemonUnreachableError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


def _sessions_list(socket_path: str, state: str | None = None, json_output: bool = False) -> int:
    """List active sessions.

    Args:
        socket_path: Path to daemon socket.
        state: Filter by state name.
        json_output: Output as JSON.

    Returns:
        Exit code.
    """
    try:
        client = DaemonClient(socket_path=socket_path)
        response = client.request("sessions.list", payload={"state": state})

        sessions = response.get("sessions", [])

        if json_output:
            sys.stdout.write(json.dumps(sessions) + "\n")
        else:
            if not sessions:
                sys.stdout.write("No sessions found.\n")
                return 0

            if _is_tty():
                console = Console()
                table = Table(title="Sessions")
                table.add_column("Session ID", style="cyan")
                table.add_column("State", style="magenta")
                table.add_column("Risk Score", style="yellow")
                table.add_column("Turns", style="green")
                table.add_column("Created", style="blue")

                for sess in sessions:
                    table.add_row(
                        sess.get("session_id", "")[:25],
                        sess.get("current_state", ""),
                        f"{sess.get('risk_score', 0):.2f}",
                        str(sess.get("turn_count", 0)),
                        sess.get("created_at", ""),
                    )

                console.print(table)
            else:
                # Plain text fallback
                sys.stdout.write("Session ID | State | Risk Score | Turns | Created\n")
                sys.stdout.write("-" * 80 + "\n")
                for sess in sessions:
                    sys.stdout.write(
                        f"{sess.get('session_id', '')[:20]} | {sess.get('current_state', '')} | "
                        f"{sess.get('risk_score', 0):.2f} | {sess.get('turn_count', 0)} | "
                        f"{sess.get('created_at', '')}\n"
                    )

        return 0
    except DaemonUnreachableError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


def _sessions_show(socket_path: str, session_id: str, json_output: bool = False) -> int:
    """Show a single session's state.

    Args:
        socket_path: Path to daemon socket.
        session_id: Session ID to retrieve.
        json_output: Output as JSON.

    Returns:
        Exit code.
    """
    try:
        client = DaemonClient(socket_path=socket_path)
        response = client.request("sessions.show", payload={"session_id": session_id})

        session = response.get("session", {})

        if not session:
            sys.stderr.write(f"Session {session_id} not found\n")
            return 1

        if json_output:
            sys.stdout.write(json.dumps(session) + "\n")
        else:
            sys.stdout.write(f"Session ID: {session.get('session_id', '')}\n")
            sys.stdout.write(f"State: {session.get('current_state', '')}\n")
            sys.stdout.write(f"Risk Score: {session.get('risk_score', '')}\n")
            sys.stdout.write(f"Turn Count: {session.get('turn_count', '')}\n")
            sys.stdout.write(f"Created: {session.get('created_at', '')}\n")
            sys.stdout.write(f"Last Seen: {session.get('last_seen_at', '')}\n")
            sys.stdout.write(f"Signal Count: {len(session.get('signal_history', []))}\n")

            # Show rolling buffer summary (no raw content)
            buffer_info = session.get("rolling_buffer", {})
            if buffer_info:
                sys.stdout.write(f"Rolling Buffer Size: {buffer_info.get('size_bytes', 0)} bytes\n")
                sys.stdout.write(f"Rolling Buffer Hash: {buffer_info.get('hash', '')}\n")

        return 0
    except DaemonUnreachableError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


def _sessions_unblock(socket_path: str, session_id: str, reason: str | None = None) -> int:
    """Unblock a blocked session (operator action).

    Args:
        socket_path: Path to daemon socket.
        session_id: Session ID to unblock.
        reason: Reason for unblocking (optional).

    Returns:
        Exit code.
    """
    try:
        client = DaemonClient(socket_path=socket_path)
        response = client.request(
            "sessions.unblock",
            payload={"session_id": session_id, "reason": reason or ""},
        )

        verdict = response.get("verdict", "error")

        if verdict == "pass":
            new_state = response.get("new_state", "")
            sys.stdout.write(f"Session {session_id} unblocked (new state: {new_state})\n")
            return 0
        else:
            error = response.get("message", "Unknown error")
            sys.stderr.write(f"Error: {error}\n")
            return 1

    except DaemonUnreachableError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


def _health_expanded(socket_path: str, json_output: bool = False) -> int:
    """Check daemon health with expanded metrics.

    Args:
        socket_path: Path to daemon socket.
        json_output: Output as JSON.

    Returns:
        Exit code (0 = healthy, 1 = degraded, 2 = critical).
    """
    try:
        client = DaemonClient(socket_path=socket_path)
        response = client.request("health.full")
        verdict = response.get("verdict")

        if verdict != "pass":
            sys.stderr.write("Error: daemon health check failed\n")
            return 2

        health = response.get("health", {})

        # Determine status code regardless of output format
        status_code = 0
        if not health.get("socket_reachable") or not health.get("db_reachable"):
            status_code = max(status_code, 1)  # degraded
        if not health.get("model_loaded"):
            status_code = 2  # critical

        if json_output:
            sys.stdout.write(json.dumps(health) + "\n")
        else:
            # Print human-readable output
            if _is_tty():
                console = Console()
                table = Table(title="Daemon Health")
                table.add_column("Component", style="cyan")
                table.add_column("Status", style="magenta")

                socket_status = "OK" if health.get("socket_reachable") else "FAIL"
                db_status = "OK" if health.get("db_reachable") else "FAIL"
                model_status = "LOADED" if health.get("model_loaded") else "NOT LOADED"

                table.add_row("Socket", socket_status)
                table.add_row("Database", db_status)
                table.add_row("Model", model_status)
                table.add_row("Uptime", f"{health.get('uptime_seconds', 0)}s")
                table.add_row("Total Checks", str(health.get("total_checks", "unknown")))
                if "p95_input_latency_ms" in health:
                    table.add_row("P95 Input Latency", f"{health['p95_input_latency_ms']:.1f}ms")
                if "p95_output_latency_ms" in health:
                    table.add_row("P95 Output Latency", f"{health['p95_output_latency_ms']:.1f}ms")

                console.print(table)
            else:
                # Plain text
                sys.stdout.write(f"Socket: {'OK' if health.get('socket_reachable') else 'FAIL'}\n")
                sys.stdout.write(f"Database: {'OK' if health.get('db_reachable') else 'FAIL'}\n")
                sys.stdout.write(f"Model: {'LOADED' if health.get('model_loaded') else 'NOT LOADED'}\n")
                sys.stdout.write(f"Uptime: {health.get('uptime_seconds', 0)}s\n")
                sys.stdout.write(f"Total Checks: {health.get('total_checks', 'unknown')}\n")
                if "p95_input_latency_ms" in health:
                    sys.stdout.write(f"P95 Input Latency: {health['p95_input_latency_ms']:.1f}ms\n")
                if "p95_output_latency_ms" in health:
                    sys.stdout.write(f"P95 Output Latency: {health['p95_output_latency_ms']:.1f}ms\n")

        return status_code

    except DaemonUnreachableError:
        if json_output:
            sys.stdout.write(json.dumps({"status": "unreachable", "socket": socket_path}) + "\n")
        else:
            sys.stdout.write(f"Daemon unreachable at {socket_path}\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2


def _health(socket_path: str) -> int:
    """Check if daemon is running by connecting to the socket.

    Args:
        socket_path: Path to the daemon socket

    Returns:
        Exit code (0 if running, 1 if unreachable)
    """
    try:
        client = DaemonClient(socket_path=socket_path)
        response = client.request("canary.list")
        verdict = response.get("verdict")

        if verdict == "pass":
            data = {"status": "ok", "daemon": "running", "socket": socket_path}
            sys.stdout.write(json.dumps(data) + "\n")
            return 0
    except DaemonUnreachableError:
        pass
    except Exception:
        pass

    # Daemon unreachable
    data = {"status": "unreachable", "socket": socket_path}
    sys.stdout.write(json.dumps(data) + "\n")
    return 1


def _install_hooks(settings_path: str | None = None) -> int:
    """Install the five Claude Code hooks to .claude/settings.json.

    Wires the lifecycle hooks per B-017 and diagrams.md §6:
    - UserPromptSubmit → armor check input
    - PreToolUse → armor check tool
    - PostToolUse (generic matcher) → armor check output
    - PostToolUse (read-tool matcher) → armor check fetched
    - Stop → armor session close

    Args:
        settings_path: Path to settings file (default: ./.claude/settings.json)

    Returns:
        Exit code (0 on success, 1 on error)
    """
    if settings_path is None:
        settings_path = "./.claude/settings.json"

    settings_path_obj = Path(settings_path)

    # Load existing settings or create new dict
    if settings_path_obj.exists():
        try:
            with open(settings_path_obj, encoding="utf-8") as f:
                settings = json.load(f)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"Error: Malformed JSON in {settings_path}: {e}\n")
            return 1
    else:
        settings = {}

    # Ensure hooks dict exists
    if "hooks" not in settings:
        settings["hooks"] = {}

    # Define the five armor hooks organized by event
    # Per B-017 and diagrams.md §6:
    # - UserPromptSubmit → check input
    # - PreToolUse → check tool
    # - PostToolUse (read tools) → check fetched
    # - PostToolUse (other tools) → check output
    # - Stop → session close
    armor_hooks_by_event = {
        "UserPromptSubmit": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "armor check input --hook-mode --socket ${ARMOR_SOCKET:-/var/run/armor.sock} --session-id ${CLAUDE_SESSION_ID:-default}",
                    }
                ]
            }
        ],
        "PreToolUse": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "armor check tool --hook-mode --socket ${ARMOR_SOCKET:-/var/run/armor.sock} --session-id ${CLAUDE_SESSION_ID:-default}",
                    }
                ]
            }
        ],
        "PostToolUse": [
            {
                "matcher": "Read|WebFetch|Grep|Glob|mcp__.*__read.*",
                "hooks": [
                    {
                        "type": "command",
                        "command": "armor check fetched --hook-mode --socket ${ARMOR_SOCKET:-/var/run/armor.sock} --session-id ${CLAUDE_SESSION_ID:-default}",
                    }
                ],
            },
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "armor check output --hook-mode --socket ${ARMOR_SOCKET:-/var/run/armor.sock} --session-id ${CLAUDE_SESSION_ID:-default}",
                    }
                ]
            },
        ],
        "Stop": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "armor session close --socket ${ARMOR_SOCKET:-/var/run/armor.sock} --session-id ${CLAUDE_SESSION_ID:-default}",
                    }
                ]
            }
        ],
    }

    # Merge hooks: preserve non-armor events, replace armor events
    armor_event_names = set(armor_hooks_by_event.keys())

    # Keep non-armor events
    existing_hooks = settings.get("hooks", {})
    if isinstance(existing_hooks, dict):
        non_armor_hooks = {k: v for k, v in existing_hooks.items() if k not in armor_event_names}
    else:
        # Handle legacy list format by discarding it
        non_armor_hooks = {}

    # Combine
    settings["hooks"] = {**non_armor_hooks, **armor_hooks_by_event}

    # Write back
    try:
        with open(settings_path_obj, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to write {settings_path}: {e}\n")
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(prog="armor", description="Defense-in-depth security layer for LLM agents")
    parser.add_argument("--version", action="version", version=f"armor {__version__}")
    parser.add_argument(
        "--socket",
        default=None,
        help="Path to daemon socket (default: $ARMOR_SOCKET or /var/run/armor.sock)",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="Session ID for stateful checks (default: $ARMOR_SESSION_ID)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Machine-readable JSON output",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    # daemon subcommand
    daemon_parser = sub.add_parser("daemon", help="Start the armor daemon")
    daemon_parser.add_argument(
        "--socket",
        default="/var/run/armor.sock",
        help="Path to bind the Unix socket",
    )
    daemon_parser.add_argument(
        "--db",
        default="/var/lib/armor/armor.db",
        help="Path to SQLite database",
    )
    daemon_parser.add_argument(
        "--model",
        default=None,
        help="Path to validator LLM weights file",
    )
    daemon_parser.add_argument(
        "--config",
        default=None,
        help="Path to armor.toml configuration file",
    )
    daemon_parser.add_argument(
        "--catalogue",
        default=None,
        help="Path to canary catalogue JSON (deprecated; use --canary-values for new deployments)",
    )
    daemon_parser.add_argument(
        "--canary-values",
        default=None,
        help="Path to canary values file (generated by 'armor canary generate')",
    )
    daemon_parser.add_argument(
        "--quarantine-key-path",
        default=None,
        help="Path to quarantine encryption key",
    )
    daemon_parser.add_argument(
        "--max-concurrent",
        type=int,
        default=64,
        help="Maximum concurrent connections",
    )
    daemon_parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default=os.environ.get("ARMOR_LOG_LEVEL", "info"),
        help="Log level",
    )

    # check subcommand (with sub-subcommands)
    check_parser = sub.add_parser("check", help="Check operations")
    check_sub = check_parser.add_subparsers(dest="check_cmd", required=True)

    # check input
    check_input_parser = check_sub.add_parser("input", help="Check a user-input payload for injection signals")
    check_input_parser.add_argument("text", nargs="?", default=None, help="Input text (or read from stdin)")
    check_input_parser.add_argument("--hook-mode", action="store_true", help="Use Claude Code hook protocol")
    check_input_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    check_input_parser.add_argument("--session-id", default=None, help="Session ID for stateful checks")
    check_input_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # check output
    check_output_parser = check_sub.add_parser("output", help="Check a model-output payload for exfiltration")
    check_output_parser.add_argument("text", nargs="?", default=None, help="Output text (or read from stdin)")
    check_output_parser.add_argument("--hook-mode", action="store_true", help="Use Claude Code hook protocol")
    check_output_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    check_output_parser.add_argument("--session-id", default=None, help="Session ID for stateful checks")
    check_output_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # check tool
    check_tool_parser = check_sub.add_parser("tool", help="Check a tool call against the command denylist")
    check_tool_parser.add_argument("--name", default=None, help="Tool name")
    check_tool_parser.add_argument("--params", default=None, help="Tool parameters as JSON")
    check_tool_parser.add_argument("--hook-mode", action="store_true", help="Use Claude Code hook protocol")
    check_tool_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    check_tool_parser.add_argument("--session-id", default=None, help="Session ID for stateful checks")
    check_tool_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # check fetched — indirect-injection detection on tool results (ADR-033, ADR-041)
    check_fetched_parser = check_sub.add_parser(
        "fetched", help="Check a tool-result payload for indirect injection (per ADR-033)"
    )
    check_fetched_parser.add_argument("text", nargs="?", default=None, help="Tool result text (or read from stdin)")
    check_fetched_parser.add_argument("--source-tool", default=None, help="Tool name that returned this result")
    check_fetched_parser.add_argument("--hook-mode", action="store_true", help="Use Claude Code hook protocol")
    check_fetched_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    check_fetched_parser.add_argument("--session-id", default=None, help="Session ID for stateful checks")
    check_fetched_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # session subcommand (with sub-subcommands)
    session_parser = sub.add_parser("session", help="Session operations")
    session_sub = session_parser.add_subparsers(dest="session_cmd", required=True)

    # session close
    session_close_parser = session_sub.add_parser("close", help="Mark a session ended; flush state")
    session_close_parser.add_argument("--session-id", required=True, help="Session ID to close")
    session_close_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    session_close_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # canary subcommand (with sub-subcommands)
    canary_parser = sub.add_parser("canary", help="Canary catalogue operations")
    canary_sub = canary_parser.add_subparsers(dest="canary_cmd", required=True)

    # canary list
    canary_list_parser = canary_sub.add_parser("list", help="List the active canary catalogue")
    canary_list_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    canary_list_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # canary generate
    canary_generate_parser = canary_sub.add_parser("generate", help="Generate canary values file")
    canary_generate_parser.add_argument(
        "--out",
        required=True,
        help="Output path for the generated values file",
    )
    canary_generate_parser.add_argument(
        "--seed",
        default=None,
        type=lambda x: int(x, 0),  # Support 0xHEX, 0o, 0b, and decimal
        help="Seed for deterministic generation (e.g., 0xCAFEBABE)",
    )

    # canary honeypot
    canary_honeypot_parser = canary_sub.add_parser(
        "honeypot",
        help="Write a honeypot .env file populated with canary credentials",
    )
    canary_honeypot_parser.add_argument(
        "--values",
        required=True,
        help="Path to the generated canary values file (from 'armor canary generate')",
    )
    canary_honeypot_parser.add_argument(
        "--out",
        required=True,
        help="Output path for the honeypot .env file",
    )

    # canary pii-context
    canary_pii_parser = canary_sub.add_parser(
        "pii-context",
        help="Write a honeypot PII context snippet to inject into an agent system prompt",
    )
    canary_pii_parser.add_argument(
        "--values",
        required=True,
        help="Path to the generated canary values file (from 'armor canary generate')",
    )
    canary_pii_parser.add_argument(
        "--out",
        required=True,
        help="Output path for the PII context snippet file",
    )

    # incidents subcommand (with sub-subcommands)
    incidents_parser = sub.add_parser("incidents", help="Incident inspection")
    incidents_sub = incidents_parser.add_subparsers(dest="incidents_cmd", required=True)

    # incidents list
    incidents_list_parser = incidents_sub.add_parser("list", help="List incidents")
    incidents_list_parser.add_argument("--since", default=None, help="Duration (e.g., 1h, 30m)")
    incidents_list_parser.add_argument("--session", default=None, help="Filter by session ID")
    incidents_list_parser.add_argument("--category", default=None, help="Filter by attack category")
    incidents_list_parser.add_argument("--limit", type=int, default=50, help="Maximum rows")
    incidents_list_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    incidents_list_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # incidents show
    incidents_show_parser = incidents_sub.add_parser("show", help="Show incident details")
    incidents_show_parser.add_argument("incident_id", help="Incident ID")
    incidents_show_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    incidents_show_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # incidents tail
    incidents_tail_parser = incidents_sub.add_parser("tail", help="Stream new incidents")
    incidents_tail_parser.add_argument(
        "--filter",
        default=None,
        help="Comma-separated filters, e.g. session=abc,category=direct_injection.*,severity=critical",
    )
    incidents_tail_parser.add_argument("--socket", default=None, help="Path to daemon socket")

    # incidents export
    incidents_export_parser = incidents_sub.add_parser("export", help="Export incidents as NDJSON")
    incidents_export_parser.add_argument("--since", default=None, help="Duration (e.g., 1h, 30m)")
    incidents_export_parser.add_argument("--session", default=None, help="Filter by session ID")
    incidents_export_parser.add_argument("--severity", default=None, help="Filter by severity level")
    incidents_export_parser.add_argument("--output", "-o", default="-", help="Output file path (default: stdout)")
    incidents_export_parser.add_argument("--socket", default=None, help="Path to daemon socket")

    # sessions subcommand (with sub-subcommands)
    sessions_parser = sub.add_parser("sessions", help="Session management")
    sessions_sub = sessions_parser.add_subparsers(dest="sessions_cmd", required=True)

    # sessions list
    sessions_list_parser = sessions_sub.add_parser("list", help="List sessions")
    sessions_list_parser.add_argument("--state", default=None, help="Filter by state name")
    sessions_list_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    sessions_list_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # sessions show
    sessions_show_parser = sessions_sub.add_parser("show", help="Show session details")
    sessions_show_parser.add_argument("session_id", help="Session ID")
    sessions_show_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    sessions_show_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # sessions unblock
    sessions_unblock_parser = sessions_sub.add_parser("unblock", help="Unblock a session")
    sessions_unblock_parser.add_argument("session_id", help="Session ID to unblock")
    sessions_unblock_parser.add_argument(
        "--reason",
        required=True,
        help="Reason for unblocking (required; written to OperatorAuditLog)",
    )
    sessions_unblock_parser.add_argument("--socket", default=None, help="Path to daemon socket")

    # health subcommand
    health_parser = sub.add_parser("health", help="Daemon liveness check")
    health_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    health_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # config subcommand — expose runtime config to hooks
    config_parser = sub.add_parser("config", help="Configuration operations")
    config_sub = config_parser.add_subparsers(dest="config_cmd", required=True)

    # config show
    config_show_parser = config_sub.add_parser("show", help="Show configuration section")
    config_show_parser.add_argument(
        "--section", required=True, help="Configuration section (e.g., pipeline.exempt, pipeline.source_multipliers)"
    )
    config_show_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    config_show_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    # hooks subcommand (with sub-subcommands)
    hooks_parser = sub.add_parser("hooks", help="Claude Code hooks management")
    hooks_sub = hooks_parser.add_subparsers(dest="hooks_cmd", required=True)

    # hooks install
    hooks_install_parser = hooks_sub.add_parser("install", help="Install Claude Code hooks")
    hooks_install_parser.add_argument(
        "--settings",
        default="./.claude/settings.json",
        help="Path to settings.json file",
    )

    # Parse arguments
    args = parser.parse_args(argv)

    # Handle commands
    if args.cmd == "daemon":
        daemon_args = [
            "--socket",
            args.socket,
            "--db",
            args.db,
            "--max-concurrent",
            str(args.max_concurrent),
            "--log-level",
            args.log_level,
        ]
        if args.model:
            daemon_args.extend(["--model", args.model])
        if args.config:
            daemon_args.extend(["--config", args.config])
        if args.catalogue:
            daemon_args.extend(["--catalogue", args.catalogue])
        if hasattr(args, "canary_values") and args.canary_values:
            daemon_args.extend(["--canary-values", args.canary_values])
        if args.quarantine_key_path:
            daemon_args.extend(["--quarantine-key-path", args.quarantine_key_path])
        return daemon_main(daemon_args)

    elif args.cmd == "check":
        if args.check_cmd == "input":
            return _check_command(
                args,
                "check.input",
                lambda text: {"text": text},
            )
        elif args.check_cmd == "output":
            return _check_command(
                args,
                "check.output",
                lambda text: {"text": text},
            )
        elif args.check_cmd == "tool":
            return _check_command(
                args,
                "check.tool",
                lambda text: {},  # Tool operation builds payload differently
            )
        elif args.check_cmd == "fetched":
            # Special handling for check.fetched (indirect injection on tool results)
            socket_path = args.socket or os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")
            session_id = args.session_id or os.environ.get("ARMOR_SESSION_ID")
            raw_stdin: str | None = None
            hook_data: dict[str, Any] | None = None

            if args.hook_mode:
                raw_stdin, stdin_exit = _read_stdin()
                if stdin_exit:
                    return stdin_exit
                hook_data = _json_object_from_text(raw_stdin or "")

            # Get text from positional arg or stdin
            if hasattr(args, "text") and args.text:
                text = args.text
            elif hook_data is not None and raw_stdin is not None:
                text = _extract_hook_text(hook_data, operation="check.fetched", raw_text=raw_stdin)
            elif raw_stdin is not None:
                text = raw_stdin
            else:
                stdin_text, stdin_exit = _read_stdin()
                if stdin_exit:
                    return stdin_exit
                text = stdin_text or ""

            source_tool = args.source_tool
            if not source_tool and hook_data is not None:
                source_tool, _ = _extract_hook_tool(hook_data)
            if not source_tool:
                sys.stderr.write("Error: --source-tool is required for check fetched\n")
                return 2

            payload = {
                "text": text,
                "source_tool": source_tool,
            }

            try:
                client = DaemonClient(socket_path=socket_path)
                response = client.request("check.fetched", payload=payload, session_id=session_id)
                verdict = response.get("verdict", "error")
                if args.hook_mode:
                    exit_code = 2 if verdict == "block" else (1 if verdict == "error" else 0)
                else:
                    exit_code = 0 if verdict == "pass" else (101 if verdict == "advisory" else 100)

                if args.json:
                    output = {
                        "verdict": verdict,
                        "signal_id": response.get("signal_id"),
                        "message": response.get("message"),
                        "incident_id": response.get("incident_id"),
                        "exit_code": exit_code,
                    }
                    sys.stdout.write(json.dumps(output) + "\n")
                else:
                    message = response.get("message", "")
                    if args.hook_mode and verdict == "block":
                        sys.stderr.write(_get_safe_message("output") + "\n")
                    elif message:
                        sys.stdout.write(message + "\n")

                return exit_code
            except DaemonUnreachableError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1

    elif args.cmd == "config":
        if args.config_cmd == "show":
            socket_path = args.socket or os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")
            try:
                client = DaemonClient(socket_path=socket_path)
                # Send config.show request to daemon
                response = client.request("config.show", payload={"section": args.section})
                verdict = response.get("verdict", "error")

                if verdict == "pass":
                    config_section = response.get("config", {})
                    if args.json:
                        sys.stdout.write(json.dumps(config_section) + "\n")
                    else:
                        sys.stdout.write(json.dumps(config_section, indent=2) + "\n")
                    return 0
                else:
                    sys.stderr.write(f"Error: {response.get('message', 'Unknown error')}\n")
                    return 1
            except DaemonUnreachableError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1

    elif args.cmd == "session":
        if args.session_cmd == "close":
            socket_path = args.socket or os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")
            try:
                client = DaemonClient(socket_path=socket_path)
                response = client.request("session.close", session_id=args.session_id)
                verdict = response.get("verdict", "error")

                if args.json:
                    output = {
                        "verdict": verdict,
                        "exit_code": 0 if verdict == "pass" else 1,
                    }
                    sys.stdout.write(json.dumps(output) + "\n")

                return 0 if verdict == "pass" else 1
            except DaemonUnreachableError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1

    elif args.cmd == "canary":
        if args.canary_cmd == "generate":
            try:
                # Get path to the bundled schema
                from importlib import resources

                schema_data = resources.files("armor").joinpath("canaries/default_catalogue.json").read_text()

                # Create a temporary schema file to pass to the generator
                import tempfile

                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
                    tf.write(schema_data)
                    schema_path = tf.name

                try:
                    write_values_file(args.out, schema_path, seed=args.seed)
                    sys.stdout.write(f"Generated canary values at {args.out}\n")
                    return 0
                finally:
                    os.unlink(schema_path)

            except FileNotFoundError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1
            except ValueError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1

        elif args.canary_cmd == "honeypot":
            try:
                from armor.canaries._generate import write_dotenv_honeypot

                write_dotenv_honeypot(args.out, args.values)
                sys.stdout.write(f"Wrote honeypot .env to {args.out}\n")
                sys.stdout.write(
                    "Place this file where your agent has filesystem access. "
                    "The canary scanner will catch it if the contents are echoed.\n"
                )
                return 0
            except FileNotFoundError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1
            except KeyError as e:
                sys.stderr.write(f"Error: missing canary in values file — {e}\n")
                return 1
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1

        elif args.canary_cmd == "pii-context":
            try:
                from armor.canaries._generate import write_pii_context

                write_pii_context(args.out, args.values)
                sys.stdout.write(f"Wrote PII context honeypot to {args.out}\n")
                sys.stdout.write(
                    "Inject the contents of this file into your agent's system prompt. "
                    "The canary scanner will catch any output that includes these values.\n"
                )
                return 0
            except FileNotFoundError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1
            except KeyError as e:
                sys.stderr.write(f"Error: missing canary in values file — {e}\n")
                return 1
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1

        elif args.canary_cmd == "list":
            socket_path = args.socket or os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")
            try:
                client = DaemonClient(socket_path=socket_path)
                response = client.request("canary.list")
                canaries = response.get("canaries", [])

                if args.json:
                    # Return as JSON array with no value field
                    output_list: list[dict[str, Any]] = [
                        {
                            "canary_id": c.get("canary_id"),
                            "kind": c.get("kind"),
                            "service": c.get("service"),
                            "active": c.get("active", True),
                        }
                        for c in canaries
                    ]
                    sys.stdout.write(json.dumps(output_list) + "\n")
                else:
                    # Human-readable format
                    if not canaries:
                        print("No active canaries")
                    else:
                        # Simple table format
                        print("ID                    | Kind       | Service    | Active")
                        print("-" * 60)
                        for c in canaries:
                            canary_id = c.get("canary_id", "")[:20].ljust(20)
                            kind = c.get("kind", "")[:10].ljust(10)
                            service = c.get("service", "")[:10].ljust(10)
                            active = "Yes" if c.get("active", True) else "No"
                            print(f"{canary_id} | {kind} | {service} | {active}")

                return 0
            except DaemonUnreachableError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1

    elif args.cmd == "incidents":
        socket_path = args.socket or os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")
        if args.incidents_cmd == "list":
            return _incidents_list(
                socket_path,
                since=args.since,
                session_id=args.session,
                category=args.category,
                limit=args.limit,
                json_output=args.json,
            )
        elif args.incidents_cmd == "show":
            return _incidents_show(socket_path, args.incident_id, json_output=args.json)
        elif args.incidents_cmd == "tail":
            return _incidents_tail(socket_path, filter_expr=args.filter)
        elif args.incidents_cmd == "export":
            return _incidents_export(
                socket_path,
                since=args.since,
                session_id=args.session,
                severity=args.severity,
                output_path=args.output,
            )

    elif args.cmd == "sessions":
        socket_path = args.socket or os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")
        if args.sessions_cmd == "list":
            return _sessions_list(socket_path, state=args.state, json_output=args.json)
        elif args.sessions_cmd == "show":
            return _sessions_show(socket_path, args.session_id, json_output=args.json)
        elif args.sessions_cmd == "unblock":
            return _sessions_unblock(socket_path, args.session_id, reason=args.reason)

    elif args.cmd == "health":
        socket_path = args.socket or os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")
        json_mode = args.json if hasattr(args, "json") else False
        return _health_expanded(socket_path, json_output=json_mode)

    elif args.cmd == "hooks":
        if args.hooks_cmd == "install":
            return _install_hooks(settings_path=args.settings)

    return 2


if __name__ == "__main__":
    sys.exit(main())
