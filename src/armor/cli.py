"""Command-line interface for the armor daemon and tools."""

import argparse
import json
import logging
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from armor import __version__
from armor.client import DaemonClient, DaemonUnreachableError
from armor.daemon.__main__ import main as daemon_main

logger = logging.getLogger(__name__)


def _get_safe_message(verdict: str, message_type: str, daemon_config: dict[str, Any] | None = None) -> str:
    """Get a safe user-facing message for a block verdict.

    Args:
        verdict: The verdict (block or advisory).
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

    # Build payload based on operation type
    if operation == "check.tool":
        # For tool, we need name and params
        if not hasattr(args, "name") or not args.name:
            sys.stderr.write("Error: --name is required for check tool\n")
            return 2

        try:
            params = json.loads(args.params or "{}")
        except json.JSONDecodeError as e:
            sys.stderr.write(f"Error: Invalid JSON in --params: {e}\n")
            return 2

        payload = {
            "tool": args.name,
            "params": params,
        }
    else:
        # For input/output, get text from positional arg or stdin
        if hasattr(args, "text") and args.text:
            text = args.text
        else:
            # Read from stdin
            try:
                text = sys.stdin.read()
            except Exception as e:
                sys.stderr.write(f"Error reading from stdin: {e}\n")
                return 1

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
        "try_later": 1,
    }
    exit_code = verdict_to_exit.get(verdict, 1)

    # Handle --hook-mode: translate verdicts to Claude Code hook contract
    if args.hook_mode:
        message_type = "input" if "input" in operation else "output"
        if verdict == "block":
            # Exit 2 + safe message to stderr
            sys.stderr.write(_get_safe_message("block", message_type) + "\n")
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
            sys.stderr.write(_get_safe_message("block", message_type) + "\n")

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
    """Install the four Claude Code hooks to .claude/settings.json.

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

    # Ensure hooks list exists
    if "hooks" not in settings:
        settings["hooks"] = []

    # Define the four armor hooks
    armor_hooks = [
        {
            "name": "armor-check-input",
            "event": "UserPromptSubmit",
            "handler": 'armor check input --hook-mode --session-id "$CLAUDE_SESSION_ID"',
        },
        {
            "name": "armor-check-output",
            "event": "PreToolUse",
            "handler": 'armor check output --hook-mode --session-id "$CLAUDE_SESSION_ID"',
        },
        {
            "name": "armor-check-tool",
            "event": "PostToolUse",
            "handler": 'armor check tool "$ARMOR_TOOL_NAME" --params \'$ARMOR_TOOL_PARAMS\' --hook-mode --session-id "$CLAUDE_SESSION_ID"',
        },
        {
            "name": "armor-session-close",
            "event": "Stop",
            "handler": 'armor session close --session-id "$CLAUDE_SESSION_ID"',
        },
    ]

    # Merge hooks: remove duplicates by name, then add armor hooks
    existing_hooks = settings.get("hooks", [])
    armor_hook_names = {h["name"] for h in armor_hooks}

    # Keep non-armor hooks
    non_armor_hooks = [h for h in existing_hooks if h.get("name") not in armor_hook_names]

    # Combine
    settings["hooks"] = non_armor_hooks + armor_hooks

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
        help="Path to canary catalogue JSON",
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
    check_tool_parser.add_argument("--name", required=True, help="Tool name")
    check_tool_parser.add_argument("--params", default="{}", help="Tool parameters as JSON")
    check_tool_parser.add_argument("--hook-mode", action="store_true", help="Use Claude Code hook protocol")
    check_tool_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    check_tool_parser.add_argument("--session-id", default=None, help="Session ID for stateful checks")
    check_tool_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

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

    # health subcommand
    health_parser = sub.add_parser("health", help="Daemon liveness check")
    health_parser.add_argument("--socket", default=None, help="Path to daemon socket")
    health_parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")

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
            logger.warning("--model flag accepted but validator LLM is not used in v0.1")
        if args.config:
            daemon_args.extend(["--config", args.config])
        if args.catalogue:
            daemon_args.extend(["--catalogue", args.catalogue])
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
        if args.canary_cmd == "list":
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

    elif args.cmd == "health":
        socket_path = args.socket or os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock")
        return _health(socket_path)

    elif args.cmd == "hooks":
        if args.hooks_cmd == "install":
            return _install_hooks(settings_path=args.settings)

    return 2


if __name__ == "__main__":
    sys.exit(main())
