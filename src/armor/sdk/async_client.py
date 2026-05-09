"""Asynchronous client for the armor daemon.

This module provides an async-compatible client for communicating
with the armor daemon. It mirrors the synchronous client interface
but returns awaitables.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from armor.client import DaemonClient, DaemonUnreachableError
from armor.types import HealthReport, Incident, Verdict


class AsyncArmorClient:
    """Asynchronous client for communicating with the armor daemon.

    This client provides an async interface to the armor daemon using
    asyncio. It wraps the synchronous DaemonClient and runs requests
    in a thread pool to avoid blocking.

    Parameters:
        socket_path (str | Path): Path to the daemon Unix socket.
            Defaults to the ARMOR_SOCKET environment variable or
            /var/run/armor.sock if not specified.

    Raises:
        DaemonUnreachableError: If the daemon socket is unreachable when
            a check is made.

    Example:
        >>> client = AsyncArmorClient(socket_path="/var/run/armor.sock")
        >>> verdict = await client.check_input("user input", session_id="sess-1")
        >>> if verdict.blocked:
        ...     await handle_block(verdict)
        ...
        >>> async with client.session("sess-2") as s:
        ...     v1 = await s.check_input("message 1")
        ...     v2 = await s.check_input("message 2")
    """

    def __init__(self, socket_path: str | Path | None = None) -> None:
        """Initialize the AsyncArmorClient.

        Parameters:
            socket_path (str | Path | None): Path to the daemon socket.
                If None, uses ARMOR_SOCKET env var or /var/run/armor.sock.
        """
        if socket_path is not None:
            socket_path = str(socket_path)
        self._transport = DaemonClient(socket_path=socket_path)
        if socket_path is not None:
            self.socket_path = Path(socket_path)
        else:
            import os

            self.socket_path = Path(os.environ.get("ARMOR_SOCKET", "/var/run/armor.sock"))

    async def check_input(self, text: str, session_id: str | None = None) -> Verdict:
        """Asynchronously check user input for injection signals.

        Sends the input text to the daemon for analysis. This method
        runs the blocking socket operation in a thread pool.

        Parameters:
            text (str): The input text to check.
            session_id (str | None): Session identifier for correlating
                multi-turn checks.

        Returns:
            Verdict: The security verdict.

        Raises:
            DaemonUnreachableError: If the daemon socket is unreachable.

        Example:
            >>> verdict = await client.check_input("user input")
            >>> if verdict.blocked:
            ...     await respond_blocked()
        """
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._transport.request(
                "check.input",
                payload={"text": text},
                session_id=session_id,
            ),
        )
        return self._parse_verdict(response)

    async def check_output(self, text: str, session_id: str | None = None) -> Verdict:
        """Asynchronously check model output for exfiltration signals.

        Parameters:
            text (str): The model output text to check.
            session_id (str | None): Session identifier.

        Returns:
            Verdict: The security verdict.

        Raises:
            DaemonUnreachableError: If the daemon socket is unreachable.

        Example:
            >>> verdict = await client.check_output(response_text)
            >>> if verdict.blocked:
            ...     return safe_response()
        """
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._transport.request(
                "check.output",
                payload={"text": text},
                session_id=session_id,
            ),
        )
        return self._parse_verdict(response)

    async def check_tool_call(
        self,
        tool: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> Verdict:
        """Asynchronously check a tool invocation.

        Parameters:
            tool (str): The name of the tool being invoked.
            params (dict[str, Any] | None): Parameters passed to the tool.
            session_id (str | None): Session identifier.

        Returns:
            Verdict: The security verdict.

        Raises:
            DaemonUnreachableError: If the daemon socket is unreachable.

        Example:
            >>> verdict = await client.check_tool_call(
            ...     tool="Bash",
            ...     params={"command": "ls /etc/passwd"},
            ... )
            >>> if verdict.blocked:
            ...     await handle_tool_blocked()
        """
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._transport.request(
                "check.tool",
                payload={"tool": tool, "params": params or {}},
                session_id=session_id,
            ),
        )
        return self._parse_verdict(response)

    async def check_fetched(
        self,
        text: str,
        source_tool: str,
        session_id: str | None = None,
    ) -> Verdict:
        """Asynchronously check a tool-call result for indirect injection signals.

        Analyzes the result text from a tool execution (e.g., from Read,
        WebFetch, or similar) for prompt injection attempts embedded in
        the tool's output. This is the post-tool-use counterpart to
        check_input and helps detect indirect injection attacks where
        untrusted tool results contain malicious instructions.

        Parameters:
            text (str): The tool-call result text to check.
            source_tool (str): The name of the tool that returned this result
                (e.g., "Read", "WebFetch", "WebSearch"). Required.
            session_id (str | None): Session identifier for correlating
                multi-turn checks.

        Returns:
            Verdict: The security verdict.

        Raises:
            DaemonUnreachableError: If the daemon socket is unreachable.
            TypeError: If source_tool is not provided or is None.

        Example:
            >>> result = await web_fetch("https://example.com")
            >>> verdict = await client.check_fetched(result, source_tool="WebFetch")
            >>> if verdict.blocked:
            ...     return safe_response()
        """
        if source_tool is None:
            raise TypeError("source_tool is required and cannot be None")

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._transport.request(
                "check.fetched",
                payload={"text": text, "source_tool": source_tool},
                session_id=session_id,
            ),
        )
        return self._parse_verdict(response)

    async def health(self) -> HealthReport:
        """Asynchronously get the health status of the daemon.

        Returns:
            HealthReport: Daemon health status.

        Raises:
            DaemonUnreachableError: If the daemon socket is unreachable.

        Example:
            >>> report = await client.health()
            >>> if report.daemon_reachable:
            ...     print(f"Daemon v{report.version}")
        """
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, lambda: self._transport.request("health"))
            # If we got a response with health fields, parse them
            if "daemon_reachable" in response or "health" in response:
                return self._parse_health_report(response)
            # If the health endpoint is not recognized, assume reachable
            # since we got a response from the daemon
            return HealthReport(
                daemon_reachable=True,
                db_reachable=True,
                model_loaded=False,
                version="unknown",
                uptime_seconds=None,
            )
        except DaemonUnreachableError:
            raise

    async def incident(self, incident_id: str) -> Incident | None:
        """Asynchronously retrieve a single incident.

        Parameters:
            incident_id (str): The unique incident identifier.

        Returns:
            Incident | None: The incident if found, else None.

        Raises:
            DaemonUnreachableError: If the daemon socket is unreachable.

        Example:
            >>> incident = await client.incident("inc-abc123")
            >>> if incident:
            ...     print(f"Signal: {incident.signal_id}")
        """
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._transport.request("incident.get", payload={"id": incident_id}),
        )
        if response.get("incident") is None:
            return None
        return self._parse_incident(response["incident"])

    @asynccontextmanager
    async def session(self, session_id: str) -> AsyncGenerator[AsyncSessionContext, None]:
        """Async context manager for session-bound checks.

        Parameters:
            session_id (str): The session identifier to bind.

        Yields:
            AsyncSessionContext: A context object that binds session_id.

        Example:
            >>> async with client.session("sess-1") as s:
            ...     await s.check_input("message 1")
            ...     await s.check_input("message 2")
        """
        ctx = AsyncSessionContext(self, session_id)
        yield ctx

    @staticmethod
    def _parse_verdict(response: dict[str, Any]) -> Verdict:
        """Parse a daemon response into a Verdict object.

        Parameters:
            response (dict): The JSON response from the daemon.

        Returns:
            Verdict: Parsed verdict.
        """
        # The daemon response has verdict decision as a string at the top level
        decision = response.get("verdict", "error")
        return Verdict(
            decision=decision,
            signal_id=response.get("signal_id"),
            severity=response.get("severity", "low"),
            message=response.get("message", ""),
            details=response.get("details", {}),
        )

    @staticmethod
    def _parse_health_report(response: dict[str, Any]) -> HealthReport:
        """Parse a daemon health response into a HealthReport object.

        Parameters:
            response (dict): The JSON response from the daemon.

        Returns:
            HealthReport: Parsed health report.
        """
        health_data = response.get("health", {})
        return HealthReport(
            daemon_reachable=health_data.get("daemon_reachable", False),
            db_reachable=health_data.get("db_reachable", False),
            model_loaded=health_data.get("model_loaded", False),
            version=health_data.get("version", "unknown"),
            uptime_seconds=health_data.get("uptime_seconds"),
        )

    @staticmethod
    def _parse_incident(incident_data: dict[str, Any]) -> Incident:
        """Parse a daemon incident response into an Incident object.

        Parameters:
            incident_data (dict): The incident data from the daemon.

        Returns:
            Incident: Parsed incident.
        """
        return Incident(
            id=incident_data.get("id", ""),
            timestamp=incident_data.get("timestamp", 0.0),
            session_id=incident_data.get("session_id", ""),
            payload_hash=incident_data.get("payload_hash", ""),
            verdict_decision=incident_data.get("verdict_decision", ""),
            signal_id=incident_data.get("signal_id"),
            details=incident_data.get("details", {}),
        )


class AsyncSessionContext:
    """Async context manager for session-bound checks.

    Parameters:
        client (AsyncArmorClient): The async client instance.
        session_id (str): The session identifier to bind.

    Example:
        >>> async with client.session("sess-1") as s:
        ...     await s.check_input("message 1")
        ...     await s.check_input("message 2")
    """

    def __init__(self, client: AsyncArmorClient, session_id: str) -> None:
        """Initialize the AsyncSessionContext.

        Parameters:
            client (AsyncArmorClient): The async client instance.
            session_id (str): The session identifier.
        """
        self.client = client
        self.session_id = session_id

    async def check_input(self, text: str) -> Verdict:
        """Check input with the bound session_id.

        Parameters:
            text (str): The input text to check.

        Returns:
            Verdict: The security verdict.
        """
        return await self.client.check_input(text, session_id=self.session_id)

    async def check_output(self, text: str) -> Verdict:
        """Check output with the bound session_id.

        Parameters:
            text (str): The output text to check.

        Returns:
            Verdict: The security verdict.
        """
        return await self.client.check_output(text, session_id=self.session_id)

    async def check_tool_call(self, tool: str, params: dict[str, Any] | None = None) -> Verdict:
        """Check a tool call with the bound session_id.

        Parameters:
            tool (str): The tool name.
            params (dict[str, Any] | None): Tool parameters.

        Returns:
            Verdict: The security verdict.
        """
        return await self.client.check_tool_call(tool, params=params, session_id=self.session_id)

    async def check_fetched(self, text: str, source_tool: str) -> Verdict:
        """Check a tool-call result with the bound session_id.

        Parameters:
            text (str): The tool-call result text.
            source_tool (str): The tool that returned this result.

        Returns:
            Verdict: The security verdict.
        """
        return await self.client.check_fetched(text, source_tool=source_tool, session_id=self.session_id)
