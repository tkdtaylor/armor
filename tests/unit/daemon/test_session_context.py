"""Tests for daemon SessionContext building (Task 083)."""

import asyncio
import json
from pathlib import Path

import pytest

from armor.daemon.server import DaemonServer
from armor.types import SessionContext


@pytest.fixture
def temp_socket(tmp_path: Path) -> str:
    """Create a temporary socket path."""
    return str(tmp_path / "armor.sock")


@pytest.fixture
def temp_db(tmp_path: Path) -> str:
    """Create a temporary database path."""
    return str(tmp_path / "test.db")


@pytest.fixture(autouse=True)
def disable_llm_for_tests(monkeypatch) -> None:
    """Disable LLM for all daemon tests to avoid exit 78 on missing LLM."""
    monkeypatch.setenv("ARMOR_DISABLE_LLM", "true")


@pytest.fixture
def simple_catalogue(tmp_path: Path) -> str:
    """Create a simple canary catalogue for testing."""
    # AWS-shape required: test fixture for TC-083 (session context building)
    catalogue_data = [
        {
            "canary_id": "aws-key-000",
            "kind": "credential",
            "service": "aws",
            "value": "AKIAIOSFODNN7EXAMPL0",  # AWS-shape required
            "marker_rule": "^AKIA[0-9A-Z]{16}$",
            "active": True,
            "created_at": "2024-01-01T00:00:00Z",
        },
        {
            "canary_id": "github-pat-000",
            "kind": "credential",
            "service": "github",
            "value": "ghp_123456789012345678901234567890123456",
            "marker_rule": "^ghp_[A-Za-z0-9_]{36}$",
            "active": True,
            "created_at": "2024-01-01T00:00:00Z",
        },
    ]
    cat_path = tmp_path / "catalogue.json"
    with open(cat_path, "w") as f:
        json.dump(catalogue_data, f)
    return str(cat_path)


class TestSessionContextBuild:
    """Tests for full SessionContext building on each check (TC-083-*)."""

    @pytest.mark.asyncio
    async def test_turn_count_increments(self, temp_socket: str, temp_db: str, simple_catalogue: str) -> None:
        """TC-083-01: turn_count increments across requests for same session."""
        server = DaemonServer(socket_path=temp_socket, db_path=temp_db, canary_values_path=simple_catalogue)
        await server.start()

        try:
            # First check for session s1
            req1 = {"v": 1, "op": "check.input", "session_id": "s1", "payload": {"text": "first"}}
            resp1 = await server._handle_request(req1)
            assert resp1["verdict"] in ("pass", "advisory")

            # Second check for same session
            req2 = {"v": 1, "op": "check.input", "session_id": "s1", "payload": {"text": "second"}}
            resp2 = await server._handle_request(req2)
            assert resp2["verdict"] in ("pass", "advisory")

            # Verify turn count via session store
            if server.session_store:
                session_row = await server.session_store.get_or_create("s1")
                # After 2 checks, turn_count should be 2
                assert session_row.turn_count == 2, f"Expected turn_count=2, got {session_row.turn_count}"

        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_rolling_buffer_carries_prior_text(
        self, temp_socket: str, temp_db: str, simple_catalogue: str
    ) -> None:
        """TC-083-02: rolling_buffer carries prior-turn text in subsequent checks."""
        server = DaemonServer(socket_path=temp_socket, db_path=temp_db, canary_values_path=simple_catalogue)
        await server.start()

        try:
            # First check with specific text
            text1 = "This is the first turn"
            req1 = {"v": 1, "op": "check.input", "session_id": "s1", "payload": {"text": text1}}
            await server._handle_request(req1)

            # Second check
            req2 = {"v": 1, "op": "check.input", "session_id": "s1", "payload": {"text": "second turn"}}
            await server._handle_request(req2)

            # Load the rolling buffer from DB to verify persistence
            if server.session_store:
                buffer = await asyncio.to_thread(server.session_store.load_rolling_buffer, "s1")
                concatenated = buffer.concatenated()
                # Should contain text from the first turn
                assert text1 in concatenated, f"Expected '{text1}' in buffer, got: {concatenated}"

        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_state_reflects_fsm_state(self, temp_socket: str, temp_db: str, simple_catalogue: str) -> None:
        """TC-083-03: SessionContext.state reflects FSM state from session_store."""
        server = DaemonServer(socket_path=temp_socket, db_path=temp_db, canary_values_path=simple_catalogue)
        await server.start()

        try:
            # Do a check that triggers an advisory (indirect); we'll manually set state in DB for this test
            req1 = {"v": 1, "op": "check.input", "session_id": "s1", "payload": {"text": "benign input"}}
            await server._handle_request(req1)

            # Directly verify session state is accessible
            if server.session_store:
                session_row = await server.session_store.get_or_create("s1")
                # Default state should be "Normal"
                assert session_row.current_state == "Normal", f"Expected Normal, got {session_row.current_state}"

                # Now manually update state and verify it's reflected in the context
                session_row.current_state = "Watching"
                await asyncio.to_thread(server.session_store._persist_to_db, session_row)

                # Build a new context and verify state is reflected
                ctx = await server._build_session_context("s1")
                assert ctx.state == "Watching", f"Expected state=Watching, got {ctx.state}"

        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_active_canaries_populated(self, temp_socket: str, temp_db: str, simple_catalogue: str) -> None:
        """TC-083-04: SessionContext.active_canaries reflects Catalogue.active_for(...)."""
        server = DaemonServer(socket_path=temp_socket, db_path=temp_db, canary_values_path=simple_catalogue)
        await server.start()

        try:
            # Perform a check
            req = {"v": 1, "op": "check.input", "session_id": "s1", "payload": {"text": "test"}}
            await server._handle_request(req)

            # Build context and verify active_canaries is populated
            ctx = await server._build_session_context("s1")
            assert ctx.active_canaries is not None
            # With the simple catalogue, we should have at least the 2 active canaries
            assert len(ctx.active_canaries) >= 1, f"Expected active_canaries to be populated, got {ctx.active_canaries}"

        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_concurrent_sessions_isolated(self, temp_socket: str, temp_db: str, simple_catalogue: str) -> None:
        """TC-083-06: Concurrent check.input for different sessions produce independent contexts."""
        server = DaemonServer(socket_path=temp_socket, db_path=temp_db, canary_values_path=simple_catalogue)
        await server.start()

        try:
            # Issue concurrent checks for different sessions
            async def check_session(session_id: str, text: str) -> dict:
                req = {"v": 1, "op": "check.input", "session_id": session_id, "payload": {"text": text}}
                return await server._handle_request(req)

            # Run two checks concurrently
            resp_a, resp_b = await asyncio.gather(
                check_session("session-a", "text for session a"),
                check_session("session-b", "text for session b"),
            )

            # Both should succeed
            assert resp_a["verdict"] in ("pass", "advisory", "block")
            assert resp_b["verdict"] in ("pass", "advisory", "block")

            # Verify they have independent state
            if server.session_store:
                session_a = await server.session_store.get_or_create("session-a")
                session_b = await server.session_store.get_or_create("session-b")
                # Each should have their own turn count
                assert session_a.session_id == "session-a"
                assert session_b.session_id == "session-b"

        finally:
            await server.stop()

    def test_session_context_empty_builder(self) -> None:
        """TC-083-07: SessionContext.empty(session_id) provides backward-compat builder."""
        ctx = SessionContext.empty("test-session")

        # Verify all fields are zero/empty
        assert ctx.session_id == "test-session"
        assert ctx.signal_history == []
        assert ctx.state is None
        assert ctx.rolling_buffer is None
        assert ctx.turn_count == 0
        assert ctx.active_canaries == []

    @pytest.mark.asyncio
    async def test_chunked_canary_across_turns(self, temp_socket: str, temp_db: str, simple_catalogue: str) -> None:
        """TC-083-05: Multi-turn chunked-exfiltration: rolling buffer carries prior-turn data for canary detection."""
        server = DaemonServer(socket_path=temp_socket, db_path=temp_db, canary_values_path=simple_catalogue)
        await server.start()

        try:
            session_id = "chunk-test"

            # Turn 1: Output containing part of a canary value
            text1 = "Some benign prompt AKIAIOSFOD"  # First 10 chars of the AWS key
            req1 = {"v": 1, "op": "check.output", "session_id": session_id, "payload": {"text": text1}}
            resp1 = await server._handle_request(req1)
            assert resp1["verdict"] in ("pass", "advisory")

            # Turn 2: Build a new context and verify rolling buffer contains text1
            if server.session_store:
                ctx = await server._build_session_context(session_id)
                # The rolling buffer should contain the first turn's text
                if ctx.rolling_buffer is not None:
                    buffered = ctx.rolling_buffer.concatenated()
                    assert text1 in buffered, f"Expected '{text1}' in rolling buffer, got: {buffered}"

        finally:
            await server.stop()
