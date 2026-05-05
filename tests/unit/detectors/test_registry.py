"""Unit tests for the detector registry."""

from unittest.mock import MagicMock, patch

from armor.detectors import DetectorRegistry
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
