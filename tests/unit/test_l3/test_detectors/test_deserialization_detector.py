"""Tests for DeserializationDetector."""

import pytest

from src.layers.l3_analysis.engines.ast_engine.detectors.deserialization_detector import (
    DeserializationDetector,
)


@pytest.mark.asyncio
class TestDeserializationDetector:
    """Test DeserializationDetector functionality."""

    async def test_detector_type(self) -> None:
        """Test detector type."""
        detector = DeserializationDetector()
        assert detector.detector_type() == "deserialization"

    async def test_detect_pickle_load(self) -> None:
        """Test detecting pickle.load."""
        detector = DeserializationDetector()

        code = "pickle.load(data)"
        findings = await detector.detect(code, "python", "test.py")

        # Should find the pickle.load
        assert len(findings) > 0
        finding = findings[0]
        assert "pickle" in finding.rule_id or "load" in finding.rule_id
        assert finding.metadata.get("validation") == "basic_pattern_only"

    async def test_detect_yaml_load(self) -> None:
        """Test detecting yaml.load."""
        detector = DeserializationDetector()

        code = "yaml.load(data)"
        findings = await detector.detect(code, "python", "test.py")

        # Should find the yaml.load
        assert len(findings) > 0
        finding = findings[0]
        assert "yaml" in finding.rule_id or "load" in finding.rule_id

    async def test_rules_loaded(self) -> None:
        """Test that rules are loaded from YAML files."""
        detector = DeserializationDetector()
        assert len(detector._rules) > 0
