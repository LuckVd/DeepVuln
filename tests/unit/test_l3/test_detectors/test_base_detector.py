"""Tests for BaseDetector."""

from pathlib import Path

import pytest

from src.layers.l3_analysis.engines.ast_engine.detectors.base_detector import BaseDetector
from src.layers.l3_analysis.models import Finding


class MockDetector(BaseDetector):
    """Mock detector for testing."""

    def detector_type(self) -> str:
        return "mock"

    def _get_default_rules_dir(self) -> Path:
        return Path("tests/unit/test_l3/test_detectors/fixtures/rules")


@pytest.mark.asyncio
class TestBaseDetector:
    """Test BaseDetector functionality."""

    async def test_detect_returns_list(self) -> None:
        """Test that detect returns a list."""
        detector = MockDetector()
        result = await detector.detect(
            code="x = 1",
            language="python",
            file_path="test.py",
        )
        assert isinstance(result, list)

    async def test_post_validate_default_noop(self) -> None:
        """Test that _post_validate returns findings unchanged by default."""
        detector = MockDetector()

        # Create a mock finding
        from src.layers.l3_analysis.models import CodeLocation, SeverityLevel

        finding = Finding(
            id="test-1",
            rule_id="test",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Test",
            description="Test",
            location=CodeLocation(file="test.py", line=1),
            source="ast_engine",
        )

        result = await detector._post_validate([finding], "code", "python", "test.py")
        assert len(result) == 1
        assert result[0].id == "test-1"
