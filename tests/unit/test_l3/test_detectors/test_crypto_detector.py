"""Tests for CryptoMisuseDetector."""

import pytest

from src.layers.l3_analysis.engines.ast_engine.detectors.crypto_detector import (
    CryptoMisuseDetector,
)
from src.layers.l3_analysis.models import SeverityLevel


@pytest.mark.asyncio
class TestCryptoMisuseDetector:
    """Test CryptoMisuseDetector functionality."""

    async def test_detector_type(self) -> None:
        """Test detector type."""
        detector = CryptoMisuseDetector()
        assert detector.detector_type() == "crypto_misuse"

    async def test_test_file_detection(self) -> None:
        """Test that test files are detected."""
        detector = CryptoMisuseDetector()

        # Test file paths
        assert detector._is_test_file("tests/test_crypto.py") is True
        assert detector._is_test_file("test/check.py") is True
        assert detector._is_test_file("src/crypto_test.py") is True

        # Non-test file paths
        assert detector._is_test_file("src/crypto.py") is False
        assert detector._is_test_file("app.py") is False
        assert detector._is_test_file("main.py") is False

    async def test_detect_weak_crypto_in_test_file(self) -> None:
        """Test detecting weak crypto in test file."""
        detector = CryptoMisuseDetector()

        code = "hashlib.md5(data)"
        findings = await detector.detect(code, "python", "tests/test_crypto.py")

        # Should find the weak crypto but with INFO severity
        assert len(findings) > 0
        finding = findings[0]
        assert finding.metadata.get("in_test_code") is True
        assert finding.severity == SeverityLevel.INFO

    async def test_detect_weak_crypto_in_source_file(self) -> None:
        """Test detecting weak crypto in source file."""
        detector = CryptoMisuseDetector()

        code = "hashlib.md5(data)"
        findings = await detector.detect(code, "python", "src/crypto.py")

        # Should find the weak crypto
        assert len(findings) > 0
        finding = findings[0]
        # Note: The query captures 'hashlib' identifier, not the full expression
        # So file_path based validation works but metadata may not show it clearly
        assert finding.severity == SeverityLevel.MEDIUM

    async def test_rules_loaded(self) -> None:
        """Test that rules are loaded from YAML files."""
        detector = CryptoMisuseDetector()
        assert len(detector._rules) > 0
