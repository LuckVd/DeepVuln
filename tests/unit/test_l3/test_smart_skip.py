"""
Unit tests for smart skip functionality in adversarial verification.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.layers.l3_analysis.verification.adversarial import (
    AdversarialVerifier,
    AdversarialVerifierConfig,
)
from src.layers.l3_analysis.verification.models import VerdictType


class TestSmartSkipConfig:
    """Test cases for smart skip configuration."""

    def test_default_config_skip_low_confidence_enabled(self):
        """Test that skip_low_confidence is enabled by default."""
        config = AdversarialVerifierConfig()
        assert config.skip_low_confidence is True
        assert config.min_confidence_to_verify == 0.3

    def test_default_config_deduplicate_enabled(self):
        """Test that deduplicate_similar is enabled by default."""
        config = AdversarialVerifierConfig()
        assert config.deduplicate_similar is True
        assert config.similarity_threshold == 0.8

    def test_custom_config(self):
        """Test custom configuration values."""
        config = AdversarialVerifierConfig(
            skip_low_confidence=False,
            min_confidence_to_verify=0.5,
            deduplicate_similar=False,
            similarity_threshold=0.9,
        )
        assert config.skip_low_confidence is False
        assert config.min_confidence_to_verify == 0.5
        assert config.deduplicate_similar is False
        assert config.similarity_threshold == 0.9


class TestLowConfidenceSkip:
    """Test cases for low confidence skip functionality."""

    @pytest.fixture
    def verifier(self):
        """Create a verifier with mock LLM client."""
        mock_llm = MagicMock()
        return AdversarialVerifier(llm_client=mock_llm)

    def test_skip_low_confidence_finding(self, verifier):
        """Test that low confidence findings are skipped."""
        finding = {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "location": "app.py:100",
            "confidence": 0.2,  # Below default threshold of 0.3
        }

        assert verifier._should_skip(finding) is True
        assert verifier._skip_stats["low_confidence"] == 1

    def test_not_skip_normal_confidence_finding(self, verifier):
        """Test that normal confidence findings are not skipped."""
        finding = {
            "id": "test-002",
            "type": "sql_injection",
            "severity": "high",
            "location": "app.py:100",
            "confidence": 0.5,  # Above threshold
        }

        assert verifier._should_skip(finding) is False

    def test_skip_with_custom_threshold(self):
        """Test skip with custom confidence threshold."""
        mock_llm = MagicMock()
        config = AdversarialVerifierConfig(
            skip_low_confidence=True,
            min_confidence_to_verify=0.6,
        )
        verifier = AdversarialVerifier(llm_client=mock_llm, config=config)

        finding = {
            "id": "test-003",
            "type": "sql_injection",
            "severity": "high",
            "confidence": 0.5,  # Below custom threshold
        }

        assert verifier._should_skip(finding) is True

    def test_disabled_low_confidence_skip(self):
        """Test that skip can be disabled."""
        mock_llm = MagicMock()
        config = AdversarialVerifierConfig(skip_low_confidence=False)
        verifier = AdversarialVerifier(llm_client=mock_llm, config=config)

        finding = {
            "id": "test-004",
            "type": "sql_injection",
            "severity": "high",
            "confidence": 0.1,  # Very low but skip disabled
        }

        assert verifier._should_skip(finding) is False


class TestDuplicateSkip:
    """Test cases for duplicate finding skip functionality."""

    @pytest.fixture
    def verifier(self):
        """Create a verifier with mock LLM client."""
        mock_llm = MagicMock()
        return AdversarialVerifier(llm_client=mock_llm)

    def test_first_finding_not_skipped(self, verifier):
        """Test that the first finding of a type is not skipped."""
        finding = {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/db.py:50",
            "confidence": 0.9,  # High enough to be recorded
        }

        assert verifier._should_skip(finding) is False

    def test_duplicate_finding_skipped(self, verifier):
        """Test that duplicate findings are skipped."""
        # First finding - should not be skipped
        finding1 = {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/db.py:50",
            "confidence": 0.9,
        }
        verifier._should_skip(finding1)

        # Second finding of same type in same file pattern - should be skipped
        finding2 = {
            "id": "test-002",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/db.py:100",  # Same file, different line
            "confidence": 0.8,
        }

        assert verifier._should_skip(finding2) is True
        assert verifier._skip_stats["duplicate"] == 1

    def test_different_types_not_skipped(self, verifier):
        """Test that different finding types are not skipped as duplicates."""
        finding1 = {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/db.py:50",
            "confidence": 0.9,
        }
        verifier._should_skip(finding1)

        finding2 = {
            "id": "test-002",
            "type": "xss",  # Different type
            "severity": "high",
            "location": "app/db.py:100",
            "confidence": 0.8,
        }

        assert verifier._should_skip(finding2) is False

    def test_different_files_not_skipped(self, verifier):
        """Test that findings in different files are not skipped as duplicates."""
        finding1 = {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/db.py:50",
            "confidence": 0.9,
        }
        verifier._should_skip(finding1)

        finding2 = {
            "id": "test-002",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/api.py:100",  # Different file
            "confidence": 0.8,
        }

        assert verifier._should_skip(finding2) is False

    def test_disabled_deduplication(self):
        """Test that deduplication can be disabled."""
        mock_llm = MagicMock()
        config = AdversarialVerifierConfig(deduplicate_similar=False)
        verifier = AdversarialVerifier(llm_client=mock_llm, config=config)

        finding1 = {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/db.py:50",
            "confidence": 0.9,
        }
        verifier._should_skip(finding1)

        finding2 = {
            "id": "test-002",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/db.py:100",
            "confidence": 0.8,
        }

        # Should not be skipped even though it's similar
        assert verifier._should_skip(finding2) is False


class TestFilePatternExtraction:
    """Test cases for file pattern extraction."""

    @pytest.fixture
    def verifier(self):
        """Create a verifier with mock LLM client."""
        mock_llm = MagicMock()
        return AdversarialVerifier(llm_client=mock_llm)

    def test_extract_pattern_with_line_number(self, verifier):
        """Test pattern extraction with line number."""
        pattern = verifier._extract_file_pattern("app/db.py:100")
        assert pattern == "app/db.py"

    def test_extract_pattern_without_line_number(self, verifier):
        """Test pattern extraction without line number."""
        pattern = verifier._extract_file_pattern("app/db.py")
        assert pattern == "app/db.py"

    def test_extract_pattern_deep_path(self, verifier):
        """Test pattern extraction from deep path."""
        pattern = verifier._extract_file_pattern("src/layers/l3/engines/codeql.py:50")
        # Returns last 2 components: engines/codeql.py
        assert pattern == "engines/codeql.py"

    def test_extract_pattern_single_component(self, verifier):
        """Test pattern extraction from single component path."""
        pattern = verifier._extract_file_pattern("main.py:10")
        assert pattern == "main.py"

    def test_extract_pattern_empty(self, verifier):
        """Test pattern extraction from empty string."""
        pattern = verifier._extract_file_pattern("")
        assert pattern == ""


class TestSkipStatistics:
    """Test cases for skip statistics."""

    @pytest.fixture
    def verifier(self):
        """Create a verifier with mock LLM client."""
        mock_llm = MagicMock()
        return AdversarialVerifier(llm_client=mock_llm)

    def test_initial_stats(self, verifier):
        """Test initial statistics are zero."""
        stats = verifier.get_skip_statistics()
        assert stats["low_confidence"] == 0
        assert stats["duplicate"] == 0
        assert stats["low_severity"] == 0
        assert stats["info_level"] == 0

    def test_stats_update(self, verifier):
        """Test statistics are updated correctly."""
        # Trigger low confidence skip
        verifier._should_skip({
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "confidence": 0.1,
        })

        # Trigger info level skip
        verifier._should_skip({
            "id": "test-002",
            "type": "info",
            "severity": "info",
            "confidence": 0.9,
        })

        stats = verifier.get_skip_statistics()
        assert stats["low_confidence"] == 1
        assert stats["info_level"] == 1

    def test_reset_stats(self, verifier):
        """Test resetting statistics."""
        # Trigger some skips
        verifier._should_skip({
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "confidence": 0.1,
        })

        # Reset
        verifier.reset_deduplication_cache()

        stats = verifier.get_skip_statistics()
        assert stats["low_confidence"] == 0
        assert len(verifier._verified_types) == 0


class TestSkippedResult:
    """Test cases for skipped result creation."""

    @pytest.fixture
    def verifier(self):
        """Create a verifier with mock LLM client."""
        mock_llm = MagicMock()
        return AdversarialVerifier(llm_client=mock_llm)

    def test_skipped_result_low_confidence(self, verifier):
        """Test skipped result for low confidence finding."""
        finding = {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "location": "app.py:100",
            "confidence": 0.2,
        }

        result = verifier._create_skipped_result(finding, "test-001")

        assert result.finding_id == "test-001"
        assert result.verdict.verdict == VerdictType.NEEDS_REVIEW
        assert "Low initial confidence" in result.verdict.reasoning
        assert result.rounds_completed == 0

    def test_skipped_result_duplicate(self, verifier):
        """Test skipped result for duplicate finding."""
        finding = {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/db.py:50",
            "confidence": 0.9,
        }

        # First finding gets recorded
        verifier._should_skip(finding)

        # Second finding should be skipped as duplicate
        finding2 = {
            "id": "test-002",
            "type": "sql_injection",
            "severity": "high",
            "location": "app/db.py:100",
            "confidence": 0.8,
        }

        result = verifier._create_skipped_result(finding2, "test-002")

        assert "Duplicate" in result.verdict.reasoning
