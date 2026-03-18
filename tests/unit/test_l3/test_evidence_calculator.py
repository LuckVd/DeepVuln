"""
Tests for P6-03: Evidence Strength Calculator

Tests the evidence strength calculation based on:
- Multi-engine cross-validation
- Confidence levels
- Hallucination checks
- Suspicious type handling
"""

import tempfile
from pathlib import Path

import pytest

from src.layers.l3_analysis.evidence_calculator import (
    calculate_evidence_strength,
    _verify_finding,
)
from src.layers.l3_analysis.models import (
    CodeLocation,
    EvidenceStrength,
    Finding,
    FindingType,
    HallucinationCheckResult,
    SeverityLevel,
)


def create_finding(
    finding_id: str = "test-001",
    finding_type: FindingType = FindingType.VULNERABILITY,
    confidence: float = 0.8,
    file_path: str = "test.py",
    line: int = 1,  # Default to line 1 which always exists
    related_engines: list[str] | None = None,
    duplicate_count: int = 0,
) -> Finding:
    """Helper to create a Finding for testing."""
    finding = Finding(
        id=finding_id,
        type=finding_type,
        severity=SeverityLevel.HIGH,
        confidence=confidence,
        title="Test vulnerability",
        description="Test description",
        location=CodeLocation(file=file_path, line=line),
        source="agent",
    )
    if related_engines:
        finding.related_engines = related_engines
    finding.duplicate_count = duplicate_count
    return finding


class TestHallucinationCheck:
    """Tests for hallucination verification."""

    def test_file_exists_and_line_valid(self):
        """Test successful hallucination check with valid file and line."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\nline4\nline5\n")

            finding = create_finding(file_path="test.py", line=3)
            result = _verify_finding(finding, source_path)

            assert result.file_exists is True
            assert result.line_number_valid is True
            assert result.actual_line_count == 5
            assert result.all_passed is True

    def test_file_not_exists(self):
        """Test hallucination check with missing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)

            finding = create_finding(file_path="missing.py", line=1)
            result = _verify_finding(finding, source_path)

            assert result.file_exists is False
            assert result.has_failure is True

    def test_line_out_of_range(self):
        """Test hallucination check with line number out of range."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\n")

            finding = create_finding(file_path="test.py", line=100)
            result = _verify_finding(finding, source_path)

            assert result.file_exists is True
            assert result.line_number_valid is False
            assert result.has_failure is True


class TestEvidenceStrengthSuspicious:
    """Tests for SUSPICIOUS type always being SPECULATIVE."""

    def test_suspicious_always_speculative(self):
        """SUSPICIOUS type should always be SPECULATIVE evidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("x" * 100)

            # Even with high confidence and multi-engine
            finding = create_finding(
                finding_type=FindingType.SUSPICIOUS,
                confidence=0.95,
                related_engines=["semgrep", "codeql", "agent"],
            )
            findings, counts = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.SPECULATIVE
            assert findings[0].evidence_details["reason"] == "suspicious_type"
            assert counts["speculative"] == 1

    def test_suspicious_with_valid_file(self):
        """SUSPICIOUS with valid file should still be SPECULATIVE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")

            finding = create_finding(
                finding_type=FindingType.SUSPICIOUS,
                file_path="test.py",
                line=2,
            )
            findings, _ = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.SPECULATIVE


class TestEvidenceStrengthLowConfidence:
    """Tests for low confidence being SPECULATIVE."""

    def test_low_confidence_speculative(self):
        """Confidence < 0.5 should be SPECULATIVE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("x" * 100)

            finding = create_finding(confidence=0.4)
            findings, counts = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.SPECULATIVE
            assert findings[0].evidence_details["reason"] == "low_confidence"
            assert counts["speculative"] == 1

    def test_confidence_exactly_0_5_not_speculative(self):
        """Confidence == 0.5 should NOT be speculative."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")  # Ensure file has multiple lines

            finding = create_finding(confidence=0.5, line=2)  # Valid line number
            findings, _ = calculate_evidence_strength([finding], source_path)

            # Should be WEAK (default), not SPECULATIVE
            assert findings[0].evidence_strength != EvidenceStrength.SPECULATIVE


class TestEvidenceStrengthHallucination:
    """Tests for hallucination check failures."""

    def test_missing_file_speculative(self):
        """Missing file should result in SPECULATIVE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)

            finding = create_finding(file_path="missing.py", confidence=0.9)
            findings, counts = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.SPECULATIVE
            assert findings[0].evidence_details["reason"] == "hallucination_check_failed"
            assert counts["speculative"] == 1

    def test_line_out_of_range_speculative(self):
        """Line number out of range should result in SPECULATIVE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\n")

            finding = create_finding(file_path="test.py", line=100, confidence=0.9)
            findings, _ = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.SPECULATIVE


class TestEvidenceStrengthStrong:
    """Tests for STRONG evidence conditions."""

    def test_multi_engine_strong(self):
        """Multi-engine detection should be STRONG."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")  # Multiple lines

            finding = create_finding(
                confidence=0.7,
                related_engines=["semgrep", "codeql"],
            )
            findings, counts = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.STRONG
            assert findings[0].evidence_details["reason"] == "multi_engine"
            assert counts["strong"] == 1

    def test_three_engines_strong(self):
        """Three engines should be STRONG."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")

            finding = create_finding(
                related_engines=["semgrep", "codeql", "agent"],
            )
            findings, _ = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.STRONG

    def test_multiple_detections_strong(self):
        """duplicate_count >= 2 should be STRONG."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")

            finding = create_finding(
                confidence=0.7,
                duplicate_count=2,
            )
            findings, counts = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.STRONG
            assert findings[0].evidence_details["reason"] == "multiple_detections"
            assert counts["strong"] == 1

    def test_high_confidence_verified_strong(self):
        """High confidence (>=0.9) with valid file should be STRONG."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")

            finding = create_finding(
                confidence=0.9,
                file_path="test.py",
                line=2,
            )
            findings, counts = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.STRONG
            assert findings[0].evidence_details["reason"] == "high_confidence_verified"
            assert counts["strong"] == 1


class TestEvidenceStrengthMedium:
    """Tests for MEDIUM evidence conditions."""

    def test_high_confidence_medium(self):
        """High confidence (>=0.8) should be MEDIUM."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")

            finding = create_finding(confidence=0.8)
            findings, counts = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.MEDIUM
            assert findings[0].evidence_details["reason"] == "high_confidence"
            assert counts["medium"] == 1

    def test_merged_finding_medium(self):
        """Merged at least once (duplicate_count >= 1) should be MEDIUM."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")

            finding = create_finding(
                confidence=0.6,
                duplicate_count=1,
            )
            findings, counts = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.MEDIUM
            assert findings[0].evidence_details["reason"] == "merged_finding"
            assert counts["medium"] == 1


class TestEvidenceStrengthWeak:
    """Tests for WEAK evidence conditions."""

    def test_moderate_confidence_weak(self):
        """Moderate confidence should default to WEAK."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")

            finding = create_finding(confidence=0.6)
            findings, counts = calculate_evidence_strength([finding], source_path)

            assert findings[0].evidence_strength == EvidenceStrength.WEAK
            assert findings[0].evidence_details["reason"] == "default"
            assert counts["weak"] == 1


class TestEvidenceStrengthCounts:
    """Tests for evidence strength counts."""

    def test_mixed_findings_counts(self):
        """Test correct counts for mixed findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            test_file = source_path / "test.py"
            test_file.write_text("line1\nline2\nline3\n")

            findings = [
                create_finding("f1", related_engines=["semgrep", "codeql"]),  # strong
                create_finding("f2", confidence=0.8),  # medium
                create_finding("f3", confidence=0.6),  # weak
                create_finding("f4", finding_type=FindingType.SUSPICIOUS),  # speculative
            ]
            findings, counts = calculate_evidence_strength(findings, source_path)

            assert counts["strong"] == 1
            assert counts["medium"] == 1
            assert counts["weak"] == 1
            assert counts["speculative"] == 1


class TestHallucinationCheckResult:
    """Tests for HallucinationCheckResult model."""

    def test_all_passed(self):
        """Test all_passed property."""
        result = HallucinationCheckResult(
            file_exists=True,
            line_number_valid=True,
            file_path="test.py",
        )
        assert result.all_passed is True
        assert result.has_failure is False

    def test_has_failure(self):
        """Test has_failure property."""
        result = HallucinationCheckResult(
            file_exists=False,
            line_number_valid=True,
            file_path="test.py",
        )
        assert result.all_passed is False
        assert result.has_failure is True

    def test_to_dict(self):
        """Test to_dict method."""
        result = HallucinationCheckResult(
            file_exists=True,
            line_number_valid=False,
            file_path="test.py",
            actual_line_count=10,
            reported_line=100,
        )
        d = result.to_dict()
        assert d["all_passed"] is False
        assert d["file_exists"] is True
        assert d["line_number_valid"] is False
