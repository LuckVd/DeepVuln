"""
Unit tests for StreamingValidator - P8-08c component.

Tests cover all validation criteria:
1. Execution evidence checking
2. Confidence calibration
3. Config issue detection
4. Finding downgrading
"""

import pytest

from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    SeverityLevel,
)
from src.layers.l3_analysis.pre_filter.streaming_validator import (
    StreamingValidator,
    ValidationResult,
    validate_finding,
)


class TestStreamingValidator:
    """Test suite for StreamingValidator class."""

    def test_init_default_mode(self):
        """Test initialization with default (non-strict) mode."""
        validator = StreamingValidator()
        assert validator.strict_mode is False

    def test_init_strict_mode(self):
        """Test initialization with strict mode."""
        validator = StreamingValidator(strict_mode=True)
        assert validator.strict_mode is True


class TestExecutionEvidenceCheck:
    """Test execution evidence validation."""

    def make_finding(self, snippet: str, confidence: float = 0.8) -> Finding:
        """Helper to create a test finding."""
        return Finding(
            id="test-001",
            rule_id="sql_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=confidence,
            title="Test Finding",
            description="Test description",
            fix_suggestion="Fix it",
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet=snippet,
            ),
            source="agent",
        )

    def test_has_execution_evidence_accepted(self):
        """Test finding with execution evidence is accepted."""
        validator = StreamingValidator()
        finding = self.make_finding('db.execute("SELECT * FROM users WHERE id = " + user_input)')

        result = validator.validate_finding(finding)

        assert result.accept is True
        assert result.adjusted_finding is not None

    def test_construction_only_downgraded(self):
        """Test construction-only finding is downgraded."""
        validator = StreamingValidator()
        finding = self.make_finding('shell = ProcessBuilder(cmd)', confidence=0.8)

        result = validator.validate_finding(finding)

        # Should be downgraded, not dropped (since confidence > 0.5)
        assert result.accept is True
        assert result.adjusted_finding.confidence < 0.8
        assert "downgraded" in result.reason.lower()

    def test_low_confidence_no_evidence_dropped(self):
        """Test low-confidence finding without evidence is dropped."""
        validator = StreamingValidator()
        finding = self.make_finding('shell = ProcessBuilder(cmd)', confidence=0.4)

        result = validator.validate_finding(finding)

        assert result.accept is False
        assert "dropped" in result.reason.lower()

    def test_return_only_string_downgraded(self):
        """Test finding with only return statement is downgraded."""
        validator = StreamingValidator()
        finding = self.make_finding('return "File uploaded: " + filename', confidence=0.7)

        result = validator.validate_finding(finding)

        assert result.accept is True
        assert result.adjusted_finding.confidence < 0.7

    def test_xss_with_json_response_rejected(self):
        """Test XSS finding with JSON response is handled correctly."""
        validator = StreamingValidator()
        finding = Finding(
            id="test-xss",
            rule_id="xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="XSS in API",
            description="User input reflected in response",
            fix_suggestion="Escape output",
            location=CodeLocation(
                file="api.js",
                line=1,
                end_line=1,
                snippet='res.json({ name: req.query.name })',
            ),
            source="agent",
        )

        result = validator.validate_finding(finding)

        # Should be rejected or downgraded
        assert result.accept is False or result.adjusted_finding.confidence < 0.5


class TestConfidenceCalibration:
    """Test confidence calibration."""

    def test_high_confidence_without_strong_evidence(self):
        """Test high confidence without strong evidence is downgraded."""
        validator = StreamingValidator()
        finding = Finding(
            id="test-002",
            rule_id="cmd_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            title="Command Injection",
            description="Possible command injection",
            fix_suggestion="Use safe alternatives",
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet='os.system(cmd)',
            ),
            source="agent",
        )

        result = validator.validate_finding(finding)

        # Should be downgraded (no PoC, no dataflow, short snippet)
        assert result.accept is True
        assert result.adjusted_finding.confidence < 0.9

    def test_high_confidence_with_poc_accepted(self):
        """Test high confidence with PoC is accepted."""
        validator = StreamingValidator()
        finding = Finding(
            id="test-003",
            rule_id="cmd_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            confidence=0.95,
            title="Command Injection",
            description="Confirmed command injection",
            fix_suggestion="Use subprocess with safe args",
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=5,
                snippet='os.system(user_input)',
            ),
            source="agent",
            metadata={"poc": "curl -X POST 'http://target/cmd?cmd=whoami'"},
        )

        result = validator.validate_finding(finding)

        assert result.accept is True
        # High confidence should be maintained with PoC
        assert result.adjusted_finding.confidence >= 0.9


class TestConfigIssueDetection:
    """Test configuration issue detection."""

    def test_dockerfile_marked_as_config(self):
        """Test Dockerfile finding is marked as config issue."""
        validator = StreamingValidator()
        finding = Finding(
            id="docker-001",
            rule_id="docker_best_practices",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.8,
            title="Missing USER directive",
            description="Dockerfile should specify USER",
            fix_suggestion="Add USER directive",
            location=CodeLocation(
                file="Dockerfile",
                line=1,
                end_line=1,
                snippet="FROM python:3.10",
            ),
            source="agent",
        )

        result = validator.validate_finding(finding)

        assert result.accept is True
        assert result.adjusted_finding.metadata.get("category") == "CONFIG"
        assert result.adjusted_finding.severity == SeverityLevel.INFO

    def test_yaml_file_marked_as_config(self):
        """Test YAML file finding is marked as config issue."""
        validator = StreamingValidator()
        finding = Finding(
            id="config-001",
            rule_id="hardcoded_secret",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.7,
            title="Possible secret in config",
            description="Config file may contain secrets",
            fix_suggestion="Use environment variables",
            location=CodeLocation(
                file="config/app.yaml",
                line=1,
                end_line=1,
                snippet="secret: 'test123'",
            ),
            source="agent",
        )

        result = validator.validate_finding(finding)

        assert result.accept is True
        assert result.adjusted_finding.metadata.get("category") == "CONFIG"


class TestConvenienceFunction:
    """Test the validate_finding convenience function."""

    def test_returns_tuple(self):
        """Test function returns (bool, Finding, str) tuple."""
        finding = Finding(
            id="test-004",
            rule_id="test",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.LOW,
            confidence=0.5,
            title="Test",
            description="Test",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="test",
            ),
            source="agent",
        )

        accept, adjusted, reason = validate_finding(finding)

        assert isinstance(accept, bool)
        assert isinstance(reason, str)
        # adjusted may be None if dropped


class TestIntegrationScenarios:
    """Integration tests for real-world scenarios."""

    def test_path_traversal_with_string_only(self):
        """Test path traversal with only string concatenation."""
        validator = StreamingValidator()
        finding = Finding(
            id="pt-001",
            rule_id="path_traversal",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.7,
            title="Path Traversal",
            description="User input in file path",
            fix_suggestion="Validate and sanitize input",
            location=CodeLocation(
                file="handlers.py",
                line=10,
                end_line=10,
                snippet='return f"File: {filename}"',
            ),
            source="agent",
        )

        result = validator.validate_finding(finding)

        # Should be downgraded (no actual file operation)
        assert result.accept is True
        assert result.adjusted_finding.confidence < 0.7

    def test_sql_injection_with_execute_accepted(self):
        """Test SQL injection with actual execute is accepted."""
        validator = StreamingValidator()
        finding = Finding(
            id="sqli-001",
            rule_id="sql_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            confidence=0.9,
            title="SQL Injection",
            description="User input in SQL query",
            fix_suggestion="Use parameterized queries",
            location=CodeLocation(
                file="dao.py",
                line=20,
                end_line=20,
                snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            ),
            source="agent",
        )

        result = validator.validate_finding(finding)

        assert result.accept is True
        # High confidence should be maintained (has execution evidence)
