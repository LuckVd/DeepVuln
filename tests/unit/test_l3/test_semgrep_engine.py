"""
Unit tests for SemgrepEngine.

Tests cover:
- Engine availability check
- Scan command building
- Result parsing
- Finding conversion
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.layers.l3_analysis.engines.semgrep import (
    OFFICIAL_RULE_SETS,
    SemgrepEngine,
    engine_registry,
)
from src.layers.l3_analysis.models import (
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)


class TestSemgrepEngine:
    """Test SemgrepEngine class."""

    def test_engine_metadata(self):
        """Test engine metadata is correctly set."""
        engine = SemgrepEngine()
        assert engine.name == "semgrep"
        assert "python" in engine.supported_languages
        assert "java" in engine.supported_languages
        assert "go" in engine.supported_languages

    def test_is_available_when_installed(self):
        """Test availability check when semgrep is installed."""
        engine = SemgrepEngine()
        # Should be True since we installed semgrep
        assert engine.is_available() is True

    def test_is_available_when_not_installed(self):
        """Test availability check when semgrep is not installed."""
        engine = SemgrepEngine(semgrep_path="nonexistent_semgrep_binary")
        assert engine.is_available() is False

    def test_supports_language(self):
        """Test language support check."""
        engine = SemgrepEngine()
        assert engine.supports_language("python") is True
        assert engine.supports_language("java") is True
        assert engine.supports_language("go") is True
        assert engine.supports_language("javascript") is True
        assert engine.supports_language("unknown_lang") is False

    def test_official_rule_sets_defined(self):
        """Test official rule sets are defined."""
        assert "security" in OFFICIAL_RULE_SETS
        assert "owasp-top-ten" in OFFICIAL_RULE_SETS
        assert "java" in OFFICIAL_RULE_SETS
        assert "python" in OFFICIAL_RULE_SETS


class TestSemgrepScanCommand:
    """Test Semgrep scan command building."""

    @pytest.mark.asyncio
    async def test_build_basic_scan_command(self, tmp_path):
        """Test building basic scan command."""
        engine = SemgrepEngine()
        cmd = await engine._build_scan_command(
            source_path=tmp_path,
            rules=None,
            rule_sets=None,
            languages=None,
            exclude_patterns=None,
            include_patterns=None,
            use_auto_config=False,
        )

        assert "semgrep" in cmd
        assert "--json" in cmd
        assert "--quiet" in cmd
        assert "--metrics=off" in cmd

    @pytest.mark.asyncio
    async def test_build_command_with_auto_config(self, tmp_path):
        """Test building command with auto config."""
        engine = SemgrepEngine()
        cmd = await engine._build_scan_command(
            source_path=tmp_path,
            rules=None,
            rule_sets=None,
            languages=None,
            exclude_patterns=None,
            include_patterns=None,
            use_auto_config=True,
        )

        assert "--config" in cmd
        auto_idx = cmd.index("--config")
        assert cmd[auto_idx + 1] == "auto"

    @pytest.mark.asyncio
    async def test_build_command_with_rule_sets(self, tmp_path):
        """Test building command with rule sets.

        Note: OFFICIAL_RULE_SETS now maps to 'auto' config which includes
        security rules. Semgrep registry URLs have changed.
        """
        engine = SemgrepEngine()
        cmd = await engine._build_scan_command(
            source_path=tmp_path,
            rules=None,
            rule_sets=["security", "java"],
            languages=None,
            exclude_patterns=None,
            include_patterns=None,
            use_auto_config=False,
        )

        assert "--config" in cmd
        config_idx = cmd.index("--config")
        config_value = cmd[config_idx + 1]
        # OFFICIAL_RULE_SETS now uses 'auto' which includes security rules
        assert "auto" in config_value
        # Should also have metrics enabled for auto config
        assert "--metrics=on" in cmd

    @pytest.mark.asyncio
    async def test_build_command_with_custom_rules(self, tmp_path):
        """Test building command with custom rules."""
        engine = SemgrepEngine()
        cmd = await engine._build_scan_command(
            source_path=tmp_path,
            rules=["rules/semgrep/python/"],
            rule_sets=None,
            languages=None,
            exclude_patterns=None,
            include_patterns=None,
            use_auto_config=False,
        )

        assert "--config" in cmd
        config_idx = cmd.index("--config")
        assert "rules/semgrep/python/" in cmd[config_idx + 1]

    @pytest.mark.asyncio
    async def test_build_command_with_language_filter(self, tmp_path):
        """Test building command with language filter."""
        engine = SemgrepEngine()
        cmd = await engine._build_scan_command(
            source_path=tmp_path,
            rules=None,
            rule_sets=None,
            languages=["python", "java"],
            exclude_patterns=None,
            include_patterns=None,
            use_auto_config=False,
        )

        assert "--lang" in cmd
        assert "python" in cmd
        assert "java" in cmd

    @pytest.mark.asyncio
    async def test_build_command_with_exclude_patterns(self, tmp_path):
        """Test building command with exclude patterns."""
        engine = SemgrepEngine()
        cmd = await engine._build_scan_command(
            source_path=tmp_path,
            rules=None,
            rule_sets=None,
            languages=None,
            exclude_patterns=["**/test/**", "**/node_modules/**"],
            include_patterns=None,
            use_auto_config=False,
        )

        assert "--exclude" in cmd
        assert "**/test/**" in cmd
        assert "**/node_modules/**" in cmd


class TestSemgrepResultParsing:
    """Test Semgrep result parsing."""

    def test_parse_empty_results(self, tmp_path):
        """Test parsing empty results."""
        engine = SemgrepEngine()
        semgrep_output = {"results": [], "errors": []}

        findings = engine._parse_results(semgrep_output, tmp_path)
        assert findings == []

    def test_parse_single_result(self, tmp_path):
        """Test parsing a single result."""
        engine = SemgrepEngine()
        semgrep_output = {
            "results": [
                {
                    "check_id": "python.sql-injection.execute",
                    "path": "app.py",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 10, "col": 50},
                    "extra": {
                        "message": "Potential SQL injection",
                        "severity": "ERROR",
                        "lines": "cursor.execute(user_input)",
                        "metadata": {
                            "category": "security",
                            "cwe": ["CWE-89"],
                            "confidence": "HIGH",
                        },
                    },
                }
            ],
            "errors": [],
        }

        findings = engine._parse_results(semgrep_output, tmp_path)
        assert len(findings) == 1

        finding = findings[0]
        assert finding.rule_id == "python.sql-injection.execute"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.type == FindingType.VULNERABILITY
        assert finding.location.file == "app.py"
        assert finding.location.line == 10
        assert finding.cwe == "CWE-89"

    def test_parse_multiple_results(self, tmp_path):
        """Test parsing multiple results."""
        engine = SemgrepEngine()
        semgrep_output = {
            "results": [
                {
                    "check_id": "rule1",
                    "path": "file1.py",
                    "start": {"line": 10},
                    "end": {"line": 10},
                    "extra": {
                        "message": "Issue 1",
                        "severity": "ERROR",
                        "metadata": {},
                    },
                },
                {
                    "check_id": "rule2",
                    "path": "file2.py",
                    "start": {"line": 20},
                    "end": {"line": 25},
                    "extra": {
                        "message": "Issue 2",
                        "severity": "WARNING",
                        "metadata": {},
                    },
                },
            ],
            "errors": [],
        }

        findings = engine._parse_results(semgrep_output, tmp_path)
        assert len(findings) == 2
        assert findings[0].location.file == "file1.py"
        assert findings[1].location.file == "file2.py"

    def test_parse_severity_mapping(self, tmp_path):
        """Test severity mapping from Semgrep to internal levels."""
        engine = SemgrepEngine()

        # Test ERROR -> HIGH
        finding = engine._convert_result_to_finding(
            {
                "check_id": "test",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "ERROR", "message": "Test", "metadata": {}},
            },
            tmp_path,
        )
        assert finding.severity == SeverityLevel.HIGH

        # Test WARNING -> MEDIUM
        finding = engine._convert_result_to_finding(
            {
                "check_id": "test",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "WARNING", "message": "Test", "metadata": {}},
            },
            tmp_path,
        )
        assert finding.severity == SeverityLevel.MEDIUM

        # Test INFO -> INFO
        finding = engine._convert_result_to_finding(
            {
                "check_id": "test",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "INFO", "message": "Test", "metadata": {}},
            },
            tmp_path,
        )
        assert finding.severity == SeverityLevel.INFO

    def test_parse_metadata_severity_override(self, tmp_path):
        """Test that metadata severity overrides default."""
        engine = SemgrepEngine()

        # Metadata CRITICAL should override ERROR
        finding = engine._convert_result_to_finding(
            {
                "check_id": "test",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "Test",
                    "metadata": {"severity": "CRITICAL"},
                },
            },
            tmp_path,
        )
        assert finding.severity == SeverityLevel.CRITICAL

    def test_parse_cwe_extraction(self, tmp_path):
        """Test CWE extraction from metadata."""
        engine = SemgrepEngine()

        # Single CWE string
        finding = engine._convert_result_to_finding(
            {
                "check_id": "test",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "Test",
                    "metadata": {"cwe": "CWE-89"},
                },
            },
            tmp_path,
        )
        assert finding.cwe == "CWE-89"

        # CWE list
        finding = engine._convert_result_to_finding(
            {
                "check_id": "test",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "Test",
                    "metadata": {"cwe": ["CWE-89", "CWE-90"]},
                },
            },
            tmp_path,
        )
        assert finding.cwe == "CWE-89"

    def test_parse_owasp_extraction(self, tmp_path):
        """Test OWASP category extraction."""
        engine = SemgrepEngine()

        finding = engine._convert_result_to_finding(
            {
                "check_id": "test",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "Test",
                    "metadata": {"owasp": "A03:2021"},
                },
            },
            tmp_path,
        )
        assert finding.owasp == "A03:2021"

    def test_parse_confidence_extraction(self, tmp_path):
        """Test confidence extraction from metadata."""
        engine = SemgrepEngine()

        # HIGH confidence
        finding = engine._convert_result_to_finding(
            {
                "check_id": "test",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "Test",
                    "metadata": {"confidence": "HIGH"},
                },
            },
            tmp_path,
        )
        assert finding.confidence == 0.9

        # LOW confidence
        finding = engine._convert_result_to_finding(
            {
                "check_id": "test",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "Test",
                    "metadata": {"confidence": "LOW"},
                },
            },
            tmp_path,
        )
        assert finding.confidence == 0.5


class TestSemgrepScan:
    """Test Semgrep scan execution."""

    @pytest.mark.asyncio
    async def test_scan_invalid_path(self):
        """Test scan with invalid path raises error."""
        engine = SemgrepEngine()

        with pytest.raises(ValueError, match="does not exist"):
            await engine.scan(Path("/nonexistent/path"))

    @pytest.mark.asyncio
    async def test_scan_creates_result(self, tmp_path):
        """Test that scan creates a ScanResult."""
        engine = SemgrepEngine()

        # Create a simple Python file
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1")

        result = await engine.scan(tmp_path, use_auto_config=True)

        assert isinstance(result, ScanResult)
        assert result.source_path == str(tmp_path)
        assert result.engine == "semgrep"
        assert result.completed_at is not None
        assert result.duration_seconds is not None


class TestEngineRegistry:
    """Test engine registry."""

    def test_semgrep_registered(self):
        """Test that SemgrepEngine is registered."""
        engine = engine_registry.get("semgrep")
        assert engine is not None
        assert isinstance(engine, SemgrepEngine)

    def test_get_available_engines(self):
        """Test getting available engines."""
        available = engine_registry.get_available_engines()
        # Semgrep should be available since we installed it
        engine_names = [e.name for e in available]
        assert "semgrep" in engine_names

    def test_get_engines_for_language(self):
        """Test getting engines for a specific language."""
        python_engines = engine_registry.get_engines_for_language("python")
        assert len(python_engines) > 0
        assert any(e.name == "semgrep" for e in python_engines)


class TestFindingModel:
    """Test Finding model functionality."""

    def test_finding_to_dict(self):
        """Test Finding serialization."""
        from src.layers.l3_analysis.models import CodeLocation

        finding = Finding(
            id="test-1",
            rule_id="rule-1",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            title="Test Finding",
            description="Test description",
            location=CodeLocation(file="test.py", line=10),
            source="semgrep",
        )

        data = finding.to_dict()
        assert data["id"] == "test-1"
        assert data["severity"] == SeverityLevel.HIGH

    def test_finding_to_summary(self):
        """Test Finding summary generation."""
        from src.layers.l3_analysis.models import CodeLocation

        finding = Finding(
            id="test-1",
            severity=SeverityLevel.HIGH,
            title="SQL Injection",
            location=CodeLocation(file="app.py", line=42),
            source="semgrep",
            description="Test",
        )

        summary = finding.to_summary()
        assert "HIGH" in summary
        assert "SQL Injection" in summary
        assert "app.py:42" in summary


class TestScanResultModel:
    """Test ScanResult model functionality."""

    def test_add_finding_updates_stats(self):
        """Test that adding findings updates statistics."""
        from src.layers.l3_analysis.models import CodeLocation, Finding

        result = ScanResult(
            source_path="/test",
            engine="semgrep",
        )

        finding = Finding(
            id="test-1",
            severity=SeverityLevel.HIGH,
            title="Test",
            location=CodeLocation(file="test.py", line=1),
            source="semgrep",
            description="Test",
        )

        result.add_finding(finding)

        assert result.total_findings == 1
        assert result.by_severity["high"] == 1

    def test_filter_by_severity(self):
        """Test filtering findings by severity."""
        from src.layers.l3_analysis.models import CodeLocation, Finding

        result = ScanResult(
            source_path="/test",
            engine="semgrep",
        )

        # Add findings at different severities
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.LOW]:
            finding = Finding(
                id=f"test-{severity.value}",
                severity=severity,
                title="Test",
                location=CodeLocation(file="test.py", line=1),
                source="semgrep",
                description="Test",
            )
            result.add_finding(finding)

        # Filter for high and above
        filtered = result.get_findings_above_severity(SeverityLevel.HIGH)
        assert len(filtered) == 2  # CRITICAL and HIGH

    def test_to_summary(self):
        """Test ScanResult summary generation."""
        result = ScanResult(
            source_path="/test/project",
            engine="semgrep",
            total_findings=5,
            by_severity={"critical": 1, "high": 2, "medium": 2, "low": 0, "info": 0},
        )

        summary = result.to_summary()
        assert "/test/project" in summary
        assert "semgrep" in summary
        assert "5" in summary
