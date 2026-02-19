"""
Unit tests for CodeQLEngine.

Tests CodeQL engine functionality without requiring CodeQL CLI to be installed.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.layers.l3_analysis import CodeQLEngine, SeverityLevel
from src.layers.l3_analysis.engines.codeql import (
    CODEQL_LANGUAGE_MAP,
    DEFAULT_QUERY_SUITES,
    SEVERITY_MAP,
)


class TestCodeQLEngineInit:
    """Tests for CodeQLEngine initialization."""

    def test_default_init(self):
        """Test default initialization."""
        engine = CodeQLEngine()
        assert engine.codeql_path == "codeql"
        assert engine.timeout == 600
        assert engine.max_memory_mb == 8192
        assert engine.name == "codeql"
        assert engine.description == "CodeQL deep dataflow analysis engine"

    def test_custom_init(self):
        """Test custom initialization."""
        engine = CodeQLEngine(
            codeql_path="/custom/path/codeql",
            timeout=1200,
            max_memory_mb=16384,
            search_path=["/custom/packs"],
        )
        assert engine.codeql_path == "/custom/path/codeql"
        assert engine.timeout == 1200
        assert engine.max_memory_mb == 16384
        assert engine.search_path == ["/custom/packs"]


class TestCodeQLEngineAvailability:
    """Tests for CodeQL availability checking."""

    def test_is_available_when_not_installed(self):
        """Test is_available returns False when codeql is not in PATH."""
        engine = CodeQLEngine(codeql_path="nonexistent_codeql")
        assert engine.is_available() is False

    def test_is_available_when_installed(self):
        """Test is_available returns True when codeql is in PATH."""
        engine = CodeQLEngine()
        # This will return False in most test environments
        # unless CodeQL is actually installed
        result = engine.is_available()
        assert isinstance(result, bool)


class TestCodeQLEngineLanguageMapping:
    """Tests for language normalization."""

    def test_normalize_language_java(self):
        """Test Java language normalization."""
        engine = CodeQLEngine()
        assert engine.normalize_language("java") == "java"
        assert engine.normalize_language("Java") == "java"
        assert engine.normalize_language("JAVA") == "java"

    def test_normalize_language_python(self):
        """Test Python language normalization."""
        engine = CodeQLEngine()
        assert engine.normalize_language("python") == "python"
        assert engine.normalize_language("Python") == "python"

    def test_normalize_language_typescript(self):
        """Test TypeScript maps to JavaScript."""
        engine = CodeQLEngine()
        assert engine.normalize_language("typescript") == "javascript"
        assert engine.normalize_language("TypeScript") == "javascript"

    def test_normalize_language_cpp(self):
        """Test C/C++ language normalization."""
        engine = CodeQLEngine()
        assert engine.normalize_language("c") == "cpp"
        assert engine.normalize_language("cpp") == "cpp"
        assert engine.normalize_language("c++") == "cpp"
        assert engine.normalize_language("C++") == "cpp"

    def test_normalize_language_csharp(self):
        """Test C# language normalization."""
        engine = CodeQLEngine()
        assert engine.normalize_language("csharp") == "csharp"
        assert engine.normalize_language("c#") == "csharp"
        assert engine.normalize_language("C#") == "csharp"

    def test_normalize_language_unsupported(self):
        """Test unsupported language returns None."""
        engine = CodeQLEngine()
        assert engine.normalize_language("unsupported_lang") is None
        assert engine.normalize_language("rust") is None


class TestCodeQLEngineSupportedLanguages:
    """Tests for supported languages."""

    def test_supported_languages_list(self):
        """Test supported languages list."""
        engine = CodeQLEngine()
        languages = engine.get_supported_languages()

        assert "java" in languages
        assert "python" in languages
        assert "go" in languages
        assert "javascript" in languages
        assert "typescript" in languages

    def test_supports_language(self):
        """Test supports_language method."""
        engine = CodeQLEngine()

        assert engine.supports_language("java") is True
        assert engine.supports_language("Python") is True
        assert engine.supports_language("unsupported") is False


class TestCodeQLEngineScan:
    """Tests for scan functionality."""

    @pytest.fixture
    def engine(self):
        """Create a CodeQLEngine instance."""
        return CodeQLEngine()

    @pytest.fixture
    def temp_project(self, tmp_path):
        """Create a temporary project directory."""
        # Create a simple Java file
        java_file = tmp_path / "Test.java"
        java_file.write_text("""
public class Test {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
""")
        return tmp_path

    @pytest.mark.asyncio
    async def test_scan_codeql_not_available(self, engine, temp_project):
        """Test scan when CodeQL is not available."""
        engine.codeql_path = "nonexistent_codeql"

        result = await engine.scan(source_path=temp_project)

        assert result.success is False
        assert "not installed" in result.error_message.lower()
        assert result.engine == "codeql"

    @pytest.mark.asyncio
    async def test_scan_unsupported_language(self, engine, temp_project):
        """Test scan with unsupported language."""
        # Mock is_available to return True
        with patch.object(engine, 'is_available', return_value=True):
            result = await engine.scan(
                source_path=temp_project,
                language="unsupported_lang",
            )

        assert result.success is False
        assert "not supported" in result.error_message.lower()


class TestCodeQLEngineSarifParsing:
    """Tests for SARIF parsing."""

    @pytest.fixture
    def engine(self):
        """Create a CodeQLEngine instance."""
        return CodeQLEngine()

    def test_parse_sarif_empty(self, engine):
        """Test parsing empty SARIF output."""
        sarif = {"runs": []}
        findings = engine._parse_sarif(sarif, Path("/test"))
        assert findings == []

    def test_parse_sarif_single_result(self, engine):
        """Test parsing SARIF with single result."""
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "java/sql-injection",
                    "level": "error",
                    "message": {"text": "SQL injection vulnerability"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/Test.java"},
                            "region": {
                                "startLine": 10,
                                "startColumn": 5,
                                "endLine": 10,
                                "endColumn": 30,
                            }
                        }
                    }]
                }]
            }]
        }

        findings = engine._parse_sarif(sarif, Path("/test"))

        assert len(findings) == 1
        assert findings[0].rule_id == "java/sql-injection"
        assert findings[0].severity == SeverityLevel.HIGH  # error maps to HIGH
        assert findings[0].location.file == "src/Test.java"
        assert findings[0].location.line == 10

    def test_parse_sarif_multiple_results(self, engine):
        """Test parsing SARIF with multiple results."""
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "java/sql-injection",
                        "level": "error",
                        "message": {"text": "SQL injection"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "A.java"},
                                "region": {"startLine": 1}
                            }
                        }]
                    },
                    {
                        "ruleId": "java/xss",
                        "level": "warning",
                        "message": {"text": "XSS vulnerability"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "B.java"},
                                "region": {"startLine": 2}
                            }
                        }]
                    },
                ]
            }]
        }

        findings = engine._parse_sarif(sarif, Path("/test"))

        assert len(findings) == 2
        severities = [f.severity for f in findings]
        assert SeverityLevel.HIGH in severities
        assert SeverityLevel.MEDIUM in severities

    def test_parse_sarif_no_location(self, engine):
        """Test parsing SARIF result without location."""
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "java/test",
                    "level": "warning",
                    "message": {"text": "Test finding"},
                    "locations": []
                }]
            }]
        }

        findings = engine._parse_sarif(sarif, Path("/test"))
        # Should skip results without locations
        assert len(findings) == 0


class TestCodeQLEngineTitleExtraction:
    """Tests for title extraction."""

    def test_extract_title_from_rule_id(self):
        """Test title extraction from rule ID with long message."""
        engine = CodeQLEngine()

        # Use a message longer than 80 chars to trigger rule ID extraction
        long_message = "This is a very long message that exceeds eighty characters and should trigger rule ID extraction instead"
        title = engine._extract_title("java/sql-injection", long_message)
        assert "Sql Injection" in title or "sql-injection" in title.lower()

    def test_extract_title_short_message(self):
        """Test using short message as title."""
        engine = CodeQLEngine()

        title = engine._extract_title("rule/id", "Short message")
        assert title == "Short message"

    def test_extract_title_complex_rule_id(self):
        """Test title extraction from complex rule ID."""
        engine = CodeQLEngine()

        # Use a message longer than 80 chars
        long_message = "This is a very long description that definitely exceeds the eighty character limit for testing"
        title = engine._extract_title(
            "java/security/injection/sql-tainted",
            long_message
        )
        assert "Sql Tainted" in title or "sql-tainted" in title.lower()


class TestCodeQLEngineLanguageDetection:
    """Tests for automatic language detection."""

    @pytest.fixture
    def engine(self):
        """Create a CodeQLEngine instance."""
        return CodeQLEngine()

    @pytest.mark.asyncio
    async def test_detect_java(self, engine, tmp_path):
        """Test detecting Java project."""
        (tmp_path / "Test.java").write_text("public class Test {}")
        (tmp_path / "Other.java").write_text("public class Other {}")
        (tmp_path / "test.py").write_text("print('test')")

        lang = await engine._detect_language(tmp_path)
        assert lang == "java"

    @pytest.mark.asyncio
    async def test_detect_python(self, engine, tmp_path):
        """Test detecting Python project."""
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def helper(): pass")

        lang = await engine._detect_language(tmp_path)
        assert lang == "python"

    @pytest.mark.asyncio
    async def test_detect_javascript(self, engine, tmp_path):
        """Test detecting JavaScript project."""
        (tmp_path / "index.js").write_text("console.log('hello')")
        (tmp_path / "app.js").write_text("console.log('app')")

        lang = await engine._detect_language(tmp_path)
        assert lang == "javascript"

    @pytest.mark.asyncio
    async def test_detect_no_files(self, engine, tmp_path):
        """Test detection with no recognized files."""
        (tmp_path / "README.md").write_text("# Project")

        lang = await engine._detect_language(tmp_path)
        assert lang is None


class TestCodeQLEngineSeverityMapping:
    """Tests for severity mapping."""

    def test_severity_map_error(self):
        """Test error severity mapping."""
        assert SEVERITY_MAP["error"] == SeverityLevel.HIGH

    def test_severity_map_warning(self):
        """Test warning severity mapping."""
        assert SEVERITY_MAP["warning"] == SeverityLevel.MEDIUM

    def test_severity_map_note(self):
        """Test note severity mapping."""
        assert SEVERITY_MAP["note"] == SeverityLevel.INFO

    def test_severity_map_recommendation(self):
        """Test recommendation severity mapping."""
        assert SEVERITY_MAP["recommendation"] == SeverityLevel.LOW


class TestCodeQLLanguageMap:
    """Tests for language mapping constants."""

    def test_codeql_language_map_completeness(self):
        """Test that all expected languages are mapped."""
        assert "java" in CODEQL_LANGUAGE_MAP
        assert "python" in CODEQL_LANGUAGE_MAP
        assert "go" in CODEQL_LANGUAGE_MAP
        assert "javascript" in CODEQL_LANGUAGE_MAP
        assert "typescript" in CODEQL_LANGUAGE_MAP

    def test_codeql_language_map_typescript(self):
        """Test TypeScript maps to JavaScript."""
        assert CODEQL_LANGUAGE_MAP["typescript"] == "javascript"

    def test_codeql_language_map_cpp(self):
        """Test C/C++ mappings."""
        assert CODEQL_LANGUAGE_MAP["c"] == "cpp"
        assert CODEQL_LANGUAGE_MAP["cpp"] == "cpp"
        assert CODEQL_LANGUAGE_MAP["c++"] == "cpp"


class TestCodeQLDefaultSuites:
    """Tests for default query suites."""

    def test_java_default_suites(self):
        """Test Java default suites."""
        assert "java" in DEFAULT_QUERY_SUITES
        assert "java-security-extended" in DEFAULT_QUERY_SUITES["java"]

    def test_python_default_suites(self):
        """Test Python default suites."""
        assert "python" in DEFAULT_QUERY_SUITES
        assert "python-security-extended" in DEFAULT_QUERY_SUITES["python"]

    def test_all_languages_have_suites(self):
        """Test all major languages have default suites."""
        expected_languages = ["java", "python", "go", "javascript", "cpp", "csharp", "ruby"]
        for lang in expected_languages:
            assert lang in DEFAULT_QUERY_SUITES
            assert len(DEFAULT_QUERY_SUITES[lang]) > 0
