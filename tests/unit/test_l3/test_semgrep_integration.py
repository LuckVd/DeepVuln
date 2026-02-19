"""
Integration tests for SemgrepEngine.

Tests that actually run Semgrep against sample code.
"""

import tempfile
from pathlib import Path

import pytest

from src.layers.l3_analysis import (
    SemgrepEngine,
    SeverityLevel,
    SmartScanner,
    create_smart_scanner,
)
from src.layers.l3_analysis.models import FindingType


# Sample vulnerable code for testing
VULNERABLE_PYTHON = '''
import os

def vulnerable_function(user_input):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_input
    cursor.execute(query)

    # Command injection vulnerability
    os.system("echo " + user_input)

    return query
'''

VULNERABLE_JAVA = '''
import java.sql.*;

public class VulnerableClass {
    public void vulnerableMethod(String userInput) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();

        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE id = " + userInput;
        ResultSet rs = stmt.executeQuery(query);
    }
}
'''

SAFE_PYTHON = '''
def safe_function(user_id):
    # Safe parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
'''


@pytest.fixture
def temp_project():
    """Create a temporary project directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        project_path = Path(tmpdir)

        # Create Python file with vulnerabilities
        py_file = project_path / "vulnerable.py"
        py_file.write_text(VULNERABLE_PYTHON)

        # Create safe Python file
        safe_file = project_path / "safe.py"
        safe_file.write_text(SAFE_PYTHON)

        # Create Java file
        java_dir = project_path / "src" / "main" / "java"
        java_dir.mkdir(parents=True)
        java_file = java_dir / "VulnerableClass.java"
        java_file.write_text(VULNERABLE_JAVA)

        yield project_path


@pytest.fixture
def python_project():
    """Create a temporary Python project."""
    with tempfile.TemporaryDirectory() as tmpdir:
        project_path = Path(tmpdir)

        py_file = project_path / "app.py"
        py_file.write_text(VULNERABLE_PYTHON)

        yield project_path


class TestSemgrepEngineIntegration:
    """Integration tests for SemgrepEngine with real Semgrep."""

    @pytest.fixture
    def engine(self):
        """Create a SemgrepEngine instance."""
        return SemgrepEngine()

    def test_engine_is_available(self, engine):
        """Test that Semgrep is available."""
        assert engine.is_available() is True

    @pytest.mark.asyncio
    async def test_scan_with_auto_config(self, engine, temp_project):
        """Test scanning with auto config."""
        result = await engine.scan(
            source_path=temp_project,
            use_auto_config=True,
        )

        assert result.success is True
        assert "auto" in result.rules_used
        assert result.engine == "semgrep"
        assert result.duration_seconds is not None
        assert result.duration_seconds > 0

    @pytest.mark.asyncio
    async def test_scan_with_exclude_patterns(self, engine, temp_project):
        """Test scanning with exclude patterns."""
        result = await engine.scan(
            source_path=temp_project,
            use_auto_config=True,
            exclude_patterns=["**/*.java"],
        )

        assert result.success is True

    @pytest.mark.asyncio
    async def test_scan_empty_project(self, engine):
        """Test scanning an empty project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            result = await engine.scan(
                source_path=project_path,
                use_auto_config=True,
            )

            # Should complete successfully even with no files
            assert result.success is True
            assert result.total_findings == 0


class TestSmartScannerIntegration:
    """Integration tests for SmartScanner."""

    def test_scanner_creation(self):
        """Test scanner creation."""
        scanner = create_smart_scanner()
        assert scanner is not None

    def test_get_recommended_rules(self):
        """Test getting recommended rules."""
        scanner = create_smart_scanner()

        tech_stack = {
            "languages": ["python", "java"],
            "frameworks": ["django"],
        }

        recommended = scanner.get_recommended_rules(tech_stack)

        assert "rule_sets" in recommended
        assert "languages" in recommended
        assert "python" in recommended["languages"]

    @pytest.mark.asyncio
    async def test_smart_scan_with_auto_config(self, temp_project):
        """Test smart scan with auto config."""
        scanner = create_smart_scanner()

        # Must explicitly set use_auto_config=True for auto detection
        result = await scanner.scan_project(
            source_path=temp_project,
            use_auto_config=True,
        )

        assert result.success is True
        assert result.engine == "semgrep"


class TestScanResultIntegration:
    """Integration tests for ScanResult methods."""

    @pytest.mark.asyncio
    async def test_deduplication(self, python_project):
        """Test that deduplication works."""
        engine = SemgrepEngine()

        result = await engine.scan(
            source_path=python_project,
            use_auto_config=True,
        )

        # Deduplicate shouldn't cause errors
        duplicates = result.deduplicate_findings()
        assert isinstance(duplicates, int)

    @pytest.mark.asyncio
    async def test_sort_by_severity(self, python_project):
        """Test sorting findings by severity."""
        engine = SemgrepEngine()

        result = await engine.scan(
            source_path=python_project,
            use_auto_config=True,
        )

        # Sort shouldn't cause errors
        result.sort_by_severity()

        # Check order
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }

        for i in range(len(result.findings) - 1):
            current_sev = severity_order.get(result.findings[i].severity, 5)
            next_sev = severity_order.get(result.findings[i + 1].severity, 5)
            assert current_sev <= next_sev

    @pytest.mark.asyncio
    async def test_export_formats(self, python_project):
        """Test exporting results in different formats."""
        engine = SemgrepEngine()

        result = await engine.scan(
            source_path=python_project,
            use_auto_config=True,
        )

        # JSON export
        json_output = result.to_json()
        assert isinstance(json_output, str)
        assert "findings" in json_output

        # Markdown export
        md_output = result.to_markdown()
        assert isinstance(md_output, str)
        assert "# Scan Report" in md_output

        # Summary
        summary = result.to_summary()
        assert isinstance(summary, str)
        assert "Total Findings" in summary


class TestCLIIntegration:
    """Integration tests for CLI commands."""

    def test_semgrep_command_available(self):
        """Test that semgrep command is available."""
        from click.testing import CliRunner
        from src.cli.main import main

        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "semgrep" in result.output.lower()

    def test_semgrep_command_help(self):
        """Test semgrep command help."""
        from click.testing import CliRunner
        from src.cli.main import main

        runner = CliRunner()
        result = runner.invoke(main, ["semgrep", "--help"])

        assert result.exit_code == 0
        assert "--path" in result.output
        assert "--rules" in result.output
        assert "--rule-sets" in result.output
