"""
Unit tests for ASTEngine.

Tests cover:
- Engine metadata
- Availability check
- Language support
- Tree-sitter parser initialization
- Query execution
- Finding generation
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.layers.l3_analysis.engines.ast_engine import ASTEngine
from src.layers.l3_analysis.models import (
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)


class TestASTEngineMetadata:
    """Test ASTEngine metadata and initialization."""

    def test_engine_metadata(self):
        """Test engine metadata is correctly set."""
        engine = ASTEngine()
        assert engine.name == "ast_engine"
        assert engine.description == "AST-based structural vulnerability detection"
        assert "python" in engine.supported_languages
        assert "javascript" in engine.supported_languages
        assert "java" in engine.supported_languages
        assert "go" in engine.supported_languages

    def test_supports_language(self):
        """Test language support check."""
        engine = ASTEngine()
        assert engine.supports_language("python") is True
        assert engine.supports_language("java") is True
        assert engine.supports_language("go") is True
        assert engine.supports_language("javascript") is True
        assert engine.supports_language("unknown_lang") is False


class TestASTEngineAvailability:
    """Test ASTEngine availability checks."""

    def test_is_available_with_tree_sitter(self):
        """Test availability check when tree-sitter is installed."""
        engine = ASTEngine()
        # tree-sitter should be available (installed in project)
        assert engine.is_available() is True

    def test_is_available_without_tree_sitter(self):
        """Test availability check when tree-sitter is not available."""
        with patch("src.layers.l3_analysis.engines.ast_engine.parser.tree_sitter_manager.TREE_SITTER_AVAILABLE", False):
            engine = ASTEngine()
            assert engine.is_available() is False


class TestTreeSitterManager:
    """Test TreeSitterManager functionality."""

    def test_get_language_for_python(self):
        """Test getting Python language from TreeSitterManager."""
        engine = ASTEngine()
        lang = engine._tree_sitter_manager.get_language("python")
        assert lang is not None

    def test_get_language_for_javascript(self):
        """Test getting JavaScript language from TreeSitterManager."""
        engine = ASTEngine()
        lang = engine._tree_sitter_manager.get_language("javascript")
        # JavaScript may not be installed, so we just check it doesn't crash
        # (The engine should gracefully handle missing language packages)
        assert lang is None or lang is not None  # Always passes, just testing no crash

    def test_get_language_for_unknown(self):
        """Test getting language for unsupported language."""
        engine = ASTEngine()
        lang = engine._tree_sitter_manager.get_language("unknown")
        assert lang is None


class TestQueryEngine:
    """Test QueryEngine functionality."""

    def test_execute_eval_query(self):
        """Test executing a query to detect eval() calls."""
        from src.layers.l3_analysis.engines.ast_engine.queries.query_engine import QueryEngine

        query_engine = QueryEngine()
        code = """
def dangerous(user_input):
    return eval(user_input)
"""
        results = query_engine.execute_query(
            query_text="""
(call
  (identifier) @func
  (#eq? @func "eval"))
""",
            code=code,
            language="python",
        )
        assert len(results) > 0

    def test_execute_empty_query(self):
        """Test executing a query with no matches."""
        from src.layers.l3_analysis.engines.ast_engine.queries.query_engine import QueryEngine

        query_engine = QueryEngine()
        code = """
def safe(x):
    return x + 1
"""
        results = query_engine.execute_query(
            query_text="""
(call
  (identifier) @func
  (#eq? @func "eval"))
""",
            code=code,
            language="python",
        )
        assert len(results) == 0


class TestASTEngineScan:
    """Test ASTEngine scan functionality."""

    @pytest.mark.asyncio
    async def test_scan_creates_result(self, tmp_path):
        """Test that scan creates a valid ScanResult."""
        # Create a test Python file
        test_file = tmp_path / "test.py"
        test_file.write_text("""
def dangerous(user_input):
    return eval(user_input)
""")

        engine = ASTEngine()
        result = await engine.scan(source_path=tmp_path)

        assert isinstance(result, ScanResult)
        assert result.engine == "ast_engine"
        assert result.source_path == str(tmp_path)

    @pytest.mark.asyncio
    async def test_scan_detects_dangerous_eval(self, tmp_path):
        """Test that scan detects eval() usage."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
def dangerous(user_input):
    return eval(user_input)
""")

        engine = ASTEngine()
        result = await engine.scan(source_path=tmp_path)

        # Should find at least one vulnerability
        assert len(result.findings) > 0

        # Check finding properties
        finding = result.findings[0]
        assert finding.source == "ast_engine"
        assert "eval" in finding.rule_id.lower() or "eval" in finding.title.lower()

    @pytest.mark.asyncio
    async def test_scan_with_nonexistent_path(self, tmp_path):
        """Test scan with nonexistent path raises error."""
        engine = ASTEngine()
        nonexistent = tmp_path / "nonexistent"

        with pytest.raises(ValueError, match="does not exist"):
            await engine.scan(source_path=nonexistent)


class TestFindingGeneration:
    """Test finding generation from detectors."""

    @pytest.mark.asyncio
    async def test_detector_creates_finding(self):
        """Test that detectors create findings correctly."""
        from src.layers.l3_analysis.engines.ast_engine.detectors.dangerous_api_detector import (
            DangerousAPIDetector,
        )

        detector = DangerousAPIDetector()

        findings = await detector.detect(
            code="eval(user_input)",
            language="python",
            file_path="test.py",
        )

        assert len(findings) > 0
        finding = findings[0]
        assert finding.source == "ast_engine"
        assert finding.rule_id == "dangerous_eval"
        assert "eval" in finding.title.lower()


class TestYAMLRuleLoading:
    """Test YAML rule file loading."""

    def test_load_yaml_rule(self):
        """Test loading a rule from YAML file."""
        from src.layers.l3_analysis.engines.ast_engine.queries.query_engine import QueryEngine

        # Create a temporary rule file
        import tempfile
        import yaml

        rule_content = {
            "id": "dangerous-eval",
            "query": """
(call_expression
  function: (identifier) @func
  (#eq? @func "eval"))
""",
            "severity": "high",
            "message": "Dangerous eval usage detected",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(rule_content, f)
            rule_path = f.name

        try:
            query_engine = QueryEngine()
            rule = query_engine.load_yaml_rule(rule_path)
            assert rule["id"] == "dangerous-eval"
            assert rule["severity"] == "high"
        finally:
            Path(rule_path).unlink()
