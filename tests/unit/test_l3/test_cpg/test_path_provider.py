"""
CPGPathProvider Unit Tests.

Test the language-agnostic interface that routes to language-specific providers.
"""

from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from src.layers.l3_analysis.engines.ast_engine.cpg.path_provider import CPGPathProvider
from src.layers.l3_analysis.engines.ast_engine.path_finder.models import AttackPath


class TestCPGPathProvider:
    """Test CPGPathProvider language-agnostic interface."""

    def test_init(self):
        """Test CPGPathProvider initialization."""
        provider = CPGPathProvider()

        assert provider is not None
        assert "python" in provider.get_supported_languages()
        assert "javascript" in provider.get_supported_languages()
        assert "typescript" in provider.get_supported_languages()

    def test_supports_language(self):
        """Test language support checking."""
        provider = CPGPathProvider()

        assert provider.supports_language("python")
        assert provider.supports_language("javascript")
        assert provider.supports_language("typescript")
        assert not provider.supports_language("unknown")
        assert provider.supports_language("java")  # Phase 18/P1: Java provider registered + e2e works

    def test_register_provider(self):
        """Test registering a custom provider."""
        provider = CPGPathProvider()

        # Create a mock provider
        mock_provider = Mock()
        mock_provider.get_paths.return_value = []

        # Register it
        provider.register_provider("custom", mock_provider)

        assert provider.supports_language("custom")
        assert "custom" in provider.get_supported_languages()

    def test_get_attack_paths_for_python(self, tmp_path):
        """Test getting attack paths for Python source."""
        provider = CPGPathProvider()

        # Create a test Python file
        test_file = tmp_path / "test.py"
        test_file.write_text("def foo(): pass\n")

        # Get paths - should return empty list for simple code
        paths = provider.get_attack_paths(test_file, "eval|exec")

        assert isinstance(paths, list)
        # Empty or actual paths depending on implementation

    def test_get_attack_paths_unsupported_language(self, tmp_path):
        """Test graceful degradation for unsupported languages."""
        provider = CPGPathProvider()

        # Create a file with unsupported extension
        test_file = tmp_path / "test.unknown"
        test_file.write_text("some code\n")

        paths = provider.get_attack_paths(test_file, "eval")

        # Should return empty list, not raise exception
        assert paths == []

    def test_get_attack_paths_nonexistent_file(self):
        """Test handling of nonexistent files."""
        provider = CPGPathProvider()

        paths = provider.get_attack_paths(
            Path("/nonexistent/path/file.py"),
            "eval"
        )

        # Should return empty list, not raise exception
        assert paths == []

    def test_get_attack_paths_directory(self, tmp_path):
        """Test getting attack paths for a directory."""
        provider = CPGPathProvider()

        # Create test files
        (tmp_path / "test1.py").write_text("def foo(): pass\n")
        (tmp_path / "test2.py").write_text("def bar(): pass\n")

        paths = provider.get_attack_paths(tmp_path, "eval")

        assert isinstance(paths, list)

    def test_detect_language_from_file(self, tmp_path):
        """Test language detection from a single file."""
        provider = CPGPathProvider()

        # Python file
        py_file = tmp_path / "test.py"
        py_file.write_text("print('hello')\n")
        lang = provider._detect_language(py_file)
        assert lang == "python"

        # JavaScript file
        js_file = tmp_path / "test.js"
        js_file.write_text("console.log('hello');\n")
        lang = provider._detect_language(js_file)
        assert lang == "javascript"

    def test_detect_language_from_directory(self, tmp_path):
        """Test language detection from a directory."""
        provider = CPGPathProvider()

        # Create mixed files
        (tmp_path / "test1.py").write_text("# python\n")
        (tmp_path / "test2.py").write_text("# more python\n")
        (tmp_path / "test.js").write_text("// javascript\n")

        lang = provider._detect_language(tmp_path)
        # Should detect the most common language
        assert lang == "python"

    def test_detect_language_empty_directory(self, tmp_path):
        """Test language detection with empty directory."""
        provider = CPGPathProvider()

        lang = provider._detect_language(tmp_path)
        assert lang is None

    @pytest.fixture
    def mock_attack_path(self):
        """Create a mock AttackPath for testing."""
        path = Mock(spec=AttackPath)
        path.entry_point = "user_input"
        path.sink = "eval"
        path.path = ["node1", "node2", "node3"]
        path.confidence = 0.9
        path.sanitizers = []
        path.reaches_sink = True
        return path

    def test_provider_error_handling(self, tmp_path, monkeypatch):
        """Test that provider errors are handled gracefully."""
        provider = CPGPathProvider()

        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("def test(): pass\n")

        # Mock the Python provider to raise an exception
        def mock_get_paths(*args, **kwargs):
            raise RuntimeError("CPG construction failed")

        # Get the python provider and mock its get_paths method
        python_provider = provider._providers.get("python")
        if python_provider:
            original_get_paths = python_provider.get_paths
            python_provider.get_paths = mock_get_paths

            # Should not raise exception, but return empty list
            paths = provider.get_attack_paths(test_file, "eval")
            assert paths == []

            # Restore original method
            python_provider.get_paths = original_get_paths
