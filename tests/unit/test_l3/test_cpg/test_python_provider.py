"""
PythonCPGProvider Unit Tests.

Test Python-specific CPG path provider implementation.
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.engines.ast_engine.cpg.providers.python_provider import (
    PythonCPGProvider,
)


class TestPythonCPGProvider:
    """Test PythonCPGProvider."""

    def test_init(self):
        """Test PythonCPGProvider initialization."""
        provider = PythonCPGProvider()

        assert provider is not None
        assert provider.file_patterns == ["*.py"]

    def test_file_patterns(self):
        """Test file patterns property."""
        provider = PythonCPGProvider()

        patterns = provider.file_patterns
        assert patterns == ["*.py"]
        assert "*.py" in patterns

    def test_get_file_extensions(self):
        """Test getting file extensions."""
        provider = PythonCPGProvider()

        extensions = provider.get_file_extensions()
        assert "*.py" in extensions

    def test_supports_language(self):
        """Test language support checking."""
        provider = PythonCPGProvider()

        assert provider.supports_language("python")
        assert not provider.supports_language("javascript")
        assert not provider.supports_language("java")

    def test_supports_file(self):
        """Test file support checking."""
        provider = PythonCPGProvider()

        assert provider.supports_file(Path("test.py"))
        assert provider.supports_file(Path("/path/to/file.py"))
        assert not provider.supports_file(Path("test.js"))
        assert not provider.supports_file(Path("test.java"))

    def test_get_paths_empty_cpg(self, tmp_path):
        """Test getting paths when CPG is empty."""
        provider = PythonCPGProvider()

        # Create an empty file
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")

        paths = provider.get_paths(empty_file, "eval")

        # Should return empty list for empty/invalid source
        assert isinstance(paths, list)

    def test_get_paths_simple_file(self, tmp_path):
        """Test getting paths for a simple Python file."""
        provider = PythonCPGProvider()

        # Create a simple file without dangerous functions
        simple_file = tmp_path / "simple.py"
        simple_file.write_text("""
def hello():
    print("Hello, world!")

def add(a, b):
    return a + b
""")

        paths = provider.get_paths(simple_file, "eval|exec")

        # Should return a list (may be empty)
        assert isinstance(paths, list)

    def test_get_paths_with_eval(self, tmp_path):
        """Test getting paths for code with eval."""
        provider = PythonCPGProvider()

        # Create a file with eval
        eval_file = tmp_path / "with_eval.py"
        eval_file.write_text("""
def process(user_input):
    result = eval(user_input)  # Dangerous
    return result
""")

        paths = provider.get_paths(eval_file, "eval")

        # Should return a list
        assert isinstance(paths, list)

    def test_get_paths_from_directory(self, tmp_path):
        """Test getting paths from a directory."""
        provider = PythonCPGProvider()

        # Create multiple Python files
        (tmp_path / "file1.py").write_text("def foo(): pass\n")
        (tmp_path / "file2.py").write_text("def bar(): pass\n")
        (tmp_path / "readme.txt").write_text("Some text\n")

        paths = provider.get_paths(tmp_path, "eval")

        assert isinstance(paths, list)

    def test_default_sink_pattern(self, tmp_path):
        """Test default sink pattern."""
        provider = PythonCPGProvider()

        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")

        # Use default sink pattern
        paths = provider.get_paths(test_file)

        assert isinstance(paths, list)

    def test_custom_sink_pattern(self, tmp_path):
        """Test custom sink pattern."""
        provider = PythonCPGProvider()

        test_file = tmp_path / "test.py"
        test_file.write_text("""
import os
os.system("ls")
""")

        # Custom pattern for os.system
        paths = provider.get_paths(test_file, "system")

        assert isinstance(paths, list)

    def test_base_provider_functionality(self):
        """Test inherited BaseCPGProvider functionality."""
        provider = PythonCPGProvider()

        # Should have logger
        assert hasattr(provider, "logger")

        # Should have base methods
        assert hasattr(provider, "_build_cpg")
        assert hasattr(provider, "_find_paths")
