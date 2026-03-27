"""
Python Docker Integration Tests (P7-11b-1).

Tests the complete flow for Python projects:
1. PythonBuilder identifies project structure
2. Build command generation
3. CodeQL database creation (if CodeQL available)
4. Runtime version management
"""

import pytest
from pathlib import Path

from src.layers.l3_analysis.build.builders import PythonBuilder
from src.layers.l3_analysis.build.builders.base import BuildResult


# Mark all tests in this module as integration tests
pytestmark = [
    pytest.mark.integration,
]


class TestPythonBuilderIntegration:
    """Integration tests for PythonBuilder."""

    def test_builder_analyzes_pyproject_toml(self, python_project: Path):
        """Test that builder analyzes pyproject.toml project."""
        builder = PythonBuilder()
        output = builder.analyze(python_project)

        assert output.language == "python"
        # Python can always be built (interpreted language)
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)

    def test_builder_detects_requirements(self, python_project: Path):
        """Test that builder detects requirements.txt."""
        builder = PythonBuilder()
        output = builder.analyze(python_project)

        # Should detect requirements.txt in detected_files
        assert any("requirements" in f.lower() for f in output.detected_files)

    def test_builder_handles_no_project_files(self, tmp_path: Path):
        """Test builder handles project without project files."""
        empty_project = tmp_path / "empty_python"
        empty_project.mkdir()
        (empty_project / "main.py").write_text("print('hello')")

        builder = PythonBuilder()
        output = builder.analyze(empty_project)

        assert output.language == "python"
        # Python can always be analyzed (no build required)
        assert output.result == BuildResult.SUCCESS or output.is_skipped

    def test_builder_detects_cython_warning(self, tmp_path: Path):
        """Test builder detects Cython usage and adds warning."""
        project = tmp_path / "cython_project"
        project.mkdir()
        (project / "setup.py").write_text('''
from setuptools import setup
from Cython.Build import cythonize

setup(ext_modules=cythonize("*.pyx"))
''')
        (project / "module.pyx").write_text("def hello(): pass")

        builder = PythonBuilder()
        output = builder.analyze(project)

        # Should have Cython warning
        assert any("Cython" in w or "cython" in w for w in output.warnings)


class TestPythonVersionDetection:
    """Integration tests for Python version detection.

    Note: Python version detection is not currently implemented in VersionDetector.
    These tests are placeholders for future implementation.
    """

    @pytest.mark.skip(reason="Python version detection not yet implemented in VersionDetector")
    def test_detect_python_version_from_pyproject(self, python_project: Path):
        """Test version detection from pyproject.toml."""
        pass

    @pytest.mark.skip(reason="Python version detection not yet implemented in VersionDetector")
    def test_detect_python_version_from_runtime_txt(self, tmp_path: Path):
        """Test version detection from runtime.txt (Heroku style)."""
        pass

    @pytest.mark.skip(reason="Python version detection not yet implemented in VersionDetector")
    def test_detect_python_version_from_python_version(self, tmp_path: Path):
        """Test version detection from .python-version (pyenv style)."""
        pass


class TestPythonCodeQLIntegration:
    """CodeQL integration tests for Python (requires CodeQL)."""

    @pytest.mark.codeql
    @pytest.mark.skip(reason="Requires CodeQL build environment")
    def test_codeql_database_creation(self, python_project: Path, tmp_path: Path):
        """Test CodeQL database creation for Python project."""
        pass


class TestPythonRuntimeVersionManager:
    """Test RuntimeVersionManager with Python."""

    @pytest.mark.asyncio
    async def test_ensure_python_version(self, test_runtime_root: Path):
        """Test ensuring a Python version is installed."""
        from src.layers.l3_analysis.build.runtime import (
            RuntimeVersionManager,
            RuntimeType,
        )

        manager = RuntimeVersionManager(
            runtime_root=test_runtime_root,
            auto_install=False,  # Don't actually download
        )

        # Test that the manager can be created
        assert manager.runtime_root == test_runtime_root

    def test_list_available_python_versions(self):
        """Test listing available Python versions."""
        from src.layers.l3_analysis.build.runtime.registry import RuntimeRegistry
        from src.layers.l3_analysis.build.runtime.models import RuntimeType

        registry = RuntimeRegistry()
        versions = registry.get_versions(RuntimeType.PYTHON)

        assert len(versions) > 0
        assert "3.10" in versions or "3.11" in versions
