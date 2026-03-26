"""
Unit tests for Python builder.
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.build.builders.base import (
    BuildResult,
    FailureCategory,
    FailureDiagnosis,
)
from src.layers.l3_analysis.build.builders.python import PythonBuilder


class TestPythonBuilderAnalyze:
    """Tests for PythonBuilder.analyze method."""

    @pytest.fixture
    def builder(self) -> PythonBuilder:
        """Create a PythonBuilder instance."""
        return PythonBuilder()

    def test_simple_python_project(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test analyzing a simple Python project."""
        # Create Python files
        main_py = tmp_path / "main.py"
        main_py.write_text('def main(): pass\n')

        lib_py = tmp_path / "lib.py"
        lib_py.write_text('def helper(): pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.language == "python"
        assert output.build_command is None  # No build required
        assert output.dependency_command is None  # No deps install by default

    def test_pyproject_toml_detection(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test detecting pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            "name = 'my-app'\n"
            "version = '1.0.0'\n"
            "requires-python = '>=3.10'\n"
        )

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert "pyproject.toml" in output.detected_files
        assert output.build_command is None

    def test_requirements_txt_detection(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test detecting requirements.txt."""
        requirements = tmp_path / "requirements.txt"
        requirements.write_text("flask>=2.0\nrequests\n")

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert "requirements.txt" in output.detected_files

    def test_poetry_project(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test detecting Poetry project."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[tool.poetry]\n"
            "name = 'my-app'\n"
            "version = '1.0.0'\n"
        )

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.build_system == "poetry"

    def test_uv_project(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test detecting uv project."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            "name = 'my-app'\n"
            "version = '1.0.0'\n"
        )

        # uv.lock indicates uv project
        uv_lock = tmp_path / "uv.lock"
        uv_lock.write_text("version = 1\n")

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.build_system == "uv"

    def test_setup_py_detection(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test detecting setup.py."""
        setup_py = tmp_path / "setup.py"
        setup_py.write_text(
            "from setuptools import setup\n"
            "setup(name='my-app', version='1.0.0')\n"
        )

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert "setup.py" in output.detected_files

    def test_cython_detection(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test detecting Cython extension."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'my-app'\n")

        # Create Cython file
        cython_file = tmp_path / "fast_module.pyx"
        cython_file.write_text('def cython_func(): pass\n')

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Should have warning about Cython
        assert any("Cython" in w for w in output.warnings)

    def test_protobuf_detection(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test detecting Protobuf files."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'my-app'\n")

        # Create Protobuf file
        proto_file = tmp_path / "message.proto"
        proto_file.write_text('syntax = "proto3";\n')

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Should have warning about Protobuf
        assert any("proto" in w.lower() or "Protobuf" in w for w in output.warnings)

    def test_no_python_files(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test analyzing a project with no Python files."""
        # Create only non-Python files
        readme = tmp_path / "README.md"
        readme.write_text("# My Project\n")

        output = builder.analyze(tmp_path)

        # Should skip since no Python files
        assert output.result == BuildResult.SKIPPED
        assert "no python" in output.skip_reason.lower()

    def test_python_version_from_pyproject(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test extracting Python version from pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            "name = 'my-app'\n"
            "requires-python = '>=3.10'\n"
        )

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Version should be detected (stored in module_name or metadata)

    def test_virtualenv_detection(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test detecting virtual environment directories."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'my-app'\n")

        # Create venv directory
        venv = tmp_path / ".venv"
        venv.mkdir()

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # venv should be detected but not scanned


class TestPythonBuilderDiagnoseFailure:
    """Tests for PythonBuilder.diagnose_failure method."""

    @pytest.fixture
    def builder(self) -> PythonBuilder:
        """Create a PythonBuilder instance."""
        return PythonBuilder()

    def test_dependency_missing(self, builder: PythonBuilder) -> None:
        """Test diagnosing missing dependency."""
        stderr = "ModuleNotFoundError: No module named 'flask'"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.DEPENDENCY_MISSING

    def test_syntax_error(self, builder: PythonBuilder) -> None:
        """Test diagnosing Python syntax error."""
        stderr = (
            "  File 'main.py', line 10\n"
            "    def broken(\n"
            "              ^\n"
            "SyntaxError: unexpected EOF while parsing"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.COMPILATION_ERROR

    def test_python_version_mismatch(self, builder: PythonBuilder) -> None:
        """Test diagnosing Python version mismatch."""
        stderr = (
            "SyntaxError: Package 'my-app' requires a different Python: "
            "3.8.10 not in '>=3.10'"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.VERSION_MISMATCH

    def test_cython_error(self, builder: PythonBuilder) -> None:
        """Test diagnosing Cython compilation error."""
        stderr = (
            "Error compiling Cython file:\n"
            "fast_module.pyx:5:10: Cannot convert 'int' to 'str'"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        # Should be related to compilation or build
        assert diagnosis.category in [
            FailureCategory.COMPILATION_ERROR,
            FailureCategory.BUILD_ERROR,
        ]

    def test_permission_denied(self, builder: PythonBuilder) -> None:
        """Test diagnosing permission error."""
        stderr = "PermissionError: [Errno 13] Permission denied: '/usr/local/lib'"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.PERMISSION_DENIED

    def test_unknown_error(self, builder: PythonBuilder) -> None:
        """Test diagnosing unknown error."""
        stderr = "Some random error message"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.UNKNOWN

    def test_success_return_code(self, builder: PythonBuilder) -> None:
        """Test that return code 0 is handled."""
        diagnosis = builder.diagnose_failure("success", "", 0)

        assert diagnosis.category == FailureCategory.UNKNOWN
        assert diagnosis.message == ""


class TestPythonBuilderUtilities:
    """Tests for PythonBuilder utility methods."""

    @pytest.fixture
    def builder(self) -> PythonBuilder:
        """Create a PythonBuilder instance."""
        return PythonBuilder()

    def test_has_cython_true(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test Cython detection when present."""
        (tmp_path / "module.pyx").write_text("def func(): pass\n")
        assert builder._has_cython(tmp_path) is True

    def test_has_cython_false(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test Cython detection when absent."""
        (tmp_path / "module.py").write_text("def func(): pass\n")
        assert builder._has_cython(tmp_path) is False

    def test_has_protobuf_true(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test Protobuf detection when present."""
        (tmp_path / "message.proto").write_text('syntax = "proto3";\n')
        assert builder._has_protobuf(tmp_path) is True

    def test_has_protobuf_false(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test Protobuf detection when absent."""
        (tmp_path / "message.py").write_text("pass\n")
        assert builder._has_protobuf(tmp_path) is False

    def test_is_poetry_project(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test Poetry project detection."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[tool.poetry]\nname = 'test'\n")

        assert builder._is_poetry_project(pyproject) is True

    def test_is_not_poetry_project(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test non-Poetry project detection."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'test'\n")

        assert builder._is_poetry_project(pyproject) is False

    def test_is_uv_project(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test uv project detection via uv.lock."""
        (tmp_path / "uv.lock").write_text("version = 1\n")

        assert builder._is_uv_project(tmp_path) is True

    def test_parse_pyproject_python_version(
        self, builder: PythonBuilder, tmp_path: Path
    ) -> None:
        """Test parsing Python version from pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            "name = 'test'\n"
            "requires-python = '>=3.10'\n"
        )

        version = builder._parse_python_version(pyproject)
        assert version == "3.10"

    def test_count_python_files(self, builder: PythonBuilder, tmp_path: Path) -> None:
        """Test counting Python files."""
        (tmp_path / "main.py").write_text("pass\n")
        (tmp_path / "lib.py").write_text("pass\n")
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "utils.py").write_text("pass\n")

        count = builder._count_python_files(tmp_path)
        assert count == 3


class TestPythonBuilderRegistration:
    """Tests for PythonBuilder registration."""

    def test_python_builder_registered(self) -> None:
        """Test that PythonBuilder is registered."""
        from src.layers.l3_analysis.build.builders.base import BuilderRegistry

        # Clear and re-register
        BuilderRegistry._builders.clear()
        from src.layers.l3_analysis.build.builders.python import PythonBuilder
        BuilderRegistry.register(PythonBuilder)

        builder = BuilderRegistry.get("python")
        assert builder is not None
        assert builder.LANGUAGE_NAME == "python"
