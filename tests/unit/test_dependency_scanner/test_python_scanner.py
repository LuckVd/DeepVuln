"""Tests for Python dependency scanner."""

import tempfile
from pathlib import Path

import pytest

from src.layers.l1_intelligence.dependency_scanner.base_scanner import Ecosystem
from src.layers.l1_intelligence.dependency_scanner.python_scanner import PythonScanner


class TestPythonScanner:
    """Tests for PythonScanner."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return PythonScanner()

    def test_ecosystem(self, scanner):
        """Test scanner ecosystem."""
        assert scanner.ecosystem == Ecosystem.PYPI

    def test_supported_files(self, scanner):
        """Test supported files."""
        assert "requirements.txt" in scanner.supported_files
        assert "pyproject.toml" in scanner.supported_files
        assert "Pipfile" in scanner.supported_files
        assert "setup.py" in scanner.supported_files

    def test_can_scan_requirements(self, scanner):
        """Test can_scan for requirements.txt file."""
        assert scanner.can_scan(Path("requirements.txt")) is True

    def test_can_scan_pyproject(self, scanner):
        """Test can_scan for pyproject.toml file."""
        assert scanner.can_scan(Path("pyproject.toml")) is True

    def test_can_scan_non_python_file(self, scanner):
        """Test can_scan for non-Python file."""
        assert scanner.can_scan(Path("package.json")) is False

    def test_scan_empty_directory(self, scanner):
        """Test scanning empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            deps = scanner.scan(path)
            assert len(deps) == 0

    def test_scan_requirements_txt(self, scanner):
        """Test scanning requirements.txt."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            requirements = """
requests==2.28.0
flask>=2.0.0
django~=3.2.0
numpy
# Comment line
pytest>=7.0,<8.0
"""
            (path / "requirements.txt").write_text(requirements)
            deps = scanner.scan(path)

            # Should find the dependencies (excluding comments)
            assert len(deps) >= 4
            dep_names = [d.name for d in deps]
            assert "requests" in dep_names
            assert "flask" in dep_names
            assert "django" in dep_names
            assert "numpy" in dep_names

    def test_scan_requirements_with_extras(self, scanner):
        """Test scanning requirements with extras."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            requirements = "requests[security]==2.28.0\nfastapi[all]>=0.68.0"
            (path / "requirements.txt").write_text(requirements)
            deps = scanner.scan(path)

            assert len(deps) == 2
            names = [d.name for d in deps]
            assert "requests" in names
            assert "fastapi" in names

    def test_scan_pyproject_toml(self, scanner):
        """Test scanning pyproject.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            pyproject = """
[project]
name = "test-project"
dependencies = [
    "requests>=2.28.0",
    "flask>=2.0.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]
"""
            (path / "pyproject.toml").write_text(pyproject)
            deps = scanner.scan(path)

            assert len(deps) >= 2
            dep_names = [d.name for d in deps]
            assert "requests" in dep_names
            assert "flask" in dep_names
            # pytest is in optional-dependencies
            assert "pytest" in dep_names

    def test_scan_poetry_pyproject(self, scanner):
        """Test scanning Poetry-style pyproject.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            pyproject = """
[tool.poetry]
name = "test-project"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.28.0"
flask = ">=2.0.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.0.0"
"""
            (path / "pyproject.toml").write_text(pyproject)
            deps = scanner.scan(path)

            # Should find dependencies, excluding python
            dep_names = [d.name for d in deps]
            assert "requests" in dep_names
            assert "flask" in dep_names
            assert "pytest" in dep_names
            assert "python" not in dep_names

    def test_scan_pipfile(self, scanner):
        """Test scanning Pipfile."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            pipfile = """
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = "==2.28.0"
flask = ">=2.0.0"

[dev-packages]
pytest = ">=7.0.0"
"""
            (path / "Pipfile").write_text(pipfile)
            deps = scanner.scan(path)

            assert len(deps) == 3
            dep_names = [d.name for d in deps]
            assert "requests" in dep_names
            assert "flask" in dep_names
            assert "pytest" in dep_names

    def test_scan_nested_project(self, scanner):
        """Test scanning nested project directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            backend = path / "backend"
            backend.mkdir()

            (backend / "requirements.txt").write_text("django>=4.0.0")

            deps = scanner.scan(path)

            # Should find requirements.txt in subdirectory
            assert len(deps) == 1
            assert deps[0].name == "django"

    def test_scan_multiple_files(self, scanner):
        """Test scanning multiple dependency files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create both requirements.txt and pyproject.toml
            (path / "requirements.txt").write_text("requests==2.28.0")
            pyproject = """
[project]
dependencies = ["flask>=2.0.0"]
"""
            (path / "pyproject.toml").write_text(pyproject)

            deps = scanner.scan(path)

            # Should scan both files
            assert len(deps) >= 2
            dep_names = [d.name for d in deps]
            assert "requests" in dep_names
            assert "flask" in dep_names

    def test_dev_dependencies_in_pipfile(self, scanner):
        """Test that dev dependencies are properly marked in Pipfile."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            pipfile = """
[packages]
requests = "==2.28.0"

[dev-packages]
pytest = ">=7.0.0"
"""
            (path / "Pipfile").write_text(pipfile)
            deps = scanner.scan(path)

            requests_dep = next((d for d in deps if d.name == "requests"), None)
            pytest_dep = next((d for d in deps if d.name == "pytest"), None)

            assert requests_dep is not None
            assert requests_dep.is_dev is False

            assert pytest_dep is not None
            assert pytest_dep.is_dev is True
