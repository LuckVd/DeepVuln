"""
Python language builder for CodeQL database creation.

Provides intelligent build strategies for Python projects:
- No-build path (CodeQL analyzes source directly)
- Cython extension detection
- Protobuf file detection
- Package manager detection (pip, poetry, uv)
- Python version requirements
"""

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

from .base import (
    BuildResult,
    BuilderOutput,
    BuilderRegistry,
    FailureCategory,
    FailureDiagnosis,
    LanguageBuilder,
)

logger = get_logger(__name__)


@dataclass
class PythonProjectInfo:
    """Information about a Python project."""

    has_pyproject: bool = False
    has_requirements: bool = False
    has_setup_py: bool = False
    has_cython: bool = False
    has_protobuf: bool = False
    package_manager: str = "pip"  # pip, poetry, uv
    python_version: str | None = None
    file_count: int = 0


@BuilderRegistry.register
class PythonBuilder(LanguageBuilder):
    """Builder for Python projects.

    Python is an interpreted language that does not require compilation
    for CodeQL analysis. This builder provides a no-build path with
    optional detection of conditions that might warrant a build.
    """

    LANGUAGE_NAME = "python"
    SUPPORTED_BUILD_SYSTEMS = ["pip", "poetry", "uv"]

    # Default timeout (Python projects typically don't need build)
    DEFAULT_TIMEOUT = 60

    def __init__(self) -> None:
        """Initialize the Python builder."""
        self._python_version: str | None = None

    def analyze(self, project_path: Path) -> BuilderOutput:
        """Analyze a Python project and generate build strategy.

        Args:
            project_path: Path to the Python project root.

        Returns:
            BuilderOutput with no-build strategy (Python doesn't require compilation).
        """
        project_path = Path(project_path)
        detected_files: list[str] = []
        warnings: list[str] = []

        # Count Python files
        py_file_count = self._count_python_files(project_path)

        if py_file_count == 0:
            return BuilderOutput(
                result=BuildResult.SKIPPED,
                language="python",
                skip_reason="No Python files found in project",
                failure_category=FailureCategory.CONFIG_ERROR,
            )

        # Detect project structure
        info = self._detect_project_info(project_path)

        # Build detected files list
        if info.has_pyproject:
            detected_files.append("pyproject.toml")
        if info.has_requirements:
            detected_files.append("requirements.txt")
        if info.has_setup_py:
            detected_files.append("setup.py")

        # Check for conditions that might need attention
        if info.has_cython:
            warnings.append(
                "Cython extension detected (.pyx files) - "
                "CodeQL may have limited coverage for Cython code"
            )

        if info.has_protobuf:
            warnings.append(
                "Protobuf files detected (.proto) - "
                "ensure generated Python code is available for full coverage"
            )

        # Determine package manager
        build_system = info.package_manager

        # Python doesn't require build for CodeQL
        # But we can provide optional dependency installation command
        dependency_command = None
        if info.has_requirements:
            dependency_command = "pip install -r requirements.txt"
        elif info.package_manager == "poetry":
            dependency_command = "poetry install"
        elif info.package_manager == "uv":
            dependency_command = "uv sync"

        return BuilderOutput(
            result=BuildResult.SUCCESS,
            language="python",
            build_command=None,  # No build required
            dependency_command=dependency_command,
            cwd=project_path,
            timeout=self.DEFAULT_TIMEOUT,
            warnings=warnings,
            detected_files=detected_files,
            build_system=build_system,
        )

    def diagnose_failure(
        self, stdout: str, stderr: str, return_code: int
    ) -> FailureDiagnosis:
        """Diagnose a Python build failure from command output.

        Args:
            stdout: Standard output from the build command.
            stderr: Standard error from the build command.
            return_code: Exit code from the build command.

        Returns:
            FailureDiagnosis with category and suggestions.
        """
        if return_code == 0:
            return FailureDiagnosis(
                category=FailureCategory.UNKNOWN,
                message="",
            )

        combined = f"{stdout}\n{stderr}".lower()

        # Missing module/package
        if "modulenotfounderror" in combined or "no module named" in combined:
            match = re.search(r"no module named ['\"]([^'\"]+)['\"]", combined)
            module = match.group(1) if match else "unknown"
            return FailureDiagnosis(
                category=FailureCategory.DEPENDENCY_MISSING,
                message=f"Missing Python module: {module}",
                suggestion=f"Install with: pip install {module}",
                is_recoverable=True,
            )

        # Python version mismatch
        if "requires a different python" in combined or "python" in combined and "not in" in combined:
            return FailureDiagnosis(
                category=FailureCategory.VERSION_MISMATCH,
                message="Python version incompatible with project requirements",
                suggestion="Check requires-python in pyproject.toml or use correct Python version",
                is_recoverable=False,
            )

        # Syntax error
        if "syntaxerror" in combined:
            # Extract error location
            match = re.search(r"file ['\"]([^'\"]+)['\"], line (\d+)", combined)
            if match:
                file, line = match.groups()
                return FailureDiagnosis(
                    category=FailureCategory.COMPILATION_ERROR,
                    message=f"Python syntax error in {file}:{line}",
                    suggestion="Fix the syntax error in the source file",
                    is_recoverable=False,
                )
            return FailureDiagnosis(
                category=FailureCategory.COMPILATION_ERROR,
                message="Python syntax error",
                suggestion="Fix the syntax error in the source file",
                is_recoverable=False,
            )

        # Cython error
        if "cython" in combined or ".pyx" in combined:
            return FailureDiagnosis(
                category=FailureCategory.BUILD_ERROR,
                message="Cython compilation error",
                suggestion="Check Cython installation and extension source",
                is_recoverable=False,
            )

        # Permission error
        if "permissionerror" in combined or "permission denied" in combined:
            return FailureDiagnosis(
                category=FailureCategory.PERMISSION_DENIED,
                message="Permission denied during Python operation",
                suggestion="Check file/directory permissions",
                is_recoverable=True,
            )

        # Import error (other than missing)
        if "importerror" in combined:
            match = re.search(r"cannot import name ['\"]([^'\"]+)['\"]", combined)
            name = match.group(1) if match else "unknown"
            return FailureDiagnosis(
                category=FailureCategory.DEPENDENCY_RESOLUTION,
                message=f"Import error: {name}",
                suggestion="Check package installation and version compatibility",
                is_recoverable=True,
            )

        return FailureDiagnosis(
            category=FailureCategory.UNKNOWN,
            message=f"Unknown Python failure (exit code {return_code})",
            suggestion="Review error output for details",
        )

    def is_available(self) -> bool:
        """Check if Python is installed."""
        return shutil.which("python3") is not None or shutil.which("python") is not None

    def get_version(self) -> str | None:
        """Get the installed Python version."""
        if self._python_version is not None:
            return self._python_version

        try:
            import subprocess

            for cmd in ["python3", "python"]:
                result = subprocess.run(
                    [cmd, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    # Parse "Python 3.10.12"
                    match = re.search(r"Python (\d+\.\d+)", result.stdout)
                    if match:
                        self._python_version = match.group(1)
                        return self._python_version
        except Exception:
            pass

        return None

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _detect_project_info(self, project_path: Path) -> PythonProjectInfo:
        """Detect Python project information.

        Args:
            project_path: Path to project root.

        Returns:
            PythonProjectInfo with detected metadata.
        """
        info = PythonProjectInfo()

        # Check for pyproject.toml
        pyproject = project_path / "pyproject.toml"
        if pyproject.exists():
            info.has_pyproject = True
            info.python_version = self._parse_python_version(pyproject)

            # Check for Poetry
            if self._is_poetry_project(pyproject):
                info.package_manager = "poetry"

        # Check for uv.lock
        if self._is_uv_project(project_path):
            info.package_manager = "uv"

        # Check for requirements.txt
        requirements = project_path / "requirements.txt"
        if requirements.exists():
            info.has_requirements = True

        # Check for setup.py
        setup_py = project_path / "setup.py"
        if setup_py.exists():
            info.has_setup_py = True

        # Check for Cython
        info.has_cython = self._has_cython(project_path)

        # Check for Protobuf
        info.has_protobuf = self._has_protobuf(project_path)

        # Count Python files
        info.file_count = self._count_python_files(project_path)

        return info

    def _has_cython(self, project_path: Path) -> bool:
        """Check if project has Cython extensions.

        Args:
            project_path: Path to project root.

        Returns:
            True if .pyx files found.
        """
        return len(list(project_path.rglob("*.pyx"))) > 0

    def _has_protobuf(self, project_path: Path) -> bool:
        """Check if project has Protobuf definitions.

        Args:
            project_path: Path to project root.

        Returns:
            True if .proto files found.
        """
        return len(list(project_path.rglob("*.proto"))) > 0

    def _is_poetry_project(self, pyproject: Path) -> bool:
        """Check if pyproject.toml is a Poetry project.

        Args:
            pyproject: Path to pyproject.toml.

        Returns:
            True if Poetry configuration found.
        """
        try:
            content = pyproject.read_text()
            return "[tool.poetry]" in content
        except Exception:
            return False

    def _is_uv_project(self, project_path: Path) -> bool:
        """Check if project uses uv package manager.

        Args:
            project_path: Path to project root.

        Returns:
            True if uv.lock exists.
        """
        return (project_path / "uv.lock").exists()

    def _parse_python_version(self, pyproject: Path) -> str | None:
        """Parse Python version requirement from pyproject.toml.

        Args:
            pyproject: Path to pyproject.toml.

        Returns:
            Python version string or None.
        """
        try:
            content = pyproject.read_text()

            # Look for requires-python
            match = re.search(r"requires-python\s*=\s*['\"]([^'\"]+)['\"]", content)
            if match:
                # Extract minimum version from requirement like ">=3.10"
                req = match.group(1)
                version_match = re.search(r"(\d+\.\d+)", req)
                if version_match:
                    return version_match.group(1)

        except Exception:
            pass

        return None

    def _count_python_files(self, project_path: Path) -> int:
        """Count Python files in project.

        Args:
            project_path: Path to project root.

        Returns:
            Number of .py files.
        """
        # Skip common non-source directories
        skip_dirs = {".venv", "venv", "node_modules", ".git", "__pycache__", "site-packages"}

        count = 0
        for py_file in project_path.rglob("*.py"):
            # Check if any skip dir is in the path
            parts = set(py_file.relative_to(project_path).parts)
            if not parts.intersection(skip_dirs):
                count += 1

        return count
