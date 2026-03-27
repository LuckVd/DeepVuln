"""
C/C++ language builder for CodeQL database creation.

Provides intelligent build strategies for C/C++ projects with clear stop-loss:
- Priority 1: Existing compile_commands.json
- Priority 2: CMake (can generate compile_commands)
- Priority 3: Makefile (conservative strategy)
- Header-only: Skip with explanation
- Non-standard systems: Skip to avoid unbounded guesswork

Supported build systems: compile_commands.json, CMake, Makefile
NOT supported: autotools, meson, scons, bazel, custom scripts
"""

import json
import re
import shutil
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


@BuilderRegistry.register
class CppBuilder(LanguageBuilder):
    """Builder for C/C++ projects.

    Only supports standard build systems with clear stop-loss lines.
    """

    LANGUAGE_NAME = "cpp"
    SUPPORTED_BUILD_SYSTEMS = [
        "compile_commands",
        "cmake",
        "make",
    ]

    # Default timeout for C++ builds (10 minutes)
    DEFAULT_TIMEOUT = 600

    # Maximum timeout (30 minutes)
    MAX_TIMEOUT = 1800

    # Common C/C++ source extensions
    SOURCE_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".C"}
    HEADER_EXTENSIONS = {".h", ".hpp", ".hh", ".hxx", ".H"}

    def __init__(self) -> None:
        """Initialize the C++ builder."""
        self._gcc_version: str | None = None
        self._cmake_version: str | None = None

    def analyze(self, project_path: Path) -> BuilderOutput:
        """Analyze a C/C++ project with clear priority:

        1. Check for existing compile_commands.json
        2. Check for CMake (can generate compile_commands)
        3. Check for Makefile (conservative)
        4. Check for header-only
        5. Skip with reason if no standard build system

        Args:
            project_path: Path to the C/C++ project root.

        Returns:
            BuilderOutput with build strategy or skip reason.
        """
        project_path = Path(project_path)
        detected_files: list[str] = []

        # Priority 1: Check for existing compile_commands.json
        compile_commands_result = self._check_compile_commands(
            project_path, detected_files
        )
        if compile_commands_result is not None:
            return compile_commands_result

        # Priority 2: Check for CMake
        cmake_result = self._check_cmake(project_path, detected_files)
        if cmake_result is not None:
            return cmake_result

        # Priority 3: Check for Makefile (conservative)
        makefile_result = self._check_makefile(project_path, detected_files)
        if makefile_result is not None:
            return makefile_result

        # Check if header-only
        if self._is_header_only(project_path):
            return BuilderOutput(
                result=BuildResult.SKIPPED,
                language="cpp",
                skip_reason=(
                    "Header-only C/C++ project detected. "
                    "CodeQL can still analyze header-only projects without a build. "
                    "Consider creating a compile_commands.json for full analysis."
                ),
                detected_files=detected_files,
                build_system="header-only",
            )

        # No standard build system found
        return BuilderOutput(
            result=BuildResult.SKIPPED,
            language="cpp",
            skip_reason=(
                "No standard C/C++ build system found. "
                "Supported: compile_commands.json, CMake, Makefile. "
                "For header-only projects, CodeQL can still analyze without build. "
                "Non-standard build systems (autotools/meson/scons/bazel) are not supported."
            ),
            detected_files=detected_files,
        )

    def diagnose_failure(
        self, stdout: str, stderr: str, return_code: int
    ) -> FailureDiagnosis:
        """Diagnose a C++ build failure from command output.

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

        # Permission denied (check first)
        if "permission denied" in combined:
            return FailureDiagnosis(
                category=FailureCategory.PERMISSION_DENIED,
                message="Permission denied during build",
                suggestion="Check file permissions and build directory access",
                is_recoverable=False,
            )

        # CMake errors
        if "cmake error" in combined or "cmake fatal error" in combined:
            if "could not find" in combined:
                # Extract missing package
                pkg_match = re.search(
                    r"could not find ([a-z0-9_-]+)", combined, re.IGNORECASE
                )
                pkg = pkg_match.group(1) if pkg_match else "dependency"
                return FailureDiagnosis(
                    category=FailureCategory.DEPENDENCY_MISSING,
                    message=f"CMake could not find: {pkg}",
                    suggestion=f"Install {pkg} or check CMAKE_PREFIX_PATH",
                    is_recoverable=False,
                )
            return FailureDiagnosis(
                category=FailureCategory.CONFIG_ERROR,
                message="CMake configuration failed",
                suggestion="Check CMakeLists.txt for errors",
                is_recoverable=False,
            )

        # Compiler errors
        if any(
            pattern in combined
            for pattern in [
                "fatal error:",
                "error: ",
                "undefined reference to",
                "undefined symbol",
            ]
        ):
            # Check for missing headers
            if "no such file or directory" in combined:
                header_match = re.search(
                    r"['\"]([^'\"]+\.(?:h|hpp|hh))['\"]", combined
                )
                header = header_match.group(1) if header_match else "header"
                return FailureDiagnosis(
                    category=FailureCategory.DEPENDENCY_MISSING,
                    message=f"Missing header file: {header}",
                    suggestion="Install required development libraries",
                    is_recoverable=False,
                )
            # Check for undefined references (linker error)
            if "undefined reference" in combined:
                return FailureDiagnosis(
                    category=FailureCategory.COMPILATION_ERROR,
                    message="Linker error - undefined references",
                    suggestion="Check library dependencies and link order",
                    is_recoverable=False,
                )
            # Generic compilation error
            return FailureDiagnosis(
                category=FailureCategory.COMPILATION_ERROR,
                message="C/C++ compilation error",
                suggestion="Fix compilation errors in source code",
                is_recoverable=False,
            )

        # Make errors
        if "make: ***" in combined:
            if "no rule to make target" in combined:
                return FailureDiagnosis(
                    category=FailureCategory.CONFIG_ERROR,
                    message="Makefile missing target or dependency",
                    suggestion="Check Makefile and dependencies",
                    is_recoverable=False,
                )
            return FailureDiagnosis(
                category=FailureCategory.BUILD_ERROR,
                message="Make build failed",
                suggestion="Review make output for specific errors",
                is_recoverable=False,
            )

        return FailureDiagnosis(
            category=FailureCategory.UNKNOWN,
            message=f"Unknown C++ build failure (exit code {return_code})",
            suggestion="Review build output for details",
        )

    def is_available(self) -> bool:
        """Check if C++ build tools are available.

        Returns:
            True if at least one C++ compiler is found.
        """
        return (
            shutil.which("gcc") is not None
            or shutil.which("g++") is not None
            or shutil.which("clang") is not None
            or shutil.which("clang++") is not None
        )

    def get_version(self) -> str | None:
        """Get the installed C++ compiler version.

        Returns:
            Version string or None if not available.
        """
        if self._gcc_version is not None:
            return self._gcc_version

        for compiler in ["g++", "gcc", "clang++", "clang"]:
            try:
                import subprocess

                result = subprocess.run(
                    [compiler, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    # Parse first line
                    first_line = result.stdout.strip().split("\n")[0]
                    self._gcc_version = first_line
                    return first_line
            except Exception:
                pass

        return None

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _check_compile_commands(
        self, project_path: Path, detected_files: list[str]
    ) -> BuilderOutput | None:
        """Check for existing compile_commands.json.

        Args:
            project_path: Path to project root.
            detected_files: List to append detected files.

        Returns:
            BuilderOutput if valid compile_commands found, None otherwise.
        """
        # Check common locations
        locations = [
            project_path / "compile_commands.json",
            project_path / "build" / "compile_commands.json",
            project_path / "out" / "compile_commands.json",
        ]

        for compile_commands_path in locations:
            if compile_commands_path.exists():
                rel_path = compile_commands_path.relative_to(project_path)
                detected_files.append(str(rel_path))

                # Validate the compile_commands
                if self._validate_compile_commands(compile_commands_path):
                    return BuilderOutput(
                        result=BuildResult.SUCCESS,
                        language="cpp",
                        build_command=None,  # Use existing compile_commands
                        dependency_command=None,
                        cwd=project_path,
                        timeout=self.DEFAULT_TIMEOUT,
                        detected_files=detected_files,
                        build_system="compile_commands",
                    )
                else:
                    logger.warning(
                        f"Found invalid compile_commands.json at {rel_path}"
                    )

        return None

    def _validate_compile_commands(self, compile_commands_path: Path) -> bool:
        """Validate compile_commands.json format.

        Args:
            compile_commands_path: Path to compile_commands.json.

        Returns:
            True if valid, False otherwise.
        """
        try:
            content = compile_commands_path.read_text()
            data = json.loads(content)

            if not isinstance(data, list):
                return False

            if len(data) == 0:
                return False

            # Check first entry has required fields
            first_entry = data[0]
            required_fields = ["directory", "command", "file"]
            return all(field in first_entry for field in required_fields)

        except (json.JSONDecodeError, KeyError, Exception):
            return False

    def _check_cmake(
        self, project_path: Path, detected_files: list[str]
    ) -> BuilderOutput | None:
        """Check for CMake project.

        Args:
            project_path: Path to project root.
            detected_files: List to append detected files.

        Returns:
            BuilderOutput if CMakeLists.txt found, None otherwise.
        """
        cmake_lists = project_path / "CMakeLists.txt"
        if not cmake_lists.exists():
            return None

        detected_files.append("CMakeLists.txt")

        # Check if CMake is available
        if shutil.which("cmake") is None:
            return BuilderOutput(
                result=BuildResult.SKIPPED,
                language="cpp",
                skip_reason="CMake project found but cmake command not available",
                failure_category=FailureCategory.TOOL_MISSING,
                detected_files=detected_files,
                build_system="cmake",
            )

        # Check for complex custom options that would require manual intervention
        if self._has_complex_cmake_options(cmake_lists):
            return BuilderOutput(
                result=BuildResult.SKIPPED,
                language="cpp",
                skip_reason=(
                    "CMake project with complex options detected. "
                    "Please generate compile_commands.json manually with: "
                    "cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
                ),
                failure_category=FailureCategory.CONFIG_ERROR,
                detected_files=detected_files,
                build_system="cmake",
            )

        # Simple CMake project - generate compile_commands
        warnings: list[str] = []
        warnings.append(
            "CMake build will generate compile_commands.json in build/ directory"
        )

        return BuilderOutput(
            result=BuildResult.SUCCESS,
            language="cpp",
            build_command=None,  # Use generated compile_commands
            dependency_command="cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            cwd=project_path,
            timeout=self.DEFAULT_TIMEOUT,
            warnings=warnings,
            detected_files=detected_files,
            build_system="cmake",
        )

    def _has_complex_cmake_options(self, cmake_lists: Path) -> bool:
        """Check if CMakeLists.txt has complex options requiring manual intervention.

        Args:
            cmake_lists: Path to CMakeLists.txt.

        Returns:
            True if complex options detected.
        """
        try:
            content = cmake_lists.read_text().lower()

            # Patterns that indicate complex configuration
            complex_patterns = [
                r"option\(",
                r"set\([^)]*cache",
                r"find_package",
                r"externalproject",
                r"fetchcontent",
            ]

            for pattern in complex_patterns:
                if re.search(pattern, content):
                    return True

            return False

        except Exception:
            # If we can't read, assume complex to be safe
            return True

    def _check_makefile(
        self, project_path: Path, detected_files: list[str]
    ) -> BuilderOutput | None:
        """Check for Makefile with conservative strategy.

        Args:
            project_path: Path to project root.
            detected_files: List to append detected files.

        Returns:
            BuilderOutput if simple Makefile found, None or skipped otherwise.
        """
        makefile_paths = [
            project_path / "Makefile",
            project_path / "makefile",
        ]

        makefile_path = None
        for path in makefile_paths:
            if path.exists():
                makefile_path = path
                break

        if makefile_path is None:
            return None

        detected_files.append(makefile_path.name)

        # Check if Makefile is complex
        if self._is_complex_makefile(makefile_path):
            return BuilderOutput(
                result=BuildResult.SKIPPED,
                language="cpp",
                skip_reason=(
                    "Complex Makefile detected - skipping to avoid uncontrolled build. "
                    "Consider creating a compile_commands.json or using CMake."
                ),
                failure_category=FailureCategory.CONFIG_ERROR,
                detected_files=detected_files,
                build_system="make",
            )

        # Simple Makefile - conservative build
        warnings: list[str] = []
        warnings.append("Makefile build is conservative - may fail for complex projects")

        return BuilderOutput(
            result=BuildResult.SUCCESS,
            language="cpp",
            build_command="make -j$(nproc)",
            dependency_command=None,
            cwd=project_path,
            timeout=900,  # Longer timeout for Make
            warnings=warnings,
            detected_files=detected_files,
            build_system="make",
        )

    def _is_complex_makefile(self, makefile_path: Path) -> bool:
        """Check if Makefile is complex and should be skipped.

        Args:
            makefile_path: Path to Makefile.

        Returns:
            True if complex Makefile detected.
        """
        try:
            content = makefile_path.read_text()

            # Patterns that indicate complex Makefiles
            complex_patterns = [
                r"\$\(shell",  # Shell calls
                r"\$\(wildcard",  # Complex wildcard usage
                r"\$\(foreach",  # Loops
                r"\$\(if",  # Conditionals
                r"^\.PHONY:",  # Phony targets (common but acceptable, check for many)
                r"configure",  # Autotools pattern
                r"autoconf",
                r"automake",
                r"@sudo",  # Requiring sudo is a red flag
                r"^include",  # Including other Makefiles
            ]

            # Count patterns
            pattern_count = 0
            for pattern in complex_patterns:
                if re.search(pattern, content, re.MULTILINE):
                    pattern_count += 1

            # If multiple complex patterns or any dangerous pattern
            if re.search(r"@sudo", content, re.IGNORECASE):
                return True

            # Check for many targets (more than 10)
            target_count = len(re.findall(r"^[a-zA-Z0-9_-]+:", content, re.MULTILINE))
            if target_count > 10:
                return True

            return pattern_count >= 2

        except Exception:
            # If we can't read, assume complex to be safe
            return True

    def _is_header_only(self, project_path: Path) -> bool:
        """Check if project is header-only.

        Args:
            project_path: Path to project root.

        Returns:
            True if project appears to be header-only.
        """
        source_count = 0
        header_count = 0

        try:
            for file_path in project_path.rglob("*"):
                if not file_path.is_file():
                    continue

                # Skip common build directories
                parts = file_path.parts
                skip_dirs = {"build", "out", "dist", "node_modules", ".git"}
                if any(skip_dir in parts for skip_dir in skip_dirs):
                    continue

                ext = file_path.suffix.lower()
                if ext in self.SOURCE_EXTENSIONS:
                    source_count += 1
                elif ext in self.HEADER_EXTENSIONS:
                    header_count += 1

        except Exception:
            pass

        total = source_count + header_count
        if total == 0:
            return False

        # If >90% headers and no source files in root
        header_ratio = header_count / total
        return header_ratio > 0.9 and source_count == 0
