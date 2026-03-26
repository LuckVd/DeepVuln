"""
JavaScript/TypeScript language builder for CodeQL database creation.

Provides intelligent build strategies for JavaScript and TypeScript projects:
- No-build path (CodeQL analyzes source directly)
- TypeScript detection and project references
- Path alias detection
- Workspace (monorepo) detection
- Package manager detection (npm, yarn, pnpm)
"""

import json
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
class JSProjectInfo:
    """Information about a JavaScript/TypeScript project."""

    has_package_json: bool = False
    has_tsconfig: bool = False
    is_typescript: bool = False
    has_project_references: bool = False
    has_path_aliases: bool = False
    has_workspace: bool = False
    package_manager: str = "npm"  # npm, yarn, pnpm
    node_version: str | None = None
    js_file_count: int = 0
    ts_file_count: int = 0
    workspace_packages: list[str] = None  # type: ignore

    def __post_init__(self):
        if self.workspace_packages is None:
            self.workspace_packages = []


@BuilderRegistry.register
class JavaScriptBuilder(LanguageBuilder):
    """Builder for JavaScript and TypeScript projects.

    JavaScript and TypeScript are interpreted/compiled languages that don't
    require compilation for CodeQL analysis. This builder provides a no-build
    path with optional detection of conditions that might warrant attention.
    """

    LANGUAGE_NAME = "javascript"
    SUPPORTED_BUILD_SYSTEMS = ["npm", "yarn", "pnpm"]

    # Default timeout (JS/TS projects typically don't need build)
    DEFAULT_TIMEOUT = 60

    def __init__(self) -> None:
        """Initialize the JavaScript builder."""
        self._node_version: str | None = None

    def analyze(self, project_path: Path) -> BuilderOutput:
        """Analyze a JavaScript/TypeScript project and generate build strategy.

        Args:
            project_path: Path to the project root.

        Returns:
            BuilderOutput with no-build strategy.
        """
        project_path = Path(project_path)
        detected_files: list[str] = []
        warnings: list[str] = []

        # Count JS/TS files
        js_count, ts_count = self._count_js_ts_files(project_path)

        if js_count == 0 and ts_count == 0:
            return BuilderOutput(
                result=BuildResult.SKIPPED,
                language="javascript",
                skip_reason="No JavaScript or TypeScript files found in project",
                failure_category=FailureCategory.CONFIG_ERROR,
            )

        # Detect project structure
        info = self._detect_project_info(project_path)

        # Build detected files list
        if info.has_package_json:
            detected_files.append("package.json")
        if info.has_tsconfig:
            detected_files.append("tsconfig.json")

        # Add lock files
        if (project_path / "package-lock.json").exists():
            detected_files.append("package-lock.json")
        elif (project_path / "yarn.lock").exists():
            detected_files.append("yarn.lock")
        elif (project_path / "pnpm-lock.yaml").exists():
            detected_files.append("pnpm-lock.yaml")

        # Determine language
        language = "typescript" if info.is_typescript else "javascript"

        # Check for conditions that might need attention
        if info.has_project_references:
            warnings.append(
                "TypeScript project references detected - "
                "CodeQL may need built output for cross-project analysis"
            )

        if info.has_path_aliases:
            warnings.append(
                "TypeScript path aliases detected - "
                "module resolution may be incomplete without build"
            )

        if info.has_workspace:
            warnings.append(
                f"Monorepo workspace detected ({len(info.workspace_packages)} packages) - "
                "ensure all workspace packages are available"
            )

        return BuilderOutput(
            result=BuildResult.SUCCESS,
            language=language,
            build_command=None,  # No build required
            dependency_command=None,  # No deps install by default
            cwd=project_path,
            timeout=self.DEFAULT_TIMEOUT,
            warnings=warnings,
            detected_files=detected_files,
            build_system=info.package_manager,
        )

    def diagnose_failure(
        self, stdout: str, stderr: str, return_code: int
    ) -> FailureDiagnosis:
        """Diagnose a JavaScript/TypeScript build failure.

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

        # Missing module
        if "cannot find module" in combined:
            match = re.search(r"cannot find module ['\"]([^'\"]+)['\"]", combined)
            module = match.group(1) if match else "unknown"
            return FailureDiagnosis(
                category=FailureCategory.DEPENDENCY_MISSING,
                message=f"Missing module: {module}",
                suggestion=f"Run npm install or yarn install",
                is_recoverable=True,
            )

        # NPM package not found
        if "404 not found" in combined and "npmjs.org" in combined:
            match = re.search(r"GET[^']*'([^']+)'", combined)
            pkg = match.group(1) if match else "unknown"
            return FailureDiagnosis(
                category=FailureCategory.DEPENDENCY_RESOLUTION,
                message=f"Package not found: {pkg}",
                suggestion="Check package name in package.json",
                is_recoverable=True,
            )

        # TypeScript compilation error
        if "error ts" in combined:
            # Extract error details
            match = re.search(r"error ts(\d+): (.+)", combined)
            if match:
                code, msg = match.groups()
                return FailureDiagnosis(
                    category=FailureCategory.COMPILATION_ERROR,
                    message=f"TypeScript error TS{code}: {msg}",
                    suggestion="Fix TypeScript errors in source files",
                    is_recoverable=False,
                )
            return FailureDiagnosis(
                category=FailureCategory.COMPILATION_ERROR,
                message="TypeScript compilation error",
                suggestion="Check TypeScript errors",
                is_recoverable=False,
            )

        # JavaScript syntax error
        if "syntaxerror" in combined:
            match = re.search(r"syntaxerror: (.+)", combined)
            msg = match.group(1) if match else "Unknown syntax error"
            return FailureDiagnosis(
                category=FailureCategory.COMPILATION_ERROR,
                message=f"JavaScript syntax error: {msg}",
                suggestion="Fix syntax error in source file",
                is_recoverable=False,
            )

        # Node version mismatch
        if "engine" in combined and "incompatible" in combined:
            return FailureDiagnosis(
                category=FailureCategory.VERSION_MISMATCH,
                message="Node.js version incompatible with project requirements",
                suggestion="Check engines field in package.json and use compatible Node version",
                is_recoverable=False,
            )

        # Permission error
        if "eacces" in combined or "permission denied" in combined:
            return FailureDiagnosis(
                category=FailureCategory.PERMISSION_DENIED,
                message="Permission denied during operation",
                suggestion="Check file/directory permissions or run with appropriate privileges",
                is_recoverable=True,
            )

        # Network error
        if "enotfound" in combined or "network" in combined:
            return FailureDiagnosis(
                category=FailureCategory.DEPENDENCY_RESOLUTION,
                message="Network error during dependency resolution",
                suggestion="Check network connection and registry access",
                is_recoverable=True,
            )

        return FailureDiagnosis(
            category=FailureCategory.UNKNOWN,
            message=f"Unknown JavaScript/TypeScript failure (exit code {return_code})",
            suggestion="Review error output for details",
        )

    def is_available(self) -> bool:
        """Check if Node.js is installed."""
        return shutil.which("node") is not None

    def get_version(self) -> str | None:
        """Get the installed Node.js version."""
        if self._node_version is not None:
            return self._node_version

        try:
            import subprocess

            result = subprocess.run(
                ["node", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse "v18.17.0"
                match = re.search(r"v(\d+\.\d+)", result.stdout)
                if match:
                    self._node_version = match.group(1)
                    return self._node_version
        except Exception:
            pass

        return None

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _detect_project_info(self, project_path: Path) -> JSProjectInfo:
        """Detect JavaScript/TypeScript project information.

        Args:
            project_path: Path to project root.

        Returns:
            JSProjectInfo with detected metadata.
        """
        info = JSProjectInfo()

        # Check for package.json
        package_json = project_path / "package.json"
        if package_json.exists():
            info.has_package_json = True
            info.package_manager = self._detect_package_manager(project_path)
            self._parse_package_json(package_json, info)

        # Check for tsconfig.json
        tsconfig = project_path / "tsconfig.json"
        if tsconfig.exists():
            info.has_tsconfig = True
            info.is_typescript = True
            info.has_project_references = self._has_project_references(project_path)
            info.has_path_aliases = self._has_path_aliases(project_path)

        # Also check for .ts/.tsx files without tsconfig
        js_count, ts_count = self._count_js_ts_files(project_path)
        info.js_file_count = js_count
        info.ts_file_count = ts_count

        # Determine if TypeScript (tsconfig or .ts/.tsx files)
        if not info.has_tsconfig and ts_count > 0:
            # Has .ts/.tsx files but no tsconfig - still TypeScript
            info.is_typescript = True

        return info

    def _detect_package_manager(self, project_path: Path) -> str:
        """Detect which package manager is used.

        Args:
            project_path: Path to project root.

        Returns:
            Package manager name: npm, yarn, or pnpm.
        """
        if (project_path / "yarn.lock").exists():
            return "yarn"
        if (project_path / "pnpm-lock.yaml").exists():
            return "pnpm"
        return "npm"

    def _parse_package_json(self, package_json: Path, info: JSProjectInfo) -> None:
        """Parse package.json for metadata.

        Args:
            package_json: Path to package.json.
            info: JSProjectInfo to update.
        """
        try:
            content = json.loads(package_json.read_text())

            # Check for workspaces
            workspaces = content.get("workspaces")
            if workspaces:
                info.has_workspace = True
                if isinstance(workspaces, list):
                    # Glob patterns - count matching directories
                    info.workspace_packages = workspaces
                elif isinstance(workspaces, dict):
                    # yarn/npm workspaces format
                    packages = workspaces.get("packages", [])
                    info.workspace_packages = packages

            # Check for engines
            engines = content.get("engines", {})
            node_engine = engines.get("node")
            if node_engine:
                # Extract version from constraint like ">=18"
                match = re.search(r"(\d+\.\d+)", node_engine)
                if match:
                    info.node_version = match.group(1)

        except Exception as e:
            logger.warning(f"Failed to parse package.json: {e}")

    def _is_typescript(self, project_path: Path) -> bool:
        """Check if project is TypeScript.

        Args:
            project_path: Path to project root.

        Returns:
            True if tsconfig.json exists.
        """
        return (project_path / "tsconfig.json").exists()

    def _has_project_references(self, project_path: Path) -> bool:
        """Check if TypeScript project has project references.

        Args:
            project_path: Path to project root.

        Returns:
            True if references field exists in tsconfig.
        """
        tsconfig = project_path / "tsconfig.json"
        if not tsconfig.exists():
            return False

        try:
            content = tsconfig.read_text()
            # Simple check for references field
            return '"references"' in content or "'references'" in content
        except Exception:
            return False

    def _has_path_aliases(self, project_path: Path) -> bool:
        """Check if TypeScript project has path aliases.

        Args:
            project_path: Path to project root.

        Returns:
            True if paths field exists in compilerOptions.
        """
        tsconfig = project_path / "tsconfig.json"
        if not tsconfig.exists():
            return False

        try:
            content = tsconfig.read_text()
            # Simple check for paths field in compilerOptions
            return '"paths"' in content or "'paths'" in content
        except Exception:
            return False

    def _has_workspace(self, project_path: Path) -> bool:
        """Check if project is a workspace root.

        Args:
            project_path: Path to project root.

        Returns:
            True if workspaces field in package.json.
        """
        package_json = project_path / "package.json"
        if not package_json.exists():
            return False

        try:
            content = json.loads(package_json.read_text())
            return "workspaces" in content
        except Exception:
            return False

    def _count_js_ts_files(self, project_path: Path) -> tuple[int, int]:
        """Count JavaScript and TypeScript files.

        Args:
            project_path: Path to project root.

        Returns:
            Tuple of (js_count, ts_count).
        """
        # Skip common non-source directories
        skip_dirs = {"node_modules", ".git", "dist", "build", "out", ".next", "__tests__"}

        js_count = 0
        ts_count = 0

        for file in project_path.rglob("*"):
            if not file.is_file():
                continue

            # Check if any skip dir is in the path
            parts = set(file.relative_to(project_path).parts)
            if parts.intersection(skip_dirs):
                continue

            ext = file.suffix.lower()
            if ext in (".js", ".jsx", ".mjs", ".cjs"):
                js_count += 1
            elif ext in (".ts", ".tsx", ".mts", ".cts"):
                ts_count += 1

        return js_count, ts_count


# Also register for TypeScript
# Note: BuilderRegistry.register decorator already registered this as "javascript"
# We need to also make it available for "typescript" lookups
def _register_typescript():
    """Register the same builder for TypeScript."""
    from .base import BuilderRegistry
    BuilderRegistry._builders["typescript"] = JavaScriptBuilder


_register_typescript()
