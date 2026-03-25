"""
Go language builder for CodeQL database creation.

Provides intelligent build strategies for Go projects including:
- go.mod parsing and validation
- CGO detection and handling
- Private module proxy configuration
- Build tag detection
- Vendor directory support
"""

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
class GoBuilder(LanguageBuilder):
    """Builder for Go projects.

    Analyzes Go projects and generates appropriate build strategies
    for CodeQL database creation.
    """

    LANGUAGE_NAME = "go"
    SUPPORTED_BUILD_SYSTEMS = ["go_modules", "go_work"]

    # Default timeout for Go builds (5 minutes)
    DEFAULT_TIMEOUT = 300

    # Maximum timeout for large projects
    MAX_TIMEOUT = 900

    def __init__(self) -> None:
        """Initialize the Go builder."""
        self._go_version: str | None = None

    def analyze(self, project_path: Path) -> BuilderOutput:
        """Analyze a Go project and generate build strategy.

        Args:
            project_path: Path to the Go project root.

        Returns:
            BuilderOutput with build commands and configuration.
        """
        project_path = Path(project_path)
        detected_files: list[str] = []

        # Check for go.work first (multi-module workspace)
        go_work = project_path / "go.work"
        if go_work.exists():
            detected_files.append("go.work")
            return self._analyze_workspace(project_path, go_work, detected_files)

        # Check for go.mod
        go_mod = project_path / "go.mod"
        if not go_mod.exists():
            return BuilderOutput(
                result=BuildResult.SKIPPED,
                language="go",
                skip_reason="No go.mod found - not a Go module",
                failure_category=FailureCategory.CONFIG_ERROR,
            )

        detected_files.append("go.mod")

        # Parse go.mod
        mod_info = self._parse_go_mod(go_mod)
        module_name = mod_info.get("module", project_path.name)
        go_version = mod_info.get("go_version")

        # Check for CGO
        has_cgo = self._has_cgo(project_path)
        warnings: list[str] = []

        if has_cgo:
            warnings.append("CGO detected in project - requires C compiler")
            # Check if C compiler is available
            if not self._has_c_compiler():
                return BuilderOutput(
                    result=BuildResult.SKIPPED,
                    language="go",
                    skip_reason="CGO project requires C compiler (cc/gcc) but none found",
                    failure_category=FailureCategory.CGO_REQUIRED,
                    detected_files=detected_files,
                    warnings=warnings,
                    module_name=module_name,
                )

        # Check for vendor directory
        has_vendor = self._has_vendor(project_path)

        # Detect build tags
        build_tags = self._get_build_tags(project_path)

        # Build command
        build_command = self._get_build_command(has_vendor, build_tags)

        # Dependency command
        dep_command = self._get_dependency_command(has_vendor)

        # Environment variables
        env_vars = self._get_env_vars(project_path)

        return BuilderOutput(
            result=BuildResult.SUCCESS,
            language="go",
            build_command=build_command,
            dependency_command=dep_command,
            env_vars=env_vars,
            cwd=project_path,
            timeout=self.DEFAULT_TIMEOUT,
            warnings=warnings,
            detected_files=detected_files,
            build_system="go_modules",
            module_name=module_name,
        )

    def diagnose_failure(
        self, stdout: str, stderr: str, return_code: int
    ) -> FailureDiagnosis:
        """Diagnose a Go build failure from command output.

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

        # Dependency missing
        if "cannot find package" in combined or "no such package" in combined:
            package_match = re.search(
                r'["\']([^"\']+)["\']', stderr or stdout
            )
            package = package_match.group(1) if package_match else "unknown"
            return FailureDiagnosis(
                category=FailureCategory.DEPENDENCY_MISSING,
                message=f"Missing Go package: {package}",
                suggestion="Run 'go mod download' or check module path",
                is_recoverable=True,
            )

        # Private module inaccessible
        if "private" in combined and ("unknown revision" in combined or "git ls-remote" in combined):
            return FailureDiagnosis(
                category=FailureCategory.PRIVATE_MODULE,
                message="Private Go module inaccessible - check GOPRIVATE and credentials",
                suggestion="Set GOPRIVATE environment variable or configure git credentials",
                is_recoverable=True,
            )

        # CGO related errors
        if any(
            pattern in combined
            for pattern in ["cgo", "import \"c\"", "#include", "fatal error:"]
        ):
            if "file not found" in combined or "not found" in combined:
                return FailureDiagnosis(
                    category=FailureCategory.CGO_REQUIRED,
                    message="CGO build failed - C header or compiler not found",
                    suggestion="Install C compiler (gcc/clang) and required headers",
                    is_recoverable=False,
                )

        # Go version mismatch
        if "maximum supported version" in combined or "go.mod file indicates go" in combined:
            version_match = re.search(r"go (\d+\.\d+)", combined)
            version = version_match.group(1) if version_match else "unknown"
            return FailureDiagnosis(
                category=FailureCategory.VERSION_MISMATCH,
                message=f"Go version mismatch - project requires Go {version}",
                suggestion=f"Upgrade Go to version {version} or higher",
                is_recoverable=False,
            )

        # Compilation errors
        if "undefined:" in combined or "syntax error" in combined or "cannot use" in combined:
            # Extract first error line for context
            error_line = stderr.split("\n")[0] if stderr else ""
            return FailureDiagnosis(
                category=FailureCategory.COMPILATION_ERROR,
                message=f"Go compilation error: {error_line[:100]}",
                suggestion="Fix the compilation errors in the source code",
                is_recoverable=False,
            )

        # Build error (generic)
        if "build" in combined and ("failed" in combined or "error" in combined):
            return FailureDiagnosis(
                category=FailureCategory.BUILD_ERROR,
                message="Go build failed",
                suggestion="Check build output for specific errors",
                is_recoverable=False,
            )

        return FailureDiagnosis(
            category=FailureCategory.UNKNOWN,
            message=f"Unknown Go build failure (exit code {return_code})",
            suggestion="Review build output for details",
        )

    def is_available(self) -> bool:
        """Check if Go is installed."""
        return shutil.which("go") is not None

    def get_version(self) -> str | None:
        """Get the installed Go version."""
        if self._go_version is not None:
            return self._go_version

        try:
            import subprocess

            result = subprocess.run(
                ["go", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse "go version go1.21.0 linux/amd64"
                match = re.search(r"go(\d+\.\d+(?:\.\d+)?)", result.stdout)
                if match:
                    self._go_version = match.group(1)
                    return self._go_version
        except Exception:
            pass

        return None

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _analyze_workspace(
        self,
        project_path: Path,
        go_work: Path,
        detected_files: list[str],
    ) -> BuilderOutput:
        """Analyze a Go workspace (go.work)."""
        # Check for go.mod in subdirectories
        module_count = 0
        for use_dir in project_path.iterdir():
            if (use_dir / "go.mod").exists():
                module_count += 1
                detected_files.append(f"{use_dir.name}/go.mod")

        return BuilderOutput(
            result=BuildResult.SUCCESS,
            language="go",
            build_command="go build ./...",
            dependency_command="go work sync",
            cwd=project_path,
            timeout=self.DEFAULT_TIMEOUT,
            detected_files=detected_files,
            build_system="go_work",
            module_name=project_path.name,
        )

    def _parse_go_mod(self, go_mod: Path) -> dict[str, Any]:
        """Parse go.mod file to extract module information.

        Args:
            go_mod: Path to go.mod file.

        Returns:
            Dictionary with module, go_version, and dependencies.
        """
        info: dict[str, Any] = {}

        try:
            content = go_mod.read_text()

            # Extract module name
            module_match = re.search(r"^module\s+([^\s\n]+)", content, re.MULTILINE)
            if module_match:
                info["module"] = module_match.group(1)

            # Extract Go version
            go_match = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", content, re.MULTILINE)
            if go_match:
                info["go_version"] = go_match.group(1)

            # Extract direct dependencies
            deps: list[str] = []
            require_block = re.search(
                r"^require\s*\(([^)]+)\)", content, re.MULTILINE | re.DOTALL
            )
            if require_block:
                for line in require_block.group(1).strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("//"):
                        # Extract module path
                        dep_match = re.match(r"^([^\s]+)", line)
                        if dep_match:
                            deps.append(dep_match.group(1))

            info["dependencies"] = deps

        except Exception as e:
            logger.warning(f"Failed to parse go.mod: {e}")

        return info

    def _has_cgo(self, project_path: Path) -> bool:
        """Check if project uses CGO by scanning for import \"C\".

        Args:
            project_path: Path to project root.

        Returns:
            True if CGO is detected in any Go file.
        """
        # Look for import "C" in Go files
        cgo_pattern = re.compile(r'import\s+"C"')

        for go_file in project_path.rglob("*.go"):
            # Skip vendor and test directories
            if "vendor" in str(go_file).split("/") or "_test.go" in go_file.name:
                continue

            try:
                content = go_file.read_text()
                if cgo_pattern.search(content):
                    return True
            except Exception:
                pass

        return False

    def _has_c_compiler(self) -> bool:
        """Check if a C compiler is available.

        Returns:
            True if cc or gcc is found in PATH.
        """
        return shutil.which("cc") is not None or shutil.which("gcc") is not None

    def _has_vendor(self, project_path: Path) -> bool:
        """Check if vendor directory exists.

        Args:
            project_path: Path to project root.

        Returns:
            True if vendor directory exists.
        """
        return (project_path / "vendor").is_dir()

    def _get_build_tags(self, project_path: Path) -> list[str]:
        """Extract build tags from Go source files.

        Args:
            project_path: Path to project root.

        Returns:
            List of unique build tags found.
        """
        tags: set[str] = set()

        # Patterns for build tags
        # Old style: // +build linux,windows
        # New style: //go:build linux && windows
        old_style = re.compile(r"//\s*\+build\s+([^\n]+)")
        new_style = re.compile(r"//go:build\s+([^\n]+)")

        for go_file in project_path.rglob("*.go"):
            if "vendor" in str(go_file).split("/"):
                continue

            try:
                content = go_file.read_text()

                # Check for build tags in first 10 lines (convention)
                for line in content.split("\n")[:10]:
                    # New style (Go 1.17+)
                    new_match = new_style.search(line)
                    if new_match:
                        # Parse expression and extract tags
                        expr = new_match.group(1)
                        # Simple extraction - split on && and ||
                        for part in re.split(r"[&|]+", expr):
                            tag = part.strip().lstrip("!")
                            if tag and not tag.startswith("("):
                                tags.add(tag)

                    # Old style
                    old_match = old_style.search(line)
                    if old_match:
                        for group in old_match.group(1).split(","):
                            for tag in group.split():
                                tag = tag.strip().lstrip("!")
                                if tag:
                                    tags.add(tag)

            except Exception:
                pass

        # Filter out common noise
        ignore_tags = {"ignore", "generated"}
        return sorted(tags - ignore_tags)

    def _get_build_command(
        self,
        has_vendor: bool,
        build_tags: list[str],
    ) -> str:
        """Generate build command.

        Args:
            has_vendor: Whether vendor directory exists.
            build_tags: List of build tags to include.

        Returns:
            Build command string.
        """
        cmd_parts = ["go build"]

        # Vendor mode
        if has_vendor:
            cmd_parts.append("-mod=vendor")

        # Build tags (only include common ones to avoid conflicts)
        # Don't add platform-specific tags automatically
        if build_tags:
            # Filter to only non-platform tags that are safe to add
            safe_tags = [
                t
                for t in build_tags
                if t
                not in {
                    "linux",
                    "windows",
                    "darwin",
                    "freebsd",
                    "netbsd",
                    "openbsd",
                    "amd64",
                    "arm64",
                    "386",
                    "arm",
                }
            ]
            if safe_tags:
                cmd_parts.append(f"-tags={','.join(safe_tags[:5])}")

        cmd_parts.append("./...")

        return " ".join(cmd_parts)

    def _get_dependency_command(self, has_vendor: bool) -> str:
        """Generate dependency installation command.

        Args:
            has_vendor: Whether vendor directory exists.

        Returns:
            Dependency command or None if vendored.
        """
        if has_vendor:
            # Vendored projects don't need to download
            return None
        return "go mod download"

    def _get_env_vars(self, project_path: Path) -> dict[str, str]:
        """Generate environment variables for Go build.

        Args:
            project_path: Path to project root.

        Returns:
            Dictionary of environment variables.
        """
        env: dict[str, str] = {}

        # Default GOPROXY
        env["GOPROXY"] = "https://proxy.golang.org,direct"

        # Check for private modules in go.mod
        go_mod = project_path / "go.mod"
        if go_mod.exists():
            try:
                content = go_mod.read_text()
                # Look for private module patterns
                module_match = re.search(r"^module\s+([^\s\n]+)", content, re.MULTILINE)
                if module_match:
                    module_path = module_match.group(1)
                    # If module path looks private (not github.com, gitlab.com, etc.)
                    if not any(
                        host in module_path
                        for host in ["github.com", "gitlab.com", "bitbucket.org", "golang.org"]
                    ):
                        # Set GOPRIVATE for the module
                        env["GOPRIVATE"] = module_path
            except Exception:
                pass

        return env
