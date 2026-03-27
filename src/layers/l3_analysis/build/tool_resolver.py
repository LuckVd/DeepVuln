"""
Tool Resolver - Discover and resolve build tools from multiple sources.

This module provides tool discovery and version detection for CodeQL build
environment setup. It searches for tools in:
1. Managed paths (pre-installed directories)
2. Local cache (user-managed tool cache)
3. System PATH
"""

import asyncio
import os
import re
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# Enums
# =============================================================================


class ToolType(str, Enum):
    """Supported tool types for CodeQL builds."""

    JAVA = "java"
    GO = "go"
    NODE = "node"
    MAVEN = "maven"
    GRADLE = "gradle"
    NPM = "npm"
    YARN = "yarn"
    PNPM = "pnpm"
    PYTHON = "python"


class ToolSource(str, Enum):
    """Where a tool was discovered."""

    SYSTEM_PATH = "system_path"
    LOCAL_CACHE = "local_cache"
    MANAGED_PATH = "managed_path"


class ProvisionPolicy(str, Enum):
    """Policy for handling missing or incompatible tools."""

    STRICT = "strict"  # Fail if requirements not met
    REUSE_ONLY = "reuse_only"  # Use available tools, warn on issues
    MANAGED_CACHE = "managed_cache"  # Try to use managed cache
    AUTO_INSTALL = "auto_install"  # Automatically install missing versions


class CompatibilityStatus(str, Enum):
    """Status of compatibility check."""

    OK = "ok"
    VERSION_MISMATCH = "version_mismatch"
    NOT_FOUND = "not_found"
    CAPABILITY_MISSING = "capability_missing"


# =============================================================================
# Tool Configuration
# =============================================================================


@dataclass
class ToolConfig:
    """Configuration for discovering a specific tool."""

    tool_type: ToolType
    version_command: list[str]  # Command to get version, e.g., ["java", "-version"]
    version_regex: str  # Regex to extract version from output
    stderr_version: bool = False  # Whether version is on stderr

    # Default search names for different platforms
    executable_names: list[str] = field(default_factory=list)


# Default tool configurations
TOOL_CONFIGS: dict[ToolType, ToolConfig] = {
    ToolType.JAVA: ToolConfig(
        tool_type=ToolType.JAVA,
        version_command=["java", "-version"],
        version_regex=r'version "?(\d+(?:\.\d+)*)',
        stderr_version=True,
        executable_names=["java"],
    ),
    ToolType.GO: ToolConfig(
        tool_type=ToolType.GO,
        version_command=["go", "version"],
        version_regex=r"go(\d+(?:\.\d+)*)",
        stderr_version=False,
        executable_names=["go"],
    ),
    ToolType.NODE: ToolConfig(
        tool_type=ToolType.NODE,
        version_command=["node", "--version"],
        version_regex=r"v?(\d+(?:\.\d+)*)",
        stderr_version=False,
        executable_names=["node"],
    ),
    ToolType.MAVEN: ToolConfig(
        tool_type=ToolType.MAVEN,
        version_command=["mvn", "-version"],
        version_regex=r"Apache Maven (\d+(?:\.\d+)*)",
        stderr_version=False,
        executable_names=["mvn"],
    ),
    ToolType.GRADLE: ToolConfig(
        tool_type=ToolType.GRADLE,
        version_command=["gradle", "-version"],
        version_regex=r"Gradle (\d+(?:\.\d+)*)",
        stderr_version=False,
        executable_names=["gradle"],
    ),
    ToolType.NPM: ToolConfig(
        tool_type=ToolType.NPM,
        version_command=["npm", "--version"],
        version_regex=r"(\d+(?:\.\d+)*)",
        stderr_version=False,
        executable_names=["npm"],
    ),
    ToolType.YARN: ToolConfig(
        tool_type=ToolType.YARN,
        version_command=["yarn", "--version"],
        version_regex=r"(\d+(?:\.\d+)*)",
        stderr_version=False,
        executable_names=["yarn"],
    ),
    ToolType.PNPM: ToolConfig(
        tool_type=ToolType.PNPM,
        version_command=["pnpm", "--version"],
        version_regex=r"(\d+(?:\.\d+)*)",
        stderr_version=False,
        executable_names=["pnpm"],
    ),
    ToolType.PYTHON: ToolConfig(
        tool_type=ToolType.PYTHON,
        version_command=["python", "--version"],
        version_regex=r"Python (\d+(?:\.\d+)*)",
        stderr_version=False,
        executable_names=["python", "python3"],
    ),
}


# =============================================================================
# Default Paths
# =============================================================================

# Default managed paths (pre-installed tools)
DEFAULT_MANAGED_PATHS = [
    Path("/opt/tools"),
    Path("/usr/local/tools"),
    Path.home() / ".local" / "tools",
]

# Default local cache directory
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "deepvuln" / "tools"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ToolInfo:
    """Information about a discovered tool."""

    tool_type: ToolType
    path: Path
    version: str | None = None
    source: ToolSource = ToolSource.SYSTEM_PATH
    executable: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "tool_type": self.tool_type.value,
            "path": str(self.path),
            "version": self.version,
            "source": self.source.value,
            "executable": self.executable,
        }


@dataclass
class CompatibilityResult:
    """Result of compatibility check for a tool."""

    tool_type: ToolType
    status: CompatibilityStatus
    tool: ToolInfo | None = None
    required_version: str | None = None
    actual_version: str | None = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "tool_type": self.tool_type.value,
            "status": self.status.value,
            "tool": self.tool.to_dict() if self.tool else None,
            "required_version": self.required_version,
            "actual_version": self.actual_version,
            "message": self.message,
        }

    @property
    def compatible(self) -> bool:
        """Check if tool is compatible."""
        return self.status == CompatibilityStatus.OK


@dataclass
class ReadinessReport:
    """Tool readiness report for build environment."""

    ready_tools: list[ToolInfo] = field(default_factory=list)
    incompatible_tools: list[CompatibilityResult] = field(default_factory=list)
    missing_tools: list[ToolType] = field(default_factory=list)
    policy: ProvisionPolicy = ProvisionPolicy.REUSE_ONLY

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "ready_tools": [t.to_dict() for t in self.ready_tools],
            "incompatible_tools": [r.to_dict() for r in self.incompatible_tools],
            "missing_tools": [t.value for t in self.missing_tools],
            "policy": self.policy.value,
        }

    @property
    def is_ready(self) -> bool:
        """Check if all required tools are ready."""
        if self.policy == ProvisionPolicy.STRICT:
            return len(self.incompatible_tools) == 0 and len(self.missing_tools) == 0
        return True  # Non-strict policies allow continuation

    @property
    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return len(self.incompatible_tools) > 0 or len(self.missing_tools) > 0


# =============================================================================
# Version Utilities
# =============================================================================


def parse_version(version_string: str) -> tuple[int, ...] | None:
    """Parse version string to tuple of integers.

    Args:
        version_string: Version string like "11.0.1" or "1.8"

    Returns:
        Tuple of integers like (11, 0, 1) or None if parsing fails.
    """
    # Remove leading 'v' if present
    version_string = version_string.lstrip("v")

    # Split by dots and convert to integers
    parts = []
    for part in version_string.split("."):
        # Handle version like "11u" or "8b"
        match = re.match(r"(\d+)", part)
        if match:
            parts.append(int(match.group(1)))
        else:
            break

    return tuple(parts) if parts else None


def version_matches(actual: str | None, required: str) -> bool:
    """Check if actual version matches required version constraint.

    Supports:
    - Exact match: "11"
    - Greater or equal: ">=11"
    - Greater than: ">11"
    - Less than or equal: "<=11"
    - Less than: "<11"
    - Caret (compatible): "^1.2.3" (>=1.2.3 <2.0.0)
    - Tilde (patch): "~1.2.3" (>=1.2.3 <1.3.0)
    - Range: "11-17" (inclusive)

    Args:
        actual: Actual version string.
        required: Required version constraint.

    Returns:
        True if version matches, False otherwise.
    """
    if not actual:
        return False

    actual_tuple = parse_version(actual)
    if not actual_tuple:
        return False

    required = required.strip()

    # Handle || (OR) operator
    if "||" in required:
        constraints = [c.strip() for c in required.split("||")]
        return any(version_matches(actual, c) for c in constraints)

    # Handle >= constraint
    if required.startswith(">="):
        required_tuple = parse_version(required[2:])
        return required_tuple is not None and _version_gte(actual_tuple, required_tuple)

    # Handle > constraint
    if required.startswith(">"):
        required_tuple = parse_version(required[1:])
        return required_tuple is not None and _version_gt(actual_tuple, required_tuple)

    # Handle <= constraint
    if required.startswith("<="):
        required_tuple = parse_version(required[2:])
        return required_tuple is not None and _version_lte(actual_tuple, required_tuple)

    # Handle < constraint
    if required.startswith("<"):
        required_tuple = parse_version(required[1:])
        return required_tuple is not None and _version_lt(actual_tuple, required_tuple)

    # Handle caret ^ constraint (compatible updates)
    if required.startswith("^"):
        required_tuple = parse_version(required[1:])
        if not required_tuple:
            return False
        # ^1.2.3 means >=1.2.3 <2.0.0
        # ^0.2.3 means >=0.2.3 <0.3.0
        # ^0.0.3 means >=0.0.3 <0.0.4
        min_version = required_tuple
        if required_tuple[0] > 0:
            max_version = (required_tuple[0] + 1,)
        elif len(required_tuple) >= 2 and required_tuple[1] > 0:
            max_version = (required_tuple[0], required_tuple[1] + 1)
        elif len(required_tuple) >= 3:
            max_version = (required_tuple[0], required_tuple[1], required_tuple[2] + 1)
        else:
            max_version = (required_tuple[0] + 1,)
        return _version_gte(actual_tuple, min_version) and _version_lt(actual_tuple, max_version)

    # Handle tilde ~ constraint (patch updates)
    if required.startswith("~"):
        required_tuple = parse_version(required[1:])
        if not required_tuple:
            return False
        # ~1.2.3 means >=1.2.3 <1.3.0
        # ~1.2 means >=1.2 <1.3
        min_version = required_tuple
        if len(required_tuple) >= 2:
            max_version = (required_tuple[0], required_tuple[1] + 1)
        else:
            max_version = (required_tuple[0] + 1,)
        return _version_gte(actual_tuple, min_version) and _version_lt(actual_tuple, max_version)

    # Handle range constraint (e.g., "11-17")
    if "-" in required:
        parts = required.split("-")
        if len(parts) == 2:
            min_tuple = parse_version(parts[0])
            max_tuple = parse_version(parts[1])
            if min_tuple and max_tuple:
                return _version_gte(actual_tuple, min_tuple) and _version_lte(actual_tuple, max_tuple)

    # Exact match
    required_tuple = parse_version(required)
    if not required_tuple:
        return False

    # Match major version if only major specified
    if len(required_tuple) == 1:
        return actual_tuple[0] == required_tuple[0]

    # Match major.minor if only major.minor specified
    if len(required_tuple) == 2 and len(actual_tuple) >= 2:
        return actual_tuple[0] == required_tuple[0] and actual_tuple[1] == required_tuple[1]

    return actual_tuple == required_tuple


def _version_gt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    """Compare version tuples: a > b"""
    # Pad shorter tuple with zeros
    max_len = max(len(a), len(b))
    a_padded = a + (0,) * (max_len - len(a))
    b_padded = b + (0,) * (max_len - len(b))
    return a_padded > b_padded


def _version_gte(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    """Compare version tuples: a >= b"""
    max_len = max(len(a), len(b))
    a_padded = a + (0,) * (max_len - len(a))
    b_padded = b + (0,) * (max_len - len(b))
    return a_padded >= b_padded


def _version_lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    """Compare version tuples: a < b"""
    max_len = max(len(a), len(b))
    a_padded = a + (0,) * (max_len - len(a))
    b_padded = b + (0,) * (max_len - len(b))
    return a_padded < b_padded


def _version_lte(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    """Compare version tuples: a <= b"""
    max_len = max(len(a), len(b))
    a_padded = a + (0,) * (max_len - len(a))
    b_padded = b + (0,) * (max_len - len(b))
    return a_padded <= b_padded


# =============================================================================
# Tool Resolver
# =============================================================================


class ToolResolver:
    """Discover tools from multiple sources.

    Search order (configurable):
    1. Managed paths (pre-installed directories)
    2. Local cache (user-managed tool cache)
    3. System PATH
    """

    def __init__(
        self,
        managed_paths: list[Path] | None = None,
        cache_dir: Path | None = None,
        env: dict[str, str] | None = None,
    ):
        """Initialize the tool resolver.

        Args:
            managed_paths: List of paths to search for managed tools.
            cache_dir: Directory for cached tools.
            env: Environment variables for tool discovery.
        """
        self.managed_paths = managed_paths or DEFAULT_MANAGED_PATHS.copy()
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.env = env or dict(os.environ)

    def resolve(self, tool_type: ToolType) -> ToolInfo | None:
        """Resolve a tool from all available sources.

        Args:
            tool_type: Type of tool to resolve.

        Returns:
            ToolInfo if found, None otherwise.
        """
        config = TOOL_CONFIGS.get(tool_type)
        if not config:
            logger.warning(f"No configuration for tool type: {tool_type}")
            return None

        # Try managed paths first
        tool = self._resolve_from_managed(config)
        if tool:
            return tool

        # Try local cache
        tool = self._resolve_from_cache(config)
        if tool:
            return tool

        # Try system PATH
        tool = self._resolve_from_path(config)
        if tool:
            return tool

        return None

    def resolve_all(self, tool_types: list[ToolType]) -> dict[ToolType, ToolInfo | None]:
        """Resolve multiple tools.

        Args:
            tool_types: List of tool types to resolve.

        Returns:
            Dictionary mapping tool type to ToolInfo (or None if not found).
        """
        results = {}
        for tool_type in tool_types:
            results[tool_type] = self.resolve(tool_type)
        return results

    def _resolve_from_managed(self, config: ToolConfig) -> ToolInfo | None:
        """Resolve tool from managed paths."""
        for managed_path in self.managed_paths:
            if not managed_path.exists():
                continue

            for exec_name in config.executable_names:
                tool_path = managed_path / exec_name
                if tool_path.exists() and os.access(tool_path, os.X_OK):
                    version = self._get_version(tool_path, config)
                    return ToolInfo(
                        tool_type=config.tool_type,
                        path=tool_path,
                        version=version,
                        source=ToolSource.MANAGED_PATH,
                    )

                # Try in tool-specific subdirectory
                tool_dir = managed_path / config.tool_type.value
                tool_path = tool_dir / exec_name
                if tool_path.exists() and os.access(tool_path, os.X_OK):
                    version = self._get_version(tool_path, config)
                    return ToolInfo(
                        tool_type=config.tool_type,
                        path=tool_path,
                        version=version,
                        source=ToolSource.MANAGED_PATH,
                    )

        return None

    def _resolve_from_cache(self, config: ToolConfig) -> ToolInfo | None:
        """Resolve tool from local cache."""
        if not self.cache_dir.exists():
            return None

        # Look in tool-specific cache directory
        tool_cache = self.cache_dir / config.tool_type.value
        if not tool_cache.exists():
            return None

        for exec_name in config.executable_names:
            tool_path = tool_cache / exec_name
            if tool_path.exists() and os.access(tool_path, os.X_OK):
                version = self._get_version(tool_path, config)
                return ToolInfo(
                    tool_type=config.tool_type,
                    path=tool_path,
                    version=version,
                    source=ToolSource.LOCAL_CACHE,
                )

        return None

    def _resolve_from_path(self, config: ToolConfig) -> ToolInfo | None:
        """Resolve tool from system PATH."""
        for exec_name in config.executable_names:
            tool_path = shutil.which(exec_name, path=self.env.get("PATH"))
            if tool_path:
                tool_path = Path(tool_path)
                version = self._get_version(tool_path, config)
                return ToolInfo(
                    tool_type=config.tool_type,
                    path=tool_path,
                    version=version,
                    source=ToolSource.SYSTEM_PATH,
                )

        return None

    def _get_version(self, tool_path: Path, config: ToolConfig) -> str | None:
        """Get version of a tool by running its version command.

        Args:
            tool_path: Path to the tool executable.
            config: Tool configuration.

        Returns:
            Version string or None if extraction fails.
        """
        try:
            # Run version command synchronously (simple and fast)
            import subprocess

            result = subprocess.run(
                [str(tool_path)] + config.version_command[1:],
                capture_output=True,
                text=True,
                timeout=5,
            )

            # Check appropriate output stream
            output = result.stderr if config.stderr_version else result.stdout

            # Try to extract version
            match = re.search(config.version_regex, output)
            if match:
                return match.group(1)

            return None

        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug(f"Failed to get version for {tool_path}: {e}")
            return None


# =============================================================================
# Compatibility Checker
# =============================================================================


class CompatibilityChecker:
    """Check tool compatibility with project requirements."""

    def __init__(self, resolver: ToolResolver | None = None):
        """Initialize the compatibility checker.

        Args:
            resolver: ToolResolver instance for discovering tools.
        """
        self.resolver = resolver or ToolResolver()

    def check(
        self,
        tool_type: ToolType,
        required_version: str | None = None,
    ) -> CompatibilityResult:
        """Check if a tool meets requirements.

        Args:
            tool_type: Type of tool to check.
            required_version: Required version constraint.

        Returns:
            CompatibilityResult with status and details.
        """
        tool = self.resolver.resolve(tool_type)

        # Tool not found
        if not tool:
            return CompatibilityResult(
                tool_type=tool_type,
                status=CompatibilityStatus.NOT_FOUND,
                required_version=required_version,
                message=f"Tool {tool_type.value} not found in any source",
            )

        # No version requirement
        if not required_version:
            return CompatibilityResult(
                tool_type=tool_type,
                status=CompatibilityStatus.OK,
                tool=tool,
                actual_version=tool.version,
                message=f"Tool {tool_type.value} found",
            )

        # Check version compatibility
        if not tool.version:
            return CompatibilityResult(
                tool_type=tool_type,
                status=CompatibilityStatus.VERSION_MISMATCH,
                tool=tool,
                required_version=required_version,
                actual_version=None,
                message=f"Tool {tool_type.value} found but version could not be determined",
            )

        if not version_matches(tool.version, required_version):
            return CompatibilityResult(
                tool_type=tool_type,
                status=CompatibilityStatus.VERSION_MISMATCH,
                tool=tool,
                required_version=required_version,
                actual_version=tool.version,
                message=f"Tool {tool_type.value} version {tool.version} does not meet requirement {required_version}",
            )

        return CompatibilityResult(
            tool_type=tool_type,
            status=CompatibilityStatus.OK,
            tool=tool,
            required_version=required_version,
            actual_version=tool.version,
            message=f"Tool {tool_type.value} {tool.version} meets requirement {required_version}",
        )

    def check_all(
        self,
        requirements: dict[ToolType, str | None],
    ) -> list[CompatibilityResult]:
        """Check multiple tools against requirements.

        Args:
            requirements: Dictionary mapping tool type to required version.

        Returns:
            List of CompatibilityResults.
        """
        results = []
        for tool_type, required_version in requirements.items():
            result = self.check(tool_type, required_version)
            results.append(result)
        return results


# =============================================================================
# Readiness Reporter
# =============================================================================


def generate_readiness_report(
    requirements: dict[ToolType, str | None],
    policy: ProvisionPolicy = ProvisionPolicy.REUSE_ONLY,
    resolver: ToolResolver | None = None,
) -> ReadinessReport:
    """Generate a readiness report for required tools.

    Args:
        requirements: Dictionary mapping tool type to required version.
        policy: Provision policy for handling issues.
        resolver: ToolResolver instance for discovering tools.

    Returns:
        ReadinessReport with ready/incompatible/missing tools.
    """
    resolver = resolver or ToolResolver()
    checker = CompatibilityChecker(resolver)

    ready_tools: list[ToolInfo] = []
    incompatible_tools: list[CompatibilityResult] = []
    missing_tools: list[ToolType] = []

    for tool_type, required_version in requirements.items():
        result = checker.check(tool_type, required_version)

        if result.status == CompatibilityStatus.OK:
            if result.tool:
                ready_tools.append(result.tool)
        elif result.status == CompatibilityStatus.NOT_FOUND:
            missing_tools.append(tool_type)
            incompatible_tools.append(result)
        else:
            incompatible_tools.append(result)

    return ReadinessReport(
        ready_tools=ready_tools,
        incompatible_tools=incompatible_tools,
        missing_tools=missing_tools,
        policy=policy,
    )


# =============================================================================
# Convenience Functions
# =============================================================================


def resolve_tool(tool_type: ToolType, **kwargs) -> ToolInfo | None:
    """Convenience function to resolve a single tool.

    Args:
        tool_type: Type of tool to resolve.
        **kwargs: Additional arguments for ToolResolver.

    Returns:
        ToolInfo if found, None otherwise.
    """
    resolver = ToolResolver(**kwargs)
    return resolver.resolve(tool_type)


def check_tool_compatibility(
    tool_type: ToolType,
    required_version: str | None = None,
    **kwargs,
) -> CompatibilityResult:
    """Convenience function to check tool compatibility.

    Args:
        tool_type: Type of tool to check.
        required_version: Required version constraint.
        **kwargs: Additional arguments for ToolResolver.

    Returns:
        CompatibilityResult with status and details.
    """
    resolver = ToolResolver(**kwargs)
    checker = CompatibilityChecker(resolver)
    return checker.check(tool_type, required_version)
