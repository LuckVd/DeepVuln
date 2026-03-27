"""
Build Plan - Generation and execution orchestration for CodeQL builds.

This module provides:
- BuildPlan: A complete build plan with steps, risk, and fallback
- BuildPlanGenerator: Generates plans from BuildTargets
- BuildOrchestrator: Coordinates execution of multiple plans
- BuildSummary: Standardized output for reporting
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.build.detector import BuildSystem
from src.layers.l3_analysis.build.target_extractor import BuildStrategy, BuildTarget
from src.layers.l3_analysis.build.tool_resolver import (
    CompatibilityStatus,
    ProvisionPolicy,
    ReadinessReport,
    ToolType,
)

# Import builders - using lazy import to avoid circular dependencies
BUILDER_REGISTRY: Any = None


def _get_builder_registry() -> Any:
    """Lazy load builder registry to avoid circular imports."""
    global BUILDER_REGISTRY
    if BUILDER_REGISTRY is None:
        from src.layers.l3_analysis.build.builders import BuilderRegistry
        BUILDER_REGISTRY = BuilderRegistry
    return BUILDER_REGISTRY

logger = get_logger(__name__)


# =============================================================================
# Enums
# =============================================================================


class RiskLevel(str, Enum):
    """Risk level of a build operation."""

    LOW = "low"  # Standard build, known to work
    MEDIUM = "medium"  # May have issues, fallback available
    HIGH = "high"  # Likely to fail, last resort


class FallbackStrategy(str, Enum):
    """Fallback strategy when build fails."""

    NONE = "none"  # No fallback
    SKIP = "skip"  # Skip and continue
    TRY_NEXT = "try_next"  # Try next plan in queue
    DIAGNOSE = "diagnose"  # Run diagnosis and retry


class BuildPlanStatus(str, Enum):
    """Status of a build plan."""

    PENDING = "pending"
    SELECTED = "selected"
    SKIPPED = "skipped"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class BuildStep:
    """A single step in a build plan."""

    name: str
    command: str
    timeout: int = 300
    cwd: Path | None = None
    env: dict[str, str] = field(default_factory=dict)
    required: bool = True  # If false, continue on failure

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "command": self.command,
            "timeout": self.timeout,
            "cwd": str(self.cwd) if self.cwd else None,
            "env": self.env,
            "required": self.required,
        }


@dataclass
class BuildPlan:
    """A complete build plan for a target."""

    target_name: str
    steps: list[BuildStep] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    fallback: FallbackStrategy = FallbackStrategy.SKIP
    skip_reason: str | None = None  # If plan is skipped
    estimated_duration: int = 60
    language: str = ""
    build_system: BuildSystem | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "target_name": self.target_name,
            "steps": [s.to_dict() for s in self.steps],
            "risk_level": self.risk_level.value,
            "fallback": self.fallback.value,
            "skip_reason": self.skip_reason,
            "estimated_duration": self.estimated_duration,
            "language": self.language,
            "build_system": self.build_system.value if self.build_system else None,
        }

    @property
    def is_skipped(self) -> bool:
        """Check if this plan is skipped."""
        return self.skip_reason is not None

    @property
    def has_steps(self) -> bool:
        """Check if plan has executable steps."""
        return len(self.steps) > 0


@dataclass
class BuildExecutionResult:
    """Result of executing a build plan."""

    plan: BuildPlan
    success: bool = False
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    selected_reason: str | None = None
    skipped_reason: str | None = None
    failed_reason: str | None = None
    from_cache: bool = False
    cache_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "plan": self.plan.to_dict(),
            "success": self.success,
            "duration_seconds": self.duration_seconds,
            "selected_reason": self.selected_reason,
            "skipped_reason": self.skipped_reason,
            "failed_reason": self.failed_reason,
            "from_cache": self.from_cache,
        }


@dataclass
class BuildSummary:
    """Standardized build summary for reporting."""

    selected_plans: list[str] = field(default_factory=list)
    skipped_plans: list[tuple[str, str]] = field(default_factory=list)  # (name, reason)
    failed_plans: list[tuple[str, str]] = field(default_factory=list)  # (name, reason)
    successful_plans: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "selected": [{"plan": p} for p in self.selected_plans],
            "skipped": [{"plan": n, "reason": r} for n, r in self.skipped_plans],
            "failed": [{"plan": n, "reason": r} for n, r in self.failed_plans],
            "successful": [{"plan": p} for p in self.successful_plans],
        }

    def add_selected(self, plan_name: str):
        """Add a selected plan."""
        self.selected_plans.append(plan_name)

    def add_skipped(self, plan_name: str, reason: str):
        """Add a skipped plan with reason."""
        self.skipped_plans.append((plan_name, reason))

    def add_failed(self, plan_name: str, reason: str):
        """Add a failed plan with reason."""
        self.failed_plans.append((plan_name, reason))

    def add_successful(self, plan_name: str):
        """Add a successful plan."""
        self.successful_plans.append(plan_name)


# =============================================================================
# Build Plan Generator
# =============================================================================


# Default timeouts for different build systems (in seconds)
DEFAULT_TIMEOUTS: dict[BuildSystem, int] = {
    BuildSystem.MAVEN: 600,
    BuildSystem.GRADLE: 600,
    BuildSystem.GRADLEW: 600,
    BuildSystem.GO_MODULES: 300,
    BuildSystem.GO_WORK: 300,
    BuildSystem.NPM: 300,
    BuildSystem.YARN: 300,
    BuildSystem.PNPM: 300,
    BuildSystem.PIP: 300,
    BuildSystem.POETRY: 300,
    BuildSystem.NONE: 0,
    BuildSystem.UNKNOWN: 60,
    BuildSystem.MAKEFILE: 600,
    BuildSystem.GO_MAKEFILE: 600,
    BuildSystem.SETUP_PY: 300,
}

# Required tools for each build system
BUILD_SYSTEM_TOOLS: dict[BuildSystem, list[ToolType]] = {
    BuildSystem.MAVEN: [ToolType.JAVA, ToolType.MAVEN],
    BuildSystem.GRADLE: [ToolType.JAVA, ToolType.GRADLE],
    BuildSystem.GRADLEW: [ToolType.JAVA],  # Gradle wrapper is self-contained
    BuildSystem.GO_MODULES: [ToolType.GO],
    BuildSystem.GO_WORK: [ToolType.GO],
    BuildSystem.NPM: [ToolType.NODE, ToolType.NPM],
    BuildSystem.YARN: [ToolType.NODE, ToolType.YARN],
    BuildSystem.PNPM: [ToolType.NODE, ToolType.PNPM],
    BuildSystem.PIP: [ToolType.PYTHON],
    BuildSystem.POETRY: [ToolType.PYTHON],
    BuildSystem.SETUP_PY: [ToolType.PYTHON],
    BuildSystem.MAKEFILE: [],
    BuildSystem.GO_MAKEFILE: [ToolType.GO],
    BuildSystem.NONE: [],
    BuildSystem.UNKNOWN: [],
}


class BuildPlanGenerator:
    """Generates build plans from build targets.

    Takes BuildTarget objects from BuildTargetExtractor and generates
    executable BuildPlan objects with appropriate steps, timeouts,
    risk levels, and fallback strategies.

    For Go and Java projects, uses the specialized builders from
    the builders package for more intelligent build strategies.
    """

    # Languages that have specialized builders
    BUILDER_LANGUAGES = {"go", "java", "python", "javascript", "cpp"}

    def __init__(
        self,
        default_timeout: int = 600,
        max_timeout: int = 1800,
    ):
        """Initialize the build plan generator.

        Args:
            default_timeout: Default timeout for build commands.
            max_timeout: Maximum allowed timeout.
        """
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout

    def generate(
        self,
        target: BuildTarget,
        readiness: ReadinessReport | None = None,
    ) -> BuildPlan:
        """Generate a build plan from a target.

        Args:
            target: Build target from BuildTargetExtractor.
            readiness: Tool readiness report from ToolResolver.

        Returns:
            BuildPlan ready for execution or skipping.
        """
        # Try using specialized builder first for Go/Java
        if target.language.lower() in self.BUILDER_LANGUAGES:
            builder_plan = self._generate_from_builder(target, readiness)
            if builder_plan:
                return builder_plan

        # Fall back to generic build plan generation
        # Check if target should be skipped
        if target.build_system == BuildSystem.NONE:
            return BuildPlan(
                target_name=target.name,
                skip_reason="No build system detected",
                language=target.language,
                build_system=target.build_system,
            )

        if target.build_system == BuildSystem.UNKNOWN:
            return BuildPlan(
                target_name=target.name,
                skip_reason="Unknown build system",
                language=target.language,
                build_system=target.build_system,
            )

        # Check tool readiness if provided
        if readiness:
            missing_tools = self._check_missing_tools(target.build_system, readiness)
            if missing_tools and readiness.policy == ProvisionPolicy.STRICT:
                return BuildPlan(
                    target_name=target.name,
                    skip_reason=f"Required tools not available: {missing_tools}",
                    language=target.language,
                    build_system=target.build_system,
                )

        # Generate build steps
        steps = self._generate_steps(target)

        # Determine risk level and fallback
        risk = self._assess_risk(target, readiness)
        fallback = self._determine_fallback(target)

        # Get timeout
        timeout = self._get_timeout(target)

        return BuildPlan(
            target_name=target.name,
            steps=steps,
            risk_level=risk,
            fallback=fallback,
            estimated_duration=timeout,
            language=target.language,
            build_system=target.build_system,
        )

    def generate_all(
        self,
        targets: list[BuildTarget],
        readiness: ReadinessReport | None = None,
    ) -> list[BuildPlan]:
        """Generate plans for multiple targets.

        Args:
            targets: List of build targets.
            readiness: Tool readiness report.

        Returns:
            List of build plans.
        """
        return [self.generate(t, readiness) for t in targets]

    def _generate_from_builder(
        self,
        target: BuildTarget,
        readiness: ReadinessReport | None = None,
    ) -> BuildPlan | None:
        """Generate build plan using specialized language builder.

        Args:
            target: Build target.
            readiness: Tool readiness report.

        Returns:
            BuildPlan from specialized builder, or None if should fall back to generic.
        """
        try:
            registry = _get_builder_registry()
            builder = registry.get(target.language)
            if not builder:
                return None

            output = builder.analyze(target.path)

            # If builder skipped due to missing build files but target has
            # a known build system, fall back to generic generation
            if output.is_skipped:
                # Fall back if target has valid build system
                if target.build_system not in (
                    BuildSystem.NONE,
                    BuildSystem.UNKNOWN,
                ):
                    return None  # Fall back to generic generation
                # Otherwise return the skip plan
                return BuildPlan(
                    target_name=target.name,
                    skip_reason=output.skip_reason,
                    language=output.language,
                    build_system=target.build_system,
                )

            # Generate steps from builder output
            steps: list[BuildStep] = []

            if output.dependency_command:
                steps.append(
                    BuildStep(
                        name=f"Install dependencies for {target.name}",
                        command=output.dependency_command,
                        timeout=output.timeout // 2,
                        cwd=output.cwd or target.path,
                        env=output.env_vars,
                        required=False,
                    )
                )

            if output.build_command:
                steps.append(
                    BuildStep(
                        name=f"Build {target.name}",
                        command=output.build_command,
                        timeout=output.timeout,
                        cwd=output.cwd or target.path,
                        env=output.env_vars,
                        required=True,
                    )
                )

            # Determine risk based on warnings
            risk = RiskLevel.MEDIUM if output.warnings else RiskLevel.LOW

            return BuildPlan(
                target_name=target.name,
                steps=steps,
                risk_level=risk,
                fallback=FallbackStrategy.SKIP,
                estimated_duration=output.timeout,
                language=output.language,
                build_system=target.build_system,
            )

        except Exception as e:
            logger.warning(f"Builder failed for {target.language}: {e}")
            return None

    def _generate_steps(self, target: BuildTarget) -> list[BuildStep]:
        """Generate build steps for a target."""
        steps = []
        timeout = self._get_timeout(target)

        # Add dependency installation step if needed
        dep_command = self._get_dependency_command(target)
        if dep_command:
            steps.append(
                BuildStep(
                    name=f"Install dependencies for {target.name}",
                    command=dep_command,
                    timeout=timeout // 2,  # Half time for deps
                    cwd=target.path,
                    required=False,  # Continue even if deps fail
                )
            )

        # Add build step
        build_command = target.build_command or self._get_build_command(target)
        if build_command:
            steps.append(
                BuildStep(
                    name=f"Build {target.name}",
                    command=build_command,
                    timeout=timeout,
                    cwd=target.path,
                    required=True,
                )
            )

        return steps

    def _get_dependency_command(self, target: BuildTarget) -> str | None:
        """Get dependency installation command for a target."""
        commands = {
            BuildSystem.MAVEN: "mvn dependency:resolve -q",
            BuildSystem.GRADLE: "gradle dependencies --quiet",
            BuildSystem.GRADLEW: "./gradlew dependencies --quiet",
            BuildSystem.GO_MODULES: "go mod download",
            BuildSystem.GO_WORK: "go work sync",
            BuildSystem.NPM: "npm install",
            BuildSystem.YARN: "yarn install",
            BuildSystem.PNPM: "pnpm install",
            BuildSystem.PIP: "pip install -r requirements.txt",
            BuildSystem.POETRY: "poetry install",
        }
        return commands.get(target.build_system)

    def _get_build_command(self, target: BuildTarget) -> str | None:
        """Get build command for a target."""
        commands = {
            BuildSystem.MAVEN: "mvn compile -q -DskipTests",
            BuildSystem.GRADLE: "gradle classes --quiet",
            BuildSystem.GRADLEW: "./gradlew classes --quiet",
            BuildSystem.GO_MODULES: "go build ./...",
            BuildSystem.GO_WORK: "go build ./...",
            BuildSystem.MAKEFILE: "make",
            BuildSystem.GO_MAKEFILE: "make",
        }
        return commands.get(target.build_system)

    def _get_timeout(self, target: BuildTarget) -> int:
        """Get timeout for a target."""
        timeout = DEFAULT_TIMEOUTS.get(target.build_system, self.default_timeout)
        if target.estimated_time_seconds > 0:
            timeout = max(timeout, target.estimated_time_seconds)
        return min(timeout, self.max_timeout)

    def _check_missing_tools(
        self,
        build_system: BuildSystem,
        readiness: ReadinessReport,
    ) -> list[str]:
        """Check for missing required tools."""
        required = BUILD_SYSTEM_TOOLS.get(build_system, [])
        missing = []

        for tool_type in required:
            # Check if tool is in missing list
            if tool_type in readiness.missing_tools:
                missing.append(tool_type.value)
            # Check if tool is incompatible
            for result in readiness.incompatible_tools:
                if result.tool_type == tool_type and result.status != CompatibilityStatus.OK:
                    missing.append(tool_type.value)

        return missing

    def _assess_risk(
        self,
        target: BuildTarget,
        readiness: ReadinessReport | None,
    ) -> RiskLevel:
        """Assess risk level for a build."""
        # High risk conditions
        if target.build_system in (BuildSystem.UNKNOWN, BuildSystem.NONE):
            return RiskLevel.HIGH

        # Check tool availability
        if readiness:
            missing = self._check_missing_tools(target.build_system, readiness)
            if missing:
                if readiness.policy == ProvisionPolicy.STRICT:
                    return RiskLevel.HIGH
                return RiskLevel.MEDIUM

        # Medium risk for compiled languages
        if target.build_system in (BuildSystem.MAVEN, BuildSystem.GRADLE, BuildSystem.GRADLEW):
            return RiskLevel.MEDIUM

        # Low risk for simple builds
        return RiskLevel.LOW

    def _determine_fallback(self, target: BuildTarget) -> FallbackStrategy:
        """Determine fallback strategy for a build."""
        # No fallback for critical builds
        if target.is_entry_point:
            return FallbackStrategy.DIAGNOSE

        # Skip for low priority targets
        if target.priority > 50:
            return FallbackStrategy.SKIP

        # Try next for medium priority
        return FallbackStrategy.TRY_NEXT


# =============================================================================
# Build Cache
# =============================================================================


@dataclass
class CacheEntry:
    """Cached build result."""

    key: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)
    ttl_seconds: int = 86400  # 24 hours default

    @property
    def expired(self) -> bool:
        """Check if entry has expired."""
        return datetime.now() > self.created_at + timedelta(seconds=self.ttl_seconds)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "key": self.key,
            "success": self.success,
            "duration_seconds": self.duration_seconds,
            "created_at": self.created_at.isoformat(),
            "ttl_seconds": self.ttl_seconds,
        }


# Default cache directory
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "deepvuln" / "builds"


class BuildCache:
    """Cache for build results.

    Provides in-memory caching with optional disk persistence.
    Used to avoid redundant builds when source and commands haven't changed.
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        max_entries: int = 1000,
        default_ttl: int = 86400,  # 24 hours
    ):
        """Initialize the build cache.

        Args:
            cache_dir: Directory for cache storage.
            max_entries: Maximum number of entries in memory.
            default_ttl: Default TTL in seconds.
        """
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self._cache: dict[str, CacheEntry] = {}

    def get(self, key: str) -> CacheEntry | None:
        """Get cached result if not expired.

        Args:
            key: Cache key.

        Returns:
            CacheEntry if found and not expired, None otherwise.
        """
        entry = self._cache.get(key)
        if entry and not entry.expired:
            logger.debug(f"Cache hit for key: {key}")
            return entry

        # Remove expired entry
        if entry:
            del self._cache[key]
            logger.debug(f"Removed expired cache entry: {key}")

        return None

    def set(
        self,
        key: str,
        success: bool,
        stdout: str = "",
        stderr: str = "",
        duration_seconds: float = 0.0,
        ttl: int | None = None,
    ):
        """Cache a build result.

        Args:
            key: Cache key.
            success: Whether build succeeded.
            stdout: Standard output.
            stderr: Standard error.
            duration_seconds: Build duration.
            ttl: TTL in seconds (uses default if not specified).
        """
        # Evict old entries if at capacity
        if len(self._cache) >= self.max_entries:
            self._evict_oldest()

        self._cache[key] = CacheEntry(
            key=key,
            success=success,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration_seconds,
            ttl_seconds=ttl or self.default_ttl,
        )
        logger.debug(f"Cached result for key: {key}")

    def make_key(self, source_path: Path, command: str) -> str:
        """Generate cache key from path and command.

        Args:
            source_path: Source directory path.
            command: Build command.

        Returns:
            Cache key string.
        """
        content = f"{source_path.absolute()}:{command}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def clear(self):
        """Clear all cached entries."""
        self._cache.clear()
        logger.info("Build cache cleared")

    def _evict_oldest(self):
        """Evict oldest entries to make room."""
        # Remove 10% of oldest entries
        to_remove = max(1, self.max_entries // 10)
        sorted_keys = sorted(
            self._cache.keys(),
            key=lambda k: self._cache[k].created_at,
        )
        for key in sorted_keys[:to_remove]:
            del self._cache[key]

    @property
    def size(self) -> int:
        """Get number of cached entries."""
        return len(self._cache)


# =============================================================================
# Build Orchestrator
# =============================================================================


class BuildOrchestrator:
    """Orchestrates execution of multiple build plans.

    Coordinates plan generation, caching, and execution to provide
    a unified build workflow with proper error handling and reporting.
    """

    def __init__(
        self,
        cache: BuildCache | None = None,
        timeout: int = 600,
    ):
        """Initialize the build orchestrator.

        Args:
            cache: BuildCache instance for result caching.
            timeout: Default timeout for build commands.
        """
        self.cache = cache or BuildCache()
        self.timeout = timeout

    async def execute_plan(
        self,
        plan: BuildPlan,
        use_cache: bool = True,
    ) -> BuildExecutionResult:
        """Execute a single build plan.

        Args:
            plan: BuildPlan to execute.
            use_cache: Whether to use cached results.

        Returns:
            BuildExecutionResult with execution details.
        """
        # Handle skipped plans
        if plan.is_skipped:
            return BuildExecutionResult(
                plan=plan,
                success=True,
                skipped_reason=plan.skip_reason,
            )

        if not plan.has_steps:
            return BuildExecutionResult(
                plan=plan,
                success=True,
                skipped_reason="No build steps to execute",
            )

        # Check cache
        if use_cache:
            first_step = plan.steps[0]
            cache_key = self.cache.make_key(
                first_step.cwd or Path.cwd(),
                first_step.command,
            )
            cached = self.cache.get(cache_key)
            if cached:
                return BuildExecutionResult(
                    plan=plan,
                    success=cached.success,
                    stdout=cached.stdout,
                    stderr=cached.stderr,
                    duration_seconds=cached.duration_seconds,
                    from_cache=True,
                    cache_key=cache_key,
                    selected_reason="Restored from cache",
                )
        else:
            cache_key = None

        # Execute steps
        import subprocess

        start_time = time.time()
        all_stdout = []
        all_stderr = []
        success = True
        failed_reason = None

        for step in plan.steps:
            logger.info(f"Executing build step: {step.name}")

            try:
                result = subprocess.run(
                    step.command,
                    shell=True,
                    cwd=step.cwd,
                    env={**os.environ, **step.env},
                    capture_output=True,
                    text=True,
                    timeout=step.timeout,
                )

                all_stdout.append(result.stdout)
                all_stderr.append(result.stderr)

                if result.returncode != 0:
                    if step.required:
                        success = False
                        failed_reason = f"Step '{step.name}' failed with code {result.returncode}"
                        logger.warning(f"Build step failed: {step.name}")
                        break
                    else:
                        logger.warning(
                            f"Non-required step failed: {step.name}, continuing..."
                        )

            except subprocess.TimeoutExpired:
                if step.required:
                    success = False
                    failed_reason = f"Step '{step.name}' timed out after {step.timeout}s"
                    logger.error(f"Build step timed out: {step.name}")
                    break
                else:
                    logger.warning(
                        f"Non-required step timed out: {step.name}, continuing..."
                    )

            except Exception as e:
                if step.required:
                    success = False
                    failed_reason = f"Step '{step.name}' error: {str(e)}"
                    logger.error(f"Build step error: {step.name} - {e}")
                    break

        duration = time.time() - start_time
        stdout = "\n".join(all_stdout)
        stderr = "\n".join(all_stderr)

        # Cache result
        if use_cache and cache_key:
            self.cache.set(
                cache_key,
                success=success,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
            )

        return BuildExecutionResult(
            plan=plan,
            success=success,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            failed_reason=failed_reason,
            cache_key=cache_key,
            selected_reason="Executed build plan",
        )

    async def execute_plans(
        self,
        plans: list[BuildPlan],
        use_cache: bool = True,
    ) -> tuple[list[BuildExecutionResult], BuildSummary]:
        """Execute multiple build plans.

        Args:
            plans: List of build plans to execute.
            use_cache: Whether to use cached results.

        Returns:
            Tuple of (results, summary).
        """
        results = []
        summary = BuildSummary()

        for plan in plans:
            result = await self.execute_plan(plan, use_cache)
            results.append(result)

            # Update summary
            plan_name = plan.target_name

            if result.skipped_reason:
                summary.add_skipped(plan_name, result.skipped_reason)
            elif result.success:
                summary.add_successful(plan_name)
            elif result.failed_reason:
                summary.add_failed(plan_name, result.failed_reason)

            summary.add_selected(plan_name)

        return results, summary


# =============================================================================
# Convenience Functions
# =============================================================================


def generate_build_plan(
    target: BuildTarget,
    readiness: ReadinessReport | None = None,
) -> BuildPlan:
    """Convenience function to generate a build plan.

    Args:
        target: Build target.
        readiness: Tool readiness report.

    Returns:
        BuildPlan ready for execution.
    """
    generator = BuildPlanGenerator()
    return generator.generate(target, readiness)


def create_build_cache(
    cache_dir: Path | None = None,
    max_entries: int = 1000,
) -> BuildCache:
    """Convenience function to create a build cache.

    Args:
        cache_dir: Directory for cache storage.
        max_entries: Maximum number of entries.

    Returns:
        BuildCache instance.
    """
    return BuildCache(cache_dir=cache_dir, max_entries=max_entries)
