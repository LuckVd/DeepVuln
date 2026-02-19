"""
Audit Strategy Models

Data models for audit priority, targets, and strategy configuration.
"""

from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class AuditPriorityLevel(str, Enum):
    """Priority levels for audit targets."""

    CRITICAL = "critical"  # Must audit immediately with all engines
    HIGH = "high"  # Priority audit with Agent + Semgrep
    MEDIUM = "medium"  # Regular audit with Semgrep + CodeQL
    LOW = "low"  # Quick scan with Semgrep only
    SKIP = "skip"  # Skip auditing (e.g., test files, generated code)


class AuditPriority(BaseModel):
    """
    Priority classification for an audit target.

    Combines multiple factors to determine the audit priority level.
    """

    # Priority level
    level: AuditPriorityLevel = Field(
        ...,
        description="Priority level for this target",
    )

    # Score components (0.0 - 1.0)
    attack_surface_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Attack surface exposure score",
    )
    tech_risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Technology stack risk score",
    )
    complexity_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Code complexity score",
    )
    history_risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Historical vulnerability risk score",
    )

    # Final calculated score
    final_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Weighted final priority score",
    )

    # Reasoning
    factors: list[str] = Field(
        default_factory=list,
        description="Factors that influenced the priority",
    )

    @field_validator("final_score")
    @classmethod
    def validate_final_score(cls, v: float) -> float:
        """Ensure final score is in valid range."""
        return max(0.0, min(1.0, v))

    def to_level(self, score: float | None = None) -> AuditPriorityLevel:
        """
        Convert a score to a priority level.

        Args:
            score: Score to convert (uses final_score if not provided).

        Returns:
            Corresponding priority level.
        """
        s = score if score is not None else self.final_score

        if s >= 0.8:
            return AuditPriorityLevel.CRITICAL
        elif s >= 0.6:
            return AuditPriorityLevel.HIGH
        elif s >= 0.4:
            return AuditPriorityLevel.MEDIUM
        elif s >= 0.2:
            return AuditPriorityLevel.LOW
        else:
            return AuditPriorityLevel.SKIP


class AuditTarget(BaseModel):
    """
    A target for security auditing.

    Represents a code location, file, or entry point to be audited.
    """

    # Identity
    id: str = Field(..., description="Unique target identifier")
    name: str = Field(..., description="Target name (e.g., endpoint path, file name)")

    # Target type
    target_type: Literal["file", "entry_point", "module", "function"] = Field(
        ...,
        description="Type of audit target",
    )

    # Location
    file_path: str = Field(..., description="File path relative to project root")
    line_start: int | None = Field(default=None, ge=1, description="Start line number")
    line_end: int | None = Field(default=None, ge=1, description="End line number")
    function_name: str | None = Field(default=None, description="Function/method name")

    # Entry point info (if applicable)
    entry_point_type: str | None = Field(
        default=None,
        description="Entry point type (http, rpc, mq, etc.)",
    )
    http_method: str | None = Field(default=None, description="HTTP method if applicable")
    endpoint_path: str | None = Field(default=None, description="Endpoint path if applicable")

    # Security context
    auth_required: bool = Field(
        default=False,
        description="Whether authentication is required",
    )
    params: list[str] = Field(
        default_factory=list,
        description="Parameter names",
    )

    # Code metrics
    cyclomatic_complexity: int | None = Field(
        default=None,
        ge=1,
        description="Cyclomatic complexity",
    )
    lines_of_code: int | None = Field(
        default=None,
        ge=0,
        description="Lines of code",
    )

    # Framework/technology
    framework: str | None = Field(default=None, description="Framework name")
    language: str | None = Field(default=None, description="Programming language")

    # Priority (assigned by PriorityCalculator)
    priority: AuditPriority | None = Field(
        default=None,
        description="Assigned audit priority",
    )

    # Metadata
    tags: list[str] = Field(
        default_factory=list,
        description="Tags for categorization",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    @field_validator("line_end")
    @classmethod
    def validate_line_end(cls, v: int | None, info) -> int | None:
        """Ensure line_end >= line_start."""
        if v is not None and "line_start" in info.data and info.data["line_start"] is not None:
            if v < info.data["line_start"]:
                raise ValueError("line_end must be >= line_start")
        return v

    def to_display(self) -> str:
        """Generate display string for this target."""
        if self.target_type == "entry_point" and self.endpoint_path:
            method = f"{self.http_method} " if self.http_method else ""
            return f"{method}{self.endpoint_path}"
        elif self.function_name:
            return f"{self.file_path}:{self.function_name}()"
        else:
            return self.file_path


class PriorityScore(BaseModel):
    """
    Detailed priority score breakdown.

    Provides transparency into how the final priority was calculated.
    """

    # Component scores
    attack_surface: float = Field(default=0.0, ge=0.0, le=1.0)
    tech_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    complexity: float = Field(default=0.0, ge=0.0, le=1.0)
    history_risk: float = Field(default=0.0, ge=0.0, le=1.0)

    # Weights used
    attack_surface_weight: float = Field(default=0.35, ge=0.0, le=1.0)
    tech_risk_weight: float = Field(default=0.25, ge=0.0, le=1.0)
    complexity_weight: float = Field(default=0.20, ge=0.0, le=1.0)
    history_risk_weight: float = Field(default=0.20, ge=0.0, le=1.0)

    # Final weighted score
    final_score: float = Field(default=0.0, ge=0.0, le=1.0)

    # Contributing factors
    factors: list[str] = Field(default_factory=list, description="Factors that increased score")
    deductions: list[str] = Field(default_factory=list, description="Factors that decreased score")

    def calculate_weighted_score(self) -> float:
        """
        Calculate the weighted final score.

        Returns:
            Weighted score (0.0 - 1.0).
        """
        score = (
            self.attack_surface * self.attack_surface_weight +
            self.tech_risk * self.tech_risk_weight +
            self.complexity * self.complexity_weight +
            self.history_risk * self.history_risk_weight
        )
        return min(1.0, max(0.0, score))

    def to_level(self, score: float | None = None) -> "AuditPriorityLevel":
        """
        Convert a score to a priority level.

        Args:
            score: Score to convert (uses final_score if not provided).

        Returns:
            Corresponding priority level.
        """
        s = score if score is not None else self.final_score

        if s >= 0.8:
            return AuditPriorityLevel.CRITICAL
        elif s >= 0.6:
            return AuditPriorityLevel.HIGH
        elif s >= 0.4:
            return AuditPriorityLevel.MEDIUM
        elif s >= 0.2:
            return AuditPriorityLevel.LOW
        else:
            return AuditPriorityLevel.SKIP


class EngineAllocation(BaseModel):
    """
    Engine allocation for a target or group of targets.

    Defines which analysis engines to use and their configurations.
    """

    engine: Literal["semgrep", "codeql", "agent"] = Field(
        ...,
        description="Engine name",
    )

    # Resource allocation
    concurrent: int = Field(
        default=1,
        ge=1,
        description="Number of concurrent tasks for this engine",
    )
    timeout_seconds: int = Field(
        default=300,
        ge=10,
        description="Timeout for this engine's analysis",
    )

    # Engine-specific configuration
    rules: list[str] | None = Field(
        default=None,
        description="Rules to use (Semgrep)",
    )
    queries: list[str] | None = Field(
        default=None,
        description="Queries to run (CodeQL)",
    )
    focus: list[str] | None = Field(
        default=None,
        description="Vulnerability types to focus on (Agent)",
    )

    # Priority within strategy
    priority: int = Field(
        default=1,
        ge=1,
        description="Execution priority (1 = highest)",
    )

    # Optional flags
    enabled: bool = Field(default=True, description="Whether this engine is enabled")
    required: bool = Field(default=False, description="Whether this engine must complete successfully")


class TargetGroup(BaseModel):
    """
    A group of targets with the same priority level.

    Groups targets for efficient batch processing.
    """

    priority_level: AuditPriorityLevel = Field(
        ...,
        description="Priority level for this group",
    )

    targets: list[AuditTarget] = Field(
        default_factory=list,
        description="Targets in this group",
    )

    engine_allocations: list[EngineAllocation] = Field(
        default_factory=list,
        description="Engine allocations for this group",
    )

    # Execution settings
    max_concurrent_files: int = Field(
        default=5,
        ge=1,
        description="Maximum concurrent files to process",
    )
    timeout_seconds: int = Field(
        default=600,
        ge=60,
        description="Total timeout for this group",
    )

    @property
    def target_count(self) -> int:
        """Number of targets in this group."""
        return len(self.targets)

    @property
    def total_lines_of_code(self) -> int:
        """Total lines of code across all targets."""
        return sum(t.lines_of_code or 0 for t in self.targets)


class AuditStrategy(BaseModel):
    """
    Complete audit strategy for a project.

    Defines how to audit all targets based on their priorities.
    """

    # Strategy info
    project_name: str = Field(..., description="Project name")
    source_path: str = Field(..., description="Source path being audited")

    # All targets
    targets: list[AuditTarget] = Field(
        default_factory=list,
        description="All audit targets",
    )

    # Grouped by priority
    groups: dict[str, TargetGroup] = Field(
        default_factory=dict,
        description="Target groups by priority level",
    )

    # Statistics
    total_targets: int = Field(default=0, description="Total number of targets")
    total_lines_of_code: int = Field(default=0, description="Total lines of code")

    # Resource limits
    max_concurrent_engines: int = Field(
        default=3,
        ge=1,
        description="Maximum concurrent engine instances",
    )
    max_total_timeout_seconds: int = Field(
        default=3600,
        ge=300,
        description="Maximum total audit time",
    )

    # Engine availability
    available_engines: list[str] = Field(
        default_factory=lambda: ["semgrep", "codeql", "agent"],
        description="Engines available for use",
    )

    # Strategy settings
    stop_on_critical: bool = Field(
        default=True,
        description="Stop and report immediately when critical vulnerability found",
    )
    incremental_mode: bool = Field(
        default=False,
        description="Only audit changed files (incremental scan)",
    )

    # Metadata
    created_at: str | None = Field(default=None, description="Strategy creation timestamp")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    def get_targets_by_level(self, level: AuditPriorityLevel) -> list[AuditTarget]:
        """Get all targets at a specific priority level."""
        return [t for t in self.targets if t.priority and t.priority.level == level]

    def get_critical_targets(self) -> list[AuditTarget]:
        """Get all critical priority targets."""
        return self.get_targets_by_level(AuditPriorityLevel.CRITICAL)

    def get_high_targets(self) -> list[AuditTarget]:
        """Get all high priority targets."""
        return self.get_targets_by_level(AuditPriorityLevel.HIGH)

    def get_sorted_targets(self) -> list[AuditTarget]:
        """Get all targets sorted by priority (highest first)."""
        level_order = {
            AuditPriorityLevel.CRITICAL: 0,
            AuditPriorityLevel.HIGH: 1,
            AuditPriorityLevel.MEDIUM: 2,
            AuditPriorityLevel.LOW: 3,
            AuditPriorityLevel.SKIP: 4,
        }

        def sort_key(t: AuditTarget) -> int:
            if t.priority:
                return level_order.get(t.priority.level, 5)
            return 5

        return sorted(self.targets, key=sort_key)

    def get_summary(self) -> dict[str, Any]:
        """Get strategy summary."""
        return {
            "project": self.project_name,
            "source_path": self.source_path,
            "total_targets": self.total_targets,
            "total_loc": self.total_lines_of_code,
            "by_priority": {
                "critical": len(self.get_critical_targets()),
                "high": len(self.get_high_targets()),
                "medium": len(self.get_targets_by_level(AuditPriorityLevel.MEDIUM)),
                "low": len(self.get_targets_by_level(AuditPriorityLevel.LOW)),
                "skip": len(self.get_targets_by_level(AuditPriorityLevel.SKIP)),
            },
            "available_engines": self.available_engines,
            "groups": list(self.groups.keys()),
        }

    def to_yaml_config(self) -> str:
        """Generate YAML configuration for the strategy."""
        lines = [
            f"strategy:",
            f"  project: \"{self.project_name}\"",
            f"  source_path: \"{self.source_path}\"",
            f"  total_targets: {self.total_targets}",
            "",
            "  priority_groups:",
        ]

        for level in ["critical", "high", "medium", "low"]:
            level_enum = AuditPriorityLevel(level)
            targets = self.get_targets_by_level(level_enum)
            if targets:
                lines.append(f"    {level}: {len(targets)}")

                # Show engine allocations if group exists
                if level in self.groups:
                    group = self.groups[level]
                    if group.engine_allocations:
                        lines.append(f"      engines:")
                        for alloc in group.engine_allocations:
                            lines.append(f"        - engine: {alloc.engine}")
                            if alloc.concurrent > 1:
                                lines.append(f"          concurrent: {alloc.concurrent}")
                            if alloc.focus:
                                lines.append(f"          focus: {alloc.focus}")
                            if alloc.rules:
                                lines.append(f"          rules: {alloc.rules}")

        lines.extend([
            "",
            "  settings:",
            f"    max_concurrent_engines: {self.max_concurrent_engines}",
            f"    stop_on_critical: {self.stop_on_critical}",
            f"    incremental_mode: {self.incremental_mode}",
        ])

        return "\n".join(lines)
