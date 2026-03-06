"""
Impact Analyzer - Analyze the impact scope of code changes.

Determines which files and modules are affected by changes and
calculates impact scores for prioritizing incremental scans.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.incremental.change_detector import (
    ChangeInfo,
    ChangeType,
    DiffResult,
)
from src.layers.l3_analysis.incremental.dependency_graph import (
    DependencyGraph,
    DependencyType,
)

logger = get_logger(__name__)


class ImpactLevel(str, Enum):
    """Level of impact on a file."""

    DIRECT = "direct"  # File directly changed
    FIRST_ORDER = "first_order"  # Directly depends on changed file
    SECOND_ORDER = "second_order"  # Indirectly depends (2 hops)
    TRANSITIVE = "transitive"  # Transitively affected (>2 hops)
    MINIMAL = "minimal"  # Very low impact


@dataclass
class ImpactResult:
    """Result of impact analysis."""

    # Input
    changed_files: list[str] = field(default_factory=list)
    analysis_time: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Direct impact
    directly_affected: list[str] = field(default_factory=list)

    # Indirect impact (by level)
    first_order_affected: list[str] = field(default_factory=list)
    second_order_affected: list[str] = field(default_factory=list)
    transitive_affected: list[str] = field(default_factory=list)

    # Impact scores (file -> score)
    impact_scores: dict[str, float] = field(default_factory=dict)

    # Impact reasons (file -> list of reasons)
    impact_reasons: dict[str, list[str]] = field(default_factory=dict)

    # Recommendations
    files_to_scan: list[str] = field(default_factory=list)
    files_to_skip: list[str] = field(default_factory=list)
    scan_priority: list[tuple[str, float]] = field(default_factory=list)  # (file, priority)

    # Statistics
    total_files: int = 0
    coverage_ratio: float = 0.0
    duration_ms: float = 0.0

    @property
    def total_affected(self) -> int:
        """Get total number of affected files."""
        return (
            len(self.directly_affected)
            + len(self.first_order_affected)
            + len(self.second_order_affected)
            + len(self.transitive_affected)
        )

    def get_all_affected(self) -> set[str]:
        """Get all affected files as a set."""
        return set(self.files_to_scan)

    def get_impact_level(self, file_path: str) -> ImpactLevel | None:
        """Get the impact level for a file."""
        if file_path in self.directly_affected:
            return ImpactLevel.DIRECT
        elif file_path in self.first_order_affected:
            return ImpactLevel.FIRST_ORDER
        elif file_path in self.second_order_affected:
            return ImpactLevel.SECOND_ORDER
        elif file_path in self.transitive_affected:
            return ImpactLevel.TRANSITIVE
        return None


class ImpactAnalyzer:
    """
    Analyzes the impact of code changes.

    Uses the dependency graph to determine which files are affected
    by changes and calculates impact scores for scan prioritization.
    """

    # Impact weights by dependency type
    DEPENDENCY_WEIGHTS: dict[DependencyType, float] = {
        DependencyType.IMPORT: 0.9,
        DependencyType.FROM_IMPORT: 0.9,
        DependencyType.DYNAMIC_IMPORT: 0.6,  # Less certain
        DependencyType.FUNCTION_CALL: 0.8,
        DependencyType.CLASS_INHERITANCE: 0.95,  # High impact
        DependencyType.CLASS_COMPOSITION: 0.7,
        DependencyType.CONFIG_INCLUDE: 0.5,
        DependencyType.TEMPLATE_EXTENDS: 0.8,
        DependencyType.TEMPLATE_INCLUDE: 0.7,
        DependencyType.FILE_READ: 0.3,  # Lower impact
        DependencyType.FILE_REFERENCE: 0.4,
    }

    # Impact thresholds
    HIGH_IMPACT_THRESHOLD = 0.7
    MEDIUM_IMPACT_THRESHOLD = 0.4
    LOW_IMPACT_THRESHOLD = 0.2

    def __init__(
        self,
        dependency_graph: DependencyGraph,
        min_impact_score: float = 0.1,
        max_depth: int = 5,
        prioritize_entry_points: bool = True,
    ):
        """
        Initialize the impact analyzer.

        Args:
            dependency_graph: Pre-built dependency graph.
            min_impact_score: Minimum score to consider a file affected.
            max_depth: Maximum depth for transitive impact analysis.
            prioritize_entry_points: Give higher priority to entry points.
        """
        self.graph = dependency_graph
        self.min_impact_score = min_impact_score
        self.max_depth = max_depth
        self.prioritize_entry_points = prioritize_entry_points

    def analyze(
        self,
        changes: DiffResult | list[ChangeInfo] | list[str],
    ) -> ImpactResult:
        """
        Analyze the impact of changes.

        Args:
            changes: Either a DiffResult, list of ChangeInfo, or list of file paths.

        Returns:
            ImpactResult with impact analysis details.
        """
        start_time = datetime.now(UTC)

        # Normalize input to list of changed files
        if isinstance(changes, DiffResult):
            changed_files = [
                c.path for c in changes.changes
                if c.change_type != ChangeType.DELETED
            ]
        elif isinstance(changes, list):
            if changes and isinstance(changes[0], ChangeInfo):
                changed_files = [
                    c.path for c in changes
                    if c.change_type != ChangeType.DELETED
                ]
            else:
                changed_files = list(changes)
        else:
            changed_files = []

        result = ImpactResult(changed_files=changed_files)

        if not changed_files:
            result.duration_ms = (datetime.now(UTC) - start_time).total_seconds() * 1000
            return result

        if not self.graph._built:
            logger.warning("Dependency graph not built, impact analysis will be limited")
            result.directly_affected = changed_files
            result.files_to_scan = changed_files
            result.total_files = len(changed_files)
            result.duration_ms = (datetime.now(UTC) - start_time).total_seconds() * 1000
            return result

        # Get impact set from dependency graph
        impact_set = self.graph.get_impact_set(changed_files)

        # Classify by impact level
        for file_path, score in impact_set.items():
            if file_path in changed_files:
                result.directly_affected.append(file_path)
                result.impact_scores[file_path] = 1.0
            else:
                result.impact_scores[file_path] = score

                # Classify by depth
                distance = self.graph._get_shortest_path_length(file_path, min(changed_files, key=lambda f: self.graph._get_shortest_path_length(file_path, f)) if changed_files else "")

                if distance <= 1:
                    result.first_order_affected.append(file_path)
                elif distance == 2:
                    result.second_order_affected.append(file_path)
                else:
                    result.transitive_affected.append(file_path)

        # Calculate impact reasons
        result.impact_reasons = self._calculate_impact_reasons(
            changed_files,
            result.first_order_affected + result.second_order_affected + result.transitive_affected,
        )

        # Determine files to scan vs skip
        for file_path, score in result.impact_scores.items():
            if score >= self.min_impact_score:
                result.files_to_scan.append(file_path)
            else:
                result.files_to_skip.append(file_path)

        # Calculate scan priority
        result.scan_priority = self._calculate_scan_priority(result)

        # Statistics
        result.total_files = len(result.files_to_scan)
        total_project_files = len(self.graph.nodes)
        result.coverage_ratio = result.total_files / total_project_files if total_project_files > 0 else 0

        result.duration_ms = (datetime.now(UTC) - start_time).total_seconds() * 1000

        logger.info(
            f"Impact analysis complete: {len(result.directly_affected)} direct, "
            f"{len(result.first_order_affected)} first-order, "
            f"{len(result.second_order_affected)} second-order, "
            f"{len(result.transitive_affected)} transitive affected. "
            f"Coverage: {result.coverage_ratio:.1%}"
        )

        return result

    def _calculate_impact_reasons(
        self,
        changed_files: list[str],
        affected_files: list[str],
    ) -> dict[str, list[str]]:
        """Calculate reasons why each file is affected."""
        reasons: dict[str, list[str]] = {}

        for affected_file in affected_files:
            file_reasons = []

            # Find which changed file affects this file
            for changed_file in changed_files:
                # Check if affected_file depends on changed_file
                deps = self.graph.get_dependencies(affected_file, max_depth=1)
                if changed_file in deps:
                    # Find the specific dependency
                    for edge in self.graph.edges.get(affected_file, []):
                        if edge.target == changed_file:
                            reason = f"Depends on {changed_file}"
                            if edge.symbol_name:
                                reason += f" (via {edge.symbol_name})"
                            file_reasons.append(reason)

            if file_reasons:
                reasons[affected_file] = file_reasons

        return reasons

    def _calculate_scan_priority(self, result: ImpactResult) -> list[tuple[str, float]]:
        """
        Calculate scan priority for affected files.

        Higher priority = scan first.

        Returns:
            List of (file_path, priority_score) tuples, sorted by priority.
        """
        priorities: list[tuple[str, float]] = []

        for file_path in result.files_to_scan:
            base_score = result.impact_scores.get(file_path, 0.0)

            # Adjust based on impact level
            if file_path in result.directly_affected:
                priority = base_score * 1.5  # Boost direct changes
            elif file_path in result.first_order_affected:
                priority = base_score * 1.2
            elif file_path in result.second_order_affected:
                priority = base_score * 1.0
            else:
                priority = base_score * 0.8

            # Boost entry points
            if self.prioritize_entry_points:
                node = self.graph.nodes.get(file_path)
                if node and node.is_entry_point:
                    priority *= 1.3

            # Boost high centrality files
            node = self.graph.nodes.get(file_path)
            if node and node.centrality_score > 0.5:
                priority *= (1 + node.centrality_score * 0.2)

            priorities.append((file_path, priority))

        # Sort by priority (highest first)
        priorities.sort(key=lambda x: x[1], reverse=True)
        return priorities

    def get_scan_recommendation(
        self,
        result: ImpactResult,
        time_budget_minutes: float | None = None,
    ) -> dict[str, Any]:
        """
        Get scan recommendation based on impact analysis.

        Args:
            result: ImpactResult from analyze().
            time_budget_minutes: Optional time budget for scanning.

        Returns:
            Dictionary with scan recommendations.
        """
        recommendation = {
            "total_files_to_scan": len(result.files_to_scan),
            "estimated_coverage": result.coverage_ratio,
            "priority_order": result.scan_priority[:20],  # Top 20
            "high_priority_files": [],
            "medium_priority_files": [],
            "low_priority_files": [],
        }

        # Classify by priority
        for file_path, priority in result.scan_priority:
            if priority >= self.HIGH_IMPACT_THRESHOLD:
                recommendation["high_priority_files"].append(file_path)
            elif priority >= self.MEDIUM_IMPACT_THRESHOLD:
                recommendation["medium_priority_files"].append(file_path)
            elif priority >= self.LOW_IMPACT_THRESHOLD:
                recommendation["low_priority_files"].append(file_path)

        # If time budget specified, estimate how many files can be scanned
        if time_budget_minutes is not None:
            # Assume ~30 seconds per file on average
            files_per_minute = 2
            max_files = int(time_budget_minutes * files_per_minute)

            recommendation["time_budget"] = time_budget_minutes
            recommendation["max_files_within_budget"] = min(max_files, len(result.files_to_scan))
            recommendation["recommended_files"] = [
                f for f, _ in result.scan_priority[:max_files]
            ]

        return recommendation

    def estimate_scan_speedup(
        self,
        result: ImpactResult,
    ) -> dict[str, Any]:
        """
        Estimate the speedup from incremental scanning.

        Args:
            result: ImpactResult from analyze().

        Returns:
            Dictionary with speedup estimates.
        """
        total_files = len(self.graph.nodes)
        files_to_scan = len(result.files_to_scan)

        if total_files == 0:
            return {
                "speedup_factor": 1.0,
                "files_saved": 0,
                "time_saved_percent": 0.0,
            }

        # Calculate speedup
        files_skipped = total_files - files_to_scan
        speedup_factor = total_files / files_to_scan if files_to_scan > 0 else float("inf")
        time_saved_percent = (files_skipped / total_files) * 100

        return {
            "speedup_factor": round(speedup_factor, 2),
            "files_saved": files_skipped,
            "time_saved_percent": round(time_saved_percent, 1),
            "original_files": total_files,
            "incremental_files": files_to_scan,
        }

    def get_critical_paths(
        self,
        result: ImpactResult,
    ) -> list[list[str]]:
        """
        Get critical dependency paths from changed files to entry points.

        Args:
            result: ImpactResult from analyze().

        Returns:
            List of critical paths (each path is a list of file paths).
        """
        critical_paths = []
        entry_points = self.graph.get_entry_points()

        for changed_file in result.changed_files:
            for entry_point in entry_points:
                path = self._find_path(entry_point, changed_file)
                if path:
                    critical_paths.append(path)

        return critical_paths

    def _find_path(self, source: str, target: str) -> list[str] | None:
        """Find a path from source to target using BFS."""
        if source == target:
            return [source]

        visited = {source}
        parent: dict[str, str] = {}
        queue = [source]

        while queue:
            current = queue.pop(0)

            for edge in self.graph.reverse_edges.get(current, []):
                if edge.source == target:
                    # Found path, reconstruct it
                    path = [target, current]
                    while current in parent:
                        current = parent[current]
                        path.append(current)
                    return list(reversed(path))

                if edge.source not in visited:
                    visited.add(edge.source)
                    parent[edge.source] = current
                    queue.append(edge.source)

        return None
